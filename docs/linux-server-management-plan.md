# Linux server management in SentinelNet

## Context

SentinelNet manages network gear (switches, firewalls, WLCs) over SSH/REST. Customers
also run Linux servers on the same networks, and today those hosts are second-class:
they get *discovered* (LLDP neighbours, ARP/MAC harvesting, subnet scan) but cannot be
*managed* — no triage, no backup, no health, no audit. Adding one as a device fails at
`resolve_driver()` with "vendor non supportato".

Goal: make a Linux server a normal managed device, reusing the machinery that already
exists, and only then add what is genuinely missing. No new top-level tab.

Exploration showed the app is already most of the way there:

- `classify_device_type()` already maps `linux/ubuntu/debian/proxmox` → `server`
  ([core_engine.py:568](core/core_engine.py#L568)); `BUILTIN_CATEGORIES` already has
  `"server"` ([inventory_manager.py:468](services/inventory_manager.py#L468)).
- Inventory is a **CSV**, not SQLite ([inventory_manager.py:252](services/inventory_manager.py#L252)) —
  a Linux host fits the existing columns as-is. **No DB migration anywhere in this plan.**
- The driver contract is **two methods** ([drivers/base_driver.py](drivers/base_driver.py))
  and netmiko ships a native `linux` device_type — SSH transport is free.
- `api_observations` + the `{"results": …, "metrics": …}` convention already flows into
  `events.metrics_json`, where rule `DEVICE_LOAD_001` alerts on `cpu_pct`/`memory_pct`
  ([rules.py:338](observability/rules.py#L338)). **CPU/RAM incidents cost zero new code.**

## Decisions locked with the user

| Question | Decision |
|---|---|
| SSH auth | **Password only.** Reuse `get_device_credentials()` untouched. SSH keys are a separate task (see *Skipped*). |
| Privilege | **Adapted per device.** Unprivileged by default; the existing `Enable Secret` field doubles as the sudo password and, when set, unlocks the root-only command tier. |
| Scope | All four phases: vendor/driver, health poller, UI, CIS audit, MCP. |

---

## Phase 1 — Linux as a first-class vendor

Makes Inventory, triage, CLI modal, backup, EUVD/Threat Intel and topology work on a
Linux row **with no UI change at all**.

### 1.1 `drivers/linux.py` (new, ~25 lines)

Implements the existing 2-method contract:

- `get_version()` → `cat /etc/os-release` + `uname -r`, regex `PRETTY_NAME` → e.g.
  `"Ubuntu 24.04 LTS (6.8.0-generic)"`, `"Unknown"` on no match (same contract as
  [cisco_ios.py](drivers/cisco_ios.py)).
- `get_backup_command()` → the *unprivileged* config artifact, one command:
  a `for f in …; do echo "--- $f ---"; cat "$f"; done` over world-readable config files
  (`/etc/os-release`, `/etc/ssh/sshd_config`, `/etc/login.defs`, `/etc/sysctl.conf`,
  `/etc/fstab`, `/etc/hosts`, `/etc/resolv.conf`).

The `--- <path> ---` markers are deliberately the same shape `_backup_section()`
already parses ([core_engine.py:714](core/core_engine.py#L714)), and they become the
detection markers for Phase 4.

### 1.2 Registration — three dicts, one line each

- `DRIVER_REGISTRY` → `'linux': (LinuxDriver, 'linux')` — [core_engine.py:100](core/core_engine.py#L100)
- `VENDOR_DRIVER_DEFAULTS` → `'linux': 'linux'` — [core_engine.py:114](core/core_engine.py#L114)
- `get_all_vendors()` defaults → `"linux": {"euvd_term": "linux kernel", "driver": "linux"}`
  — [inventory_manager.py:429](services/inventory_manager.py#L429)
- `VENDOR_ALIASES` → `ubuntu|debian|rhel|centos|rocky|almalinux|suse → linux`
  — [inventory_manager.py:406](services/inventory_manager.py#L406). CSV imports written
  by humans say "Ubuntu", not "linux"; `normalize_vendor()` already runs on every write.

### 1.3 Three adaptations in `run_backup_and_triage()`

All inside [core_engine.py:290-350](core/core_engine.py#L290). These are the only places
the existing flow is genuinely wrong for a Linux host:

1. **`enable()` is unconditional at [:292](core/core_engine.py#L292).** netmiko's linux
   driver translates `enable()` into `sudo su`, which hangs or fails on a host with no
   sudo password. Guard it — this is the privilege adaptation the user asked for:

   ```python
   # Linux non ha enable mode: netmiko traduce enable() in `sudo su`. Ha senso
   # solo se l'operatore ha messo la password sudo in Enable Secret; altrimenti
   # la sessione resta non privilegiata e i comandi non-root bastano.
   if netmiko_type != 'linux' or secret:
       net_connect.enable()
   ```

2. **Hostname.** `find_prompt().strip().rstrip('#>')` at [:293](core/core_engine.py#L293)
   yields `user@web-01:~$` on Linux. Fix at the source instead: in the linux branch of the
   extra-command chain, emit the hostname as `hostname <name>` so the **existing**
   `extract_hostname_from_config()` regex ([:481](core/core_engine.py#L481)) picks it up.
   Two lines, no new parser.

3. **Extra-command chain** — a new `elif vendor == 'linux':` branch alongside the
   cisco/hpe/fortinet ones at [:306-345](core/core_engine.py#L306). Two tiers:

   | Tier | Gate | Commands |
   |---|---|---|
   | always | — | `hostname`, `uptime -p`, `ip -br a`, `ip route`, `lsblk`, `df -hT`, `systemctl --failed`, `ss -tuln`, `lldpctl` |
   | privileged | `if secret:` | `ss -tulpn`, `stat -c '%a %U %G %n' /etc/shadow /etc/passwd /etc/group`, `sshd -T` |

   Same `try/except: pass` per command as the existing branches — a missing binary on a
   minimal distro must not fail the whole triage.

### 1.4 Tests (`tests/test_linux_driver.py`)

Template: [tests/test_arp_collector.py](tests/test_arp_collector.py) — raw command output
as module constants, parser asserted with no I/O.

- `get_version()` parses a realistic `/etc/os-release` + `uname -r`, and returns
  `"Unknown"` on garbage.
- `extract_hostname_from_config()` recovers `web-01` from a `--- HOSTNAME ---` section.
- `resolve_driver("ubuntu")` → `(LinuxDriver, "linux")` via the alias.
- The `enable()` guard: `netmiko_type == "linux"` + empty secret → not called.

---

## Phase 2 — Health poller into the existing incident pipeline

### 2.1 `observability/ingesters/linux_poller.py` (new)

Modelled 1:1 on [snmp_poller.py](observability/ingesters/snmp_poller.py) — same four
functions, same names:

```
poll_loop(interval_s)     while True: poll_once(); await asyncio.sleep(interval_s)
poll_once() -> int        asyncio.to_thread(_linux_devices); per device _poll_device
_linux_devices() -> list  get_all_devices() filtered on normalize_vendor(...) == 'linux'
_poll_device(device)      one netmiko session -> [(kind, summary_json)]
```

- Device selection reuses `inventory_manager.get_all_devices()` + `get_device_credentials()`;
  tenant is `device.get("Group") or "Generale"` exactly as [snmp_poller.py:235](observability/ingesters/snmp_poller.py#L235).
- **No sudo.** Every health metric is readable unprivileged, so the poller never
  touches `enable()`.
- Emits one row, `kind='linux_health'`, in the declared shape:
  `{"results": {uptime_s, kernel, failed_units, …}, "metrics": {cpu_pct, memory_pct, disk_pct}}`.
  `results` = state (change-detected), `metrics` = measured (threshold-read, excluded from
  change detection at [normalize.py:216](observability/normalize.py#L216)).
- Write via `db.enqueue_write("INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json) …")`.
  **No schema change, no new table.**

Metric sources: `/proc/stat` delta or `top -bn1` for `cpu_pct`, `free` for `memory_pct`,
`df -P /` for `disk_pct`. One SSH session per device per round.

### 2.2 Wiring — three existing extension points

- `data_config.obs_config()` → `"linux_poll_s": _port("SENTINELNET_OBS_LINUX_POLL_S", "linux_poll_s", 0)`
  — [data_config.py:123](core/data_config.py#L123) pattern. **Default 0 (off)**, same
  rationale as SNMP: it uses a credential, it must be switched on deliberately.
- `listener_manager.apply_obs_config()` → task handle + cancel/recreate on interval change,
  copying the `_snmp_poller_task` block at [listener_manager.py:136-145](observability/listener_manager.py#L136).
- POST allowlist at [routers/observability.py:611](routers/observability.py#L611).

### 2.3 Disk threshold — one tuple

`_device_load` already loops over `(field, limit, label)` pairs. Add one:

```python
("disk_pct", p["max_disk_pct"], "Disco")
```

at [rules.py:338](observability/rules.py#L338), plus `max_disk_pct` (default 90) in the
`DEVICE_LOAD_001` `parameters` dict at [rules.py:837](observability/rules.py#L837).
Evidence → incident → conclusion is then automatic; `entity_key` is `ip:<device_ip>`, so a
disk symptom groups with any syslog/flow trigger on the same host.

### 2.4 Tests (`tests/test_linux_poller.py`)

Template: [tests/test_snmp_poller.py](tests/test_snmp_poller.py) — the mandatory tempdir-
before-import idiom, and its three layers:

1. Pure parsing of `/proc/stat` / `free` / `df` output → the metrics dict.
2. `_linux_devices()` with `patch("services.inventory_manager.get_all_devices")`.
3. End-to-end: insert a `linux_health` row into `api_observations`, assert it reaches
   `events.metrics_json` and produces evidence — plus a disk-over-threshold case modelled
   on [tests/test_device_load.py](tests/test_device_load.py).

---

## Phase 3 — UI additions, inside existing tabs only

No new top-level nav entry. Ordered by cost:

| Surface | Change |
|---|---|
| **Inventory** ([tab-devices](templates/dashboard.html#L317)) | **None.** `linux` appears in the vendor dropdown automatically from `get_all_vendors()`; the Firmware column shows the distro + kernel string. |
| **Categories** ([tab-categories](templates/dashboard.html#L810)) | **None.** `server` is already a builtin category and auto-classification already matches Linux strings. |
| **Provisioning credentials** ([dashboard.html:547](templates/dashboard.html#L547)) | Relabel `#devSecret`'s helper text to say it doubles as the sudo password when Vendor is `linux`. One conditional hint in `provisioning.js` + 2 i18n keys. |
| **Settings → Observability** ([obsSettingsBody](templates/dashboard.html#L2457)) | Add a `linux_poll_s` `form-group` next to the SNMP one in `renderObsSettings()` ([observability.js:49](static/js/observability.js#L49)) + one line in `saveObsSettings()`'s payload + 2 i18n keys (`lblObsLinuxPoll`, `hintObsLinuxPoll`) in **both** `it` and `en`. The panel is hand-written, not generic — ~12 lines. |
| **Incidents** ([tab-incidents](templates/dashboard.html#L2550)) | **None.** Host incidents render through the existing per-device blocks. |
| **NetSec Audit** ([tab-netsec-audit](templates/dashboard.html#L2616)) | **None** for markup — the benchmark selector is populated from `GET /api/netsec-audit/benchmarks`, so Phase 4 rules appear on their own. |

New JS goes in existing files; no new `static/js/*.js`, no change to the script tags at
[dashboard.html:3082](templates/dashboard.html#L3082).

---

## Phase 4 — Linux CIS audit (third platform in `services/netsec_audit/`)

The engine is already multi-platform (FortiOS + IOS), so the seam is proven. Input is the
Phase 1 backup artifact, which is why Phase 1 must land first.

- **`LINUX = "linux"`** constant in [benchmarks.py:43](services/netsec_audit/benchmarks.py#L43).
- **`detect_vendor()`** ([__init__.py:49](services/netsec_audit/__init__.py#L49)) — add
  `_LINUX_MARKERS`. Because we generate the artifact ourselves, the markers are exact and
  unambiguous: `--- /etc/ssh/sshd_config ---`, `--- /etc/login.defs ---`, `--- /etc/fstab ---`.
  Keep the existing count-and-compare shape so a concatenated file still resolves.
- **`linux_parser.py`** (new, ~60 lines) — splits the artifact on `--- <path> ---` into
  per-file line lists. Returns a `NamedTuple` exposing `.lines` (satisfies the
  `parsed_anything` check at [__init__.py:111](services/netsec_audit/__init__.py#L111))
  and `.files: dict[path, list[LinuxLine]]`. `LinuxLine` mirrors `IosLine`
  (`line`, `text`, `lower`, `raw`) minus the indentation-block machinery Linux config
  files do not have. Tolerant: no malformed line raises.
- **`linux_rules.py`** (new) — `check_x(cfg) -> RuleOutcome` returning **catalog keys**,
  never prose ([model.py](services/netsec_audit/model.py) contract). First rule set, all
  derivable from the unprivileged artifact: SSH `PermitRootLogin`/`PasswordAuthentication`/
  `Protocol`/`MaxAuthTries`/`X11Forwarding`, `PASS_MAX_DAYS`/`PASS_MIN_LEN` in
  `login.defs`, `nodev`/`nosuid`/`noexec` on `/tmp` and `/var` in `fstab`,
  `net.ipv4.ip_forward` and redirect-acceptance in `sysctl.conf`.
- **`benchmarks.py`** entries with `"vendor": LINUX`, plus paraphrased `guidance.py` and
  `messages.py` keys in `it` + `en`.
- Parser dispatch at [__init__.py:99](services/netsec_audit/__init__.py#L99) grows one branch.

**Prerequisite before writing `ref`/`level`/`automated` values:** the CIS Distribution
Independent Linux (or CIS Ubuntu Linux) Benchmark PDF. The FortiGate and Cisco PDFs the
existing rules cite are in the user's OneDrive; there is no Linux one there yet. Do not
invent recommendation numbers. Same constraint as the other two platforms: **cite `ref`
numbers only, paraphrase all rationale/impact in our own words** — CIS text is copyrighted
and this repo is public.

Tests: [tests/test_netsec_audit_ios.py](tests/test_netsec_audit_ios.py) is the exact
"second platform" precedent. Add `tests/fixtures/linux_clean.conf` and
`linux_violations.conf` alongside the existing `ios_*.conf`, plus a `detect_vendor()`
test asserting a Linux artifact is not mistaken for FortiOS (the current fallback at
[__init__.py:104](services/netsec_audit/__init__.py#L104) defaults unknown text to FortiOS).

---

## Phase 5 — MCP exposure

`TOOLS` in [ai/mcp_server.py:99](ai/mcp_server.py#L99) is one dict; every tool is a thin
proxy to an existing REST endpoint via `api(...)`, so auth, RBAC, tenant scoping and
`redact()` are all enforced server-side.

Add one entry — `linux_health(ip)` → the observability endpoint serving `linux_health`
snapshots. Follow the read-only observability precedent at
[mcp_server.py:411-425](ai/mcp_server.py#L411): **disabled by default** in the tool-config
list. Existing `list_devices`, `send_cli_command` and `analyze_config` already cover Linux
hosts once Phase 1 lands — no new entries needed for those.

---

## Verification

Run in order, from the repo root, reading the output — never claim a check passed without
having run it (`docs/development.md` §6 is the canonical list):

```sh
uv run pyrefly check                          # 0 errors
uv run python -m unittest discover -s tests   # all green
graphify update .                             # after code changes
```

End-to-end, per phase:

1. **Phase 1** — add a lab Linux host via Provisioning (Vendor `linux`, Profile `custom`,
   an unprivileged account, Enable Secret empty). Then: row appears in Inventory → *Triage*
   → status `online`, Firmware shows the distro + kernel, hostname resolves to the short
   name (not `user@host:~$`) → *Backup* downloads an artifact whose sections are all
   `--- /etc/... ---`. Repeat with Enable Secret set and confirm the privileged tier
   (`ss -tulpn`, `stat` on `/etc/shadow`) appears and the unprivileged run still succeeds
   without it.
2. **Phase 2** — Settings → Observability, set the Linux polling interval to 60s, save
   (hot-applied, no restart). After two rounds:
   `SELECT kind, summary_json FROM api_observations WHERE kind='linux_health'` has rows;
   `events.metrics_json` carries `cpu_pct`/`memory_pct`/`disk_pct`. Fill a scratch loop
   device or lower `max_disk_pct` to force a crossing and confirm an incident appears in
   the Incidents tab keyed to the host IP.
3. **Phase 4** — NetSec Audit tab, upload/select a Linux backup: the payload reports
   `vendor: "linux"`, only Linux rules are evaluated (no FortiOS rules leaking in), and a
   FAIL cites the exact line from `sshd_config`.
4. **Phase 5** — enable the tool in Integrazioni, then ask the AI assistant for a host's
   health and confirm the response is redacted.

Finally, per the standing rule: rebuild the executable — `pyinstaller SentinelNet.spec`.
No new data files are introduced, and every new module is statically imported
(`drivers/linux.py` via `core_engine`, `linux_poller.py` via `listener_manager`,
`linux_parser.py`/`linux_rules.py` via `benchmarks.py`), so the spec needs no edits —
confirm the built exe still starts and the Linux vendor is selectable.

**Public-repo constraint:** use only RFC 5737 addresses (`192.0.2.x`, `198.51.100.x`) and
placeholder names (`web-01`, `switch-01`) in fixtures, tests, comments and commit
messages. Real values from `data/` verify the parsers; they never enter the tree.

---

## Deliberately skipped

- **SSH key authentication.** The real gap for Linux fleets — `get_device_credentials()`
  returns a 3-tuple and the netmiko `device_params` dict is copy-pasted at ~9 sites, so
  keys mean widening a contract that all 8 existing vendors share, plus key-at-rest storage
  in `crypto_vault`. Add when password auth proves insufficient; do the
  `build_netmiko_params(device)` extraction first so the feature diff is one file.
- **A dedicated `linux_metrics` table.** `api_observations` takes an arbitrary `kind` and
  `events.metrics_json` is the generic measured-value channel. Add a table only for
  something they cannot express — an installed-package/CVE inventory would qualify.
- **A top-level "Servers" tab.** Every surface a Linux host needs already exists. Add when
  Linux gains workflows unrelated to inventory — not before.
- **Agent-site support.** Central cannot SSH into `mode == 'agent'` sites
  ([commands.py:158](routers/commands.py#L158)); the poller is central-sites-only and must
  say so in its docstring. Add to `services/site_agent.py` when a customer needs it.
- **Package/CVE inventory per host.** EUVD matching on the kernel version via the existing
  `euvd_term` covers the first-order case.
