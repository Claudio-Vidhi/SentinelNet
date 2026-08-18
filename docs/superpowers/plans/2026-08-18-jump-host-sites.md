# Jump-Host Sites (Mode C) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reach devices of a remote customer network through an SSH bastion (a Linux
box we can only log into), with no SentinelNet software installed on that box.

**Architecture:** A third site mode, `jump`, next to `central` and `agent`. When a
device belongs to a `jump` site, SentinelNet opens one SSH session to the bastion
with paramiko and asks it for a `direct-tcpip` channel to the device; the channel is
handed to netmiko as its `sock=` parameter. All CLI collection then works unchanged.
No `ssh.exe`, no `~/.ssh/config`, no port forwards, no agent on the customer box.

**Tech Stack:** paramiko 3.4+ (already a direct dependency), netmiko 4.3+
(`sock` parameter, `base_connection.py:202` and `:1078`), existing
`security/identity_manager.py` for the bastion credentials.

**Spec:** this document (design + plan in one; the feature is small enough that a
separate spec would only duplicate it).

## Global Constraints

- Version bump: MINOR (`core/version.py` + `pyproject.toml` must match) — new site mode.
- New comments in English; do not touch surrounding Italian comments.
- No real customer data in the tree: examples use `192.0.2.x` / `198.51.100.x`.
- Never write `identities.json` or any credential file from a task; the app writes them at runtime.
- Bastion secrets are stored only as an existing identity id, never duplicated into `sites.json`.
- Pre-commit gate (`docs/development.md` §6): `uv run pyrefly check`,
  `uv run python scripts/check_frontend.py`, `uv run python -m unittest discover -s tests`,
  `graphify update .`.

---

## What is doable, and what is not

The bastion gives us **outbound TCP only, initiated by us**. Everything SentinelNet
does that is not "open a TCP connection from the central to a device" stays broken.

**Works through a jump site (phase 1):**

| Capability | Why it works |
|---|---|
| CLI collection: inventory, version, config backup (`core/core_engine.py:313,511,555,602`) | netmiko over a `direct-tcpip` channel |
| MAC table and ARP collection (`collectors/mac_collector.py`, `collectors/arp_collector.py`) | same |
| Port actions (`services/port_action.py`), switch and FortiGate provisioning via CLI | same |
| WLC CLI (`services/wlc_service.py`) | same |
| Bulk command, CLI modal, config analyzer, netsec audit (they consume CLI output) | same |

**Does not work, and must be visibly disabled:**

| Capability | Why |
|---|---|
| ICMP ping monitor (`services/ping_monitor.py:59`, `collectors/network_scanner._ping`) | ICMP is not TCP; an SSH channel cannot carry it |
| Subnet scan and discovery from the central | same, plus it needs broadcast/ARP adjacency |
| Syslog reception, NetFlow/flow ingestion | inbound UDP from devices to us; the bastion never initiates back |
| FortiGate REST, WLC REST, any `requests`-based vendor API | needs a listening local port, not a channel — see phase 2 |
| SNMP (if ever wired up; `pysnmp` is a dependency but currently unused in code) | UDP |
| Real-time device status in the inventory KPIs | derives from ping |

**Consequence to state in the UI, not only in the docs:** a jump site shows inventory
and configs but never shows online/offline; triage on a jump site reports reachability
as "not measurable", never as "down".

**Phase 2, only if the customer asks:** a local TCP listener per (device, port) over
the same paramiko transport gives `requests` a `https://127.0.0.1:<p>` target and
restores the REST features. It costs one thread per forward and a TLS hostname
mismatch to handle. Not built in phase 1.

---

## File Structure

- `core/net_ssh.py` (new) — the only new module. Exports `ConnectHandler`, a drop-in
  wrapper that injects `sock=` for devices in a jump site, plus `close_all()`. Owns
  the per-site paramiko transport cache.
- `services/site_manager.py` (modify) — `VALID_MODES` gains `"jump"`; the bastion
  fields are validated on create and update.
- 9 SSH call sites (modify) — import swap only, one line each.
- `routers/sites.py` (modify) — accept and return the jump fields.
- `static/js/site-agent.js`, `templates/dashboard.html` (modify) — jump form and the
  limitation panel.
- `services/ping_monitor.py`, `routers/scan.py` (modify) — skip jump-site devices.
- `tests/test_jump_site.py` (new) — the whole feature's tests.
- `docs/remote-sites.md` (modify) — mode C section carrying the two tables above.

---

### Task 1: Site mode `jump` in the data model

**Files:**
- Modify: `services/site_manager.py:34` (`VALID_MODES`), `:123` (`create_site`), `:167` (`update_site`)
- Test: `tests/test_jump_site.py`

**Interfaces:**
- Produces: a site dict with `mode == "jump"` and the keys `jump_host: str`,
  `jump_port: int` (default 22), `jump_identity: str` (an identity id from
  `security/identity_manager.py`). `create_site(name, mode, subnets=None, **kwargs)`
  returns `(public_site, None)` for jump sites — no token is generated.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jump_site.py
import os
import tempfile
import unittest


class JumpSiteModel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.environ["SENTINELNET_DATA_DIR"] = self.tmp

    def test_create_jump_site_keeps_fields_and_issues_no_token(self):
        from services import site_manager
        site, token = site_manager.create_site(
            "Customer A", "jump", subnets=["192.0.2.0/24"],
            jump_host="198.51.100.10", jump_port=22, jump_identity="id-1")
        self.assertIsNone(token)
        self.assertEqual(site["mode"], "jump")
        self.assertEqual(site["jump_host"], "198.51.100.10")
        self.assertEqual(site["jump_port"], 22)
        self.assertEqual(site["jump_identity"], "id-1")

    def test_jump_site_without_host_is_rejected(self):
        from services import site_manager
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer B", "jump", jump_identity="id-1")


if __name__ == "__main__":
    unittest.main()
```

Before running it, open two existing tests in `tests/` and copy how they point the
data dir at a temp directory (env var, monkeypatch of `core.data_config`, or a
fixture). Use that mechanism verbatim if it differs from the `setUp` above.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_jump_site -v`
Expected: FAIL — `ValueError: Modalità non valida: jump`.

- [ ] **Step 3: Write minimal implementation**

```python
# services/site_manager.py
VALID_MODES = ("central", "agent", "jump")


def _validate_jump(values: dict) -> dict:
    """Normalize and check the bastion fields of a 'jump' site."""
    host = (values.get("jump_host") or "").strip()
    if not host:
        raise ValueError("Un sito 'jump' richiede jump_host.")
    identity = (values.get("jump_identity") or "").strip()
    if not identity:
        raise ValueError("Un sito 'jump' richiede jump_identity.")
    port = int(values.get("jump_port") or 22)
    if not (1 <= port <= 65535):
        raise ValueError("jump_port non valida.")
    return {"jump_host": host, "jump_port": port, "jump_identity": identity}
```

Change the signature to `create_site(name, mode, subnets=None, **kwargs)`; when
`mode == "jump"`, merge `_validate_jump(kwargs)` into the stored dict and leave
`token_hash = None`. In `update_site`, when the resulting mode is `jump`, run the
same validation over the merged existing-plus-kwargs values before saving.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_jump_site -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add services/site_manager.py tests/test_jump_site.py
git commit -m "feat(sites): add jump site mode to the data model"
```

---

### Task 2: The jump channel factory

**Files:**
- Create: `core/net_ssh.py`
- Test: `tests/test_jump_site.py` (append)

**Interfaces:**
- Consumes: the site fields of Task 1; `identity_manager.get_identity_credentials(identity_id)`.
- Produces:
  - `jump_channel(site: dict, host: str, port: int) -> paramiko.Channel`
  - `ConnectHandler(**params)` — drop-in for `netmiko.ConnectHandler`
  - `close_all() -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jump_site.py (append)
import unittest.mock as mock


class JumpChannel(unittest.TestCase):
    def test_connect_handler_injects_sock_for_a_jump_device(self):
        from core import net_ssh
        chan = object()
        device = {"IP": "192.0.2.5", "Site": "customer-a"}
        site = {"id": "customer-a", "mode": "jump", "jump_host": "198.51.100.10",
                "jump_port": 22, "jump_identity": "id-1"}
        with mock.patch.object(net_ssh, "_netmiko_connect") as nm, \
             mock.patch.object(net_ssh, "jump_channel", return_value=chan) as jc, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=device), \
             mock.patch("services.site_manager.get_site", return_value=site):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="192.0.2.5",
                                   username="u", password="p")
        jc.assert_called_once_with(site, "192.0.2.5", 22)
        self.assertIs(nm.call_args.kwargs["sock"], chan)

    def test_connect_handler_is_untouched_for_a_central_device(self):
        from core import net_ssh
        device = {"IP": "192.0.2.6", "Site": "central"}
        site = {"id": "central", "mode": "central"}
        with mock.patch.object(net_ssh, "_netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=device), \
             mock.patch("services.site_manager.get_site", return_value=site):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="192.0.2.6",
                                   username="u", password="p")
        self.assertNotIn("sock", nm.call_args.kwargs)

    def test_unknown_device_is_untouched(self):
        from core import net_ssh
        with mock.patch.object(net_ssh, "_netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=None):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="203.0.113.9",
                                   username="u", password="p")
        self.assertNotIn("sock", nm.call_args.kwargs)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_jump_site -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'core.net_ssh'`.

- [ ] **Step 3: Write minimal implementation**

```python
# core/net_ssh.py
# -*- coding: utf-8 -*-
"""netmiko entry point that is aware of jump (bastion) sites.

Import ConnectHandler from here instead of from netmiko. For a device that
belongs to a site in 'jump' mode the connection is tunnelled through one SSH
session to the bastion: paramiko opens a 'direct-tcpip' channel towards the
device and netmiko drives that channel through its own sock= parameter. For
every other device this is netmiko unchanged.

One transport is kept per site and reused by all its devices; a dead transport
is rebuilt on the next call.
"""
import threading

import paramiko
from netmiko import ConnectHandler as _netmiko_connect

_transports: "dict[str, paramiko.Transport]" = {}
_lock = threading.Lock()


def _transport(site: dict) -> paramiko.Transport:
    """Return a live SSH transport to the site's bastion, opening it if needed."""
    from security import identity_manager
    site_id = site["id"]
    with _lock:
        tr = _transports.get(site_id)
        if tr is not None and tr.is_active():
            return tr
        creds = identity_manager.get_identity_credentials(site["jump_identity"])
        if not creds:
            raise ValueError(f"Identita' {site['jump_identity']} non trovata.")
        username, password = creds[0], creds[1]
        tr = paramiko.Transport((site["jump_host"], int(site.get("jump_port") or 22)))
        tr.connect(username=username, password=password)
        _transports[site_id] = tr
        return tr


def jump_channel(site: dict, host: str, port: int) -> paramiko.Channel:
    """Open a direct-tcpip channel from the bastion to host:port."""
    return _transport(site).open_channel(
        "direct-tcpip", (host, int(port)), ("127.0.0.1", 0))


def _jump_site_for(host: str):
    """Return the jump site owning this device IP, or None."""
    from services import inventory_manager, site_manager
    device = inventory_manager.get_device_by_ip(host)
    if not device:
        return None
    site = site_manager.get_site(device.get("Site") or "")
    return site if site and site.get("mode") == "jump" else None


def ConnectHandler(**params):
    """netmiko.ConnectHandler, tunnelled when the device sits behind a bastion."""
    host = params.get("host") or params.get("ip")
    site = _jump_site_for(host) if host else None
    if site:
        params["sock"] = jump_channel(site, host, int(params.get("port") or 22))
    return _netmiko_connect(**params)


def close_all() -> None:
    """Close every cached bastion transport (application shutdown)."""
    with _lock:
        for tr in _transports.values():
            tr.close()
        _transports.clear()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_jump_site -v`
Expected: PASS, 5 tests.

Then read `security/identity_manager.py:97` and confirm the credential tuple really is
`(username, password, enable_secret)`; fix the unpacking if it is not.

- [ ] **Step 5: Commit**

```bash
git add core/net_ssh.py tests/test_jump_site.py
git commit -m "feat(ssh): tunnel netmiko through a bastion for jump sites"
```

---

### Task 3: Route every SSH call site through the wrapper

**Files:**
- Modify (import line only): `core/core_engine.py:7`, `services/fortigate_provisioner.py:376`,
  `services/fortigate_service.py:266`, `services/port_action.py:82` and `:109`,
  `services/switch_provisioner.py:330`, `services/wlc_service.py:99`,
  `collectors/arp_collector.py:115`, `collectors/mac_collector.py:404`
- Test: `tests/test_jump_site.py` (append)

**Interfaces:**
- Consumes: `core.net_ssh.ConnectHandler` from Task 2.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jump_site.py (append)
import pathlib
import re


class NoDirectNetmikoImports(unittest.TestCase):
    """Every SSH call site must go through core.net_ssh, otherwise a jump site
    silently bypasses the tunnel and tries to reach the device directly."""

    # site_agent.py runs inside the remote network: it must NOT tunnel.
    ALLOWED = {"core/net_ssh.py", "services/site_agent.py"}

    def test_no_module_imports_connecthandler_from_netmiko(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        offenders = []
        for path in root.rglob("*.py"):
            if ".venv" in path.parts or "tests" in path.parts:
                continue
            rel = path.relative_to(root).as_posix()
            if rel in self.ALLOWED:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"from netmiko import [^\n]*ConnectHandler", text):
                offenders.append(rel)
        self.assertEqual(offenders, [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_jump_site -v`
Expected: FAIL, listing the files above.

- [ ] **Step 3: Write minimal implementation**

In each listed file replace the import, leaving every call unchanged:

```python
from core.net_ssh import ConnectHandler
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest discover -s tests`
Expected: all green — the existing SSH tests still pass, since the wrapper is a
pass-through for non-jump devices.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor(ssh): route all netmiko call sites through core.net_ssh"
```

---

### Task 4: Disable what a bastion cannot carry

**Files:**
- Modify: `services/site_manager.py`, `services/ping_monitor.py:59`, `routers/scan.py`
- Test: `tests/test_jump_site.py` (append)

**Interfaces:**
- Produces: `site_manager.is_reachable_by_icmp(site_id: str) -> bool` — False for jump
  sites, True otherwise. Callers use it to skip, never to report "down".

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jump_site.py (append)
class IcmpSkippedForJumpSites(unittest.TestCase):
    def test_ping_monitor_reports_unknown_not_offline(self):
        from services import ping_monitor
        device = {"IP": "192.0.2.5", "Site": "customer-a"}
        site = {"id": "customer-a", "mode": "jump"}
        with mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("collectors.network_scanner._ping") as p:
            status = ping_monitor.check_device(device)
        p.assert_not_called()
        self.assertEqual(status, "unknown")
```

Read `services/ping_monitor.py:59` first and use the entry point it actually exposes,
with its actual return shape — do not invent one.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_jump_site -v`
Expected: FAIL — `_ping` was called, or the status came back as offline.

- [ ] **Step 3: Write minimal implementation**

```python
# services/site_manager.py
def is_reachable_by_icmp(site_id: str) -> bool:
    """False for bastion-only sites: ICMP cannot cross an SSH tunnel."""
    site = get_site(site_id or "")
    return not (site and site.get("mode") == "jump")
```

Guard the ping path with it, returning the `unknown` status instead of a false
negative, and reject a scan request that targets a jump site with HTTP 409 and the
message `Sito jump: la scansione ICMP non e' possibile.`

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest discover -s tests`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(sites): skip ICMP paths for jump sites instead of reporting down"
```

---

### Task 5: UI — create a jump site and see its limits

**Files:**
- Modify: `routers/sites.py`, `static/js/site-agent.js`, `templates/dashboard.html`
  (`tab-sites`), `static/js/i18n.js`, `types/globals.d.ts` if a new global is exposed
- Test: `tests/test_jump_site.py` (append), plus `uv run python scripts/check_frontend.py`

**Interfaces:**
- Consumes: the site fields of Task 1 and `is_reachable_by_icmp` of Task 4.
- Produces: `POST /api/sites` accepting `mode: "jump"` with `jump_host`, `jump_port`,
  `jump_identity`; `GET /api/sites` returning them, never a secret.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jump_site.py (append)
class JumpSiteApi(unittest.TestCase):
    def setUp(self):
        # Reuse the authenticated client that tests/test_remote_site.py builds in
        # RemoteSiteE2E.setUp (tests/test_remote_site.py:41): same app import, same
        # login, same temp data dir. Copy that setUp body verbatim rather than
        # writing a second way of authenticating.
        raise NotImplementedError("copy RemoteSiteE2E.setUp here")

    def test_post_sites_accepts_jump_mode(self):
        r = self.client.post("/api/sites", json={
            "name": "Customer A", "mode": "jump", "jump_host": "198.51.100.10",
            "jump_port": 22, "jump_identity": "id-1", "subnets": ["192.0.2.0/24"]})
        self.assertEqual(r.status_code, 200)
        body = r.json()["site"]
        self.assertEqual(body["mode"], "jump")
        self.assertNotIn("token_hash", body)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_jump_site -v`
Expected: FAIL — 400 or 422, the router rejects the unknown mode.

- [ ] **Step 3: Write minimal implementation**

Router: extend the site payload model with the three optional fields and pass them to
`create_site` / `update_site`.

Template (`tab-sites`): add `Jump (bastion SSH)` to the mode selector; show a
`#jumpFields` block with host, port and an identity `<select>` fed by the existing
identities endpoint. Under it, the user-facing limitation notice — it must be visible
at creation time, not buried in the docs:

```html
<div class="panel" id="jumpLimits" style="display:none; border-left:2px solid var(--warning); padding-left:10px;">
  <h4 data-i18n="jumpLimitsTitle">Cosa non funziona su un sito jump</h4>
  <ul>
    <li data-i18n="jumpLimitsPing">Nessun ping ICMP: lo stato online/offline resta "non misurabile".</li>
    <li data-i18n="jumpLimitsScan">Nessuna scansione di subnet ne' discovery dal centrale.</li>
    <li data-i18n="jumpLimitsUdp">Nessun syslog, flow o SNMP in ingresso.</li>
    <li data-i18n="jumpLimitsRest">Nessuna API REST vendor (FortiGate, WLC): solo CLI.</li>
    <li data-i18n="jumpLimitsWorks">Funzionano: inventario, backup config, MAC/ARP, comandi CLI, audit.</li>
  </ul>
</div>
```

JS: bind a delegated listener to the mode `<select>` id that exists in the template,
toggling `#jumpFields` and `#jumpLimits`. No inline `onclick`. Add every `data-i18n`
key to both languages in `static/js/i18n.js`. In the inventory table, render the
status cell of a jump-site device as an em dash with the `jumpLimitsPing` tooltip,
never as "offline".

- [ ] **Step 4: Run the tests and the frontend check**

Run: `uv run python -m unittest discover -s tests` — all green.
Run: `uv run python scripts/check_frontend.py` — 0 errors.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(ui): create jump sites and surface their limitations"
```

---

### Task 6: Docs, version, graph

**Files:**
- Modify: `docs/remote-sites.md`, `core/version.py`, `pyproject.toml`

- [ ] **Step 1: Write the mode C section**

Add to `docs/remote-sites.md`: when to pick mode C (the customer forbids any installed
agent and grants only SSH to one Linux box), the three fields to fill, the identity to
create first, and the two tables from the "What is doable" section of this plan, copied
verbatim. State the bastion prerequisites: reachable over SSH from the central, an
account allowed to open TCP forwards (`AllowTcpForwarding yes`, the OpenSSH default),
and IP reachability from the bastion to the devices.

- [ ] **Step 2: Bump the version**

MINOR bump in `core/version.py`, same value in `pyproject.toml`.

- [ ] **Step 3: Run the full gate**

```sh
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run python -m unittest discover -s tests
graphify update .
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(sites): document jump mode and its limits; bump minor version"
```

---

## Deferred, on purpose

- **REST over the bastion** (phase 2 above) — one local forwarder thread per device port.
- **Key-based bastion auth** — identities are username/password today; a key-file field
  belongs to the identity model, not to the site.
- **Multi-hop** (bastion to bastion to device) — nobody asked.
- **Keepalive and reconnect storms** — the transport cache rebuilds on demand; if a
  flapping bastion turns out to hurt, add `set_keepalive(30)` then, not now.
