# Linux server collection

What SentinelNet reads off a managed Linux host, where each piece comes from,
and which view shows it. For the health poller as a collector among the
others, see [collectors.md](collectors.md) §7b.

There are **two independent paths**, and which one a fact belongs to is a
design decision, not an accident:

| Path | Cadence | Purpose | Consumers |
|---|---|---|---|
| **Backup artefact** | on demand / scheduled | stable state, audit-relevant, archived forever | Config Analyzer, NetSec Audit, search, AI assistant |
| **Health poller** | every polling round | time-varying measurements | `device.state`, rules, incidents |

A number that changes on every read belongs to the poller. Putting it in the
artefact would make every backup differ from the last one for no reason.

---

## 1. The artefact

One SSH session. The running config equivalent — a `cat` of world-readable
config files — followed by an appendix of command output. Every section is
introduced by a `--- <name> ---` marker, the same shape `_backup_section()`
already parses for switches, which is why the audit and the analyzer can split
the artefact back into its parts.

Each command is wrapped in its own `try/except: pass`. A missing binary on a
minimal distro leaves one empty section; it never fails the backup.

### 1.1 Config files

Read by [`drivers/linux.py`](../drivers/linux.py) in a single loop:

`/etc/os-release` · `/etc/ssh/sshd_config` · `/etc/login.defs` ·
`/etc/sysctl.conf` · `/etc/fstab` · `/etc/hosts` · `/etc/resolv.conf` ·
`/etc/passwd` · `/etc/group`

**`/etc/shadow` is deliberately absent.** Password hashes must not enter an
artefact that is archived, re-read by the analyzer, and passed to an LLM. The
privileged tier still checks its *permissions* via `stat`, which is what the
CIS rule actually needs.

### 1.2 Unprivileged commands

Always run. Nothing here needs root.

| Command | Section | Config Analyzer view |
|---|---|---|
| `hostname` | `HOSTNAME` | System |
| `uname -srm` | `UNAME` | System — kernel, architecture |
| `uptime -p` / `uptime -s` | `UPTIME` / `BOOT TIME` | System |
| `ip -br a` | `IP ADDRESS` | Interfaces — state, addresses |
| `ip -s link` | `LINK STATS` | Interfaces (MTU) + Interface counters |
| sysfs `speed`/`duplex` loop | `LINK SPEED` | Interfaces |
| `ip route` | `IP ROUTE` | Routing |
| `lsblk` / `lsblk -dno NAME,MODEL,SERIAL,SIZE` | `LSBLK` / `DISKS` | Physical disks |
| `lscpu` | `LSCPU` | Hardware |
| `df -hT` | `DF` | Disks and mounts (merged with `fstab`) |
| `systemctl --failed` | `SYSTEMCTL FAILED` | Failed services |
| `systemctl list-unit-files --state=enabled` | `SYSTEMCTL ENABLED` | Enabled services |
| `ss -tuln` | `LISTENING SOCKETS` | Listening ports |
| `docker ps --format '…'` | `CONTAINERS` | Containers |
| `docker version` / `kubelet --version` | `DOCKER VERSION` / `KUBELET VERSION` | System |
| `lldpctl` | `SHOW LLDP NEIGHBORS` | topology map (shared parser) |

Notes that are easy to get wrong twice:

- **Speed and duplex come from `/sys/class/net`, not `ethtool`.** Same values,
  no package to install, no privilege. The kernel writes `-1` on an interface
  with no link — that is a "don't know", not a speed, and is shown blank.
- **`docker ps` output is tab-separated on purpose.** `STATUS` is `Up 3 hours`
  and `PORTS` contains `, ` — splitting on whitespace would break two columns
  of four.
- **`kubelet --version`, not `kubectl`.** `kubectl` needs a kubeconfig readable
  by this session, which on a worker node it usually is not. `kubelet` is on
  every cluster node.
- **Container commands sit in the unprivileged tier** because an operator in the
  `docker` group sees them without sudo — and with sudo the session is root
  anyway.

### 1.3 Privileged commands

Gated on `if secret:` — the operator has stored the sudo password as *Enable
Secret*. netmiko translates `enable()` into `sudo -s`, so these run as root.

| Command | Section | View |
|---|---|---|
| `ss -tulpn` | `LISTENING SOCKETS PID` | Listening ports — adds the process |
| `stat` on `/etc/shadow`, `/etc/passwd`, `/etc/group` | `FILE PERMISSIONS` | NetSec Audit |
| `sshd -T` | `SSHD EFFECTIVE CONFIG` | SSH — wins over the file (honours `Include`) |
| `cat /etc/sudoers /etc/sudoers.d/*` | `SUDOERS` | Sudoers |
| `dmidecode -s …` | `DMIDECODE` | Hardware — manufacturer, model, serial, BIOS |
| `dmidecode -t 17` | `MEMORY DEVICES` | Memory modules |
| `nft list ruleset \|\| iptables -S` | `FIREWALL RULES` | Host firewall |

Without a sudo password those sections are simply empty, and the views that
depend on them show nothing. That is the correct outcome: an empty Sudoers
table means "not collected", and the audit distinguishes that from "collected
and empty" per file.

### 1.4 ANSI escapes

systemd colourises `enabled`; netmiko strips only an enumerated list of escape
sequences, not the general CSI form. Without help those codes end up inside the
artefact and from there in the UI tables. `sanitize_session()`
([drivers/linux.py](../drivers/linux.py)) extends netmiko's own hook to strip
OSC *and* generic CSI, so every command on the session is clean — including the
prompt netmiko uses to detect end-of-command.

---

## 2. Derived facts

Read back out of the artefact by other parts of the app:

| Fact | Source | Where it shows |
|---|---|---|
| Hostname | `--- HOSTNAME ---`, written as `hostname <name>` so the existing regex finds it | inventory |
| Version | `get_version()` — `PRETTY_NAME` + kernel | inventory, NIST NVD lookup |
| **Model** | `dmidecode -s system-product-name`, else `lscpu` → `Hypervisor vendor` as `VM (VMware)`, else empty | inventory *Modello* |
| Device category | `classify_device_type()` maps `linux`/`ubuntu`/`debian`/`proxmox` → `server` | map, inventory |
| CIS verdicts | `netsec_audit.linux_rules` over the same sections | NetSec Audit |

**The model is not `lscpu`'s `Model:`.** That field is the CPU's model number
(e.g. `186`), and the Cisco pattern `^\s*Model\s*:` used to match it, putting a
bare integer in the inventory where the machine belongs. The Linux branch is
keyed on `/etc/os-release` being present and runs before the Cisco patterns.
SMBIOS placeholders (`To Be Filled By O.E.M.`, `Not Specified`, …) count as
absent.

---

## 3. What the poller collects

See [collectors.md](collectors.md) §7b for the full contract. In short: one
command per round, `cpu_pct` / `memory_pct` / `disk_pct` / `load1` / `load5` /
`load15` / `zombies` / `pending_updates` under `metrics`, and `kernel` /
`uptime_s` / `failed_units` under `results`.

`pending_updates` asks both `apt-get -s upgrade` and `dnf list --upgrades` and
keeps the larger count: the absent package manager prints nothing and `grep -c`
answers 0. Both are wrapped in `timeout 5` — the whole probe shares a 30-second
read budget, and an apt call hanging on a slow mirror would take CPU, memory and
disk down with it.

---

## 4. Deliberately not collected

| Not collected | Why |
|---|---|
| `journalctl`, `dmesg`, `auth.log` | The artefact is archived and fed to an LLM. Auth logs carry usernames, source IPs and occasionally a password typed at a prompt. Logs belong to the on-demand triage path. |
| Full package list (`dpkg -l`) | Thousands of lines per backup for a signal the *count of pending updates* already answers. |
| Top CPU / memory processes | Churny strings. `normalize` filters `metrics` to `int`/`float`, so they would be stored every round and read by nothing. |
| `smartctl`, RAID status | Root-only, hardware-specific, high variance. Deferred until a host needs it. |
| `podman ps` | A fourth container command with its own semantics. Add it when a host actually runs it. |
| Bonding / teaming | Niche; `/proc/net/bonding/*` if it ever matters. |

---

## 5. Adding a section

1. A command and its `--- TAG ---` in the `linux` branch of the extra-command
   chain ([core_engine.py](../core/core_engine.py)) — unprivileged list, or the
   `if secret:` block.
2. A `_xxx_rows()` parser plus a `_section("id", columns, rows)` entry in
   [ai/linux_analyzer.py](../ai/linux_analyzer.py). Tolerant: a malformed line
   is skipped, a missing section yields an empty table, never an exception.
3. `srv.sec.<id>`, `srv.col.<key>` and `srv.help.<id>` in both languages in
   [static/js/i18n.js](../static/js/i18n.js).
4. Nothing in the renderer: `caRenderEnvelopeView` is generic over `sections`,
   and picks up the help line by swapping `.sec.` for `.help.` in the label key.

Existing backups do not gain the new section — the parser keys off a marker that
older artefacts do not contain. The host has to be backed up again.
