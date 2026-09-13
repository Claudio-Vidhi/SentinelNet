# Windows server collection

What SentinelNet reads off a managed Windows host, how it gets there, and which
view shows it. The Linux counterpart is
[server-collection.md](server-collection.md), and the shapes are deliberately
the same — a driver, an artefact of `--- <section> ---` markers, an analyzer
that turns it into the existing envelope.

---

## 1. Why SSH and not WinRM

WinRM is the obvious answer and it is not the one taken here.

Windows has shipped an **OpenSSH server** as an optional feature since Windows
10 and Server 2019. Using it means the netmiko transport already used for every
switch, firewall and Linux host reaches a Windows host too, which buys:

- **no new dependency.** `pywinrm` brings an authentication stack with it —
  NTLM, Kerberos, or CredSSP, the last of which forwards the caller's
  credentials to the target and is its own security conversation.
- **no second remote-execution path to secure.** The CLI blacklist
  (`security/command_policy.py`), the audited admin bypass, the credential
  resolution in `core_engine.get_device_credentials` and the jump-host
  transport all apply unchanged, because there is only one way commands leave
  this product.
- **one artefact format**, so the NetSec Audit, the Config Analyzer, search and
  the AI assistant read a Windows host with the code they already have.

**The cost is on the customer side, and it is real:** the OpenSSH feature has
to be installed and its service started on each host, where WinRM is already on
in a domain. That is a deployment note, not a code problem — and it buys back a
whole authentication surface.

```powershell
# Su ogni host da gestire, una volta, come amministratore:
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
# La regola di firewall la crea l'installazione della capability; verificarla:
Get-NetFirewallRule -Name *ssh*
```

In inventory the device is a normal row with `Vendor` = `windows` (the aliases
`win`, `windows server`, `winsrv` and `microsoft` normalise to it). Port 22
unless the SSH server was moved.

---

## 2. Why the artefact is pipe-delimited

**Windows command output is localised.** `net user`, `sc query` and `wmic`
print their column headers and their state words in the system language: a
parser written against an English box reads nothing on an Italian one, and
worse, reads it *wrongly* on a language close enough to almost match.

So no command in `drivers/windows.py` prints a table. Each one builds its own
line from object **properties**, joined with `|`:

```powershell
Get-NetAdapter | ForEach-Object {
  [string]$_.Name + '|' + [string]$_.Status + '|' + [string]$_.LinkSpeed }
```

The enum names PowerShell returns (`Up`, `Running`, `Automatic`) are
culture-independent, the header row is gone, and the parser has no table
geometry to guess. `services/netsec_audit/linux_parser.parse_linux` — a generic
`--- marker ---` splitter despite its name — does the section splitting, and
`ai/windows_analyzer.py` only has to split on `|`.

**Every script uses single quotes inside.** The command travels as one
double-quoted argument to `powershell -Command`, through the local shell,
netmiko and cmd.exe. A double quote inside would have to survive all three;
concatenation with `+ '|' +` needs no escaping anywhere, and what is written in
the driver is exactly what runs. `tests/test_windows_driver.py` asserts that no
command contains an inner double quote.

Two flags on every invocation: `-NoProfile`, so a customised profile does not
print a banner into the artefact, and `-NonInteractive`, so an unexpected
prompt fails instead of hanging the session until the read timeout.

---

## 3. No privileged tier

Linux has one: `Enable Secret` doubles as the sudo password and unlocks a
root-only command tier. **Windows has no equivalent.** There is no sudo, and an
SSH session is either elevated or it is not.

`core_engine.maybe_enable` therefore never calls `enable()` for this platform —
not even when an Enable Secret is set, because on this vendor it means nothing
and netmiko would send an enable command that lands in the output as text.

The consequence for the operator: with a non-administrator account the sections
that need administrator come back empty. The firewall profiles and the SMB
server configuration are the two that do. **An empty section is dropped, not
shown empty**, so the card does not offer a pill that leads to an empty table.

---

## 4. What each section feeds

| Section | Command source | Shown as |
|---|---|---|
| `HOSTNAME` | `[System.Net.Dns]::GetHostName()` | the device hostname in inventory (written as `hostname <name>`, the same form the Linux driver uses, so `extract_hostname_from_config` reads it — the `C:\Users\admin>` prompt would not give a usable name) |
| `OS INFO`, `COMPUTER INFO` | `Win32_OperatingSystem`, `Win32_ComputerSystem` | **Sistema**: edition, build, architecture, domain or workgroup, memory, boot time |
| `BIOS`, `CPU` | `Win32_BIOS`, `Win32_Processor` | **Hardware** |
| `NET ADAPTERS`, `IP ADDRESSES` | `Get-NetAdapter`, `Get-NetIPAddress` | **Interfacce**, joined on the interface alias |
| `NET ROUTES` | `Get-NetRoute` | **Routing** |
| `LISTENING PORTS` | `Get-NetTCPConnection -State Listen` | **Porte in ascolto**. The PID is resolved to a process name on the host: on its own a PID tells the reader nothing |
| `SERVICES DOWN` | automatic services not running | **Servizi non avviati** — the equivalent of `systemctl --failed`; an empty table is the normal condition |
| `SERVICES AUTO` | every automatic service | **Servizi automatici** |
| `LOCAL USERS`, `LOCAL GROUPS` | `Get-LocalUser`, `Get-LocalGroup` | **Utenti / Gruppi locali** |
| `LOCAL ADMINS` | `Get-LocalGroupMember -Group Administrators` | **Amministratori locali** — the counterpart of sudoers, and the first question anyone asks about a Windows server |
| `DISKS`, `VOLUMES` | `Win32_DiskDrive`, `Win32_LogicalDisk` | **Dischi fisici**, **Volumi** |
| `FIREWALL PROFILES` | `Get-NetFirewallProfile` | **Firewall host**. A disabled profile is the finding: the rules under it stop applying. *Needs administrator* |
| `REMOTE ACCESS`, `SMB CONFIG` | Terminal Server registry keys, `Get-SmbServerConfiguration` | **Accesso remoto** — the counterpart of `sshd_config`: whether RDP is open, whether it demands NLA, and whether SMBv1 is still on and signing required. *SMB needs administrator* |
| `SMB SHARES` | `Get-SmbShare` | **Condivisioni SMB**. The administrative shares (`C$`, `ADMIN$`) appear here: normal, but read them next to the port exposure |
| `C:\Windows\System32\drivers\etc\hosts` | the backup command | the one real configuration *file* worth carrying — everything else on this platform is a service or a registry value, not a file to diff |

---

## 5. Deliberately not collected

- **Installed updates and pending reboots.** `Get-HotFix` lists what was
  installed, not what is missing, so it answers a question nobody asked;
  "missing updates" needs the WSUS / Windows Update API and is a feature of its
  own.
- **The password policy.** `net accounts` prints localised labels, which is
  exactly the trap §2 exists to avoid, and `secedit /export` needs
  administrator and writes a file on the host. A deliberate gap, not an
  oversight.
- **Event logs.** They are a stream, not state: the same argument that keeps
  time-varying numbers out of the Linux artefact. Central syslog is the right
  path, and Windows can forward to it.
- **CIS Windows audit rules.** The NetSec Audit has no Windows mappings yet, so
  selecting a benchmark against a Windows artefact yields an empty report —
  the same situation as NIST/PCI on Linux. Deliberate, and stated here rather
  than silently returning an empty verdict.

---

## 6. What has not been verified

**No Windows host has run this.** The command *shapes* are tested (no nested
quotes, `-NoProfile -NonInteractive` everywhere, the sections the analyzer
reads), and the analyzer is tested against a realistic artefact. That
PowerShell answers as expected on a real machine — and that netmiko's `generic`
driver reads the cmd.exe prompt cleanly — is still to be proven on hardware,
like the FortiGate HA member parsing.

Do the first real run on a host whose session you can afford to lose: the worst
case is a command that hangs until its read timeout, twenty times over.

---

## 7. Adding a section

1. One entry in `TRIAGE_COMMANDS` in `drivers/windows.py` — build the line from
   object properties with `_fields(...)`, never from a printed table.
2. One `_*_rows()` in `ai/windows_analyzer.py` and one `_section(...)` in
   `_analyze`. Reuse the existing `srv.col.*` column keys: a column called
   "Nome" is the same column on either platform.
3. Two i18n keys, `srv.sec.win_<id>` and `srv.help.win_<id>`, in **both**
   dictionaries. The Config Analyzer derives the help line from the label key,
   so a missing help text silently shows nothing.
4. A case in `tests/test_windows_driver.py` against the artefact fixture.
