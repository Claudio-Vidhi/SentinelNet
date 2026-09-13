# -*- coding: utf-8 -*-
"""Windows driver, over SSH.

WHY SSH AND NOT WinRM — Windows ships an OpenSSH *server* as an optional
feature since Windows 10 / Server 2019, so the netmiko transport this product
already uses for every other device reaches a Windows host with no new
dependency, no second remote-execution path to secure (the CLI blacklist, the
audited admin bypass, the identity resolution and the jump-host transport all
apply unchanged) and one artefact format. The cost moves to the customer side:
the OpenSSH feature has to be installed and the service started, where WinRM
is already on in a domain. That is a deployment note, not a code problem.

WHY THE ARTEFACT IS PIPE-DELIMITED — Windows command output is LOCALISED.
``net user``, ``sc query`` and ``wmic`` print column headers and state words in
the system language, so a parser written against an English box reads nothing
on an Italian one. Every command here therefore builds its own line from
object PROPERTIES joined with '|': the enum names PowerShell returns ('Up',
'Running', 'Automatic', 'AzureAD') are culture-independent, the header row is
gone, and the parser has no table geometry to guess.

The one exception found on a real Italian host is ``ObjectClass`` on a group
member, which comes back as 'Utente'/'Altro'. It is carried as a display
value and nothing compares it; the rule to keep is that a value only gets
compared in code once it has been seen to be an enum name.

WHY EVERY SCRIPT USES SINGLE QUOTES INSIDE — the command travels as one
double-quoted argument to ``powershell -Command`` over an SSH channel. A
double quote inside it would have to survive the local shell, netmiko and
cmd.exe; string concatenation with ``+ '|' +`` needs no escaping anywhere, and
what is written here is exactly what runs.

The ``--- <section> ---`` markers are the same form ``drivers/linux.py`` writes
and ``netsec_audit.linux_parser`` already splits.

NO PRIVILEGED TIER — the `Enable Secret` that unlocks the root-only Linux tier
has no equivalent here: Windows has no sudo, and an SSH session is either
elevated or it is not (see ``core_engine.maybe_enable``). A non-administrator
account simply gets empty sections where the command needs administrator (the
SMB server configuration, the firewall profiles), and an empty section is the
normal empty state everywhere else in this product too.
"""

import re

from drivers.base_driver import BaseDriver

# One PowerShell per command: -NoProfile keeps a customised profile from
# printing a banner into the artefact, -NonInteractive makes a prompt fail
# instead of hanging the session until the read timeout.
_PS = 'powershell -NoProfile -NonInteractive -Command'


def ps(script: str) -> str:
    """Wraps a PowerShell one-liner to run from cmd.exe, the OpenSSH default.

    It does NOT work with PowerShell configured as the SSH default shell: the
    outer PowerShell expands ``$o`` inside the double quotes before the inner
    one runs, and every command arrives broken (seen on a real host). See
    prepare_session.
    """
    return f'{_PS} "{script}"'


# The one real configuration FILE worth carrying: everything else on this
# platform is a service or a registry setting, not a file to diff.
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"

_SERIAL_PLACEHOLDERS = ("to be filled", "system serial", "default string",
                        "none", "not specified", "o.e.m.")

# Registry path of the Terminal Server settings, doubled for the PowerShell
# string literal it lands in.
_TS_KEY = r"HKLM:\System\CurrentControlSet\Control\Terminal Server"


def _fields(obj: str, *props: str) -> str:
    """``$_.A + '|' + $_.B`` — one artefact line per object, no quotes to escape."""
    return (" + '|' + ".join(f"[string]${obj}.{p}" for p in props))


# The triage command chain, as data. It lives with the driver and not inside
# core_engine because it is vendor logic: core_engine only walks the list.
#
# Every section is one table in the Config Analyzer (see ai/windows_analyzer).
TRIAGE_COMMANDS = (
    # Written as `hostname <name>`, like the Linux driver does, so
    # extract_hostname_from_config recognises it: the Windows prompt
    # ('C:\\Users\\admin>') would not give it a usable name.
    (ps("'hostname ' + [System.Net.Dns]::GetHostName()"),
     "--- HOSTNAME ---"),
    (ps("$o = Get-CimInstance Win32_OperatingSystem; "
        + _fields("o", "Caption", "Version", "BuildNumber", "OSArchitecture",
                  "InstallDate", "LastBootUpTime")),
     "--- OS INFO ---"),
    (ps("$c = Get-CimInstance Win32_ComputerSystem; "
        + _fields("c", "Manufacturer", "Model", "Domain", "PartOfDomain",
                  "TotalPhysicalMemory", "NumberOfLogicalProcessors")),
     "--- COMPUTER INFO ---"),
    (ps("$b = Get-CimInstance Win32_BIOS; "
        + _fields("b", "Manufacturer", "SMBIOSBIOSVersion", "ReleaseDate",
                  "SerialNumber")),
     "--- BIOS ---"),
    (ps("Get-CimInstance Win32_Processor | ForEach-Object { "
        + _fields("_", "Name", "NumberOfCores", "NumberOfLogicalProcessors",
                  "MaxClockSpeed") + " }"),
     "--- CPU ---"),
    # Get-NetAdapter / -NetIPAddress / -NetRoute ship with Windows 8 and
    # Server 2012: no module to install on the customer's host.
    (ps("Get-NetAdapter | ForEach-Object { "
        + _fields("_", "Name", "InterfaceDescription", "Status", "LinkSpeed",
                  "MacAddress", "MtuSize") + " }"),
     "--- NET ADAPTERS ---"),
    (ps("Get-NetIPAddress | ForEach-Object { "
        + _fields("_", "InterfaceAlias", "IPAddress", "PrefixLength",
                  "AddressFamily", "PrefixOrigin") + " }"),
     "--- IP ADDRESSES ---"),
    (ps("Get-NetRoute | ForEach-Object { "
        + _fields("_", "DestinationPrefix", "NextHop", "InterfaceAlias",
                  "RouteMetric") + " }"),
     "--- NET ROUTES ---"),
    # The PID is resolved to a process name here, not in the parser: on its
    # own a PID tells the reader nothing.
    (ps("Get-NetTCPConnection -State Listen | ForEach-Object { "
        "$p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue)"
        ".ProcessName; 'TCP|' + "
        + _fields("_", "LocalAddress", "LocalPort", "OwningProcess")
        + " + '|' + [string]$p }"),
     "--- LISTENING PORTS ---"),
    # Services that should start by themselves and are not running: the
    # equivalent of `systemctl --failed`, and the only service list worth
    # opening first.
    (ps("Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and "
        "$_.Status -ne 'Running' } | ForEach-Object { "
        + _fields("_", "Name", "DisplayName", "Status", "StartType") + " }"),
     "--- SERVICES DOWN ---"),
    (ps("Get-Service | Where-Object { $_.StartType -eq 'Automatic' } | "
        "ForEach-Object { "
        + _fields("_", "Name", "DisplayName", "Status", "StartType") + " }"),
     "--- SERVICES AUTO ---"),
    (ps("Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object { "
        + _fields("_", "Name", "Enabled", "PasswordExpires",
                  "PasswordRequired", "LastLogon", "Description") + " }"),
     "--- LOCAL USERS ---"),
    (ps("Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object { "
        "$m = (Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue | "
        "ForEach-Object { $_.Name }) -join ','; "
        + _fields("_", "Name") + " + '|' + [string]$m }"),
     "--- LOCAL GROUPS ---"),
    # Who is a local administrator: the equivalent of sudoers, and the first
    # question anyone asks about a Windows server.
    #
    # By WELL-KNOWN SID and not by the name 'Administrators': the built-in
    # group can be renamed, and on some localised installations it is. The SID
    # S-1-5-32-544 is the same on every Windows ever shipped.
    #
    # ObjectClass is the ONE property here that comes back localised ('Utente'
    # / 'Altro' on an Italian host, where PrincipalSource stays 'AzureAD'):
    # it is display-only, and nothing in the analyzer compares it.
    (ps("Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue"
        " | ForEach-Object { "
        + _fields("_", "Name", "ObjectClass", "PrincipalSource") + " }"),
     "--- LOCAL ADMINS ---"),
    (ps("Get-CimInstance Win32_DiskDrive | ForEach-Object { "
        + _fields("_", "DeviceID", "Model", "SerialNumber", "Size") + " }"),
     "--- DISKS ---"),
    (ps("Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | "
        "ForEach-Object { "
        + _fields("_", "DeviceID", "VolumeName", "FileSystem", "Size",
                  "FreeSpace") + " }"),
     "--- VOLUMES ---"),
    (ps("Get-NetFirewallProfile -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        + _fields("_", "Name", "Enabled", "DefaultInboundAction",
                  "DefaultOutboundAction", "LogAllowed") + " }"),
     "--- FIREWALL PROFILES ---"),
    # Remote access: the counterpart of sshd_config. The three registry
    # values say whether RDP is open, whether it demands NLA, and at which
    # security layer.
    (ps("$t = '" + _TS_KEY + "'; "
        "$d = (Get-ItemProperty $t -Name fDenyTSConnections -ErrorAction "
        "SilentlyContinue).fDenyTSConnections; "
        "$r = Get-ItemProperty ($t + '\\WinStations\\RDP-Tcp') -ErrorAction "
        "SilentlyContinue; "
        "'rdp_enabled|' + [string]($d -eq 0); "
        "'rdp_nla|' + [string]$r.UserAuthentication; "
        "'rdp_security_layer|' + [string]$r.SecurityLayer; "
        "'rdp_port|' + [string]$r.PortNumber"),
     "--- REMOTE ACCESS ---"),
    # SMBv1 still enabled and signing not required are the two classic
    # findings on a Windows server, and they come from one command. Needs
    # administrator: without it the section stays empty rather than lying.
    (ps("$s = Get-SmbServerConfiguration -ErrorAction SilentlyContinue; "
        "'smb1_enabled|' + [string]$s.EnableSMB1Protocol; "
        "'smb_signing_required|' + [string]$s.RequireSecuritySignature; "
        "'smb_encrypt_data|' + [string]$s.EncryptData"),
     "--- SMB CONFIG ---"),
    (ps("Get-SmbShare -ErrorAction SilentlyContinue | ForEach-Object { "
        + _fields("_", "Name", "Path", "Description") + " }"),
     "--- SMB SHARES ---"),
)


_CURSOR_POSITION = re.compile(r"\x1b\[(?:\d+(?:;\d+)?)?H")
_CURSOR_FORWARD = re.compile(r"\x1b\[(\d*)C")


def prepare_session(net_connect):
    """Makes a netmiko 'generic' session usable against cmd.exe behind ConPTY.

    Seen on a real Windows 11 session (tests/test_windows_transport.py):

    - ConPTY opens with mode switches, a screen clear and an OSC window title,
      and repeats the title after every prompt. Netmiko 'generic' strips no
      escape codes at all, so the last line never ends in '>' and the prompt
      comes back empty. The Linux cleanup handles both CSI and OSC forms.
    - A bare LF does not submit a line; CR does. With netmiko's default
      RETURN of '\\n' every command sat unexecuted until the read timeout.

    Requires cmd.exe as the SSH default shell. With PowerShell as default
    shell the command line is re-expanded (``$o`` becomes empty) and PSReadLine
    repaints the echo, and no amount of cleanup here fixes that.
    """
    from drivers.linux import sanitize_session
    net_connect.RETURN = "\r\n"
    net_connect.ansi_escape_codes = True
    # ConPTY also replaces line breaks with cursor moves where it can: a
    # skipped line becomes ESC[<row>;<col>H, a run of spaces ESC[<n>C. Deleted
    # like any other escape, they glued an output line onto the prompt (and
    # netmiko then stripped it as the prompt: HOSTNAME came back empty). They
    # are turned back into what they stand for BEFORE the generic cleanup.
    generic = net_connect.strip_ansi_escape_codes
    net_connect.strip_ansi_escape_codes = lambda text: generic(
        _CURSOR_FORWARD.sub(lambda m: " " * int(m.group(1) or 1),
                            _CURSOR_POSITION.sub("\n", text)))
    sanitize_session(net_connect)


class WindowsDriver(BaseDriver):
    def get_version(self):
        out = self.connection.send_command(ps(
            "$o = Get-CimInstance Win32_OperatingSystem; "
            + _fields("o", "Caption", "Version", "OSArchitecture")))
        rows = [p.strip() for p in (out or "").splitlines() if "|" in p]
        if not rows:
            return "Unknown"
        caption, _, rest = rows[-1].partition("|")
        version, _, arch = rest.partition("|")
        caption = re.sub(r"^Microsoft\s+", "", caption.strip())
        if not caption:
            return "Unknown"
        # "Windows Server 2022 Standard (10.0.20348, 64-bit)" — the build
        # identifies the patch level, so it is not dropped.
        extra = ", ".join(p for p in (version.strip(), arch.strip()) if p)
        return f"{caption} ({extra})" if extra else caption

    def get_model(self):
        out = self.connection.send_command(ps(
            "$c = Get-CimInstance Win32_ComputerSystem; "
            + _fields("c", "Manufacturer", "Model")))
        for line in reversed((out or "").splitlines()):
            if "|" not in line:
                continue
            manufacturer, _, model = line.strip().partition("|")
            model = model.strip()
            # On a VM the model is the hypervisor's own string ("Virtual
            # Machine"): still true, and more useful than "Non Rilevato".
            if model:
                return f"{manufacturer.strip()} {model}".strip()
        return "Non Rilevato"

    def get_serial(self):
        out = self.connection.send_command(ps(
            "(Get-CimInstance Win32_BIOS).SerialNumber"))
        for line in reversed((out or "").splitlines()):
            candidate = line.strip()
            if not candidate:
                continue
            # Hypervisors and some OEMs return a placeholder: reporting it
            # would put "To be filled by O.E.M." in the inventory as if it
            # were a serial number.
            if any(p in candidate.lower() for p in _SERIAL_PLACEHOLDERS):
                continue
            return candidate
        return ""

    def get_backup_command(self):
        return ps("'--- " + HOSTS_FILE + " ---'; "
                  "Get-Content -ErrorAction SilentlyContinue '"
                  + HOSTS_FILE + "'")
