# -*- coding: utf-8 -*-
"""Switch Provisioner — genera una running-config Cisco IOS/IOS-XE "da zero"
per uno switch appena installato, seguendo le linee guida di hardening Cisco,
e la consegna in tre modalita' selezionabili dall'utente:

  1. Solo testo (view/copy/download .txt)
  2. Push via SSH su un apparato raggiungibile (riusa Netmiko, come core_engine)
  3. Push via console/serial (pyserial) per il provisioning "day-0" senza rete

Il modulo e' volutamente semplice: ``build_config`` e' una funzione pura
(nessun I/O) che assembla la config come testo a partire da un dict di
parametri; ``push_via_ssh``/``push_via_serial`` si occupano della consegna.
"""

import time

from security import redaction

ROLES = ("access", "distribution")


def _expand_vlan_ids(vlans):
    """Normalizza la lista VLAN: accetta [{'id':10,'name':'DATA'}, ...] oppure
    [10, 20]. Ritorna sempre una lista di dict {'id': int, 'name': str}."""
    out = []
    for v in vlans or []:
        if isinstance(v, dict):
            vid = v.get("id")
            name = v.get("name") or f"VLAN{vid}"
        else:
            vid, name = v, f"VLAN{v}"
        if vid is None:
            continue
        out.append({"id": int(vid), "name": str(name)})
    return out


def build_config(cfg: dict) -> str:
    """Costruisce la running-config IOS/IOS-XE completa a partire da ``cfg``.

    Chiavi principali attese (tutte opzionali salvo dove indicato):
      hostname (str, richiesto), domain (str)
      mgmt_vlan (int), mgmt_ip (str), mgmt_mask (str), mgmt_gw (str)
      admin_user (str), admin_password (str), enable_secret (str)
      ssh_only (bool)               -> transport input ssh + crypto key gen
      banner (str)
      ntp_servers (list[str])
      syslog_server (str)
      snmpv3 (dict: user, auth_pass, priv_pass, group)
      vlans (list)                  -> vedi _expand_vlan_ids
      vtp_mode (str, default "transparent")
      stp_mode (str, default "rapid-pvst")
      bpduguard (bool, default True su edge/access)
      port_security (bool)
      dhcp_snooping (bool)
      dhcp_snooping_vlans (str, es. "10,20")
      cdp_enabled (bool, default True)
      lldp_enabled (bool, default True)
      role (str: "access" | "distribution", default "access")
      access_ports (list[str])      -> range interfacce, es. ["GigabitEthernet1/0/1-24"]
      access_vlan (int)             -> vlan dati di default sulle porte access
      trunk_ports (list[str])
      trunk_allowed_vlans (str)     -> es. "10,20,30"
      uplink_pc_id (int)            -> aggrega le porte trunk in Port-channelN (LACP active)
      login_block (bool, default True)      -> login block-for anti brute-force
      storm_control (bool)                  -> storm-control broadcast sulle porte access
      errdisable_recovery (bool, default True) -> auto-recovery da bpduguard/port-security
      no_vstack (bool, default True)        -> disabilita Smart Install (no vstack)
      svis (list[dict])             -> [{'vlan':10,'ip':'10.1.10.1','mask':'255.255.255.0'}]
      enable_routing (bool)         -> "ip routing" (solo role=distribution)
      default_route_gw (str)
    """
    hostname = (cfg.get("hostname") or "Switch").strip()
    role = cfg.get("role") or "access"
    lines = []

    def sec(title):
        lines.append("!")
        lines.append(f"! --- {title} ---")

    lines.append("no service pad")
    lines.append("service password-encryption")
    lines.append("service timestamps debug datetime msec localtime")
    lines.append("service timestamps log datetime msec localtime")
    lines.append("service tcp-keepalives-in")
    lines.append("service tcp-keepalives-out")
    lines.append("!")
    lines.append(f"hostname {hostname}")
    lines.append("!")
    lines.append("no ip domain-lookup")
    ssh_only = cfg.get("ssh_only", True)
    if cfg.get("domain") or ssh_only:
        # 'crypto key generate rsa' below refuses to run without a domain name.
        # Emitting it only when the operator typed one left the SSH-only path
        # with no host key AND telnet already disabled: console-only device.
        lines.append(f"ip domain-name {cfg.get('domain') or 'local'}")
    lines.append("no ip http server")
    lines.append("no ip http secure-server")
    if cfg.get("no_vstack", True):
        # Smart Install (vstack) e' un noto vettore d'attacco: va disabilitato.
        # Sui modelli che non lo supportano il comando viene semplicemente rifiutato.
        lines.append("no vstack")

    sec("AUTENTICAZIONE LOCALE / ENABLE")
    if cfg.get("enable_secret"):
        lines.append(f"enable secret {cfg['enable_secret']}")
    # No fallback password here on purpose: 'changeme' was a known credential
    # pushed to real hardware whenever the field was left empty. The boundary
    # (SwitchProvisionSchema) now rejects an empty user or password, so an
    # absent one here means a direct caller, not an operator.
    if cfg.get("admin_user") and cfg.get("admin_password"):
        lines.append(
            f"username {cfg['admin_user']} privilege 15 secret {cfg['admin_password']}")
    lines.append("aaa new-model")

    aaa_protocol = cfg.get("aaa_protocol") or "none"
    aaa_servers = cfg.get("aaa_servers") or []
    if aaa_protocol in ("radius", "tacacs") and aaa_servers:
        proto_label = "radius" if aaa_protocol == "radius" else "tacacs+"
        server_type = "radius server" if aaa_protocol == "radius" else "tacacs server"
        server_names = []
        sec(f"AAA {'RADIUS' if aaa_protocol == 'radius' else 'TACACS+'}")
        for i, srv in enumerate(aaa_servers, 1):
            name = f"{'RADIUS' if aaa_protocol == 'radius' else 'TACACS'}-{i}"
            server_names.append(name)
            lines.append(f"{server_type} {name}")
            if aaa_protocol == "radius":
                auth_port = srv.get("auth_port") or 1812
                acct_port = srv.get("acct_port") or 1813
                lines.append(f" address ipv4 {srv['ip']} auth-port {auth_port} acct-port {acct_port}")
            else:
                lines.append(f" address ipv4 {srv['ip']}")
            if srv.get("key"):
                lines.append(f" key {srv['key']}")
        lines.append(f"aaa group server {proto_label} SENTINEL-AAA")
        for name in server_names:
            lines.append(f" server name {name}")
        lines.append("aaa authentication login default group SENTINEL-AAA local")
        lines.append("aaa authorization exec default group SENTINEL-AAA local")
    else:
        lines.append("aaa authentication login default local")
        lines.append("aaa authorization exec default local")

    if cfg.get("login_block", True):
        # Anti brute-force: dopo 5 tentativi falliti in 60s blocca i login per 120s.
        lines.append("login block-for 120 attempts 5 within 60")
        lines.append("login on-failure log")
        lines.append("login on-success log")

    if ssh_only:
        sec("SSH-ONLY MANAGEMENT")
        lines.append("crypto key generate rsa modulus 2048")
        lines.append("ip ssh version 2")
        lines.append("ip ssh time-out 60")
        lines.append("ip ssh authentication-retries 3")

    sec("VTP")
    lines.append(f"vtp mode {cfg.get('vtp_mode', 'transparent')}")

    vlans = _expand_vlan_ids(cfg.get("vlans"))
    # 'vtp mode transparent' above means a VLAN exists only if it is in the
    # local database. An SVI or an access port pointed at a VLAN nobody
    # declared comes up down/down — a day-0 switch with no management address,
    # or a floor of ports in an inactive VLAN. Declare what we are about to use.
    for vid, fallback_name in ((cfg.get("mgmt_vlan"), "MGMT"),
                               (cfg.get("access_vlan"), "DATA")):
        if vid and not any(int(v["id"]) == int(vid) for v in vlans):
            vlans.append({"id": int(vid), "name": fallback_name})
    if vlans:
        sec("VLAN DATABASE")
        for v in vlans:
            lines.append(f"vlan {v['id']}")
            lines.append(f" name {v['name']}")

    mgmt_vlan = cfg.get("mgmt_vlan")
    if mgmt_vlan:
        sec("INTERFACCIA DI MANAGEMENT")
        lines.append(f"interface Vlan{mgmt_vlan}")
        if cfg.get("mgmt_ip") and cfg.get("mgmt_mask"):
            lines.append(f" ip address {cfg['mgmt_ip']} {cfg['mgmt_mask']}")
        lines.append(" no shutdown")
        lines.append("exit")
        if cfg.get("mgmt_gw") and role == "access":
            lines.append(f"ip default-gateway {cfg['mgmt_gw']}")

    if role == "distribution":
        sec("ROUTING MINIMO (DISTRIBUTION/CORE)")
        if cfg.get("enable_routing", True):
            lines.append("ip routing")
        for svi in cfg.get("svis") or []:
            lines.append(f"interface Vlan{svi['vlan']}")
            lines.append(f" ip address {svi['ip']} {svi['mask']}")
            lines.append(" no shutdown")
            lines.append("exit")
        if cfg.get("default_route_gw"):
            lines.append(f"ip route 0.0.0.0 0.0.0.0 {cfg['default_route_gw']}")

    sec("SPANNING-TREE")
    stp_mode = cfg.get("stp_mode", "rapid-pvst")
    lines.append(f"spanning-tree mode {stp_mode}")
    lines.append("spanning-tree extend system-id")
    if cfg.get("bpduguard", True):
        lines.append("spanning-tree portfast bpduguard default")

    if cfg.get("errdisable_recovery", True):
        causes = []
        if cfg.get("bpduguard", True):
            causes.append("bpduguard")
        if cfg.get("port_security"):
            causes.append("psecure-violation")
        if cfg.get("storm_control"):
            causes.append("storm-control")
        if causes:
            sec("ERRDISABLE AUTO-RECOVERY")
            for c in causes:
                lines.append(f"errdisable recovery cause {c}")
            lines.append("errdisable recovery interval 300")

    if cfg.get("dhcp_snooping"):
        sec("DHCP SNOOPING")
        lines.append("ip dhcp snooping")
        if cfg.get("dhcp_snooping_vlans"):
            lines.append(f"ip dhcp snooping vlan {cfg['dhcp_snooping_vlans']}")
        lines.append("no ip dhcp snooping information option")

    sec("CDP / LLDP")
    if cfg.get("cdp_enabled", True):
        lines.append("cdp run")
    else:
        lines.append("no cdp run")
    if cfg.get("lldp_enabled", True):
        lines.append("lldp run")
    else:
        lines.append("no lldp run")

    access_ports = cfg.get("access_ports") or []
    if access_ports:
        sec("PORTE ACCESS (EDGE)")
        access_vlan = cfg.get("access_vlan")
        for rng in access_ports:
            lines.append(f"interface range {rng}")
            lines.append(" switchport mode access")
            if access_vlan:
                lines.append(f" switchport access vlan {access_vlan}")
            lines.append(" switchport nonegotiate")
            lines.append(" spanning-tree portfast")
            lines.append(" spanning-tree bpduguard enable")
            if cfg.get("port_security"):
                lines.append(" switchport port-security")
                lines.append(" switchport port-security maximum 2")
                lines.append(" switchport port-security violation restrict")
                lines.append(" switchport port-security aging time 2")
                lines.append(" switchport port-security aging type inactivity")
            if cfg.get("storm_control"):
                lines.append(" storm-control broadcast level 5.00")
                lines.append(" storm-control action trap")
            if cfg.get("dhcp_snooping"):
                lines.append(" ip dhcp snooping limit rate 15")
            lines.append(" no shutdown")
            lines.append("exit")

    trunk_ports = cfg.get("trunk_ports") or []
    if trunk_ports:
        sec("PORTE TRUNK (UPLINK)")
        allowed = cfg.get("trunk_allowed_vlans")
        pc_id = cfg.get("uplink_pc_id")
        for rng in trunk_ports:
            lines.append(f"interface range {rng}")
            # On 3560/3650/3750-class IOS a port whose trunk encapsulation is
            # 'auto' rejects 'switchport mode trunk' outright, leaving every
            # uplink an access port. 2960-class rejects this line harmlessly
            # instead — the same tolerance 'no vstack' above relies on.
            lines.append(" switchport trunk encapsulation dot1q")
            lines.append(" switchport mode trunk")
            if allowed:
                lines.append(f" switchport trunk allowed vlan {allowed}")
            lines.append(" switchport nonegotiate")
            if cfg.get("dhcp_snooping"):
                lines.append(" ip dhcp snooping trust")
            if pc_id:
                lines.append(f" channel-group {pc_id} mode active")
            lines.append(" no shutdown")
            lines.append("exit")
        if pc_id:
            # EtherChannel di uplink (LACP): l'interfaccia logica replica la
            # configurazione trunk dei membri.
            lines.append(f"interface Port-channel{pc_id}")
            lines.append(" switchport mode trunk")
            if allowed:
                lines.append(f" switchport trunk allowed vlan {allowed}")
            lines.append(" switchport nonegotiate")
            if cfg.get("dhcp_snooping"):
                lines.append(" ip dhcp snooping trust")
            lines.append(" no shutdown")
            lines.append("exit")

    if cfg.get("banner"):
        sec("BANNER")
        lines.append(f"banner motd ^C{cfg['banner']}^C")

    if cfg.get("ntp_servers"):
        sec("NTP")
        for srv in cfg["ntp_servers"]:
            lines.append(f"ntp server {srv}")

    sec("LOGGING")
    lines.append("logging buffered 16384")
    if cfg.get("syslog_server"):
        lines.append(f"logging host {cfg['syslog_server']}")
        lines.append("logging trap informational")
        lines.append("logging source-interface Vlan%s" % mgmt_vlan if mgmt_vlan else "logging on")

    snmpv3 = cfg.get("snmpv3") or {}
    # Both passphrases are required: 'authpass123'/'privpass123' used to be
    # substituted on an empty field, shipping a known credential to the device.
    # Emitting nothing is the safe half-answer; the boundary rejects the input.
    if snmpv3.get("user") and snmpv3.get("auth_pass") and snmpv3.get("priv_pass"):
        sec("SNMPv3")
        group = snmpv3.get("group", "SNMP-GROUP")
        lines.append(f"snmp-server group {group} v3 priv")
        auth_pass = snmpv3["auth_pass"]
        priv_pass = snmpv3["priv_pass"]
        lines.append(
            f"snmp-server user {snmpv3['user']} {group} v3 auth sha {auth_pass} "
            f"priv aes 128 {priv_pass}"
        )

    sec("HARDENING VTY / CONSOLE")
    lines.append("line con 0")
    lines.append(" login local")
    lines.append(" exec-timeout 5 0")
    lines.append("line vty 0 15")
    lines.append(" login local")
    lines.append(" exec-timeout 5 0")
    if ssh_only:
        lines.append(" transport input ssh")
    else:
        lines.append(" transport input ssh telnet")

    lines.append("!")
    lines.append("end")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CONSEGNA: SSH (Netmiko) e CONSOLE/SERIALE (pyserial)
# ---------------------------------------------------------------------------

# IOS never raises on a rejected command: it answers on the same session and
# carries on. Reporting 'success' on that meant a wrong interface range, or a
# rejected hardening line, looked identical to a clean push.
_CLI_ERRORS = ("% Invalid input", "% Incomplete command", "% Ambiguous command",
               "% Bad", "% Unrecognized", "Command rejected")


# Minutes the switch waits before rebooting into the saved config if this
# session never gets far enough to cancel it. Long enough for a slow push,
# short enough that an operator who cut the path is not stuck for an hour.
RELOAD_GUARD_MINUTES = 10


def _arm_reload(conn) -> bool:
    """Schedule 'reload in N' so a push that cuts its own path self-recovers.

    Returns whether it was armed: on a device that refuses the command there
    is nothing to cancel later, and the push proceeds without the net rather
    than failing over the safety measure itself.
    """
    try:
        out = str(conn.send_command_timing(f"reload in {RELOAD_GUARD_MINUTES}"))
        if "confirm" in out.lower() or "[yes/no]" in out.lower():
            # 'System configuration has been modified. Save? [yes/no]' first,
            # then 'Proceed with reload? [confirm]'. Never save here: saving is
            # what the reload is supposed to undo.
            if "yes/no" in out.lower():
                out += str(conn.send_command_timing("no"))
            conn.send_command_timing("\n")
        return "%" not in out
    except Exception:
        return False


def _push_result(output: str) -> dict:
    """Turn a raw session transcript into a push result.

    The transcript echoes every command back, so it also carries the secrets
    that were just typed: it is redacted before leaving this function, which
    is the single point every caller (router, MCP, tests) goes through.
    """
    rejected = [ln.strip() for ln in output.splitlines()
                if any(err in ln for err in _CLI_ERRORS)]
    return {
        "status": "partial" if rejected else "success",
        "output": redaction.redact(output),
        "rejected": redaction.redact(rejected),
    }


def push_via_ssh(host: str, username: str, password: str, secret: str,
                  config_text: str, port: int = 22, save: bool = True,
                  device_type: str = "cisco_ios", site: str = "") -> dict:
    """Applica la config generata via SSH (Netmiko) su un apparato
    raggiungibile e opzionalmente esegue 'write memory'.

    # A day-0 device is usually not in hosts.csv yet, so core.net_ssh cannot
    # resolve its site from the inventory: `site` names it explicitly so a
    # switch inside a jump site is reached through the bastion instead of
    # being dialled directly and timing out.
    """
    from core.net_ssh import ConnectHandler

    commands = [ln for ln in config_text.splitlines()
                if ln.strip() and not ln.strip().startswith("!")]
    # A device we can already reach over SSH has RSA keys, so this line only
    # ever asks '% They will be replaced ... [yes/no]:'. send_config_set does
    # not answer prompts, so the rest of the config would be typed into that
    # question — and replacing the key can drop the session carrying it. The
    # console path keeps the line: there it is a genuine day-0 first key.
    commands = [c for c in commands
                if not c.strip().startswith("crypto key generate rsa")]

    device_params = {
        "device_type": device_type,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "secret": secret or password,
        "timeout": 20,
        "auth_timeout": 15,
        "banner_timeout": 15,
    }
    try:
        with ConnectHandler(site_id=site or None, **device_params) as conn:
            conn.enable()
            # Rollback net. This config rewrites the access VLAN of the range
            # we may be connected through, applies bpduguard, and replaces the
            # default gateway: any of those can kill this session mid-push,
            # after which save_config() never runs and the switch is left half
            # configured and unreachable. An armed 'reload in' reboots it into
            # the last saved config; it is cancelled once the push AND the save
            # have both come back.
            armed = _arm_reload(conn)
            output = conn.send_config_set(commands)
            if save:
                try:
                    output += "\n" + conn.save_config()
                except Exception as se:
                    output += f"\n[Salvataggio configurazione non riuscito: {se}]"
                    return _push_result(output)   # leave the reload armed
            if armed:
                output += "\n" + str(conn.send_command_timing("reload cancel"))
            return _push_result(output)
    except Exception as e:
        return {"status": "error", "message": str(e)}


def push_via_serial(com_port: str, config_text: str, baudrate: int = 9600,
                     timeout: float = 2.0) -> dict:
    """Applica la config generata via connessione console/seriale (RS-232 o
    USB-to-serial), per il provisioning day-0 di uno switch appena estratto
    dall'imballo (nessun IP di management ancora configurato).

    Invia riga per riga in configuration mode, con una breve pausa fra i
    comandi per dare tempo alla CLI di elaborarli (nessun prompt-matching
    sofisticato: sufficiente per uno switch vergine in stato noto)."""
    import serial  # pyserial

    commands = [ln for ln in config_text.splitlines()
                if ln.strip() and not ln.strip().startswith("!")]

    log = []
    try:
        with serial.Serial(com_port, baudrate=baudrate, timeout=timeout) as ser:
            def send(line, delay=0.3):
                ser.write((line + "\r\n").encode("utf-8"))
                time.sleep(delay)
                try:
                    log.append(ser.read(ser.in_waiting or 1).decode("utf-8", "ignore"))
                except Exception:
                    pass

            send("", 0.5)
            send("enable", 0.5)
            send("configure terminal", 0.5)
            for cmd in commands:
                send(cmd, 0.3)
            send("end", 0.5)
            send("write memory", 1.0)

        return _push_result("".join(log))
    except Exception as e:
        return {"status": "error", "message": str(e)}


def list_serial_ports() -> list:
    """Elenca le porte seriali/COM disponibili sull'host (best-effort)."""
    try:
        from serial.tools import list_ports
        return [{"device": p.device, "description": p.description}
                for p in list_ports.comports()]
    except Exception:
        return []
