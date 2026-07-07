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
    if cfg.get("domain"):
        lines.append(f"ip domain-name {cfg['domain']}")
    lines.append("no ip http server")
    lines.append("no ip http secure-server")
    if cfg.get("no_vstack", True):
        # Smart Install (vstack) e' un noto vettore d'attacco: va disabilitato.
        # Sui modelli che non lo supportano il comando viene semplicemente rifiutato.
        lines.append("no vstack")

    sec("AUTENTICAZIONE LOCALE / ENABLE")
    if cfg.get("enable_secret"):
        lines.append(f"enable secret {cfg['enable_secret']}")
    if cfg.get("admin_user"):
        pwd = cfg.get("admin_password") or "changeme"
        lines.append(f"username {cfg['admin_user']} privilege 15 secret {pwd}")
    lines.append("aaa new-model")
    lines.append("aaa authentication login default local")
    lines.append("aaa authorization exec default local")
    if cfg.get("login_block", True):
        # Anti brute-force: dopo 5 tentativi falliti in 60s blocca i login per 120s.
        lines.append("login block-for 120 attempts 5 within 60")
        lines.append("login on-failure log")
        lines.append("login on-success log")

    ssh_only = cfg.get("ssh_only", True)
    if ssh_only:
        sec("SSH-ONLY MANAGEMENT")
        lines.append("crypto key generate rsa modulus 2048")
        lines.append("ip ssh version 2")
        lines.append("ip ssh time-out 60")
        lines.append("ip ssh authentication-retries 3")

    sec("VTP")
    lines.append(f"vtp mode {cfg.get('vtp_mode', 'transparent')}")

    vlans = _expand_vlan_ids(cfg.get("vlans"))
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
    if snmpv3.get("user"):
        sec("SNMPv3")
        group = snmpv3.get("group", "SNMP-GROUP")
        lines.append(f"snmp-server group {group} v3 priv")
        auth_pass = snmpv3.get("auth_pass", "authpass123")
        priv_pass = snmpv3.get("priv_pass", "privpass123")
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

def push_via_ssh(host: str, username: str, password: str, secret: str,
                  config_text: str, port: int = 22, save: bool = True,
                  device_type: str = "cisco_ios") -> dict:
    """Applica la config generata via SSH (Netmiko) su un apparato
    raggiungibile e opzionalmente esegue 'write memory'."""
    from netmiko import ConnectHandler

    commands = [ln for ln in config_text.splitlines()
                if ln.strip() and not ln.strip().startswith("!")]

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
        with ConnectHandler(**device_params) as conn:
            conn.enable()
            output = conn.send_config_set(commands)
            if save:
                try:
                    output += "\n" + conn.save_config()
                except Exception as se:
                    output += f"\n[Salvataggio configurazione non riuscito: {se}]"
            return {"status": "success", "output": output}
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

        return {"status": "success", "output": "".join(log)}
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
