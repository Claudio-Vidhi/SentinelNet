# -*- coding: utf-8 -*-
"""FortiGate Provisioner — genera una configurazione FortiOS "day-0" per un
firewall FortiGate appena installato (zero-touch), seguendo le linee guida di
hardening Fortinet, e la consegna nelle stesse tre modalita' dello Switch
Provisioner: solo testo, push via SSH (Netmiko), push via console/seriale.

Come switch_provisioner: ``build_config`` e' una funzione pura che assembla la
config come testo FortiOS a partire da un dict di parametri.
"""

import time


def _q(s):
    """Quota un valore per la CLI FortiOS (stringhe con spazi)."""
    s = str(s or "")
    return f'"{s}"' if (" " in s or not s) else s


def build_config(cfg: dict) -> str:
    """Costruisce la configurazione FortiOS completa a partire da ``cfg``.

    Chiavi principali attese (tutte opzionali salvo hostname):
      hostname (str)
      timezone (str, default "Europe/Rome")
      admin_user (str), admin_password (str)   -> admin aggiuntivo super_admin
      admin_timeout (int, default 10)          -> minuti di idle
      lockout (bool, default True)             -> anti brute-force sul login admin
      strong_crypto (bool, default True)
      mgmt_interface (str, es. "mgmt" o "port1")
      mgmt_ip (str), mgmt_mask (str)
      mgmt_allowaccess (str, default "ping https ssh")
      wan_interface (str), wan_mode (str: "dhcp"|"static")
      wan_ip (str), wan_mask (str), wan_gw (str)
      lan_interface (str), lan_ip (str), lan_mask (str)
      dhcp_server (bool), dhcp_start (str), dhcp_end (str)
      dns_primary (str), dns_secondary (str)
      ntp_servers (list[str])
      syslog_server (str)
      snmpv3 (dict: user, auth_pass, priv_pass)
      lan_to_wan_policy (bool, default True)   -> policy LAN->WAN con NAT
      disable_wan_admin (bool, default True)   -> nessun accesso admin dal WAN
      banner (str)                             -> post-login banner
    """
    hostname = (cfg.get("hostname") or "FortiGate").strip()
    lines = []

    def sec(title):
        lines.append("")
        lines.append(f"# --- {title} ---")

    sec("SYSTEM GLOBAL / HARDENING")
    lines.append("config system global")
    lines.append(f"    set hostname {_q(hostname)}")
    lines.append(f"    set timezone {_q(cfg.get('timezone') or 'Europe/Rome')}")
    lines.append(f"    set admintimeout {int(cfg.get('admin_timeout') or 10)}")
    if cfg.get("strong_crypto", True):
        lines.append("    set strong-crypto enable")
    lines.append("    set admin-https-redirect enable")
    if cfg.get("lockout", True):
        # Anti brute-force: 3 tentativi falliti -> blocco 120s.
        lines.append("    set admin-lockout-threshold 3")
        lines.append("    set admin-lockout-duration 120")
    if cfg.get("banner"):
        lines.append("    set post-login-banner enable")
    lines.append("end")
    if cfg.get("banner"):
        lines.append("config system replacemsg admin post_admin-disclaimer-text")
        lines.append(f"    set buffer {_q(cfg['banner'])}")
        lines.append("end")

    if cfg.get("admin_user"):
        sec("ADMIN LOCALE AGGIUNTIVO")
        lines.append("config system admin")
        lines.append(f"    edit {_q(cfg['admin_user'])}")
        lines.append(f"        set password {_q(cfg.get('admin_password') or 'changeme')}")
        lines.append("        set accprofile \"super_admin\"")
        lines.append("    next")
        lines.append("end")

    sec("INTERFACCE")
    lines.append("config system interface")
    mgmt_if = cfg.get("mgmt_interface")
    if mgmt_if and cfg.get("mgmt_ip"):
        lines.append(f"    edit {_q(mgmt_if)}")
        lines.append("        set mode static")
        lines.append(f"        set ip {cfg['mgmt_ip']} {cfg.get('mgmt_mask') or '255.255.255.0'}")
        lines.append(f"        set allowaccess {cfg.get('mgmt_allowaccess') or 'ping https ssh'}")
        lines.append("        set alias \"MGMT\"")
        lines.append("    next")
    wan_if = cfg.get("wan_interface")
    if wan_if:
        lines.append(f"    edit {_q(wan_if)}")
        if (cfg.get("wan_mode") or "dhcp") == "static" and cfg.get("wan_ip"):
            lines.append("        set mode static")
            lines.append(f"        set ip {cfg['wan_ip']} {cfg.get('wan_mask') or '255.255.255.0'}")
        else:
            lines.append("        set mode dhcp")
        # Hardening: mai management esposto sul WAN (solo ping diagnostico).
        allow = "ping" if cfg.get("disable_wan_admin", True) else "ping https ssh"
        lines.append(f"        set allowaccess {allow}")
        lines.append("        set alias \"WAN\"")
        lines.append("        set role wan")
        lines.append("    next")
    lan_if = cfg.get("lan_interface")
    if lan_if and cfg.get("lan_ip"):
        lines.append(f"    edit {_q(lan_if)}")
        lines.append("        set mode static")
        lines.append(f"        set ip {cfg['lan_ip']} {cfg.get('lan_mask') or '255.255.255.0'}")
        lines.append("        set allowaccess ping")
        lines.append("        set alias \"LAN\"")
        lines.append("        set role lan")
        lines.append("        set device-identification enable")
        lines.append("    next")
    lines.append("end")

    if wan_if and (cfg.get("wan_mode") or "dhcp") == "static" and cfg.get("wan_gw"):
        sec("DEFAULT ROUTE")
        lines.append("config router static")
        lines.append("    edit 1")
        lines.append(f"        set gateway {cfg['wan_gw']}")
        lines.append(f"        set device {_q(wan_if)}")
        lines.append("    next")
        lines.append("end")

    if cfg.get("dns_primary"):
        sec("DNS")
        lines.append("config system dns")
        lines.append(f"    set primary {cfg['dns_primary']}")
        if cfg.get("dns_secondary"):
            lines.append(f"    set secondary {cfg['dns_secondary']}")
        lines.append("end")

    ntp = cfg.get("ntp_servers") or []
    if ntp:
        sec("NTP")
        lines.append("config system ntp")
        lines.append("    set ntpsync enable")
        lines.append("    set type custom")
        lines.append("    config ntpserver")
        for i, srv in enumerate(ntp, 1):
            lines.append(f"        edit {i}")
            lines.append(f"            set server {_q(srv)}")
            lines.append("        next")
        lines.append("    end")
        lines.append("end")

    if cfg.get("dhcp_server") and lan_if and cfg.get("lan_ip") and cfg.get("dhcp_start") and cfg.get("dhcp_end"):
        sec("DHCP SERVER (LAN)")
        lines.append("config system dhcp server")
        lines.append("    edit 1")
        lines.append(f"        set default-gateway {cfg['lan_ip']}")
        lines.append(f"        set netmask {cfg.get('lan_mask') or '255.255.255.0'}")
        lines.append(f"        set interface {_q(lan_if)}")
        lines.append("        config ip-range")
        lines.append("            edit 1")
        lines.append(f"                set start-ip {cfg['dhcp_start']}")
        lines.append(f"                set end-ip {cfg['dhcp_end']}")
        lines.append("            next")
        lines.append("        end")
        if cfg.get("dns_primary"):
            lines.append(f"        set dns-server1 {cfg['dns_primary']}")
        lines.append("    next")
        lines.append("end")

    if cfg.get("syslog_server"):
        sec("SYSLOG")
        lines.append("config log syslogd setting")
        lines.append("    set status enable")
        lines.append(f"    set server {_q(cfg['syslog_server'])}")
        lines.append("end")

    snmpv3 = cfg.get("snmpv3") or {}
    if snmpv3.get("user"):
        sec("SNMPv3")
        lines.append("config system snmp sysinfo")
        lines.append("    set status enable")
        lines.append(f"    set description {_q(hostname)}")
        lines.append("end")
        lines.append("config system snmp user")
        lines.append(f"    edit {_q(snmpv3['user'])}")
        lines.append("        set security-level auth-priv")
        lines.append("        set auth-proto sha")
        lines.append(f"        set auth-pwd {_q(snmpv3.get('auth_pass') or 'authpass123')}")
        lines.append("        set priv-proto aes")
        lines.append(f"        set priv-pwd {_q(snmpv3.get('priv_pass') or 'privpass123')}")
        lines.append("    next")
        lines.append("end")

    if cfg.get("lan_to_wan_policy", True) and lan_if and wan_if:
        sec("FIREWALL POLICY LAN -> WAN (NAT)")
        lines.append("config firewall policy")
        lines.append("    edit 1")
        lines.append("        set name \"LAN-to-WAN\"")
        lines.append(f"        set srcintf {_q(lan_if)}")
        lines.append(f"        set dstintf {_q(wan_if)}")
        lines.append("        set srcaddr \"all\"")
        lines.append("        set dstaddr \"all\"")
        lines.append("        set action accept")
        lines.append("        set schedule \"always\"")
        lines.append("        set service \"ALL\"")
        lines.append("        set nat enable")
        lines.append("        set logtraffic all")
        lines.append("    next")
        lines.append("end")

    return "\n".join(lines).lstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# CONSEGNA: SSH (Netmiko) e CONSOLE/SERIALE (pyserial)
# ---------------------------------------------------------------------------

def push_via_ssh(host: str, username: str, password: str, config_text: str,
                 port: int = 22) -> dict:
    """Applica la config FortiOS via SSH (Netmiko, device_type 'fortinet').
    FortiOS salva automaticamente a ogni 'end': nessun write memory."""
    from netmiko import ConnectHandler

    commands = [ln for ln in config_text.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]

    device_params = {
        "device_type": "fortinet",
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "timeout": 20,
        "auth_timeout": 15,
        "banner_timeout": 15,
    }
    try:
        with ConnectHandler(**device_params) as conn:
            output = conn.send_config_set(commands, exit_config_mode=False,
                                          cmd_verify=False)
            return {"status": "success", "output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def push_via_serial(com_port: str, config_text: str, baudrate: int = 9600,
                    timeout: float = 2.0, username: str = "admin",
                    password: str = "") -> dict:
    """Applica la config via console/seriale per il provisioning day-0 di un
    FortiGate vergine (default: login 'admin' senza password; al primo accesso
    FortiOS chiede di impostarne una — qui si inviano comunque le credenziali
    fornite). Invio riga per riga con pausa, come per gli switch."""
    import serial  # pyserial

    commands = [ln for ln in config_text.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]

    log = []
    try:
        with serial.Serial(com_port, baudrate=baudrate, timeout=timeout) as ser:
            def send(line, delay=0.4):
                ser.write((line + "\r\n").encode("utf-8"))
                time.sleep(delay)
                try:
                    log.append(ser.read(ser.in_waiting or 1).decode("utf-8", "ignore"))
                except Exception:
                    pass

            # Login console: username, poi password (vuota su unita' vergine).
            send("", 0.6)
            send(username or "admin", 0.6)
            send(password or "", 0.8)
            for cmd in commands:
                send(cmd, 0.4)

        return {"status": "success", "output": "".join(log)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


if __name__ == "__main__":
    cfg = {
        "hostname": "FGT-SEDE-01",
        "admin_user": "netadmin", "admin_password": "S3cret!",
        "mgmt_interface": "mgmt", "mgmt_ip": "10.0.0.254", "mgmt_mask": "255.255.255.0",
        "wan_interface": "wan1", "wan_mode": "static",
        "wan_ip": "203.0.113.2", "wan_mask": "255.255.255.252", "wan_gw": "203.0.113.1",
        "lan_interface": "internal", "lan_ip": "192.168.1.1", "lan_mask": "255.255.255.0",
        "dhcp_server": True, "dhcp_start": "192.168.1.100", "dhcp_end": "192.168.1.200",
        "dns_primary": "1.1.1.1", "dns_secondary": "8.8.8.8",
        "ntp_servers": ["it.pool.ntp.org"], "syslog_server": "10.0.0.50",
        "snmpv3": {"user": "monitor", "auth_pass": "authpass", "priv_pass": "privpass"},
        "banner": "Accesso riservato",
    }
    text = build_config(cfg)
    assert "set hostname FGT-SEDE-01" in text
    assert "config firewall policy" in text
    assert "set admin-lockout-threshold 3" in text
    print(text)
