"""Collection of the MAC address-table from devices, pluggable transport.

Order of preference (best-effort, with automatic fallback):
  1. NETCONF  – Cisco-IOS-XE-matm-oper model (Catalyst with switching).
  2. NETCONF  – FDB via SMIv2 Q-BRIDGE-MIB (broad; to be refined live on the
                C8000V bridge-domain: hook already present, completed after
                validation).
  3. CLI      – 'show mac address-table' via Netmiko (universal fallback, the
                only path for CBS/legacy without NETCONF).

The module returns a normalized list of sightings
  {mac, vlan, interface, port_channel, is_uplink, type}
ready for mac_history.record_sightings(). The transports (ncclient/netmiko) are
imported lazily: the app works even if they are not installed.
"""
import re
import logging
from xml.etree import ElementTree as ET

log = logging.getLogger("mac_collector")

NS_MATM = "http://cisco.com/ns/yang/Cisco-IOS-XE-matm-oper"
NS_OPENCONFIG_NI = "http://openconfig.net/yang/network-instance"

_PO_RE = re.compile(r'^(?:po|port-?channel)\s*\d+$', re.I)
_HEX12 = re.compile(r'^[0-9a-fA-F]{12}$')


def _localname(tag: str) -> str:
    """Tag name without namespace ('{ns}mac-addr' -> 'mac-addr')."""
    return tag.rsplit('}', 1)[-1] if '}' in tag else tag


def is_port_channel(port: str) -> bool:
    return bool(port and _PO_RE.match(port.strip()))


def expand_iface(name: str) -> str:
    """Expands common abbreviations ('Gi1/0/5' -> 'GigabitEthernet1/0/5')."""
    if not name:
        return ""
    name = name.strip()
    abbr = [
        (r'^(?:GigabitEthernet|Gi)(?=\d)', 'GigabitEthernet'),
        (r'^(?:TenGigabitEthernet|TenGigE|Te|XGi|10Ge)(?=\d)', 'TenGigabitEthernet'),
        (r'^(?:TwentyFiveGigE|Twe|25Ge)(?=\d)', 'TwentyFiveGigE'),
        (r'^(?:FortyGigabitEthernet|FortyGigE|Fo|40Ge)(?=\d)', 'FortyGigE'),
        (r'^(?:HundredGigE|Hu|100Ge)(?=\d)', 'HundredGigE'),
        (r'^(?:FastEthernet|Fa|fe)(?=\d)', 'FastEthernet'),
        (r'^(?:Ethernet|Eth|Et|e)(?=\d)', 'Ethernet'),
        (r'^(?:Port-channel|Port-Channel|Po)(?=\d)', 'Port-channel'),
    ]
    for pat, full in abbr:
        if re.match(pat, name, re.I):
            return re.sub(pat, full, name, flags=re.I)
    return name


# --- Parser NETCONF: Cisco-IOS-XE-matm-oper ---

def parse_matm_oper(xml_text: str) -> list:
    """Extracts sightings from the matm-oper model (namespace-agnostic)."""
    out = []
    if not xml_text or 'matm' not in xml_text:
        return out
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for entry in root.iter():
        if _localname(entry.tag) not in ('matm-table', 'mac-table', 'matm-mac-entry'):
            continue
        rec = {}
        for child in entry:
            rec[_localname(child.tag)] = (child.text or '').strip()
        mac = rec.get('mac-addr') or rec.get('mac-address') or rec.get('address')
        iface = rec.get('interface') or rec.get('interface-name') or rec.get('port')
        if not mac or not iface:
            continue
        out.append({
            "mac": mac,
            "vlan": rec.get('vlan') or rec.get('fdb-id') or '',
            "interface": expand_iface(iface),
            "port_channel": expand_iface(iface) if is_port_channel(iface) else '',
            "type": (rec.get('type') or '').lower(),
        })
    return out


# --- Standardized parsers: OpenConfig FDB (vendor-neutral) ---
#
# Standard model 'openconfig-network-instance':
#   network-instances/network-instance/fdb/mac-table/entries/entry
#     { mac-address, vlan, interface/interface-ref/state/interface }
# Available on IOS-XE (17.x) both via NETCONF (XML) and via RESTCONF (JSON):
# it is the preferred path because it is vendor-independent.

def _row_from(mac, vlan, iface, etype=""):
    iface = str(iface or "")
    return {
        "mac": mac,
        "vlan": str(vlan) if vlan not in (None, "") else "",
        "interface": expand_iface(iface),
        "port_channel": expand_iface(iface) if is_port_channel(iface) else "",
        "type": str(etype or "").lower(),
    }


def _json_mac_rows(data, mac_keys, iface_keys, vlan_keys) -> list:
    """Generic recursive JSON extractor for FDB (OpenConfig / matm RESTCONF)."""
    out = []

    def iface_of(o):
        for k in iface_keys:
            if isinstance(o.get(k), str) and o.get(k):
                return o[k]
        ir = o.get("interface")
        if isinstance(ir, dict):
            st = (ir.get("interface-ref") or {}).get("state") or {}
            return st.get("interface") or ""
        return ""

    def pick(o, keys):
        for k in keys:
            if o.get(k) not in (None, ""):
                return o[k]
        st = o.get("state")
        if isinstance(st, dict):
            for k in keys:
                if st.get(k) not in (None, ""):
                    return st[k]
        return None

    def walk(o):
        if isinstance(o, dict):
            mac = pick(o, mac_keys)
            iface = iface_of(o)
            if mac and iface:
                etype = o.get("type") or (o.get("state") or {}).get("entry-type") or ""
                out.append(_row_from(str(mac), pick(o, vlan_keys), iface, etype))
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    return out


def parse_openconfig_fdb_json(data) -> list:
    return _json_mac_rows(data, ["mac-address"], ["interface"], ["vlan"])


def parse_matm_oper_json(data) -> list:
    return _json_mac_rows(data, ["mac-addr", "mac-address", "address"],
                          ["interface", "interface-name", "port"], ["vlan", "fdb-id"])


def parse_openconfig_fdb_xml(xml_text: str) -> list:
    """OpenConfig FDB from a NETCONF response (XML), namespace-agnostic."""
    out = []
    if not xml_text or ('mac-table' not in xml_text and 'fdb' not in xml_text):
        return out
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for entry in root.iter():
        if _localname(entry.tag) != 'entry':
            continue
        mac = vlan = iface = None
        for d in entry.iter():
            ln = _localname(d.tag)
            t = (d.text or '').strip()
            if not t:
                continue
            if ln == 'mac-address' and not mac:
                mac = t
            elif ln == 'vlan' and vlan is None:
                vlan = t
            elif ln == 'interface' and not iface:   # interface-ref/state/interface leaf
                iface = t
        if mac and iface:
            out.append(_row_from(mac, vlan, iface))
    return out


# --- CLI parser: 'show mac address-table' ---

# E.g.:  "  10    aabb.ccdd.eeff    DYNAMIC     Gi1/0/5"
_CLI_ROW = re.compile(
    r'^\s*(?P<vlan>\d+|All)\s+(?P<mac>[0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4}[.:-][0-9a-fA-F]{4})'
    r'\s+(?P<type>\w+)\s+(?:\S+\s+)*?(?P<port>\S+)\s*$', re.I)


def parse_cli_mac_table(text: str) -> list:
    out = []
    if not text:
        return out
    for line in text.splitlines():
        m = _CLI_ROW.match(line)
        if not m:
            continue
        port = m.group('port')
        # Discards system/non-endpoint rows (CPU, Router, Drop, etc.).
        if port.lower() in ('cpu', 'router', 'drop', 'switch', '-'):
            continue
        vlan = m.group('vlan')
        out.append({
            "mac": m.group('mac'),
            "vlan": '' if vlan.lower() == 'all' else vlan,
            "interface": expand_iface(port),
            "port_channel": expand_iface(port) if is_port_channel(port) else '',
            "type": m.group('type').lower(),
        })
    return out


# --- Ad-hoc CLI parser: 'show bridge-domain' (EVC/service-instance, e.g. C8000V) ---
#
# Some devices do not expose the FDB like a normal switch: on the Catalyst
# 8000V a bridge-domain learns MACs in 'show bridge-domain', not in
# 'show mac address-table' (which there shows only system/CPU MACs). Format:
#   Bridge-domain 10 (2 ports in all)
#      AED MAC address    Policy  Tag       Age  Pseudoport
#      0   F8B9.5AB2.ACEE forward dynamic   300  GigabitEthernet1.EFP10
#      -   001E.7ACE.A1BF to_bdi  static    0    BDI10
_BD_HDR = re.compile(r'^\s*Bridge-domain\s+(\d+)', re.I)
_BD_ROW = re.compile(
    r'^\s*(?:\d+|-)\s+([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})\s+\S+\s+'
    r'(dynamic|static)\s+\d+\s+(\S+)\s*$', re.I)


def parse_bridge_domain_mac(text: str) -> list:
    out = []
    bd = ''
    for line in (text or '').splitlines():
        h = _BD_HDR.match(line)
        if h:
            bd = h.group(1)
            continue
        m = _BD_ROW.match(line)
        if not m:
            continue
        out.append(_row_from(m.group(1), bd, m.group(3), m.group(2)))
    return out


# Generic best-effort parser: extracts any MAC + interface from arbitrary CLI
# output (for unanticipated ad-hoc commands). VLAN not deducible => empty.
_MAC_ANY = re.compile(r'([0-9A-Fa-f]{4}[.:-][0-9A-Fa-f]{4}[.:-][0-9A-Fa-f]{4}'
                      r'|[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})')
_IFACE_TOK = re.compile(
    r'\b((?:GigabitEthernet|TenGigabitEthernet|FortyGigE|HundredGigE|FastEthernet|'
    r'Ethernet|Port-channel|Gi|Te|Fo|Hu|Fa|Eth|Po|BDI|Vlan)\d[\w./]*)', re.I)


def parse_cli_generic(text: str) -> list:
    out = []
    for line in (text or '').splitlines():
        mm = _MAC_ANY.search(line)
        if not mm:
            continue
        im = _IFACE_TOK.search(line)
        if not im:
            continue
        out.append(_row_from(mm.group(1), '', im.group(1), ''))
    return out


# Registry of CLI formats selectable for ad-hoc commands.
CLI_FORMATS = {
    "mac-address-table": parse_cli_mac_table,
    "bridge-domain": parse_bridge_domain_mac,
    "generic": parse_cli_generic,
}


# --- Post-processing: uplink + dedup ---

def mark_uplinks(rows: list, uplink_ports) -> list:
    """Marks sightings on trunk/uplink ports as is_uplink (from CDP/LLDP):
    a MAC seen on an uplink is transit, not its real 'location'."""
    ups = set()
    port_to_neighbor = {}
    if isinstance(uplink_ports, dict):
        port_to_neighbor = uplink_ports.copy()
        uplink_list = list(uplink_ports.keys())
    else:
        uplink_list = uplink_ports or []

    for u in uplink_list:
        u = (u or '').strip()
        if not u:
            continue
        ups.add(u.lower())                    # abbreviated form (e.g. 'gi1/0/9')
        ups.add(expand_iface(u).lower())      # expanded form (expanded from raw)
        neigh = port_to_neighbor.get(u)
        if neigh:
            port_to_neighbor[u.lower()] = neigh
            port_to_neighbor[expand_iface(u).lower()] = neigh

    for r in rows:
        iface = (r.get('interface') or '').lower()
        base = iface.split('.')[0]   # subinterface/service-instance -> physical
        is_up = iface in ups or base in ups
        r['is_uplink'] = is_up
        if is_up:
            r['uplink_to'] = port_to_neighbor.get(iface) or port_to_neighbor.get(base) or ""
        else:
            r['uplink_to'] = ""
    return rows


# --- Transports ---

def collect_via_netconf(host, username, password, port=830, timeout=30):
    """Returns the sightings list via NETCONF by trying, in order:
      1) Cisco-IOS-XE-matm-oper (Catalyst with switching);
      2) OpenConfig network-instance FDB (standard, vendor-neutral).
    Returns None if no model yields results / ncclient not installed."""
    try:
        from ncclient import manager
    except ImportError:
        log.warning("ncclient non installato: NETCONF non disponibile.")
        return None
    attempts = [
        ('<matm-oper-data xmlns="%s"/>' % NS_MATM, parse_matm_oper),
        ('<network-instances xmlns="%s"><network-instance><fdb/></network-instance></network-instances>'
         % NS_OPENCONFIG_NI, parse_openconfig_fdb_xml),
    ]
    try:
        conn = manager.connect(host=host, port=port, username=username, password=password,
                               hostkey_verify=False, allow_agent=False, look_for_keys=False,
                               timeout=timeout, device_params={'name': 'iosxe'})
        if conn is not None:
            with conn as m:
                for flt, parser in attempts:
                    try:
                        rows = parser(m.get(('subtree', flt)).data_xml)
                        if rows:
                            return rows
                    except Exception as e:
                        log.info("NETCONF get fallito su %s: %s", host, e)
        return None
    except Exception as e:
        log.info("NETCONF connessione fallita su %s: %s", host, e)
        return None


def collect_via_restconf(host, username, password, port=443, timeout=15):
    """Returns the sightings via RESTCONF (HTTPS), trying (Cisco-first):
      1) Cisco-IOS-XE-matm-oper (Catalyst) — primary path, Cisco-specific;
      2) OpenConfig network-instance FDB (standard, vendor-neutral) — fallback.
    Returns None if RESTCONF is unreachable / no data."""
    try:
        import requests
        import urllib3
        from urllib.parse import quote
        urllib3.disable_warnings()
    except ImportError:
        return None
    base = "https://%s:%s/restconf" % (host, port)
    s = requests.Session()
    s.auth = (username, password)
    s.verify = False
    s.headers.update({"Accept": "application/yang-data+json"})
    try:
        # 1) Cisco-specific: matm-oper via RESTCONF (Catalyst).
        r = s.get(base + "/data/Cisco-IOS-XE-matm-oper:matm-oper-data", timeout=timeout)
        if r.status_code == 200:
            rows = parse_matm_oper_json(r.json())
            if rows:
                return rows
        # 2) Standard fallback: OpenConfig FDB for network-instance.
        r = s.get(base + "/data/openconfig-network-instance:network-instances/network-instance",
                  timeout=timeout)
        if r.status_code == 200:
            nis = r.json().get("openconfig-network-instance:network-instance") or []
            rows = []
            for ni in nis:
                name = ni.get("name")
                if not name:
                    continue
                fr = s.get(base + "/data/openconfig-network-instance:network-instances/"
                           "network-instance=%s/fdb/mac-table/entries" % quote(str(name), safe=''),
                           timeout=timeout)
                if fr.status_code == 200:
                    rows += parse_openconfig_fdb_json(fr.json())
            if rows:
                return rows
    except Exception as e:
        log.info("RESTCONF fallito su %s: %s", host, e)
    return None


def collect_via_cli(host, username, password, secret="", device_type="cisco_ios",
                    timeout=20, command=None, fmt=None):
    """CLI via Netmiko. Defaults to 'show mac address-table'; for non-ordinary
    cases an ad-hoc command can be passed (e.g. 'show bridge-domain') with the
    related parsing format (fmt in CLI_FORMATS)."""
    try:
        from core.net_ssh import ConnectHandler
    except ImportError:
        return None
    cmd = command or "show mac address-table"
    parser = CLI_FORMATS.get((fmt or "").lower(), parse_cli_mac_table)
    params = {'device_type': device_type, 'host': host, 'username': username,
              'password': password, 'secret': secret or '', 'timeout': timeout,
              'auth_timeout': 10, 'banner_timeout': 10}
    try:
        with ConnectHandler(**params) as conn:
            try:
                conn.enable()
            except Exception:
                pass
            out = conn.send_command(cmd, read_timeout=30)
            out_str = out if isinstance(out, str) else str(out or "")
            return parser(out_str)
    except Exception as e:
        log.info("CLI mac-table fallito su %s: %s", host, e)
        return None


# --- MAC collection of the switch's OWN interfaces (infrastructure) ---
#
# Beyond the FDB (endpoint MACs), it is useful to know the MACs of the switch's
# own interfaces ('own' hardware address): they also appear in the scan and must
# be classified as infrastructure ("switch-interface"), not as endpoints.
# Standard model 'ietf-interfaces': interfaces-state/interface {name, phys-address}.

NS_IETF_IF = "urn:ietf:params:xml:ns:yang:ietf-interfaces"

# E.g.:  "  Hardware is Ethernet, address is aabb.cc00.0300 (bia aabb.cc00.0300)"
_IF_HDR = re.compile(r'^(\S+) is ', re.I)
_IF_ADDR = re.compile(r'address is\s+([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})', re.I)


def parse_ietf_if_macs_xml(xml_text: str) -> list:
    """Extracts the (name, phys-address) pairs from ietf-interfaces (NETCONF XML)."""
    out = []
    if not xml_text or 'interface' not in xml_text:
        return out
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for entry in root.iter():
        if _localname(entry.tag) != 'interface':
            continue
        name = mac = None
        for d in entry.iter():
            ln = _localname(d.tag)
            t = (d.text or '').strip()
            if not t:
                continue
            if ln == 'name' and not name:
                name = t
            elif ln == 'phys-address' and not mac:
                mac = t
        if name and mac:
            out.append({"interface": name, "mac": mac})
    return out


def parse_ietf_if_macs_json(data) -> list:
    """Extracts the {interface, mac} pairs from ietf-interfaces (RESTCONF JSON)."""
    out = []

    def walk(o):
        if isinstance(o, dict):
            name = o.get("name")
            mac = o.get("phys-address")
            if isinstance(name, str) and name and isinstance(mac, str) and mac:
                out.append({"interface": name, "mac": mac})
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    return out


def parse_cli_if_macs(text: str) -> list:
    """Parses 'show interfaces' statefully: the interface header line
    ('^<name> is ') sets the current interface; the following
    'address is <mac>' emits the {interface, mac} pair. The filter
    '| include address is' would lose the interface name: parse everything."""
    out = []
    cur = ""
    for line in (text or '').splitlines():
        h = _IF_HDR.match(line)
        if h:
            cur = h.group(1)
        a = _IF_ADDR.search(line)
        if a and cur:
            out.append({"interface": cur, "mac": a.group(1)})
    return out


def collect_if_macs_via_netconf(host, username, password, port=830, timeout=30):
    """Own-interface MACs via NETCONF (ietf-interfaces): tries
    'interfaces-state' (operational) first, then 'interfaces' (config). None if
    ncclient not installed or no data."""
    try:
        from ncclient import manager
    except ImportError:
        log.warning("ncclient non installato: NETCONF non disponibile.")
        return None
    attempts = [
        '<interfaces-state xmlns="%s"/>' % NS_IETF_IF,
        '<interfaces xmlns="%s"/>' % NS_IETF_IF,
    ]
    try:
        conn = manager.connect(host=host, port=port, username=username, password=password,
                               hostkey_verify=False, allow_agent=False, look_for_keys=False,
                               timeout=timeout, device_params={'name': 'iosxe'})
        if conn is not None:
            with conn as m:
                for flt in attempts:
                    try:
                        rows = parse_ietf_if_macs_xml(m.get(('subtree', flt)).data_xml)
                        if rows:
                            return rows
                    except Exception as e:
                        log.info("NETCONF if-macs get fallito su %s: %s", host, e)
        return None
    except Exception as e:
        log.info("NETCONF if-macs connessione fallita su %s: %s", host, e)
        return None


def collect_if_macs_via_restconf(host, username, password, port=443, timeout=15):
    """Own-interface MACs via RESTCONF (ietf-interfaces). Tries the restricted
    fields (name;phys-address), then full state, then config. None if
    unreachable / no data."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings()
    except ImportError:
        return None
    base = "https://%s:%s/restconf" % (host, port)
    s = requests.Session()
    s.auth = (username, password)
    s.verify = False
    s.headers.update({"Accept": "application/yang-data+json"})
    endpoints = [
        "/data/ietf-interfaces:interfaces-state/interface?fields=name;phys-address",
        "/data/ietf-interfaces:interfaces-state",
        "/data/ietf-interfaces:interfaces",
    ]
    try:
        for ep in endpoints:
            r = s.get(base + ep, timeout=timeout)
            if r.status_code == 200:
                rows = parse_ietf_if_macs_json(r.json())
                if rows:
                    return rows
    except Exception as e:
        log.info("RESTCONF if-macs fallito su %s: %s", host, e)
    return None


def collect_if_macs_via_cli(host, username, password, secret="", device_type="cisco_ios",
                            timeout=20):
    """Own-interface MACs via Netmiko CLI ('show interfaces')."""
    try:
        from core.net_ssh import ConnectHandler
    except ImportError:
        return None
    params = {'device_type': device_type, 'host': host, 'username': username,
              'password': password, 'secret': secret or '', 'timeout': timeout,
              'auth_timeout': 10, 'banner_timeout': 10}
    try:
        with ConnectHandler(**params) as conn:
            try:
                conn.enable()
            except Exception:
                pass
            out = conn.send_command("show interfaces", read_timeout=30)
            out_str = out if isinstance(out, str) else str(out or "")
            return parse_cli_if_macs(out_str)
    except Exception as e:
        log.info("CLI if-macs fallito su %s: %s", host, e)
        return None


def _resolve_transport_plan(transports, netconf_port, restconf_port, device_type):
    """Applies the transports declared per-device (§11.6). Returns
    (nc_enabled, netconf_port, rc_enabled, restconf_port, cli_enabled, device_type).
    transports=None => legacy behavior (all transports, default ports)."""
    if transports is None:
        return True, netconf_port, True, restconf_port, True, device_type
    nc_enabled = 'netconf' in transports
    rc_enabled = 'restconf' in transports
    cli_enabled = ('ssh' in transports) or ('telnet' in transports)
    # Telnet only if declared and SSH absent → Netmiko '_telnet' variant.
    if ('telnet' in transports) and ('ssh' not in transports) and not device_type.endswith('_telnet'):
        device_type = device_type + '_telnet'
    if nc_enabled and transports.get('netconf'):
        netconf_port = transports['netconf']
    if rc_enabled and transports.get('restconf'):
        restconf_port = transports['restconf']
    return nc_enabled, netconf_port, rc_enabled, restconf_port, cli_enabled, device_type


def collect_interface_macs(host, username, password, secret="", device_type="cisco_ios",
                           netconf_port=830, restconf_port=443, transport=None,
                           transports=None) -> dict:
    """High-level collection of the switch's own interface MACs, with fallback
    NETCONF -> RESTCONF -> CLI (same structure as collect_mac_table).
    Returns {rows, method, error}; 'rows' is list[{interface, mac}] (raw MACs)."""
    want = (transport or "").strip().lower() or None
    (nc_enabled, netconf_port, rc_enabled, restconf_port,
     cli_enabled, device_type) = _resolve_transport_plan(
        transports, netconf_port, restconf_port, device_type)
    rows = None
    method = None
    if nc_enabled and want in (None, "netconf"):
        rows = collect_if_macs_via_netconf(host, username, password, port=netconf_port)
        if rows is not None:
            method = "netconf"
    if rows is None and rc_enabled and want in (None, "restconf"):
        rows = collect_if_macs_via_restconf(host, username, password, port=restconf_port)
        if rows is not None:
            method = "restconf"
    if rows is None and cli_enabled and want in (None, "cli"):
        rows = collect_if_macs_via_cli(host, username, password, secret, device_type)
        if rows is not None:
            method = "cli"
    if rows is None:
        scope = want or "NETCONF/RESTCONF/CLI"
        return {"rows": [], "method": None,
                "error": "MAC interfacce non ottenibili (%s)." % scope}
    return {"rows": rows, "method": method, "error": None}


def collect_mac_table(host, username, password, secret="", device_type="cisco_ios",
                      uplink_ports=None, netconf_port=830, restconf_port=443,
                      transport=None, cli_command=None, cli_format=None,
                      transports=None) -> dict:
    """High-level collection with fallback NETCONF -> RESTCONF -> CLI.

    NETCONF and RESTCONF use the standardized models (OpenConfig FDB) in
    addition to Cisco matm-oper (primary path); CLI is the last resort
    (CBS/legacy).
    'transport' (netconf|restconf|cli) forces a single transport; None = auto.
    'transports' (§11.6): a {protocol: port|None} map declared for the device —
    if provided, ONLY the declared protocols are tried, with the declared ports.
    None = legacy behavior (all, default ports).
    Returns {rows, method, error}: 'rows' is already normalized and with is_uplink.
    """
    want = (transport or "").strip().lower() or None
    (nc_enabled, netconf_port, rc_enabled, restconf_port,
     cli_enabled, device_type) = _resolve_transport_plan(
        transports, netconf_port, restconf_port, device_type)
    rows = None
    method = None
    if nc_enabled and want in (None, "netconf"):
        rows = collect_via_netconf(host, username, password, port=netconf_port)
        if rows is not None:
            method = "netconf"
    if rows is None and rc_enabled and want in (None, "restconf"):
        rows = collect_via_restconf(host, username, password, port=restconf_port)
        if rows is not None:
            method = "restconf"
    if rows is None and cli_enabled and want in (None, "cli"):
        rows = collect_via_cli(host, username, password, secret, device_type,
                               command=cli_command, fmt=cli_format)
        if rows is not None:
            method = "cli"
    if rows is None:
        scope = want or "NETCONF/RESTCONF/CLI"
        return {"rows": [], "method": None,
                "error": "MAC-table non ottenibile (%s)." % scope}
    mark_uplinks(rows, uplink_ports)
    return {"rows": rows, "method": method, "error": None}


def uplink_ports_from_backup(ip: str) -> dict:
    """Local ports of the device that have a CDP/LLDP neighbor: these are
    trunk/uplink, so MACs seen there are transit and not the host's real
    'location'. They are derived from the device backup (already collected by
    triage)."""
    import os
    from core import core_engine
    try:
        content = None
        for root, _dirs, files in os.walk(core_engine.BACKUP_FOLDER):
            for f in files:
                if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt":
                    with open(os.path.join(root, f), encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    break
            if content:
                break
        if not content:
            return {}
        out = {}
        for n in core_engine.parse_cdp_lldp_neighbors(content):
            lp = n.get("local_port")
            if lp and lp != "Unknown":
                name = n.get("neighbor_id") or n.get("neighbor_ip") or "Unknown"
                out[lp] = name
        return out
    except Exception:
        return {}


def collect_one(device: dict, transport=None) -> dict:
    """MAC-table of ONE device, with uplinks already marked. Writes nothing."""
    from core import core_engine
    from collectors import mac_history
    from services import inventory_manager

    ip = device["IP"]
    vendor = (device.get("Vendor") or "cisco").lower()
    username, password, secret = core_engine.get_device_credentials(device)
    try:
        _, netmiko_type = core_engine.resolve_driver(vendor)
    except ValueError as e:
        # Un vendor senza driver non e' un Cisco: partire lo stesso con i
        # comandi IOS restituirebbe una MAC-table letta col parser sbagliato,
        # cioe' dati inventati presentati come raccolta riuscita. Come fa
        # arp_collector.collect_from_device, l'errore si propaga.
        log.warning("MAC collection on %s: %s", ip, e)
        return {"device": device, "error": str(e), "if_macs": []}
    # Ad-hoc command configured for this device (non-ordinary cases).
    ov = mac_history.get_override(ip) or {}
    dev_transports = inventory_manager.parse_transports(device)
    res = collect_mac_table(
        ip, username, password, secret, device_type=netmiko_type,
        uplink_ports=uplink_ports_from_backup(ip), transport=transport,
        cli_command=ov.get("command"), cli_format=ov.get("fmt"),
        transports=dev_transports,
    )
    res["device"] = device
    # Also collect the MACs of the switch's own interfaces (infrastructure):
    # needed to classify them as "switch-interface" instead of endpoints.
    # Failures are non-fatal (empty list).
    if not res.get("error"):
        try:
            ifres = collect_interface_macs(
                ip, username, password, secret, device_type=netmiko_type,
                transport=transport, transports=dev_transports,
            )
            res["if_macs"] = ifres.get("rows") or []
        except Exception:
            res["if_macs"] = []
    else:
        res["if_macs"] = []
    return res


def collect_all(devices: list, transport=None) -> dict:
    """Collects AND persists the MAC-table of multiple devices.

    Twin of ``arp_collector.collect_all``: collection and writing in the same
    place. Previously the sequence lived inside the route, so anyone who needed
    to re-scan for other reasons — a client diagnosis finding stale data —
    would have had to redo it, uplinks and overrides included, or import a
    router from a service.

    Local imports: ``mac_history`` imports this module, so a module-level import
    would be a cycle.
    """
    from concurrent.futures import ThreadPoolExecutor
    from functools import partial
    from collectors import mac_history

    if not devices:
        return {"scanned": 0, "results": [], "pruned": 0}
    worker = partial(collect_one, transport=transport)
    with ThreadPoolExecutor(max_workers=min(8, len(devices))) as ex:
        collected = list(ex.map(worker, devices))

    results = []
    for res in collected:
        d = res["device"]
        ip = d["IP"]
        if res.get("error"):
            results.append({"ip": ip, "error": res["error"], "count": 0})
            continue
        summ = mac_history.record_sightings(
            res["rows"], switch_ip=ip, switch_name=d.get("Hostname", ""),
            tenant=d.get("Group") or "Generale",
            site=d.get("Site") or "central",
        )
        if res.get("if_macs"):
            mac_history.record_switch_if_macs(
                res["if_macs"], switch_ip=ip, switch_name=d.get("Hostname", ""),
            )
        results.append({"ip": ip, "method": res["method"],
                        "count": len(res["rows"]), **summ})
    return {"scanned": len(devices), "results": results,
            "pruned": mac_history.prune()}
