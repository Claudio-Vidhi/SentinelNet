"""Raccolta della MAC address-table dagli apparati, trasporto pluggable.

Ordine di preferenza (best-effort, con fallback automatico):
  1. NETCONF  – modello Cisco-IOS-XE-matm-oper (Catalyst con switching).
  2. NETCONF  – FDB via SMIv2 Q-BRIDGE-MIB (broad; da rifinire live sul C8000V
                bridge-domain: hook già presente, si completa dopo validazione).
  3. CLI      – 'show mac address-table' via Netmiko (fallback universale, unica
                via per CBS/legacy senza NETCONF).

Il modulo restituisce una lista normalizzata di avvistamenti
  {mac, vlan, interface, port_channel, is_uplink, type}
pronta per mac_history.record_sightings(). I trasporti (ncclient/netmiko) sono
importati in modo lazy: l'app funziona anche se non installati.
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
    """Nome del tag senza namespace ('{ns}mac-addr' -> 'mac-addr')."""
    return tag.rsplit('}', 1)[-1] if '}' in tag else tag


def is_port_channel(port: str) -> bool:
    return bool(port and _PO_RE.match(port.strip()))


def expand_iface(name: str) -> str:
    """Espande le abbreviazioni comuni ('Gi1/0/5' -> 'GigabitEthernet1/0/5')."""
    if not name:
        return ""
    name = name.strip()
    abbr = [
        (r'^Gi(?=\d)', 'GigabitEthernet'), (r'^Te(?=\d)', 'TenGigabitEthernet'),
        (r'^Fo(?=\d)', 'FortyGigE'), (r'^Twe(?=\d)', 'TwentyFiveGigE'),
        (r'^Hu(?=\d)', 'HundredGigE'), (r'^Fa(?=\d)', 'FastEthernet'),
        (r'^Eth(?=\d)', 'Ethernet'), (r'^Po(?=\d)', 'Port-channel'),
    ]
    for pat, full in abbr:
        if re.match(pat, name):
            return re.sub(pat, full, name)
    return name


# --- Parser NETCONF: Cisco-IOS-XE-matm-oper ---

def parse_matm_oper(xml_text: str) -> list:
    """Estrae gli avvistamenti dal modello matm-oper (namespace-agnostico)."""
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


# --- Parser standardizzati: OpenConfig FDB (vendor-neutral) ---
#
# Modello standard 'openconfig-network-instance':
#   network-instances/network-instance/fdb/mac-table/entries/entry
#     { mac-address, vlan, interface/interface-ref/state/interface }
# Disponibile su IOS-XE (17.x) sia via NETCONF (XML) sia via RESTCONF (JSON):
# è la via preferita perché indipendente dal vendor.

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
    """Estrattore JSON ricorsivo generico per FDB (OpenConfig / matm RESTCONF)."""
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
    """OpenConfig FDB da risposta NETCONF (XML), namespace-agnostico."""
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
            elif ln == 'interface' and not iface:   # foglia interface-ref/state/interface
                iface = t
        if mac and iface:
            out.append(_row_from(mac, vlan, iface))
    return out


# --- Parser CLI: 'show mac address-table' ---

# Es.:  "  10    aabb.ccdd.eeff    DYNAMIC     Gi1/0/5"
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
        # Scarta righe di sistema/non-endpoint (CPU, Router, Drop, ecc.).
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


# --- Parser CLI ad-hoc: 'show bridge-domain' (EVC/service-instance, es. C8000V) ---
#
# Alcuni apparati non espongono la FDB come uno switch normale: sul Catalyst
# 8000V un bridge-domain impara i MAC in 'show bridge-domain', non in
# 'show mac address-table' (che lì mostra solo MAC di sistema/CPU). Formato:
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


# Parser generico best-effort: estrae qualsiasi MAC + interfaccia da output CLI
# arbitrario (per comandi ad-hoc non previsti). VLAN non deducibile => vuota.
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


# Registro dei formati CLI selezionabili per i comandi ad-hoc.
CLI_FORMATS = {
    "mac-address-table": parse_cli_mac_table,
    "bridge-domain": parse_bridge_domain_mac,
    "generic": parse_cli_generic,
}


# --- Post-processing: uplink + dedup ---

def mark_uplinks(rows: list, uplink_ports) -> list:
    """Marca come is_uplink gli avvistamenti su porte trunk/uplink (da CDP/LLDP):
    un MAC visto su una dorsale è transito, non la sua 'posizione' reale."""
    ups = set()
    for u in (uplink_ports or []):
        u = (u or '').strip()
        if not u:
            continue
        ups.add(u.lower())                    # forma abbreviata (es. 'gi1/0/9')
        ups.add(expand_iface(u).lower())      # forma estesa (espansa dal raw)
    for r in rows:
        iface = (r.get('interface') or '').lower()
        base = iface.split('.')[0]   # sottinterfaccia/service-instance -> fisica
        r['is_uplink'] = iface in ups or base in ups
    return rows


# --- Trasporti ---

def collect_via_netconf(host, username, password, port=830, timeout=30):
    """Ritorna la lista avvistamenti via NETCONF provando, nell'ordine:
      1) Cisco-IOS-XE-matm-oper (Catalyst con switching);
      2) OpenConfig network-instance FDB (standard, vendor-neutral).
    Ritorna None se nessun modello dà risultati / ncclient non installato."""
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
        with manager.connect(host=host, port=port, username=username, password=password,
                             hostkey_verify=False, allow_agent=False, look_for_keys=False,
                             timeout=timeout, device_params={'name': 'iosxe'}) as m:
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
    """Ritorna gli avvistamenti via RESTCONF (HTTPS), provando (Cisco-first):
      1) Cisco-IOS-XE-matm-oper (Catalyst) — via primaria, specifica Cisco;
      2) OpenConfig network-instance FDB (standard, vendor-neutral) — fallback.
    Ritorna None se RESTCONF non è raggiungibile / nessun dato."""
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
        # 1) Specifico Cisco: matm-oper via RESTCONF (Catalyst).
        r = s.get(base + "/data/Cisco-IOS-XE-matm-oper:matm-oper-data", timeout=timeout)
        if r.status_code == 200:
            rows = parse_matm_oper_json(r.json())
            if rows:
                return rows
        # 2) Fallback standard: OpenConfig FDB per network-instance.
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
    """CLI via Netmiko. Di default 'show mac address-table'; per i casi non
    ordinari si può passare un comando ad-hoc (es. 'show bridge-domain') con il
    relativo formato di parsing (fmt in CLI_FORMATS)."""
    try:
        from netmiko import ConnectHandler
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
            return parser(out)
    except Exception as e:
        log.info("CLI mac-table fallito su %s: %s", host, e)
        return None


def collect_mac_table(host, username, password, secret="", device_type="cisco_ios",
                      uplink_ports=None, netconf_port=830, restconf_port=443,
                      transport=None, cli_command=None, cli_format=None) -> dict:
    """Raccolta ad alto livello con fallback NETCONF -> RESTCONF -> CLI.

    NETCONF e RESTCONF usano i modelli standardizzati (OpenConfig FDB) oltre a
    Cisco matm-oper (via primaria); il CLI è l'ultima spiaggia (CBS/legacy).
    'transport' (netconf|restconf|cli) forza un singolo trasporto; None = auto.
    Ritorna {rows, method, error}: 'rows' è già normalizzato e con is_uplink.
    """
    want = (transport or "").strip().lower() or None
    rows = None
    method = None
    if want in (None, "netconf"):
        rows = collect_via_netconf(host, username, password, port=netconf_port)
        if rows is not None:
            method = "netconf"
    if rows is None and want in (None, "restconf"):
        rows = collect_via_restconf(host, username, password, port=restconf_port)
        if rows is not None:
            method = "restconf"
    if rows is None and want in (None, "cli"):
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
