# -*- coding: utf-8 -*-
"""Config Analyzer — analisi delle running-config Cisco IOS/IOS-XE raccolte come
backup, per estrarne una vista strutturata (VLAN, Routing/VPN, ACL, Interfacce) +
validazione incrociata degli oggetti (ACL/VLAN inutilizzati, riferimenti mancanti).

Il modulo e' volutamente tollerante: non deve MAI sollevare eccezioni su config
strane o parziali. La funzione centrale ``analyze_config`` e' pura (nessun I/O) ed
e' quindi facilmente testabile; ``analyze_device``/``analyze_all`` aggiungono la
lettura del backup piu' recente e lo scoping per sede/tenant.
"""

import os
import re

# --- Utility di basso livello ----------------------------------------------

def _mask_to_prefix(mask):
    """Converte una subnet mask dotted (255.255.255.0) in lunghezza /nn.
    Ritorna None se non e' una mask valida (es. gia' in forma /nn o wildcard)."""
    try:
        parts = mask.split('.')
        if len(parts) != 4:
            return None
        bits = 0
        for p in parts:
            v = int(p)
            if v < 0 or v > 255:
                return None
            bits += bin(v).count('1')
        return bits
    except Exception:
        return None


def _ip_addr_to_cidr(tokens):
    """Da una lista di token tipo ['10.1.10.1', '255.255.255.0'] ricava
    'a.b.c.d/nn'. Ritorna '' se non interpretabile."""
    try:
        if len(tokens) >= 2:
            ip = tokens[0]
            pfx = _mask_to_prefix(tokens[1])
            if pfx is not None:
                return f"{ip}/{pfx}"
            # eventuale forma gia' /nn
            if tokens[1].startswith('/'):
                return f"{ip}{tokens[1]}"
        if len(tokens) == 1 and '/' in tokens[0]:
            return tokens[0]
    except Exception:
        pass
    return ''


def _expand_vlan_list(spec):
    """Espande '10,20,30-35' in ['10','20','30','31',...]. Tollerante."""
    out = []
    if not spec:
        return out
    for chunk in spec.replace(' ', '').split(','):
        if not chunk:
            continue
        if '-' in chunk:
            try:
                a, b = chunk.split('-', 1)
                a, b = int(a), int(b)
                if a <= b and (b - a) < 5000:
                    out.extend(str(x) for x in range(a, b + 1))
            except Exception:
                continue
        else:
            if chunk.isdigit():
                out.append(chunk)
    return out


def running_config(content):
    """Ritorna solo la parte 'running-config' del backup, tagliando le sezioni
    appese (=== ... === e --- SHOW ... ---)."""
    lines = []
    for ln in (content or '').splitlines():
        s = ln.strip()
        if s.startswith('===') or s.startswith('--- SHOW'):
            break
        lines.append(ln)
    return lines


_SHOW_VLAN_ROW = re.compile(r'^(\d{1,4})\s+(\S+)\s+(?:active|act/\S+|suspended|sus/\S+)', re.I)

def parse_show_vlan(content):
    """VLAN apprese via VTP dalla sezione '--- SHOW VLAN ---' appesa al backup:
    {vlan_id: nome}. Sugli access switch le VLAN sono definite sul VTP server,
    non nella running-config locale: senza questa sezione risulterebbero
    falsamente 'non definite'."""
    out = {}
    m = re.search(r'--- SHOW VLAN ---\s*\n(.*?)(?=\n--- [A-Z]|\n===|\Z)',
                  content or '', re.DOTALL | re.IGNORECASE)
    if not m:
        return out
    for ln in m.group(1).splitlines():
        row = _SHOW_VLAN_ROW.match(ln.strip())
        if row:
            out[row.group(1)] = row.group(2)
    return out


def parse_vtp_status(content):
    """Estrae mode/domain dalla sezione '--- SHOW VTP STATUS ---' appesa al backup.
    Ritorna {"mode": "server", "domain": "OLITALIA-VTP-DOM"} (mode minuscolo);
    stringhe vuote se la sezione o le singole righe mancano."""
    out = {"mode": "", "domain": ""}
    m = re.search(r'--- SHOW VTP STATUS ---\s*\n(.*?)(?=\n--- [A-Z]|\n===|\Z)',
                  content or '', re.DOTALL | re.IGNORECASE)
    if not m:
        return out
    section = m.group(1)
    mm = re.search(r'VTP Operating Mode\s*:\s*(\S+)', section, re.IGNORECASE)
    if mm:
        out["mode"] = mm.group(1).strip().lower()
    md = re.search(r'VTP Domain Name\s*:\s*(\S+)', section, re.IGNORECASE)
    if md:
        out["domain"] = md.group(1).strip()
    return out


def _iter_blocks(lines):
    """Itera i blocchi top-level della config. Un blocco inizia su una riga a
    colonna 0 (non '!', non vuota) e prosegue con le righe indentate seguenti.
    Yields (header, [body_lines])."""
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped == '!' or raw[:1] in (' ', '\t'):
            i += 1
            continue
        header = raw.rstrip()
        body = []
        i += 1
        while i < n:
            nxt = lines[i]
            if nxt[:1] in (' ', '\t') and nxt.strip() and nxt.strip() != '!':
                body.append(nxt.rstrip())
                i += 1
            else:
                break
        yield header, body


# --- Parsing dei singoli oggetti -------------------------------------------

def _parse_interface(header, body):
    """Estrae i campi di un blocco 'interface X'."""
    name = header.split(None, 1)[1].strip() if len(header.split(None, 1)) > 1 else ''
    iface = {
        "name": name, "description": "", "mode": "", "access_vlan": "",
        "voice_vlan": "", "trunk_allowed": "", "trunk_native": "", "ip": "",
        "acl_in": "", "acl_out": "", "shutdown": False, "channel_group": "",
        "raw": "\n".join([header] + body),
    }
    has_switchport = False
    sw_mode = ""
    ip_secondary_only = False
    for b in body:
        s = b.strip()
        low = s.lower()
        if low.startswith('description '):
            iface["description"] = s[12:].strip()
        elif low.startswith('switchport access vlan '):
            has_switchport = True
            iface["access_vlan"] = s.split()[-1]
        elif low.startswith('switchport voice vlan '):
            has_switchport = True
            iface["voice_vlan"] = s.split()[-1]
        elif low.startswith('switchport trunk allowed vlan '):
            has_switchport = True
            val = s.split('vlan', 1)[1].strip()
            # 'add' per righe multiple
            val = val.replace('add ', '').strip()
            iface["trunk_allowed"] = (iface["trunk_allowed"] + ',' + val).strip(',') if iface["trunk_allowed"] else val
        elif low.startswith('switchport trunk native vlan '):
            has_switchport = True
            iface["trunk_native"] = s.split()[-1]
        elif low.startswith('switchport mode '):
            has_switchport = True
            sw_mode = s.split()[-1]
        elif low == 'switchport' or low.startswith('switchport '):
            has_switchport = True
        elif low.startswith('ip address ') or low.startswith('ipv4 address '):
            toks = s.split()
            # ip address A.B.C.D MASK [secondary]
            if 'secondary' in low:
                ip_secondary_only = True if not iface["ip"] else ip_secondary_only
            else:
                cidr = _ip_addr_to_cidr(toks[2:4])
                if cidr:
                    iface["ip"] = cidr
        elif low.startswith('ip access-group '):
            toks = s.split()
            if len(toks) >= 4:
                if toks[-1] == 'in':
                    iface["acl_in"] = toks[2]
                elif toks[-1] == 'out':
                    iface["acl_out"] = toks[2]
        elif low == 'shutdown':
            iface["shutdown"] = True
        elif low.startswith('channel-group '):
            iface["channel_group"] = s.split()[1] if len(s.split()) > 1 else ''
    # Determinazione modo
    nm = name.lower()
    if nm.startswith('vlan'):
        iface["mode"] = "svi"
    elif sw_mode == 'trunk' or (iface["trunk_allowed"] or iface["trunk_native"]):
        iface["mode"] = "trunk"
    elif sw_mode == 'access' or iface["access_vlan"] or iface["voice_vlan"]:
        iface["mode"] = "access"
    elif iface["ip"]:
        iface["mode"] = "routed"
    elif has_switchport:
        iface["mode"] = "access"
    elif iface["shutdown"]:
        iface["mode"] = "shutdown-only"
    else:
        iface["mode"] = ""
    return iface


def _parse_static_route(line):
    """Parsa una riga 'ip route ...'. Ritorna dict o None."""
    toks = line.split()
    # toks[0]=ip toks[1]=route
    rest = toks[2:]
    vrf = ""
    if rest[:1] == ['vrf'] and len(rest) >= 2:
        vrf = rest[1]
        rest = rest[2:]
    if len(rest) < 3:
        return None
    net, mask, nexthop = rest[0], rest[1], rest[2]
    pfx = _mask_to_prefix(mask)
    prefix = f"{net}/{pfx}" if pfx is not None else f"{net} {mask}"
    tail = rest[3:]
    name = ""
    ad = None
    if 'name' in tail:
        idx = tail.index('name')
        name = ' '.join(tail[idx + 1:]).strip()
        tail = tail[:idx]
    for t in tail:
        if t.isdigit():
            ad = t
            break
    return {"prefix": prefix, "next_hop": nexthop, "ad": ad, "name": name, "vrf": vrf,
             "raw_lines": [line]}


def _parse_router_block(header, body):
    """router ospf|eigrp|bgp|rip <id>."""
    toks = header.split()
    proto = toks[1] if len(toks) > 1 else ""
    rid = toks[2] if len(toks) > 2 else ""
    details = []
    dist_refs = []  # (acl, direction)
    for b in body:
        s = b.strip()
        low = s.lower()
        if low.startswith(('network ', 'neighbor ', 'redistribute ', 'distribute-list ')):
            details.append(s)
        if low.startswith('distribute-list '):
            m = re.match(r'distribute-list\s+(?:prefix\s+)?(\S+)\s+(in|out)', low)
            if m:
                dist_refs.append((m.group(1), m.group(2)))
    return {
        "proto": proto, "id": rid, "details": details,
        "raw": "\n".join([header] + body),
    }, dist_refs


# --- Analisi principale (pura, testabile) ----------------------------------

def analyze_config(content):
    """Analizza il testo di una running-config e ritorna la struttura del
    contratto (senza i campi meta ip/hostname/tenant, aggiunti a valle)."""
    lines = running_config(content)

    interfaces = []
    svis = {}            # vlan_id -> {"ip","shutdown"}
    vlan_defs = {}       # vlan_id -> name
    static_routes = []
    protocols = []
    vrfs = {}            # name -> {"name","rd","interfaces"[]}
    acls = {}            # name -> {"name","kind","entries"[]}
    acl_refs = []        # {"name","where","target","direction","context","routing"}
    vpn = []

    access_use = {}      # vlan_id -> "IFACE (access)" (per undefined)
    used_vlans = set()

    for header, body in _iter_blocks(lines):
        low = header.lower()

        # --- Interfacce ---
        if low.startswith('interface '):
            iface = _parse_interface(header, body)
            interfaces.append(iface)
            nm = iface["name"]
            nml = nm.lower()
            # SVI
            if nml.startswith('vlan'):
                vid = nm[4:] if nm[:4].lower() == 'vlan' else ''
                vid = vid.strip()
                if vid.isdigit():
                    svis[vid] = {"ip": iface["ip"], "shutdown": iface["shutdown"]}
                    used_vlans.add(vid)
            # utilizzo VLAN
            if iface["access_vlan"]:
                used_vlans.add(iface["access_vlan"])
                access_use.setdefault(iface["access_vlan"], f"{nm} (access)")
            if iface["voice_vlan"]:
                used_vlans.add(iface["voice_vlan"])
                access_use.setdefault(iface["voice_vlan"], f"{nm} (voice)")
            for v in _expand_vlan_list(iface["trunk_allowed"]):
                used_vlans.add(v)
            # riferimenti ACL su interfaccia
            if iface["acl_in"]:
                acl_refs.append({"name": iface["acl_in"], "where": "interface",
                                 "target": nm, "direction": "in",
                                 "context": f"interface {nm} (in)", "routing": False})
            if iface["acl_out"]:
                acl_refs.append({"name": iface["acl_out"], "where": "interface",
                                 "target": nm, "direction": "out",
                                 "context": f"interface {nm} (out)", "routing": False})
            # VRF forwarding sull'interfaccia
            for b in body:
                s = b.strip().lower()
                m = re.match(r'(?:ip\s+)?vrf forwarding (\S+)', s)
                if m:
                    vname = b.strip().split()[-1]
                    vrfs.setdefault(vname, {"name": vname, "rd": "", "interfaces": []})
                    vrfs[vname]["interfaces"].append(nm)
            # Tunnel -> VPN
            if nml.startswith('tunnel'):
                vpn.append({"kind": "tunnel", "name": nm,
                            "raw": "\n".join([header] + body)})
            continue

        # --- VLAN definitions ---
        m = re.match(r'vlan (\d[\d,\-]*)\s*$', low)
        if m and not low.startswith('vlan configuration') and not low.startswith('vlan internal'):
            ids = _expand_vlan_list(m.group(1))
            name = ""
            for b in body:
                bs = b.strip()
                if bs.lower().startswith('name '):
                    name = bs[5:].strip()
            for vid in ids:
                vlan_defs[vid] = name if len(ids) == 1 else vlan_defs.get(vid, "")
            continue

        # --- Static routes ---
        if low.startswith('ip route '):
            r = _parse_static_route(header.strip())
            if r:
                static_routes.append(r)
            continue

        # --- Router blocks ---
        if low.startswith('router '):
            proto_info, dist_refs = _parse_router_block(header.strip(), body)
            protocols.append(proto_info)
            ctx = f"router {proto_info['proto']} {proto_info['id']}".strip()
            for acl, direction in dist_refs:
                acl_refs.append({"name": acl, "where": "route-map", "target": ctx,
                                 "direction": direction,
                                 "context": f"distribute-list in {ctx}", "routing": True})
            continue

        # --- VRF ---
        m = re.match(r'(?:ip vrf|vrf definition) (\S+)', low)
        if m:
            vname = header.strip().split()[-1]
            v = vrfs.setdefault(vname, {"name": vname, "rd": "", "interfaces": []})
            for b in body:
                bs = b.strip()
                if bs.lower().startswith('rd '):
                    v["rd"] = bs[3:].strip()
            continue

        # --- ACL numerati ---
        m = re.match(r'access-list (\d+) (.*)$', header.strip(), re.IGNORECASE)
        if m:
            num = m.group(1)
            rest = m.group(2).strip()
            n = int(num)
            kind = "standard" if (1 <= n <= 99 or 1300 <= n <= 1999) else "extended"
            acl = acls.setdefault(num, {"name": num, "kind": kind, "entries": []})
            action = rest.split()[0] if rest else ""
            acl["entries"].append({"seq": "", "action": action, "text": rest})
            continue

        # --- ACL nominali ---
        m = re.match(r'ip access-list (standard|extended) (\S+)', low)
        if m:
            kind = "named-std" if m.group(1) == 'standard' else "named-ext"
            aname = header.strip().split()[-1]
            acl = acls.setdefault(aname, {"name": aname, "kind": kind, "entries": []})
            acl["kind"] = kind
            for b in body:
                bs = b.strip()
                mm = re.match(r'(\d+)\s+(.*)$', bs)
                if mm:
                    seq, txt = mm.group(1), mm.group(2)
                else:
                    seq, txt = "", bs
                action = txt.split()[0] if txt else ""
                acl["entries"].append({"seq": seq, "action": action, "text": txt})
            continue

        # --- line vty/con: access-class ---
        if low.startswith('line '):
            for b in body:
                bs = b.strip()
                mm = re.match(r'access-class (\S+) (in|out)', bs, re.IGNORECASE)
                if mm:
                    acl_refs.append({"name": mm.group(1), "where": "line",
                                     "target": header.strip()[5:], "direction": mm.group(2).lower(),
                                     "context": f"{header.strip()} (access-class {mm.group(2).lower()})",
                                     "routing": False})
            continue

        # --- route-map: match ip address ---
        m = re.match(r'route-map (\S+)(?:\s+(permit|deny)\s+(\d+))?', low)
        if m:
            rmname = header.strip().split()[1] if len(header.strip().split()) > 1 else ""
            seq = m.group(3) or ""
            ctx = f"route-map {rmname} seq {seq}".strip()
            for b in body:
                bs = b.strip()
                mm = re.match(r'match ip address (?:prefix-list )?(.+)$', bs, re.IGNORECASE)
                if mm:
                    for acl in mm.group(1).split():
                        acl_refs.append({"name": acl, "where": "route-map",
                                         "target": rmname, "direction": "",
                                         "context": ctx, "routing": True})
            continue

        # --- crypto (VPN best-effort) ---
        if low.startswith('crypto map '):
            toks = header.strip().split()
            vpn.append({"kind": "crypto-map", "name": toks[2] if len(toks) > 2 else "",
                        "raw": "\n".join([header] + body)})
            continue
        if low.startswith('crypto isakmp'):
            toks = header.strip().split()
            vpn.append({"kind": "isakmp", "name": toks[-1] if len(toks) > 2 else "",
                        "raw": "\n".join([header] + body)})
            continue
        if low.startswith('crypto ipsec profile') or low.startswith('crypto ipsec transform-set'):
            toks = header.strip().split()
            vpn.append({"kind": "ipsec-profile", "name": toks[-1],
                        "raw": "\n".join([header] + body)})
            continue

        # --- snmp community con ACL / ip nat inside source list (righe singole) ---
        # (gestite anche come header senza body)
        # snmp-server community <str> [RO|RW] [acl]
        mm = re.match(r'snmp-server community (\S+)(?:\s+(ro|rw))?(?:\s+(\S+))?', low)
        if mm and mm.group(3):
            acl = header.strip().split()[-1]
            acl_refs.append({"name": acl, "where": "snmp", "target": mm.group(1),
                             "direction": "", "context": f"snmp-server community {mm.group(1)}",
                             "routing": False})
            continue
        mm = re.match(r'ip nat inside source list (\S+)', low)
        if mm:
            acl = header.strip().split()[5]
            acl_refs.append({"name": acl, "where": "nat", "target": "nat",
                             "direction": "", "context": "ip nat inside source list",
                             "routing": False})
            continue

    # --- Costruzione vista VLAN ---
    # VLAN apprese via VTP (sezione SHOW VLAN del backup): contano come definite
    # e arricchiscono i nomi; nell'elenco entrano solo se usate localmente.
    vtp_vlans = parse_show_vlan(content)
    all_vids = set(vlan_defs) | set(svis) | {v for v in vtp_vlans if v in used_vlans}
    access_by_vlan = {}
    trunk_by_vlan = {}
    for iface in interfaces:
        if iface["mode"] == "access" and iface["access_vlan"]:
            access_by_vlan.setdefault(iface["access_vlan"], []).append(iface["name"])
        for v in _expand_vlan_list(iface["trunk_allowed"]):
            trunk_by_vlan.setdefault(v, []).append(iface["name"])
    vlans = []
    for vid in sorted(all_vids, key=lambda x: int(x) if x.isdigit() else 0):
        vlans.append({
            "id": vid,
            "name": vlan_defs.get(vid) or vtp_vlans.get(vid, ""),
            "svi": svis.get(vid),
            "access_ifaces": access_by_vlan.get(vid, []),
            "trunk_ifaces": trunk_by_vlan.get(vid, []),
        })

    # --- Validazione ---
    defined_acls = set(acls)
    applied_names = {r["name"] for r in acl_refs}
    # applied per-acl
    for name, acl in acls.items():
        acl["applied"] = [{"where": r["where"], "target": r["target"],
                           "direction": r["direction"]}
                          for r in acl_refs if r["name"] == name]

    unused_acls = sorted(defined_acls - applied_names)
    missing_acls = []
    seen_missing = set()
    for r in acl_refs:
        if r["name"] not in defined_acls and r["name"] not in seen_missing:
            seen_missing.add(r["name"])
            missing_acls.append({"name": r["name"], "referenced_in": r["context"]})

    route_acl_refs = [{"context": r["context"], "acl": r["name"]}
                      for r in acl_refs if r["routing"]]

    # Definite = blocchi vlan locali + SVI + VTP; "non usate" solo tra quelle
    # definite LOCALMENTE (segnalare le VLAN VTP non usate su un access switch
    # sarebbe rumore: vivono sul server VTP).
    defined_vlans = all_vids | set(vtp_vlans)
    unused_vlans = sorted(
        [v for v in (set(vlan_defs) | set(svis))
         if v not in used_vlans and v != "1"],
        key=lambda x: int(x) if x.isdigit() else 0)
    undefined_vlans = []
    seen_undef = set()
    for vid, ctx in access_use.items():
        if vid not in defined_vlans and vid != "1" and vid not in seen_undef:
            seen_undef.add(vid)
            undefined_vlans.append({"vlan": vid, "referenced_in": ctx})

    return {
        "vlans": vlans,
        "interfaces": interfaces,
        "routing": {
            "static": static_routes,
            "protocols": protocols,
            "vrfs": list(vrfs.values()),
        },
        "acls": [dict(a) for a in acls.values()],
        "vpn": vpn,
        "validation": {
            "unused_acls": unused_acls,
            "missing_acls": missing_acls,
            "unused_vlans": unused_vlans,
            "undefined_vlans": undefined_vlans,
            "route_acl_refs": route_acl_refs,
        },
    }


# --- Rilevamento tipo config (multi-vendor) ----------------------------------

_FORTIOS_VENDORS = {'fortinet', 'fortigate', 'fortios'}
_WLC_AIREOS_VENDORS = {'cisco_wlc'}


def detect_config_type(content, device=None):
    """Determina il tipo di configurazione: 'ios' | 'fortios' | 'wlc-aireos'.
    Usa il campo Vendor dell'inventario se disponibile, altrimenti riconosce
    il formato dal contenuto (sniffing). Tollerante: default 'ios'."""
    try:
        if device:
            vendor = (device.get('Vendor') or '').strip().lower()
            if vendor in _FORTIOS_VENDORS:
                return 'fortios'
            if vendor in _WLC_AIREOS_VENDORS:
                return 'wlc-aireos'
            if vendor:
                # cisco_9800 (IOS-XE) e altri: formato IOS
                return 'ios'
        text = content or ''
        head = text[:4000]
        # FortiOS: inizia con #config-version= e usa blocchi config/edit/next/end
        if '#config-version=' in head:
            return 'fortios'
        if re.search(r'^config system (global|interface)\b', text, re.MULTILINE):
            return 'fortios'
        # AireOS 'show run-config commands': righe 'config sysname/wlan/interface ...'
        if re.search(r'^config (sysname|wlan|interface|radius|mobility|network)\b',
                     text, re.MULTILINE):
            return 'wlc-aireos'
        # AireOS 'show run-config' tabellare
        if re.search(r'^System Name\.{3,}', text, re.MULTILINE):
            return 'wlc-aireos'
    except Exception:
        pass
    return 'ios'


# --- FortiOS ------------------------------------------------------------------

_FORTI_TOKEN = re.compile(r'"[^"]*"|\S+')


def _forti_tokens(s):
    """Tokenizza una riga FortiOS rispettando le stringhe tra doppi apici."""
    return [t[1:-1] if t.startswith('"') and t.endswith('"') and len(t) >= 2 else t
            for t in _FORTI_TOKEN.findall(s)]


def _forti_tree(content):
    """Parsa la struttura a blocchi config/edit/next/end di FortiOS in un albero:
    nodo = {"sets": {chiave: [valori]}, "children": {nome: nodo}}. Tollerante a
    blocchi non chiusi o annidamenti anomali."""
    root = {"sets": {}, "children": {}}
    stack = [root]
    for raw in (content or '').splitlines():
        s = raw.strip()
        if not s or s.startswith('#'):
            continue
        low = s.lower()
        try:
            if low.startswith('config '):
                name = s[7:].strip().strip('"')
                node = stack[-1]["children"].setdefault(
                    name, {"sets": {}, "children": {}})
                stack.append(node)
            elif low.startswith('edit '):
                key = s[5:].strip().strip('"')
                node = stack[-1]["children"].setdefault(
                    key, {"sets": {}, "children": {}})
                stack.append(node)
            elif low in ('next', 'end'):
                if len(stack) > 1:
                    stack.pop()
            elif low.startswith('set '):
                toks = _forti_tokens(s)
                if len(toks) >= 2:
                    stack[-1]["sets"][toks[1].lower()] = toks[2:]
        except Exception:
            continue
    return root


def _forti_get(root, path):
    """Naviga l'albero FortiOS per nome sezione (es. 'firewall policy').
    Ritorna il nodo o None."""
    return root["children"].get(path)


def _forti_set1(node, key, default=''):
    """Primo valore di un 'set' (stringa), oppure default."""
    vals = node["sets"].get(key)
    return vals[0] if vals else default


def _forti_ip_cidr(node):
    """'set ip A.B.C.D MASK' -> 'A.B.C.D/nn'."""
    vals = node["sets"].get('ip') or []
    return _ip_addr_to_cidr(vals) if vals else ''


def analyze_fortios_config(content):
    """Analizza una configurazione FortiOS (FortiGate). Pura, tollerante.
    Ritorna interfacce, policy firewall, oggetti address/service, VIP, rotte
    statiche, VPN, VLAN e i controlli di validazione specifici."""
    root = _forti_tree(content)

    # --- Hostname ---
    hostname = ''
    glob = _forti_get(root, 'system global')
    if glob:
        hostname = _forti_set1(glob, 'hostname')

    # --- Interfacce (+ VLAN) ---
    interfaces = []
    vlans = []
    ifs = _forti_get(root, 'system interface')
    if ifs:
        for name, n in ifs["children"].items():
            iface = {
                "name": name,
                "ip": _forti_ip_cidr(n),
                "allowaccess": n["sets"].get('allowaccess', []),
                "vdom": _forti_set1(n, 'vdom'),
                "role": _forti_set1(n, 'role'),
                "description": _forti_set1(n, 'description'),
                "vlanid": _forti_set1(n, 'vlanid'),
                "parent": _forti_set1(n, 'interface'),
                "status": _forti_set1(n, 'status', 'up'),
            }
            interfaces.append(iface)
            if iface["vlanid"]:
                vlans.append({"id": iface["vlanid"], "name": name,
                              "parent": iface["parent"], "ip": iface["ip"]})

    # --- Policy firewall ---
    policies = []
    pol = _forti_get(root, 'firewall policy')
    if pol:
        for pid, n in pol["children"].items():
            policies.append({
                "id": pid,
                "name": _forti_set1(n, 'name'),
                "srcintf": n["sets"].get('srcintf', []),
                "dstintf": n["sets"].get('dstintf', []),
                "srcaddr": n["sets"].get('srcaddr', []),
                "dstaddr": n["sets"].get('dstaddr', []),
                "service": n["sets"].get('service', []),
                "action": _forti_set1(n, 'action', 'deny'),
                "schedule": _forti_set1(n, 'schedule'),
                "nat": _forti_set1(n, 'nat', 'disable'),
                "status": _forti_set1(n, 'status', 'enable'),
                "logtraffic": _forti_set1(n, 'logtraffic', ''),
            })

    # --- Oggetti address/service, gruppi, VIP ---
    def _names_of(section, extra=None):
        node = _forti_get(root, section)
        out = []
        if node:
            for name, n in node["children"].items():
                item = {"name": name}
                for k in (extra or []):
                    item[k] = (n["sets"].get(k, [])
                               if k == 'member' else _forti_set1(n, k))
                out.append(item)
        return out

    addresses = _names_of('firewall address', ['subnet', 'type', 'comment'])
    addr_groups = _names_of('firewall addrgrp', ['member'])
    services = _names_of('firewall service custom',
                         ['tcp-portrange', 'udp-portrange', 'protocol'])
    service_groups = _names_of('firewall service group', ['member'])
    vips = _names_of('firewall vip',
                     ['extip', 'mappedip', 'extintf', 'extport', 'mappedport'])

    # --- Rotte statiche ---
    static_routes = []
    rst = _forti_get(root, 'router static')
    if rst:
        for seq, n in rst["children"].items():
            dst = n["sets"].get('dst') or []
            static_routes.append({
                "seq": seq,
                "prefix": _ip_addr_to_cidr(dst) or ' '.join(dst) or '0.0.0.0/0',
                "next_hop": _forti_set1(n, 'gateway'),
                "device": _forti_set1(n, 'device'),
                "distance": _forti_set1(n, 'distance'),
            })

    # --- VPN IPsec (nomi fase 1 / fase 2) ---
    phase1 = []
    phase2 = []
    for sec in ('vpn ipsec phase1-interface', 'vpn ipsec phase1'):
        node = _forti_get(root, sec)
        if node:
            phase1.extend(node["children"].keys())
    for sec in ('vpn ipsec phase2-interface', 'vpn ipsec phase2'):
        node = _forti_get(root, sec)
        if node:
            phase2.extend(node["children"].keys())

    # --- Validazione ---
    any_any = []
    disabled_pol = []
    unlogged_pol = []
    for p in policies:
        label = f"{p['id']}" + (f" ({p['name']})" if p['name'] else '')
        src_all = any(a.lower() == 'all' for a in p['srcaddr'])
        dst_all = any(a.lower() == 'all' for a in p['dstaddr'])
        if p['action'] == 'accept' and src_all and dst_all:
            any_any.append(label)
        if p['status'] == 'disable':
            disabled_pol.append(label)
        if p['logtraffic'] == 'disable':
            unlogged_pol.append(label)

    # Oggetti inutilizzati: definiti ma mai riferiti da policy / gruppi
    used_addr = set()
    used_svc = set()
    for p in policies:
        used_addr.update(a.lower() for a in p['srcaddr'] + p['dstaddr'])
        used_svc.update(s.lower() for s in p['service'])
    for g in addr_groups:
        used_addr.update(m.lower() for m in g.get('member', []))
    for g in service_groups:
        used_svc.update(m.lower() for m in g.get('member', []))
    vip_names = {v['name'].lower() for v in vips}
    unused_addresses = sorted(
        a['name'] for a in addresses
        if a['name'].lower() not in used_addr and a['name'].lower() != 'all')
    unused_services = sorted(
        s['name'] for s in services
        if s['name'].lower() not in used_svc and s['name'].lower() != 'all')
    unused_addr_groups = sorted(
        g['name'] for g in addr_groups
        if g['name'].lower() not in used_addr and g['name'].lower() not in vip_names)

    # Accesso di management insicuro (http/telnet in allowaccess)
    insecure_mgmt = []
    for i in interfaces:
        bad = [a for a in i['allowaccess'] if a.lower() in ('http', 'telnet')]
        if bad:
            insecure_mgmt.append({"name": i['name'], "allowaccess": bad})

    # Admin senza trusthost
    admins_no_trusthost = []
    adm = _forti_get(root, 'system admin')
    if adm:
        for name, n in adm["children"].items():
            if not any(k.startswith('trusthost') for k in n["sets"]):
                admins_no_trusthost.append(name)

    # Logging: almeno una sezione 'log ... setting' con 'set status enable'
    logging_enabled = False
    for sec_name, node in root["children"].items():
        if re.match(r'^log\b.*\bsetting$', sec_name):
            if _forti_set1(node, 'status') == 'enable':
                logging_enabled = True
                break

    return {
        "hostname": hostname,
        "interfaces": interfaces,
        "vlans": vlans,
        "policies": policies,
        "addresses": addresses,
        "addr_groups": addr_groups,
        "services": services,
        "service_groups": service_groups,
        "vips": vips,
        "routing": {"static": static_routes},
        "vpn": {"phase1": phase1, "phase2": phase2},
        "validation": {
            "any_any_policies": any_any,
            "disabled_policies": disabled_pol,
            "unlogged_policies": unlogged_pol,
            "unused_addresses": unused_addresses,
            "unused_addr_groups": unused_addr_groups,
            "unused_services": unused_services,
            "insecure_mgmt_interfaces": insecure_mgmt,
            "admins_without_trusthost": admins_no_trusthost,
            "logging_disabled": not logging_enabled,
        },
    }


def parse_fortigate_config(text):
    """Parser dedicato al sub-tab Firewall del Config Analyzer: estrae policy,
    interfacce/zone, VIP/NAT e oggetti address/service da una config FortiOS
    grezza. Sezione-based (config/edit/set/next/end), pura e tollerante —
    non solleva mai eccezioni su input vuoto o non riconosciuto."""
    try:
        root = _forti_tree(text or '')

        # --- Policy firewall ---
        policies = []
        pol = _forti_get(root, 'firewall policy')
        if pol:
            for pid, n in pol["children"].items():
                policies.append({
                    "id": pid,
                    "name": _forti_set1(n, 'name'),
                    "srcintf": n["sets"].get('srcintf', []),
                    "dstintf": n["sets"].get('dstintf', []),
                    "srcaddr": n["sets"].get('srcaddr', []),
                    "dstaddr": n["sets"].get('dstaddr', []),
                    "service": n["sets"].get('service', []),
                    "action": _forti_set1(n, 'action', 'deny'),
                    "nat": _forti_set1(n, 'nat', 'disable'),
                    "status": _forti_set1(n, 'status', 'enable'),
                })

        # --- Zone: nome zona -> interfacce membro ---
        zone_of_iface = {}
        zones = _forti_get(root, 'system zone')
        if zones:
            for zname, n in zones["children"].items():
                for member in n["sets"].get('interface', []):
                    zone_of_iface[member] = zname

        # --- Interfacce (+ zona) ---
        interfaces_zones = []
        ifs = _forti_get(root, 'system interface')
        if ifs:
            for name, n in ifs["children"].items():
                interfaces_zones.append({
                    "name": name,
                    "ip": _forti_ip_cidr(n),
                    "vdom": _forti_set1(n, 'vdom'),
                    "zone": zone_of_iface.get(name, ''),
                    "status": _forti_set1(n, 'status', 'up'),
                })

        # --- VIP / NAT ---
        vips_nat = []
        vip = _forti_get(root, 'firewall vip')
        if vip:
            for name, n in vip["children"].items():
                vips_nat.append({
                    "name": name,
                    "extip": _forti_set1(n, 'extip'),
                    "mappedip": _forti_set1(n, 'mappedip'),
                    "extintf": _forti_set1(n, 'extintf'),
                    "extport": _forti_set1(n, 'extport'),
                    "mappedport": _forti_set1(n, 'mappedport'),
                })

        # --- Oggetti address/service ---
        addresses_services = []
        addr = _forti_get(root, 'firewall address')
        if addr:
            for name, n in addr["children"].items():
                addresses_services.append({
                    "kind": "address",
                    "name": name,
                    "subnet": _ip_addr_to_cidr(n["sets"].get('subnet', [])),
                    "type": _forti_set1(n, 'type'),
                })
        svc = _forti_get(root, 'firewall service custom')
        if svc:
            for name, n in svc["children"].items():
                addresses_services.append({
                    "kind": "service",
                    "name": name,
                    "tcp_portrange": _forti_set1(n, 'tcp-portrange'),
                    "udp_portrange": _forti_set1(n, 'udp-portrange'),
                    "protocol": _forti_set1(n, 'protocol'),
                })

        return {
            "policies": policies,
            "interfaces_zones": interfaces_zones,
            "vips_nat": vips_nat,
            "addresses_services": addresses_services,
        }
    except Exception:
        return {"policies": [], "interfaces_zones": [], "vips_nat": [], "addresses_services": []}


# --- Cisco WLC (AireOS) -------------------------------------------------------

def analyze_wlc_config(content):
    """Analizza la config di un WLC Cisco AireOS ('show run-config commands').
    Tollera anche il formato IOS-XE (Catalyst 9800): in quel caso riusa il
    parser IOS come base e aggiunge l'estrazione dei blocchi wlan. Pura."""
    text = content or ''
    is_aireos = bool(re.search(
        r'^config (sysname|wlan|interface|radius|mobility|network)\b',
        text, re.MULTILINE))

    wlans = {}   # id -> dict
    dyn_ifaces = {}
    radius = []
    mobility_group = ''
    hostname = ''
    mgmt_http = False
    base = None

    def _wlan(wid):
        return wlans.setdefault(wid, {
            "id": wid, "ssid": "", "profile": "", "enabled": False,
            "interface": "", "security": "open", "tkip": False,
            "broadcast_ssid": True,
        })

    if is_aireos:
        for raw in text.splitlines():
            s = raw.strip()
            low = s.lower()
            try:
                if low.startswith('config sysname '):
                    hostname = s.split(None, 2)[2]
                elif low.startswith('config wlan create '):
                    toks = _forti_tokens(s)
                    # config wlan create <id> <profile> [<ssid>]
                    if len(toks) >= 4:
                        w = _wlan(toks[3])
                        w["profile"] = toks[4] if len(toks) > 4 else ''
                        w["ssid"] = toks[5] if len(toks) > 5 else w["profile"]
                elif re.match(r'config wlan (enable|disable) (\S+)', low):
                    m = re.match(r'config wlan (enable|disable) (\S+)', low)
                    if m.group(2) != 'all':
                        _wlan(m.group(2))["enabled"] = (m.group(1) == 'enable')
                elif low.startswith('config wlan interface '):
                    toks = s.split()
                    if len(toks) >= 5:
                        _wlan(toks[3])["interface"] = toks[4]
                elif low.startswith('config wlan broadcast-ssid disable '):
                    _wlan(s.split()[-1])["broadcast_ssid"] = False
                elif low.startswith('config wlan security '):
                    toks = low.split()
                    wid = toks[-1]
                    rest = ' '.join(toks[3:-1])
                    w = _wlan(wid)
                    if rest == 'wpa disable':
                        w["security"] = 'open'
                    elif 'wpa wpa2 enable' in rest:
                        w["security"] = 'WPA2'
                    elif 'wpa wpa3 enable' in rest or 'wpa akm sae enable' in rest:
                        w["security"] = 'WPA3'
                    elif rest == 'wpa enable' and w["security"] == 'open':
                        w["security"] = 'WPA'
                    elif 'wpa wpa1 enable' in rest:
                        w["security"] = 'WPA'
                    if 'ciphers tkip enable' in rest:
                        w["tkip"] = True
                elif low.startswith('config interface create '):
                    toks = s.split()
                    if len(toks) >= 4:
                        dyn_ifaces[toks[3]] = {"name": toks[3],
                                               "vlan": toks[4] if len(toks) > 4 else '',
                                               "ip": ''}
                elif low.startswith('config interface address '):
                    toks = s.split()
                    # config interface address [dynamic-interface] <name> <ip> <mask> [gw]
                    t = toks[3:]
                    if t and t[0] == 'dynamic-interface':
                        t = t[1:]
                    if len(t) >= 3:
                        d = dyn_ifaces.setdefault(t[0], {"name": t[0], "vlan": '', "ip": ''})
                        d["ip"] = _ip_addr_to_cidr(t[1:3])
                elif low.startswith('config interface vlan '):
                    toks = s.split()
                    if len(toks) >= 5:
                        d = dyn_ifaces.setdefault(toks[3], {"name": toks[3], "vlan": '', "ip": ''})
                        d["vlan"] = toks[4]
                elif re.match(r'config radius (auth|acct) add ', low):
                    toks = s.split()
                    if len(toks) >= 6:
                        radius.append({"kind": toks[2], "index": toks[4],
                                       "ip": toks[5],
                                       "port": toks[6] if len(toks) > 6 else ''})
                elif low.startswith('config mobility group domain '):
                    mobility_group = s.split()[-1]
                elif low == 'config network webmode enable':
                    mgmt_http = True
            except Exception:
                continue
    else:
        # IOS-XE (Catalyst 9800): base IOS + blocchi 'wlan <profile> <id> <ssid>'
        try:
            base = analyze_config(text)
        except Exception:
            base = None
        for header, body in _iter_blocks(running_config(text)):
            m = re.match(r'wlan (\S+) (\d+) (\S+)', header.strip(), re.IGNORECASE)
            if not m:
                continue
            w = _wlan(m.group(2))
            w["profile"], w["ssid"] = m.group(1), m.group(3)
            w["enabled"] = True
            sec = 'WPA2'
            for b in body:
                bl = b.strip().lower()
                if bl == 'shutdown':
                    w["enabled"] = False
                elif bl == 'no security wpa':
                    sec = 'open'
                elif 'security wpa wpa3' in bl or 'sae' in bl:
                    sec = 'WPA3'
                elif 'security wpa wpa1' in bl:
                    sec = 'WPA'
                elif 'tkip' in bl:
                    w["tkip"] = True
                elif bl == 'no broadcast-ssid':
                    w["broadcast_ssid"] = False
            w["security"] = sec
        m = re.search(r'^hostname (\S+)', text, re.MULTILINE)
        if m:
            hostname = m.group(1)

    wlan_list = sorted(wlans.values(),
                       key=lambda w: int(w["id"]) if w["id"].isdigit() else 0)

    # --- Validazione ---
    def _label(w):
        return f"{w['id']}" + (f" ({w['ssid']})" if w['ssid'] else '')

    validation = {
        "open_wlans": [_label(w) for w in wlan_list if w["security"] == 'open'],
        "legacy_tkip_wlans": [_label(w) for w in wlan_list
                              if w["tkip"] or w["security"] == 'WPA'],
        "disabled_wlans": [_label(w) for w in wlan_list if not w["enabled"]],
        "broadcast_ssid_off": [_label(w) for w in wlan_list
                               if not w["broadcast_ssid"]],
        "management_http": mgmt_http,
    }

    result = {
        "hostname": hostname,
        "platform": "aireos" if is_aireos else "iosxe",
        "wlans": wlan_list,
        "dynamic_interfaces": list(dyn_ifaces.values()),
        "radius_servers": radius,
        "mobility_group": mobility_group,
        "validation": validation,
    }
    if base:
        result["ios_base"] = base
    return result


# --- Config Converter (deterministico, FortiOS <-> IOS) ----------------------

_CONVERT_VENDORS = {'ios', 'fortios'}


def _prefix_to_mask(pfx):
    """Da lunghezza prefisso (int) a mask dotted. '' se non valida."""
    try:
        n = int(pfx)
        if not 0 <= n <= 32:
            return ''
        v = (0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF if n else 0
        return '.'.join(str((v >> s) & 0xFF) for s in (24, 16, 8, 0))
    except Exception:
        return ''


def _cidr_split(cidr):
    """'a.b.c.d/nn' -> ('a.b.c.d', 'mask dotted') oppure (None, None)."""
    if not cidr or '/' not in cidr:
        return None, None
    ip, _, pfx = cidr.partition('/')
    mask = _prefix_to_mask(pfx)
    return (ip, mask) if mask else (None, None)


def _forti_render_stanza(section, key, node):
    """Ricostruisce il testo di una stanza FortiOS (config/edit/set/next/end)
    dal nodo dell'albero. Solo il livello 'sets' (sufficiente come stanza raw)."""
    lines = [f'config {section}', f'    edit "{key}"']
    for k, vals in node["sets"].items():
        rendered = ' '.join(f'"{v}"' if (' ' in v or v == '') else v for v in vals)
        lines.append(f'        set {k} {rendered}'.rstrip())
    lines.extend(['    next', 'end'])
    return '\n'.join(lines)


def _convert_fortios_to_ios(source_text):
    root = _forti_tree(source_text)
    mapped = []
    unmapped = []
    handled = {'system interface', 'router static', 'firewall address',
               'system global'}

    ifs = _forti_get(root, 'system interface')
    if ifs:
        for name, n in ifs["children"].items():
            src = _forti_render_stanza('system interface', name, n)
            vlanid = _forti_set1(n, 'vlanid')
            parent = _forti_set1(n, 'interface')
            tgt_name = f"{parent}.{vlanid}" if (vlanid and parent) else name
            lines = [f"interface {tgt_name}"]
            if vlanid and parent:
                lines.append(f" encapsulation dot1Q {vlanid}")
            desc = _forti_set1(n, 'description') or _forti_set1(n, 'alias')
            if desc:
                lines.append(f" description {desc}")
            ip, mask = _cidr_split(_forti_ip_cidr(n))
            if ip:
                lines.append(f" ip address {ip} {mask}")
            if _forti_set1(n, 'status', 'up').lower() == 'down':
                lines.append(" shutdown")
            dropped = sorted(k for k in n["sets"]
                             if k not in ('ip', 'description', 'alias', 'status',
                                          'vlanid', 'interface'))
            note = f"set non convertiti: {', '.join(dropped)}" if dropped else ''
            mapped.append({"source": src, "target": '\n'.join(lines), "note": note})

    rst = _forti_get(root, 'router static')
    if rst:
        for seq, n in rst["children"].items():
            src = _forti_render_stanza('router static', seq, n)
            dst = n["sets"].get('dst') or ['0.0.0.0', '0.0.0.0']
            net = dst[0]
            mask = dst[1] if len(dst) > 1 else '0.0.0.0'
            gw = _forti_set1(n, 'gateway')
            dev = _forti_set1(n, 'device')
            hop = gw or dev
            if not hop:
                unmapped.append(src)
                continue
            dist = _forti_set1(n, 'distance')
            target = f"ip route {net} {mask} {hop}" + (f" {dist}" if dist else '')
            note = 'next-hop = interfaccia di uscita' if (dev and not gw) else ''
            mapped.append({"source": src, "target": target, "note": note})

    adr = _forti_get(root, 'firewall address')
    if adr:
        for name, n in adr["children"].items():
            src = _forti_render_stanza('firewall address', name, n)
            subnet = n["sets"].get('subnet') or []
            atype = _forti_set1(n, 'type', 'ipmask')
            if atype not in ('ipmask', '') or len(subnet) < 2:
                unmapped.append(src)
                continue
            ip, mask = subnet[0], subnet[1]
            if mask == '255.255.255.255':
                body = f" host {ip}"
            else:
                body = f" subnet {ip} {mask}"
            mapped.append({"source": src,
                           "target": f"object network {name}\n{body}",
                           "note": ''})

    # Policy e ogni altra sezione non gestita -> unmapped (stanza raw)
    for section, node in root["children"].items():
        if section in handled:
            continue
        if node["children"]:
            for key, child in node["children"].items():
                unmapped.append(_forti_render_stanza(section, key, child))
        elif node["sets"]:
            unmapped.append(_forti_render_stanza(section, '', node)
                            .replace('    edit ""\n', '').replace('    next\n', ''))
    return mapped, unmapped


def _convert_ios_to_fortios(source_text):
    mapped = []
    unmapped = []
    seq = 0
    for header, body in _iter_blocks(running_config(source_text)):
        low = header.lower()
        src = '\n'.join([header] + body)
        if low.startswith('interface '):
            iface = _parse_interface(header, body)
            lines = ['config system interface', f'    edit "{iface["name"]}"']
            if iface["description"]:
                lines.append(f'        set description "{iface["description"]}"')
            if iface["ip"]:
                ip, mask = _cidr_split(iface["ip"])
                if ip:
                    lines.append(f'        set ip {ip} {mask}')
            if iface["shutdown"]:
                lines.append('        set status down')
            lines.extend(['    next', 'end'])
            note = ''
            if iface["mode"] in ('access', 'trunk'):
                note = 'configurazione switchport non convertita'
            mapped.append({"source": src, "target": '\n'.join(lines), "note": note})
        elif low.startswith('ip route '):
            r = _parse_static_route(header.strip())
            if not r or r.get("vrf"):
                unmapped.append(src)
                continue
            net, mask = _cidr_split(r["prefix"])
            if not net:
                toks = r["prefix"].split()
                net, mask = (toks + ['', ''])[:2]
            seq += 1
            lines = ['config router static', f'    edit {seq}',
                     f'        set dst {net} {mask}',
                     f'        set gateway {r["next_hop"]}']
            if r.get("ad"):
                lines.append(f'        set distance {r["ad"]}')
            lines.extend(['    next', 'end'])
            mapped.append({"source": src, "target": '\n'.join(lines), "note": ''})
        else:
            unmapped.append(src)
    return mapped, unmapped


def convert_config(source_text, source_vendor, target_vendor):
    """Conversione deterministica (preview) tra 'fortios' e 'ios'.
    Ritorna {"mapped": [{source,target,note}], "unmapped": [str],
    "preview_text": str}. Solleva ValueError su vendor non validi."""
    sv = (source_vendor or '').strip().lower()
    tv = (target_vendor or '').strip().lower()
    if sv not in _CONVERT_VENDORS or tv not in _CONVERT_VENDORS:
        raise ValueError(f"Vendor non supportato: {source_vendor!r} -> {target_vendor!r} "
                         f"(supportati: {sorted(_CONVERT_VENDORS)})")
    if sv == tv:
        raise ValueError("Vendor sorgente e destinazione coincidono.")
    if sv == 'fortios':
        mapped, unmapped = _convert_fortios_to_ios(source_text or '')
        comment = '!'
    else:
        mapped, unmapped = _convert_ios_to_fortios(source_text or '')
        comment = '#'
    header = (f"{comment} Anteprima conversione {sv} -> {tv} — SentinelNet Config Converter\n"
              f"{comment} {len(mapped)} elementi mappati, {len(unmapped)} non mappati "
              f"(vedi elenco 'unmapped').\n")
    preview_text = header + '\n' + '\n\n'.join(m["target"] for m in mapped) + '\n'
    return {"mapped": mapped, "unmapped": unmapped, "preview_text": preview_text}


# --- I/O: lettura backup + scoping ------------------------------------------

def _find_freshest_backup(ip):
    """Trova il file di backup piu' recente per l'IP dato. Ritorna
    (path, tenant_folder) oppure (None, None)."""
    import core_engine
    best = None
    best_mtime = -1
    best_tenant = None
    folder = core_engine.BACKUP_FOLDER
    if not os.path.exists(folder):
        return None, None
    for root, _dirs, files in os.walk(folder):
        for f in files:
            if f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt":
                path = os.path.join(root, f)
                try:
                    mt = os.path.getmtime(path)
                except OSError:
                    mt = 0
                if mt > best_mtime:
                    best_mtime = mt
                    best = path
                    rel = os.path.relpath(root, folder)
                    best_tenant = rel.split(os.sep)[0] if rel != '.' else ''
    return best, best_tenant


def analyze_device(ip):
    """Legge il backup piu' recente per l'IP e ritorna analisi + meta.
    Ritorna None se non esiste alcun backup."""
    path, tenant_folder = _find_freshest_backup(ip)
    if not path:
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except OSError:
        return None

    # Lookup inventario prima dell'analisi: il Vendor guida il rilevamento tipo
    dev = None
    tenant = tenant_folder or ""
    try:
        import inventory_manager
        dev = next((d for d in inventory_manager.get_all_devices()
                    if d.get('IP') == ip), None)
    except Exception:
        dev = None

    config_type = detect_config_type(content, dev)

    is_firewall = False
    firewall = None
    if config_type == 'fortios':
        result = analyze_fortios_config(content)
        hostname = result.pop("hostname", "")
        is_firewall = True
        firewall = parse_fortigate_config(content)
    elif config_type == 'wlc-aireos':
        result = analyze_wlc_config(content)
        hostname = result.pop("hostname", "")
    else:
        result = analyze_config(content)
        hostname = ""
        m = re.search(r'^hostname (\S+)', content, re.MULTILINE)
        if m:
            hostname = m.group(1)
        result["vtp"] = parse_vtp_status(content)

    if dev:
        tenant = dev.get('Group', tenant) or tenant
        if not hostname:
            hostname = dev.get('Hostname', '') or ''
        # Firewall non-FortiGate (es. rilevato dall'inventario/CDP): tab
        # Firewall visibile ma senza il parsing dedicato (solo FortiGate).
        if not is_firewall and (dev.get('Type') or '').strip().lower() == 'firewall':
            is_firewall = True

    result["ip"] = ip
    result["hostname"] = hostname
    result["tenant"] = tenant
    result["config_type"] = config_type
    result["is_firewall"] = is_firewall
    result["firewall"] = firewall
    return result


def analyze_all(group_filter=None, allowed_groups=None):
    """Analizza tutti i dispositivi in inventario che hanno un backup, applicando
    lo scoping per sede (allowed_groups) ed un eventuale filtro di gruppo."""
    import inventory_manager
    devices = []
    for dev in inventory_manager.get_all_devices():
        ip = dev.get('IP')
        if not ip:
            continue
        group = dev.get('Group', 'Generale') or 'Generale'
        if allowed_groups is not None and group not in allowed_groups:
            continue
        if group_filter and group_filter != 'all' and group != group_filter:
            continue
        try:
            res = analyze_device(ip)
        except Exception:
            res = None
        if res:
            devices.append(res)
    return {"devices": devices}
