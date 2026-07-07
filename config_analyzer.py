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

    result = analyze_config(content)

    # meta: hostname dalla config, tenant/hostname dall'inventario se disponibile
    hostname = ""
    m = re.search(r'^hostname (\S+)', content, re.MULTILINE)
    if m:
        hostname = m.group(1)
    tenant = tenant_folder or ""
    try:
        import inventory_manager
        dev = next((d for d in inventory_manager.get_all_devices()
                    if d.get('IP') == ip), None)
        if dev:
            tenant = dev.get('Group', tenant) or tenant
            if not hostname:
                hostname = dev.get('Hostname', '') or ''
    except Exception:
        pass

    result["ip"] = ip
    result["hostname"] = hostname
    result["tenant"] = tenant
    result["vtp"] = parse_vtp_status(content)
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
