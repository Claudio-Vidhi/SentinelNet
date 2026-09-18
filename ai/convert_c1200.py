# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Cisco IOS/IOS-XE (Catalyst 2960/9200) -> Cisco Catalyst 1200 converter.

The Catalyst 1200 is not an IOS switch: it runs the Cisco SMB CLI. Ports are
numbered flat (``GigabitEthernet1``..``24``), VLANs are created inside
``vlan database`` and named under ``interface vlan N``, every interface block
must be closed with ``exit`` (the SMB CLI does not fall back to global mode
the way IOS does), and several IOS features simply do not exist. Everything
this module cannot translate with a C1200 command is returned as *unmapped*
rather than guessed: a preview that invents commands is worse than one that
says "do this by hand".

Syntax checked against the Cisco Catalyst 1200 Series CLI Guide and a real
C1200 running-config (4.1.x firmware).
"""

import re

from ai import config_analyzer

# Interface sub-commands translated (or explicitly noted) below; anything else
# in the block is listed in the note so it is never dropped silently.
_IF_HANDLED = ('description', 'switchport', 'ip address', 'no ip address',
               'shutdown', 'no shutdown', 'channel-group', 'spanning-tree portfast',
               'spanning-tree bpdu', 'negotiation auto', 'lacp port-priority',
               'lacp rate')

_IF_NAME = re.compile(r'([a-z-]+?)\s*(\d[\d/]*)$')

# 'show run' framing captured by a terminal log: not configuration, never
# worth an "unmapped" entry. The last alternative is the CLI prompt (SW1#sh run).
_SHOW_RUN_NOISE = re.compile(
    r'(building configuration|current configuration|last configuration change'
    r'|nvram config last updated|version \S+$|end$|\S+#)', re.I)


def _c1200_ifname(name):
    """IOS interface name -> C1200 name. Returns (name, note); name is '' when
    there is no unambiguous C1200 equivalent (note says why)."""
    low = (name or '').strip().lower()
    m = _IF_NAME.match(low)
    if not m:
        return '', f"interfaccia '{name}' non riconosciuta"
    kind, num = m.groups()
    if kind == 'vlan':
        return f"vlan {num}", ''
    if kind in ('port-channel', 'portchannel', 'po'):
        return f"po{num}", ''
    if kind not in ('gigabitethernet', 'gi', 'fastethernet', 'fa'):
        return '', (f"'{name}': porta uplink, la numerazione dipende dal modello "
                    "C1200 (4G/4X): assegnarla a mano")
    parts = num.split('/')
    if len(parts) == 3:
        unit, slot, port = parts
        if unit != '1':
            return '', f"'{name}': membro di stack {unit}, il C1200 non e' stackable"
        if slot != '0':
            return '', (f"'{name}': porta del modulo uplink, la numerazione dipende "
                        "dal modello C1200 (4G/4X): assegnarla a mano")
    elif len(parts) == 2:
        port = parts[1]
        if port == '0':
            # 9200 Gi0/0: out-of-band management port in Mgmt-vrf.
            return '', f"'{name}': porta di management out-of-band, assente sul C1200"
    else:
        port = parts[0]
    note = (f"porta FastEthernet '{name}' mappata su GigabitEthernet{port}"
            if kind.startswith('fa') else '')
    return f"GigabitEthernet{port}", note


def _quote(text):
    """C1200 quotes descriptions that contain spaces."""
    text = text.strip().strip('"')
    return f'"{text}"' if ' ' in text else text


def _convert_interface(body, iface, globals_out):
    """One IOS interface block -> C1200 lines. Returns (lines, note) with
    lines empty when the block cannot be translated at all."""
    name, note = _c1200_ifname(iface["name"])
    if not name:
        return [], note
    notes = [note] if note else []
    lines = [f"interface {name}"]

    if iface["description"]:
        lines.append(f"description {_quote(iface['description'])}")

    if iface["mode"] == 'svi':
        if iface["ip"]:
            addr, _, pfx = iface["ip"].partition('/')
            lines.append(f"ip address {addr} {config_analyzer._prefix_to_mask(int(pfx))}")
            if name == 'vlan 1':
                # VLAN 1 runs a DHCP client out of the box.
                lines.append("no ip address dhcp")
    elif iface["ip"]:
        # A routed physical port: the C1200 puts IP addresses on VLAN
        # interfaces, so there is nothing honest to emit here.
        return [], ("porta routed (no switchport): sul Catalyst 1200 "
                    "l'indirizzo va su una interface vlan")
    elif iface["channel_group"]:
        # A LAG member takes its L2 settings from the port-channel: the C1200
        # rejects switchport/STP commands on a port that belongs to a LAG.
        if iface["mode"] in ('trunk', 'access') or iface["voice_vlan"]:
            notes.append(f"switchport/STP della porta membro non riportati: sul C1200 "
                         f"li eredita da po{iface['channel_group']}")
    elif iface["mode"] == 'trunk':
        lines.append("switchport mode trunk")
        allowed = (iface["trunk_allowed"] or '').strip()
        if allowed.lower() in ('all', 'none'):
            lines.append(f"switchport trunk allowed vlan {allowed.lower()}")
        elif allowed:
            lines.append(f"switchport trunk allowed vlan add {allowed}")
        if iface["trunk_native"]:
            lines.append(f"switchport trunk native vlan {iface['trunk_native']}")
    elif iface["access_vlan"]:
        # Access is the C1200 default mode: the running-config shows only the VLAN.
        lines.append(f"switchport access vlan {iface['access_vlan']}")

    member = bool(iface["channel_group"])
    if iface["voice_vlan"] and not member:
        globals_out.add(f"voice vlan id {iface['voice_vlan']}")
        notes.append(f"voice VLAN {iface['voice_vlan']}: il C1200 la configura solo a livello "
                     "globale ('voice vlan id'), la porta va resa membro taggata in modalita' general")

    if member:
        ios_mode = ''
        for b in body:
            m = re.search(r'channel-group\s+\S+\s+mode\s+(\S+)', b.strip(), re.I)
            if m:
                ios_mode = m.group(1).lower()
        # C1200: 'on' (static) or 'auto' (LACP). No PAgP, no LACP passive.
        mode = 'on' if ios_mode in ('', 'on') else 'auto'
        if ios_mode == 'passive':
            notes.append("LACP passive non esiste sul C1200: usato 'auto' (LACP attivo)")
        elif ios_mode in ('desirable', 'auto'):
            notes.append(f"PAgP ({ios_mode}) non esiste sul C1200: convertito in LACP 'auto', "
                         "l'altro capo del link deve usare LACP")
        lines.append(f"channel-group {iface['channel_group']} mode {mode}")

    for b in body:
        low = b.strip().lower()
        if low.startswith('lacp port-priority '):
            lines.append(f"lacp port-priority {low.split()[-1]}")
        elif low.startswith('lacp rate '):
            lines.append(f"lacp timeout {'short' if low.split()[-1] == 'fast' else 'long'}")
        elif low.startswith('spanning-tree portfast'):
            if not member:
                lines.append("spanning-tree portfast")
        elif 'bpduguard' in low or 'bpdufilter' in low:
            notes.append("BPDU guard/filter per porta non disponibile sul Catalyst 1200")
        elif low.startswith('switchport port-security'):
            notes.append("port-security: sul Catalyst 1200 e' 'port security' con parametri "
                         "diversi, da rivedere a mano")

    if iface["shutdown"]:
        lines.append("shutdown")

    dropped = [b.strip() for b in body if not b.strip().lower().startswith(_IF_HANDLED)]
    if dropped:
        notes.append("non convertite: " + "; ".join(dropped))

    if len(lines) == 1:
        return [], "blocco senza configurazione traducibile"
    lines.append("exit")
    return lines, '; '.join(notes)


def _convert_global(header, body, globals_out):
    """One non-interface top-level block/line. Returns (lines, note); lines is
    None when the command has no C1200 equivalent, [] when it was absorbed
    into ``globals_out``."""
    s = header.strip()
    low = s.lower()

    if low.startswith('hostname '):
        name = s.split(None, 1)[1].strip()
        clean = re.sub(r'[^A-Za-z0-9-]', '-', name)
        note = ("hostname normalizzato: il C1200 ammette solo lettere, cifre e trattini"
                if clean != name else '')
        return [f"hostname {clean}"], note

    if re.match(r'vlan\s+\d[\d,\-]*\s*$', low):
        ids = s.split(None, 1)[1].strip()
        vname = ''
        for b in body:
            if b.strip().lower().startswith('name '):
                vname = b.strip().split(None, 1)[1].strip()
        lines = ["vlan database", f"vlan {ids}", "exit"]
        note = ''
        if vname and ids.isdigit():
            lines += [f"interface vlan {ids}", f"name {vname[:32]}", "exit"]
            if len(vname) > 32:
                note = "nome VLAN troncato a 32 caratteri (limite C1200)"
        elif vname:
            note = (f"nome '{vname}' non applicabile a un range di VLAN: "
                    "assegnarlo con 'name' sotto interface vlan")
        return lines, note

    if low.startswith('port-channel load-balance '):
        method = low.split()[-1]
        # C1200 hashes on MAC only, or MAC+IP: L4 ports are not an option.
        target = 'src-dst-mac' if method.endswith('mac') else 'src-dst-mac-ip'
        note = ('' if method == target else
                f"'{method}' non esiste sul C1200: usato il metodo piu' vicino ({target})")
        return [f"port-channel load-balance {target}"], note

    if low.startswith('lacp system-priority '):
        return [f"lacp system-priority {low.split()[-1]}"], ''

    if low.startswith('ip default-gateway '):
        return [f"ip default-gateway {s.split()[-1]}"], ''

    if low.startswith('ip route 0.0.0.0 0.0.0.0 '):
        return [f"ip default-gateway {s.split()[4]}"], \
            ("rotta di default convertita in default-gateway (in modalita' L2 "
             "il C1200 non ha rotte statiche)")

    if low.startswith('snmp-server community '):
        toks = s.split()
        access = 'ro'
        for t in toks[3:]:
            if t.lower() in ('ro', 'rw'):
                access = t.lower()
        # The SNMP agent is off until 'snmp-server server'.
        globals_out.add("snmp-server server")
        note = ("ACL di restrizione non riportata: sul C1200 si indica direttamente "
                "l'IP della management station") if len(toks) > 4 else ''
        return [f"snmp-server community {toks[2]} {access}"], note

    if low.startswith('snmp-server location ') or low.startswith('snmp-server contact '):
        return [s], ''

    if low.startswith('username '):
        toks = s.split()
        user = toks[1]
        # IOS and C1200 both default to level 1 when privilege is omitted.
        m = re.search(r'privilege\s+(\d+)', low)
        priv = m.group(1) if m else '1'
        hashed = bool(re.search(r'\b(?:password|secret)\s+(?:[5789]|sha512)\s', s))
        m = re.search(r'\b(?:password|secret)\s+(?:0\s+)?(\S+)\s*$', s)
        secret = m.group(1) if m else ''
        if hashed or not secret:
            return [f"username {user} password <PASSWORD> privilege {priv}"], \
                ("hash IOS non portabile sul C1200: impostare la password in chiaro "
                 "alla prima configurazione")
        return [f"username {user} password {secret} privilege {priv}"], ''

    if low.startswith('ip ssh ') or low.startswith('crypto key generate rsa'):
        globals_out.add("ip ssh server")
        return [], ''

    if low.startswith('spanning-tree mode '):
        mode = low.split()[-1]
        if mode in ('stp', 'rstp', 'mst', 'pvst', 'rapid-pvst'):
            return [f"spanning-tree mode {mode}"], ''
        return None, ''

    return None, ''


def convert_ios_to_c1200(source_text):
    """Cisco IOS (2960/9200) -> Catalyst 1200. Returns (mapped, unmapped);
    an unmapped block carries the reason as a trailing '!' comment."""
    lines = config_analyzer.running_config(source_text or '')
    mapped = []
    unmapped = []
    globals_out = set()
    used_ports = set()

    for header, body in config_analyzer._iter_blocks(lines):
        if _SHOW_RUN_NOISE.match(header.strip()):
            continue
        raw = "\n".join([header] + body)
        if header.strip().lower().startswith('interface '):
            iface = config_analyzer._parse_interface(header, body)
            out, note = _convert_interface(body, iface, globals_out)
            # 2960 Fa0/1 and Gi0/1 both land on GigabitEthernet1.
            if out and out[0].startswith('interface GigabitEthernet'):
                if out[0] in used_ports:
                    out, note = [], f"collisione: {out[0][10:]} gia' assegnata da un'altra porta IOS"
                else:
                    used_ports.add(out[0])
        else:
            out, note = _convert_global(header, body, globals_out)
            if out == []:
                # Absorbed into a global command emitted once at the end (SSH).
                continue
        if not out:
            unmapped.append(raw + (f"\n! {note}" if note else ''))
            continue
        mapped.append({"source": raw, "target": "\n".join(out), "note": note})

    for extra in sorted(globals_out):
        mapped.append({"source": '', "target": extra,
                       "note": "comando globale richiesto dal Catalyst 1200"})
    return mapped, unmapped
