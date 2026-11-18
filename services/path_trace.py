# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Percorso di un indirizzo attraverso gli apparati, letto dalle loro tabelle.

La vista Rotte mostra le tabelle; questa risponde alla domanda successiva:
**per quali apparati passa il traffico verso un indirizzo, e perche' su
ciascuno ha vinto quella riga**. Nessun pacchetto viene inviato: e' la tabella
che viene interpretata, non la rete che viene sondata. Restano percio' fuori le
policy che scartano, le interfacce down e i next-hop irraggiungibili, e la
vista lo dichiara invece di lasciar credere il contrario.

Per concatenare due salti serve un dato che le rotte da sole non danno:
**l'indirizzo delle interfacce**. Sapere che una rotta punta a 192.0.2.9 non
dice niente finche' non si sa quale apparato possiede 192.0.2.9. Da qui
``addresses_for``, che quel dato lo prende dove gia' esiste invece di aprire
una raccolta nuova:

- FortiGate: ``monitor/system/interface``, che la tab FortiGate interroga gia';
- Cisco: le rotte *local* (``L 10.0.0.1/32``) che il parser di `show ip route`
  estrae gia' — sono per definizione l'indirizzo di un'interfaccia.
"""
import ipaddress
import logging

logger = logging.getLogger("sentinelnet.path_trace")

# Distanza amministrativa per tipo, quando l'apparato non la dichiara. Sono i
# valori standard: servono a ordinare due rotte con lo stesso prefisso, e un
# numero dichiarato qui e' preferibile a uno nascosto dentro un ramo.
DEFAULT_AD = {"connected": 0, "local": 0, "static": 1, "bgp": 20,
              "eigrp": 90, "ospf": 110, "isis": 115, "rip": 120}

MAX_HOPS = 16


def _net(value):
    """``10.0.0.0/16`` in una rete, o None se non e' interpretabile."""
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None


def _addr(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def addresses_for(device, rows) -> list:
    """Gli indirizzi delle interfacce di UN apparato: ``[{iface, ip, network}]``.

    ``rows`` sono le righe gia' raccolte per quell'apparato: per uno switch
    bastano quelle, perche' una rotta local E' l'indirizzo di un'interfaccia.
    Per un FortiGate si chiede l'elenco interfacce, e se non risponde si resta
    senza: un salto che si ferma e' meglio di un salto attribuito all'apparato
    sbagliato.
    """
    out = []
    if (device.get("Vendor") or "").lower() == "fortinet":
        out.extend(_fortigate_addresses(device))
    for r in rows or []:
        if r.get("type") != "local":
            continue
        net = _net(r.get("network"))
        if net is None or net.prefixlen != 32:
            continue
        out.append({"iface": r.get("interface") or "",
                    "ip": str(net.network_address), "network": str(net)})
    return out


def _fortigate_addresses(device) -> list:
    from services import fortigate_service
    try:
        answer = fortigate_service.get_interfaces(device)
    except fortigate_service.FortiGateError as e:
        # Non solleva: senza interfacce il percorso si ferma a questo apparato,
        # e la vista lo dice. Non e' un motivo per non mostrare gli altri.
        logger.debug("interfacce non lette da %s: %s", device.get("IP"), e)
        return []
    data = answer.get("data")
    # L'endpoint monitor risponde con un dizionario per nome interfaccia; il
    # ripiego SSH risponde con testo, e da quello qui non si estrae niente.
    entries = list(data.values()) if isinstance(data, dict) else data
    if not isinstance(entries, (list, tuple)):
        return []
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # Alcune build di FortiOS chiamano il campo ipv4_address: la stessa
        # doppia lettura che fa gia' fortigate_service. Senza, l'apparato torna
        # zero indirizzi in silenzio e ogni suo next-hop diventa "fuori
        # inventario".
        ip = _addr(entry.get("ip") or entry.get("ipv4_address"))
        if ip is None:
            continue
        try:
            mask = int(entry.get("mask"))  # type: ignore[arg-type]
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except (TypeError, ValueError):
            net = ipaddress.ip_network(f"{ip}/32")
        # The alias ("wan1" for port1) is what the Routing Monitor shows.
        out.append({"iface": entry.get("name") or "", "ip": str(ip),
                    "network": str(net), "alias": entry.get("alias") or ""})
    return out


def _num(value):
    """Un numero, anche quando l'apparato lo manda come stringa. None se non
    c'e' o non e' interpretabile: scartare "110" come se fosse assente fa
    sembrare uguali due rotte che non lo sono, e nasce un ECMP inventato."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ad(row) -> int:
    d = _num(row.get("distance"))
    if d is not None:
        return d
    return DEFAULT_AD.get(row.get("type"), 255)


def candidates(rows, dst, vrf=None) -> list:
    """Le rotte che coprono l'indirizzo, dalla piu' specifica in giu'.

    L'ordine e' quello con cui decide un apparato: prefisso piu' lungo, poi
    distanza amministrativa, poi metrica. Le rotte local (il /32
    dell'interfaccia) non sono rotte di inoltro e restano fuori.
    When ``vrf`` is given (e.g. ``""`` for global or ``"VRF-OT"``), only
    routes belonging to that VRF are considered.
    """
    target = _addr(dst)
    if target is None:
        return []
    out = []
    for r in rows:
        if r.get("type") == "local":
            continue
        if vrf is not None and (r.get("vrf") or "") != vrf:
            continue
        net = _net(r.get("network"))
        if net is None or target not in net:
            continue
        metric = _num(r.get("metric"))
        out.append({**r, "prefixlen": net.prefixlen, "ad": _ad(r),
                    "metric": metric if metric is not None else 0})
    out.sort(key=lambda r: (-r["prefixlen"], r["ad"], r["metric"]))
    return out


def decided_by(cand) -> str:
    """Quale criterio ha deciso, fra le candidate ordinate.

    E' l'informazione che spiega la scelta: "vince il /24, e la distanza
    amministrativa non viene nemmeno guardata" e' il punto in cui si sbaglia a
    ragionare piu' spesso."""
    if len(cand) < 2:
        return "unica"
    first, second = cand[0], cand[1]
    if first["prefixlen"] != second["prefixlen"]:
        return "prefisso"
    if first["ad"] != second["ad"]:
        return "distanza"
    if first["metric"] != second["metric"]:
        return "metrica"
    return "ecmp"


def owner_of(hop_ip, addresses, exclude=None):
    """L'apparato che possiede quel next-hop, per IP di gestione.

    Si esclude quello da cui si esce: il next-hop sta su una rete connessa
    anche a lui, e senza il filtro ogni salto tornerebbe indietro. Si accetta
    solo l'indirizzo esatto di un'interfaccia — attribuire un salto per
    vicinanza di sottorete significherebbe inventare la topologia."""
    target = _addr(hop_ip)
    if target is None:
        return None
    for device_ip, addrs in addresses.items():
        if device_ip == exclude:
            continue
        if any(_addr(a.get("ip")) == target for a in addrs):
            return device_ip
    return None


def _on_own_lan(hop_ip, addrs) -> bool:
    """Il next-hop sta su una rete connessa dell'apparato: e' un host non
    gestito sulla sua LAN, non un salto verso l'esterno. La differenza cambia
    la frase che la vista scrive."""
    target = _addr(hop_ip)
    if target is None:
        return False
    for a in addrs or []:
        net = _net(a.get("network"))
        if net is not None and target in net:
            return True
    return False


def _name(devices_by_ip, ip) -> str:
    return (devices_by_ip.get(ip) or {}).get("Hostname") or ip


def _same_choice(a, b) -> bool:
    return (a["prefixlen"], a["ad"], a["metric"]) == (b["prefixlen"], b["ad"], b["metric"])


def _iface_for_ip(addrs, ip_str):
    target = _addr(ip_str)
    if target is None:
        return ""
    for a in addrs or []:
        if _addr(a.get("ip")) == target:
            return a.get("iface") or ""
    return ""


def _iface_in_subnet(addrs, ip_str):
    target = _addr(ip_str)
    if target is None:
        return ""
    best_iface = ""
    best_len = -1
    for a in addrs or []:
        net = _net(a.get("network"))
        if net is not None and target in net and net.prefixlen > best_len:
            best_len = net.prefixlen
            best_iface = a.get("iface") or ""
    return best_iface


def _first_ip_for_iface(addrs, iface_name: str, aliases: dict) -> str:
    if not iface_name:
        return ""
    wanted = {iface_name.lower()}
    for k, v in (aliases or {}).items():
        if k.lower() == iface_name.lower() and v:
            wanted.add(v.lower())
        elif v and v.lower() == iface_name.lower():
            wanted.add(k.lower())
    for a in addrs or []:
        if (a.get("iface") or "").lower() in wanted or (a.get("alias") or "").lower() in wanted:
            if a.get("ip"):
                return str(a["ip"])
    return ""


def _build_fgt_aliases(addrs, ctx: dict) -> dict:
    """Map interface physical name <-> alias in both directions."""
    aliases = {}
    for a in addrs or []:
        name = a.get("iface") or ""
        alias = a.get("alias") or ""
        if name and alias:
            aliases[name] = alias
            aliases[alias] = name
    env = ctx.get("policy_env")
    for name, info in (getattr(env, "interfaces", {}) or {}).items():
        alias = info.get("alias") or ""
        if name and alias:
            aliases[name] = alias
            aliases[alias] = name
    return aliases


def _port_in_spec(port: "int | None", spec: str) -> bool:
    if not spec or port is None:
        return True
    for part in str(spec).replace(",", " ").split():
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            if lo_s.isdigit() and hi_s.isdigit() and int(lo_s) <= port <= int(hi_s):
                return True
        elif part.isdigit() and int(part) == port:
            return True
    return False


def _match_ip_item(item: str, ip_str: str, addr_map: dict) -> bool:
    ip_obj = _addr(ip_str)
    if ip_obj is None:
        return False
    net = _net(item)
    if net is not None:
        return ip_obj in net
    if item in (addr_map or {}):
        from services.policy_test.model import ip_to_int
        ip_int = ip_to_int(ip_str)
        return any(c.contains_ip(ip_int) for c in addr_map[item])
    return False


def _apply_dnat(ctx: dict, vendor: str, cur_dst: str, cur_dport, cur_proto: str,
                cur_vrf: str, ingress_iface: str, aliases: dict) -> tuple:
    """Apply pre-routing DNAT (FortiGate VIP or Cisco IOS static outside->inside)."""
    env = ctx.get("policy_env")
    if vendor == "fortinet":
        vips = ctx.get("vips")
        if vips is None and env is not None:
            vips = list((getattr(env, "vips", {}) or {}).values())
        for vip in vips or []:
            extip = str(vip.get("extip") or "").strip()
            mappedip = str(vip.get("mappedip") or "").strip()
            if not extip or not mappedip:
                continue
            extintf = str(vip.get("extintf") or "any")
            if extintf not in ("", "any") and ingress_iface:
                canon = {ingress_iface.lower()}
                if aliases.get(ingress_iface):
                    canon.add(aliases[ingress_iface].lower())
                if extintf.lower() not in canon:
                    continue
            if extip != cur_dst:
                # Support range or CIDR extip if specified
                net = _net(extip)
                dst_obj = _addr(cur_dst)
                if net is None or dst_obj is None or dst_obj not in net:
                    continue
            pf = bool(vip.get("portforward"))
            if pf:
                vproto = str(vip.get("protocol") or "").lower()
                if cur_proto and vproto and vproto != cur_proto:
                    continue
                if cur_dport is not None and not _port_in_spec(cur_dport, str(vip.get("extport") or "")):
                    continue
            # Compute mapped destination IP & port
            new_dst = mappedip.split("-")[0].strip()
            if _addr(new_dst) is None:
                continue
            new_dport = cur_dport
            mport_str = str(vip.get("mappedport") or "").strip()
            if pf and mport_str.isdigit():
                new_dport = int(mport_str)
            nat_ev = {
                "kind": "dnat_vip",
                "rule": vip.get("name") or "vip",
                "orig_dst": cur_dst,
                "new_dst": new_dst,
                "orig_dport": cur_dport,
                "new_dport": new_dport,
            }
            return new_dst, new_dport, vip.get("name") or "", nat_ev

    elif vendor == "cisco" and env is not None:
        ifaces = getattr(env, "interfaces", {}) or {}
        in_info = ifaces.get(ingress_iface) or next(
            (v for k, v in ifaces.items() if k.lower() == ingress_iface.lower()), None
        )
        # Apply static global->local translation when arriving on an outside interface
        # or when no nat_role is explicitly set on any interface in a partial config.
        is_outside = (in_info or {}).get("nat_role") == "outside"
        has_any_role = any((info.get("nat_role") for info in ifaces.values()))
        if is_outside or not has_any_role:
            for nat in getattr(env, "static_nats", []) or []:
                if nat.get("vrf") and nat["vrf"] != cur_vrf:
                    continue
                if nat.get("global_ip") != cur_dst:
                    continue
                nproto = (nat.get("proto") or "").lower()
                if nproto and cur_proto and nproto != cur_proto:
                    continue
                if nat.get("global_port") is not None and cur_dport is not None:
                    if nat["global_port"] != cur_dport:
                        continue
                new_dport = nat["local_port"] if nat.get("local_port") is not None else cur_dport
                nat_ev = {
                    "kind": "dnat_static",
                    "rule": nat.get("raw_text") or "ip nat static",
                    "orig_dst": cur_dst,
                    "new_dst": nat["local_ip"],
                    "orig_dport": cur_dport,
                    "new_dport": new_dport,
                }
                return nat["local_ip"], new_dport, "", nat_ev

    return cur_dst, cur_dport, "", None


def _eval_pbr(ctx: dict, ingress_iface: str, src_ip: str, dst_ip: str, aliases: dict) -> "dict | None":
    """Evaluate FortiGate policy routes in seq order."""
    pbrs = ctx.get("policy_routes")
    env = ctx.get("policy_env")
    if pbrs is None and env is not None:
        pbrs = getattr(env, "policy_routes", None)
    if not pbrs:
        return None
    addr_map = getattr(env, "addresses", {}) if env is not None else {}
    in_names = {ingress_iface.lower()} if ingress_iface else set()
    if ingress_iface and aliases.get(ingress_iface):
        in_names.add(aliases[ingress_iface].lower())

    for pr in sorted(pbrs, key=lambda x: x.get("seq") or 0):
        if not pr.get("enabled", True):
            continue
        inputs = [str(i).lower() for i in (pr.get("input") or []) if i]
        if inputs and "any" not in inputs:
            if not in_names or not (in_names & set(inputs)):
                continue
        srcs = pr.get("src") or []
        if srcs and "all" not in [s.lower() for s in srcs]:
            if not src_ip or not any(_match_ip_item(s, src_ip, addr_map) for s in srcs):
                continue
        dsts = pr.get("dst") or []
        if dsts and "all" not in [d.lower() for d in dsts]:
            if not any(_match_ip_item(d, dst_ip, addr_map) for d in dsts):
                continue
        return dict(pr)
    return None


def _sdwan_map(ctx: dict) -> dict:
    out = {}
    for m in ctx.get("sdwan") or []:
        iface = (m.get("interface") or "").lower()
        if iface:
            out[iface] = m
    return out


def _tunnel_for_iface(ctx: dict, iface_name: str, aliases: dict) -> "dict | None":
    if not iface_name:
        return None
    wanted = {iface_name.lower()}
    if aliases.get(iface_name):
        wanted.add(aliases[iface_name].lower())
    for t in ctx.get("tunnels") or []:
        tname = (t.get("name") or "").lower()
        if tname and tname in wanted:
            return dict(t)
    return None


def _eval_hop_security(ctx: dict, device: dict, vendor: str, addrs: list, aliases: dict,
                       cur_src: str, cur_dst: str, cur_proto: str, cur_dport,
                       ingress_iface: str, egress_iface: str,
                       matched_vip_name: str = "") -> tuple:
    """Evaluate per-hop Cisco ACL or FortiGate firewall policy and SNAT.

    Returns ``(security_dict, new_src, snat_event_or_None)``.
    """
    env = ctx.get("policy_env")
    src_label = ctx.get("policy_source") or ("backup" if env is not None else "none")

    if not cur_src:
        if env is not None or ctx.get("live_policy_lookup"):
            return ({
                "evaluated": False,
                "source": src_label,
                "verdict": "SKIPPED",
                "note": "IP sorgente non specificato: policy/ACL non valutabile",
            }, cur_src, None)
        return ({
            "evaluated": False,
            "source": "none",
            "verdict": "SKIPPED",
            "note": "nessun dato policy/ACL",
        }, cur_src, None)

    from services.policy_test.model import Flow

    proto_use = cur_proto or "tcp"

    if vendor == "cisco":
        if env is None:
            return ({
                "evaluated": False,
                "source": "none",
                "verdict": "SKIPPED",
                "note": "nessun backup IOS disponibile per valutare le ACL",
            }, cur_src, None)
        from services.policy_test.engine import _find_interface, _first_match
        steps_out = []
        verdict = "PERMIT"
        matched_rule_label = ""
        matched_acl = ""
        flow = Flow(
            src_ip=cur_src,
            dst_ip=cur_dst,
            proto=proto_use,
            dport=cur_dport,
            ingress_intf=ingress_iface or None,
            egress_intf=egress_iface or None,
        )
        # Inbound ACL
        in_info = _find_interface(env.interfaces, ingress_iface)
        if in_info and in_info.get("acl_in") and in_info["acl_in"] in env.acls:
            acl_name = in_info["acl_in"]
            acl = env.acls[acl_name]
            m = _first_match(acl.rules, flow)
            if m is None:
                verdict = "DENY"
                matched_acl = acl_name
                matched_rule_label = "implicit deny"
                steps_out.append({"kind": "acl_in", "acl": acl_name, "action": "deny", "matched": "implicit deny"})
            elif m.unresolved or m.fields.opaque:
                verdict = "UNKNOWN"
                matched_acl = acl_name
                matched_rule_label = f"seq {m.id}"
                steps_out.append({"kind": "acl_in", "acl": acl_name, "action": "unknown", "matched": matched_rule_label, "raw_text": m.raw_text})
            elif m.action == "deny":
                verdict = "DENY"
                matched_acl = acl_name
                matched_rule_label = f"seq {m.id}"
                steps_out.append({"kind": "acl_in", "acl": acl_name, "action": "deny", "matched": matched_rule_label, "raw_text": m.raw_text})
            else:
                matched_acl = acl_name
                matched_rule_label = f"seq {m.id}"
                steps_out.append({"kind": "acl_in", "acl": acl_name, "action": "permit", "matched": matched_rule_label, "raw_text": m.raw_text})

        # Outbound ACL (only if inbound didn't stop)
        if verdict == "PERMIT":
            out_info = _find_interface(env.interfaces, egress_iface)
            if out_info and out_info.get("acl_out") and out_info["acl_out"] in env.acls:
                acl_name = out_info["acl_out"]
                acl = env.acls[acl_name]
                m = _first_match(acl.rules, flow)
                if m is None:
                    verdict = "DENY"
                    matched_acl = acl_name
                    matched_rule_label = "implicit deny"
                    steps_out.append({"kind": "acl_out", "acl": acl_name, "action": "deny", "matched": "implicit deny"})
                elif m.unresolved or m.fields.opaque:
                    verdict = "UNKNOWN"
                    matched_acl = acl_name
                    matched_rule_label = f"seq {m.id}"
                    steps_out.append({"kind": "acl_out", "acl": acl_name, "action": "unknown", "matched": matched_rule_label, "raw_text": m.raw_text})
                elif m.action == "deny":
                    verdict = "DENY"
                    matched_acl = acl_name
                    matched_rule_label = f"seq {m.id}"
                    steps_out.append({"kind": "acl_out", "acl": acl_name, "action": "deny", "matched": matched_rule_label, "raw_text": m.raw_text})
                else:
                    matched_acl = acl_name
                    matched_rule_label = f"seq {m.id}"
                    steps_out.append({"kind": "acl_out", "acl": acl_name, "action": "permit", "matched": matched_rule_label, "raw_text": m.raw_text})

        # Outbound static SNAT (inside -> outside)
        snat_ev = None
        new_src = cur_src
        if verdict == "PERMIT":
            out_info = _find_interface(env.interfaces, egress_iface)
            if (out_info or {}).get("nat_role") == "outside":
                vrf_here = (out_info or {}).get("vrf") or ""
                for nat in getattr(env, "static_nats", []) or []:
                    if nat.get("vrf") and nat["vrf"] != vrf_here:
                        continue
                    if nat.get("local_ip") == cur_src and not nat.get("proto"):
                        new_src = nat["global_ip"]
                        snat_ev = {
                            "kind": "snat_static",
                            "rule": nat.get("raw_text") or "ip nat static",
                            "orig_src": cur_src,
                            "new_src": new_src,
                        }
                        break

        note = "" if steps_out else "nessuna ACL applicata sulle interfacce del salto"
        return ({
            "evaluated": True,
            "source": "backup",
            "verdict": verdict,
            "acl": matched_acl,
            "matched_rule": matched_rule_label,
            "steps": steps_out,
            "note": note,
        }, new_src, snat_ev)

    if vendor == "fortinet":
        if env is not None:
            from services.policy_test.engine import _rule_stops_walk
            from services.policy_test.model import Rule

            def _expand_ifaces(if_set):
                if if_set is None:
                    return None
                expanded = set(if_set)
                for item in list(if_set):
                    if item in aliases:
                        expanded.add(aliases[item])
                return expanded

            flow = Flow(
                src_ip=cur_src,
                dst_ip=cur_dst,
                proto=proto_use,
                dport=cur_dport,
                ingress_intf=ingress_iface or None,
                egress_intf=egress_iface or None,
            )
            matched_pol = None
            for pol in env.policies:
                if pol.disabled:
                    continue
                # Expand interface aliases so 'wan1' matches 'port1' transparently
                if pol.fields.ingress_intfs is not None or pol.fields.egress_intfs is not None:
                    f_copy = pol.fields
                    exp_in = _expand_ifaces(f_copy.ingress_intfs)
                    exp_out = _expand_ifaces(f_copy.egress_intfs)
                    from dataclasses import replace
                    pol_chk = Rule(
                        id=pol.id, name=pol.name, action=pol.action,
                        fields=replace(f_copy, ingress_intfs=exp_in, egress_intfs=exp_out),
                        disabled=pol.disabled, raw_text=pol.raw_text,
                        line_no=pol.line_no, nat_enabled=pol.nat_enabled,
                        unresolved=pol.unresolved,
                    )
                else:
                    pol_chk = pol
                if _rule_stops_walk(pol_chk, flow):
                    matched_pol = pol
                    break

            if matched_pol is None:
                return ({
                    "evaluated": True,
                    "source": "backup",
                    "verdict": "DENY",
                    "acl": "policy 0",
                    "matched_rule": "implicit deny",
                    "steps": [{"kind": "policy", "acl": "default", "action": "deny", "matched": "implicit deny (policy 0)"}],
                    "note": "",
                }, cur_src, None)

            if matched_pol.unresolved or matched_pol.fields.opaque:
                return ({
                    "evaluated": True,
                    "source": "backup",
                    "verdict": "UNKNOWN",
                    "acl": matched_pol.name or f"policy {matched_pol.id}",
                    "matched_rule": f"policy {matched_pol.id}",
                    "steps": [{"kind": "policy", "acl": matched_pol.name or f"policy {matched_pol.id}",
                               "action": "unknown", "matched": f"policy {matched_pol.id}",
                               "raw_text": matched_pol.raw_text}],
                    "note": "; ".join(matched_pol.unresolved),
                }, cur_src, None)

            pol_label = f"policy {matched_pol.id}" + (f" ({matched_pol.name})" if matched_pol.name else "")
            if matched_pol.action in ("deny", "drop"):
                return ({
                    "evaluated": True,
                    "source": "backup",
                    "verdict": "DENY",
                    "acl": matched_pol.name or f"policy {matched_pol.id}",
                    "matched_rule": pol_label,
                    "steps": [{"kind": "policy", "acl": matched_pol.name or f"policy {matched_pol.id}",
                               "action": "deny", "matched": pol_label,
                               "raw_text": matched_pol.raw_text}],
                    "note": "",
                }, cur_src, None)

            # PERMIT — compute SNAT if enabled
            snat_ev = None
            new_src = cur_src
            if matched_pol.nat_enabled:
                pools = getattr(env, "policy_nat_pools", {}).get(str(matched_pol.id), [])
                ippools = getattr(env, "ippools", {}) or {}
                pool_ip = ""
                pool_name = ""
                if pools and pools[0] in ippools:
                    pool_name = pools[0]
                    pool_ip = ippools[pool_name].get("startip") or ""
                out_ip = pool_ip or _first_ip_for_iface(addrs, egress_iface, aliases)
                if out_ip:
                    new_src = out_ip
                    snat_ev = {
                        "kind": "snat_ippool" if pool_ip else "snat_interface",
                        "rule": f"{pol_label} [{pool_name}]" if pool_name else pol_label,
                        "orig_src": cur_src,
                        "new_src": new_src,
                    }
            return ({
                "evaluated": True,
                "source": "backup",
                "verdict": "PERMIT",
                "acl": matched_pol.name or f"policy {matched_pol.id}",
                "matched_rule": pol_label,
                "steps": [{"kind": "policy", "acl": matched_pol.name or f"policy {matched_pol.id}",
                           "action": "permit", "matched": pol_label,
                           "raw_text": matched_pol.raw_text}],
                "note": f"VIP {matched_vip_name}" if matched_vip_name else "",
            }, new_src, snat_ev)

        if ctx.get("live_policy_lookup"):
            try:
                from services import fortigate_service
                res = fortigate_service.policy_lookup(
                    device, cur_src, cur_dst, proto_use.upper(),
                    int(cur_dport or 443), srcintf=ingress_iface or None,
                )
                data = res.get("data") if isinstance(res, dict) else {}
                pol_id = data.get("policyid") if isinstance(data, dict) else None
                act_raw = str((data.get("action") if isinstance(data, dict) else "") or "").lower()
                verdict = "PERMIT" if act_raw == "accept" else "DENY" if act_raw == "deny" else "UNKNOWN"
                return ({
                    "evaluated": True,
                    "source": "live",
                    "verdict": verdict,
                    "acl": f"policy {pol_id}" if pol_id is not None else "live policy-lookup",
                    "matched_rule": f"policy {pol_id}" if pol_id is not None else "live policy-lookup",
                    "steps": [],
                    "note": "",
                }, cur_src, None)
            except Exception as e:
                return ({
                    "evaluated": False,
                    "source": "live",
                    "verdict": "UNKNOWN",
                    "note": f"policy lookup live fallito: {e}",
                }, cur_src, None)

    return ({
        "evaluated": False,
        "source": "none",
        "verdict": "SKIPPED",
        "note": "nessuna configurazione policy/ACL disponibile",
    }, cur_src, None)


def collect_hop_context(device: dict, forti_ctx: "dict | None" = None,
                        answer: "dict | None" = None,
                        live_policy_lookup: bool = False) -> dict:
    """Gather offline backup policy/NAT/VRF context plus live FortiGate metadata."""
    ctx: dict = {
        "policy_env": None,
        "policy_source": "none",
        "policy_routes": list((forti_ctx or {}).get("policy_routes") or []),
        "sdwan": list((forti_ctx or {}).get("sdwan") or []),
        "tunnels": list((forti_ctx or {}).get("tunnels") or []),
        "vips": None,
        "ippools": None,
        "live_policy_lookup": bool(live_policy_lookup and (answer or {}).get("source") == "api"),
    }
    ip = device.get("IP")
    vendor = (device.get("Vendor") or "").lower()
    if ip and vendor in ("cisco", "fortinet", "fortigate"):
        try:
            from ai import config_analyzer
            path, _tenant = config_analyzer._find_freshest_backup(ip, device.get("Group") or "")
            if path:
                with open(path, encoding="utf-8", errors="ignore") as fh:
                    raw = fh.read()
                content = "\n".join(config_analyzer.running_config(raw))
                cfg_type = config_analyzer.detect_config_type(content, device)
                if cfg_type == "fortios":
                    from services.policy_test.fortios import parse_fortios_config
                    env = parse_fortios_config(content)
                    ctx["policy_env"] = env
                    ctx["policy_source"] = "backup"
                    if not ctx["policy_routes"] and env.policy_routes:
                        ctx["policy_routes"] = list(env.policy_routes)
                elif cfg_type == "ios":
                    from services.policy_test.ios import parse_ios_config
                    ctx["policy_env"] = parse_ios_config(content)
                    ctx["policy_source"] = "backup"
        except Exception as e:
            logger.debug("Impossibile caricare backup policy per %s: %s", ip, e)

    if vendor in ("fortinet", "fortigate") and (answer or {}).get("source") == "api":
        from services import fortigate_service
        try:
            vdata = fortigate_service.get_vips(device).get("data")
            if isinstance(vdata, list):
                ctx["vips"] = [v for v in vdata if isinstance(v, dict)]
        except fortigate_service.FortiGateError:
            pass
        try:
            pdata = fortigate_service.get_ip_pools(device).get("data")
            if isinstance(pdata, list):
                ctx["ippools"] = [p for p in pdata if isinstance(p, dict)]
        except fortigate_service.FortiGateError:
            pass
    return ctx


def supplement_from_backup_env(device: dict, rows: list, addrs: list, ctx: dict) -> tuple:
    """Fill missing connected subnets and interface addresses from backup policy_env.

    Only adds entries that are absent (never overrides live routes or live
    interface lists), so offline/manual devices can participate in end-to-end
    path tracing.
    """
    env = (ctx or {}).get("policy_env")
    if env is None:
        return rows, addrs

    out_rows = list(rows or [])
    out_addrs = list(addrs or [])
    existing_keys = {
        (r.get("vrf") or "", r.get("network") or "", r.get("gateway") or "", r.get("type") or "")
        for r in out_rows
    }
    if not any(r.get("type") == "connected" for r in out_rows):
        dev_name = device.get("Hostname") or device.get("IP") or ""
        dev_ip = device.get("IP") or ""
        for rt in getattr(env.route_table, "routes", []) or []:
            vrf_val = getattr(rt, "vrf", "") or ""
            key = (vrf_val, rt.prefix, rt.next_hop or "", rt.source)
            if key in existing_keys:
                continue
            existing_keys.add(key)
            out_rows.append({
                "device": dev_name,
                "device_ip": dev_ip,
                "network": rt.prefix,
                "vrf": vrf_val,
                "gateway": rt.next_hop or "",
                "interface": rt.interface or "",
                "type": rt.source,
                "distance": rt.distance,
                "metric": rt.metric,
                "from_backup": True,
            })

    if not out_addrs:
        for iface_name, info in (getattr(env, "interfaces", {}) or {}).items():
            if info.get("shutdown") or info.get("status", "up") == "down":
                continue
            ip_val = info.get("ip") or ""
            mask_val = info.get("mask") or ""
            if not ip_val or not mask_val:
                continue
            try:
                net_obj = ipaddress.ip_network(f"{ip_val}/{mask_val}", strict=False)
                out_addrs.append({
                    "iface": iface_name,
                    "ip": ip_val,
                    "network": str(net_obj),
                    "alias": info.get("alias") or "",
                })
            except ValueError:
                continue

    return out_rows, out_addrs


def _finalize_trace(base: dict, flow_init: dict, cur_src: str, cur_dst: str,
                    cur_proto: str, cur_dport, cur_vrf: str,
                    nat_all: list, blocked_at: "dict | None") -> dict:
    hops = base.get("hops") or []
    verdicts = [h.get("security", {}).get("verdict") for h in hops if h.get("security")]
    if "DENY" in verdicts or blocked_at is not None:
        sec_verdict = "DENY"
    elif "UNKNOWN" in verdicts:
        sec_verdict = "UNKNOWN"
    elif "PERMIT" in verdicts:
        sec_verdict = "PERMIT"
    else:
        sec_verdict = "NOT_EVALUATED"

    base["flow"] = flow_init
    base["effective_flow"] = {
        "src_ip": cur_src,
        "dst_ip": cur_dst,
        "proto": cur_proto,
        "dport": cur_dport,
        "vrf": cur_vrf,
    }
    base["nat_translations"] = nat_all
    base["security_verdict"] = sec_verdict
    base["blocked_at_hop"] = blocked_at
    return base


def trace(dst, start_ip, rows_by_device, addresses, devices_by_ip,
          *, src_ip: str = "", proto: str = "", dport: "int | None" = None,
          vrf: str = "", hop_contexts: "dict | None" = None) -> dict:
    """Il percorso verso ``dst`` a partire dall'apparato ``start_ip``.

    Torna ``{"hops": [...], "outcome": ...}``. Gli esiti sono distinti perche'
    rispondono a domande diverse: consegna, uscita dal perimetro noto, nessuna
    rotta, anello, biforcazione ECMP, blocco da policy/ACL.
    """
    hops = []
    seen = set()
    current = start_ip
    cur_src = (src_ip or "").strip()
    cur_dst = (dst or "").strip()
    cur_proto = (proto or "").strip().lower()
    cur_dport = dport
    cur_vrf = (vrf or "").strip()
    prev_gateway_ip = ""
    nat_all: list = []
    blocked_at = None
    flow_init = {
        "src_ip": cur_src,
        "dst_ip": cur_dst,
        "proto": cur_proto,
        "dport": cur_dport,
        "vrf": cur_vrf,
    }

    for _ in range(MAX_HOPS):
        if current not in rows_by_device:
            # L'apparato non e' fra quelli interrogati: il percorso si ferma
            # perche' manca la sua tabella, non perche' finisce li'.
            return _finalize_trace(
                {"hops": hops, "outcome": "non interrogato", "device_ip": current},
                flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
            )

        ctx = (hop_contexts or {}).get(current) or {}
        dev = devices_by_ip.get(current) or {}
        vendor = (dev.get("Vendor") or "").lower()
        if vendor == "fortigate":
            vendor = "fortinet"
        dev_addrs = addresses.get(current) or []
        aliases = _build_fgt_aliases(dev_addrs, ctx)

        # Determine ingress interface on this device
        if prev_gateway_ip:
            ingress_iface = _iface_for_ip(dev_addrs, prev_gateway_ip)
        elif cur_src:
            ingress_iface = _iface_in_subnet(dev_addrs, cur_src)
        else:
            ingress_iface = ""

        # If ingress interface is bound to a VRF on this device, enter that VRF
        env = ctx.get("policy_env")
        if env is not None and ingress_iface:
            ifaces_cfg = getattr(env, "interfaces", {}) or {}
            in_cfg = ifaces_cfg.get(ingress_iface) or next(
                (v for k, v in ifaces_cfg.items() if k.lower() == ingress_iface.lower()), None
            )
            if in_cfg and in_cfg.get("vrf") and (len(hops) > 0 or not cur_vrf):
                cur_vrf = in_cfg["vrf"]

        loop_key = (current, cur_vrf)
        if loop_key in seen:
            hops.append({"device_ip": current, "device": _name(devices_by_ip, current),
                         "vrf": cur_vrf, "outcome": "anello"})
            return _finalize_trace(
                {"hops": hops, "outcome": "anello"},
                flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
            )
        seen.add(loop_key)

        flow_in = {"src_ip": cur_src, "dst_ip": cur_dst, "proto": cur_proto, "dport": cur_dport}
        hop_nats = []

        # 1. Pre-routing DNAT (VIP / Cisco static inside-outside)
        cur_dst, cur_dport, matched_vip_name, dnat_ev = _apply_dnat(
            ctx, vendor, cur_dst, cur_dport, cur_proto, cur_vrf, ingress_iface, aliases,
        )
        if dnat_ev is not None:
            hop_nats.append(dnat_ev)
            nat_all.append({**dnat_ev, "device_ip": current, "device": _name(devices_by_ip, current)})

        # 2. Policy-based routing (FortiGate)
        pbr = _eval_pbr(ctx, ingress_iface, cur_src, cur_dst, aliases) if vendor == "fortinet" else None
        pbr_active = bool(pbr and pbr.get("permit") and (pbr.get("gateway") or pbr.get("output")))

        rows = rows_by_device[current]
        # Respect active VRF; fallback to unfiltered only if caller left vrf="" AND no VRF rows exist
        cand = candidates(rows, cur_dst, vrf=cur_vrf)

        hop: dict = {
            "device_ip": current,
            "device": _name(devices_by_ip, current),
            "vendor": vendor,
            "vrf": cur_vrf,
            "ingress_iface": ingress_iface,
            "egress_iface": "",
            "from_backup": any(r.get("from_backup") for r in rows),
            "candidates": cand,
            "flow_in": flow_in,
            "nat": hop_nats,
        }
        if pbr is not None:
            hop["pbr"] = pbr

        sdwan_by_iface = _sdwan_map(ctx)

        if pbr_active and pbr is not None:
            pbr_route = {
                "device": _name(devices_by_ip, current),
                "device_ip": current,
                "network": cur_dst + "/32",
                "gateway": pbr.get("gateway") or "",
                "interface": pbr.get("output") or "",
                "type": "policy",
                "vrf": cur_vrf,
                "distance": 0,
                "metric": 0,
                "prefixlen": 32,
                "ad": 0,
            }
            best = pbr_route
            hop["best"] = best
            hop["decided_by"] = "pbr"
            tied = [best]
        else:
            if not cand:
                hop["outcome"] = "nessuna rotta"
                hop["flow_out"] = {"src_ip": cur_src, "dst_ip": cur_dst, "proto": cur_proto, "dport": cur_dport}
                hops.append(hop)
                return _finalize_trace(
                    {"hops": hops, "outcome": "nessuna rotta"},
                    flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
                )
            best = cand[0]
            tied = [r for r in cand if _same_choice(r, best)]
            # SD-WAN health tie-breaker among ECMP routes when health checks exist
            if len(tied) > 1 and sdwan_by_iface:
                healthy = [
                    r for r in tied
                    if (sdwan_by_iface.get((r.get("interface") or "").lower()) or {}).get("state") != "down"
                ]
                if healthy and len(healthy) < len(tied):
                    tied = healthy
                    best = healthy[0]
                    hop["decided_by"] = "sdwan"
            if "decided_by" not in hop:
                hop["decided_by"] = decided_by(cand)
            hop["best"] = best

        egress_iface = str(best.get("interface") or "")
        if not egress_iface and best.get("gateway"):
            egress_iface = _iface_in_subnet(dev_addrs, str(best["gateway"]))
        hop["egress_iface"] = egress_iface

        if egress_iface and egress_iface.lower() in sdwan_by_iface:
            hop["sdwan"] = sdwan_by_iface[egress_iface.lower()]
        tun = _tunnel_for_iface(ctx, egress_iface, aliases)
        if tun is not None:
            hop["tunnel"] = tun

        # 3. Evaluate ACL / Firewall policy & outbound SNAT at this hop
        sec, new_src, snat_ev = _eval_hop_security(
            ctx, dev, vendor, dev_addrs, aliases,
            cur_src, cur_dst, cur_proto, cur_dport,
            ingress_iface, egress_iface, matched_vip_name=matched_vip_name,
        )
        hop["security"] = sec
        if snat_ev is not None:
            hop_nats.append(snat_ev)
            nat_all.append({**snat_ev, "device_ip": current, "device": _name(devices_by_ip, current)})
            cur_src = new_src

        hop["flow_out"] = {"src_ip": cur_src, "dst_ip": cur_dst, "proto": cur_proto, "dport": cur_dport}

        if sec.get("verdict") == "DENY":
            hop["outcome"] = "bloccato"
            hops.append(hop)
            blocked_at = {
                "device_ip": current,
                "device": _name(devices_by_ip, current),
                "acl": sec.get("acl") or "",
                "rule": sec.get("matched_rule") or "",
            }
            return _finalize_trace(
                {"hops": hops, "outcome": "bloccato"},
                flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
            )

        if len(tied) > 1:
            hop["outcome"] = "biforcazione"
            hop["tied"] = tied
            hops.append(hop)
            return _finalize_trace(
                {"hops": hops, "outcome": "biforcazione",
                 "branches": [{"route": r,
                               "next_device_ip": owner_of(r.get("gateway"),
                                                          addresses, current)}
                              for r in tied]},
                flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
            )

        if best.get("type") in ("connected", "local"):
            hop["outcome"] = "consegna"
            hops.append(hop)
            return _finalize_trace(
                {"hops": hops, "outcome": "consegna"},
                flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
            )

        # Follow gateway (or IPsec remote gateway if tunnel is up)
        next_gw = best.get("gateway") or ""
        if not next_gw and tun and tun.get("up") and tun.get("remote_gw"):
            next_gw = tun["remote_gw"]

        nxt = owner_of(next_gw, addresses, current)
        hop["next_device_ip"] = nxt
        hops.append(hop)
        if nxt is None:
            return _finalize_trace(
                {"hops": hops, "outcome": "fuori inventario",
                 "exit_hop": next_gw,
                 "exit_local": _on_own_lan(next_gw, addresses.get(current))},
                flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
            )
        prev_gateway_ip = next_gw
        current = nxt
    # Sedici salti senza mai rivedere un apparato: non e' un anello, e' un
    # percorso piu' lungo di quanto questa vista segua. Chiamarlo anello
    # manderebbe l'operatore a cercare un giro che non c'e'.
    return _finalize_trace(
        {"hops": hops, "outcome": "limite salti"},
        flow_init, cur_src, cur_dst, cur_proto, cur_dport, cur_vrf, nat_all, blocked_at,
    )


# --- Prova sul campo ---------------------------------------------------------
#
# Tutto quello che sta sopra legge tabelle. Questo pezzo, e solo questo, manda
# davvero dei pacchetti: un traceroute lanciato DALL'APPARATO di partenza verso
# la destinazione. Serve a rispondere alla domanda che il calcolo non puo'
# toccare — "e nella realta' ci passa?" — ed e' percio' un'azione esplicita
# dell'utente, non qualcosa che parte con la vista.

import re

# Un traceroute che attraversa mezza rete puo' impiegare parecchio: il numero
# di salti e' limitato perche' la risposta deve tornare mentre l'utente guarda.
PROBE_MAX_HOPS = 8
# Worst case: every hop silent, 2 probes x 2 s each, plus slack for the session.
PROBE_READ_TIMEOUT = PROBE_MAX_HOPS * 2 * 2 + 20

_HOP_LINE = re.compile(r"^\s*(?P<n>\d{1,2})\s+(?P<rest>.*)$")
_IP = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


def probe_command(device, dst: str) -> str:
    """Il comando di traceroute per quel vendor.

    ``dst`` e' gia' stato validato come indirizzo dal chiamante: qui non si
    concatena nient'altro che quello, perche' questa stringa finisce in una
    shell di rete."""
    vendor = (device.get("Vendor") or "").lower()
    if vendor == "fortinet":
        return f"execute traceroute {dst}"
    from drivers.registry import resolve_driver
    if resolve_driver(vendor)[1] == "cisco_s300":
        # CBS / Catalyst 1200-1300: own syntax, the IOS keywords are rejected.
        return f"traceroute ip {dst} ttl {PROBE_MAX_HOPS} count 2 timeout 2"
    return f"traceroute {dst} numeric timeout 2 probe 2 ttl 1 {PROBE_MAX_HOPS}"


def parse_traceroute(output: str) -> list:
    """I salti di un traceroute: ``[{n, ip}]``, con ip vuoto se non ha risposto.

    Le righe senza risposta (`* * *`) restano nella lista con ip vuoto: sono
    un'informazione, non un buco da nascondere — un salto che non risponde a
    ICMP e' normale, un salto che manca del tutto no."""
    hops = []
    for raw in (output or "").splitlines():
        m = _HOP_LINE.match(raw.rstrip())
        if not m:
            continue
        n = int(m.group("n"))
        if hops and n <= hops[-1]["n"]:
            # Non e' una riga di salto: e' un'altra tabella che ricomincia da 1
            # (o l'eco del comando). Meglio fermarsi che inventare salti.
            continue
        ip = _IP.search(m.group("rest"))
        hops.append({"n": n, "ip": ip.group("ip") if ip else ""})
    return hops


def probe(device, dst: str) -> dict:
    """Traceroute dall'apparato verso ``dst``. Non solleva."""
    command = probe_command(device, dst)
    vendor = (device.get("Vendor") or "").lower()
    try:
        if vendor == "fortinet":
            from services import fortigate_service
            output = str(fortigate_service.ssh_command(device, command))
        else:
            from core import core_engine
            answer = core_engine.send_custom_command(device, command,
                                                     bypass_blacklist=True,
                                                     read_timeout=PROBE_READ_TIMEOUT)
            if answer.get("status") != "success":
                return {"command": command,
                        "error": answer.get("message") or "sessione non riuscita"}
            output = str(answer.get("output") or "")
    except Exception as e:   # noqa: BLE001 — un traceroute fallito e' un esito
        return {"command": command, "error": str(e)}
    return {"command": command, "output": output, "hops": parse_traceroute(output)}


def compare(trace_result: dict, probe_hops) -> dict:
    """Il percorso calcolato contro quello che il traceroute ha visto.

    Confronta i next-hop attesi con gli indirizzi che hanno risposto, in
    ordine. Un next-hop atteso che non compare non e' di per se' un guasto (un
    apparato puo' non rispondere a ICMP): e' il punto da cui guardare, ed e'
    cosi' che va presentato."""
    expected = [h["best"].get("gateway") for h in trace_result.get("hops", [])
                if h.get("best") and h["best"].get("gateway")]
    seen = [h.get("ip") for h in (probe_hops or []) if h.get("ip")]
    seen_set = set(seen)
    return {
        "expected": expected,
        "seen": seen,
        "matched": [ip for ip in expected if ip in seen_set],
        "missing": [ip for ip in expected if ip not in seen_set],
        "unexpected": [ip for ip in seen if ip not in set(expected)],
    }
