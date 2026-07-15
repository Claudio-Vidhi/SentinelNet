# -*- coding: utf-8 -*-
"""Router MAC. Estratto da app_server.py (fase 6.6)."""

import time
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from pydantic import BaseModel

import inventory_manager
import core_engine
import mac_collector
import mac_history
from security_manager import log_audit
from routers.deps import get_current_user, require_operator, require_admin, user_group_scope, assert_group_allowed

router = APIRouter(tags=["MAC"])

class MacScanSchema(BaseModel):
    group: str = "all"
    ip: Optional[str] = None
    ips: List[str] = []               # multi-selezione: più device in un'unica scansione
    transport: Optional[str] = None   # netconf | restconf | cli | None=auto

class MacRetentionSchema(BaseModel):
    days: int

class MacOverrideSchema(BaseModel):
    ip: str
    command: str
    fmt: str = "generic"    # bridge-domain | mac-address-table | generic

class MacOverrideDeleteSchema(BaseModel):
    ip: str


# --- ENDPOINTS E HELPERS ---

def _mac_uplink_ports(ip: str) -> dict:
    """Porte locali dell'apparato che hanno un vicino CDP/LLDP: sono trunk/uplink,
    quindi i MAC visti lì sono transito e non 'posizione' reale dell'host. Si
    ricavano dal backup dell'apparato (già raccolto dal triage)."""
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

def _mac_topology_uplinks():
    """Ritorna (uplink_map, known_switches).

    uplink_map: { switch_ip: { porta_normalizzata: etichetta_vicino } } — solo le
                porte che vanno verso un altro apparato di rete (infrastruttura).
    known_switches: insieme degli IP inventariati presenti in mappa (per cui la
                topologia è autorevole: assenza di una porta = porta di accesso).
    """
    from collections import defaultdict
    uplink_map: dict = defaultdict(dict)
    known_switches: set = set()
    try:
        data = core_engine.generate_network_map(group_filter="all")
    except Exception:
        return uplink_map, known_switches

    nodes = data.get("nodes", [])
    node_type = {n["id"]: n.get("device_type") for n in nodes}
    node_label = {n["id"]: (n.get("label") or n["id"]) for n in nodes}
    known_switches = {n["id"] for n in nodes if n.get("group") != "Discovered"}

    def add(sw, port, neigh_id):
        if not port:
            return
        uplink_map[sw][core_engine._normalize_iface(port)] = node_label.get(neigh_id, neigh_id)

    for l in data.get("links", []):
        src, tgt = l.get("source"), l.get("target")
        tgt_infra = node_type.get(tgt) in _MAC_INFRA_TYPES
        src_infra = node_type.get(src) in _MAC_INFRA_TYPES
        pc = l.get("pc_name")
        # Le porte locali di src vanno verso tgt: sono uplink solo se tgt è infra.
        if tgt_infra:
            for p in l.get("local_ports", []):
                add(src, p, tgt)
            if pc:
                add(src, pc, tgt)
        if src_infra:
            for p in l.get("remote_ports", []):
                add(tgt, p, src)
            if pc:
                add(tgt, pc, src)
    return uplink_map, known_switches

def _reclassify_sightings(rows, uplink_map=None, known_switches=None):
    """Ricalcola is_uplink/uplink_to di ogni avvistamento contro la topologia
    globale. Per gli switch noti la topologia è autorevole; per gli switch senza
    dati topologici si conserva il valore rilevato in raccolta (fallback)."""
    if uplink_map is None or known_switches is None:
        uplink_map, known_switches = _mac_topology_uplinks()
    # MAC delle interfacce proprie degli switch: tali MAC sono infrastruttura
    # ("switch-interface"), non endpoint. Si taggano, non si scartano.
    if_macs = mac_history.get_switch_if_macs()
    norm = core_engine._normalize_iface
    for r in rows:
        sw = r.get("switch_ip")
        if sw in known_switches:
            ups = uplink_map.get(sw, {})
            ni = norm(r.get("interface") or "")
            npc = norm(r.get("port_channel") or "") if r.get("port_channel") else ""
            neigh = ups.get(ni) or (ups.get(npc) if npc else None)
            r["is_uplink"] = bool(neigh)
            r["uplink_to"] = neigh or ""
        # else: switch senza topologia nota → mantiene is_uplink/uplink_to raccolti
        r["is_uplink"] = bool(r.get("is_uplink"))
        info = if_macs.get(r.get("mac"))
        if info:
            r["origin_type"] = "switch-interface"
            r["origin_switch"] = info.get("switch_name") or info.get("switch_ip") or ""
            r["origin_interface"] = info.get("interface") or ""
        else:
            r["origin_type"] = "endpoint"
    return rows

def _mac_collect_one(device: dict, transport=None) -> dict:
    ip = device["IP"]
    vendor = (device.get("Vendor") or "cisco").lower()
    username, password, secret = core_engine.get_device_credentials(device)
    try:
        _, netmiko_type = core_engine.resolve_driver(vendor)
    except Exception:
        netmiko_type = "cisco_ios"
    # Comando ad-hoc configurato per questo apparato (casi non ordinari).
    ov = mac_history.get_override(ip) or {}
    dev_transports = inventory_manager.parse_transports(device)
    res = mac_collector.collect_mac_table(
        ip, username, password, secret, device_type=netmiko_type,
        uplink_ports=_mac_uplink_ports(ip), transport=transport,
        cli_command=ov.get("command"), cli_format=ov.get("fmt"),
        transports=dev_transports,
    )
    res["device"] = device
    # Raccogli anche i MAC delle interfacce proprie dello switch (infrastruttura):
    # servono a classificarli come "switch-interface" invece che endpoint. I
    # fallimenti sono non fatali (lista vuota).
    if not res.get("error"):
        try:
            ifres = mac_collector.collect_interface_macs(
                ip, username, password, secret, device_type=netmiko_type,
                transport=transport, transports=dev_transports,
            )
            res["if_macs"] = ifres.get("rows") or []
        except Exception:
            res["if_macs"] = []
    else:
        res["if_macs"] = []
    return res

def _mac_group(rows):
    """Raggruppa gli avvistamenti (già riclassificati) per MAC in
    {mac, oui_vendor, origin[], transit[], status}. origin ordinato per recency."""
    by_mac, order = {}, []
    for s in rows:
        m = s["mac"]
        if m not in by_mac:
            order.append(m)
            by_mac[m] = []
        by_mac[m].append(s)

    results = []
    for m in order:
        grp = by_mac[m]
        origin = [s for s in grp if not s.get("is_uplink")]
        transit = [s for s in grp if s.get("is_uplink")]
        # Ordina per ultimo avvistamento (più recente prima).
        origin.sort(key=lambda s: s.get("last_seen", ""), reverse=True)
        transit.sort(key=lambda s: s.get("last_seen", ""), reverse=True)
        # Posizioni di accesso DISTINTE (switch, interfaccia): l'ambiguità reale.
        distinct = {(s.get("switch_ip"), (s.get("interface") or "").lower()) for s in origin}
        if not origin and not transit:
            status = "not_found"
        elif not origin:
            status = "transit_only"          # visto solo in transito → dietro switch non gestito
        elif len(distinct) > 1:
            status = "ambiguous"             # più porte d'accesso plausibili
        else:
            status = "resolved"
        oui = next((s["oui_vendor"] for s in grp if s.get("oui_vendor")), "")
        entry = {"mac": m, "oui_vendor": oui, "origin": origin,
                 "transit": transit, "status": status,
                 "access_count": len(distinct)}
        # MAC di un'interfaccia propria di uno switch: infrastruttura, non endpoint.
        si = next((s for s in grp if s.get("origin_type") == "switch-interface"), None)
        if si:
            entry["device_type"] = "switch-interface"
            entry["origin_type"] = "switch-interface"
            entry["origin_switch"] = si.get("origin_switch") or ""
            entry["origin_interface"] = si.get("origin_interface") or ""
        results.append(entry)
    # I gruppi switch-interface (infrastruttura) vanno dopo gli endpoint.
    results.sort(key=lambda e: 1 if e.get("origin_type") == "switch-interface" else 0)
    return results

@router.post("/api/mac/scan")
def mac_scan(payload: MacScanSchema, current_user = Depends(require_operator)):
    """Raccoglie la MAC-table degli apparati selezionati (scoped per tenant) e la
    storicizza. Manuale, parallelizzato; al termine applica la retention."""
    scope = user_group_scope(current_user)
    devices = inventory_manager.get_all_devices()

    # Insieme di IP richiesti esplicitamente (singolo 'ip' e/o multi-selezione 'ips').
    want_ips = set(payload.ips or [])
    if payload.ip:
        want_ips.add(payload.ip)

    def allowed(d):
        g = d.get("Group") or "Generale"
        if scope is not None and g not in scope:
            return False
        if payload.group and payload.group != "all" and g != payload.group:
            return False
        if want_ips and d["IP"] not in want_ips:
            return False
        return True

    targets = [d for d in devices if allowed(d)]
    if not targets:
        raise HTTPException(status_code=404, detail="Nessun dispositivo idoneo per la scansione MAC.")

    # Raccolta in parallelo (I/O di rete), scrittura DB serializzata dopo.
    from functools import partial
    worker = partial(_mac_collect_one, transport=payload.transport)
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as ex:
        collected = list(ex.map(worker, targets))

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
        # Storicizza i MAC delle interfacce proprie dello switch (infrastruttura).
        if res.get("if_macs"):
            mac_history.record_switch_if_macs(
                res["if_macs"], switch_ip=ip, switch_name=d.get("Hostname", ""),
            )
        results.append({"ip": ip, "method": res["method"], "count": len(res["rows"]), **summ})

    pruned = mac_history.prune()
    log_audit(f"MAC scan eseguita da '{current_user.get('sub')}' su {len(targets)} apparati (pruned: {pruned}).")
    return {"scanned": len(targets), "results": results, "pruned": pruned}

@router.get("/api/mac/search")
def mac_search(mac: str = None, vlan: str = None, interface: str = None,
               switch: str = None, frm: str = None, to: str = None,
               tenant: str = None,
               current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    if tenant:
        if scope is not None and tenant not in scope:
            raise HTTPException(status_code=403, detail=f"Tenant '{tenant}' non consentito.")
        tenants = [tenant]
    else:
        tenants = scope
    rows = mac_history.search(mac=mac, vlan=vlan, interface=interface,
                              switch_ip=switch, tenants=tenants, frm=frm, to=to,
                              limit=10000)
    # Riclassifica accesso/transito contro la topologia globale (fix falsi positivi).
    _reclassify_sightings(rows)
    return {"results": rows, "count": len(rows)}

@router.get("/api/mac/locate")
def mac_locate(mac: str, current_user = Depends(get_current_user)):
    if not mac or not mac.strip():
        raise HTTPException(status_code=400, detail="Parametro mac obbligatorio")
    scope = user_group_scope(current_user)
    sightings = mac_history.search(mac=mac, tenants=scope, limit=500)
    if not sightings:
        return {"status": "not_found", "origin": [], "transit": [], "results": []}
    _reclassify_sightings(sightings)
    results = _mac_group(sightings)
    if len(results) == 1:
        r = results[0]
        return {"mac": r["mac"], "status": r["status"], "access_count": r["access_count"],
                "origin": r["origin"], "transit": r["transit"],
                "origin_type": r.get("origin_type"), "device_type": r.get("device_type"),
                "origin_switch": r.get("origin_switch"), "origin_interface": r.get("origin_interface"),
                "results": results}
    return {"results": results}

@router.get("/api/mac/switch/{ip}")
def mac_switch(ip: str, current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    return {"results": mac_history.switch_table(ip, tenants=scope)}

@router.get("/api/mac/stats")
def mac_stats(tenant: str = None, current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    if tenant:
        if scope is not None and tenant not in scope:
            raise HTTPException(status_code=403, detail=f"Tenant '{tenant}' non consentito.")
        tenants = [tenant]
    else:
        tenants = scope
    return mac_history.stats(tenants=tenants)

@router.post("/api/mac/settings")
def mac_set_settings(payload: MacRetentionSchema, current_user = Depends(require_admin)):
    days = mac_history.set_retention_days(payload.days)
    log_audit(f"MAC retention impostata a {days} giorni da '{current_user.get('sub')}'.")
    return {"retention_days": days}

@router.get("/api/mac/overrides")
def mac_list_overrides(current_user = Depends(get_current_user)):
    return {"overrides": mac_history.list_overrides()}

@router.post("/api/mac/overrides")
def mac_set_override(payload: MacOverrideSchema, current_user = Depends(require_operator)):
    if payload.fmt not in mac_collector.CLI_FORMATS:
        raise HTTPException(status_code=400, detail="Formato di parsing non valido.")
    assert_device_allowed(current_user, payload.ip)
    if not mac_history.set_override(payload.ip, payload.command, payload.fmt):
        raise HTTPException(status_code=400, detail="IP e comando obbligatori.")
    log_audit(f"MAC override per '{payload.ip}' impostato ('{payload.command}' / {payload.fmt}) "
              f"da '{current_user.get('sub')}'.")
    return {"status": "success"}

@router.post("/api/mac/overrides/delete")
def mac_delete_override(payload: MacOverrideDeleteSchema, current_user = Depends(require_operator)):
    assert_device_allowed(current_user, payload.ip)
    mac_history.delete_override(payload.ip)
    log_audit(f"MAC override per '{payload.ip}' rimosso da '{current_user.get('sub')}'.")
    return {"status": "success"}

