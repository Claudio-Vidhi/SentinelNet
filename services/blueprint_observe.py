# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""What the Blueprint checks compare the model with (spec 2026-10-11
network-blueprint). gather() reads only what the product already has —
inventory, ARP, the stored snapshot, static routes from backups — and opens
no connection. observe() is the explicit «Aggiorna dai gateway»: live routes
and IPsec tunnels of each location's gateway, stored as the snapshot."""
from services import blueprint_store, fortigate_service, inventory_manager, probe_manager, route_table


def _slim(rows) -> list:
    return [{"network": r.get("network") or "", "interface": r.get("interface") or "",
             "gateway": r.get("gateway") or "", "from_backup": bool(r.get("from_backup"))} for r in rows or []]


def gateways(org: str, view: dict) -> list:
    devs = {d["IP"]: d for d in inventory_manager.get_all_devices() if d.get("Group") == org}
    return [(lid, devs[l["gateway"]]) for lid, l in sorted(view["locations"].items())
            if l.get("gateway") in devs]


def _tunnels(device) -> dict:
    if probe_manager.is_agent_probe(device.get("Probe") or "central"):
        return {"tunnels": [], "error": "sede in modalita' agent: il centrale non raggiunge l'apparato"}
    try:
        data = fortigate_service.get_vpn_tunnels(device).get("data")
    except fortigate_service.FortiGateError as e:
        return {"tunnels": [], "error": str(e)}
    if not isinstance(data, list):
        return {"tunnels": [], "error": "solo testo CLI: tunnel non leggibili"}
    out = []
    for t in data:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        proxies = [p for p in t.get("proxyid") or [] if isinstance(p, dict)]
        dst = sorted({route_table._cidr(s.get("subnet")) for p in proxies
                      for s in p.get("proxy_dst") or [] if isinstance(s, dict) and s.get("subnet")})
        # Up when at least one phase-2 selector is, as route_table reads it.
        out.append({"name": t["name"], "remote_gw": t.get("rgwy") or "",
                    "up": any(p.get("status") == "up" for p in proxies), "dst": dst})
    return {"tunnels": out, "error": ""}


def observe(org: str, view: dict) -> dict:
    data, summary = {}, {}
    for _lid, dev in gateways(org, view):
        answer = route_table.collect_for(dev)
        entry = {"routes": {"rows": _slim(answer.get("rows")), "error": answer.get("error") or ""}}
        if (dev.get("Vendor") or "").lower() == "fortinet":
            entry["tunnels"] = _tunnels(dev)
        data[dev["IP"]] = entry
        t = entry.get("tunnels")
        summary[dev["IP"]] = {"routes": len(entry["routes"]["rows"]), "routes_error": entry["routes"]["error"],
                              "tunnels": len(t["tunnels"]) if t else None,
                              "tunnels_error": t["error"] if t else ""}
    with inventory_manager._db() as conn, conn:
        at = blueprint_store.put_observation(conn, org, data)
    return {"at": at, "gateways": summary}


def gather(org: str, view: dict) -> dict:
    from collectors import mac_history
    devices = [d for d in inventory_manager.get_all_devices() if d.get("Group") == org]
    # ponytail: the 5000 most recent bindings (search_arp's ceiling); a paged
    # read if an organization ever has more live endpoints than that.
    arp = [{"ip": e.get("ip"), "source_ip": e.get("source_ip")}
           for e in mac_history.search_arp(tenants=[org], limit=5000)]
    with inventory_manager._db() as conn:
        obs = blueprint_store.get_observation(conn, org)
    live = obs["data"] if obs else {}
    routes, tunnels = {}, {}
    for _lid, dev in gateways(org, view):
        ip = dev["IP"]
        if ip in live:
            r = live[ip]["routes"]
            routes[ip] = {"rows": r["rows"], "error": r["error"],
                          "from_backup": bool(r["rows"]) and all(x["from_backup"] for x in r["rows"])}
            if "tunnels" in live[ip]:
                tunnels[ip] = live[ip]["tunnels"]
        else:
            backup = route_table.routes_from_backup(dev)
            if backup and backup.get("rows"):
                routes[ip] = {"rows": _slim(backup["rows"]), "error": "", "from_backup": True}
    return {"devices": devices, "arp": arp, "routes": routes, "tunnels": tunnels,
            "observed_at": obs["at"] if obs else None}
