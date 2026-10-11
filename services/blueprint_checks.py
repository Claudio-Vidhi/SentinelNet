# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic checks of the Network Blueprint (spec 2026-10-11
network-blueprint): the expected model against the observed snapshot.
Pure: no connection is ever opened here, the same inputs give the same
findings. A check that lacks its data says «unknown», never ok or error.

A finding may carry a proposal: draft operations that close the gap, which
the user accepts, edits or ignores."""
import ipaddress
from itertools import combinations

SEVERITY_ORDER = {"error": 0, "warning": 1, "unknown": 2, "info": 3}
HUB_ROLES = ("hq", "datacenter")
SPOKE_ROLES = ("branch", "warehouse")
# Vendors whose route table SentinelNet reads (route_table.ROUTE_SOURCES):
# the ones that can be a location's gateway for these checks.
GATEWAY_VENDORS = ("fortinet", "cisco")
# Spelled out: ip_address.is_private also says True for the documentation
# ranges (RFC 5737) and others that are never a location's LAN.
_LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _f(code, severity, subject, proposal=None, **params) -> dict:
    return {"code": code, "severity": severity, "subject": subject, "params": params, "proposal": proposal}


def _net(text):
    try:
        return ipaddress.ip_network(str(text or "").strip().replace(" ", "/"), strict=False)
    except ValueError:
        return None


def _nets(subnets) -> list:
    return [n for n in (_net(s) for s in subnets or []) if n is not None]


def _addr(ip):
    try:
        return ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return None


def _covers(nets, ip) -> bool:
    # ip_address in ip_network does not compare versions: guard it.
    return any(n.version == ip.version and ip in n for n in nets)


def _slash24(ip) -> str:
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def _model_checks(locs: dict, links: dict, devices: list) -> list:
    out = []
    items = sorted(locs.items())
    for (ida, la), (idb, lb) in combinations(items, 2):
        for na in _nets(la["subnets"]):
            for nb in _nets(lb["subnets"]):
                if na.version == nb.version and na.overlaps(nb):
                    out.append(_f("subnet_overlap", "error", {"location": ida}, a=la["name"], b=lb["name"],
                                  subnet_a=str(na), subnet_b=str(nb)))
    for lid, l in items:
        if not l["subnets"]:
            out.append(_f("location_no_subnets", "warning", {"location": lid}, name=l["name"]))

    hubs = {lid for lid, l in items if l["role"] in HUB_ROLES}
    adj = {lid: set() for lid in locs}
    for k in links.values():
        adj[k["a"]].add(k["b"])
        adj[k["b"]].add(k["a"])
    reach, todo = set(hubs), list(hubs)
    while todo:
        for nxt in adj[todo.pop()] - reach:
            reach.add(nxt)
            todo.append(nxt)
    hub = next((lid for lid, l in items if l["role"] == "hq"), None) or next(iter(sorted(hubs)), None)
    for lid, l in items:
        if l["role"] in SPOKE_ROLES and lid not in reach:
            prop = [{"op": "add_link", "a": hub, "b": lid, "kind": "vpn", "note": ""}] if hub else None
            out.append(_f("location_isolated", "warning", {"location": lid}, prop, name=l["name"]))

    for lid, l in items:
        gw = l.get("gateway") or ""
        mine = [d for d in devices if d.get("Location") == lid]
        if not gw:
            cands = sorted(d["IP"] for d in mine if (d.get("Vendor") or "").lower() in GATEWAY_VENDORS)
            prop = [{"op": "set_gateway", "id": lid, "ip": cands[0]}] if len(cands) == 1 else None
            out.append(_f("location_no_gateway", "warning", {"location": lid}, prop,
                          name=l["name"], candidates=cands))
        elif not any(d.get("IP") == gw for d in mine):
            out.append(_f("gateway_not_in_location", "error", {"location": lid}, name=l["name"], ip=gw))
    return out


def _subnet_checks(locs: dict, devices: list, arp: list) -> list:
    out = []
    nets = {lid: _nets(l["subnets"]) for lid, l in locs.items()}
    all_nets = [n for ns in nets.values() for n in ns]

    for d in devices:
        lid, ip = d.get("Location"), _addr(d.get("IP"))
        if lid not in locs or ip is None or not nets[lid] or _covers(nets[lid], ip):
            continue
        owner = next((o for o, ns in sorted(nets.items()) if o != lid and _covers(ns, ip)), None)
        # Moving a device is an inventory write, not a model operation: when
        # another location owns the address the finding names it, no proposal.
        prop = None if owner or ip.version != 4 else \
            [{"op": "add_subnet", "id": lid, "subnet": _slash24(d["IP"])}]
        out.append(_f("device_outside_subnets", "warning", {"device": d["IP"]}, prop,
                      ip=d["IP"], name=locs[lid]["name"], owner=locs[owner]["name"] if owner else ""))

    gw_loc = {l["gateway"]: lid for lid, l in locs.items() if l.get("gateway")}
    seen = {}
    for e in arp:
        lid, ip = gw_loc.get(e.get("source_ip")), _addr(e.get("ip"))
        # RFC 1918 only: the ISP side of a WAN interface shows up in ARP too,
        # and a public /24 is never a location's subnet.
        if lid is None or ip is None or not _covers(_LAN_NETS, ip) or _covers(all_nets, ip):
            continue
        key = (lid, _slash24(str(ip)))
        seen[key] = seen.get(key, 0) + 1
    for (lid, net), count in sorted(seen.items()):
        out.append(_f("arp_uncovered", "warning", {"location": lid},
                      [{"op": "add_subnet", "id": lid, "subnet": net}],
                      name=locs[lid]["name"], subnet=net, count=count))

    used = [a for a in (_addr(x) for x in [d.get("IP") for d in devices] + [e.get("ip") for e in arp]) if a]
    for lid, ns in sorted(nets.items()):
        for n in ns:
            if not any(a.version == n.version and a in n for a in used):
                out.append(_f("subnet_unused", "info", {"location": lid}, name=locs[lid]["name"], subnet=str(n)))
    return out


def _route_nets(entry) -> list:
    return [(n, row) for n, row in ((_net(r.get("network")), r) for r in entry.get("rows") or []) if n is not None]


def _routing_checks(locs: dict, links: dict, routes: dict, tunnels: dict) -> list:
    out = []
    for lkid, k in sorted(links.items()):
        for src, dst in ((k["a"], k["b"]), (k["b"], k["a"])):
            gw = locs[src].get("gateway")
            entry = routes.get(gw) if gw else None
            names = {"src": locs[src]["name"], "dst": locs[dst]["name"]}
            if not entry or not entry.get("rows"):
                out.append(_f("link_no_route", "unknown", {"link": lkid},
                              reason="no_gateway" if not gw else "no_routes", **names))
                continue
            nets = _route_nets(entry)
            for s in _nets(locs[dst]["subnets"]):
                if any(n.version == s.version and n.prefixlen > 0 and s.subnet_of(n) for n, _ in nets):
                    continue
                if any(n.version == s.version and n.prefixlen == 0 for n, _ in nets):
                    sev, via = "warning", "default"
                else:
                    # The backup only has static routes: a dynamic route may
                    # well exist, so a gap there is a warning, not an error.
                    sev, via = ("warning" if entry.get("from_backup") else "error"), ""
                out.append(_f("link_no_route", sev, {"link": lkid}, subnet=str(s), via=via,
                              backup_only=bool(entry.get("from_backup")), **names))

    linked = {frozenset((k["a"], k["b"])) for k in links.values()}
    proposed = set()
    for src, l in sorted(locs.items()):
        gw = l.get("gateway")
        entry = routes.get(gw) if gw else None
        if not entry:
            continue
        tnames = {t["name"] for t in (tunnels.get(gw) or {}).get("tunnels") or []}
        nets = _route_nets(entry)
        for dst, m in sorted(locs.items()):
            pair = frozenset((src, dst))
            if dst == src or pair in linked or pair in proposed:
                continue
            dnets = _nets(m["subnets"])
            hit = next((row for n, row in nets if n.prefixlen > 0
                        and any(n.version == s.version and n.overlaps(s) for s in dnets)), None)
            if hit:
                proposed.add(pair)
                kind = "vpn" if hit.get("interface") in tnames else "wan"
                out.append(_f("route_without_link", "info", {"location": src},
                              [{"op": "add_link", "a": src, "b": dst, "kind": kind, "note": ""}],
                              src=l["name"], dst=m["name"], network=hit.get("network") or "",
                              interface=hit.get("interface") or ""))
    return out


def _tunnel_matches(t: dict, other: dict) -> bool:
    gw = other.get("gateway") or ""
    if gw and t.get("remote_gw") == gw:
        return True
    dnets = _nets(other["subnets"])
    return any(any(n.version == s.version and n.overlaps(s) for s in dnets) for n in _nets(t.get("dst")))


def _vpn_checks(locs: dict, links: dict, tunnels: dict, devices: list) -> list:
    out = []
    vendor = {d.get("IP"): (d.get("Vendor") or "").lower() for d in devices}

    def side_tunnels(loc_id):
        """The location's gateway tunnels, or None when they are not known
        (no FortiGate gateway, or never collected)."""
        gw = locs[loc_id].get("gateway")
        data = tunnels.get(gw) if gw else None
        if not gw or vendor.get(gw) != "fortinet" or data is None:
            return None
        if data.get("error") and not data.get("tunnels"):
            return None
        return data.get("tunnels") or []

    for lkid, k in sorted(links.items()):
        if k["kind"] != "vpn":
            continue
        known = False
        for side, other in ((k["a"], k["b"]), (k["b"], k["a"])):
            ts = side_tunnels(side)
            if ts is None:
                continue
            known = True
            match = [t for t in ts if _tunnel_matches(t, locs[other])]
            names = {"side": locs[side]["name"], "other": locs[other]["name"]}
            if not match:
                out.append(_f("vpn_link_down", "error", {"link": lkid}, state="missing", tunnel="", **names))
            elif not any(t.get("up") for t in match):
                out.append(_f("vpn_link_down", "error", {"link": lkid}, state="down",
                              tunnel=match[0].get("name") or "", **names))
        if not known:
            out.append(_f("vpn_link_down", "unknown", {"link": lkid}, state="unknown", tunnel="",
                          side=locs[k["a"]]["name"], other=locs[k["b"]]["name"]))

    linked = {frozenset((k["a"], k["b"])) for k in links.values() if k["kind"] == "vpn"}
    proposed = set()
    for src, l in sorted(locs.items()):
        for t in side_tunnels(src) or []:
            if not t.get("up"):
                continue
            for dst, m in sorted(locs.items()):
                pair = frozenset((src, dst))
                if dst == src or pair in linked or pair in proposed or not _tunnel_matches(t, m):
                    continue
                proposed.add(pair)
                out.append(_f("tunnel_without_link", "info", {"location": src},
                              [{"op": "add_link", "a": src, "b": dst, "kind": "vpn", "note": ""}],
                              src=l["name"], dst=m["name"], tunnel=t.get("name") or ""))
    return out


def run(view: dict, observed: dict) -> list:
    locs, links = view["locations"], view["links"]
    devices = observed.get("devices") or []
    routes, tunnels = observed.get("routes") or {}, observed.get("tunnels") or {}
    findings = (_model_checks(locs, links, devices)
                + _subnet_checks(locs, devices, observed.get("arp") or [])
                + _routing_checks(locs, links, routes, tunnels)
                + _vpn_checks(locs, links, tunnels, devices))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
