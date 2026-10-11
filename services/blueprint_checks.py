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


def run(view: dict, observed: dict) -> list:
    locs, links = view["locations"], view["links"]
    devices = observed.get("devices") or []
    findings = _model_checks(locs, links, devices) + _subnet_checks(locs, devices, observed.get("arp") or [])
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
