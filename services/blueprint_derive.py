# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""«Ricava dalle configurazioni» (spec 2026-10-11 blueprint-assistant): draft
operations read from the configuration backups of an organization's devices.
Pure: the caller passes the model view (the preview when a draft exists), the
inventory rows and one config_analyzer analysis per device IP."""
import ipaddress

from services.blueprint_model import link_id

_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def _addresses(analysis: dict):
    """(interface, IPv4Interface) for every parsable IPv4 interface address."""
    for i in analysis.get("interfaces") or []:
        try:
            addr = ipaddress.ip_interface(i.get("ip") or "")
        except ValueError:
            continue
        if addr.version == 4:
            yield i, addr


def _lan(i: dict, addr) -> bool:
    """An interface whose network may be a location subnet."""
    net = addr.network
    return not (net.prefixlen >= 31 or addr.is_loopback
                or str(i.get("name") or "").lower().startswith("loopback")
                or i.get("shutdown") or i.get("status") == "down"
                or not any(net.subnet_of(r) for r in _RFC1918))


def derive(view: dict, devices: list, analyses: dict):
    """Returns (ops, notes): add_subnet, set_gateway and add_link vpn
    operations, then one Italian note per kind of skipped input."""
    locs, links = view["locations"], view["links"]
    taken = [n for n in (ipaddress.ip_network(s, strict=False)
                         for l in locs.values() for s in l.get("subnets") or []) if n.version == 4]
    no_loc = no_backup = unreadable = unknown = 0
    placed = []
    # owner: address -> location of the device holding it; management IPs win over interface addresses.
    owner = {}
    by_place = sorted(devices, key=lambda d: (d.get("Location") or "", d.get("IP") or ""))
    for d in by_place:
        if d.get("Location") in locs:
            owner.setdefault(d.get("IP") or "", d["Location"])
    for d in by_place:
        lid, ip = d.get("Location") or "", d.get("IP") or ""
        if lid not in locs:
            no_loc += 1
            continue
        a = analyses.get(ip)
        if a is None:
            no_backup += 1
        elif "interfaces" not in a:
            unreadable += 1
        else:
            placed.append((lid, ip, a))
            for _i, addr in _addresses(a):
                owner.setdefault(str(addr.ip), lid)

    ops = []
    for lid, _ip, a in placed:
        for i, addr in _addresses(a):
            net = addr.network
            if not _lan(i, addr) or any(net.overlaps(t) for t in taken):
                continue
            taken.append(net)            # one op per network: the first location keeps it
            ops.append({"op": "add_subnet", "id": lid, "subnet": str(net)})

    # A default route inside a VRF is a management port's, not the location's exit.
    defaults: dict = {}
    for lid, ip, a in placed:
        if any(r.get("prefix") == "0.0.0.0/0" and not r.get("vrf")
               for r in (a.get("routing") or {}).get("static") or []):
            defaults.setdefault(lid, []).append(ip)
    crowded = []
    for lid in sorted(defaults):
        if locs[lid].get("gateway"):
            continue
        if len(defaults[lid]) == 1:
            ops.append({"op": "set_gateway", "id": lid, "ip": defaults[lid][0]})
        else:
            crowded.append(f"{locs[lid]['name']}: {len(defaults[lid])} apparati con rotta di default, "
                           "gateway da scegliere a mano.")

    proposed = set()
    for lid, _ip, a in placed:
        vpn = a.get("vpn")
        for p in (vpn.get("peers") or []) if isinstance(vpn, dict) else []:
            gw = p.get("remote_gw") or ""
            if not gw:
                continue                 # dial-up phase 1: no fixed peer
            other = owner.get(gw)
            if other is None:
                unknown += 1
                continue
            k = link_id(lid, other, "vpn")
            if other == lid or k in links or k in proposed:
                continue
            proposed.add(k)
            # The phase-1 name comes from a device config and reaches the LLM
            # in the rename pass: a short label, not free text.
            ops.append({"op": "add_link", "a": lid, "b": other, "kind": "vpn",
                        "note": str(p.get("name") or "")[:64]})

    notes = [text for n, text in ((no_loc, f"{no_loc} apparati senza sede: ignorati."),
                                  (no_backup, f"{no_backup} apparati senza backup della configurazione."),
                                  (unreadable, f"{unreadable} backup non leggibili.")) if n]
    notes += crowded
    if unknown:
        notes.append(f"{unknown} peer IPsec verso indirizzi che non sono apparati di questa organizzazione.")
    return ops, notes
