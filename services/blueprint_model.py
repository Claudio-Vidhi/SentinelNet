# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure logic of the Network Blueprint (spec 2026-10-11 network-blueprint):
draft operations applied to the locations and links tables, revision diffs,
restore and preset operations. No I/O: callers pass the tables in and
persist what comes out."""
import copy
import ipaddress
from itertools import combinations

from services.location_manager import ROLES, _clean_subnets

KINDS = ("vpn", "wan", "mpls", "lan")
FIELDS = ("name", "role", "subnets", "probe", "gateway")
PRESETS = ("single", "hub_spoke", "hub_spoke_dc", "full_mesh")
MAX_PRESET = 50


class OpError(ValueError):
    """A draft operation that cannot be applied; ``index`` is its position."""

    def __init__(self, index: int, message: str):
        super().__init__(f"Modifica {index + 1}: {message}")
        self.index = index


def link_id(a: str, b: str, kind: str) -> str:
    a, b = sorted((a, b))
    return f"{a}--{b}--{kind}"


def org_view(locations: dict, links: dict, org: str) -> dict:
    return {"locations": {k: v for k, v in locations.items() if v["org"] == org},
            "links": {k: v for k, v in links.items() if v["org"] == org}}


def _free_id(base: str, taken) -> str:
    lid, n = base, 2
    while lid in taken:
        lid, n = f"{base}-{n}", n + 1
    return lid


def _clean_fields(fields: dict, probes) -> dict:
    out = {}
    for k, v in fields.items():
        if k not in FIELDS:
            raise ValueError(f"campo sconosciuto: {k}")
        if k == "name":
            v = str(v or "").strip()
            if not v:
                raise ValueError("il nome della sede è obbligatorio")
        elif k == "role" and v not in ROLES:
            raise ValueError(f"ruolo non valido: {v}")
        elif k == "subnets":
            v = _clean_subnets(v)
        elif k == "probe" and probes is not None and v not in probes:
            raise ValueError(f"sonda '{v}' inesistente")
        elif k == "gateway":
            v = str(v or "").strip()
            if v:
                try:
                    ipaddress.ip_address(v)
                except ValueError:
                    raise ValueError(f"gateway non valido: {v}")
        out[k] = v
    return out


def apply_ops(org: str, locations: dict, links: dict, ops: list, probes=None):
    """Apply draft operations to copies of the whole locations and links
    tables (whole, because a new location's id must be unique across every
    organization). Returns (locations, links, refs); refs maps the «+…» ref
    of each created location to the id it got."""
    from services.probe_manager import _slugify
    locs, lnks, refs = copy.deepcopy(locations), copy.deepcopy(links), {}

    def loc_id(i, x):
        lid = refs.get(x, x)
        if lid not in locs or locs[lid]["org"] != org:
            raise OpError(i, f"sede '{x}' inesistente in questa organizzazione")
        return lid

    for i, op in enumerate(ops):
        kind = op.get("op")
        try:
            if kind == "create_location":
                fields = _clean_fields({"name": op.get("name"), "role": op.get("role") or "branch",
                                        "subnets": op.get("subnets") or [],
                                        "probe": op.get("probe") or "central",
                                        "gateway": op.get("gateway") or ""}, probes)
                ref = op.get("ref")
                if ref is not None and (not str(ref).startswith("+") or ref in refs):
                    raise ValueError(f"riferimento non valido: {ref}")
                wanted = op.get("id")
                lid = wanted if wanted and wanted not in locs else _free_id(wanted or _slugify(fields["name"]), locs)
                locs[lid] = dict(fields, org=org)
                if ref:
                    refs[ref] = lid
            elif kind in ("update_location", "set_gateway", "add_subnet"):
                lid = loc_id(i, op.get("id"))
                if kind == "update_location":
                    fields = op.get("fields")
                    if not isinstance(fields, dict) or not fields:
                        raise ValueError("nessun campo da modificare")
                elif kind == "set_gateway":
                    fields = {"gateway": op.get("ip")}
                else:
                    fields = {"subnets": locs[lid]["subnets"] + [op.get("subnet")]}
                locs[lid].update(_clean_fields(fields, probes))
            elif kind == "delete_location":
                lid = loc_id(i, op.get("id"))
                del locs[lid]
                lnks = {k: v for k, v in lnks.items() if lid not in (v["a"], v["b"])}
            elif kind == "add_link":
                a, b = loc_id(i, op.get("a")), loc_id(i, op.get("b"))
                if a == b:
                    raise ValueError("un collegamento unisce due sedi diverse")
                if op.get("kind") not in KINDS:
                    raise ValueError(f"tipo di collegamento non valido: {op.get('kind')}")
                k = link_id(a, b, op["kind"])
                if k in lnks:
                    raise ValueError("collegamento già presente")
                a, b = sorted((a, b))
                lnks[k] = {"org": org, "a": a, "b": b, "kind": op["kind"], "note": str(op.get("note") or "")}
            elif kind == "remove_link":
                k = op.get("id")
                if k not in lnks or lnks[k]["org"] != org:
                    raise ValueError(f"collegamento '{k}' inesistente")
                del lnks[k]
            else:
                raise ValueError(f"operazione sconosciuta: {kind}")
        except OpError:
            raise
        except ValueError as e:
            raise OpError(i, str(e))
    return locs, lnks, refs
