# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Network segments of a tenant (plan 2026-11-03 network-segments): separate
networks inside a site, e.g. an OT network behind its own firewalls. The map
decides membership (subnets + members - excluded); this module only stores
what the user saved and the decisions on links between segments."""
import ipaddress
import json
import uuid

COLORS = ("amber", "teal", "violet", "rose", "lime", "sky")
DECISIONS = ("allowed", "gateway")
_MAX_IDS = 2000


def _db():
    from services import inventory_manager
    return inventory_manager._db()


def _check_org(org: str) -> None:
    from services import inventory_manager
    if org not in inventory_manager.get_all_groups():
        raise ValueError(f"Organizzazione '{org}' inesistente.")


def _ids(values) -> list:
    out = sorted({str(v).strip()[:200] for v in values or [] if str(v).strip()})
    if len(out) > _MAX_IDS:
        raise ValueError("Troppi apparati in un segmento.")
    return out


def _subnets(values) -> list:
    out = set()
    for raw in values or []:
        raw = str(raw).strip()
        if not raw:
            continue
        try:
            out.add(str(ipaddress.ip_network(raw, strict=False)))
        except ValueError:
            raise ValueError(f"Subnet non valida: {raw}")
    return sorted(out)


def _row(r) -> dict:
    return {"id": r["id"], "org": r["org"], "name": r["name"], "color": r["color"],
            "subnets": json.loads(r["subnets"]), "members": json.loads(r["members"]),
            "excluded": json.loads(r["excluded"])}


def list_segments(org: str) -> dict:
    with _db() as conn:
        segs = [_row(r) for r in conn.execute("SELECT * FROM segments WHERE org = ? ORDER BY name, id", (org,))]
        links = [{"a": r["a"], "b": r["b"], "decision": r["decision"]}
                 for r in conn.execute("SELECT a, b, decision FROM segment_links WHERE org = ? ORDER BY a, b", (org,))]
    return {"segments": segs, "links": links}


def save_segment(org, seg_id, name, color, subnets=None, members=None, excluded=None) -> dict:
    _check_org(org)
    name = str(name or "").strip()
    if not name or len(name) > 60:
        raise ValueError("Nome del segmento obbligatorio (massimo 60 caratteri).")
    if color not in COLORS:
        raise ValueError(f"Colore non valido: {color}")
    subnets, members, excluded = _subnets(subnets), _ids(members), _ids(excluded)
    with _db() as conn, conn:
        if seg_id:
            r = conn.execute("SELECT org FROM segments WHERE id = ?", (seg_id,)).fetchone()
            if not r or r["org"] != org:
                raise ValueError(f"Segmento '{seg_id}' inesistente.")
        else:
            seg_id = uuid.uuid4().hex[:12]
        # One node, one segment: whoever saves last takes it.
        taken = set(members)
        for r in conn.execute("SELECT id, members FROM segments WHERE org = ? AND id != ?", (org, seg_id)).fetchall():
            left = [m for m in json.loads(r["members"]) if m not in taken]
            conn.execute("UPDATE segments SET members = ? WHERE id = ?", (json.dumps(left), r["id"]))
        conn.execute(
            "INSERT INTO segments (id, org, name, color, subnets, members, excluded) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (id) DO UPDATE SET name = excluded.name, color = excluded.color, "
            "subnets = excluded.subnets, members = excluded.members, excluded = excluded.excluded",
            (seg_id, org, name, color, json.dumps(subnets), json.dumps(members), json.dumps(excluded)))
    return {"id": seg_id, "org": org, "name": name, "color": color,
            "subnets": subnets, "members": members, "excluded": excluded}


def delete_segment(org: str, seg_id: str) -> None:
    with _db() as conn, conn:
        if not conn.execute("DELETE FROM segments WHERE id = ? AND org = ?", (seg_id, org)).rowcount:
            raise ValueError(f"Segmento '{seg_id}' inesistente.")


def set_link_decision(org: str, a: str, b: str, decision) -> None:
    """decision None clears it: the link is back to "to verify"."""
    _check_org(org)
    a, b = str(a or "").strip()[:200], str(b or "").strip()[:200]
    if not a or not b or a == b:
        raise ValueError("Collegamento non valido.")
    if decision is not None and decision not in DECISIONS:
        raise ValueError(f"Decisione non valida: {decision}")
    a, b = sorted((a, b))
    with _db() as conn, conn:
        if decision is None:
            conn.execute("DELETE FROM segment_links WHERE org = ? AND a = ? AND b = ?", (org, a, b))
        else:
            conn.execute("INSERT INTO segment_links (org, a, b, decision) VALUES (?, ?, ?, ?) "
                         "ON CONFLICT (org, a, b) DO UPDATE SET decision = excluded.decision",
                         (org, a, b, decision))
