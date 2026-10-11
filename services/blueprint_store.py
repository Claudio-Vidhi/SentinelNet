# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Storage of the Network Blueprint (spec 2026-10-11 network-blueprint):
revisions of each organization's locations and links, the open draft, the
last observation of its gateways. Tables live in inventory.db
(inventory_store). No writer commits: callers group a model write and its
revision in one ``with conn:``."""
import json
from datetime import datetime, timezone

from services import inventory_store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def snapshot(conn, org: str) -> dict:
    return {"locations": {k: v for k, v in inventory_store.read_locations(conn).items() if v["org"] == org},
            "links": {k: v for k, v in inventory_store.read_links(conn).items() if v["org"] == org}}


def latest_rev(conn, org: str) -> int:
    return conn.execute("SELECT MAX(rev) FROM blueprint_revisions WHERE org = ?", (org,)).fetchone()[0] or 0


def record_revisions(conn, by: str, source: str, note: str = "") -> list:
    """Append a revision for every organization whose locations or links
    differ from its latest snapshot. Comparing snapshots instead of trusting
    each caller to say what changed is what keeps the history aligned: a
    cascade (a deleted location takes its links) is recorded too."""
    # ponytail: re-reads both tables per organization; per-org queries if an
    # install ever has thousands of organizations.
    made = []
    for (org,) in conn.execute("SELECT key FROM organizations ORDER BY key").fetchall():
        snap = snapshot(conn, org)
        rev = latest_rev(conn, org)
        if rev:
            last = conn.execute("SELECT snapshot FROM blueprint_revisions WHERE org = ? AND rev = ?",
                                (org, rev)).fetchone()[0]
            if json.loads(last) == snap:
                continue
        conn.execute("INSERT INTO blueprint_revisions (org, rev, at, by, source, note, snapshot) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (org, rev + 1, _now(), by or "", source, note or "", json.dumps(snap, sort_keys=True)))
        made.append((org, rev + 1))
    return made


def revisions(conn, org: str) -> list:
    return [dict(r) for r in conn.execute(
        "SELECT rev, at, by, source, note FROM blueprint_revisions WHERE org = ? ORDER BY rev DESC", (org,))]


def revision(conn, org: str, rev: int):
    r = conn.execute("SELECT rev, at, by, source, note, snapshot FROM blueprint_revisions "
                     "WHERE org = ? AND rev = ?", (org, rev)).fetchone()
    if not r:
        return None
    out = dict(r)
    out["snapshot"] = json.loads(out["snapshot"])
    return out


def get_draft(conn, org: str):
    r = conn.execute("SELECT base_rev, source, ops, updated_by, updated_at FROM blueprint_drafts "
                     "WHERE org = ?", (org,)).fetchone()
    if not r:
        return None
    out = dict(r)
    out["ops"] = json.loads(out["ops"])
    return out


def put_draft(conn, org: str, base_rev: int, source: str, ops: list, by: str) -> None:
    conn.execute("INSERT INTO blueprint_drafts (org, base_rev, source, ops, updated_by, updated_at) "
                 "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (org) DO UPDATE SET base_rev = excluded.base_rev, "
                 "source = excluded.source, ops = excluded.ops, updated_by = excluded.updated_by, "
                 "updated_at = excluded.updated_at",
                 (org, base_rev, source, json.dumps(ops), by or "", _now()))


def delete_draft(conn, org: str) -> None:
    conn.execute("DELETE FROM blueprint_drafts WHERE org = ?", (org,))


def get_observation(conn, org: str):
    r = conn.execute("SELECT at, data FROM blueprint_observations WHERE org = ?", (org,)).fetchone()
    return {"at": r["at"], "data": json.loads(r["data"])} if r else None


def put_observation(conn, org: str, data: dict) -> str:
    at = _now()
    conn.execute("INSERT INTO blueprint_observations (org, at, data) VALUES (?, ?, ?) "
                 "ON CONFLICT (org) DO UPDATE SET at = excluded.at, data = excluded.data",
                 (org, at, json.dumps(data)))
    return at
