# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Network Blueprint (spec 2026-10-11 network-blueprint): drafts over an
organization's locations and links, applied in one transaction, every write
versioned. Storage in blueprint_store, pure logic in blueprint_model, checks
in blueprint_checks, observed data in blueprint_observe."""
from services import (blueprint_checks, blueprint_model, blueprint_observe, blueprint_store,
                      inventory_manager, inventory_store, location_manager, probe_manager)


class Conflict(Exception):
    """The model changed after the draft was made from it."""


def _probes() -> set:
    return {p["id"] for p in probe_manager.list_probes()}


def _tables(conn):
    return inventory_store.read_locations(conn), inventory_store.read_links(conn)


def _preview(org, locs, links, draft):
    if not draft:
        return None, ""
    try:
        new_locs, new_links, _ = blueprint_model.apply_ops(org, locs, links, draft["ops"], _probes())
    except blueprint_model.OpError as e:
        return None, str(e)
    return blueprint_model.org_view(new_locs, new_links, org), ""


def state(org: str) -> dict:
    with inventory_manager._db() as conn:
        locs, links = _tables(conn)
        draft = blueprint_store.get_draft(conn, org)
        revs = blueprint_store.revisions(conn, org)
    preview, error = _preview(org, locs, links, draft)
    view = blueprint_model.org_view(locs, links, org)
    return {"org": org, "locations": view["locations"], "links": view["links"],
            "rev": revs[0]["rev"] if revs else 0, "rev_info": revs[0] if revs else None,
            "draft": draft, "preview": preview, "draft_error": error,
            "probes": [{"id": p["id"], "name": p.get("name") or p["id"]} for p in probe_manager.list_probes()]}


def checks(org: str) -> dict:
    """Findings on the model with the draft applied in memory: a proposal
    already in the draft does not come back."""
    st = state(org)
    view = st["preview"] or {"locations": st["locations"], "links": st["links"]}
    observed = blueprint_observe.gather(org, view)
    return {"findings": blueprint_checks.run(view, observed), "observed_at": observed.get("observed_at")}


def _with_unique_refs(existing: list, new: list) -> list:
    """Rename the refs the new operations define when the draft already uses
    them (two presets both start at «+1»)."""
    used = {o["ref"] for o in existing if o.get("ref")}
    mapping = {}
    for o in new:
        r = o.get("ref")
        if not r:
            continue
        fresh, n = r, 2
        while fresh in used:
            fresh, n = f"{r}.{n}", n + 1
        used.add(fresh)
        mapping[r] = fresh
    return [dict(o, **{k: mapping.get(o[k], o[k]) for k in ("ref", "id", "a", "b") if k in o}) for o in new]


def add_ops(org: str, ops: list, source: str, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        locs, links = _tables(conn)
        draft = blueprint_store.get_draft(conn, org)
        old = draft["ops"] if draft else []
        new = _with_unique_refs(old, [dict(o, source=source) for o in ops])
        if not new:
            raise ValueError("Nessuna modifica da aggiungere.")
        blueprint_model.apply_ops(org, locs, links, old + new, _probes())
        base = draft["base_rev"] if draft else blueprint_store.latest_rev(conn, org)
        with conn:
            blueprint_store.put_draft(conn, org, base, draft["source"] if draft else source, old + new, by)
    return state(org)


def replace_ops(org: str, ops: list, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        draft = blueprint_store.get_draft(conn, org)
        if not draft:
            raise LookupError("Nessuna bozza aperta.")
        locs, links = _tables(conn)
        blueprint_model.apply_ops(org, locs, links, ops, _probes())
        with conn:
            if ops:
                blueprint_store.put_draft(conn, org, draft["base_rev"], draft["source"], ops, by)
            else:
                blueprint_store.delete_draft(conn, org)
    return state(org)


def discard(org: str) -> None:
    with location_manager._lock, inventory_manager._db() as conn, conn:
        blueprint_store.delete_draft(conn, org)


def align(org: str, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        draft = blueprint_store.get_draft(conn, org)
        if not draft:
            raise LookupError("Nessuna bozza aperta.")
        with conn:
            blueprint_store.put_draft(conn, org, blueprint_store.latest_rev(conn, org),
                                      draft["source"], draft["ops"], by)
    return state(org)


def apply(org: str, by: str, note: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        draft = blueprint_store.get_draft(conn, org)
        if not draft:
            raise LookupError("Nessuna bozza aperta.")
        current = blueprint_store.latest_rev(conn, org)
        if draft["base_rev"] != current:
            raise Conflict(f"Il modello è cambiato dopo la bozza: revisione {draft['base_rev']} → {current}.")
        locs, links = _tables(conn)
        new_locs, new_links, refs = blueprint_model.apply_ops(org, locs, links, draft["ops"], _probes())
        for lid in sorted(set(locs) - set(new_locs)):
            n = location_manager.devices_in(lid)
            if n:
                raise ValueError(f"La sede '{locs[lid]['name']}' contiene {n} apparati: spostali o eliminali prima.")
        source = "restore" if draft["source"] == "restore" else "blueprint"
        with conn:
            inventory_store.put_locations(conn, new_locs)
            inventory_store.put_links(conn, new_links)
            blueprint_store.record_revisions(conn, by, source, note)
            blueprint_store.delete_draft(conn, org)
        rev = blueprint_store.latest_rev(conn, org)
    renamed = {r[1:]: lid for r, lid in refs.items() if source == "restore" and r[1:] != lid}
    return {"rev": rev, "renamed": renamed}


def restore(org: str, rev: int, by: str) -> dict:
    with location_manager._lock, inventory_manager._db() as conn:
        if blueprint_store.get_draft(conn, org):
            raise ValueError("C'è già una bozza aperta: applicala o scartala prima del ripristino.")
        target = blueprint_store.revision(conn, org, rev)
        if not target:
            raise LookupError(f"Revisione {rev} inesistente.")
        locs, links = _tables(conn)
        ops = blueprint_model.restore_ops(blueprint_model.org_view(locs, links, org), target["snapshot"])
        if not ops:
            raise ValueError(f"Il modello è già uguale alla revisione {rev}.")
        ops = [dict(o, source="restore") for o in ops]
        blueprint_model.apply_ops(org, locs, links, ops, _probes())
        with conn:
            blueprint_store.put_draft(conn, org, blueprint_store.latest_rev(conn, org), "restore", ops, by)
    return state(org)


def preset(org: str, kind: str, n: int, by: str) -> dict:
    st = state(org)
    view = st["preview"] or {"locations": st["locations"], "links": st["links"]}
    ops = blueprint_model.preset_ops(kind, n, view)
    if not ops:
        raise ValueError("Il preset non aggiunge nulla a questo modello.")
    return add_ops(org, ops, "preset", by)


def diff(org: str, a: int, b: int) -> dict:
    with inventory_manager._db() as conn:
        ra, rb = blueprint_store.revision(conn, org, a), blueprint_store.revision(conn, org, b)
    if not ra or not rb:
        raise LookupError("Revisione inesistente.")
    return blueprint_model.diff(ra["snapshot"], rb["snapshot"])


def revisions(org: str) -> list:
    with inventory_manager._db() as conn:
        return blueprint_store.revisions(conn, org)


def revision(org: str, rev: int) -> dict:
    with inventory_manager._db() as conn:
        r = blueprint_store.revision(conn, org, rev)
    if not r:
        raise LookupError(f"Revisione {rev} inesistente.")
    return r


def observe(org: str) -> dict:
    st = state(org)
    return blueprint_observe.observe(org, {"locations": st["locations"], "links": st["links"]})
