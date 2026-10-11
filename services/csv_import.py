# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""CSV import with preview (spec 2026-10-10 inventory-sqlite-import).

classify() is pure: it reads the inventory and writes nothing. The preview
endpoint returns it; the import endpoint recomputes it on the same input and
writes its new + update rows in one go, so the two cannot disagree."""
import functools
import ipaddress

from services import inventory_manager, location_manager, probe_manager

_SECRET = ("Password", "Enable Secret")
_COMPARED = ("Hostname", "Vendor", "Username", "Password", "Enable Secret", "Probe", "Location")


def _credentials_note(username, password, probe_id, get_probe) -> str:
    from core import device_credentials
    from security import identity_manager
    if username and password:
        return "credenziali proprie della riga"
    identity = (get_probe(probe_id) or {}).get("device_identity")
    if identity and identity_manager.get_identity_credentials(identity):
        return f"userà l'identità della sonda {probe_id}"
    if device_credentials.DEFAULT_USERNAME and device_credentials.DEFAULT_PASSWORD:
        return "userà l'account globale"
    return "nessuna: la connessione fallirà finché non assegni un'identità"


def _find_location(org, value, locs):
    if not value:
        return None
    if value in locs and locs[value]["org"] == org:
        return value
    return next((i for i, l in locs.items()
                 if l["org"] == org and l["name"].casefold() == value.casefold()), None)


def _in(ip, subnets) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(s) for s in subnets)


def _valid_ip(ip) -> bool:
    m = inventory_manager.IP_PATTERN.match(ip)
    return bool(m) and all(0 <= int(o) <= 255 for o in m.groups())


def classify(csv_text, default_org, default_location, decisions, scope) -> dict:
    parsed = inventory_manager._read_inventory_csv(csv_text)   # ValueError: unreadable file
    locs = {l["id"]: l for l in location_manager.list_locations()}
    active = {(d["Group"], d["IP"]): d for d in inventory_manager.get_all_devices()}
    retired = {(d["Group"], d["IP"]) for d in inventory_manager.get_decommissioned_devices()}
    # ponytail: per-call memo; each lookup re-reads its table (~2 ms/row on 2000 rows).
    get_probe = functools.cache(probe_manager.get_probe)
    resolve_group = functools.cache(inventory_manager.resolve_group)
    seen, rows = set(), []
    for line, rec in parsed:
        dec = (decisions or {}).get(str(line)) or {}
        ip = (rec.get("IP") or "").strip()
        r: dict = {"row": line, "ip": ip, "hostname": (rec.get("Hostname") or "").strip(),
             "vendor": inventory_manager.normalize_vendor(rec.get("Vendor") or "cisco"),
             "org": None, "location": None, "probe": None, "status": "new", "changes": {},
             "reason": "", "warnings": [], "action": None, "credentials_note": "",
             "_rec": rec}
        rows.append(r)

        def fail(reason, action=None):
            r.update(status="error", reason=reason, action=action)

        if dec.get("skip"):
            r["status"] = "skipped"
            continue
        if not _valid_ip(ip):
            fail("IP mancante o non valido")
            continue
        raw_org = (rec.get("Group") or "").strip() or default_org
        if not raw_org:
            fail("Organizzazione mancante: scegli una destinazione o aggiungi la colonna")
            continue
        org = resolve_group(raw_org)
        if org is None:
            fail(f"Organizzazione '{raw_org}' inesistente: crea prima l'organizzazione")
            continue
        if scope is not None and org not in scope:
            fail(f"Organizzazione '{org}' non consentita per il tuo profilo")
            continue
        r["org"] = org
        loc_value = dec.get("location") or (rec.get("Location") or "").strip() or \
            (default_location if org == default_org else None)
        loc_id = _find_location(org, loc_value, locs)
        if not loc_id:
            fail(f"Sede '{loc_value or ''}' inesistente o non appartenente a '{org}'")
            continue
        r["location"] = loc_id
        probe = (rec.get("Probe") or "").strip()
        if probe and not get_probe(probe):
            fail(f"Sonda '{probe}' inesistente")
            continue
        r["probe"] = probe or locs[loc_id]["probe"]
        if (org, ip) in seen:
            fail("IP già presente in una riga precedente del file", {"kind": "skip"})
            continue
        seen.add((org, ip))
        subnets = locs[loc_id]["subnets"]
        if subnets and not _in(ip, subnets) and "location" not in dec:
            other = next((i for i, l in locs.items() if l["org"] == org and i != loc_id
                          and l["subnets"] and _in(ip, l["subnets"])), None)
            if other:
                fail(f"Fuori dalle subnet di {locs[loc_id]['name']}: rientra in {locs[other]['name']}",
                     {"kind": "move", "location": other})
                continue
            r["warnings"].append("fuori dalle subnet della sede")
        if (org, ip) in retired:
            fail("Apparato dismesso: riattivalo o eliminalo prima")
            continue
        existing = active.get((org, ip))
        username, password = rec.get("Username", ""), rec.get("Password", "")
        if existing:
            r["status"] = "update"
            r["_profile"] = existing.get("Profile", "")   # the file has no Profile column: keep it
            incoming = {"Hostname": r["hostname"], "Vendor": r["vendor"] if rec.get("Vendor") else "",
                        "Username": username, "Password": password,
                        "Enable Secret": rec.get("Enable Secret", ""), "Probe": probe,
                        "Location": loc_id}
            for f in _COMPARED:
                new = incoming[f]
                if not new:
                    continue                      # empty cell keeps the stored value
                if f in _SECRET:
                    r["changes"][f] = ["", "changed"]
                elif new != existing.get(f, ""):
                    r["changes"][f] = [existing.get(f, ""), new]
            # What apply will write: an empty cell keeps the stored value.
            if not rec.get("Vendor"):
                r["vendor"] = existing["Vendor"]
            r["probe"] = probe or existing.get("Probe") or locs[loc_id]["probe"]
            username = username or existing.get("Username", "")
            password = password or existing.get("Password", "")
        r["credentials_note"] = _credentials_note(username, password, r["probe"], get_probe)
    counts = {k: sum(1 for r in rows if r["status"] == k) for k in ("new", "update", "error", "skipped")}
    columns = [{"header": h, "field": f} for h, f in inventory_manager._csv_columns(csv_text)]
    return {"columns": columns, "rows": rows, "counts": counts}


def public(result: dict) -> dict:
    """The classification without the private keys (raw records carry passwords)."""
    return dict(result, rows=[{k: v for k, v in r.items() if not k.startswith("_")}
                              for r in result["rows"]])


def apply(csv_text, default_org, default_location, decisions, scope) -> dict:
    result = classify(csv_text, default_org, default_location, decisions, scope)
    todo = [r for r in result["rows"] if r["status"] in ("new", "update")]
    entries = []
    for r in todo:
        rec = r["_rec"]
        entries.append(dict(ip=r["ip"], vendor=r["vendor"], profile=r.get("_profile", "custom"),
                            username=rec.get("Username", ""), password=rec.get("Password", ""),
                            enable_secret=rec.get("Enable Secret", ""), group=r["org"],
                            probe=(rec.get("Probe") or "").strip() or None,
                            location=r["location"], hostname=r["hostname"] or None))
    if entries:
        inventory_manager.upsert_devices(entries)
    return {"imported": [r["ip"] for r in todo if r["status"] == "new"],
            "updated": [r["ip"] for r in todo if r["status"] == "update"],
            "skipped": [r["row"] for r in result["rows"] if r["status"] == "skipped"],
            "failed": [{"row": r["row"], "ip": r["ip"] or "?", "error": r["reason"]}
                       for r in result["rows"] if r["status"] == "error"],
            "preview": public(result)}
