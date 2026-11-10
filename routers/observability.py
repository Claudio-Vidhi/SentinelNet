# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Router observability: endpoint dati scoped multi-tenant (/syslog, /events,
/interfaces) e diagnostica operativa della pipeline (health, fase 3.8).

REGOLA DI SCOPE (CONTRIBUTING.md §4): ogni query filtra
``WHERE tenant IN (…placeholders…)`` con parametri bound — mai interpolazione
di stringhe, mai un gruppo scalare. Scope None (admin o utente non limitato)
= nessun filtro tenant."""

import asyncio
import ipaddress
import json
import os
import re
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from routers.deps import require_tab

from core import db
from core import data_config
from core.app_settings import get_app_settings, save_app_settings
from observability import metrics, suppression
from routers.deps import (get_current_user, require_unscoped_admin, require_operator,
                          user_group_scope)
from security.security_manager import log_audit

router = APIRouter(tags=["Observability"])

# Popolato dal lifespan con lo stato dei listener attivi.
listener_status: dict = {}

_WINDOW_RE = re.compile(r"^(\d{1,4})([mhd])$")
_WINDOW_UNIT_S = {"m": 60, "h": 3600, "d": 86400}
MAX_WINDOW_S = 7 * 86400
MAX_LIMIT = 500


def _parse_window(window: str) -> int:
    """'15m' | '24h' | '7d' → secondi, validato e con tetto massimo."""
    m = _WINDOW_RE.match((window or "").strip())
    if not m:
        raise HTTPException(status_code=400,
                            detail="Invalid window: use e.g. 15m, 24h, 7d.")
    seconds = int(m.group(1)) * _WINDOW_UNIT_S[m.group(2)]
    if seconds <= 0 or seconds > MAX_WINDOW_S:
        raise HTTPException(status_code=400,
                            detail="Window out of bounds (max 7d).")
    return seconds


def _tenant_filter(current_user):
    """Ritorna (clausola_sql, params) per lo scope multi-gruppo dell'utente.
    Scope None = nessuna restrizione (admin / utente non limitato)."""
    scope = user_group_scope(current_user)
    if scope is None:
        return "", ()
    groups = sorted(scope)
    placeholders = ",".join("?" * len(groups))
    return f" AND tenant IN ({placeholders})", tuple(groups)


@router.get("/api/observability/syslog", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_syslog(
    window: str = Query("15m"),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    current_user = Depends(get_current_user),
):
    """Ultimi eventi syslog normalizzati sulla finestra, scoped per tenant."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT ts, tenant, device_ip, severity, action, message, exporter_ip
            FROM syslog_events
            WHERE ts >= ?{clause}
            ORDER BY ts DESC
            LIMIT ?""",
        (cutoff, *params, limit))
    return {"window": window, "events": [dict(r) for r in rows]}


# Superficie pubblica deliberata: nessun chiamante in-tree (la UI legge le
# tabelle specifiche), esiste per i consumatori esterni CLI/MCP/automazione.
@router.get("/api/observability/events", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_events(
    window: str = Query("15m"),
    event_type: str = Query("all"),
    entity_id: str = Query(""),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    page: int = Query(0, ge=0),
    current_user = Depends(get_current_user),
):
    """Feed del modello eventi unificato: la stessa forma per syslog e
    snapshot REST/SNMP. È il livello che leggono le viste derivate, ed
    è esposto perché ogni consumatore (CLI, AI, automazione) possa partire da
    qui invece che dalle tabelle grezze di ogni sorgente."""
    import time as _time
    seconds = _parse_window(window)
    cutoff = int(_time.time()) - seconds
    clause, params = _tenant_filter(current_user)
    type_clause = "" if event_type == "all" else " AND event_type = ?"
    type_params = () if event_type == "all" else (event_type,)
    entity_clause = " AND entity_id = ?" if entity_id else ""
    entity_params = (entity_id,) if entity_id else ()
    rows = await db.read(
        f"""SELECT id, ts, tenant, source, source_id, event_type, entity_type,
                   entity_id, severity, device_ip, interface, src_ip, dst_ip,
                   dst_port, protocol, metrics_json, attrs_json
            FROM events
            WHERE ts >= ?{clause}{type_clause}{entity_clause}
            ORDER BY ts DESC
            LIMIT ? OFFSET ?""",
        (cutoff, *params, *type_params, *entity_params, limit, page * limit))
    # Classificazione DERIVATA in lettura, mai salvata dentro l'evento: quando
    # la Endpoint KB impara un ruolo nuovo, migliora anche il passato.
    from observability import endpoints
    events = []
    for r in rows:
        row = dict(r)
        row["src_info"] = endpoints.classify(row.get("src_ip"))
        row["dst_info"] = endpoints.classify(row.get("dst_ip"))
        row["direction"] = endpoints.traffic_direction(row.get("src_ip"),
                                                       row.get("dst_ip"))
        events.append(row)
    return {"window": window, "event_type": event_type, "page": page,
            "events": events}


# --- Interfaces tab: last state per port and what the operator expects ------
# Moved here from the removed /api/incidents router (0.65.0).

INSTABILITY_WINDOW_S = 86400
# Link transitions in INSTABILITY_WINDOW_S that make a port "flapping" (4 = two
# full down/up cycles). It was the IFACE_FLAPPING_001 default of the removed
# incidents engine; a saved correlation_rules override is ignored.
MIN_FLAPS = 4
LINK_UP = frozenset({"up", "1", "true"})
LINK_DOWN = frozenset({"down", "0", "false", "lowerlayerdown", "notpresent"})


def _parse_json(raw):
    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


def _iface_state(item: dict, min_flaps: int) -> str:
    """The one classifier. It used to exist twice -- here and again in
    interfaces.js -- with two different vocabularies, so a change to one left
    the KPI cards disagreeing with the table under them.

    Order matters: a declared expectation outranks a fault, because that is
    what declaring it is for.

    An unrecognised or missing link value is NOT up. Only "down"/"0"/"false"
    used to count as down and everything else fell through to up, which read a
    port whose transceiver had been pulled (notPresent) or whose lower layer
    had failed (lowerLayerDown) as operational -- on the one view whose job is
    saying what is broken.
    """
    if item.get("suppressed"):
        return "maint" if item.get("to_ts") is not None else "by_design"
    if (item.get("transitions") or 0) >= min_flaps:
        return "flapping"
    link = str(item.get("link") or "").strip().lower()
    if link in LINK_DOWN:
        return "outage"
    if link in LINK_UP:
        return "up"
    return "unknown"


@router.get("/api/observability/interfaces", dependencies=[Depends(require_tab("tab-interfaces"))])
async def list_interfaces(current_user = Depends(get_current_user)):
    """Interfacce: ultimo stato, instabilità recente e la soppressione che le
    copre.

    Serve a due cose opposte. Togliere rumore prima che diventi tale (Loopback,
    Null e VLAN dismesse sono giù per progetto), e MOSTRARE l'instabilità su
    un giorno intero, anche quella di una porta che oscilla piano."""
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT tenant, device_ip, interface, attrs_json, ts FROM events
            WHERE event_type = 'interface.state'{clause}
              AND id IN (SELECT MAX(id) FROM events
                         WHERE event_type = 'interface.state'
                         GROUP BY tenant, entity_id)
            ORDER BY device_ip, interface LIMIT ?""",
        (*params, MAX_LIMIT))
    now = int(time.time())
    flaps = await _link_transitions(current_user, now - INSTABILITY_WINDOW_S)
    # Events only know the IP: the name lives in the inventory. Without it, with
    # several locations the table is a list of addresses to translate by heart.
    names = await asyncio.to_thread(_hostnames)
    out = []
    for r in rows:
        attrs = _parse_json(r["attrs_json"])
        rule = suppression.active(r["tenant"], f"ip:{r['device_ip']}",
                                  r["interface"], now)
        out.append({"tenant": r["tenant"], "device_ip": r["device_ip"],
                    "hostname": names.get(r["device_ip"], ""),
                    "interface": r["interface"], "ts": r["ts"],
                    "link": attrs.get("link"),
                    "admin_status": attrs.get("admin_status"),
                    "transitions": flaps.get((r["tenant"], r["device_ip"],
                                              r["interface"]), 0),
                    "suppressed": rule is not None,
                    "scope": ("device" if rule and not rule.get("interface")
                              else "interface") if rule else None,
                    "from_ts": (rule or {}).get("from_ts"),
                    "to_ts": (rule or {}).get("to_ts"),
                    "note": (rule or {}).get("note", "")})

    counts = {"total": len(out), "up": 0, "outage": 0, "flapping": 0,
              "maint": 0, "by_design": 0, "unknown": 0}
    for item in out:
        # Computed once, server side, and shipped with the row: the client
        # renders this value instead of deriving its own.
        item["state"] = _iface_state(item, MIN_FLAPS)
        counts[item["state"]] += 1

    return {"interfaces": out, "counts": counts, "window_s": INSTABILITY_WINDOW_S,
            "min_transitions": MIN_FLAPS,
            # The cap is not a detail the reader can afford to miss: past it,
            # every count above describes the first MAX_LIMIT ports and nothing
            # says so. 20 switches x 48 ports is already over.
            "truncated": len(out) >= MAX_LIMIT,
            "limit": MAX_LIMIT,
            "suppressions": _visible_suppressions(current_user)}


def _hostnames() -> dict:
    from services import inventory_manager
    return {d.get("IP"): (d.get("Hostname") or "")
            for d in inventory_manager.get_all_devices()}


async def _link_transitions(current_user, since: int) -> dict:
    """{(tenant, device_ip, interface): transizioni di link} nella finestra.

    Solo il campo ``link``: uno shutdown amministrativo è una decisione, non
    instabilità, e contarlo qui farebbe sembrare inaffidabile una porta che
    qualcuno ha semplicemente spento."""
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT tenant, device_ip, interface, COUNT(*) AS n FROM events
            WHERE event_type = 'interface.change' AND ts >= ?{clause}
              AND json_extract(attrs_json, '$.field') LIKE '%.link'
            GROUP BY tenant, device_ip, interface""",
        (since, *params))
    return {(r["tenant"], r["device_ip"], r["interface"]): r["n"] for r in rows}


def _visible_suppressions(current_user) -> list:
    """Every suppression in scope, expired ones too: the UI shows them greyed
    out instead of letting them vanish."""
    scope = user_group_scope(current_user)
    now = int(time.time())
    out = []
    for key, rule in suppression.all_rules().items():
        if not isinstance(rule, dict):
            continue
        if scope is not None and rule.get("tenant") not in scope:
            continue
        out.append({**rule, "key": key, "expired": suppression.expired(rule, now)})
    return sorted(out, key=lambda r: (r.get("entity_key") or "",
                                      r.get("interface") or ""))


def _mutate_suppression(saved: dict, payload: dict, current_user) -> dict:
    """Apply one declaration to ``saved`` in place, and report it.

    Takes the dict instead of loading and saving it: a bulk call used to
    read-modify-write the whole settings blob once PER ITEM, so fifty
    ports meant fifty rewrites and a concurrent operator's save was lost
    to whoever finished last."""
    tenant = str((payload or {}).get("tenant") or "")
    device_ip = str((payload or {}).get("device_ip") or "")
    interface = str((payload or {}).get("interface") or "") or None
    if not (tenant and device_ip):
        raise HTTPException(status_code=400,
                            detail="tenant e device_ip sono richiesti.")
    scope = user_group_scope(current_user)
    if scope is not None and tenant not in scope:
        raise HTTPException(status_code=404, detail="Interface not found.")

    frm = _optional_ts(payload, "from_ts")
    to = _optional_ts(payload, "to_ts")
    if frm is not None and to is not None and to <= frm:
        raise HTTPException(status_code=400,
                            detail="La fine della finestra precede l'inizio.")

    entity_key = f"ip:{device_ip}"
    key = suppression.key(tenant, entity_key, interface)
    if (payload or {}).get("suppressed"):
        saved[key] = {"tenant": tenant, "entity_key": entity_key,
                      "device_ip": device_ip, "interface": interface,
                      "from_ts": frm, "to_ts": to,
                      "note": str((payload or {}).get("note") or "")[:200],
                      "by": current_user.get("sub"),
                      "created_ts": int(time.time())}
        window = "sempre" if to is None else f"fino a {to}"
        action = f"soppressa ({window})"
    else:
        saved.pop(key, None)
        action = "riportata sotto osservazione"
    log_audit(f"{device_ip}:{interface or 'tutto l apparato'} ({tenant}) "
              f"{action} da '{current_user.get('sub')}'.")
    return {"status": "success", "key": key, "suppressed": key in saved}


@router.post("/api/observability/interfaces/expected", dependencies=[Depends(require_tab("tab-interfaces"))])
async def set_suppression(payload: dict,
                          current_user = Depends(require_operator)):
    """Dichiara che qualcosa è atteso, con o senza scadenza.

    Nessuna finestra = "è così per progetto". Con ``to_ts`` = manutenzione
    pianificata. Sono lo stesso modello: 'per sempre' è il caso senza scadenza,
    non un caso speciale.

    Deletes and hides nothing: the event stays in ``events``. It only changes
    how the Interfaces tab classifies the port."""
    items = (payload or {}).get("items")
    batch = [i for i in items if isinstance(i, dict)] if isinstance(items, list) else None

    saved = dict(get_app_settings().get("suppressions") or {})
    if batch is None:
        result = _mutate_suppression(saved, payload, current_user)
        save_app_settings({"suppressions": saved})
        return result

    # One read, one write, whatever the size of the batch. A rejected item
    # raises before anything is saved, so the batch does not land half applied.
    results = [_mutate_suppression(saved, item, current_user) for item in batch]
    save_app_settings({"suppressions": saved})
    return {"status": "success", "count": len(results), "results": results}


def _optional_ts(payload: dict, name: str):
    """Estremo di finestra: assente o vuoto = aperto."""
    raw = (payload or {}).get(name)
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"'{name}' non valido.")


@router.get("/api/observability/config", dependencies=[Depends(require_tab("tab-settings"))])
def obs_get_config(current_user = Depends(require_unscoped_admin)):
    """Config effettiva dei listener (settings + eventuali override da env).
    Le modifiche via POST vengono applicate a caldo, senza riavvio."""
    cfg = data_config.obs_config()
    # The UI shows the platform default as placeholder/hint.
    cfg["syslog"]["default_port"] = data_config.obs_syslog_default_port()
    return cfg


@router.post("/api/observability/config", dependencies=[Depends(require_tab("tab-settings"))])
async def obs_set_config(payload: dict, current_user = Depends(require_unscoped_admin)):
    """Salva la sezione 'observability' in app_settings.json (§9.5) e applica
    subito la nuova config ai listener UDP e ai task di background (nessun
    riavvio del processo necessario).
    Chiavi ammesse: enabled, bind, syslog_{enabled,port},
    api_poll_s, snmp_poll_s, linux_poll_s."""
    allowed = {"enabled", "bind", "api_poll_s", "snmp_poll_s", "linux_poll_s",
               "syslog_enabled", "syslog_port"}
    # Flow collectors were removed: a tab still running the old cached JS
    # posts these keys. Drop them instead of failing the whole save.
    legacy = ("ipfix_", "sflow_", "netflow_")
    clean = {}
    ignored = []
    for k, v in (payload or {}).items():
        if k.startswith(legacy):
            ignored.append(k)
            continue
        if k not in allowed:
            raise HTTPException(status_code=400, detail=f"Invalid key: '{k}'.")
        if k.endswith("_port") or k in ("api_poll_s", "snmp_poll_s", "linux_poll_s"):
            if k.endswith("_port") and v in (None, "") \
                    and not (payload or {}).get(f"{k[:-5]}_enabled"):
                continue  # listener disabilitato senza porta: mantieni il valore salvato
            try:
                v = int(v)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"Invalid value for '{k}'.")
            if k.endswith("_port") and not (1 <= v <= 65535):
                raise HTTPException(status_code=400, detail=f"Invalid port for '{k}'.")
        elif k == "bind":
            # Stored and then fed to every listener: a non-address here broke
            # obs_config() on each later read (security review 2026-10-12, L3).
            try:
                v = str(ipaddress.ip_address(str(v).strip()))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid value for 'bind'.")
        clean[k] = v
    saved = {k: v for k, v in (get_app_settings().get("observability", {}) or {}).items()
             if not k.startswith(legacy)}
    saved.update(clean)
    save_app_settings({"observability": saved})
    effective = data_config.obs_config()
    from observability import listener_manager
    await listener_manager.apply_obs_config(effective)
    log_audit(f"Config observability aggiornata da '{current_user.get('sub')}': "
              f"{clean} (applicata a caldo, nessun riavvio)."
              + (f" Legacy flow keys ignored: {ignored}." if ignored else ""))
    return {"status": "success", "restart_required": False,
            "effective": effective, "listeners": listener_status,
            "ignored": ignored}


@router.get("/api/observability/api-context", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_api_context(
    device_ip: str = Query(...),
    current_user = Depends(get_current_user),
):
    """Ultimi snapshot REST (api_observations, §9.2) per un dispositivo,
    scoped per tenant: una riga per kind (la più recente)."""
    clause, params = _tenant_filter(current_user)
    rows = await db.read(
        f"""SELECT ts, tenant, device_ip, kind, summary_json
            FROM api_observations
            WHERE device_ip = ?{clause}
              AND id IN (SELECT MAX(id) FROM api_observations
                         WHERE device_ip = ?{clause} GROUP BY kind)
            ORDER BY kind""",
        (device_ip, *params, device_ip, *params))
    return {"device_ip": device_ip, "observations": [dict(r) for r in rows]}


@router.post("/api/observability/api-poll", dependencies=[Depends(require_tab("tab-flows"))])
async def obs_api_poll_now(current_user = Depends(require_operator)):
    """Polling REST one-shot ("Aggiorna ora"): esegue subito un giro del
    poller API su tutti i FortiGate con token configurato."""
    import asyncio as _asyncio
    from observability.ingesters import api_poller
    n = await _asyncio.to_thread(api_poller.poll_once)
    return {"status": "success", "snapshots": n}


@router.get("/api/observability/health", dependencies=[Depends(require_tab("tab-flows", "tab-settings"))])
def obs_health(current_user = Depends(require_unscoped_admin)):
    """Stato pipeline: listener attivi, metriche, dimensione DB, versione
    schema. Diagnostica operativa primaria dell'intero modulo (solo admin)."""
    db_path = db.get_db_path()
    try:
        db_size = os.path.getsize(db_path)
    except OSError:
        db_size = 0
    snap = metrics.snapshot()
    snap["counters"].update({f"db_{k}": v for k, v in db.metrics.items()})
    return {
        "enabled": data_config.obs_config()["enabled"],
        "listeners": listener_status,
        "metrics": snap,
        # WP7: writer loss is a STATE the operator reads, not just counters:
        # "degraded" is true on any drop or a dead writer since startup.
        "db_health": db.health_state(),
        "db_size_bytes": db_size,
        "schema_version": db.SCHEMA_VERSION,
    }


from pydantic import BaseModel

class PruneLogsSchema(BaseModel):
    days: int = 30


@router.post("/api/observability/prune-logs", dependencies=[Depends(require_tab("tab-settings"))])
async def obs_prune_logs(payload: PruneLogsSchema, current_user = Depends(require_unscoped_admin)):
    """Elimina i log di osservabilità più vecchi del limite in giorni."""
    cutoff = int(time.time()) - (payload.days * 86400)
    db.enqueue_write("DELETE FROM syslog_events WHERE ts < ?", (cutoff,))
    return {"status": "success", "days_retained": payload.days, "cutoff_timestamp": cutoff}
