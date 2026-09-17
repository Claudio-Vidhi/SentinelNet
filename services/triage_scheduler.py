# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Motore di scheduling periodico per Triage automatico apparati.

Consente agli utenti (in base al loro scope perimetrale di tenant e apparati)
di pianificare il triage a intervalli orari definiti.
Un loop asincrono esegue a intervalli di 60s i triage dovuti.
"""

import asyncio
import json
import logging
import threading
import time
from typing import Optional, List, Dict, Any

from core import db
from services import inventory_manager, site_manager
from security import user_manager
from security.security_manager import log_audit

logger = logging.getLogger("sentinelnet.triage_scheduler")

_scheduler_task: Optional[asyncio.Task] = None
_stop_event = asyncio.Event()

VALID_INTERVALS = (15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080)
MIN_INTERVAL_MINUTES = 5
DEFAULT_INTERVAL_MINUTES = 360


def _parse_row(r) -> dict:
    devs = []
    if r["devices_json"]:
        try:
            devs = json.loads(r["devices_json"])
        except (ValueError, TypeError):
            devs = []
    return {
        "id": r["id"],
        "name": r["name"],
        "enabled": bool(r["enabled"]),
        "tenant": r["tenant"],
        "devices": devs,
        "interval_minutes": r["interval_minutes"],
        "created_by": r["created_by"],
        "created_ts": r["created_ts"],
        "last_run_ts": r["last_run_ts"],
        "next_run_ts": r["next_run_ts"],
        "last_status": r["last_status"],
        "last_summary": r["last_summary"],
    }


def get_schedules(current_user: dict) -> List[dict]:
    """Recupera le pianificazioni visibili all'utente in base al proprio perimetro."""
    from security.user_manager import is_admin
    from routers.deps import user_group_scope

    scope = user_group_scope(current_user)
    is_adm = is_admin(current_user.get("role"))
    username = current_user.get("username") or current_user.get("sub", "")

    conn = db.get_observability_connection()
    try:
        rows = conn.execute("SELECT * FROM scheduled_triage ORDER BY id DESC").fetchall()
        schedules = [_parse_row(r) for r in rows]
    finally:
        conn.close()

    if is_adm or scope is None:
        return schedules

    # Per operatori con scope limitato: filtra solo pianificazioni con tenant nel proprio scope o create da sé
    return [
        s for s in schedules
        if s["created_by"] == username or s["tenant"] in scope
    ]


def get_schedule(schedule_id: int) -> Optional[dict]:
    """Recupera una singola pianificazione per ID."""
    conn = db.get_observability_connection()
    try:
        r = conn.execute("SELECT * FROM scheduled_triage WHERE id = ?", (schedule_id,)).fetchone()
        if not r:
            return None
        return _parse_row(r)
    finally:
        conn.close()


def create_schedule(data: dict, current_user: dict) -> dict:
    """Crea una nuova pianificazione validando il perimetro dell'utente."""
    from security.user_manager import is_admin
    from routers.deps import user_group_scope

    name = str(data.get("name", "")).strip()
    if not name:
        raise ValueError("Il nome della pianificazione è obbligatorio.")

    tenant = str(data.get("tenant", "")).strip()
    if not tenant:
        raise ValueError("Il tenant (sede) è obbligatorio.")

    scope = user_group_scope(current_user)
    if not is_admin(current_user.get("role")) and scope is not None:
        if tenant == "all" or tenant not in scope:
            raise PermissionError(f"Non hai i permessi per il tenant '{tenant}'.")

    # Verifica lista apparati se specificata
    devices_raw = data.get("devices")
    devices_list: Optional[List[str]] = None
    if devices_raw:
        if isinstance(devices_raw, list):
            devices_list = [str(ip).strip() for ip in devices_raw if str(ip).strip()]
        else:
            raise ValueError("Il campo 'devices' deve essere una lista di IP.")

        # Valida che gli apparati appartengano al tenant e allo scope
        all_devs = inventory_manager.get_all_devices()
        dev_by_ip = {d["IP"]: d for d in all_devs}
        for ip in devices_list:
            d = dev_by_ip.get(ip)
            if not d:
                raise ValueError(f"Dispositivo {ip} non presente in inventario.")
            d_group = d.get("Group", "")
            if tenant != "all" and d_group != tenant:
                raise ValueError(f"Dispositivo {ip} appartiene al gruppo '{d_group}', non '{tenant}'.")
            if not is_admin(current_user.get("role")) and scope is not None and d_group not in scope:
                raise PermissionError(f"Dispositivo {ip} fuori dallo scope consentito.")

    interval_min = int(data.get("interval_minutes") or DEFAULT_INTERVAL_MINUTES)
    if interval_min < MIN_INTERVAL_MINUTES:
        interval_min = MIN_INTERVAL_MINUTES

    enabled = 1 if data.get("enabled", True) else 0
    now = time.time()
    next_run = now if data.get("run_immediately") else now + (interval_min * 60)
    created_by = current_user.get("username") or current_user.get("sub", "")

    devices_json = json.dumps(devices_list) if devices_list is not None else None

    conn = db.get_observability_connection()
    try:
        cur = conn.execute("""
            INSERT INTO scheduled_triage
                (name, enabled, tenant, devices_json, interval_minutes,
                 created_by, created_ts, last_run_ts, next_run_ts, last_status, last_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 'idle', NULL)
        """, (
            name, enabled, tenant, devices_json, interval_min,
            created_by, now, next_run
        ))
        conn.commit()
        new_id = int(cur.lastrowid or 0)
    finally:
        conn.close()

    log_audit(f"Creata pianificazione triage #{new_id} '{name}' (tenant: {tenant}, ogni {interval_min}m) da '{created_by}'.")
    return get_schedule(new_id) or {}


def update_schedule(schedule_id: int, data: dict, current_user: dict) -> Optional[dict]:
    """Aggiorna una pianificazione esistente rispettando i permessi."""
    from security.user_manager import is_admin
    from routers.deps import user_group_scope

    sched = get_schedule(schedule_id)
    if not sched:
        return None

    username = current_user.get("username") or current_user.get("sub", "")
    is_adm = is_admin(current_user.get("role"))
    scope = user_group_scope(current_user)

    if not is_adm and sched["created_by"] != username:
        if scope is not None and sched["tenant"] not in scope:
            raise PermissionError("Permesso negato per modificare questa pianificazione.")

    name = str(data.get("name", sched["name"])).strip()
    tenant = str(data.get("tenant", sched["tenant"])).strip()

    if not is_adm and scope is not None:
        if tenant == "all" or tenant not in scope:
            raise PermissionError(f"Non hai i permessi per il tenant '{tenant}'.")

    devices_raw = data.get("devices")
    devices_list = sched["devices"]
    if "devices" in data:
        if devices_raw is None or devices_raw == []:
            devices_list = None
        elif isinstance(devices_raw, list):
            devices_list = [str(ip).strip() for ip in devices_raw if str(ip).strip()]
            all_devs = inventory_manager.get_all_devices()
            dev_by_ip = {d["IP"]: d for d in all_devs}
            for ip in devices_list:
                d = dev_by_ip.get(ip)
                if not d:
                    raise ValueError(f"Dispositivo {ip} non presente in inventario.")
                d_group = d.get("Group", "")
                if tenant != "all" and d_group != tenant:
                    raise ValueError(f"Dispositivo {ip} appartiene al gruppo '{d_group}', non '{tenant}'.")
                if not is_adm and scope is not None and d_group not in scope:
                    raise PermissionError(f"Dispositivo {ip} fuori dallo scope consentito.")

    raw_interval = data.get("interval_minutes")
    interval_min = int(raw_interval) if raw_interval is not None else int(sched["interval_minutes"])
    if interval_min < MIN_INTERVAL_MINUTES:
        interval_min = MIN_INTERVAL_MINUTES

    enabled = 1 if data.get("enabled", sched["enabled"]) else 0
    next_run = sched["next_run_ts"]
    if interval_min != sched["interval_minutes"]:
        # Ricalcola la prossima esecuzione
        last_run = sched["last_run_ts"] or time.time()
        next_run = last_run + (interval_min * 60)

    devices_json = json.dumps(devices_list) if devices_list is not None else None

    conn = db.get_observability_connection()
    try:
        conn.execute("""
            UPDATE scheduled_triage
            SET name = ?, enabled = ?, tenant = ?, devices_json = ?, interval_minutes = ?, next_run_ts = ?
            WHERE id = ?
        """, (name, enabled, tenant, devices_json, interval_min, next_run, schedule_id))
        conn.commit()
    finally:
        conn.close()

    log_audit(f"Aggiornata pianificazione triage #{schedule_id} '{name}' da '{username}'.")
    return get_schedule(schedule_id)


def delete_schedule(schedule_id: int, current_user: dict) -> bool:
    """Elimina una pianificazione se autorizzati."""
    from security.user_manager import is_admin
    from routers.deps import user_group_scope

    sched = get_schedule(schedule_id)
    if not sched:
        return False

    username = current_user.get("username") or current_user.get("sub", "")
    is_adm = is_admin(current_user.get("role"))
    scope = user_group_scope(current_user)

    if not is_adm and sched["created_by"] != username:
        if scope is not None and sched["tenant"] not in scope:
            raise PermissionError("Permesso negato per eliminare questa pianificazione.")

    conn = db.get_observability_connection()
    try:
        conn.execute("DELETE FROM scheduled_triage_log WHERE schedule_id = ?", (schedule_id,))
        conn.execute("DELETE FROM scheduled_triage WHERE id = ?", (schedule_id,))
        conn.commit()
    finally:
        conn.close()

    log_audit(f"Eliminata pianificazione triage #{schedule_id} da '{username}'.")
    return True


def get_schedule_history(schedule_id: int, limit: int = 50) -> List[dict]:
    """Recupera lo storico delle esecuzioni per una pianificazione."""
    conn = db.get_observability_connection()
    try:
        rows = conn.execute("""
            SELECT * FROM scheduled_triage_log
            WHERE schedule_id = ?
            ORDER BY ts DESC
            LIMIT ?
        """, (schedule_id, limit)).fetchall()
        return [
            {
                "id": r["id"],
                "schedule_id": r["schedule_id"],
                "ts": r["ts"],
                "tenant": r["tenant"],
                "device_count": r["device_count"],
                "success_count": r["success_count"],
                "error_count": r["error_count"],
                "status": r["status"],
                "summary": r["summary"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def _log_schedule_result(schedule_id: int, tenant: str, total: int, successes: int, errors: int, status: str, summary: str):
    """Scrive l'esito dell'esecuzione nello storico e aggiorna lo stato della pianificazione."""
    now = time.time()
    conn = db.get_observability_connection()
    try:
        conn.execute("""
            INSERT INTO scheduled_triage_log
                (schedule_id, ts, tenant, device_count, success_count, error_count, status, summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (schedule_id, now, tenant, total, successes, errors, status, summary))

        conn.execute("""
            UPDATE scheduled_triage
            SET last_run_ts = ?, last_status = ?, last_summary = ?
            WHERE id = ?
        """, (now, status, summary, schedule_id))
        conn.commit()
    except Exception as e:
        logger.warning("Impossibile registrare log triage programmato: %s", e)
    finally:
        conn.close()


def execute_schedule_job(schedule_id: int, requested_by: Optional[str] = None) -> Dict[str, Any]:
    """Avvia l'esecuzione del job associato alla pianificazione."""
    sched = get_schedule(schedule_id)
    if not sched:
        return {"status": "error", "message": "Pianificazione non trovata."}

    from routers import triage as triage_router

    # Controllo concorrenza con triage in corso
    with triage_router.triage_lock:
        if triage_router.triage_job["status"] == "running":
            return {"status": "deferred", "message": "Triage già in corso, esecuzione rimandata."}

    tenant = sched["tenant"]
    wanted_ips = set(sched["devices"]) if sched["devices"] else None

    # Controllo scope del creatore se non invocato esplicitamente
    creator_name = sched["created_by"]
    creator_user = user_manager.get_users().get(creator_name)
    creator_scope = None
    if creator_user:
        # Se utente disabilitato, non eseguire
        if not creator_user.get("active", True):
            _log_schedule_result(schedule_id, tenant, 0, 0, 0, "failed", f"Utente '{creator_name}' disabilitato.")
            return {"status": "error", "message": f"Utente '{creator_name}' disabilitato."}
        if creator_user.get("role") not in ("admin", "super_admin"):
            creator_scope = set(creator_user.get("groups") or [])

    all_devs = inventory_manager.get_all_devices()
    devices = all_devs
    if tenant != "all":
        devices = [d for d in devices if d.get("Group") == tenant]
    elif creator_scope is not None:
        devices = [d for d in devices if d.get("Group") in creator_scope]

    if wanted_ips is not None:
        devices = [d for d in devices if d["IP"] in wanted_ips]

    from services.tenant_telemetry import is_telemetry_enabled
    devices = [d for d in devices if is_telemetry_enabled(d.get("Group") or "Generale", "triage")]

    # Partiziona tra sedi con agente e sedi dirette
    direct_devices = []
    queued_count = 0
    for d in devices:
        if site_manager.is_agent_site(d.get("Site")):
            if not site_manager.has_pending_triage_job(d["Site"], d["IP"]):
                site_manager.enqueue_job(
                    d["Site"], d["IP"], "",
                    requested_by=requested_by or f"schedule:{creator_name}",
                    kind="triage"
                )
            queued_count += 1
        else:
            direct_devices.append(d)

    total_devs = len(devices)
    if total_devs == 0:
        summary = "Nessun apparato trovato per il tenant configurato."
        _log_schedule_result(schedule_id, tenant, 0, 0, 0, "success", summary)
        return {"status": "success", "message": summary, "queued": 0}

    now = time.time()
    next_run = now + (sched["interval_minutes"] * 60)
    # Aggiorna subito lo stato a running e imposta next_run_ts
    conn = db.get_observability_connection()
    try:
        conn.execute("""
            UPDATE scheduled_triage
            SET last_run_ts = ?, next_run_ts = ?, last_status = 'running'
            WHERE id = ?
        """, (now, next_run, schedule_id))
        conn.commit()
    finally:
        conn.close()

    def _on_triage_complete(job_snapshot: dict):
        results = job_snapshot.get("results") or []
        errors = 0
        successes = 0
        for r in results:
            res_dict = r.get("result") or {}
            if res_dict.get("status") == "error":
                errors += 1
            else:
                successes += 1

        final_status = "success"
        if errors > 0 and successes > 0:
            final_status = "partial_failure"
        elif errors > 0 and successes == 0:
            final_status = "failed"

        summary = f"{successes}/{len(results)} apparati diretti ok"
        if queued_count > 0:
            summary += f", {queued_count} accodati per sedi remote"
        if errors > 0:
            summary += f" ({errors} errori)"

        _log_schedule_result(schedule_id, tenant, total_devs, successes + queued_count, errors, final_status, summary)

    log_audit(f"Avviato triage schedulato #{schedule_id} '{sched['name']}' su {total_devs} apparati.")
    thread = threading.Thread(
        target=triage_router.run_triage_background,
        args=(direct_devices, _on_triage_complete),
        daemon=True
    )
    thread.start()

    return {
        "status": "running",
        "message": f"Triage avviato per {len(direct_devices)} apparati diretti ({queued_count} remoti).",
        "queued": queued_count,
        "total": total_devs,
    }


def _scheduler_tick():
    """Un tick del ciclo di scheduling: controlla se ci sono pianificazioni dovute."""
    now = time.time()
    conn = db.get_observability_connection()
    due_schedules = []
    try:
        rows = conn.execute("""
            SELECT id FROM scheduled_triage
            WHERE enabled = 1 AND next_run_ts <= ?
            ORDER BY next_run_ts ASC
        """, (now,)).fetchall()
        due_schedules = [r["id"] for r in rows]
    except Exception as e:
        logger.warning("Errore query scheduled_triage: %s", e)
    finally:
        conn.close()

    for sched_id in due_schedules:
        try:
            res = execute_schedule_job(sched_id)
            if res.get("status") == "deferred":
                # Triage in corso, rimandiamo al prossimo tick
                break
        except Exception as e:
            logger.error("Errore esecuzione triage schedulato #%s: %s", sched_id, e)


async def _triage_scheduler_loop():
    """Loop asincrono che verifica ogni 30s le pianificazioni dovute."""
    logger.info("Loop scheduler triage automatico avviato.")
    while not _stop_event.is_set():
        try:
            await asyncio.to_thread(_scheduler_tick)
        except Exception as e:
            logger.warning("Eccezione durante tick scheduler triage: %s", e)
        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=30.0)
        except asyncio.TimeoutError:
            pass


def start_triage_scheduler():
    """Avvia il task in background del triage scheduler."""
    global _scheduler_task
    _stop_event.clear()
    if _scheduler_task is None or _scheduler_task.done():
        try:
            loop = asyncio.get_running_loop()
            _scheduler_task = loop.create_task(_triage_scheduler_loop())
        except RuntimeError:
            pass


def stop_triage_scheduler():
    """Arresta il task del triage scheduler."""
    global _scheduler_task
    _stop_event.set()
    if _scheduler_task and not _scheduler_task.done():
        _scheduler_task.cancel()
        _scheduler_task = None
