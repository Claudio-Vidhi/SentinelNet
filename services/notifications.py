# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Motore di notifica email: preferenze utente, regole admin, dispatcher asincrono.

Design: docs/superpowers/specs/2026-09-16-email-notifications-design.md.
Punto di ingresso unico: emit(kind, device_ip, severity, title, ctx, dedup_key).
"""

import asyncio
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from core import db
from services import mailer, inventory_manager
from security import user_manager

logger = logging.getLogger("sentinelnet.notifications")

KINDS = ("incident.opened", "siem.alert", "device.down", "device.up", "cve.new")
SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

DEFAULT_KINDS = list(KINDS)
DEFAULT_MIN_SEVERITY = "low"
DEFAULT_MODE = "immediate"
DEFAULT_DIGEST_MIN = 60
FLOOD_WINDOW_S = 1800  # 30 minuti
RETENTION_DAYS = 30
MAX_ATTEMPTS = 3

_loop_task: asyncio.Task | None = None
_stop_event = asyncio.Event()


def normalize_severity(sev) -> str:
    """Normalizza a una delle 4 severita': critical, high, medium, low."""
    if isinstance(sev, str):
        s = sev.lower().strip()
        if s in SEVERITY_RANK:
            return s
        try:
            val = float(s)
            if val >= 9.0:
                return "critical"
            if val >= 7.0:
                return "high"
            if val >= 4.0:
                return "medium"
            return "low"
        except ValueError:
            pass
    elif isinstance(sev, (int, float)):
        # Se intero 0-7 (syslog): 0-2 critical, 3 high, 4 medium, 5-7 low
        if isinstance(sev, int) and 0 <= sev <= 7:
            if sev <= 2:
                return "critical"
            if sev == 3:
                return "high"
            if sev == 4:
                return "medium"
            return "low"
        # CVSS score
        if sev >= 9.0:
            return "critical"
        if sev >= 7.0:
            return "high"
        if sev >= 4.0:
            return "medium"
        return "low"
    return "low"


def _is_in_quiet_hours(quiet_start: str | None, quiet_end: str | None, dt: datetime) -> tuple[bool, int]:
    """Ritorna (in_quiet, defer_until_ts).
    quiet_start/end sono formato 'HH:MM'. Se None o vuoti, False.
    """
    if not quiet_start or not quiet_end or ":" not in quiet_start or ":" not in quiet_end:
        return False, int(dt.timestamp())

    try:
        sh, sm = map(int, quiet_start.split(":")[:2])
        eh, em = map(int, quiet_end.split(":")[:2])
    except (ValueError, TypeError):
        return False, int(dt.timestamp())

    cur_min = dt.hour * 60 + dt.minute
    start_min = sh * 60 + sm
    end_min = eh * 60 + em

    in_quiet = False
    if start_min <= end_min:
        in_quiet = start_min <= cur_min < end_min
    else:  # a cavallo di mezzanotte
        in_quiet = cur_min >= start_min or cur_min < end_min

    if not in_quiet:
        return False, int(dt.timestamp())

    # Calcola l'istante di fine finestra silenziosa
    target_dt = dt.replace(hour=eh, minute=em, second=0, microsecond=0)
    if target_dt <= dt:
        target_dt += timedelta(days=1)
    return True, int(target_dt.timestamp())


def get_user_prefs(username: str) -> dict:
    """Restituisce le preferenze utente (con default se non presenti)."""
    conn = db.get_observability_connection()
    try:
        row = conn.execute("SELECT * FROM notify_prefs WHERE username = ?", (username,)).fetchone()
        if row:
            return {
                "username": row["username"],
                "enabled": bool(row["enabled"]),
                "kinds": json.loads(row["kinds_json"]),
                "min_severity": row["min_severity"],
                "groups": json.loads(row["groups_json"]),
                "mode": row["mode"],
                "digest_every_min": row["digest_every_min"],
                "quiet_start": row["quiet_start"],
                "quiet_end": row["quiet_end"],
                "quiet_bypass_critical": bool(row["quiet_bypass_critical"]),
            }
        return {
            "username": username,
            "enabled": True,
            "kinds": list(DEFAULT_KINDS),
            "min_severity": DEFAULT_MIN_SEVERITY,
            "groups": [],
            "mode": DEFAULT_MODE,
            "digest_every_min": DEFAULT_DIGEST_MIN,
            "quiet_start": None,
            "quiet_end": None,
            "quiet_bypass_critical": True,
        }
    finally:
        conn.close()


def save_user_prefs(username: str, prefs: dict) -> None:
    conn = db.get_observability_connection()
    try:
        conn.execute("""
            INSERT INTO notify_prefs
                (username, enabled, kinds_json, min_severity, groups_json, mode,
                 digest_every_min, quiet_start, quiet_end, quiet_bypass_critical)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(username) DO UPDATE SET
                enabled = excluded.enabled,
                kinds_json = excluded.kinds_json,
                min_severity = excluded.min_severity,
                groups_json = excluded.groups_json,
                mode = excluded.mode,
                digest_every_min = excluded.digest_every_min,
                quiet_start = excluded.quiet_start,
                quiet_end = excluded.quiet_end,
                quiet_bypass_critical = excluded.quiet_bypass_critical
        """, (
            username,
            1 if prefs.get("enabled", True) else 0,
            json.dumps(prefs.get("kinds", list(DEFAULT_KINDS))),
            prefs.get("min_severity", DEFAULT_MIN_SEVERITY),
            json.dumps(prefs.get("groups", [])),
            prefs.get("mode", DEFAULT_MODE),
            int(prefs.get("digest_every_min", DEFAULT_DIGEST_MIN)),
            prefs.get("quiet_start"),
            prefs.get("quiet_end"),
            1 if prefs.get("quiet_bypass_critical", True) else 0,
        ))
        conn.commit()
    finally:
        conn.close()


def list_rules() -> list[dict]:
    conn = db.get_observability_connection()
    try:
        rows = conn.execute("SELECT * FROM notify_rules ORDER BY id DESC").fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "enabled": bool(r["enabled"]),
                "recipients": json.loads(r["recipients_json"]),
                "kinds": json.loads(r["kinds_json"]),
                "min_severity": r["min_severity"],
                "groups": json.loads(r["groups_json"]),
                "mode": r["mode"],
                "digest_every_min": r["digest_every_min"],
                "quiet_start": r["quiet_start"],
                "quiet_end": r["quiet_end"],
                "quiet_bypass_critical": bool(r["quiet_bypass_critical"]),
                "created_by": r["created_by"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def get_rule(rule_id: int) -> dict | None:
    conn = db.get_observability_connection()
    try:
        r = conn.execute("SELECT * FROM notify_rules WHERE id = ?", (rule_id,)).fetchone()
        if not r:
            return None
        return {
            "id": r["id"],
            "name": r["name"],
            "enabled": bool(r["enabled"]),
            "recipients": json.loads(r["recipients_json"]),
            "kinds": json.loads(r["kinds_json"]),
            "min_severity": r["min_severity"],
            "groups": json.loads(r["groups_json"]),
            "mode": r["mode"],
            "digest_every_min": r["digest_every_min"],
            "quiet_start": r["quiet_start"],
            "quiet_end": r["quiet_end"],
            "quiet_bypass_critical": bool(r["quiet_bypass_critical"]),
            "created_by": r["created_by"],
        }
    finally:
        conn.close()


def create_rule(data: dict, created_by: str) -> int:
    conn = db.get_observability_connection()
    try:
        cur = conn.execute("""
            INSERT INTO notify_rules
                (name, enabled, recipients_json, kinds_json, min_severity, groups_json,
                 mode, digest_every_min, quiet_start, quiet_end, quiet_bypass_critical, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["name"],
            1 if data.get("enabled", True) else 0,
            json.dumps(data.get("recipients", [])),
            json.dumps(data.get("kinds", list(DEFAULT_KINDS))),
            data.get("min_severity", DEFAULT_MIN_SEVERITY),
            json.dumps(data.get("groups", [])),
            data.get("mode", DEFAULT_MODE),
            int(data.get("digest_every_min", DEFAULT_DIGEST_MIN)),
            data.get("quiet_start"),
            data.get("quiet_end"),
            1 if data.get("quiet_bypass_critical", True) else 0,
            created_by,
        ))
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def update_rule(rule_id: int, data: dict) -> bool:
    conn = db.get_observability_connection()
    try:
        cur = conn.execute("""
            UPDATE notify_rules SET
                name = ?,
                enabled = ?,
                recipients_json = ?,
                kinds_json = ?,
                min_severity = ?,
                groups_json = ?,
                mode = ?,
                digest_every_min = ?,
                quiet_start = ?,
                quiet_end = ?,
                quiet_bypass_critical = ?
            WHERE id = ?
        """, (
            data["name"],
            1 if data.get("enabled", True) else 0,
            json.dumps(data.get("recipients", [])),
            json.dumps(data.get("kinds", list(DEFAULT_KINDS))),
            data.get("min_severity", DEFAULT_MIN_SEVERITY),
            json.dumps(data.get("groups", [])),
            data.get("mode", DEFAULT_MODE),
            int(data.get("digest_every_min", DEFAULT_DIGEST_MIN)),
            data.get("quiet_start"),
            data.get("quiet_end"),
            1 if data.get("quiet_bypass_critical", True) else 0,
            rule_id,
        ))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_rule(rule_id: int) -> bool:
    conn = db.get_observability_connection()
    try:
        cur = conn.execute("DELETE FROM notify_rules WHERE id = ?", (rule_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_log(limit: int = 100, target_filter: str | None = None, status_filter: str | None = None) -> list[dict]:
    conn = db.get_observability_connection()
    try:
        sql = "SELECT * FROM notify_log WHERE 1=1"
        params: list = []
        if target_filter:
            sql += " AND target = ?"
            params.append(target_filter)
        if status_filter:
            sql += " AND status = ?"
            params.append(status_filter)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "id": r["id"],
                "ts": r["ts"],
                "target": r["target"],
                "recipient": r["recipient"],
                "kind": r["kind"],
                "title": r["title"],
                "status": r["status"],
                "error": r["error"],
                "item_count": r["item_count"],
            }
            for r in rows
        ]
    finally:
        conn.close()


def _is_suppressed(conn: sqlite3.Connection, target: str, dedup_key: str, now: int) -> bool:
    """Controlla se lo stesso target + dedup_key e' stato emesso negli ultimi 30 min."""
    cutoff = now - FLOOD_WINDOW_S
    # Controlla outbox
    row = conn.execute("""
        SELECT 1 FROM notify_outbox
        WHERE target = ? AND dedup_key = ? AND created_ts >= ?
        LIMIT 1
    """, (target, dedup_key, cutoff)).fetchone()
    if row:
        return True
    # Controlla log inviati o soppressi
    row = conn.execute("""
        SELECT 1 FROM notify_log
        WHERE target = ? AND error LIKE ? AND ts >= ?
        LIMIT 1
    """, (target, f"%{dedup_key}%", cutoff)).fetchone()
    return bool(row)


def emit(kind: str, device_ip: str | None, severity: str | int | float,
         title: str, ctx: dict | None = None, dedup_key: str | None = None) -> int:
    """Emette un evento verso le notifiche.

    Risolve perimetro, filtri, anti-flood e accoda in notify_outbox.
    Ritorna il numero di target accodati.
    """
    cfg = mailer.get_config()
    if not cfg.get("enabled"):
        return 0

    sev_norm = normalize_severity(severity)
    ctx = ctx or {}

    # Risolve tenant/gruppo da device_ip
    grp = None
    if device_ip:
        for d in inventory_manager.get_all_devices():
            if d.get("IP") == device_ip:
                grp = d.get("Group") or "Generale"
                break

    now = int(time.time())
    dt_now = datetime.now(timezone.utc)
    enqueued = 0

    conn = db.get_observability_connection()
    try:
        # 1. Target: Utenti con email configurata e notifiche attive
        users = user_manager.get_users()
        for uname, udata in users.items():
            if udata.get("disabled") or udata.get("pending_approval"):
                continue
            email = (udata.get("email") or "").strip()
            if not email or "@" not in email:
                continue

            prefs = get_user_prefs(uname)
            if not prefs.get("enabled"):
                continue

            # Scope: se l'utente e' limitato per sede, il device deve ricadere nello scope
            user_groups = user_manager.get_user_groups(uname)
            if user_groups:
                if grp is None or grp not in user_groups:
                    continue  # Fuori perimetro: nessuna email

            # Filtri: tipo evento
            if kind not in prefs.get("kinds", DEFAULT_KINDS):
                continue

            # Filtri: severita' minima
            user_min_sev = prefs.get("min_severity", DEFAULT_MIN_SEVERITY)
            if SEVERITY_RANK.get(sev_norm, 0) < SEVERITY_RANK.get(user_min_sev, 0):
                continue

            # Filtri: gruppi scelti dall'utente (se specificati)
            pref_groups = prefs.get("groups") or []
            if pref_groups and grp and grp not in pref_groups:
                continue

            target = f"user:{uname}"

            # Anti-flood 30 min
            if dedup_key and _is_suppressed(conn, target, dedup_key, now):
                conn.execute("""
                    INSERT INTO notify_log (ts, target, recipient, kind, title, status, error, item_count)
                    VALUES (?, ?, ?, ?, ?, 'suppressed', ?, 1)
                """, (now, target, email, kind, title, f"Anti-flood dedup_key: {dedup_key}"))
                continue

            # Calcolo due_ts
            due_ts = now
            mode = prefs.get("mode", "immediate")
            if mode == "digest":
                digest_s = int(prefs.get("digest_every_min", 60)) * 60
                due_ts = now + digest_s

            # Orari silenziosi
            in_quiet, defer_ts = _is_in_quiet_hours(prefs.get("quiet_start"), prefs.get("quiet_end"), dt_now)
            if in_quiet:
                if sev_norm == "critical" and prefs.get("quiet_bypass_critical", True):
                    pass  # Bypass critical
                else:
                    due_ts = max(due_ts, defer_ts)

            conn.execute("""
                INSERT INTO notify_outbox
                    (target, kind, severity, device_ip, grp, title, ctx_json, dedup_key, created_ts, due_ts, attempts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (target, kind, sev_norm, device_ip, grp, title, json.dumps(ctx), dedup_key, now, due_ts))
            enqueued += 1

        # 2. Target: Regole admin abilitate
        rules = list_rules()
        for rule in rules:
            if not rule.get("enabled"):
                continue
            recipients = rule.get("recipients") or []
            if not recipients:
                continue

            # Filtri: tipo evento
            if kind not in rule.get("kinds", DEFAULT_KINDS):
                continue

            # Filtri: severita' minima
            rule_min_sev = rule.get("min_severity", DEFAULT_MIN_SEVERITY)
            if SEVERITY_RANK.get(sev_norm, 0) < SEVERITY_RANK.get(rule_min_sev, 0):
                continue

            # Filtri: gruppi scelti dalla regola (se specificati)
            rule_groups = rule.get("groups") or []
            if rule_groups and grp and grp not in rule_groups:
                continue

            target = f"rule:{rule['id']}"

            # Anti-flood 30 min
            if dedup_key and _is_suppressed(conn, target, dedup_key, now):
                for rec in recipients:
                    conn.execute("""
                        INSERT INTO notify_log (ts, target, recipient, kind, title, status, error, item_count)
                        VALUES (?, ?, ?, ?, ?, 'suppressed', ?, 1)
                    """, (now, target, rec, kind, title, f"Anti-flood dedup_key: {dedup_key}"))
                continue

            # Calcolo due_ts
            due_ts = now
            mode = rule.get("mode", "immediate")
            if mode == "digest":
                digest_s = int(rule.get("digest_every_min", 60)) * 60
                due_ts = now + digest_s

            # Orari silenziosi
            in_quiet, defer_ts = _is_in_quiet_hours(rule.get("quiet_start"), rule.get("quiet_end"), dt_now)
            if in_quiet:
                if sev_norm == "critical" and rule.get("quiet_bypass_critical", True):
                    pass
                else:
                    due_ts = max(due_ts, defer_ts)

            conn.execute("""
                INSERT INTO notify_outbox
                    (target, kind, severity, device_ip, grp, title, ctx_json, dedup_key, created_ts, due_ts, attempts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (target, kind, sev_norm, device_ip, grp, title, json.dumps(ctx), dedup_key, now, due_ts))
            enqueued += 1

        conn.commit()
    finally:
        conn.close()

    return enqueued


def _format_single_mail(item: dict) -> tuple[str, str]:
    """Costruisce oggetto e corpo per una notifica singola."""
    subject = f"[SentinelNet] [{item['severity'].upper()}] {item['title']}"
    dev_line = f"Dispositivo: {item['device_ip']}\n" if item.get('device_ip') else ""
    grp_line = f"Gruppo: {item['grp']}\n" if item.get('grp') else ""
    ts_str = datetime.fromtimestamp(item['created_ts'], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    body = (
        f"SentinelNet - Notifica di Sicurezza ed Esercizio\n\n"
        f"Tipo: {item['kind']}\n"
        f"Severità: {item['severity'].upper()}\n"
        f"{dev_line}"
        f"{grp_line}"
        f"Data/Ora: {ts_str}\n\n"
        f"Dettagli:\n{item['title']}\n"
    )
    return subject, body


def _format_digest_mail(items: list[dict]) -> tuple[str, str]:
    """Costruisce oggetto e corpo per un digest di notifiche."""
    count = len(items)
    severities = [it["severity"] for it in items]
    crit_count = severities.count("critical")
    high_count = severities.count("high")

    extra = []
    if crit_count:
        extra.append(f"{crit_count} critiche")
    if high_count:
        extra.append(f"{high_count} alte")
    extra_str = f" ({', '.join(extra)})" if extra else ""

    subject = f"[SentinelNet] Riepilogo notifiche: {count} eventi{extra_str}"
    lines = [f"SentinelNet - Riepilogo periodico notifiche ({count} eventi):\n"]
    for i, it in enumerate(items, 1):
        ts_str = datetime.fromtimestamp(it['created_ts'], tz=timezone.utc).strftime("%H:%M:%S")
        dev = f" [{it['device_ip']}]" if it.get('device_ip') else ""
        lines.append(f"{i}. [{it['severity'].upper()}] {ts_str}{dev} - {it['title']}")

    lines.append("\nAccedi alla dashboard di SentinelNet per visualizzare lo stato completo.")
    return subject, "\n".join(lines)


async def notification_tick() -> None:
    """Un ciclo di invio notifiche."""
    cfg = mailer.get_config()
    if not cfg.get("enabled"):
        return

    now = int(time.time())
    conn = db.get_observability_connection()
    try:
        # 1. Avanzamento cursore incidents
        cur_row = conn.execute("SELECT last_id FROM notify_cursors WHERE source = 'incidents'").fetchone()
        last_inc_id = cur_row["last_id"] if cur_row else 0
        new_incidents = conn.execute("""
            SELECT id, tenant, title, severity FROM incidents
            WHERE id > ? ORDER BY id ASC LIMIT 50
        """, (last_inc_id,)).fetchall()
        for inc in new_incidents:
            emit(
                kind="incident.opened",
                device_ip=None,
                severity=inc["severity"] if inc["severity"] is not None else "high",
                title=f"Incidente aperto: {inc['title'] or 'Incidente rilevato'}",
                ctx={"incident_id": inc["id"], "tenant": inc["tenant"]},
                dedup_key=f"incident:{inc['id']}",
            )
            last_inc_id = inc["id"]
        conn.execute("""
            INSERT INTO notify_cursors (source, last_id) VALUES ('incidents', ?)
            ON CONFLICT(source) DO UPDATE SET last_id = excluded.last_id
        """, (last_inc_id,))

        # 2. Avanzamento cursore events (siem.alert)
        cur_row = conn.execute("SELECT last_id FROM notify_cursors WHERE source = 'events'").fetchone()
        last_evt_id = cur_row["last_id"] if cur_row else 0
        new_events = conn.execute("""
            SELECT id, tenant, entity_id, device_ip, severity, attrs_json FROM events
            WHERE event_type = 'log.security' AND id > ? ORDER BY id ASC LIMIT 50
        """, (last_evt_id,)).fetchall()
        for ev in new_events:
            msg = ""
            if ev["attrs_json"]:
                try:
                    msg = json.loads(ev["attrs_json"]).get("message", "")
                except Exception:
                    pass
            emit(
                kind="siem.alert",
                device_ip=ev["device_ip"] or ev["entity_id"],
                severity=ev["severity"] if ev["severity"] is not None else "high",
                title=f"Allerta SIEM: {msg[:100] if msg else 'Attività sospetta'}",
                ctx={"event_id": ev["id"], "tenant": ev["tenant"]},
                dedup_key=f"siem:{ev['id']}",
            )
            last_evt_id = ev["id"]
        conn.execute("""
            INSERT INTO notify_cursors (source, last_id) VALUES ('events', ?)
            ON CONFLICT(source) DO UPDATE SET last_id = excluded.last_id
        """, (last_evt_id,))
        conn.commit()

        # 3. Prelievo notifiche da outbox dovute
        outbox_rows = conn.execute("""
            SELECT * FROM notify_outbox
            WHERE due_ts <= ? AND attempts < ?
            ORDER BY id ASC
        """, (now, MAX_ATTEMPTS)).fetchall()

        if not outbox_rows:
            return

        # Raggruppa per target
        by_target: dict[str, list[dict]] = {}
        for r in outbox_rows:
            item = dict(r)
            by_target.setdefault(item["target"], []).append(item)

        for target, items in by_target.items():
            # Risolvi destinatari
            recipients = []
            if target.startswith("user:"):
                uname = target[5:]
                email = user_manager.get_email(uname)
                if email and "@" in email:
                    recipients = [email]
            elif target.startswith("rule:"):
                try:
                    rule_id = int(target[5:])
                    rule = get_rule(rule_id)
                    if rule and rule.get("enabled"):
                        recipients = rule.get("recipients") or []
                except ValueError:
                    pass

            if not recipients:
                # Nessun destinatario valido: elimina da outbox e registra log
                ids = [it["id"] for it in items]
                placeholders = ",".join("?" * len(ids))
                conn.execute(f"DELETE FROM notify_outbox WHERE id IN ({placeholders})", ids)
                conn.execute("""
                    INSERT INTO notify_log (ts, target, recipient, kind, title, status, error, item_count)
                    VALUES (?, ?, '', ?, ?, 'failed', 'Nessun destinatario configurato', ?)
                """, (now, target, items[0]["kind"], items[0]["title"], len(items)))
                conn.commit()
                continue

            # Formatta messaggio
            if len(items) == 1:
                subject, body = _format_single_mail(items[0])
                kind_for_log = items[0]["kind"]
                title_for_log = items[0]["title"]
            else:
                subject, body = _format_digest_mail(items)
                kind_for_log = "digest"
                title_for_log = f"{len(items)} notifiche raggruppate"

            # Invia per ogni destinatario
            all_succeeded = True
            last_err = ""
            for rec in recipients:
                try:
                    await asyncio.to_thread(mailer.send_email, rec, subject, body)
                    conn.execute("""
                        INSERT INTO notify_log (ts, target, recipient, kind, title, status, error, item_count)
                        VALUES (?, ?, ?, ?, ?, 'sent', NULL, ?)
                    """, (now, target, rec, kind_for_log, title_for_log, len(items)))
                except Exception as e:
                    all_succeeded = False
                    last_err = str(e)
                    conn.execute("""
                        INSERT INTO notify_log (ts, target, recipient, kind, title, status, error, item_count)
                        VALUES (?, ?, ?, ?, ?, 'failed', ?, ?)
                    """, (now, target, rec, kind_for_log, title_for_log, last_err, len(items)))

            ids = [it["id"] for it in items]
            placeholders = ",".join("?" * len(ids))
            if all_succeeded:
                conn.execute(f"DELETE FROM notify_outbox WHERE id IN ({placeholders})", ids)
            else:
                # Incrementa attempts, ritenta al prossimo tick fino a MAX_ATTEMPTS
                for it in items:
                    att = it["attempts"] + 1
                    if att >= MAX_ATTEMPTS:
                        conn.execute("DELETE FROM notify_outbox WHERE id = ?", (it["id"],))
                    else:
                        conn.execute("""
                            UPDATE notify_outbox SET attempts = ?, due_ts = ? WHERE id = ?
                        """, (att, now + 60, it["id"]))

            conn.commit()

        # 4. Retention cleanup 30 giorni
        cutoff_retention = now - (RETENTION_DAYS * 86400)
        conn.execute("DELETE FROM notify_log WHERE ts < ?", (cutoff_retention,))
        conn.commit()

    except Exception as e:
        logger.error("Errore durante notification_tick: %s", e, exc_info=True)
    finally:
        conn.close()


async def notification_loop() -> None:
    """Task asincrono principale con tick a 60s."""
    logger.info("Notification loop avviato.")
    while not _stop_event.is_set():
        try:
            await notification_tick()
        except Exception as e:
            logger.error("Eccezione non gestita nel ciclo notifiche: %s", e)
        try:
            # Attesa di 60s con possibilità di wake immediato su shutdown
            await asyncio.wait_for(_stop_event.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            pass


def start_notification_loop() -> None:
    global _loop_task
    _stop_event.clear()
    if _loop_task is None or _loop_task.done():
        _loop_task = asyncio.create_task(notification_loop())


def stop_notification_loop() -> None:
    global _loop_task
    _stop_event.set()
    if _loop_task and not _loop_task.done():
        _loop_task.cancel()
    _loop_task = None
