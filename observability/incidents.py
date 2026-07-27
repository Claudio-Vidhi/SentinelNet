# -*- coding: utf-8 -*-
"""Motore incidenti: raggruppa ``correlated_events`` in ``incidents`` e ne
deduce la causa in modo DETERMINISTICO (causa + confidenza + percorso di
ragionamento).

Raggruppamento (entità condivisa + gap temporale):
- da ogni evento correlato si ricavano le chiavi entità ``ip:<src>``,
  ``ip:<dst>``, ``port:<switch:porta>``;
- un evento entra in un incidente APERTO dello STESSO tenant che condivide
  almeno una chiave entità e il cui ``last_event_ts`` non è più vecchio di
  GAP_S; a parità di candidati vince il più vecchio (deterministico);
- altrimenti nasce un incidente nuovo;
- dopo QUIET_S senza eventi l'incidente viene chiuso (``closed_ts``);
- MAI raggruppamento cross-tenant.

Idempotenza: gli eventi già associati sono esclusi con un anti-join su
``incident_events``, quindi rieseguire un ciclo non duplica nulla.

Ragionamento: tabella di regole valutata sull'insieme degli eventi
dell'incidente e sul loro ``evidence_json``. La confidenza parte dal punteggio
base della regola e cresce di CONFIDENCE_STEP per ogni fonte corroborante; ogni
incremento è registrato in ``reasoning_json.sources_used`` così il punteggio
resta ricostruibile dall'ingegnere.

Gira nel ciclo periodico del correlatore (nessun task aggiuntivo), su thread
dedicato con connessione propria.
"""

import json
import logging
import statistics
import time
from typing import Optional

from core import db
from observability import metrics

logger = logging.getLogger("sentinelnet.obs")

GAP_S = 900           # evento entro 15 min da last_event_ts → stesso incidente
QUIET_S = 1800        # 30 min senza eventi → incidente chiuso
LOOKBACK_S = 3600     # eventi correlati considerati per il raggruppamento
CONFIDENCE_STEP = 8   # bonus per fonte corroborante
CONFIDENCE_MAX = 95

_UNGROUPED_SQL = """
SELECT ce.id, ce.created_ts, ce.tenant, ce.kind, ce.src_ip, ce.dst_ip,
       ce.switch_port, ce.severity, ce.evidence_json
FROM correlated_events ce
LEFT JOIN incident_events ie ON ie.correlated_event_id = ce.id
WHERE ce.created_ts >= ? AND ie.incident_id IS NULL
ORDER BY ce.created_ts ASC, ce.id ASC
"""

_CAUSE_TITLES = {
    "scan_bloccato": "Scansione bloccata",
    "traffico_bloccato_ripetuto": "Traffico bloccato ripetuto",
    "trasferimento_anomalo": "Trasferimento anomalo",
    "evento_critico_isolato": "Evento critico isolato",
    "attivita_correlata": "Attività correlata",
}


def _event_ts(row) -> int:
    """Istante reale dell'evento: il ts del syslog se presente nell'evidenza,
    altrimenti il ts del ciclo di correlazione."""
    ev = _evidence(row)
    ts = ev.get("syslog_ts")
    return int(ts) if isinstance(ts, (int, float)) else int(row["created_ts"])


def _evidence(row) -> dict:
    try:
        data = json.loads(row["evidence_json"] or "{}")
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _entity_keys(row) -> list:
    """Chiavi entità candidate per un evento correlato."""
    keys = []
    for ip in (row["src_ip"], row["dst_ip"]):
        if ip:
            keys.append(f"ip:{ip}")
    if row["switch_port"]:
        keys.append(f"port:{row['switch_port']}")
    return keys


def _entity_label(entity_key: str) -> str:
    return entity_key.split(":", 1)[1] if ":" in entity_key else entity_key


# --- RAGGRUPPAMENTO ----------------------------------------------------------

def group_once(now: Optional[int] = None) -> int:
    """Un ciclo di raggruppamento. Ritorna il numero di eventi associati."""
    now = now or int(time.time())
    conn = db.get_observability_connection()
    try:
        rows = conn.execute(_UNGROUPED_SQL, (now - LOOKBACK_S,)).fetchall()
        linked = 0
        touched = set()
        for row in rows:
            keys = _entity_keys(row)
            if not keys:
                continue  # senza entità non c'è nulla da correlare
            ts = _event_ts(row)
            severity = row["severity"] if row["severity"] is not None else 4

            placeholders = ",".join("?" * len(keys))
            match = conn.execute(
                f"""SELECT id FROM incidents
                    WHERE tenant = ? AND closed_ts IS NULL
                      AND last_event_ts >= ? AND entity_key IN ({placeholders})
                    ORDER BY opened_ts ASC, id ASC LIMIT 1""",
                (row["tenant"], ts - GAP_S, *keys)).fetchone()

            if match is None:
                cur = conn.execute(
                    """INSERT INTO incidents
                           (tenant, entity_key, opened_ts, last_event_ts, title,
                            severity, event_count, status)
                       VALUES (?, ?, ?, ?, ?, ?, 0, 'new')""",
                    (row["tenant"], keys[0], ts, ts,
                     _entity_label(keys[0]), severity))
                assert cur.lastrowid is not None   # garantito da sqlite3 dopo INSERT
                incident_id = cur.lastrowid
            else:
                incident_id = match["id"]

            conn.execute(
                """INSERT OR IGNORE INTO incident_events
                       (incident_id, correlated_event_id) VALUES (?, ?)""",
                (incident_id, row["id"]))
            conn.execute(
                """UPDATE incidents
                      SET last_event_ts = MAX(last_event_ts, ?),
                          opened_ts = MIN(opened_ts, ?),
                          event_count = event_count + 1,
                          severity = MIN(COALESCE(severity, ?), ?)
                    WHERE id = ?""",
                (ts, ts, severity, severity, incident_id))
            touched.add(incident_id)
            linked += 1

        conn.commit()
        for incident_id in sorted(touched):
            _reason(conn, incident_id)
        conn.commit()
        metrics.set_gauge("last_incident_grouping_ts", now)
        metrics.inc("incident_events_linked", linked)
        return linked
    finally:
        conn.close()


def close_stale(now: Optional[int] = None) -> int:
    """Chiude gli incidenti senza nuovi eventi da più di QUIET_S."""
    now = now or int(time.time())
    conn = db.get_observability_connection()
    try:
        cur = conn.execute(
            "UPDATE incidents SET closed_ts = ? "
            "WHERE closed_ts IS NULL AND last_event_ts < ?",
            (now, now - QUIET_S))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


# --- RAGIONAMENTO DETERMINISTICO ---------------------------------------------

def _is_blocked(row) -> bool:
    return (row["kind"] or "").startswith("traffico_bloccato")


def _flow_bytes(row) -> Optional[int]:
    flow = _evidence(row).get("flow") or {}
    value = flow.get("bytes")
    return int(value) if isinstance(value, (int, float)) else None


def _rules_fired(events: list) -> list:
    """Regole soddisfatte, in ordine di priorità. La prima è la causa."""
    fired = []
    blocked = [e for e in events if _is_blocked(e)]
    srcs = {e["src_ip"] for e in blocked if e["src_ip"]}
    dsts = {e["dst_ip"] for e in blocked if e["dst_ip"]}
    ports = {(_evidence(e).get("flow") or {}).get("dst_port") for e in blocked}
    ports.discard(None)

    if len(blocked) >= 5 and len(srcs) == 1 and (len(dsts) >= 5 or len(ports) >= 5):
        fired.append(("scan_bloccato", 70))
    if len(blocked) >= 3 and len(srcs) <= 1 and len(dsts) <= 1:
        fired.append(("traffico_bloccato_ripetuto", 65))

    volumes = [b for b in (_flow_bytes(e) for e in events) if b is not None]
    if len(volumes) >= 3:
        peak = max(volumes)
        rest = sorted(volumes)[:-1]
        median = statistics.median(rest)
        if median > 0 and peak >= 10 * median:
            fired.append(("trasferimento_anomalo", 60))

    if len(events) == 1 and (events[0]["severity"] or 4) <= 3 and not volumes:
        fired.append(("evento_critico_isolato", 45))

    if not fired:
        fired.append(("attivita_correlata", 30))
    return fired


def _corroborating_sources(conn, incident, events: list) -> list:
    """Fonti che corroborano la conclusione (una voce = un bonus confidenza)."""
    sources = []
    if any(_flow_bytes(e) is not None for e in events):
        sources.append("flow_aggregates")
    if any(e["switch_port"] for e in events):
        sources.append("switch_port")

    ips = sorted({ip for e in events for ip in (e["src_ip"], e["dst_ip"]) if ip})
    if ips:
        placeholders = ",".join("?" * len(ips))
        api_row = conn.execute(
            f"""SELECT 1 FROM api_observations
                WHERE tenant = ? AND device_ip IN ({placeholders})
                  AND ts BETWEEN ? AND ? LIMIT 1""",
            (incident["tenant"], *ips,
             incident["opened_ts"] - 300, incident["last_event_ts"] + 300)).fetchone()
        if api_row is not None:
            sources.append("api_observations")
        try:
            from collectors import mac_history
            if mac_history.vlans_for_ips({ip: incident["tenant"] for ip in ips}):
                sources.append("arp_vlan")
        except Exception as e:
            logger.debug("VLAN non risolvibili per l'incidente %s: %s",
                         incident["id"], e)
    return sources


def _reason(conn, incident_id: int) -> None:
    """Ricalcola causa, confidenza e percorso di ragionamento di un incidente."""
    incident = conn.execute(
        "SELECT id, tenant, entity_key, opened_ts, last_event_ts FROM incidents "
        "WHERE id = ?", (incident_id,)).fetchone()
    if incident is None:
        return
    events = conn.execute(
        """SELECT ce.id, ce.kind, ce.src_ip, ce.dst_ip, ce.switch_port,
                  ce.severity, ce.evidence_json
           FROM incident_events ie
           JOIN correlated_events ce ON ce.id = ie.correlated_event_id
           WHERE ie.incident_id = ?
           ORDER BY ce.id ASC""", (incident_id,)).fetchall()
    if not events:
        return

    fired = _rules_fired(events)
    cause, base = fired[0]
    sources = _corroborating_sources(conn, incident, events)
    confidence = min(base + CONFIDENCE_STEP * len(sources), CONFIDENCE_MAX)

    reasoning = json.dumps({
        "cause": cause,
        "base_confidence": base,
        "confidence_step": CONFIDENCE_STEP,
        "rules_fired": [r for r, _ in fired],
        "sources_used": sources,
        "evidence_refs": [e["id"] for e in events],
    }, ensure_ascii=False)
    title = f"{_CAUSE_TITLES.get(cause, cause)} — {_entity_label(incident['entity_key'])}"

    conn.execute(
        "UPDATE incidents SET cause_kind = ?, confidence = ?, "
        "reasoning_json = ?, title = ? WHERE id = ?",
        (cause, confidence, reasoning, title, incident_id))


def reason(incident_id: int) -> None:
    """Ricalcolo del ragionamento fuori dal ciclo (test/uso manuale)."""
    conn = db.get_observability_connection()
    try:
        _reason(conn, incident_id)
        conn.commit()
    finally:
        conn.close()
