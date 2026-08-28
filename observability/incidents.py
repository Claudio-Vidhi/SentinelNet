# -*- coding: utf-8 -*-
"""Incident Engine: l'incidente come VISTA DERIVATA dalle evidenze.

Il correlatore produce evidenze (``observability/rules.py`` →
``observability/correlator.py``); qui le evidenze non ancora assegnate vengono
raggruppate e da esse si deduce la conclusione.

Raggruppamento (entità condivisa + gap temporale):
- ogni evidenza porta la propria ``entity_key`` (dichiarata dalla regola);
- un'evidenza entra in un incidente APERTO dello STESSO tenant con la stessa
  entità e ``last_event_ts`` non più vecchio di GAP_S; a parità vince il più
  vecchio (deterministico);
- altrimenti nasce un incidente nuovo;
- dopo QUIET_S senza evidenze l'incidente viene chiuso;
- MAI raggruppamento cross-tenant.

Ragionamento — usa i RUOLI, che è il motivo per cui esistono:
- la causa è la regola dell'evidenza con ruolo ``trigger``;
- le altre evidenze non competono per la causa, la rinforzano: ogni tipo di
  corroborazione presente aggiunge CONFIDENCE_STEP;
- ogni incremento è pubblicato in ``reasoning_json.sources_used``, così la
  confidenza è ricostruibile da chi legge.

Idempotenza: si lavora solo sulle evidenze con ``incident_id`` NULL.
"""

import json
import logging
import time
from typing import Optional

from core import db
from observability import metrics, rules

logger = logging.getLogger("sentinelnet.obs")

GAP_S = 900           # evidenza entro 15 min da last_event_ts → stesso incidente
QUIET_S = 1800        # 30 min senza evidenze → incidente chiuso
LOOKBACK_S = 3600
CONFIDENCE_STEP = 8
CONFIDENCE_MAX = 95

# Ordine di severità dei ruoli nel decidere QUALE trigger è la causa primaria
# quando ce n'è più d'uno: prima la severità più alta, poi il più antico.
# Si seleziona per ``created_ts`` (quando la regola ha concluso), NON per ``ts``
# (quando il fatto è successo). Sono due assi distinti, come ``ingested_ts`` e
# ``ts`` sugli eventi, e confonderli aveva un effetto preciso: le evidenze
# statistiche portano il timestamp dell'INIZIO dell'ora misurata, e l'ultima ora
# conclusa è sempre fra i 60 e i 120 minuti prima di adesso. Con la finestra su
# ``ts`` non rientravano MAI, quindi BASELINE_SPIKE_001, NEW_TALKER_001 e
# TOP_TALKER_001 producevano evidenze che nessun incidente raccoglieva.
_UNASSIGNED_SQL = """
SELECT id, ts, tenant, entity_key, role, rule_id, severity
FROM evidence
WHERE incident_id IS NULL AND status = 'active' AND created_ts >= ?
ORDER BY ts ASC, id ASC
"""

# Incidenti in cui qualcosa è stato ritrattato di recente: vanno ri-ragionati
# anche se non hanno ricevuto evidenze nuove, altrimenti resterebbero con una
# conclusione che si regge su un fatto ormai invalidato.
_RETRACTED_SQL = """
SELECT DISTINCT incident_id FROM evidence
WHERE status = 'retracted' AND incident_id IS NOT NULL AND retracted_at >= ?
"""


def _entity_label(entity_key: str) -> str:
    return entity_key.split(":", 1)[1] if ":" in entity_key else entity_key


def group_once(now: Optional[int] = None) -> int:
    """Assegna le evidenze libere a un incidente. Ritorna quante ne ha assegnate."""
    now = now or int(time.time())
    conn = db.get_observability_connection()
    try:
        rows = conn.execute(_UNASSIGNED_SQL, (now - LOOKBACK_S,)).fetchall()
        linked = 0
        touched = set()
        for row in rows:
            if not row["entity_key"]:
                continue  # senza entità non c'è nulla da raggruppare
            ts = row["ts"]
            severity = row["severity"] if row["severity"] is not None else 4

            match = conn.execute(
                """SELECT id FROM incidents
                   WHERE tenant = ? AND closed_ts IS NULL
                     AND entity_key = ? AND last_event_ts >= ?
                   ORDER BY opened_ts ASC, id ASC LIMIT 1""",
                (row["tenant"], row["entity_key"], ts - GAP_S)).fetchone()

            if match is None:
                cur = conn.execute(
                    """INSERT INTO incidents
                           (tenant, entity_key, opened_ts, last_event_ts, title,
                            severity, event_count, status)
                       VALUES (?, ?, ?, ?, ?, ?, 0, 'new')""",
                    (row["tenant"], row["entity_key"], ts, ts,
                     _entity_label(row["entity_key"]), severity))
                assert cur.lastrowid is not None   # garantito da sqlite3 dopo INSERT
                incident_id = cur.lastrowid
            else:
                incident_id = match["id"]

            conn.execute("UPDATE evidence SET incident_id = ? WHERE id = ?",
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

        for row in conn.execute(_RETRACTED_SQL, (now - LOOKBACK_S,)).fetchall():
            touched.add(row["incident_id"])

        conn.commit()
        for incident_id in sorted(touched):
            _reason(conn, incident_id)
        conn.commit()
        metrics.set_gauge("last_incident_grouping_ts", now)
        metrics.inc("evidence_linked", linked)
        return linked
    finally:
        conn.close()


def close_stale(now: Optional[int] = None) -> int:
    """Chiude gli incidenti senza nuove evidenze da più di QUIET_S."""
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

def _corroborating_sources(conn, incident, evidence: list) -> list:
    """Cosa rinforza la conclusione. Una voce = un bonus di confidenza."""
    roles = {e["role"] for e in evidence}
    rule_ids = {e["rule_id"] for e in evidence}
    sources = []
    if "supporting" in roles:
        sources.append("evidenza_di_supporto")
    if "symptom" in roles:
        sources.append("sintomo_osservato")
    if "consequence" in roles:
        sources.append("conseguenza_osservata")
    if len(rule_ids) > 1:
        sources.append("piu_regole_concordi")
    if any(e["switch_port"] for e in evidence):
        sources.append("posizione_fisica")

    ips = sorted({ip for e in evidence
                  for ip in (e["src_ip"], e["dst_ip"]) if ip})
    if ips:
        placeholders = ",".join("?" * len(ips))
        api_row = conn.execute(
            f"""SELECT 1 FROM events
                WHERE tenant = ? AND event_type IN ('device.state', 'interface.state')
                  AND device_ip IN ({placeholders})
                  AND ts BETWEEN ? AND ? LIMIT 1""",
            (incident["tenant"], *ips,
             incident["opened_ts"] - 300, incident["last_event_ts"] + 300)).fetchone()
        if api_row is not None:
            sources.append("stato_apparato")
        try:
            from collectors import mac_history
            if mac_history.vlans_for_ips({ip: incident["tenant"] for ip in ips}):
                sources.append("binding_arp_vlan")
        except Exception as e:
            logger.debug("VLAN non risolvibili per l'incidente %s: %s",
                         incident["id"], e)
    return sources


def _primary_trigger(evidence: list):
    """Il trigger che vale come causa: il più severo, a parità il più antico.
    Nessun trigger (solo sintomi o supporti) → nessuna causa dichiarata."""
    triggers = [e for e in evidence if e["role"] == "trigger"]
    if not triggers:
        return None
    return sorted(triggers,
                  key=lambda e: (e["severity"] if e["severity"] is not None else 9,
                                 e["ts"], e["id"]))[0]


def _reason(conn, incident_id: int) -> None:
    """Ricalcola causa, confidenza e percorso di ragionamento di un incidente."""
    incident = conn.execute(
        "SELECT id, tenant, entity_key, opened_ts, last_event_ts FROM incidents "
        "WHERE id = ?", (incident_id,)).fetchone()
    if incident is None:
        return
    # Le evidenze ritrattate restano nel database e nella timeline, ma NON
    # partecipano più alla conclusione: è tutta la differenza fra "cambiare
    # idea in silenzio" e "poter spiegare perché si è cambiata idea".
    evidence = conn.execute(
        """SELECT id, ts, role, rule_id, rule_version, params_json, severity,
                  src_ip, dst_ip, switch_port, summary
           FROM evidence WHERE incident_id = ? AND status = 'active'
           ORDER BY ts ASC, id ASC""",
        (incident_id,)).fetchall()
    retracted = conn.execute(
        "SELECT COUNT(*) AS n FROM evidence "
        "WHERE incident_id = ? AND status = 'retracted'",
        (incident_id,)).fetchone()["n"]
    if not evidence:
        if retracted:
            _record_conclusion(conn, incident_id, "tutte_le_evidenze_ritrattate",
                               0, json.dumps({"cause": "tutte_le_evidenze_ritrattate",
                                              "retracted_count": retracted},
                                             ensure_ascii=False))
        return

    trigger = _primary_trigger(evidence)
    if trigger is None:
        # Solo sintomi o corroborazioni: si registra ciò che si vede, senza
        # inventare un innesco che nessuna regola ha dichiarato.
        cause, base, rule_version, params = "causa_non_determinata", 25, "-", {}
    else:
        cause = trigger["rule_id"]
        rule_version = trigger["rule_version"]
        params = json.loads(trigger["params_json"] or "{}")
        base = rules.base_confidence(cause)

    sources = _corroborating_sources(conn, incident, evidence)
    confidence = min(base + CONFIDENCE_STEP * len(sources), CONFIDENCE_MAX)

    by_role: dict = {}
    for e in evidence:
        by_role.setdefault(e["role"], []).append(e["id"])

    reasoning = json.dumps({
        "cause": cause,
        "rule_id": cause,
        "rule_version": rule_version,
        "rule_params": params,
        "base_confidence": base,
        "confidence_step": CONFIDENCE_STEP,
        "rules_fired": sorted({e["rule_id"] for e in evidence}),
        "sources_used": sources,
        "evidence_by_role": by_role,
        "evidence_refs": [e["id"] for e in evidence],
        "retracted_count": retracted,
    }, ensure_ascii=False)

    title_source = trigger["summary"] if trigger is not None else evidence[0]["summary"]
    title = (title_source or _entity_label(incident["entity_key"]))[:160]

    conn.execute(
        "UPDATE incidents SET cause_kind = ?, confidence = ?, "
        "reasoning_json = ?, title = ? WHERE id = ?",
        (cause, confidence, reasoning, title, incident_id))
    _record_conclusion(conn, incident_id, cause, confidence, reasoning)


def _record_conclusion(conn, incident_id: int, cause, confidence,
                       reasoning: str) -> None:
    """Archivia la conclusione precedente e registra quella nuova, ma SOLO se
    è davvero cambiata: un ricalcolo che conferma non deve gonfiare lo storico.

    Il confronto è sull'INTERO ragionamento, non sulla sola coppia
    causa+confidenza: una ritrattazione può togliere una regola dal percorso
    lasciando causa e punteggio invariati, e quella resta una conclusione
    diversa da spiegare. ``reasoning_json`` è deterministico a parità di
    evidenze, quindi il confronto per stringa è sufficiente."""
    current = conn.execute(
        "SELECT id, reasoning_json FROM incident_conclusions "
        "WHERE incident_id = ? AND superseded_ts IS NULL "
        "ORDER BY concluded_ts DESC, id DESC LIMIT 1",
        (incident_id,)).fetchone()
    if current is not None:
        if current["reasoning_json"] == reasoning:
            return
        conn.execute(
            "UPDATE incident_conclusions SET superseded_ts = ? WHERE id = ?",
            (int(time.time()), current["id"]))
    conn.execute(
        """INSERT INTO incident_conclusions
               (incident_id, concluded_ts, cause_kind, confidence, reasoning_json)
           VALUES (?, ?, ?, ?, ?)""",
        (incident_id, int(time.time()), cause, confidence, reasoning))


def reason(incident_id: int) -> None:
    """Ricalcolo del ragionamento fuori dal ciclo (test/uso manuale)."""
    conn = db.get_observability_connection()
    try:
        _reason(conn, incident_id)
        conn.commit()
    finally:
        conn.close()
