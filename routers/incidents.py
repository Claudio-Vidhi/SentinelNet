# -*- coding: utf-8 -*-
"""Router incidenti: lista, dettaglio con timeline multi-fonte, transizioni di
stato e narrativa AI opzionale.

REGOLA DI SCOPE (CONTRIBUTING.md §4): ogni query filtra per tenant con
parametri bound; fuori scope e inesistente rispondono lo STESSO 404, per non
confermare l'esistenza di un incidente di un altro tenant.

La conclusione (causa + confidenza + percorso di ragionamento) è SEMPRE quella
deterministica prodotta da ``observability/incidents.py``. La narrativa AI di
``/explain`` è un di più: viene salvata in colonne separate e marcata
``ai_assisted``, non sostituisce mai la conclusione.
"""

import asyncio
import json
import time

from fastapi import APIRouter, Depends, HTTPException, Query

from core import db
from observability import timeline
from routers.deps import (get_current_user, require_admin, require_operator,
                          user_group_scope)
from routers.observability import MAX_LIMIT, _parse_window, _tenant_filter
from security.security_manager import log_audit

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

_ALLOWED_TRANSITIONS = {("new", "ack"), ("new", "resolved"), ("ack", "resolved")}

MAX_NARRATIVE_ENTRIES = 40


def _parse_json(raw):
    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


@router.get("/rules")
def list_rules(current_user = Depends(get_current_user)):
    """Catalogo delle regole di correlazione: il motore descrive se stesso.

    La UI ci costruisce il pannello soglie, l'assistente AI sa quali regole
    esistono e la documentazione deriva dal codice — una sola fonte di verità.
    Nessun dato di tenant qui dentro, solo la definizione del motore."""
    from observability import rules
    return {"rules": rules.catalog()}


@router.post("/rules/{rule_id}/parameters")
def set_rule_parameters(rule_id: str, payload: dict,
                        current_user = Depends(require_admin)):
    """Ritocca le soglie di UNA regola. La logica resta nel codice: qui si
    accettano solo i parametri dichiarati dal catalogo, solo numerici e solo
    dentro l'intervallo min/max — la UI non può iniettare nulla nel motore."""
    from core.app_settings import get_app_settings, save_app_settings
    from observability import rules

    if rule_id not in rules.RULES:
        raise HTTPException(status_code=404, detail="Rule not found.")
    specs = {p["name"]: p for p in rules.parameter_specs(rule_id)}

    accepted = {}
    for name, value in (payload or {}).items():
        spec = specs.get(name)
        if spec is None:
            raise HTTPException(status_code=400,
                                detail=f"Parametro sconosciuto: '{name}'.")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise HTTPException(status_code=400,
                                detail=f"'{name}' deve essere numerico.")
        if not (spec["min"] <= value <= spec["max"]):
            raise HTTPException(
                status_code=400,
                detail=f"'{name}' fuori intervallo "
                       f"({spec['min']}–{spec['max']}).")
        accepted[name] = type(spec["default"])(value)

    saved = dict(get_app_settings().get("correlation_rules") or {})
    saved[rule_id] = {**(saved.get(rule_id) or {}), **accepted}
    save_app_settings({"correlation_rules": saved})
    log_audit(f"Soglie della regola {rule_id} aggiornate da "
              f"'{current_user.get('sub')}': {accepted}.")
    return {"status": "success", "rule_id": rule_id,
            "effective": rules.params_for(rule_id)}


@router.get("")
async def list_incidents(
    status: str = Query("new", pattern="^(new|ack|resolved|all)$"),
    window: str = Query("24h"),
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    page: int = Query(0, ge=0),
    current_user = Depends(get_current_user),
):
    """Incidenti aperti/chiusi sulla finestra, scoped per tenant, paginati."""
    seconds = _parse_window(window)
    cutoff = int(time.time()) - seconds
    clause, params = _tenant_filter(current_user)
    status_clause = "" if status == "all" else " AND status = ?"
    status_params = () if status == "all" else (status,)
    rows = await db.read(
        f"""SELECT id, tenant, entity_key, opened_ts, last_event_ts, closed_ts,
                   title, severity, event_count, status, cause_kind, confidence,
                   ai_assisted
            FROM incidents
            WHERE last_event_ts >= ?{clause}{status_clause}
            ORDER BY last_event_ts DESC
            LIMIT ? OFFSET ?""",
        (cutoff, *params, *status_params, limit, page * limit))
    return {"window": window, "status": status, "page": page,
            "incidents": [dict(r) for r in rows]}


async def _incident_in_scope(incident_id: int, current_user):
    """Riga incidente se visibile all'utente, altrimenti 404 (mai 403: non si
    conferma l'esistenza di risorse fuori scope)."""
    rows = await db.read(
        """SELECT id, tenant, entity_key, opened_ts, last_event_ts, closed_ts,
                  title, severity, event_count, status, cause_kind, confidence,
                  reasoning_json, ai_narrative, ai_narrative_ts, ai_assisted
           FROM incidents WHERE id = ?""", (incident_id,))
    scope = user_group_scope(current_user)
    if not rows or (scope is not None and rows[0]["tenant"] not in scope):
        raise HTTPException(status_code=404, detail="Incident not found.")
    return dict(rows[0])


@router.get("/{incident_id}")
async def get_incident(incident_id: int, current_user = Depends(get_current_user)):
    """Dettaglio: conclusione corrente, storico delle conclusioni superate e
    timeline multi-fonte.

    Lo storico esiste perché una ritrattazione può cambiare la causa: il
    sistema deve poter dire "avevamo ipotizzato X, poi un fatto nuovo l'ha
    invalidata" invece di cambiare idea in silenzio."""
    incident = await _incident_in_scope(incident_id, current_user)
    incident["reasoning"] = _parse_json(incident.pop("reasoning_json"))
    entries = await asyncio.to_thread(timeline.build, incident_id)
    history = await db.read(
        """SELECT concluded_ts, cause_kind, confidence, superseded_ts
           FROM incident_conclusions
           WHERE incident_id = ? AND superseded_ts IS NOT NULL
           ORDER BY concluded_ts DESC LIMIT 20""", (incident_id,))
    return {"incident": incident, "timeline": entries,
            "previous_conclusions": [dict(r) for r in history]}


@router.post("/{incident_id}/status")
async def set_incident_status(
    incident_id: int,
    payload: dict,
    current_user = Depends(require_operator),
):
    """Transizione di stato: new→ack, new→resolved, ack→resolved, con
    concorrenza ottimistica. Lo stato vive sull'incidente e basta: le evidenze
    non hanno uno stato proprio, seguono l'incidente (anche in cancellazione,
    via ON DELETE CASCADE)."""
    new_status = (payload or {}).get("status")
    from_status = (payload or {}).get("from_status")
    if (from_status, new_status) not in _ALLOWED_TRANSITIONS:
        raise HTTPException(
            status_code=409,
            detail=f"Status transition not allowed: "
                   f"'{from_status}' → '{new_status}'.")

    scope = user_group_scope(current_user)

    def _transition():
        conn = db.get_observability_connection()
        try:
            row = conn.execute(
                "SELECT tenant, status FROM incidents WHERE id = ?",
                (incident_id,)).fetchone()
            if row is None or (scope is not None and row["tenant"] not in scope):
                return "not_found"
            cur = conn.execute(
                "UPDATE incidents SET status = ? WHERE id = ? AND status = ?",
                (new_status, incident_id, from_status))
            conn.commit()
            return "ok" if cur.rowcount == 1 else "stale"
        finally:
            conn.close()

    result = await asyncio.to_thread(_transition)
    if result == "not_found":
        raise HTTPException(status_code=404, detail="Incident not found.")
    if result == "stale":
        raise HTTPException(
            status_code=409,
            detail="The incident status changed in the meantime: reload the list.")
    log_audit(f"Incidente #{incident_id}: stato '{from_status}' → "
              f"'{new_status}' da '{current_user.get('sub')}'.")
    return {"status": "success", "id": incident_id, "new_status": new_status}


def _narrative_prompt(incident: dict, entries: list) -> str:
    """Contesto per il modello: la conclusione è già presa, all'AI si chiede
    solo di ESPORLA in prosa operativa."""
    reasoning = incident.get("reasoning") or {}
    lines = [
        "Conclusione deterministica già calcolata dalla piattaforma "
        "(NON metterla in discussione, esponila):",
        f"- causa: {incident.get('cause_kind')}",
        f"- confidenza: {incident.get('confidence')}%",
        f"- regole attivate: {', '.join(reasoning.get('rules_fired') or []) or 'nessuna'}",
        f"- fonti corroboranti: {', '.join(reasoning.get('sources_used') or []) or 'nessuna'}",
        f"- entità: {incident.get('entity_key')}",
        f"- eventi correlati: {incident.get('event_count')}",
        "",
        "Timeline (istante, fonte, descrizione):",
    ]
    for e in entries[:MAX_NARRATIVE_ENTRIES]:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"]))
        lines.append(f"- {stamp} [{e['source']}] {e['text']}")
    lines += [
        "",
        "Scrivi in italiano, massimo 8 righe: cosa è successo, in che ordine, "
        "e cosa conviene verificare per primo. Non inventare dati assenti dalla "
        "timeline e non proporre una causa diversa da quella indicata.",
    ]
    return "\n".join(lines)


@router.post("/{incident_id}/explain")
async def explain_incident(
    incident_id: int,
    current_user = Depends(require_operator),
):
    """Narrativa AI on-demand per UN incidente. Costa credito: ogni chiamata è
    tracciata nell'audit. Il risultato è salvato in colonne separate e marcato
    ``ai_assisted`` — resta una riformulazione, non la conclusione."""
    from ai import ai_assistant
    from routers.ai import _get_active_ai_profile
    from security import crypto_vault

    incident = await _incident_in_scope(incident_id, current_user)
    incident["reasoning"] = _parse_json(incident.pop("reasoning_json"))

    profile = _get_active_ai_profile()
    if profile is None:
        raise HTTPException(
            status_code=400,
            detail="Nessun profilo AI configurato/attivo. Un amministratore "
                   "deve crearne uno prima.")
    provider = profile.get("provider", "")
    api_key = (crypto_vault.decrypt_password(profile.get("api_key_enc", ""))
               if profile.get("api_key_enc") else None)
    if provider != "ollama" and not api_key:
        raise HTTPException(status_code=400,
                            detail="API key non configurata per il profilo AI attivo.")

    entries = await asyncio.to_thread(timeline.build, incident_id)
    messages = [{"role": "user", "content": _narrative_prompt(incident, entries)}]
    try:
        reply = await asyncio.to_thread(
            lambda: ai_assistant.chat(
                messages,
                provider=provider,
                model=profile.get("model") or None,
                api_key=api_key,
                base_url=profile.get("base_url") or None,
                rate_limit_rpm=profile.get("rate_limit_rpm", 0),
                allow_unredacted=bool(profile.get("allow_unredacted", False)),
            ))
    except ai_assistant.RateLimitExceededError as e:
        raise HTTPException(status_code=429, detail=str(e))
    except ai_assistant.AiAssistantError as e:
        raise HTTPException(status_code=502, detail=str(e))

    now = int(time.time())
    db.enqueue_write(
        "UPDATE incidents SET ai_narrative = ?, ai_narrative_ts = ?, "
        "ai_assisted = 1 WHERE id = ?", (reply, now, incident_id))
    log_audit(f"Narrativa AI generata per l'incidente #{incident_id} "
              f"da '{current_user.get('sub')}' (provider {provider}).")
    return {"status": "success", "id": incident_id, "ai_narrative": reply,
            "ai_narrative_ts": now, "provider": provider}
