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
from observability import flowpath, rules, suppression, timeline
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
def list_rules(lang: str = Query("it", description="Language: 'it' or 'en'"),
               current_user = Depends(get_current_user)):
    """Catalogo delle regole di correlazione: il motore descrive se stesso.

    La UI ci costruisce il pannello soglie, l'assistente AI sa quali regole
    esistono e la documentazione deriva dal codice — una sola fonte di verità.
    Nessun dato di tenant qui dentro, solo la definizione del motore."""
    return {"rules": rules.catalog(lang=lang)}


@router.post("/rules/{rule_id}/parameters")
def set_rule_parameters(rule_id: str, payload: dict,
                        current_user = Depends(require_admin)):
    """Ritocca le soglie di UNA regola. La logica resta nel codice: qui si
    accettano solo i parametri dichiarati dal catalogo, solo numerici e solo
    dentro l'intervallo min/max — la UI non può iniettare nulla nel motore."""
    from core.app_settings import get_app_settings, save_app_settings

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


INSTABILITY_WINDOW_S = 86400


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

    The vocabulary lives in observability.rules, next to the rule that raises
    the incident from the same values. Two copies is how this view and that
    rule would come to disagree about what "down" means.
    """
    if item.get("suppressed"):
        return "maint" if item.get("to_ts") is not None else "by_design"
    if (item.get("transitions") or 0) >= min_flaps:
        return "flapping"
    link = str(item.get("link") or "").strip().lower()
    if link in rules.LINK_DOWN:
        return "outage"
    if link in rules.LINK_UP:
        return "up"
    return "unknown"


@router.get("/interfaces")
async def list_interfaces(current_user = Depends(get_current_user)):
    """Interfacce viste dal motore: ultimo stato, instabilità recente e la
    soppressione che le copre.

    Serve a due cose opposte. Togliere rumore prima che diventi tale (Loopback,
    Null e VLAN dismesse sono giù per progetto), e MOSTRARE l'instabilità anche
    quando non è mai diventata un incidente: la regola guarda una finestra di
    correlazione, questa vista guarda un giorno intero, quindi una porta che
    oscilla piano compare qui pur non scattando mai."""
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
    # Il motore conosce solo l'IP: il nome lo sa l'inventario. Senza, con più
    # sedi la tabella è un elenco di indirizzi da tradurre a mente.
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

    min_flaps = rules.params_for("IFACE_FLAPPING_001")["min_transitions"]
    counts = {"total": len(out), "up": 0, "outage": 0, "flapping": 0,
              "maint": 0, "by_design": 0, "unknown": 0}
    for item in out:
        # Computed once, server side, and shipped with the row: the client
        # renders this value instead of deriving its own.
        item["state"] = _iface_state(item, min_flaps)
        counts[item["state"]] += 1

    return {"interfaces": out, "counts": counts, "window_s": INSTABILITY_WINDOW_S,
            "min_transitions": min_flaps,
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
    """Tutte le soppressioni dello scope, anche scadute: mostrarle spente è ciò
    che rende leggibile *perché* un incidente di ieri non è mai nato."""
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


@router.post("/interfaces/expected")
async def set_suppression(payload: dict,
                          current_user = Depends(require_operator)):
    """Dichiara che qualcosa è atteso, con o senza scadenza.

    Nessuna finestra = "è così per progetto". Con ``to_ts`` = manutenzione
    pianificata. Sono lo stesso modello: 'per sempre' è il caso senza scadenza,
    non un caso speciale.

    Non cancella e non nasconde niente: l'evento resta in ``events`` e nel
    feed. Cambia solo se le regole ne traggano un'evidenza — l'interpretazione,
    che è dove la conoscenza dell'operatore deve entrare."""
    from core.app_settings import get_app_settings, save_app_settings

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
            "previous_conclusions": [dict(r) for r in history],
            "flow_path": await _flow_path(incident_id, incident["tenant"])}


async def _flow_path(incident_id: int, tenant: str) -> dict:
    """Percorso della conversazione che ha innescato l'incidente.

    Gli endpoint si prendono dall'evidenza di innesco ancora attiva: è quella
    che la conclusione indica come causa, quindi è il traffico di cui ha senso
    mostrare il percorso."""
    rows = await db.read(
        """SELECT src_ip, dst_ip FROM evidence
           WHERE incident_id = ? AND status = 'active' AND role = 'trigger'
             AND src_ip IS NOT NULL
           ORDER BY ts ASC, id ASC LIMIT 1""", (incident_id,))
    if not rows:
        return {"direction": None, "hops": [], "complete": False}
    return await asyncio.to_thread(flowpath.build, rows[0]["src_ip"],
                                   rows[0]["dst_ip"], tenant)


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
            if new_status == "resolved":
                # resolved_ts ancora la retention (schema v10): un incidente
                # chiuso ieri non decade per quanto e' stato aperto.
                cur = conn.execute(
                    "UPDATE incidents SET status = ?, resolved_ts = ? "
                    "WHERE id = ? AND status = ?",
                    (new_status, int(time.time()), incident_id, from_status))
            else:
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
