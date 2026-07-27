# -*- coding: utf-8 -*-
"""Correlation Rules Engine: dal modello eventi unificato alle EVIDENZE.

Il correlatore non produce più incidenti. Produce evidenze, ciascuna con un
ruolo causale, e l'incidente è la vista che ne deriva.

Le regole sono CALLABLE PYTHON in una tabella, non un DSL. È lo stesso schema
già usato da ``services/netsec_audit/benchmarks.py``: si mette un breakpoint
dentro una regola e si vede perché è scattata. Un interprete di condizioni in
YAML sembra più flessibile finché non serve il primo ``or``, e da lì in poi si
sta scrivendo un linguaggio peggiore di Python dentro Python.

Ciò che è configurabile a runtime sono le SOGLIE, non la logica: ogni regola
dichiara i propri parametri con un default, l'admin li può ritoccare da
``app_settings`` (sezione ``correlation_rules``), e i valori EFFETTIVAMENTE
usati finiscono in ``evidence.params_json`` accanto a ``rule_version``. Senza
questo, due esiti diversi avrebbero la stessa provenienza.

Ruoli (``evidence.role``) — dichiarati dalla regola, mai dedotti:
- ``trigger``     ciò che ha innescato;
- ``supporting``  ciò che corrobora la conclusione;
- ``symptom``     ciò che si osserva come effetto sullo stato;
- ``consequence`` ciò che ne è derivato a valle.
"""

import json
import logging
from typing import Optional

from core.app_settings import get_app_settings

logger = logging.getLogger("sentinelnet.obs")

ROLES = ("trigger", "supporting", "symptom", "consequence")


class Retraction:
    """Invalidazione di un'evidenza precedente, prodotta da una REGOLA.

    Nessun adapter ritratta mai nulla: gli adapter osservano e normalizzano, le
    regole interpretano. Il fatto nuovo ("l'interfaccia è tornata su", domani
    "la deviazione rientra nella norma") arriva come evento; è una regola che,
    vedendolo accanto all'evidenza precedente, decide che quella conclusione
    non regge più.

    ``witness`` è il Finding che giustifica la ritrattazione: viene registrato
    come evidenza a sé, così il suo id finisce in ``retracted_by_evidence_id``
    e la ritrattazione resta spiegabile (e a sua volta ritrattabile).
    """

    __slots__ = ("target_rule_id", "entity_key", "tenant", "reason", "witness",
                 "window_s")

    def __init__(self, target_rule_id, entity_key, tenant, reason, witness,
                 window_s=3600):
        self.target_rule_id = target_rule_id
        self.entity_key = entity_key
        self.tenant = tenant
        self.reason = reason
        self.witness = witness
        self.window_s = window_s


class Finding:
    """Una evidenza proposta da una regola. Non è ancora un incidente."""

    __slots__ = ("event_id", "ts", "tenant", "role", "entity_key", "severity",
                 "src_ip", "dst_ip", "switch_port", "summary", "attrs")

    def __init__(self, event_id, ts, tenant, role, entity_key, summary,
                 severity=None, src_ip=None, dst_ip=None, switch_port=None,
                 attrs=None):
        assert role in ROLES, f"ruolo non ammesso: {role}"
        self.event_id = event_id
        self.ts = ts
        self.tenant = tenant
        self.role = role
        self.entity_key = entity_key
        self.summary = summary
        self.severity = severity
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.switch_port = switch_port
        self.attrs = attrs or {}


def parameter_specs(rule_id: str) -> list:
    """Soglie dichiarate da una regola: [{name, default, min, max, description}]."""
    specs = (RULES.get(rule_id) or {}).get("parameters")
    return specs if isinstance(specs, list) else []


def defaults_for(rule_id: str) -> dict:
    return {p["name"]: p["default"] for p in parameter_specs(rule_id)}


def params_for(rule_id: str) -> dict:
    """Soglie effettive: default della regola sovrascritti da app_settings.

    Confine di sistema: si accettano solo i parametri dichiarati dalla regola,
    solo valori numerici, e solo dentro l'intervallo ``min``/``max`` del
    catalogo. Un valore fuori range viene riportato dentro invece di essere
    scartato in silenzio, così una configurazione sbagliata non spegne la
    regola senza dirlo."""
    saved = (get_app_settings().get("correlation_rules") or {}).get(rule_id) or {}
    out = {}
    for spec in parameter_specs(rule_id):
        default = spec["default"]
        value = saved.get(spec["name"], default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            value = default
        value = max(spec["min"], min(spec["max"], value))
        out[spec["name"]] = type(default)(value)
    return out


def catalog() -> list:
    """Il motore descrive se stesso: la UI costruisce il pannello soglie da
    qui, l'assistente AI sa quali regole esistono e la documentazione deriva
    dal codice. Una sola fonte di verità."""
    return [{
        "id": rule_id,
        "version": rule["version"],
        "title": rule["title"],
        "description": rule["description"],
        "inputs": list(rule["inputs"]),
        "outputs": list(rule["outputs"]),
        "base_confidence": rule.get("base_confidence"),
        "parameters": [dict(p) for p in parameter_specs(rule_id)],
        "effective": params_for(rule_id),
    } for rule_id, rule in RULES.items()]


# --- REGOLE ------------------------------------------------------------------
# Ogni regola: (id, versione, titolo, callable). Il callable riceve la finestra
# di eventi normalizzati e i propri parametri, e ritorna una lista di Finding.

def _blocked_traffic(events: list, p: dict) -> list:
    """Traffico bloccato con evidenza di flusso corroborante.

    Precision over recall: l'evento di sicurezza da solo non basta, serve un
    flusso che confermi che il traffico è davvero avvenuto. Il log è il
    trigger, il flusso è il supporting.
    """
    flows = [e for e in events if e["event_type"] == "flow.aggregate"]
    out = []
    for ev in events:
        if ev["event_type"] != "log.security":
            continue
        if not (ev["src_ip"] and ev["dst_ip"]):
            continue
        match = next(
            (f for f in flows
             if f["tenant"] == ev["tenant"]
             and f["src_ip"] == ev["src_ip"] and f["dst_ip"] == ev["dst_ip"]
             and abs(f["ts"] - ev["ts"]) <= p["match_delta_s"] + 60), None)
        if match is None:
            continue
        entity = f"ip:{ev['src_ip']}"
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=entity, severity=ev["severity"],
            src_ip=ev["src_ip"], dst_ip=ev["dst_ip"],
            summary=f"Traffico bloccato {ev['src_ip']} → {ev['dst_ip']}",
            attrs={"action": json.loads(ev["attrs_json"] or "{}").get("action")}))
        out.append(Finding(
            event_id=match["id"], ts=match["ts"], tenant=match["tenant"],
            role="supporting", entity_key=entity,
            src_ip=match["src_ip"], dst_ip=match["dst_ip"],
            summary=f"Flusso corrispondente {match['src_ip']} → {match['dst_ip']}",
            attrs={"metrics": json.loads(match["metrics_json"] or "{}")}))
    return out


def _high_severity_log(events: list, p: dict) -> list:
    """Log ad alta severità: emerge da solo, anche senza flusso e anche senza
    endpoint estraibili dal messaggio."""
    out = []
    for ev in events:
        if not ev["event_type"].startswith("log."):
            continue
        if ev["severity"] is None or ev["severity"] > p["max_severity"]:
            continue
        entity = f"ip:{ev['src_ip']}" if ev["src_ip"] else f"ip:{ev['device_ip']}"
        attrs = json.loads(ev["attrs_json"] or "{}")
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=entity, severity=ev["severity"],
            src_ip=ev["src_ip"], dst_ip=ev["dst_ip"],
            summary=(attrs.get("message") or "Evento critico")[:200],
            attrs={"action": attrs.get("action")}))
    return out


def _config_change(events: list, p: dict) -> list:
    """Variazione di configurazione/stato su un apparato.

    È il trigger classico: qualcosa è cambiato, e ciò che segue va letto alla
    sua luce. Da sola non è un incidente — lo diventa se altre evidenze si
    raggruppano sulla stessa entità.
    """
    out = []
    for ev in events:
        if ev["event_type"] not in ("device.change", "interface.change"):
            continue
        attrs = json.loads(ev["attrs_json"] or "{}")
        where = ev["interface"] or ev["device_ip"]
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=f"ip:{ev['device_ip']}", severity=ev["severity"],
            summary=f"Modifica su {where}: {attrs.get('field')} "
                    f"{attrs.get('before')} → {attrs.get('after')}",
            attrs=attrs))
    return out


def _interface_down(events: list, p: dict) -> list:
    """Interfaccia passata a down: sintomo osservato sullo stato, non causa."""
    out = []
    for ev in events:
        if ev["event_type"] != "interface.change":
            continue
        attrs = json.loads(ev["attrs_json"] or "{}")
        if str(attrs.get("after")).lower() not in ("down", "0", "false"):
            continue
        if "link" not in str(attrs.get("field", "")).lower() \
                and "status" not in str(attrs.get("field", "")).lower():
            continue
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="symptom",
            entity_key=f"ip:{ev['device_ip']}", severity=ev["severity"],
            summary=f"Interfaccia {ev['interface']} passata a down",
            attrs=attrs))
    return out


def _traffic_volume_spike(events: list, p: dict) -> list:
    """Volume di un flusso molto sopra la mediana della finestra.

    Non è un baseline: confronta solo dentro la finestra corrente. Quando il
    Baseline Engine esisterà, sostituirà il confronto — non la regola, che
    resta il punto in cui il volume diventa evidenza.
    """
    flows = [e for e in events if e["event_type"] == "flow.aggregate"]
    if len(flows) < p["min_flows"]:
        return []
    volumes = sorted((json.loads(f["metrics_json"] or "{}").get("bytes") or 0)
                     for f in flows)
    mid = volumes[len(volumes) // 2]
    if mid <= 0:
        return []
    out = []
    for f in flows:
        nbytes = json.loads(f["metrics_json"] or "{}").get("bytes") or 0
        if nbytes < mid * p["spike_ratio"]:
            continue
        out.append(Finding(
            event_id=f["id"], ts=f["ts"], tenant=f["tenant"], role="supporting",
            entity_key=f"ip:{f['src_ip']}",
            src_ip=f["src_ip"], dst_ip=f["dst_ip"],
            summary=f"Volume anomalo {f['src_ip']} → {f['dst_ip']}: "
                    f"{nbytes} byte contro una mediana di {mid}",
            attrs={"bytes": nbytes, "median_bytes": mid}))
    return out


def _baseline_spike(events: list, p: dict) -> list:
    """Il traffico si discosta dall'abitudine, non solo dai vicini di finestra.

    Consuma la misura prodotta dal Baseline Adapter: la decisione su cosa sia
    "troppo" vive qui, dove è tarabile e registrata nella provenienza.
    """
    out = []
    for ev in events:
        if ev["event_type"] != "flow.baseline":
            continue
        m = json.loads(ev["metrics_json"] or "{}")
        if (m.get("samples") or 0) < p["min_samples"]:
            continue
        deviation = m.get("deviation_pct")
        if deviation is None or deviation < p["min_deviation_pct"]:
            continue
        attrs = json.loads(ev["attrs_json"] or "{}")
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=f"ip:{ev['src_ip']}", severity=4, src_ip=ev["src_ip"],
            summary=f"{ev['src_ip']}: traffico {deviation:+.0f}% rispetto "
                    f"all'abitudine ({m.get('observed')} byte contro "
                    f"{m.get('expected')} attesi)",
            attrs={**attrs, **m}))
    return out


def _baseline_normal_retracts_spike(events: list, p: dict) -> list:
    """La misura storica dice che l'ora rientra nella norma: il picco rilevato
    guardando solo dentro la finestra non regge più.

    È il caso che il documento chiede di evitare — allarmi da picchi temporanei
    — risolto senza cancellare nulla: l'evidenza resta, ritrattata, e
    l'incidente può raccontare di aver cambiato idea.
    """
    out = []
    for ev in events:
        if ev["event_type"] != "flow.baseline":
            continue
        m = json.loads(ev["metrics_json"] or "{}")
        if (m.get("samples") or 0) < p["min_samples"]:
            continue
        deviation = m.get("deviation_pct")
        if deviation is None or abs(deviation) > p["normal_band_pct"]:
            continue
        witness = Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"],
            role="supporting", entity_key=f"ip:{ev['src_ip']}",
            src_ip=ev["src_ip"],
            summary=f"{ev['src_ip']}: volume nella norma storica "
                    f"({deviation:+.0f}% sull'atteso)",
            attrs={**m})
        out.append(Retraction(
            target_rule_id="TRAFFIC_SPIKE_001",
            entity_key=f"ip:{ev['src_ip']}", tenant=ev["tenant"],
            reason=f"Il confronto con lo storico colloca il volume nella norma "
                   f"({deviation:+.0f}% sull'atteso)",
            witness=witness, window_s=p["window_s"]))
    return out


def _interface_recovered(events: list, p: dict) -> list:
    """L'interfaccia è tornata su: il sintomo precedente non regge più.

    È il primo caso di ritrattazione, e vale come modello per quelli che
    verranno (il Baseline che dice "quella deviazione rientrava nella norma"):
    la regola NON ricalcola nulla, guarda un fatto nuovo accanto a una
    conclusione vecchia e dichiara che quella conclusione è decaduta.
    """
    out = []
    for ev in events:
        if ev["event_type"] != "interface.change":
            continue
        attrs = json.loads(ev["attrs_json"] or "{}")
        field = str(attrs.get("field", "")).lower()
        if "link" not in field and "status" not in field:
            continue
        if str(attrs.get("after")).lower() not in ("up", "1", "true"):
            continue
        witness = Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"],
            role="consequence", entity_key=f"ip:{ev['device_ip']}",
            summary=f"Interfaccia {ev['interface']} tornata su",
            attrs=attrs)
        out.append(Retraction(
            target_rule_id="IFACE_DOWN_001",
            entity_key=f"ip:{ev['device_ip']}", tenant=ev["tenant"],
            reason=f"Interfaccia {ev['interface']} tornata su",
            witness=witness, window_s=p["window_s"]))
    return out


# ``base_confidence``: quanto vale da sola la conclusione di questa regola.
# Il motore di ragionamento ci somma i bonus delle evidenze corroboranti.
# ``inputs``/``outputs``: cosa consuma e cosa produce — servono al catalogo,
# che è ciò che leggono la UI e l'assistente AI.
RULES = {
    "BLOCKED_TRAFFIC_001": {
        "version": "1.0.0",
        "title": "Traffico bloccato con evidenza di flusso",
        "description": "Un evento di sicurezza bloccante corroborato da un "
                       "flusso reale fra gli stessi endpoint.",
        "inputs": ["log.security", "flow.aggregate"],
        "outputs": ["trigger", "supporting"],
        "parameters": [
            {"name": "match_delta_s", "default": 120, "min": 0, "max": 3600,
             "description": "Distanza massima fra evento e bucket di flusso."},
        ],
        "base_confidence": 65,
        "check": _blocked_traffic,
    },
    "HIGH_SEVERITY_LOG_001": {
        "version": "1.0.0",
        "title": "Log ad alta severità",
        "description": "Un log abbastanza grave da emergere anche senza "
                       "corroborazione di flusso.",
        "inputs": ["log.security", "log.event"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "max_severity", "default": 3, "min": 0, "max": 7,
             "description": "Severità syslog massima considerata (0 = emerg)."},
        ],
        "base_confidence": 45,
        "check": _high_severity_log,
    },
    "CFG_CHANGE_001": {
        "version": "1.0.0",
        "title": "Variazione di configurazione o stato",
        "description": "Qualcosa è cambiato su un apparato: ciò che segue va "
                       "letto alla sua luce.",
        "inputs": ["device.change", "interface.change"],
        "outputs": ["trigger"],
        "parameters": [],
        "base_confidence": 55,
        "check": _config_change,
    },
    "IFACE_DOWN_001": {
        "version": "1.0.0",
        "title": "Interfaccia giù",
        "description": "Una porta è passata a down: sintomo osservato sullo "
                       "stato, non causa.",
        "inputs": ["interface.change"],
        "outputs": ["symptom"],
        "parameters": [],
        "base_confidence": 60,
        "check": _interface_down,
    },
    "IFACE_RECOVERED_001": {
        "version": "1.0.0",
        "title": "Interfaccia ripristinata (ritratta il sintomo)",
        "description": "La porta è tornata su: ritratta l'evidenza di "
                       "interfaccia giù, senza cancellarla.",
        "inputs": ["interface.change"],
        "outputs": ["consequence", "retraction"],
        "parameters": [
            {"name": "window_s", "default": 3600, "min": 60, "max": 86400,
             "description": "Quanto indietro cercare il sintomo da ritrattare."},
        ],
        "base_confidence": 0,
        "check": _interface_recovered,
    },
    "BASELINE_SPIKE_001": {
        "version": "1.0.0",
        "title": "Scostamento dalla baseline storica",
        "description": "Il volume di un talker si discosta dal suo "
                       "comportamento abituale (stesso giorno e stessa ora "
                       "delle settimane precedenti).",
        "inputs": ["flow.baseline"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_deviation_pct", "default": 200, "min": 20, "max": 10000,
             "description": "Scostamento minimo sull'atteso per parlare di picco."},
            {"name": "min_samples", "default": 3, "min": 2, "max": 30,
             "description": "Campioni storici minimi perché il confronto valga."},
        ],
        "base_confidence": 55,
        "check": _baseline_spike,
    },
    "BASELINE_NORMAL_RETRACT_001": {
        "version": "1.0.0",
        "title": "Volume nella norma storica (ritratta il picco di finestra)",
        "description": "Lo storico dice che l'ora rientra nell'abitudine: "
                       "ritratta il picco rilevato guardando solo dentro la "
                       "finestra corrente.",
        "inputs": ["flow.baseline"],
        "outputs": ["supporting", "retraction"],
        "parameters": [
            {"name": "normal_band_pct", "default": 50, "min": 5, "max": 500,
             "description": "Entro quale scostamento il volume è considerato normale."},
            {"name": "min_samples", "default": 3, "min": 2, "max": 30,
             "description": "Campioni storici minimi perché il confronto valga."},
            {"name": "window_s", "default": 7200, "min": 60, "max": 86400,
             "description": "Quanto indietro cercare il picco da ritrattare."},
        ],
        "base_confidence": 0,
        "check": _baseline_normal_retracts_spike,
    },
    "TRAFFIC_SPIKE_001": {
        "version": "1.0.0",
        "title": "Picco di volume nella finestra",
        "description": "Un flusso molto sopra la mediana della finestra "
                       "corrente. Non è un baseline: confronta solo dentro la "
                       "finestra.",
        "inputs": ["flow.aggregate"],
        "outputs": ["supporting"],
        "parameters": [
            {"name": "min_flows", "default": 5, "min": 2, "max": 1000,
             "description": "Flussi minimi perché la mediana abbia senso."},
            {"name": "spike_ratio", "default": 10, "min": 2, "max": 1000,
             "description": "Quante volte la mediana per considerarlo picco."},
        ],
        "base_confidence": 50,
        "check": _traffic_volume_spike,
    },
}


def base_confidence(rule_id: str, default: int = 40) -> int:
    """Confidenza di partenza dichiarata dalla regola."""
    value = (RULES.get(rule_id) or {}).get("base_confidence", default)
    return value if isinstance(value, int) else default


def evaluate(events: list, only: Optional[list] = None) -> list:
    """Esegue le regole sulla finestra di eventi normalizzati.
    Ritorna [(rule_id, version, params, Finding | Retraction), ...].

    Una regola che esplode non ferma le altre: si perde il suo contributo, non
    l'intero ciclo di correlazione.
    """
    out = []
    for rule_id, rule in RULES.items():
        if only is not None and rule_id not in only:
            continue
        params = params_for(rule_id)
        try:
            produced = rule["check"](events, params)
        except Exception as e:
            logger.warning("Regola %s fallita: %s", rule_id, e)
            continue
        for item in produced:
            out.append((rule_id, rule["version"], params, item))
    return out
