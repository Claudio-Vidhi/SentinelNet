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
from observability import endpoints

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
                 "src_ip", "dst_ip", "switch_port", "summary", "attrs", "key")

    def __init__(self, event_id, ts, tenant, role, entity_key, summary,
                 severity=None, src_ip=None, dst_ip=None, switch_port=None,
                 attrs=None, key=None):
        assert role in ROLES, f"ruolo non ammesso: {role}"
        # ``key``: discriminante quando la STESSA regola trae più conclusioni
        # distinte dallo STESSO evento (CPU e memoria dallo stesso snapshot).
        # Senza, la deduplica le considera un doppione e ne perde una. È la
        # regola a dichiararlo, perché è l'unica a sapere di aver risposto a
        # due domande diverse.
        self.key = key
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
        # Knowledge base derivata dal codice, non scritta a parte: il catalogo
        # dice quali regole esistono E cosa farci quando scattano.
        "investigation": rule.get("investigation"),
        "remediation": rule.get("remediation"),
        "parameters": [dict(p) for p in parameter_specs(rule_id)],
        "effective": params_for(rule_id),
    } for rule_id, rule in RULES.items()]


def declares_output(rule_id: str, name: str) -> bool:
    """Una regola può produrre solo ciò che ha dichiarato in ``outputs``.

    Senza questo controllo il catalogo sarebbe una promessa non verificata: una
    regola potrebbe restituire una ritrattazione senza averla dichiarata, e la
    UI, l'assistente AI e la documentazione — che leggono tutti il catalogo —
    descriverebbero un motore diverso da quello che gira."""
    outputs = (RULES.get(rule_id) or {}).get("outputs")
    return isinstance(outputs, list) and name in outputs


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
            summary=f"Traffico bloccato {endpoints.describe(ev['src_ip'])} → "
                    f"{endpoints.describe(ev['dst_ip'])}",
            attrs={"action": json.loads(ev["attrs_json"] or "{}").get("action")}))
        out.append(Finding(
            event_id=match["id"], ts=match["ts"], tenant=match["tenant"],
            role="supporting", entity_key=entity,
            src_ip=match["src_ip"], dst_ip=match["dst_ip"],
            summary=f"Flusso corrispondente {endpoints.describe(match['src_ip'])} → "
                    f"{endpoints.describe(match['dst_ip'])}",
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
        # Un link che cade non è una MODIFICA: è qualcosa che è successo
        # all'apparato, non qualcosa che qualcuno gli ha fatto. Chiamarlo
        # "modifica di configurazione" mandava a cercare chi aveva toccato la
        # configurazione mentre il cavo era staccato. Lo stato configurato
        # (``admin_status``) resta qui: quello lo decide una persona.
        if str(attrs.get("field", "")).rsplit(".", 1)[-1].lower() == "link":
            continue
        where = ev["interface"] or ev["device_ip"]
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=f"ip:{ev['device_ip']}", severity=ev["severity"],
            summary=f"Modifica su {where}: {attrs.get('field')} "
                    f"{attrs.get('before')} → {attrs.get('after')}",
            attrs=attrs))
    return out


def expectation_key(tenant, device_ip, interface) -> str:
    """Chiave di una interfaccia dichiarata 'attesa giù' dall'operatore."""
    return f"{tenant}|{device_ip}|{interface}"


def expected_down() -> dict:
    """Interfacce che l'operatore ha confermato come volutamente giù.

    Non è una regola e non è un fatto della rete: è CONOSCENZA DELL'OPERATORE,
    e vive dove vive il resto della configurazione. Una Loopback, una Null0 o
    una VLAN dismessa sono giù per progetto, e segnalarle a ogni transizione
    riempie gli incidenti di rumore che nasconde quello vero.

    Non sopprime nulla a monte: l'evento resta in ``events`` e resta visibile
    nel feed. Cambia solo l'INTERPRETAZIONE — che è esattamente il posto in cui
    la conoscenza di chi gestisce la rete deve entrare.
    """
    saved = get_app_settings().get("interface_expectations")
    return saved if isinstance(saved, dict) else {}


def _interface_down(events: list, p: dict) -> list:
    """Interfaccia passata a down: sintomo osservato sullo stato, non causa."""
    expected = expected_down()
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
        if expectation_key(ev["tenant"], ev["device_ip"],
                           ev["interface"]) in expected:
            continue
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="symptom",
            entity_key=f"ip:{ev['device_ip']}", severity=ev["severity"],
            summary=f"Interfaccia {ev['interface']} passata a down",
            attrs=attrs))
    return out


def _interface_flapping(events: list, p: dict) -> list:
    """Una porta che continua a cadere e risalire.

    Le singole cadute sono rumore; il PATTERN è il segnale. Finché ogni caduta
    resta un sintomo isolato, l'ingegnere vede dieci incidenti e nessuna causa
    — che è esattamente il problema, perché il guasto non è la caduta di
    stanotte ma il collegamento instabile.

    NON ritratta nulla, di proposito. Delle singole cadute se ne occupa già
    ``IFACE_RECOVERED_001``, che le ritratta a ogni risalita: su una porta che
    oscilla restano quindi solo evidenze ritrattate e nessuna conclusione in
    piedi — ed è precisamente il buco che questa regola riempie.

    Ritrattare sarebbe anche impreciso: le evidenze di ``IFACE_DOWN_001`` sono
    legate all'APPARATO, non alla porta, e una ritrattazione per entità
    zittirebbe anche la porta accanto, davvero giù, per colpa di questa.
    """
    changes: dict = {}
    for ev in events:
        if ev["event_type"] != "interface.change" or not ev["interface"]:
            continue
        field = str(json.loads(ev["attrs_json"] or "{}").get("field", "")).lower()
        if "link" not in field and "status" not in field:
            continue
        changes.setdefault((ev["tenant"], ev["device_ip"], ev["interface"]),
                           []).append(ev)

    out = []
    for (tenant, device_ip, interface), seen in changes.items():
        if len(seen) < p["min_transitions"]:
            continue
        span = seen[-1]["ts"] - seen[0]["ts"]
        out.append(Finding(
            event_id=seen[-1]["id"], ts=seen[-1]["ts"], tenant=tenant,
            role="trigger", entity_key=f"ip:{device_ip}", severity=3,
            # Due porte instabili sullo stesso apparato sono due conclusioni.
            key=f"flap:{interface}",
            summary=f"Interfaccia {interface} instabile: {len(seen)} "
                    f"transizioni in {max(span // 60, 1)} minuti",
            attrs={"interface": interface, "transitions": len(seen),
                   "span_s": span}))
    return out


def _device_load(events: list, p: dict) -> list:
    """Carico dell'apparato oltre soglia: CPU o memoria.

    Prima regola che legge uno STATO invece di un cambiamento. Tutte le altre
    aspettano una transizione — un log, una porta caduta, una configurazione
    toccata — e quindi non sanno dire "questo valore è troppo alto", solo
    "questo valore è diverso da prima".

    Ruolo ``symptom``, non ``trigger``: una CPU alta è ciò che va SPIEGATO, non
    la spiegazione. Se nella stessa finestra e sulla stessa entità arriva un
    innesco — un picco di traffico, una modifica di configurazione — è quello a
    diventare la causa, e il carico resta il sintomo che gli dà peso. È la
    forma esatta della frase che il documento chiede al motore di produrre.
    """
    out = []
    for ev in events:
        if ev["event_type"] != "device.state":
            continue
        m = json.loads(ev["metrics_json"] or "{}")
        for field, limit, label in (("cpu_pct", p["max_cpu_pct"], "CPU"),
                                    ("memory_pct", p["max_memory_pct"], "Memoria")):
            value = m.get(field)
            # Assente ≠ zero: un apparato che non espone il carico non deve
            # sembrare scarico.
            if value is None or value < limit:
                continue
            out.append(Finding(
                event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"],
                role="symptom", entity_key=f"ip:{ev['device_ip']}", severity=4,
                summary=f"{label} al {value}% su {ev['device_ip']} "
                        f"(soglia {limit}%)",
                key=field,
                attrs={"metric": field, "value": value, "threshold": limit}))
    return out


def _traffic_volume_spike(events: list, p: dict) -> list:
    """Volume di un flusso molto sopra la mediana della finestra.

    Non è un baseline: confronta solo dentro la finestra corrente. Quando il
    Baseline Engine esisterà, sostituirà il confronto — non la regola, che
    resta il punto in cui il volume diventa evidenza.
    """
    flows = [e for e in events if e["event_type"] == "flow.aggregate"]
    if not p["include_control_plane"]:
        # Su una rete reale la maggioranza schiacciante dei bucket è chiacchiera
        # di scoperta verso multicast e broadcast (mDNS, SSDP, OSPF, ARP).
        # Lasciandola dentro, la mediana descrive il rumore e non le
        # conversazioni: sia il riferimento sia i "picchi" finiscono per
        # misurare quanto un host annuncia se stesso.
        flows = [f for f in flows
                 if endpoints.traffic_direction(f["src_ip"],
                                                f["dst_ip"]) != "control_plane"]
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
            summary=f"Volume anomalo {endpoints.describe(f['src_ip'])} → "
                    f"{endpoints.describe(f['dst_ip'])}: "
                    f"{nbytes} byte contro una mediana di {mid}",
            attrs={"bytes": nbytes, "median_bytes": mid,
                   "direction": endpoints.traffic_direction(f["src_ip"],
                                                            f["dst_ip"])}))
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
        if (m.get("quality") or 0) < p["min_quality"]:
            continue
        deviation = m.get("deviation_pct")
        if deviation is None or deviation < p["min_deviation_pct"]:
            continue
        attrs = json.loads(ev["attrs_json"] or "{}")
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=f"ip:{ev['src_ip']}", severity=4, src_ip=ev["src_ip"],
            summary=f"{endpoints.describe(ev['src_ip'])}: traffico {deviation:+.0f}% rispetto "
                    f"all'abitudine ({m.get('observed')} byte contro "
                    f"{m.get('expected')} attesi, baseline "
                    f"{attrs.get('quality_label', '?')})",
            attrs={**attrs, **m}))
    return out


def _new_talker(events: list, p: dict) -> list:
    """Un talker mai visto prima. Non è una deviazione: è un'emergenza.

    Distinzione voluta — chiedere "di quanto si discosta dalla sua abitudine"
    a qualcosa che un'abitudine non ce l'ha produce solo numeri senza senso.
    """
    out = []
    for ev in events:
        if ev["event_type"] != "flow.emergence":
            continue
        m = json.loads(ev["metrics_json"] or "{}")
        observed = m.get("observed") or 0
        if observed < p["min_bytes"]:
            continue
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=f"ip:{ev['src_ip']}", severity=5, src_ip=ev["src_ip"],
            summary=f"{endpoints.describe(ev['src_ip'])}: host mai osservato prima, "
                    f"{observed} byte trasmessi",
            attrs={**json.loads(ev["attrs_json"] or "{}"), **m}))
    return out


def _unknown_exporter(events: list, p: dict) -> list:
    """Un exporter continua a inviare da un IP fuori inventario.

    Non è correlazione: è un controllo di salute in cui SentinelNet osserva SÉ
    STESSO. I record vengono scartati per non attribuirli a una sede sbagliata,
    ma una perdita di dati che dura è un guasto della piattaforma, e finché
    resta solo in una tabella di diagnostica nessuno la vede.

    La soglia è sulla DURATA, non sul singolo pacchetto: un apparato appena
    aggiunto e non ancora censito è normale per qualche minuto, un exporter
    scartato da un'ora è una configurazione sbagliata.
    """
    out = []
    for ev in events:
        if ev["event_type"] != "platform.exporter_unknown":
            continue
        m = json.loads(ev["metrics_json"] or "{}")
        persisted = m.get("persisted_s") or 0
        packets = m.get("packets") or 0
        if persisted < p["min_persistence_s"] or packets < p["min_packets"]:
            continue
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=f"exporter:{ev['entity_id']}", severity=ev["severity"],
            src_ip=ev["src_ip"],
            summary=f"Exporter {endpoints.describe(ev['entity_id'])} fuori "
                    f"inventario da {persisted // 60} minuti: {packets} "
                    f"pacchetti scartati",
            attrs={**json.loads(ev["attrs_json"] or "{}"), **m}))
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
        # Soglia di qualità PIÙ ALTA che nella regola di scoperta: per
        # concludere si può accettare un rischio, per DIS-concludere ne serve
        # meno. Ritrattare un allarme sulla base di una baseline debole fa un
        # danno silenzioso, ed è il verso opposto del falso positivo.
        if (m.get("quality") or 0) < p["min_quality"]:
            continue
        deviation = m.get("deviation_pct")
        if deviation is None or abs(deviation) > p["normal_band_pct"]:
            continue
        witness = Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"],
            role="supporting", entity_key=f"ip:{ev['src_ip']}",
            src_ip=ev["src_ip"],
            summary=f"{endpoints.describe(ev['src_ip'])}: volume nella norma storica "
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
        "investigation": 'Verificare se il blocco è atteso dalla policy o se un servizio legittimo è stato bloccato per errore. Controllare la porta dello switch del client e se il tentativo si ripete verso destinazioni diverse.',
        "remediation": "Se il traffico è legittimo, correggere la regola di firewall. Se non lo è, isolare l'host e verificare la presenza di malware.",
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
        "investigation": "Leggere il messaggio completo dell'apparato e correlarlo con eventuali modifiche di configurazione o riavvii nella stessa finestra.",
        "remediation": "Intervenire secondo la natura dell'errore riportato dall'apparato; se si ripete, aprire una verifica sullo stato hardware o sulla versione firmware.",
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
        "investigation": 'Identificare chi ha eseguito la modifica e se era pianificata. Confrontare il campo cambiato con il backup di configurazione precedente.',
        "remediation": "Se la modifica non era autorizzata, ripristinare dal backup e verificare gli accessi amministrativi all'apparato.",
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
        "investigation": "Verificare cablaggio, stato del transceiver e "
                         "contatori di errore della porta. Controllare se la "
                         "caduta coincide con una modifica di configurazione. "
                         "Se la porta è giù per progetto (Loopback, Null, VLAN "
                         "dismessa), confermarla come attesa dal pannello "
                         "interfacce invece di conviverci come rumore.",
        "remediation": "Sostituire il collegamento difettoso o riabilitare la "
                       "porta. Se la caduta si ripete, sospettare duplex "
                       "mismatch o alimentazione PoE insufficiente.",
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
        "investigation": "Nessuna: registra un ripristino. Se il ciclo giù/su si ripete spesso, il vero problema è l'instabilità del collegamento, non la singola caduta.",
        "remediation": "In caso di flapping ripetuto, indagare cablaggio e transceiver invece di considerare l'incidente chiuso.",
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
            {"name": "min_quality", "default": 0.3, "min": 0.0, "max": 1.0,
             "description": "Qualità minima della baseline per fidarsene."},
        ],
        "base_confidence": 55,
        "investigation": "Identificare il processo dietro il volume (backup, "
                         "replica, sincronizzazione). Verificare se il picco è "
                         "East-West o attraversa il firewall, e se coincide con "
                         "una finestra pianificata.",
        "remediation": "Se è un'attività legittima fuori finestra, riprogrammarla. "
                       "Se non è riconducibile a nulla di noto, isolare l'host e "
                       "ispezionare le sessioni attive.",
        "check": _baseline_spike,
    },
    "NEW_TALKER_001": {
        "version": "1.0.0",
        "title": "Host mai osservato prima",
        "description": "Un IP che non ha mai trasmesso nella finestra "
                       "conservata inizia a generare traffico. È un'emergenza, "
                       "non uno scostamento da un'abitudine.",
        "inputs": ["flow.emergence"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_bytes", "default": 10000, "min": 0, "max": 10 ** 12,
             "description": "Volume minimo perché l'apparizione conti."},
        ],
        "base_confidence": 40,
        "investigation": "Risalire a MAC, VLAN e porta dello switch dalla mappa "
                         "client. Verificare se l'IP è nell'inventario, se è un "
                         "rilascio DHCP legittimo o un dispositivo non censito.",
        "remediation": "Se non è censito, registrarlo in inventario o rimuoverlo "
                       "dalla rete. Verificare che la porta di accesso abbia il "
                       "profilo di sicurezza previsto.",
        "check": _new_talker,
    },
    "FLOW_EXPORTER_UNKNOWN_001": {
        "version": "1.0.0",
        "title": "Exporter di flussi fuori inventario",
        "description": "Un exporter invia flussi da un IP non presente in "
                       "inventario e i suoi record vengono scartati. È un "
                       "controllo di salute della piattaforma, non "
                       "un'anomalia della rete: qui SentinelNet osserva sé "
                       "stesso.",
        "inputs": ["platform.exporter_unknown"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_persistence_s", "default": 3600, "min": 0, "max": 604800,
             "description": "Da quanto deve durare la quarantena prima di "
                            "segnalarla: un apparato appena aggiunto e non "
                            "ancora censito è normale per qualche minuto."},
            {"name": "min_packets", "default": 50, "min": 1, "max": 10 ** 9,
             "description": "Pacchetti scartati minimi perché la segnalazione "
                            "valga: qualche datagramma isolato è rumore."},
        ],
        # La più alta del catalogo, e giustificata: le altre regole INFERISCONO
        # qualcosa sulla rete a partire da segnali indiretti. Questa riporta un
        # fatto misurato dalla piattaforma su se stessa — i pacchetti scartati
        # sono stati contati, non stimati. Non c'è margine di errore da scontare.
        "base_confidence": 90,
        "investigation": "Verificare se l'IP appartiene a un apparato "
                         "legittimo non ancora censito, a un apparato che ha "
                         "cambiato indirizzo, oppure a un dispositivo che non "
                         "dovrebbe esportare nulla. Controllare `first_seen` "
                         "per capire se coincide con un intervento recente.",
        "remediation": "Se l'exporter è legittimo, aggiungerlo all'inventario: "
                       "i flussi vengono accettati dal primo pacchetto "
                       "successivo, senza recuperare quelli già persi. Se non "
                       "lo è, bloccarne il traffico verso i listener.",
        "check": _unknown_exporter,
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
            {"name": "min_quality", "default": 0.5, "min": 0.0, "max": 1.0,
             "description": "Qualità minima per ritrattare: più alta che per "
                            "concludere, perché disfare una conclusione su dati "
                            "deboli fa un danno silenzioso."},
            {"name": "window_s", "default": 7200, "min": 60, "max": 86400,
             "description": "Quanto indietro cercare il picco da ritrattare."},
        ],
        "base_confidence": 0,
        "investigation": "Nessuna: questa regola serve a togliere rumore, non a "
                         "segnalarlo. Se la ritrattazione sembra sbagliata, "
                         "controllare qualità e numero di campioni della baseline.",
        "remediation": "Se il picco era invece reale, alzare `min_quality` o "
                       "stringere `normal_band_pct`.",
        "check": _baseline_normal_retracts_spike,
    },
    "IFACE_FLAPPING_001": {
        "version": "1.0.0",
        "title": "Interfaccia instabile (flapping)",
        "description": "Una porta cade e risale ripetutamente nella stessa "
                       "finestra. Il guasto non è la singola caduta ma il "
                       "collegamento instabile, ed è quello che va indagato.",
        "inputs": ["interface.change"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_transitions", "default": 4, "min": 2, "max": 100,
             "description": "Transizioni di link nella finestra di "
                            "correlazione perché sia instabilità e non una "
                            "caduta singola con il suo ripristino. Quattro = "
                            "due cicli completi."},
        ],
        "base_confidence": 70,
        "investigation": "Cablaggio, transceiver e contatori di errore della "
                         "porta — nell'ordine. Verificare se le transizioni "
                         "coincidono con un negoziato di duplex o con "
                         "alimentazione PoE al limite. Non trattare l'ultima "
                         "caduta come l'evento da spiegare.",
        "remediation": "Sostituire il collegamento o il transceiver. Nel "
                       "frattempo, se la porta è in un port-channel, "
                       "disabilitarla è meglio che lasciarla oscillare: un "
                       "membro instabile ricalcola il bundle a ogni "
                       "transizione.",
        "check": _interface_flapping,
    },
    "DEVICE_LOAD_001": {
        "version": "1.0.0",
        "title": "Carico dell'apparato oltre soglia",
        "description": "CPU o memoria sopra la soglia dichiarata. È un "
                       "sintomo da spiegare, non una causa: da solo dice che "
                       "l'apparato è sotto sforzo, non perché.",
        "inputs": ["device.state"],
        "outputs": ["symptom"],
        "parameters": [
            {"name": "max_cpu_pct", "default": 85, "min": 1, "max": 100,
             "description": "Percentuale di CPU oltre la quale segnalare. Si "
                            "considera il core più carico, non la media: su "
                            "uno chassis la media nasconde la scheda satura."},
            {"name": "max_memory_pct", "default": 90, "min": 1, "max": 100,
             "description": "Percentuale di memoria occupata oltre la quale "
                            "segnalare."},
        ],
        "base_confidence": 50,
        "investigation": "Cercare nella stessa finestra un innesco sulla "
                         "stessa entità: picco di traffico, modifica di "
                         "configurazione, interfaccia in flapping. Il carico "
                         "da solo non identifica il processo — su Cisco "
                         "serve `show processes cpu sorted`.",
        "remediation": "Se il carico è causato da traffico legittimo fuori "
                       "finestra, riprogrammarlo. Se non è riconducibile a "
                       "nulla, verificare bug noti della versione firmware "
                       "prima di sostituire l'apparato.",
        "check": _device_load,
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
            # 0/1 e non booleano: ``params_for`` accetta solo numeri e scarta
            # esplicitamente i bool, perché una soglia deve restare confrontabile
            # con il proprio min/max.
            {"name": "include_control_plane", "default": 0, "min": 0, "max": 1,
             "description": "1 per includere nel confronto anche il traffico "
                            "verso multicast e broadcast (protocolli di "
                            "scoperta e routing). Di norma va escluso: è la "
                            "maggioranza dei bucket e non è una conversazione "
                            "fra due host."},
        ],
        "base_confidence": 50,
        "investigation": "Confrontare con la baseline storica prima di agire: "
                         "questo confronto guarda solo dentro la finestra "
                         "corrente e non conosce le abitudini del talker.",
        "remediation": "Nessun intervento diretto: usare l'evidenza come "
                       "contesto per l'innesco principale dell'incidente.",
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
