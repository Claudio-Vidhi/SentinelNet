# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
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
                 "src_ip", "dst_ip", "switch_port", "summary", "attrs", "key",
                 "interface")

    def __init__(self, event_id, ts, tenant, role, entity_key, summary,
                 severity=None, src_ip=None, dst_ip=None, switch_port=None,
                 attrs=None, key=None, interface=None):
        assert role in ROLES, f"ruolo non ammesso: {role}"
        # ``key``: discriminante quando la STESSA regola trae più conclusioni
        # distinte dallo STESSO evento (CPU e memoria dallo stesso snapshot).
        # Senza, la deduplica le considera un doppione e ne perde una. È la
        # regola a dichiararlo, perché è l'unica a sapere di aver risposto a
        # due domande diverse.
        self.key = key
        # Quale porta riguarda, quando ne riguarda una: senza, una manutenzione
        # su una singola interfaccia non sarebbe distinguibile da una
        # sull'intero apparato.
        self.interface = interface
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


# Roadmap §1, voce 3: "conferma prima di concludere". Ogni regola la dichiara
# con UN parametro in piu', invece di una macchina a stati HARD/SOFT alla
# Nagios -- il catalogo e' gia' il posto dove una regola dice come ragiona.
#
# Un'osservazione e' un EVENTO distinto, non un ciclo: il correlatore rivaluta
# l'intera finestra a ogni giro, quindi lo stesso fatto ricompare a ogni ciclo
# finche' resta nella finestra, e contarlo per cicli confermerebbe un singolo
# datagramma a forza di rileggerlo.
#
# Default 1: e' il comportamento di prima, identico. Alzarlo e' una scelta
# dell'amministratore, regola per regola, dal pannello soglie che esiste gia'.
CONFIRMATION_PARAM = "min_observations"
_CONFIRMATION_SPEC = {
    "name": CONFIRMATION_PARAM, "default": 1, "min": 1, "max": 20,
    "description": "Eventi distinti che la regola deve vedere nella finestra "
                   "prima di produrre un'evidenza. 1 = conclude alla prima "
                   "osservazione. Alzarlo evita di concludere su un fatto "
                   "isolato: una conclusione notificata non si ritira.",
}
_CONFIRMATION_DESCRIPTION_EN = (
    "Distinct events the rule must see within the window before producing "
    "evidence. 1 = concludes on the first observation. Raising it avoids "
    "concluding on an isolated fact: a notified conclusion cannot be taken back.")


def parameter_specs(rule_id: str) -> list:
    """Soglie dichiarate da una regola: [{name, default, min, max, description}].

    Include sempre ``min_observations``, dichiarato una volta sola qui e non
    ripetuto in ogni regola."""
    declared = (RULES.get(rule_id) or {}).get("parameters")
    specs = list(declared) if isinstance(declared, list) else []
    if rule_id in RULES and not any(isinstance(p, dict)
                                    and p.get("name") == CONFIRMATION_PARAM
                                    for p in specs):
        specs.append(dict(_CONFIRMATION_SPEC))
    return specs


def min_observations(rule_id: str) -> int:
    return int(params_for(rule_id).get(CONFIRMATION_PARAM, 1))


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


RULES_EN = {
    "BLOCKED_TRAFFIC_001": {
        "title": "Repeatedly blocked traffic",
        "description": "The firewall logs several blocks from the same source within the window.",
        "investigation": "Verify if the block is expected by policy or if a legitimate service was blocked by mistake. Check the client switch port and whether attempts repeat toward different destinations.",
        "remediation": "If traffic is legitimate, update the firewall rule. If not, isolate the host and check for malware.",
        "parameters": {
            "min_observations": "Distinct block logs from the same source within the window before concluding. A single block is noise: a firewall denies all the time.",
        },
    },
    "HIGH_SEVERITY_LOG_001": {
        "title": "High severity event log",
        "description": "A log event severe enough to emerge on its own.",
        "investigation": "Read the full device message and correlate with any configuration changes or reboots in the same time window.",
        "remediation": "Intervene according to the reported device error; if recurring, investigate hardware health or firmware version.",
        "parameters": {
            "max_severity": "Maximum syslog severity considered (0 = emerg).",
        },
    },
    "CFG_CHANGE_001": {
        "title": "Configuration or state change",
        "description": "Something changed on a device: subsequent events should be evaluated in this context.",
        "investigation": "Identify who made the change and whether it was scheduled. Compare the changed field with the previous configuration backup.",
        "remediation": "If the change was unauthorized, restore from backup and verify administrative access to the device.",
        "parameters": {},
    },
    "IFACE_DOWN_001": {
        "title": "Interface down",
        "description": "A port transitioned to down: observed state symptom, not root cause.",
        "investigation": "Inspect cabling, transceiver optics, and port error counters. Check if the link drop coincided with a configuration change. If the port is down by design (Loopback, Null, decommissioned VLAN), confirm it as expected in the interfaces panel instead of treating it as noise.",
        "remediation": "Replace the faulty link or re-enable the port. If link drop recurs, investigate duplex mismatch or insufficient PoE power.",
        "parameters": {},
    },
    "IFACE_RECOVERED_001": {
        "title": "Interface recovered (retracts symptom)",
        "description": "Port link returned up: retracts interface down evidence without deleting it.",
        "investigation": "None: records recovery. If down/up cycles repeat frequently, the real issue is link flapping, not a single drop.",
        "remediation": "In case of repeated flapping, investigate cabling and transceiver optics rather than considering the incident closed.",
        "parameters": {
            "window_s": "Lookback window to find the symptom to retract.",
        },
    },
    "FLOW_EXPORTER_UNKNOWN_001": {
        "title": "Uninventoried syslog sender",
        "description": "A device is sending syslog from an IP not present in inventory and its messages are discarded. Platform health monitoring.",
        "investigation": "Verify if the IP belongs to a legitimate uninventoried device, a device with a changed address, or an unintended exporter. Check `first_seen` for recent activity.\nFIRST OF ALL: Is the reported IP the SERVER itself, or a router/gateway? Then it is NAT rewriting the source IP along the path. Compare with server local IPs and listener bind addresses.",
        "remediation": "If the IP is rewritten by NAT, bind listeners to the interface reached directly and point export to THAT address. Only this way does the source IP remain that of the device.\nDO NOT add the NAT IP to inventory: it would attribute all exporter traffic to a non-existent device.\nIf the exporter is legitimate, add it to inventory. If not, block its traffic to the listeners.",
        "parameters": {
            "min_persistence_s": "Quarantine duration before alerting: newly added devices are normal for a few minutes.",
            "min_packets": "Minimum dropped packets threshold to trigger an alert.",
        },
    },
    "IFACE_FLAPPING_001": {
        "title": "Unstable flapping interface",
        "description": "A port transitions down and up repeatedly in the same window, indicating link instability.",
        "investigation": "Inspect cabling, transceiver optics, and port error counters. Check for duplex negotiation failures or PoE power budget limits. Do not treat the last drop as the primary event.",
        "remediation": "Replace cable or transceiver. In a port-channel, disable the flapping member to prevent frequent bundle recalculations.",
        "parameters": {
            "min_transitions": "Link transition count in correlation window required to qualify as flapping (4 = two full cycles).",
        },
    },
    "BLAST_RADIUS_001": {
        "title": "Several clients blocked towards the same destination",
        "description": "Traffic towards one service is being blocked for several distinct clients. It is not a client's problem: it is the destination, or the policy in front of it.",
        "investigation": "Start from the destination, not from the first client who called: did the policy covering that service change recently? Is the service down and the firewall answering with a reset? Do the clients share something (same VLAN, same site) that sets them apart from those who do get through?",
        "remediation": "Fix the policy or restore the service. The per-client conclusions of BLOCKED_TRAFFIC_001 close by themselves once traffic resumes.",
        "parameters": {
            "min_sources": "Distinct clients blocked towards the same destination and port for it to be a service problem rather than a client's. Two can be a coincidence; three is already a pattern.",
        },
    },
    "DEVICE_UNREACHABLE_001": {
        "title": "Device no longer reachable",
        "description": "A device that was answering the poller has stopped for several consecutive rounds. Before this, it produced nothing: silence was not a fact.",
        "investigation": "Path first, then the device: are other devices behind the same uplink silent in the same window? Then it is the link, not the node. If it is alone, check power and console. A recent change to the SNMP ACL produces the same silence with nothing actually down.",
        "remediation": "Restore the link or the device. If the SNMP ACL was changed, re-admit the collector: otherwise the device will read as down on every round.",
        "parameters": {
            "min_silent_rounds": "Consecutive silent polling rounds, after the last answer, before concluding. One is not enough: on UDP a lost datagram is normal, and a notified conclusion cannot be taken back.",
        },
    },
    "IFACE_ERRORS_001": {
        "title": "Rising error counters on a port",
        "description": "An interface error counter keeps rising within the window. A physical-layer fault that degrades without dropping the link, so it produces no transition to observe.",
        "investigation": "Cable, transceiver optics, and duplex negotiation, in that order. Inbound-only errors point at the remote side or the medium; outbound errors point at congestion or a duplex mismatch. Compare with the port at the other end: only one side counting errors narrows it down immediately.",
        "remediation": "Replace the cable or the transceiver. If the errors are outbound only and rise with traffic it is not a fault to replace: it is congestion, and it is fixed on link capacity.",
        "parameters": {
            "min_errors": "Errors accumulated within the window to qualify as a fault rather than the noise floor of a copper link. The delta between first and last sample is used: the counters are cumulative, so the absolute value of a switch up for two years says nothing.",
        },
    },
    "DEVICE_LOAD_001": {
        "title": "Device resource load over threshold",
        "description": "CPU, memory, or disk exceeded threshold. Indicates high resource strain, not root cause.",
        "investigation": "Search the same window for entity triggers: traffic spike, config change, flapping interface. Check active process list (on Cisco: `show processes cpu sorted`).",
        "remediation": "Reschedule if caused by legitimate heavy jobs. Otherwise, check for firmware memory leaks or software bugs before replacing hardware.",
        "parameters": {
            "max_cpu_pct": "CPU threshold percentage. Evaluates highest single core load rather than average.",
            "max_memory_pct": "Memory utilization threshold percentage.",
            "max_disk_pct": "Root filesystem disk utilization threshold percentage (Linux hosts).",
        },
    },
}


def catalog(lang: str = "it") -> list:
    """Il motore descrive se stesso: la UI costruisce il pannello soglie da
    qui, l'assistente AI sa quali regole esistono e la documentazione deriva
    dal codice. Una sola fonte di verità."""
    is_en = str(lang).lower().startswith("en")
    out = []
    for rule_id, rule in RULES.items():
        tr = (RULES_EN.get(rule_id) or {}) if is_en else {}
        param_tr = tr.get("parameters") or {}
        specs = []
        for p in parameter_specs(rule_id):
            spec = dict(p)
            if is_en and p["name"] in param_tr:
                spec["description"] = param_tr[p["name"]]
            elif is_en and p["name"] == CONFIRMATION_PARAM:
                spec["description"] = _CONFIRMATION_DESCRIPTION_EN
            specs.append(spec)

        out.append({
            "id": rule_id,
            "version": rule["version"],
            "title": tr.get("title") or rule["title"],
            "description": tr.get("description") or rule["description"],
            "inputs": list(rule["inputs"]),
            "outputs": list(rule["outputs"]),
            "base_confidence": rule.get("base_confidence"),
            "investigation": tr.get("investigation") or rule.get("investigation"),
            "remediation": tr.get("remediation") or rule.get("remediation"),
            "parameters": specs,
            "effective": params_for(rule_id),
        })
    return out


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
    """Blocked traffic from the firewall's own log.

    Flow corroboration is gone with the flow collectors. Precision now comes
    from repetition instead: the rule declares its own ``min_observations``
    (default 3), so a single deny line does not open an incident — the same
    source has to be blocked several times in the window.
    """
    out = []
    for ev in events:
        if ev["event_type"] != "log.security":
            continue
        if not (ev["src_ip"] and ev["dst_ip"]):
            continue
        attrs = json.loads(ev["attrs_json"] or "{}")
        action = str(attrs.get("action") or "").lower()
        if action and action not in ("deny", "drop", "block", "close", "reject", "reset"):
            continue
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="trigger",
            entity_key=f"ip:{ev['src_ip']}", severity=ev["severity"],
            src_ip=ev["src_ip"], dst_ip=ev["dst_ip"],
            summary=f"Traffico bloccato {endpoints.describe(ev['src_ip'])} → "
                    f"{endpoints.describe(ev['dst_ip'])}",
            attrs={"action": attrs.get("action")}))
    return out


def _high_severity_log(events: list, p: dict) -> list:
    """Log ad alta severità: emerge da solo, anche senza
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
            interface=ev["interface"],
            summary=f"Modifica su {where}: {attrs.get('field')} "
                    f"{attrs.get('before')} → {attrs.get('after')}",
            attrs=attrs))
    return out


# ifOperStatus, in the words the SNMP poller translates it to
# (_IF_STATUS there). Two lists, not one list and an else: "up" is the only
# value that means the port carries traffic, three others are faults, and what
# is left -- dormant, testing, unknown, a missing field -- is neither. Deciding
# the leftovers by falling through to one side is what made a port whose
# transceiver had been pulled read as operational.
#
# routers/incidents.py imports these: the classifier that fills the Interfaces
# tab and the rule that raises the incident must not drift apart.
LINK_UP = frozenset({"up", "1", "true"})
LINK_DOWN = frozenset({"down", "0", "false", "lowerlayerdown", "notpresent"})
ADMIN_DOWN = frozenset({"down", "0", "false", "admin_down",
                        "administratively down"})


def _interface_down(events: list, p: dict) -> list:
    """Interfaccia passata a down: sintomo osservato sullo stato, non causa."""
    out = []
    for ev in events:
        if ev["event_type"] != "interface.change":
            continue
        attrs = json.loads(ev["attrs_json"] or "{}")
        if str(attrs.get("after")).lower() not in LINK_DOWN:
            continue
        if "link" not in str(attrs.get("field", "")).lower() \
                and "status" not in str(attrs.get("field", "")).lower():
            continue
        # Uno shutdown amministrativo è una decisione intenzionale, non un guasto
        admin_st = str(attrs.get("admin_status") or "").lower()
        if admin_st in ADMIN_DOWN:
            continue
        out.append(Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"], role="symptom",
            entity_key=f"ip:{ev['device_ip']}", severity=ev["severity"],
            interface=ev["interface"],
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
    max_span = p.get("max_span_s", 3600)
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
        # Limita alla finestra temporale recente per non allarmare su transizioni distanziate di giorni
        recent = [e for e in seen if seen[-1]["ts"] - e["ts"] <= max_span]
        if len(recent) < p["min_transitions"]:
            continue
        span = recent[-1]["ts"] - recent[0]["ts"]
        out.append(Finding(
            event_id=recent[-1]["id"], ts=recent[-1]["ts"], tenant=tenant,
            role="trigger", entity_key=f"ip:{device_ip}", severity=3,
            # Due porte instabili sullo stesso apparato sono due conclusioni.
            key=f"flap:{interface}", interface=interface,
            summary=f"Interfaccia {interface} instabile: {len(recent)} "
                    f"transizioni in {max(span // 60, 1)} minuti",
            attrs={"interface": interface, "transitions": len(recent),
                   "span_s": span}))
    return out


def _blast_radius(events: list, p: dict) -> list:
    """"E' solo mio?" -- piu' client bloccati verso la STESSA destinazione.

    Una conclusione per client (``BLOCKED_TRAFFIC_001``) risponde a "perche'
    IO non arrivo?", non a "anche gli altri non arrivano?". Sono due guasti
    diversi: il primo e' un client, il secondo e' un servizio o una policy, e
    chi lo indaga partendo dal primo client perde tempo sul posto sbagliato.

    La chiave e' la DESTINAZIONE (``dst:<ip>:<porta>``), scelta dell'utente: e'
    la domanda come la fa chi chiama l'helpdesk, e funziona con qualunque
    firewall che logghi i blocchi. La chiave per policy esisterebbe solo dove
    i log portano un policyid, cioe' in pratica su FortiGate.

    Blocks are classified by ``BLOCKED_TRAFFIC_001``'s own logic, called
    rather than duplicated, so the two rules agree on what "blocked" means.
    Its repetition threshold does not apply here: ``min_sources`` distinct
    clients is already the corroboration.
    """
    by_id = {e["id"]: e for e in events}
    blocked = _blocked_traffic(events, params_for("BLOCKED_TRAFFIC_001"))
    groups: dict = {}
    for f in blocked:
        if f.role != "trigger" or not f.dst_ip or not f.src_ip:
            continue
        ev = by_id.get(f.event_id) or {}
        attrs = json.loads(ev.get("attrs_json") or "{}")
        port = attrs.get("dst_port") or attrs.get("dport") or ev.get("dst_port")
        key = (f.tenant, f.dst_ip, str(port) if port not in (None, "") else "")
        groups.setdefault(key, {"sources": set(), "last": f})
        groups[key]["sources"].add(f.src_ip)
        if f.ts >= groups[key]["last"].ts:
            groups[key]["last"] = f

    out = []
    for (tenant, dst_ip, port), g in groups.items():
        sources = g["sources"]
        if len(sources) < p["min_sources"]:
            continue
        last = g["last"]
        target = f"{dst_ip}:{port}" if port else dst_ip
        out.append(Finding(
            event_id=last.event_id, ts=last.ts, tenant=tenant,
            role="trigger", entity_key=f"dst:{target}", severity=3,
            dst_ip=dst_ip,
            summary=f"{len(sources)} client bloccati verso "
                    f"{endpoints.describe(dst_ip)}"
                    + (f" porta {port}" if port else ""),
            # Un campione limitato e ordinato: cento indirizzi in un'evidenza
            # non si leggono, e l'ordine stabile rende confrontabili due cicli.
            attrs={"sources": len(sources),
                   "sample": sorted(sources)[:10],
                   "dst_port": port or None,
                   "threshold": p["min_sources"]}))
    return out


def _device_unreachable(events: list, p: dict) -> list:
    """Un apparato che rispondeva e ha smesso.

    Prima il silenzio non era un fatto: ``_poll_device`` tornava una lista
    vuota e il giro passava oltre. Nessun evento, nessuna regola poteva
    vederlo, e l'unico segno di un apparato caduto era l'assenza di dati
    nuovi -- che nessuna schermata mostra.

    DUE condizioni, entrambe necessarie:

    - **PRIMA rispondeva.** Serve un ``device.state`` nella finestra. Un
      apparato mai raggiunto perche' una ACL non contempla il collector non
      e' "caduto", e sarebbe il caso piu' comune: su UDP il silenzio e' la
      norma, non l'eccezione. Senza questa condizione la regola aprirebbe un
      incidente per ogni apparato con SNMP filtrato, per sempre.
    - **Piu' giri muti DI FILA dopo l'ultima risposta.** E' "conferma prima di
      concludere" (roadmap §1, voce 3) applicata dove conta di piu': un
      datagramma perso non deve svegliare nessuno alle tre di notte, e una
      conclusione non si ritira dopo averla notificata.

    Si conta solo cio' che viene DOPO l'ultima risposta: un apparato che ha
    saltato un giro e poi ha ripreso non ha giri muti pendenti, anche se nella
    finestra ce ne sono stati.
    """
    per_device: dict = {}
    for ev in events:
        if ev["event_type"] not in ("device.state", "device.unreachable")                 or not ev["device_ip"]:
            continue
        per_device.setdefault((ev["tenant"], ev["device_ip"]), []).append(ev)

    out = []
    for (tenant, device_ip), seen in per_device.items():
        seen.sort(key=lambda e: (e["ts"], e["id"]))
        answered = [i for i, e in enumerate(seen)
                    if e["event_type"] == "device.state"]
        if not answered:
            continue                      # mai risposto: non e' "caduto"
        silent_after = [e for e in seen[answered[-1] + 1:]
                        if e["event_type"] == "device.unreachable"]
        if len(silent_after) < p["min_silent_rounds"]:
            continue
        last_ok = seen[answered[-1]]
        last = silent_after[-1]
        out.append(Finding(
            event_id=last["id"], ts=last["ts"], tenant=tenant,
            role="trigger", entity_key=f"ip:{device_ip}", severity=2,
            key="unreachable",
            summary=f"{device_ip} non risponde da {len(silent_after)} giri "
                    f"di polling consecutivi",
            attrs={"silent_rounds": len(silent_after),
                   "last_answer_ts": last_ok["ts"],
                   "threshold": p["min_silent_rounds"]}))
    return out


def _interface_errors(events: list, p: dict) -> list:
    """Errori in CRESCITA su una porta.

    ``in_errors``/``out_errors`` erano raccolti dal poller SNMP e li leggeva
    solo la diagnosi di un client, su richiesta: nessuna regola li guardava,
    quindi una porta che accumulava errori non diceva niente a nessuno finche'
    qualcuno non andava a cercarla.

    Si guarda la DIFFERENZA fra il primo e l'ultimo campione della finestra,
    non il valore assoluto: sono contatori cumulativi, e uno switch acceso da
    due anni ha errori diversi da zero senza che significhi nulla. Un solo
    campione non e' quindi valutabile, e va lasciato cadere invece di essere
    confrontato con la soglia.

    Il riavvio dell'apparato azzera i contatori: la differenza diventa
    negativa e resta sotto soglia da se', senza un caso speciale.

    Ruolo ``trigger`` e non ``symptom``: come per il flapping, il guasto e'
    fisico e la regola sa dire di che classe e'. Quale dei tre candidati sia
    (cavo, ottica, negoziato di duplex) non lo sa, e lo dice
    nell'investigazione invece di indovinarlo.
    """
    per_iface: dict = {}
    for ev in events:
        if ev["event_type"] != "interface.state" or not ev["interface"]:
            continue
        # metrics_json e non attrs_json: i contatori sono MISURE, e gli attrs
        # di uno snapshot interfacce escludono per progetto tutto cio' che
        # cambia a ogni lettura (vedi normalize._stable_fields).
        measured = json.loads(ev["metrics_json"] or "{}")
        total, seen_any = 0, False
        for field in ("in_errors", "out_errors"):
            value = measured.get(field)
            # Assente non e' zero: una porta che non espone il contatore non
            # deve sembrare pulita.
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                total += int(value)
                seen_any = True
        if seen_any:
            per_iface.setdefault(
                (ev["tenant"], ev["device_ip"], ev["interface"]), []).append((ev, total))

    out = []
    for (tenant, device_ip, interface), samples in per_iface.items():
        if len(samples) < 2:
            continue
        delta = samples[-1][1] - samples[0][1]
        if delta < p["min_errors"]:
            continue
        last_ev = samples[-1][0]
        span = last_ev["ts"] - samples[0][0]["ts"]
        out.append(Finding(
            event_id=last_ev["id"], ts=last_ev["ts"], tenant=tenant,
            role="trigger", entity_key=f"ip:{device_ip}", severity=4,
            # Due porte con errori sullo stesso apparato sono due conclusioni,
            # come per il flapping.
            key=f"errors:{interface}", interface=interface,
            summary=f"Interfaccia {interface}: {delta} errori in "
                    f"{max(span // 60, 1)} minuti",
            attrs={"interface": interface, "errors_delta": delta,
                   "span_s": span, "threshold": p["min_errors"]}))
    return out


def _device_load(events: list, p: dict) -> list:
    """Carico dell'apparato oltre soglia: CPU, memoria o disco.

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
                                    ("memory_pct", p["max_memory_pct"], "Memoria"),
                                    ("disk_pct", p["max_disk_pct"], "Disco")):
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
        if str(attrs.get("after")).lower() not in LINK_UP:
            continue
        witness = Finding(
            event_id=ev["id"], ts=ev["ts"], tenant=ev["tenant"],
            role="consequence", entity_key=f"ip:{ev['device_ip']}",
            interface=ev["interface"],
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
        # 2.0.0: syslog only. The flow corroboration (1.x) went with the flow
        # collectors; repetition (min_observations) replaces it.
        "version": "2.0.0",
        "title": "Traffico bloccato ripetutamente",
        "description": "Il firewall registra più blocchi della stessa "
                       "sorgente nella finestra.",
        "inputs": ["log.security"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_observations", "default": 3, "min": 1, "max": 20,
             "description": "Log di blocco distinti della stessa sorgente "
                            "nella finestra prima di concludere. Un blocco "
                            "isolato è rumore: un firewall nega di continuo."},
        ],
        "base_confidence": 65,
        "investigation": 'Verificare se il blocco è atteso dalla policy o se un servizio legittimo è stato bloccato per errore. Controllare la porta dello switch del client e se il tentativo si ripete verso destinazioni diverse.',
        "remediation": "Se il traffico è legittimo, correggere la regola di firewall. Se non lo è, isolare l'host e verificare la presenza di malware.",
        "check": _blocked_traffic,
    },
    "HIGH_SEVERITY_LOG_001": {
        "version": "1.0.0",
        "title": "Log ad alta severità",
        "description": "Un log abbastanza grave da emergere da solo.",
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
    "FLOW_EXPORTER_UNKNOWN_001": {
        "version": "1.0.0",
        "title": "Mittente syslog fuori inventario",
        "description": "Un apparato invia syslog da un IP non presente in "
                       "inventario e i suoi messaggi vengono scartati. È un "
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
                         "per capire se coincide con un intervento recente.\n"
                         "PRIMA DI TUTTO: l'IP segnalato è quello del SERVER "
                         "stesso, o di un router/gateway? Allora non è "
                         "l'exporter — è un NAT che ne ha riscritto l'indirizzo "
                         "sorgente lungo il percorso. Succede sempre quando "
                         "l'apparato sta dietro un NAT (una VM su rete NAT che "
                         "invia all'IP esterno dell'host, o una sede dietro un "
                         "router che fa masquerade): l'IP vero non arriva mai al "
                         "collector. Confrontare l'IP con gli indirizzi locali "
                         "del server e con l'indirizzo di bind dei listener.",
        "remediation": "Se l'IP segnalato è il risultato di un NAT, la "
                       "soluzione è far arrivare i pacchetti SENZA attraversarlo: "
                       "mettere i listener in ascolto sull'interfaccia che "
                       "l'apparato raggiunge direttamente (bind su tutte le "
                       "interfacce, se ce n'è più di una) e puntare l'export a "
                       "QUELL'indirizzo. Solo così l'IP sorgente resta quello "
                       "dell'apparato.\n"
                       "NON aggiungere l'IP riscritto dal NAT all'inventario: "
                       "attribuirebbe i messaggi di tutti gli apparati dietro quel "
                       "NAT a un dispositivo che non esiste, e li renderebbe "
                       "visibili al tenant sbagliato — è esattamente il danno che "
                       "lo scarto serve a evitare (ADR-0005).\n"
                       "Se invece l'exporter è legittimo e semplicemente non "
                       "censito, aggiungerlo all'inventario: i messaggi vengono "
                       "accettati dal primo pacchetto successivo, senza "
                       "recuperare quelli già persi. Se non lo è, bloccarne il "
                       "traffico verso i listener.",
        "check": _unknown_exporter,
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
    "BLAST_RADIUS_001": {
        # 2.0.0: counts block logs without flow corroboration.
        "version": "2.0.0",
        "title": "Piu' client bloccati verso la stessa destinazione",
        "description": "Il traffico verso uno stesso servizio viene bloccato "
                       "per piu' client distinti. Non e' un problema di un "
                       "client: e' la destinazione, o la policy davanti.",
        "inputs": ["log.security"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_sources", "default": 3, "min": 2, "max": 1000,
             "description": "Client distinti bloccati verso la stessa "
                            "destinazione e porta perche' sia un problema del "
                            "servizio e non di un client. Due puo' essere una "
                            "coincidenza; tre e' gia' un andamento."},
        ],
        "base_confidence": 70,
        "investigation": "Partire dalla destinazione, non dal primo client "
                         "che ha chiamato: la policy che copre quel servizio "
                         "e' cambiata di recente? Il servizio e' giu' e il "
                         "firewall risponde con un reset? I client hanno "
                         "qualcosa in comune (stessa VLAN, stessa sede) che "
                         "li distingue da chi invece arriva?",
        "remediation": "Correggere la policy o ripristinare il servizio. Le "
                       "conclusioni per singolo client di BLOCKED_TRAFFIC_001 "
                       "si chiudono da sole quando il traffico riprende.",
        "check": _blast_radius,
    },
    "DEVICE_UNREACHABLE_001": {
        "version": "1.0.0",
        "title": "Apparato non piu' raggiungibile",
        "description": "Un apparato che rispondeva al polling ha smesso di "
                       "farlo per piu' giri consecutivi. Prima questo non "
                       "produceva nulla: il silenzio non era un fatto.",
        "inputs": ["device.state", "device.unreachable"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_silent_rounds", "default": 3, "min": 1, "max": 100,
             "description": "Giri di polling muti consecutivi, dopo l'ultima "
                            "risposta, prima di concludere. Uno solo non "
                            "basta: su UDP un datagramma perso e' la norma, e "
                            "una conclusione notificata non si ritira."},
        ],
        "base_confidence": 75,
        "investigation": "Prima il percorso, poi l'apparato: la stessa "
                         "finestra ha altri apparati muti dietro lo stesso "
                         "uplink? Allora e' il collegamento, non il nodo. Se "
                         "e' solo, controllare alimentazione e console. Un "
                         "cambio recente della ACL SNMP produce lo stesso "
                         "silenzio senza che nulla sia caduto.",
        "remediation": "Ripristinare il collegamento o l'apparato. Se e' "
                       "stata cambiata la ACL SNMP, riammettere il collector: "
                       "altrimenti l'apparato risultera' caduto a ogni giro.",
        "check": _device_unreachable,
    },
    "IFACE_ERRORS_001": {
        "version": "1.0.0",
        "title": "Errori in crescita su una porta",
        "description": "I contatori di errore di un'interfaccia crescono "
                       "nella finestra. E' un guasto del livello fisico che "
                       "degrada senza far cadere il link, quindi non produce "
                       "nessuna transizione da vedere.",
        "inputs": ["interface.state"],
        "outputs": ["trigger"],
        "parameters": [
            {"name": "min_errors", "default": 100, "min": 1, "max": 1000000,
             "description": "Errori accumulati nella finestra perche' sia un "
                            "guasto e non il fondo di rumore di un "
                            "collegamento in rame. Si conta la differenza fra "
                            "primo e ultimo campione: i contatori sono "
                            "cumulativi, e il valore assoluto di uno switch "
                            "acceso da due anni non dice niente."},
        ],
        "base_confidence": 60,
        "investigation": "Cavo, ottica e negoziato di duplex, nell'ordine. "
                         "Errori solo in ingresso indicano il lato remoto o il "
                         "mezzo; errori in uscita indicano congestione o "
                         "duplex disallineato. Confrontare con la porta "
                         "all'altro capo: un solo lato che conta errori "
                         "restringe subito il campo.",
        "remediation": "Sostituire il collegamento o il transceiver. Se gli "
                       "errori sono solo in uscita e crescono col traffico, "
                       "non e' un guasto da sostituire: e' congestione, e si "
                       "risolve sulla capacita' del collegamento.",
        "check": _interface_errors,
    },
    "DEVICE_LOAD_001": {
        "version": "1.0.0",
        "title": "Carico dell'apparato oltre soglia",
        "description": "CPU, memoria o disco sopra la soglia dichiarata. È un "
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
            {"name": "max_disk_pct", "default": 90, "min": 1, "max": 100,
             "description": "Percentuale di occupazione del filesystem di "
                            "radice oltre la quale segnalare. La misura arriva "
                            "dagli host Linux interrogati dal poller."},
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
