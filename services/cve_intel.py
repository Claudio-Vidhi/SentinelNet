# -*- coding: utf-8 -*-
"""Correlazione CVE: snapshot persistito, confidenza del match, punteggio.

Il vincolo che decide tutto: **il motore non dice mai "non impattato"**.
Nessun CVE viene mai rimosso dalla lista, i segnali spostano soltanto la
posizione, e ogni verdetto porta con se' l'elenco di cio' che NON e' stato
valutato. Un falso positivo costa dieci minuti di verifica; un falso negativo
e' un apparato bucato con scritto "a posto".

Design: docs/superpowers/specs/2026-09-09-cve-correlation-design.md (F1, F2,
F3, F5, F8, F9, F9b).
"""

import json
import logging
import os
from datetime import datetime, timezone

import requests

from core import data_config
from services import nvd
from services.config_drift import history

log = logging.getLogger("sentinelnet.cve")

SNAPSHOT_SUFFIX = "-cve_snapshot.json"

# Quanto puo' invecchiare uno snapshot prima di essere riscaricato. NVD non
# cambia cosi' in fretta da giustificare di piu', e i rate limit sono reali.
DEFAULT_MAX_AGE_H = 24

# Oltre una settimana la lettura di versione descrive una rete che potrebbe non
# esistere piu'. Stessa soglia dell'eta' del backup (static/js/core.js).
STALE_HOURS = 168

# Quanti CVE tenere per apparato. NVD non ordina per gravita': si prende la
# coda piu' RECENTE dell'elenco (vedi _fetch_cves).
MAX_CVES = 200

# Cio' che questo motore non guarda. Finche' F6/F7 (raggiungibilita') non
# esistono la lista non e' mai vuota: un punteggio senza perimetro viene letto
# come completo, e un ordinamento letto come completo diventa un verdetto
# negativo per gli elementi in fondo alla lista.
NOT_EVALUATED = ("reachability", "switch_acls", "vrf", "physical_access")

# Un CVE trovato per parole chiave e uno trovato per CPE esatto non possono
# valere uguale.
CONFIDENCE_FACTOR = {"exact": 1.0, "product": 0.8, "keyword": 0.5}

# Il segnale dei servizi e' un moltiplicatore, non un addendo: cosi' un CVE
# 'keyword' non puo' in nessun caso scavalcare un 'exact' di pari CVSS
# (0.5 * 1.15 = 0.575 sta sempre sotto 1.0 * 0.85 = 0.85).
SERVICE_FACTOR = {"enabled": 1.15, "disabled": 0.85, "unknown": 1.0}

# Parole con cui il testo NVD nomina un servizio. Deterministico e grossolano:
# quando non riconosce nulla la lista resta vuota e il CVE non viene toccato.
_CVE_SERVICE_WORDS = {
    "snmp": ("snmp",),
    "ssh": ("ssh",),
    "telnet": ("telnet",),
    "http": ("http", "https", "web ui", "web interface", "web-based management"),
}


# --- Snapshot su disco (F1) -------------------------------------------------

def snapshot_path(device: dict) -> str:
    """Accanto all'archivio di configurazione dell'apparato.

    Il design lo chiama `<device_dir>/cve_snapshot.json`; la cartella e' per
    gruppo/vendor e ospita piu' apparati, quindi il nome porta l'IP davanti
    come gia' fa l'indice della history.
    """
    from core import core_engine
    folder = core_engine.group_backup_dir(device.get("Group") or "Generale",
                                          device.get("Vendor") or "")
    return os.path.join(folder, f"{device['IP']}{SNAPSHOT_SUFFIX}")


def load(device: dict) -> dict:
    """Lo snapshot dell'apparato, o {} se non e' mai stato scaricato."""
    try:
        with open(snapshot_path(device), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(device: dict, snapshot: dict) -> None:
    # Uno snapshot troncato a meta' e' peggio di uno assente, perche' sembra
    # valido: la scrittura e' atomica.
    data_config.atomic_write(snapshot_path(device), snapshot)


def max_age_hours() -> int:
    from core import app_settings
    env_val = os.environ.get("SENTINELNET_CVE_MAX_AGE_H")
    if env_val is not None:
        raw = env_val
    else:
        settings = app_settings.get_app_settings()
        app_sec = settings.get("app") if isinstance(settings.get("app"), dict) else {}
        raw = app_sec.get("cve_max_age_h", settings.get("cve_max_age_h"))
    try:
        return int(raw) if raw is not None else DEFAULT_MAX_AGE_H
    except (TypeError, ValueError):
        return DEFAULT_MAX_AGE_H


# --- Eta' del dato (F2) -----------------------------------------------------

def _parse_stamp(stamp: str):
    """Il timestamp basic ISO usato in tutto l'archivio -> datetime UTC."""
    if not stamp:
        return None
    try:
        return datetime.strptime(stamp, "%Y%m%dT%H%M%S.%f%z")
    except ValueError:
        return None


def version_seen_at_of(device: dict, snapshot: dict) -> str:
    """Quando e' stata letta la versione su cui poggia lo snapshot.

    Il ripiego sulla data del backup vale anche in LETTURA, non solo quando lo
    snapshot viene riscritto: gli snapshot gia' su disco non hanno il campo, e
    aspettare che ognuno venga riscaricato significherebbe una colonna che dice
    "eta' ignota" per un giorno intero. Versione e configurazione si leggono
    nello stesso giro, quindi e' la stessa data.
    """
    return snapshot.get("version_seen_at") or history.last_seen_at(device)


def age_hours(stamp: str):
    """Ore trascorse da `stamp`, o None se il timestamp manca o non si legge."""
    dt = _parse_stamp(stamp)
    if dt is None:
        return None
    return (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0


# --- Confidenza del match (F3) ----------------------------------------------

def query_for(device: dict, version_text: str) -> dict:
    """Con che identita' si interroga NVD, e quanto ci si puo' fidare.

    `cpe_match_string` gia' distingue i casi ma butta via l'informazione:
    ritorna None quando il vendor non ha identita' CPE e il chiamante ripiega
    su una ricerca testuale, senza che il risultato porti traccia della
    differenza. Qui la differenza viene salvata.
    """
    from drivers.registry import cpe_match_string
    from services import inventory_manager

    vendor = device.get("Vendor") or ""
    text = version_text or ""
    version = nvd.version_of(text)

    if version:
        exact = cpe_match_string(vendor, version, text)
        if exact:
            return {"kind": "cpe", "value": exact, "confidence": "exact"}

    product = cpe_match_string(vendor, None, text)
    if product:
        return {"kind": "cpe", "value": product, "confidence": "product"}

    term = inventory_manager.resolve_euvd_term(vendor) or vendor
    return {"kind": "keyword", "value": term, "confidence": "keyword"}


# --- Servizi attivi dalla configurazione archiviata (F5) --------------------

def device_services(device: dict) -> dict:
    """Servizi di management accesi secondo l'ultima config archiviata.

    {} significa IGNOTO (nessun estrattore per il vendor, o nessuna config in
    archivio), non "tutto spento".
    """
    from drivers import registry
    versions = history.list_versions(device)
    if not versions:
        return {}
    config_text = history.read_version(device, versions[0].get("seen_at", ""))
    return registry.services_enabled(registry.driver_name_for(device.get("Vendor")),
                                     config_text)


def cve_services(text: str) -> list:
    """Servizi nominati dal testo di un CVE. Vuota = il CVE non li nomina."""
    hay = (text or "").lower()
    return [name for name, words in _CVE_SERVICE_WORDS.items()
            if any(w in hay for w in words)]


def _service_signal(names: list, services: dict) -> str:
    """'enabled' | 'disabled' | 'unknown'.

    'unknown' quando il CVE non nomina servizi, quando il vendor non ha
    estrattore, o quando l'estrattore non sa dire nulla su QUEL servizio:
    tre situazioni diverse che condividono l'unico esito onesto, cioe' non
    toccare il punteggio.
    """
    if not names or not services:
        return "unknown"
    states = []
    for name in names:
        keys = ("http", "https") if name == "http" else (name,)
        known = [services[k] for k in keys if k in services]
        if known:
            states.append(any(known))
    if not states:
        return "unknown"
    return "enabled" if any(states) else "disabled"


# --- Scaricamento (F1) ------------------------------------------------------

def _fetch_cves(query: dict):
    """I CVE piu' RECENTI per questa identita', e quanti ne esistono in tutto.

    NVD non ordina: rende le prime N per id CVE, cioe' le piu' vecchie. Si
    chiede prima il totale e poi la coda dell'elenco, altrimenti lo snapshot
    di un apparato di oggi si riempie di CVE del 1999.

    Il totale torna insieme all'elenco perche' e' il totale a dire se quello
    che si sta guardando e' tutto: una query senza versione rende la storia
    intera di un prodotto, il tetto la taglia, e un elenco tagliato in
    silenzio si legge come un elenco completo.
    """
    key = "virtualMatchString" if query["kind"] == "cpe" else "keywordSearch"
    base = {key: query["value"]}

    probe = requests.get(nvd.BASE_URL, params=dict(base, resultsPerPage="1"),
                         headers=nvd.headers(), timeout=20)
    probe.raise_for_status()
    total = probe.json().get("totalResults", 0)
    if not total:
        return [], 0

    page = requests.get(
        nvd.BASE_URL,
        params=dict(base, resultsPerPage=str(MAX_CVES),
                    startIndex=str(max(0, total - MAX_CVES))),
        headers=nvd.headers(), timeout=20)
    page.raise_for_status()
    return page.json().get("vulnerabilities", []), total


def is_truncated(snapshot: dict) -> bool:
    """Se lo snapshot contiene meno CVE di quanti NVD ne conosca.

    Gli snapshot scritti prima che il totale venisse registrato non hanno
    `total_available`: per quelli il tetto raggiunto e' l'unico indizio, e
    vale come "tagliato". Sbagliare per eccesso di prudenza qui costa una
    tilde in piu' sul numero; sbagliare al contrario significa presentare un
    conteggio parziale come definitivo.
    """
    cves = snapshot.get("cves") or []
    total = snapshot.get("total_available")
    if total is None:
        return len(cves) >= MAX_CVES
    return total > len(cves)


def refresh(device: dict, version_text: str = "", version_seen_at: str = "") -> dict:
    """Riscarica lo snapshot dell'apparato e lo scrive su disco."""
    from services import inventory_manager

    if not version_text or not version_seen_at:
        entry = inventory_manager.get_detected_versions().get(device["IP"], {})
        if isinstance(entry, dict):
            version_text = version_text or entry.get("version", "")
            version_seen_at = version_seen_at or entry.get("seen_at", "")

    # `seen_at` e' nato con la correlazione CVE: le voci scritte prima non lo
    # hanno, e lo avranno solo dopo il prossimo triage. Nel frattempo l'ora del
    # backup e' la risposta giusta comunque — versione e configurazione
    # vengono lette nello stesso giro (run_backup_and_triage), quindi e' la
    # stessa data. Meglio di una colonna che dice "ignoto" per settimane.
    if not version_seen_at:
        version_seen_at = history.last_seen_at(device)

    query = query_for(device, version_text)
    model = device.get("Model") or ""
    cves = []
    vulns, total_available = _fetch_cves(query)
    for elem in vulns:
        item = nvd.normalize_item(elem.get("cve", {}), model=model)
        cves.append({
            "id": item["id"],
            "cvss": item["score"],
            "severity": item["severity"],
            "published": item["published"],
            "summary": item["summary"],
            "cpe_hardware": item["cpeHardware"],
            "model_scope": item["modelScope"],
            "exploited": item["exploited"],
            "services": cve_services(item["summary"]),
        })

    snapshot = {
        "device": device["IP"],
        # Due date distinte, e servono entrambe: la prima dice quanto e'
        # vecchio l'elenco CVE, la seconda quanto e' vecchia la versione su cui
        # e' stato costruito. Un elenco fresco su una lettura di firmware di
        # tre settimane fa e' fresco solo all'apparenza.
        "fetched_at": history._now(),
        "version_seen_at": version_seen_at,
        "source": "nvd",
        "query": query,
        # Quanti NVD ne conosce in tutto, non quanti ne sono stati tenuti: e'
        # la differenza fra "questi sono i CVE" e "questi sono i primi 200".
        "total_available": total_available,
        "cves": cves,
    }
    _save(device, snapshot)
    return snapshot


def refresh_due() -> int:
    """Riscarica gli snapshot piu' vecchi della soglia. Chiamata dal poller."""
    from services import inventory_manager

    limit = max_age_hours()
    versions = inventory_manager.get_detected_versions()
    done = 0
    for device in inventory_manager.get_all_devices():
        entry = versions.get(device.get("IP"), {})
        if not isinstance(entry, dict) or not entry.get("version"):
            continue
        age = age_hours(load(device).get("fetched_at", ""))
        if age is not None and age < limit:
            continue
        try:
            refresh(device, entry.get("version", ""), entry.get("seen_at", ""))
            done += 1
        except Exception as e:
            log.debug("Snapshot CVE %s non aggiornato: %s", device.get("IP"), e)
    return done


# --- Punteggio e perimetro (F2/F3/F5/F8/F9) ---------------------------------

def not_evaluated_for(services: dict) -> list:
    """Cio' che non e' stato valutato per questo apparato."""
    out = list(NOT_EVALUATED)
    if not services:
        out.append("service_state")
    return out


def score_rows(snapshot: dict, services: dict) -> list:
    """I CVE dello snapshot con punteggio e fattori, dal piu' urgente.

    I segnali RIORDINANO, non filtrano: la lista in uscita ha sempre gli stessi
    elementi di `snapshot['cves']`.
    """
    confidence = (snapshot.get("query") or {}).get("confidence", "keyword")
    conf_factor = CONFIDENCE_FACTOR.get(confidence, CONFIDENCE_FACTOR["keyword"])

    age = age_hours(snapshot.get("version_seen_at", ""))
    # Eta' ignota vale come vecchia: dire "fresco" senza saperlo e' il verdetto
    # negativo travestito da ordinamento che questo design vieta.
    stale = age is None or age > STALE_HOURS

    rows = []
    for cve in snapshot.get("cves", []):
        signal = _service_signal(cve.get("services") or [], services)
        svc_factor = SERVICE_FACTOR[signal]
        base = cve.get("cvss") or 0.0
        rows.append({
            "device": snapshot.get("device", ""),
            "id": cve.get("id", ""),
            "cvss": cve.get("cvss"),
            "severity": cve.get("severity", ""),
            "summary": cve.get("summary", ""),
            "published": cve.get("published", ""),
            "exploited": bool(cve.get("exploited")),
            "model_scope": cve.get("model_scope", "generic"),
            "confidence": confidence,
            "service": signal,
            "services": cve.get("services") or [],
            # Lo 'stale' e' un marchio, non un declassamento: non entra nel
            # prodotto qui sotto.
            "stale": stale,
            "version_seen_at": snapshot.get("version_seen_at", ""),
            "score": round(base * conf_factor * svc_factor, 2),
            "factors": {
                "cvss": base,
                "confidence": confidence,
                "confidence_factor": conf_factor,
                "service": signal,
                "service_factor": svc_factor,
                "stale": stale,
            },
        })

    rows.sort(key=lambda r: (r["score"], bool(r["exploited"]), r.get("published") or ""),
              reverse=True)
    return rows


# --- Resoconto per tenant (F9b) ---------------------------------------------

def summary(devices: list) -> list:
    """Una riga per tenant: aggrega, non elenca.

    Ogni conteggio viaggia con il suo denominatore di copertura. "Tenant A: 0
    CVE critiche" viene letto come "tenant A e' a posto", ma significa anche,
    identico, "nessun apparato di quel tenant ha una versione leggibile": due
    situazioni opposte, stesso numero.
    """
    from services import inventory_manager

    detected = inventory_manager.get_detected_versions()
    tenants: "dict[str, dict]" = {}
    for device in devices:
        tenant = device.get("Group") or "Generale"
        if tenant not in tenants:
            tenants[tenant] = {
                "tenant": tenant, "devices": 0, "with_version": 0, "exact_cpe": 0,
                "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "oldest_version_seen_at": "",
                "not_evaluated": set(NOT_EVALUATED),
                "truncated": False,
                # Da dove viene ogni numero della riga. Un totale di tenant e'
                # quasi sempre un apparato solo che lo domina — nel caso che ha
                # motivato questa colonna, 94 di 109 CVE HIGH venivano da uno —
                # e senza il dettaglio quella e' proprio la cosa che l'aggregato
                # nasconde.
                "devices_detail": [],
            }
        row: dict = tenants[tenant]
        row["devices"] += 1

        entry = detected.get(device.get("IP"), {})
        version = entry.get("version", "") if isinstance(entry, dict) else ""
        has_version = version not in (None, "", "Unknown", "Non Scansionato")
        if has_version:
            row["with_version"] += 1

        snapshot = load(device)
        services = device_services(device)
        detail = {
            "ip": device.get("IP", ""),
            "hostname": device.get("Hostname", ""),
            "vendor": device.get("Vendor", ""),
            "version": version if has_version else "",
            # 'none' non e' un quarto livello di confidenza: e' l'assenza di
            # uno snapshot, cioe' un apparato che non ha ancora contribuito
            # nulla ai conteggi. Va detto, non lasciato indovinare da uno zero.
            "confidence": (snapshot.get("query") or {}).get("confidence", "") or "none",
            "cves": len(snapshot.get("cves") or []),
            "truncated": bool(snapshot) and is_truncated(snapshot),
            "total_available": snapshot.get("total_available"),
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "version_seen_at": version_seen_at_of(device, snapshot),
            # Il perimetro e' per APPARATO prima che per tenant: lo stato dei
            # servizi si sa per uno e non per l'altro, e il rapporto stampa una
            # sezione per apparato. Un perimetro solo aggregato costringerebbe
            # a scrivere sotto ognuno la voce piu' pessimista di tutti.
            "not_evaluated": not_evaluated_for(services),
        }
        row["devices_detail"].append(detail)

        if not snapshot:
            continue
        if (snapshot.get("query") or {}).get("confidence") == "exact":
            row["exact_cpe"] += 1
        if not services:
            row["not_evaluated"].add("service_state")
        if detail["truncated"]:
            row["truncated"] = True

        seen = version_seen_at_of(device, snapshot)
        if seen and (not row["oldest_version_seen_at"]
                     or seen < row["oldest_version_seen_at"]):
            row["oldest_version_seen_at"] = seen

        for cve in snapshot.get("cves", []):
            sev = str(cve.get("severity", "")).lower()
            if sev in row["counts"]:
                row["counts"][sev] += 1
                detail["counts"][sev] += 1

    out = []
    for row in tenants.values():
        row["not_evaluated"] = sorted(row["not_evaluated"])
        # Chi pesa di piu' sta in cima: aprire la riga deve rispondere subito a
        # "chi mi ha fatto questo numero", non far cercare.
        row["devices_detail"].sort(
            key=lambda d: (d["counts"]["critical"], d["counts"]["high"], d["cves"]),
            reverse=True)
        out.append(row)
    out.sort(key=lambda r: r["tenant"])
    return out
