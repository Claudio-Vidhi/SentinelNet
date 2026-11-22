# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""FortiGate Service — accesso live a un FortiGate per l'osservabilità LAN.

Due trasporti:
  - REST API FortiOS (primario): token API "api-user", header Authorization
    Bearer, endpoint /api/v2/monitor|cmdb|log su HTTPS (porta admin, default
    443). Restituisce JSON strutturato.
  - SSH/CLI (fallback, Netmiko device_type 'fortinet'): usato quando il token
    API non è configurato o la chiamata REST fallisce; output testuale.

I token API sono salvati cifrati (crypto_vault) in data/fortigate_tokens.json,
per IP: {"<ip>": {"token_enc": ..., "port": 443, "verify_tls": false,
"keepalive": false}}. ``keepalive`` = sessione persistente (vedi _http).

Le funzioni di alto livello (get_*) accettano il dict `device` dell'inventario
e ritornano sempre {"source": "api"|"ssh", "data": ...} oppure sollevano
FortiGateError con il dettaglio di entrambi i tentativi.
"""

import datetime
import ipaddress
import json
import logging
import os
import re
import threading
import time
import warnings
from typing import Optional, Any, Dict

import requests
import urllib3

from core import data_config
from security.crypto_vault import encrypt_password, decrypt_password
from services.fortigate_hw_profiles import FortiGateHWProfile, profile_to_dict, resolve_profile

TOKENS_FILE = data_config.get_path("fortigate_tokens.json")

logger = logging.getLogger(__name__)

_lock = threading.Lock()


class FortiGateError(Exception):
    pass


# --- Persistenza token API ---------------------------------------------------

def _load_tokens() -> dict:
    if not os.path.exists(TOKENS_FILE):
        # Prima esecuzione: nessun token configurato, caso normale.
        return {}
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        # Un file illeggibile fa cadere ogni FortiGate sul fallback SSH come
        # se l'API non fosse configurata: senza questo log i due casi sono
        # indistinguibili.
        logger.exception("Token store FortiGate illeggibile: %s", TOKENS_FILE)
        return {}


def _save_tokens(tokens: dict):
    os.makedirs(os.path.dirname(TOKENS_FILE) or ".", exist_ok=True)
    with _lock:
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=1)


def set_api_token(ip: str, token: str, port: int = 443, verify_tls: bool = False,
                  name: str = "", keepalive: bool = False):
    """Salva (cifrato) il token API di un FortiGate. Token vuoto = rimozione
    (e, se era il target attivo, azzera anche `_active`)."""
    tokens = _load_tokens()
    if token:
        entry = {"token_enc": encrypt_password(token),
                 "port": int(port or 443), "verify_tls": bool(verify_tls),
                 "keepalive": bool(keepalive)}
        if name:
            entry["name"] = name
        elif isinstance(tokens.get(ip), dict) and tokens[ip].get("name"):
            entry["name"] = tokens[ip]["name"]  # preserva il nome se non passato
        tokens[ip] = entry
    else:
        tokens.pop(ip, None)
        if tokens.get("_active") == ip:
            tokens.pop("_active", None)
    _save_tokens(tokens)
    _drop_session(ip)


def get_api_config(ip: str):
    """Ritorna (token, port, verify_tls) oppure (None, ...) se non configurato."""
    entry = _load_tokens().get(ip)
    if not entry or ip == "_active":
        return None, 443, False
    return (decrypt_password(entry.get("token_enc", "")) or None,
            int(entry.get("port") or 443), bool(entry.get("verify_tls")))


def token_status() -> dict:
    """Elenco IP con token configurato (senza esporre i token)."""
    return {ip: {"port": e.get("port", 443), "verify_tls": e.get("verify_tls", False)}
            for ip, e in _load_tokens().items() if ip != "_active"}


# --- Multi-target: nome, target attivo, elenco, test connessione ------------

def update_target(ip: str, *, name: Optional[str] = None, port: Optional[int] = None,
                  verify_tls: Optional[bool] = None, token: Optional[str] = None,
                  keepalive: Optional[bool] = None) -> None:
    """Aggiorna solo i campi forniti di un target FortiGate già configurato
    (usato dal manager multi-target per modifiche parziali: rinomina, cambio
    porta/TLS senza dover reinserire il token). Token omesso o vuoto = il
    token cifrato esistente resta invariato ("•••• invariato" lato UI).
    Solleva KeyError se l'IP non ha ancora un target configurato."""
    tokens = _load_tokens()
    entry = tokens.get(ip)
    if not isinstance(entry, dict) or ip == "_active":
        raise KeyError(f"Nessun target FortiGate configurato per {ip}.")
    if name is not None:
        entry["name"] = name
    if port is not None:
        entry["port"] = int(port or 443)
    if verify_tls is not None:
        entry["verify_tls"] = bool(verify_tls)
    if token:
        entry["token_enc"] = encrypt_password(token)
    if keepalive is not None:
        entry["keepalive"] = bool(keepalive)
    tokens[ip] = entry
    _save_tokens(tokens)
    _drop_session(ip)


def list_targets() -> list:
    """Elenco dei target FortiGate configurati (mai i token), con flag
    'active' per il target correntemente selezionato."""
    tokens = _load_tokens()
    active = tokens.get("_active")
    out = []
    for ip, e in tokens.items():
        if ip == "_active" or not isinstance(e, dict):
            continue
        out.append({
            "ip": ip,
            "name": e.get("name", ""),
            "port": int(e.get("port") or 443),
            "verify_tls": bool(e.get("verify_tls")),
            "keepalive": bool(e.get("keepalive")),
            "active": ip == active,
        })
    return out


def set_active_target(ip: str) -> None:
    """Imposta il target FortiGate attivo (persistito in `_active`)."""
    tokens = _load_tokens()
    tokens["_active"] = ip
    _save_tokens(tokens)


def get_active_target():
    """IP del target FortiGate attivo, o None se non impostato."""
    active = _load_tokens().get("_active")
    return active if isinstance(active, str) and active else None


def test_connection(ip: str) -> dict:
    """Verifica la raggiungibilità del target chiamando
    /api/v2/monitor/system/status con timeout breve. Non solleva mai."""
    try:
        data = api_get(ip, "monitor/system/status", timeout=5)
        results = data.get("results") if isinstance(data, dict) else None
        version = None
        if isinstance(results, dict):
            version = results.get("version")
        if not version and isinstance(data, dict):
            version = data.get("version")
        return {"ok": True, "version": str(version).lstrip("v") if version else None}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# --- Trasporto REST ----------------------------------------------------------

# Connect timeout, split from the caller's read timeout. An unreachable
# FortiGate used to burn the whole read budget (30s by default, 60s on a config
# pull) just failing to open the socket, and the dashboard tab that asked for it
# stayed blank the entire time. A box that is up answers the TCP handshake in
# milliseconds; one that is down should say so straight away.
CONNECT_TIMEOUT = 4

# Sessione persistente, opzione per FortiGate ("keepalive" nel token store):
# un requests.Session per apparato tiene aperta la connessione HTTPS e le
# chiamate successive la riusano invece di rifare TCP + TLS ogni volta. Il
# token Bearer viaggia comunque a ogni richiesta: la sessione non autentica
# niente. Cambiare token, porta o TLS la chiude (_drop_session).
# ponytail: never closed while idle; the FortiGate drops idle connections and
# urllib3 reconnects transparently, so the cost is one socket per target.
_sessions: Dict[str, requests.Session] = {}


def _http(ip: str):
    """requests itself, or the persistent Session of a keepalive target."""
    entry = _load_tokens().get(ip)
    if not (isinstance(entry, dict) and entry.get("keepalive")):
        return requests
    with _lock:
        session = _sessions.get(ip)
        if session is None:
            session = _sessions[ip] = requests.Session()
    return session


def _drop_session(ip: str) -> None:
    with _lock:
        session = _sessions.pop(ip, None)
    if session is not None:
        session.close()


def api_request(ip: str, method: str, path: str, params: Optional[dict] = None,
                json_body=None, timeout: int = 30):
    """Richiesta su /api/v2/<path> con Bearer token. Solleva FortiGateError."""
    token, port, verify = get_api_config(ip)
    if not token:
        raise FortiGateError(f"Nessun token API configurato per {ip}.")
    url = f"https://{ip}:{port}/api/v2/{path.lstrip('/')}"
    try:
        # Il silenziamento vale solo per questa richiesta: ``disable_warnings``
        # spegneva il warning per l'intero processo, quindi il primo apparato
        # con verify_tls=False nascondeva l'avviso anche a quelli che il
        # certificato lo verificano.
        # ponytail: catch_warnings tocca uno stato globale, quindi sotto
        # richieste concorrenti l'avviso puo' comparire o sparire a sproposito;
        # se servisse deterministico, filtrare a livello di logging handler.
        with warnings.catch_warnings():
            if not verify:
                warnings.simplefilter(
                    "ignore", urllib3.exceptions.InsecureRequestWarning)
            r = _http(ip).request(method, url,
                                 headers={"Authorization": f"Bearer {token}"},
                                 params=params or {}, json=json_body,
                                 verify=verify,
                                 timeout=(CONNECT_TIMEOUT, timeout))
    except requests.exceptions.SSLError as e:
        raise FortiGateError(
            f"REST API {ip} non raggiungibile: certificato TLS non attendibile ({e}). "
            "Il FortiGate usa probabilmente un certificato self-signed: disabilitare "
            "'Verifica certificato TLS' nella configurazione del token oppure installare "
            "un certificato attendibile sul FortiGate.")
    except requests.RequestException as e:
        raise FortiGateError(f"REST API {ip} non raggiungibile: {e}")
    if r.status_code == 401:
        raise FortiGateError(f"REST API {ip}: token non valido o scaduto (401). "
                             "Verificare anche i trusted host dell'api-user.")
    if r.status_code == 403:
        raise FortiGateError(f"REST API {ip}: accesso negato (403), profilo "
                             "accprofile dell'api-user insufficiente.")
    if r.status_code >= 400:
        raise FortiGateError(f"REST API {ip} HTTP {r.status_code}: {r.text[:300]}")
    try:
        return r.json()
    except ValueError:
        return {"raw": r.text}


def api_get(ip: str, path: str, params: Optional[dict] = None, timeout: int = 30):
    """GET su /api/v2/<path> con Bearer token. Solleva FortiGateError."""
    return api_request(ip, "GET", path, params=params, timeout=timeout)


def get_ha_status(device: dict) -> dict:
    # `monitor/system/ha-status` NON esiste: su 7.4.12 risponde HTTP 404 e la
    # vista HA finiva in errore 502 invece che in un pannello vuoto. I path
    # reali, verificati sul box: ha-peer, ha-statistics, ha-checksums.
    return api_get(device["IP"], "monitor/system/ha-peer")


def get_ha_checksums(device: dict) -> dict:
    return api_get(device["IP"], "monitor/system/ha-checksums")


def api_get_cmdb(ip: str, path: str, fmt: Optional[str] = None, flt: Optional[str] = None,
                 timeout: int = 30):
    """GET su un endpoint cmdb con proiezione dei campi (query `format`,
    es. 'name|type|subnet') ed eventuale filtro (query `filter`, es.
    'name=@X'), come da documentazione FortiOS "Using APIs". Riduce il
    payload agli oggetti cmdb di sola lettura (address/policy/service)."""
    params = {}
    if fmt:
        params["format"] = fmt
    if flt:
        params["filter"] = flt
    return api_get(ip, path, params=params or None, timeout=timeout)


# --- Trasporto SSH (fallback) ------------------------------------------------

def ssh_command(device: dict, command: str, timeout: int = 30) -> str:
    """Esegue un comando CLI FortiOS via Netmiko e ritorna l'output testuale."""
    from core.net_ssh import ConnectHandler
    from core.core_engine import get_device_credentials, get_device_port
    # Credential resolution is INSIDE the try on purpose: a device with an API
    # token but no SSH identity can no longer resolve one (it used to get
    # admin/admin), and callers of the SSH fallback all handle FortiGateError.
    # Left outside, that raise would take down the whole Policy view instead of
    # leaving the address names unresolved, which _address_map is built for.
    try:
        username, password, _secret = get_device_credentials(device)
        params = {"device_type": "fortinet", "host": device["IP"],
                  "port": get_device_port(device),
                  "username": username, "password": password,
                  "timeout": timeout, "auth_timeout": 15, "banner_timeout": 15,
                  # Same reason as CONNECT_TIMEOUT above: the SSH fallback runs
                  # after REST already failed, so an unreachable device must not
                  # spend another full timeout on the TCP connect.
                  "conn_timeout": CONNECT_TIMEOUT}
        with ConnectHandler(**params) as conn:
            # UNA RIGA ALLA VOLTA. send_command aspetta il prompt DOPO il
            # comando che gli si passa: dandogliene tre separati da newline
            # aspettava un prompt che conteneva tutte e tre le righe, non lo
            # trovava mai e falliva con "Pattern not detected", portandosi
            # dietro l'intero blocco come se fosse il pattern cercato. E'
            # quello che succedeva alla sequenza `diagnose sys session
            # filter ... / list` della diagnosi client.
            lines = [x for x in command.split("\n") if x.strip()]
            out = [conn.send_command(line, read_timeout=timeout) for line in lines]
            return "\n".join(
                x if isinstance(x, str) else str(x or "") for x in out)
    except Exception as e:
        raise FortiGateError(f"SSH {device.get('IP')}: {e}")


# --- Helper API-first con fallback SSH ---------------------------------------

def _api_or_ssh(device, api_path, api_params, ssh_cmd, parser=None):
    """``api_path`` puo' essere un percorso o una sequenza di percorsi.

    FortiOS sposta gli endpoint monitor fra le versioni: get_ha_status lo ha
    gia' incontrato (ha-status non esiste, e' ha-peer). Provarne piu' d'uno in
    ordine, dal piu' recente, costa una richiesta in piu' solo sulle versioni
    vecchie ed evita che una minor release renda muta una vista."""
    ip = device["IP"]
    api_err = None
    paths = [api_path] if isinstance(api_path, str) else list(api_path)
    for path in paths:
        try:
            data = api_get(ip, path, api_params)
            return {"source": "api", "data": data.get("results", data)}
        except FortiGateError as e:
            # Il primo errore e' quello che si riporta: dice cosa ha risposto
            # il path che ci aspettavamo funzionasse.
            api_err = api_err or str(e)
    try:
        out = ssh_command(device, ssh_cmd)
        return {"source": "ssh", "api_error": api_err,
                "data": parser(out) if parser else out}
    except FortiGateError as ssh_err:
        raise FortiGateError(f"API: {api_err} | SSH: {ssh_err}")


# --- Servizi di osservabilità -------------------------------------------------

def _parse_system_status_cli(out: str) -> dict:
    """Parsa l'output CLI di 'get system status' in un dict con almeno
    hostname/version/serial (il testo grezzo resta in 'raw')."""
    info = {"raw": out}
    for line in (out or "").splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "hostname":
            info["hostname"] = val
        elif key == "version":
            # Es. "FortiGate-60F v7.2.5,build1517,230410 (GA.F)"
            m = re.search(r"v(\d+\.\d+\.\d+)", val)
            info["version"] = m.group(1) if m else val
            info["model"] = val.split(" v")[0].strip()
        elif key == "serial-number":
            info["serial"] = val
    return info


def _attach_hardware_profile(device: dict, payload: Any, lang: str = "it") -> Any:
    """Attach resolved ``hardware_profile`` metadata to a status dict."""
    if not isinstance(payload, dict):
        return payload
    model = (
        payload.get("model_name")
        or payload.get("model")
        or payload.get("platform_name")
        or (device.get("Model") if isinstance(device, dict) else "")
        or ""
    )
    version = (
        payload.get("version")
        or (device.get("Version") if isinstance(device, dict) else "")
        or ""
    )
    serial = payload.get("serial") or ""
    prof = resolve_profile(model=str(model), version=str(version), serial=str(serial))
    payload["hardware_profile"] = profile_to_dict(prof, lang=lang)
    return payload


def get_system_status(device):
    """Stato di sistema: hostname/version/serial. A differenza degli altri
    endpoint, per monitor/system/status version e serial stanno nella busta
    della risposta REST (non in 'results'): si fondono qui, e il fallback SSH
    parsa l'output CLI invece di restituire testo grezzo."""
    ip = device["IP"]
    api_err = None
    try:
        data = api_get(ip, "monitor/system/status")
        results = data.get("results") if isinstance(data, dict) else None
        merged = dict(results) if isinstance(results, dict) else {}
        if isinstance(data, dict):
            if data.get("version") and not merged.get("version"):
                merged["version"] = str(data["version"]).lstrip("v")
            if data.get("serial") and not merged.get("serial"):
                merged["serial"] = data["serial"]
        out_data = merged or (dict(data) if isinstance(data, dict) else data)
        return {"source": "api", "data": _attach_hardware_profile(device, out_data)}
    except FortiGateError as e:
        api_err = str(e)
    try:
        out = ssh_command(device, "get system status")
        parsed = _parse_system_status_cli(out)
        return {"source": "ssh", "api_error": api_err,
                "data": _attach_hardware_profile(device, parsed)}
    except FortiGateError as ssh_err:
        raise FortiGateError(f"API: {api_err} | SSH: {ssh_err}")


# --- Sistema: risorse, HA, account, revisioni, certificati -------------------
# Sola REST: nessuno di questi ha un equivalente CLI 1:1 affidabile, quindi
# niente fallback SSH (stessa scelta di policy_lookup e dell'inventario cmdb).

# Proiezione degli account amministrativi. È l'unica barriera fra gli account
# del FortiGate e il browser: elencare i campi voluti, mai filtrare quelli
# indesiderati dalla risposta, perché una versione futura di FortiOS potrebbe
# aggiungerne uno nuovo che nessuno ha pensato di escludere.
ADMIN_FIELDS = "name|accprofile|trusthost1|trusthost2|two-factor|comments"


def get_system_resources(device):
    """Uso CPU/memoria/disco/sessioni più l'ora di sistema, in una risposta
    sola: la Overview ne fa una card, non quattro richieste."""
    ip = device["IP"]
    return {"source": "api",
            "data": {"usage": api_get(ip, "monitor/system/resource/usage").get("results"),
                     "time": api_get(ip, "monitor/system/time").get("results")}}


def get_ha(device):
    """Stato HA e checksum di sincronizzazione insieme: due cluster allineati
    ma con checksum diversi sono il caso che conta, e serve vederli vicini."""
    return {"source": "api",
            "data": {"status": get_ha_status(device).get("results"),
                     "checksums": get_ha_checksums(device).get("results")}}


def get_admins(device):
    """Account amministrativi (cmdb/system/admin), proiettati su ADMIN_FIELDS:
    nessuna credenziale lascia questa funzione."""
    data = api_get_cmdb(device["IP"], "cmdb/system/admin", fmt=ADMIN_FIELDS)
    return {"source": "api", "data": data.get("results", data)}


def get_banned_users(device):
    """Utenti/IP bannati dalle azioni di quarantena FortiOS."""
    data = api_get(device["IP"], "monitor/user/banned")
    return {"source": "api", "data": data.get("results", data)}


def get_config_revisions(device):
    """Revisioni di configurazione salvate a bordo (config-revision)."""
    data = api_get(device["IP"], "monitor/system/config-revision")
    return {"source": "api", "data": data.get("results", data)}


def get_certificates(device):
    """Certificati disponibili con scadenza. Endpoint monitor: metadati e
    scadenza, mai il materiale della chiave privata."""
    data = api_get(device["IP"], "monitor/system/available-certificates")
    return {"source": "api", "data": data.get("results", data)}


def get_interfaces(device):
    """Stato interfacce con IP, link, contatori."""
    return _api_or_ssh(device, "monitor/system/interface",
                       {"include_vlan": "true", "include_aggregate": "true"},
                       "get system interface")


def get_arp_table(device):
    return _api_or_ssh(device, "monitor/network/arp", None, "get system arp")


def get_dhcp_leases(device):
    return _api_or_ssh(device, "monitor/system/dhcp", None,
                       "execute dhcp lease-list")


def get_device_inventory(device):
    """Device inventory FortiOS (device-identification): MAC, IP, hostname,
    OS rilevato, interfaccia di ingresso, online/offline."""
    return _api_or_ssh(device, "monitor/user/device/query",
                       {"timestamp_from": 0},
                       "diagnose user device list")


def get_firewall_policies(device):
    """Policy firewall configurate (cmdb) — la 'full config' delle policy."""
    return _api_or_ssh(device, "cmdb/firewall/policy", None,
                       "show firewall policy")


def get_policy_stats(device):
    """Contatori runtime per policy (hit, byte, sessioni attive)."""
    return _api_or_ssh(device, "monitor/firewall/policy", None,
                       "diagnose firewall iprope show 100004")


# --- Inventario cmdb "slim" (sola REST, campi proiettati via `format`) -------
# A differenza di get_firewall_policies() (full config, usata anche dal
# fallback SSH), queste tre funzioni restituiscono solo i campi utili
# all'osservabilità, come da doc Fortinet "Using APIs": nessun fallback SSH,
# in analogia a policy_lookup() (nessun equivalente CLI 1:1 affidabile).

def get_firewall_addresses(device):
    """Oggetti indirizzo firewall (address book): nome, tipo, subnet/FQDN,
    commento. Query cmdb/firewall/address con format proiettato."""
    ip = device["IP"]
    try:
        data = api_get_cmdb(ip, "cmdb/firewall/address",
                            fmt="name|type|subnet|fqdn|start-ip|end-ip|comment")
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        raise FortiGateError(f"firewall/address disponibile solo via REST API: {e}")


def _address_literal(obj: dict) -> Optional[str]:
    """L'indirizzo LETTERALE di un oggetto dell'address book, o None.

    None non è un errore: un FQDN o un oggetto geography non HA un indirizzo
    finché non lo si risolve, e stampare comunque qualcosa al suo posto
    significherebbe far leggere all'operatore un valore inventato. Il nome
    dell'oggetto resta la risposta giusta in quel caso."""
    typ = str(obj.get("type") or "ipmask").lower()
    if typ in ("ipmask", "subnet", ""):
        raw = str(obj.get("subnet") or "").strip()
        if not raw:
            return None
        parts = raw.replace("/", " ").split()
        if len(parts) == 2:
            try:
                return str(ipaddress.ip_network(f"{parts[0]}/{parts[1]}",
                                                strict=False))
            except ValueError:
                return None
        return parts[0] if parts else None
    if typ == "iprange":
        start, end = obj.get("start-ip"), obj.get("end-ip")
        return f"{start}-{end}" if start and end else None
    return None


def _address_map(device) -> dict:
    """name -> indirizzo letterale, per gli oggetti che ne hanno uno.

    Include i gruppi (espansi nei membri) e gli oggetti impliciti
    "<interfaccia> address", che NON stanno nell'address book: sono derivati
    dall'IP dell'interfaccia a runtime, ed è esattamente il caso in cui il
    nome da solo non dice nulla ("port2 address" non è consultabile). Ogni
    sorgente è best-effort: quello che non arriva semplicemente non viene
    risolto."""
    out: Dict[str, str] = {}
    try:
        for a in (get_firewall_addresses(device).get("data") or []):
            if isinstance(a, dict) and a.get("name"):
                lit = _address_literal(a)
                if lit:
                    out[a["name"]] = lit
    except FortiGateError:
        pass

    try:
        for it in (get_interfaces(device).get("data") or []):
            if not isinstance(it, dict):
                continue
            name = it.get("name") or it.get("interface")
            addr = it.get("ip") or it.get("ipv4_address")
            if name and addr:
                out[f"{name} address"] = str(addr)
    except FortiGateError:
        pass

    try:
        for g in (get_address_groups(device).get("data") or []):
            if not isinstance(g, dict) or not g.get("name"):
                continue
            members = [m.get("name") if isinstance(m, dict) else str(m)
                       for m in (g.get("member") or [])]
            vals = [out[m] for m in members if m in out]
            if vals:
                out[g["name"]] = ", ".join(vals)
    except FortiGateError:
        pass
    return out


def _resolve_addr_field(value, amap: dict) -> Optional[str]:
    """Rende ``srcaddr``/``dstaddr`` di una policy come indirizzi letterali."""
    if not isinstance(value, list):
        value = [value]
    parts = []
    for m in value:
        name = m.get("name") if isinstance(m, dict) else str(m)
        if not name:
            continue
        if name == "all":
            parts.append("0.0.0.0/0")
        elif name in amap:
            parts.append(amap[name])
    return ", ".join(parts) or None


_L7_POLICY_PROFILE_TAGS = (
    ("AV", "av-profile"),
    ("IPS", "ips-sensor"),
    ("Web", "webfilter-profile"),
    ("App", "application-list"),
    ("DNS", "dnsfilter-profile"),
    ("SSL", "ssl-ssh-profile"),
)


def _profile_name_val(val: Any) -> str:
    if isinstance(val, dict):
        return str(val.get("name") or val.get("q_origin_key") or "").strip()
    return str(val or "").strip()


def _summarize_l7_profiles(row: dict) -> str:
    if str(row.get("utm-status") or "").lower() == "disable":
        return ""
    parts = []
    for tag, key in _L7_POLICY_PROFILE_TAGS:
        name = _profile_name_val(row.get(key))
        if name:
            parts.append(f"{tag}:{name}")
    return ", ".join(parts)


def get_firewall_policy_objects(device):
    """Policy firewall (cmdb) con soli campi rilevanti per l'osservabilità
    (policyid, nome, interfacce, indirizzi, servizi, azione, stato,
    logtraffic, L7/SPU). Complementare a get_firewall_policies() (full config)."""
    ip = device["IP"]
    try:
        data = api_get_cmdb(
            ip,
            "cmdb/firewall/policy",
            fmt="policyid|name|srcintf|dstintf|srcaddr|dstaddr|"
                "service|action|status|logtraffic|inspection-mode|"
                "utm-status|auto-asic-offload|ips-sensor|av-profile|"
                "webfilter-profile|application-list|dnsfilter-profile|ssl-ssh-profile",
        )
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        raise FortiGateError(f"firewall/policy (slim) disponibile solo via REST API: {e}")


def get_policies_with_stats(device):
    """Policy (cmdb, slim) unite ai contatori runtime, join su ``policyid``.

    ``never_hit`` è vero solo per le policy che HANNO un contatore e vale
    zero: senza contatore non si può dire che la regola sia morta, e
    marcarla produrrebbe un falso positivo in audit. Se i contatori non
    arrivano la configurazione viene restituita comunque, con l'errore in
    ``stats_error``: metà risposta è meglio di un 502."""
    policies = get_firewall_policy_objects(device)
    rows = policies.get("data") or []
    stats_error = None
    by_id = {}
    try:
        stats = get_policy_stats(device)
        data = stats.get("data")
        if isinstance(data, list):
            by_id = {s.get("policyid"): s for s in data if isinstance(s, dict)}
    except FortiGateError as e:
        stats_error = str(e)

    # Gli indirizzi in una policy sono NOMI di oggetti: "port2 address" o
    # "LAN_Uffici" non dicono che rete intercettano, e per saperlo si apre
    # l'address book in un'altra scheda. Qui si risolvono una volta sola.
    amap = _address_map(device)

    merged = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        s = by_id.get(row.get("policyid"))
        merged.append({**row,
                       "srcaddr_ips": _resolve_addr_field(row.get("srcaddr"), amap),
                       "dstaddr_ips": _resolve_addr_field(row.get("dstaddr"), amap),
                       "inspection_mode": str(row.get("inspection-mode") or "flow"),
                       "asic_offload": str(row.get("auto-asic-offload") or "enable"),
                       "l7_profiles": _summarize_l7_profiles(row),
                       "hit_count": (s or {}).get("hit_count", 0),
                       "bytes": (s or {}).get("bytes", 0),
                       "active_sessions": (s or {}).get("active_sessions", 0),
                       "last_used": (s or {}).get("last_used"),
                       "never_hit": bool(s) and not (s or {}).get("hit_count")})
    return {"source": policies.get("source", "api"), "data": merged,
            "stats_error": stats_error}


def get_firewall_custom_services(device):
    """Servizi custom (firewall.service/custom): nome, range porte TCP/UDP,
    commento."""
    ip = device["IP"]
    try:
        data = api_get_cmdb(ip, "cmdb/firewall.service/custom",
                            fmt="name|tcp-portrange|udp-portrange|comment")
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        raise FortiGateError(f"firewall.service/custom disponibile solo via REST API: {e}")


def get_address_groups(device):
    """Gruppi di indirizzi: nome, membri, commento."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall/addrgrp",
                        fmt="name|member|comment")
    return {"source": "api", "data": data.get("results", data)}


def get_service_groups(device):
    """Gruppi di servizi."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall.service/group",
                        fmt="name|member|comment")
    return {"source": "api", "data": data.get("results", data)}


def get_vips(device):
    """Virtual IP (DNAT): da quale indirizzo esterno a quale interno."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall/vip",
                        fmt="name|extip|extintf|mappedip|portforward|"
                            "extport|mappedport|protocol|comment")
    return {"source": "api", "data": data.get("results", data)}


def get_ip_pools(device):
    """IP pool (SNAT)."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall/ippool",
                        fmt="name|type|startip|endip|comments")
    return {"source": "api", "data": data.get("results", data)}


# Famiglie di profili di sicurezza: chiave usata dalla UI -> percorso cmdb.
_SECURITY_PROFILES = {
    "antivirus": "cmdb/antivirus/profile",
    "ips": "cmdb/ips/sensor",
    "webfilter": "cmdb/webfilter/profile",
    "application": "cmdb/application/list",
    "dnsfilter": "cmdb/dnsfilter/profile",
    "ssl_ssh": "cmdb/firewall/ssl-ssh-profile",
}


def get_security_profiles(device):
    """Profili di sicurezza per famiglia.

    Una famiglia che manca (licenza senza IPS, feature non abilitata)
    risponde 404: si registra in ``errors`` e le altre passano comunque.
    Fallire tutto perché una sola manca renderebbe il pannello inutile
    sulla metà dei FortiGate."""
    out, errors = {}, {}
    for key, path in _SECURITY_PROFILES.items():
        try:
            data = api_get_cmdb(device["IP"], path, fmt="name|comment")
            out[key] = data.get("results", data)
        except FortiGateError as e:
            out[key] = []
            errors[key] = str(e)
    return {"source": "api", "data": out, "errors": errors}


# IP protocol numbers. monitor/firewall/policy-lookup wants the NUMBER, not
# the name: "tcp" is rejected where 6 is accepted.
_PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58,
              "sctp": 132, "gre": 47, "esp": 50, "ah": 51}


def policy_lookup_params(src_ip: str, dest: str, protocol: str = "TCP",
                         dest_port: Optional[int] = 443,
                         srcintf: Optional[str] = None) -> dict:
    """Query string for monitor/firewall/policy-lookup.

    The parameter names are not the ones the CLI or the cmdb schema suggest,
    and getting them wrong costs a 4xx that reads like "the box does not
    support this": the source address is ``sourceip`` (not ``srcip``), the
    source port would be ``sourceport``, and ``protocol`` is the IP protocol
    number.
    ``srcintf`` is mandatory — the lookup is evaluated per ingress interface,
    exactly like the GUI Policy Lookup tool, which also refuses to run without
    it. Shared with the relay path in ``client_diagnosis`` so both spellings
    cannot drift apart again.
    """
    proto = str(protocol or "tcp").strip().lower()
    num = _PROTO_NUM.get(proto, proto if proto.isdigit() else None)
    if num is None:
        raise FortiGateError(f"Protocollo '{protocol}' non riconosciuto.")
    params: Dict[str, Any] = {"sourceip": src_ip, "dest": dest,
                              "protocol": int(num), "policy_type": "policy",
                              "ipv6": "false"}
    if srcintf:
        params["srcintf"] = srcintf
    # Ports only mean something for TCP/UDP. Sending destport on an ICMP
    # lookup is how you get a match against the wrong service object.
    if int(num) in (6, 17):
        params["destport"] = int(dest_port or 443)
    return params


def policy_lookup(device, src_ip: str, dest: str, protocol: str = "TCP",
                  dest_port: int = 443, srcintf: Optional[str] = None):
    """Chiede al FortiGate QUALE policy matcherebbe un flusso (senza generare
    traffico): fondamentale per 'perché il client X non raggiunge il sito Y'.
    `dest` può essere IP o FQDN.

    ``srcintf`` omesso viene dedotto dalla rotta verso ``src_ip``: è
    l'interfaccia da cui quel client entra, cioè esattamente quella che la
    lookup richiede. Il chiamante che la conosce la passa e si risparmia la
    lettura della tabella di routing."""
    ip = device["IP"]
    if not srcintf:
        try:
            route = get_route_for(device, src_ip).get("data")
            intf = route.get("interface") if isinstance(route, dict) else None
            srcintf = str(intf) if intf else None
        except FortiGateError:
            srcintf = None
        if not srcintf:
            raise FortiGateError(
                f"policy-lookup richiede l'interfaccia di ingresso e non è "
                f"deducibile da una rotta verso {src_ip}: indicarla.")
    params = policy_lookup_params(src_ip, dest, protocol, dest_port, srcintf)
    try:
        data = api_get(ip, "monitor/firewall/policy-lookup", params)
        return {"source": "api", "srcintf": srcintf,
                "data": data.get("results", data)}
    except FortiGateError as e:
        # Nessun equivalente CLI 1:1 affidabile: si riporta l'errore API.
        raise FortiGateError(f"policy-lookup disponibile solo via REST API: {e}")


_PROTO_BY_NUM = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPv6"}


def normalize_session_row(row: dict) -> dict:
    """Attach normalized NPU offload metadata to a FortiGate session dict."""
    if not isinstance(row, dict):
        return row
    reason = str(row.get("no_ofld_reason") or "").strip()
    if not reason and isinstance(row.get("npu_info"), dict):
        reason = str(row["npu_info"].get("no_ofld_reason") or "").strip()
    if reason.lower() in ("none", "n/a", "-"):
        reason = ""

    offload_val = row.get("offload")
    if offload_val is None and isinstance(row.get("npu_info"), dict):
        offload_val = row["npu_info"].get("offload")
    npu_state = str(row.get("npu_state") or row.get("npu") or "").strip().lower()

    npu_offload = "unknown"
    if reason:
        npu_offload = "cpu"
    elif offload_val is not None:
        if isinstance(offload_val, bool):
            npu_offload = "hardware" if offload_val else "cpu"
        elif isinstance(offload_val, (int, float)):
            npu_offload = "hardware" if offload_val > 0 else "cpu"
        else:
            s = str(offload_val).strip().lower()
            if s in ("0", "0/0", "false", "no", "none", "disable", "disabled"):
                npu_offload = "cpu"
            elif s in ("true", "yes", "enable", "enabled", "ofld") or re.match(r"^[1-9]\d*/\d+$", s):
                npu_offload = "hardware"
    elif npu_state:
        if "ofld" in npu_state or npu_state in ("true", "hardware", "npu"):
            npu_offload = "hardware"
        elif npu_state in ("false", "cpu", "none"):
            npu_offload = "cpu"

    if npu_offload == "hardware":
        detail = "NPU"
    elif npu_offload == "cpu":
        detail = f"CPU ({reason})" if reason else "CPU"
    else:
        detail = ""

    return {
        **row,
        "npu_offload": npu_offload,
        "no_ofld_reason": reason,
        "npu_detail": detail,
    }


def parse_sessions_cli(raw_text: str) -> list:
    """Parse ``diagnose sys session list`` output into normalized session rows."""
    if not raw_text or "session info:" not in raw_text:
        return []
    blocks = re.split(r"(?=^session info:)", raw_text.strip(), flags=re.MULTILINE)
    rows = []
    for blk in blocks:
        if "session info:" not in blk:
            continue
        proto_m = re.search(r"\bproto=(\d+)", blk)
        dur_m = re.search(r"\bduration=(\d+)", blk)
        pol_m = re.search(r"\bpolicy_id=(\d+)", blk)
        flow_m = re.search(
            r"hook=pre\s+dir=org\s+act=\S+\s+([0-9a-fA-F:.]+):(\d+)->([0-9a-fA-F:.]+):(\d+)",
            blk,
        )
        reason_m = re.search(r"\bno_ofld_reason[:=]\s*([A-Za-z0-9_.-]+)", blk)
        ofld_m = re.search(r"\b(?:offload|ofld)[:=]\s*(\S+)", blk)
        state_m = re.search(r"\bstate=([^\r\n]+)", blk)

        if not (proto_m or flow_m):
            continue

        row: Dict[str, Any] = {
            "protocol": _PROTO_BY_NUM.get(proto_m.group(1), proto_m.group(1)) if proto_m else "",
            "duration": int(dur_m.group(1)) if dur_m else None,
            "policy_id": int(pol_m.group(1)) if pol_m else None,
        }
        if flow_m:
            row["source"] = flow_m.group(1)
            row["source_port"] = int(flow_m.group(2))
            row["destination"] = flow_m.group(3)
            row["destination_port"] = int(flow_m.group(4))
        if reason_m:
            row["no_ofld_reason"] = reason_m.group(1)
        if ofld_m:
            row["offload"] = ofld_m.group(1)
        elif state_m:
            st_tokens = set(state_m.group(1).lower().split())
            if "ofld" in st_tokens or "npu" in st_tokens:
                row["npu_state"] = "ofld"
        rows.append(normalize_session_row(row))
    return rows


def get_sessions(device, src_ip: Optional[str] = None, dst_ip: Optional[str] = None,
                 dst_port: Optional[int] = None, count: int = 100):
    """Sessioni attive (session table), filtrabili per src/dst/porta."""
    params: Dict[str, Any] = {"count": int(count)}
    if src_ip:
        params["srcaddr"] = src_ip
    if dst_ip:
        params["dstaddr"] = dst_ip
    if dst_port:
        params["dstport"] = int(dst_port)
    filt = []
    if src_ip:
        filt.append(f"diagnose sys session filter src {src_ip}")
    if dst_ip:
        filt.append(f"diagnose sys session filter dst {dst_ip}")
    if dst_port:
        filt.append(f"diagnose sys session filter dport {dst_port}")
    ssh_cmd = "\n".join(["diagnose sys session filter clear", *filt,
                         "diagnose sys session list"])
    # `monitor/firewall/session` da solo e' un 404 su 7.6.7: il body dice
    # {"path":"firewall","name":"session","action":""} — il path esiste ma
    # nessuna azione GET vi corrisponde. L'elenco delle sessioni sta su
    # .../session/select, che accetta proprio srcaddr/dstaddr/dstport/count.
    # Il path vecchio resta come secondo tentativo per le versioni che lo
    # servivano.
    res = _api_or_ssh(device,
                      ("monitor/firewall/session/select", "monitor/firewall/session"),
                      params, ssh_cmd)
    data = res.get("data")
    if res.get("source") == "api":
        if isinstance(data, list):
            res["data"] = [normalize_session_row(r) if isinstance(r, dict) else r for r in data]
        elif isinstance(data, dict) and isinstance(data.get("details"), list):
            res["data"] = {
                **data,
                "details": [normalize_session_row(r) if isinstance(r, dict) else r for r in data["details"]],
            }
    elif res.get("source") == "ssh" and isinstance(data, str):
        parsed = parse_sessions_cli(data)
        if parsed:
            res["data"] = parsed
    return res


def delete_sessions(device, src_ip: Optional[str] = None, dst_ip: Optional[str] = None,
                    dst_port: Optional[int] = None):
    """Termina le sessioni attive nel firewall in base ai filtri specificati."""
    filt = []
    if src_ip:
        filt.append(f"diagnose sys session filter src {src_ip}")
    if dst_ip:
        filt.append(f"diagnose sys session filter dst {dst_ip}")
    if dst_port:
        filt.append(f"diagnose sys session filter dport {dst_port}")
    if not filt:
        raise FortiGateError("At least one filter (src_ip, dst_ip, dst_port) is required to clear sessions.")

    ssh_cmd = "\n".join(["diagnose sys session filter clear", *filt, "diagnose sys session clear"])
    out = ssh_command(device, ssh_cmd)
    return {"source": "ssh", "status": "success", "message": "Filter applied and sessions cleared", "output": out}


def get_routes(device):
    return _api_or_ssh(device, "monitor/router/ipv4", None,
                       "get router info routing-table all")


def get_vpn_tunnels(device):
    """Stato VIVO dei tunnel IPsec: phase1 su/giù, phase2 e selettori.

    La configurazione statica diceva quali tunnel ESISTONO; questo dice quali
    stanno in piedi adesso. Per una diagnosi fra due sedi è la differenza fra
    "il tunnel c'è" e "il tunnel funziona"."""
    return _api_or_ssh(device, "monitor/vpn/ipsec", None,
                       "get vpn ipsec tunnel summary")


def get_sdwan_health(device):
    """Qualità dei link SD-WAN (latenza, jitter, packet loss per SLA).

    Un FortiGate senza SD-WAN configurata risponde 404 e questa solleva
    FortiGateError: è corretto, la tab lo rende come pannello vuoto invece
    che come errore."""
    data = api_get(device["IP"], "monitor/virtual-wan/health-check")
    return {"source": "api", "data": data.get("results", data)}


def get_policy_routes(device):
    """Configured policy routes (PBR). They are matched BEFORE the routing
    table, so a route graph that ignores them shows a path the traffic does
    not take. REST only: the CLI text is not parsed anywhere."""
    data = api_get_cmdb(device["IP"], "cmdb/router/policy")
    return {"source": "api", "data": data.get("results", data)}


def get_route_for(device, dst_ip: str):
    """La rotta che il FortiGate userebbe per ``dst_ip``: prefisso più
    specifico che lo contiene, con gateway e interfaccia di uscita.

    Risponde a "non c'è rotta verso la subnet del datacenter", che nessuna
    ispezione delle policy può rivelare: una policy che permette il traffico
    e una rotta che non esiste danno lo stesso sintomo e richiedono due
    interventi diversi.

    Solo REST, come ``policy_lookup``: l'uscita CLI è testo libero che varia
    per versione, e un parser che sbaglia qui manderebbe a cercare un guasto
    di routing che non c'è.
    """
    import ipaddress

    ip = device["IP"]
    try:
        addr = ipaddress.ip_address(dst_ip)
    except ValueError:
        raise FortiGateError(f"'{dst_ip}' non è un indirizzo IP valido.")
    try:
        data = api_get(ip, "monitor/router/ipv4")
    except FortiGateError as e:
        raise FortiGateError(f"tabella di routing disponibile solo via REST API: {e}")

    best = None
    best_len = -1
    for r in (data.get("results") or []):
        if not isinstance(r, dict):
            continue
        raw = r.get("ip_mask") or r.get("dst") or ""
        try:
            net = ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            continue
        if addr in net and net.prefixlen > best_len:
            best, best_len = r, net.prefixlen

    if best is None:
        return {"source": "api", "data": {"matched": False, "dst_ip": dst_ip}}
    return {"source": "api", "data": {
        "matched": True, "dst_ip": dst_ip,
        "destination": best.get("ip_mask") or best.get("dst"),
        "gateway": best.get("gateway"),
        "interface": best.get("interface"),
        "distance": best.get("distance"), "metric": best.get("metric"),
        "type": best.get("type")}}


def _enforce_log_subtype(rows, log_subtype: str):
    """Tiene solo le righe del sottotipo richiesto, se le righe lo dichiarano.

    Perché serve: la GUI del FortiGate separa *Forward Traffic* (traffico che
    ATTRAVERSA il firewall, gestito dalle policy normali) da *Local Traffic*
    (traffico verso gli IP del FortiGate stesso o da lui generato, gestito
    dalle local-in policy). Entrambi possono mostrare policy id 0 — l'implicit
    deny nel forward, la local-in di default nel local — quindi l'id della
    policy NON basta a distinguerli. Il campo che li distingue è ``subtype``.

    Su alcune versioni di FortiOS il percorso ``log/{dev}/traffic/{subtype}``
    non restringe davvero il risultato e torna traffico locale a chi ha
    chiesto forward. Qui si riallinea la risposta alla domanda.

    Il filtro si applica SOLO se almeno una riga porta ``subtype``: filtrare
    su un campo che non esiste svuoterebbe la vista e sembrerebbe "nessun
    log", che in diagnosi è peggio del problema che risolve. Ritorna
    ``(righe, filtrato)`` così il chiamante può dire se è stato necessario.
    """
    if not isinstance(rows, list):
        return rows, False
    if not any(isinstance(r, dict) and r.get("subtype") for r in rows):
        return rows, False
    kept = [r for r in rows
            if not isinstance(r, dict) or r.get("subtype") == log_subtype]
    return kept, len(kept) != len(rows)


def _log_search(ip: str, path: str, params: dict, deadline: float = 10.0):
    """Una ricerca sui log portata a termine, non la sua prima risposta.

    La ricerca log del FortiGate è ASINCRONA: la prima chiamata avvia un
    motore che scorre il file e può tornare subito con ``ready: False``,
    ``total_lines: 0`` e zero righe mentre il lavoro è appena cominciato.
    Prendere quella risposta per buona mostra "nessun log" a una query che
    ha migliaia di match — misurato: ``date==<giorno>`` tornava 0 righe al
    primo colpo e 2761 righe un secondo dopo.

    Si ripete con lo stesso ``session_id`` finché ``ready``. Il tetto di
    tempo serve perché una ricerca su un log grande non blocchi la pagina:
    scaduto, si restituisce il parziale, che resta la risposta migliore
    disponibile.

    Nota sui campi: ``completed`` e ``percent_logs_processed`` sono
    percentuali (2, 30, 35...), non booleani. L'unico flag è ``ready``.
    """
    sid = None
    stop_at = time.monotonic() + deadline
    while True:
        p = dict(params)
        if sid:
            p["session_id"] = sid
        data = api_get(ip, path, p)
        if not isinstance(data, dict):
            return data
        sid = data.get("session_id", sid)
        # `ready` assente = risposta non asincrona (altra versione, altro
        # endpoint): è già il risultato, non c'è niente da attendere.
        if data.get("ready", True) or time.monotonic() >= stop_at:
            return data
        time.sleep(0.4)


def _log_range_days(since: Optional[str], until: Optional[str], cap: int = 31):
    """I giorni da interrogare per un intervallo, dal più recente al più vecchio.

    Perché un giorno alla volta invece di un filtro di intervallo: su FortiOS
    7.4 il log API rifiuta gli operatori ``>=`` e ``<=`` con HTTP 500 (provato
    su ``date`` e su ``eventtime``), e ripetere lo stesso campo non produce un
    OR — vince l'ultimo filtro. ``date==<giorno>`` invece funziona ed è esatto,
    quindi l'intervallo si copre enumerando le giornate. Campi diversi sono
    in AND, così il filtro sul sottotipo resta valido dentro ogni giornata.

    Il chiamante si ferma appena ha le righe che gli servono, perciò di solito
    parte una sola richiesta. ``cap`` limita il caso patologico (intervallo di
    un anno su un log vuoto = una richiesta per giorno).
    """
    if not since and not until:
        return []
    fmt = "%Y-%m-%d"
    end = datetime.datetime.strptime(until, fmt).date() if until \
        else datetime.date.today()
    start = datetime.datetime.strptime(since, fmt).date() if since \
        else end - datetime.timedelta(days=cap - 1)
    if start > end:
        return []
    days = []
    d = end
    while d >= start and len(days) < cap:
        days.append(d.strftime(fmt))
        d -= datetime.timedelta(days=1)
    return days


def get_traffic_logs(device, src_ip: Optional[str] = None, dst_ip: Optional[str] = None,
                     action: Optional[str] = None, count: int = 100,
                     log_device: str = "disk", log_type: str = "traffic",
                     log_subtype: str = "forward", cli_category: str = "traffic",
                     since: Optional[str] = None, until: Optional[str] = None):
    """Log del firewall (disk o memory), filtrabili. Risponde a 'cosa dicono i
    log per questo client?'.

    ``log_type``/``log_subtype`` compongono il percorso REST
    ``log/{device}/{type}/{subtype}``; ``cli_category`` è la categoria per il
    fallback ``execute log filter category``. I default danno il traffico
    forward, cioè il comportamento storico invariato.

    Perché parametri e non un elenco di categorie UTM predefinite: un sito che
    "si carica a metà" di solito è web filter, application control o SSL deep
    inspection, non un deny di policy — ma i sottotipi REST esatti variano per
    versione di FortiOS, e non sono stati verificati contro un apparato con
    profili di sicurezza attivi (licenza eval: nessun profilo attivabile).
    Codificare qui una lista indovinata produrrebbe 404 travestiti da "nessun
    log", che in diagnosi è peggio di un buco dichiarato. Il chiamante passa
    la coppia che il suo FortiOS espone; l'unica verificata è quella di
    default.

    Nota: chi inoltra i syslog al collector integrato vede comunque i verdetti
    UTM, perché ``observability/fieldmap.py`` legge ``utmaction`` e ``subtype``
    dal messaggio grezzo — quella strada non dipende da questi percorsi REST.

    ``since``/``until`` sono date ``YYYY-MM-DD``. Diventano una richiesta per
    giornata (``date==<giorno>``), dalla più recente alla più vecchia, perché
    gli operatori di intervallo non esistono su questo API — vedi
    ``_log_range_days``. Omesse, il comportamento è quello storico (le ultime
    ``count`` righe). Restano applicate solo al percorso REST: la sintassi di
    ``execute log filter`` per gli intervalli varia per versione di FortiOS e
    indovinarla darebbe zero righe travestite da "nessun log" — lo stesso
    rischio che questa funzione documenta già per i sottotipi UTM.
    """
    base_params: Dict[str, Any] = {"rows": int(count)}
    filters = []
    if src_ip:
        filters.append(f"srcip=={src_ip}")
    if dst_ip:
        filters.append(f"dstip=={dst_ip}")
    if action:
        filters.append(f"action=={action}")
    days = _log_range_days(since, until)
    ip = device["IP"]
    api_err = None
    # Il sottotipo va chiesto anche come filtro, non solo nel percorso: dove
    # FortiOS ignora `log/{dev}/{type}/{subtype}` (vedi _enforce_log_subtype)
    # `rows` conta righe di TUTTI i sottotipi, quindi chiedere 100 righe
    # forward su un apparato pieno di traffico locale ne restituisce zero e
    # sembra "nessun log". Col filtro le `count` righe sono già quelle giuste.
    # Failsafe: se la versione rifiuta il filtro (errore) o lo accetta ma
    # svuota il risultato (nome/valore di campo diverso), si ritenta senza —
    # lì _enforce_log_subtype fa lo stesso lavoro a valle, sul campione più
    # ampio possibile. Un filtro non supportato non deve costare i log.
    for dev in (log_device, "memory" if log_device == "disk" else "disk"):
        path = f"log/{dev}/{log_type}/{log_subtype}"
        for extra in ([f"subtype=={log_subtype}"], []):
            try:
                rows = []
                # Senza intervallo è una sola ricerca; con l'intervallo una per
                # giornata, e ci si ferma appena `count` righe sono raccolte.
                for day in (days or [None]):
                    params = dict(base_params)
                    flt = filters + extra + ([f"date=={day}"] if day else [])
                    if flt:
                        params["filter"] = flt
                    data = _log_search(ip, path, params)
                    got = data.get("results", data) if isinstance(data, dict) else data
                    if not isinstance(got, list):
                        rows = got
                        break
                    rows += got
                    if len(rows) >= count:
                        rows = rows[:count]
                        break
            except FortiGateError as e:
                api_err = str(e)
                continue
            if extra and not rows:
                continue
            rows, enforced = _enforce_log_subtype(rows, log_subtype)
            return {"source": "api", "log_device": dev,
                    "log_type": log_type, "log_subtype": log_subtype,
                    "subtype_enforced": enforced,
                    "days_queried": len(days) or None,
                    "data": rows}
    # Fallback CLI: execute log filter + display.
    # ``category`` da solo NON restringe il sottotipo: con category=traffic la
    # CLI restituisce forward, local e multicast mescolati, così il fallback
    # mostrava traffico locale a chi aveva chiesto forward. Il percorso REST
    # sopra distingue i due (log/{dev}/{type}/{subtype}); qui serve il filtro
    # esplicito sul campo, altrimenti REST e SSH rispondono a due domande
    # diverse senza dirlo.
    lines = ["execute log filter reset",
             f"execute log filter category {cli_category}",
             f"execute log filter field subtype {log_subtype}"]
    ssh_filters = []
    if src_ip:
        ssh_filters.append(f"execute log filter field srcip {src_ip}")
    if dst_ip:
        ssh_filters.append(f"execute log filter field dstip {dst_ip}")
    if action:
        ssh_filters.append(f"execute log filter field action {action}")
    lines += ssh_filters + [f"execute log filter view-lines {min(count, 1000)}",
                            "execute log display"]
    try:
        out = ssh_command(device, "\n".join(lines), timeout=60)
        return {"source": "ssh", "api_error": api_err, "data": out}
    except FortiGateError as ssh_err:
        raise FortiGateError(f"API: {api_err} | SSH: {ssh_err}")


def get_wifi_clients(device):
    """Client WiFi connessi ai FortiAP gestiti (RSSI, SNR, AP, SSID)."""
    return _api_or_ssh(device, "monitor/wifi/client", {"with_triangulation": "false"},
                       "diagnose wireless-controller wlac -c sta")


def get_managed_aps(device):
    """FortiAP gestiti: stato, canale, client, versione."""
    return _api_or_ssh(device, "monitor/wifi/managed_ap", None,
                       "diagnose wireless-controller wlac -c wtp")


def get_full_config(device):
    """Configurazione completa del FortiGate (backup testuale).
    Via API: monitor/system/config/backup?scope=global (testo, non JSON)."""
    ip = device["IP"]
    token, port, verify = get_api_config(ip)
    api_err = None
    if token:
        try:
            # Vedi api_request: silenziamento limitato alla singola richiesta.
            with warnings.catch_warnings():
                if not verify:
                    warnings.simplefilter(
                        "ignore", urllib3.exceptions.InsecureRequestWarning)
                r = _http(ip).get(
                    f"https://{ip}:{port}/api/v2/monitor/system/config/backup",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"scope": "global"}, verify=verify, timeout=60)
            if r.status_code < 400:
                return {"source": "api", "data": r.text}
            api_err = f"HTTP {r.status_code}: {r.text[:200]}"
        except requests.RequestException as e:
            api_err = str(e)
    else:
        api_err = f"Nessun token API configurato per {ip}."
    try:
        out = ssh_command(device, "show full-configuration", timeout=120)
        return {"source": "ssh", "api_error": api_err, "data": out}
    except FortiGateError as ssh_err:
        raise FortiGateError(f"API: {api_err} | SSH: {ssh_err}")


# --- Diagnosi aggregata client ------------------------------------------------

def diagnose_client(device, client: str, dest: Optional[str] = None,
                    dest_port: Optional[int] = 443, protocol: str = "TCP") -> dict:
    """Raccoglie in un colpo solo tutto ciò che il FortiGate sa di un client
    (IP o MAC) ed eventualmente del flusso verso `dest`: inventario device,
    ARP/DHCP, sessioni, policy match e ultimi log. Pensato per l'AI assistant
    e per il tool MCP 'fortigate_diagnose_client'.

    Ogni sezione è best-effort: se una sorgente fallisce si riporta l'errore
    nella sezione invece di far fallire l'intera diagnosi."""
    is_mac = bool(re.fullmatch(r"[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}", client))
    result = {"client": client, "client_type": "mac" if is_mac else "ip",
              "fortigate": device.get("IP"), "sections": {}}

    def section(name, fn, *args, **kw):
        try:
            result["sections"][name] = fn(*args, **kw)
        except Exception as e:
            result["sections"][name] = {"error": str(e)}

    client_ip = None if is_mac else client

    section("device_inventory", get_device_inventory, device)
    section("arp", get_arp_table, device)
    section("dhcp_leases", get_dhcp_leases, device)

    # Se il client era un MAC, prova a risolverlo in IP da inventory/ARP/DHCP.
    if is_mac:
        norm = re.sub(r"[^0-9a-f]", "", client.lower())
        for sec in ("device_inventory", "dhcp_leases", "arp"):
            data = result["sections"].get(sec, {}).get("data")
            if not isinstance(data, list):
                continue
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                mac = re.sub(r"[^0-9a-f]", "", str(entry.get("mac", "")).lower())
                if mac == norm and entry.get("ip" if sec != "dhcp_leases" else "ip"):
                    client_ip = entry.get("ip")
                    break
            if client_ip:
                break
        result["resolved_ip"] = client_ip

    if client_ip:
        section("sessions", get_sessions, device, src_ip=client_ip)
        section("traffic_logs", get_traffic_logs, device, src_ip=client_ip, count=50)
        if dest:
            section("policy_lookup", policy_lookup, device, client_ip, dest,
                    protocol=protocol, dest_port=dest_port)
    section("wifi_clients", get_wifi_clients, device)
    return result


# --- Advisor live L7/SPU ------------------------------------------------------

_ADVISOR_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "WARN": 2, "INFO": 3}
_GENERIC_IPS_NAMES = frozenset({"default", "high_security", "all_default", "all_default_pass"})
_BYPASS_TOP_BYTES = 100_000_000


def _policy_member_names(val: Any) -> list[str]:
    if not val:
        return []
    items = val if isinstance(val, list) else [val]
    out = []
    for item in items:
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("q_origin_key") or "").strip().lower()
        else:
            name = str(item or "").strip().lower()
        if name:
            out.append(name)
    return out


def _vip_remediation_cli(pid: str) -> str:
    return (
        "config firewall ssl-ssh-profile\n"
        '    edit "SSL_Protect_WebServer"\n'
        "        config https\n"
        "            set ports 443\n"
        "            set status deep-inspection\n"
        "            set min-allowed-ssl-version tls-1.2\n"
        "            set unsupported-ssl-version block\n"
        "            set expired-server-cert block\n"
        "        end\n"
        "        set server-cert-mode replace\n"
        '        set server-cert "Cert_WebServer_Prod"\n'
        "    next\n"
        "end\n"
        "config ips sensor\n"
        '    edit "IPS_WebServer_Linux"\n'
        "        config entries\n"
        "            edit 1\n"
        "                set location server\n"
        "                set severity high critical\n"
        "                set os Linux\n"
        "                set application Apache Nginx\n"
        "                set status enable\n"
        "                set action block\n"
        "            next\n"
        "        end\n"
        "    next\n"
        "end\n"
        "config firewall policy\n"
        f"    edit {pid}\n"
        "        set inspection-mode flow\n"
        "        set utm-status enable\n"
        '        set ssl-ssh-profile "SSL_Protect_WebServer"\n'
        '        set ips-sensor "IPS_WebServer_Linux"\n'
        "    next\n"
        "end"
    )


def get_firewall_advisor(device, lang: str = "it") -> dict:
    """Hardware-aware live policy & security profile recommendations."""
    en = (lang or "it").strip().lower().startswith("en")
    errors: Dict[str, str] = {}

    status_data: Dict[str, Any] = {}
    try:
        st_res = get_system_status(device)
        if isinstance(st_res.get("data"), dict):
            status_data = st_res["data"]
    except FortiGateError as e:
        errors["status"] = str(e)

    policies: list[dict] = []
    try:
        pol_res = get_policies_with_stats(device)
        raw_pols = pol_res.get("data")
        if isinstance(raw_pols, list):
            policies = [p for p in raw_pols if isinstance(p, dict)]
        if pol_res.get("stats_error"):
            errors["policy_stats"] = str(pol_res["stats_error"])
    except FortiGateError as e:
        errors["policies"] = str(e)

    vip_names: set[str] = set()
    try:
        vip_res = get_vips(device)
        for v in (vip_res.get("data") or []):
            if isinstance(v, dict) and v.get("name"):
                vip_names.add(str(v["name"]).strip().lower())
    except FortiGateError as e:
        errors["vips"] = str(e)

    profile_errors: Dict[str, str] = {}
    try:
        sp_res = get_security_profiles(device)
        if isinstance(sp_res.get("errors"), dict):
            profile_errors = dict(sp_res["errors"])
    except FortiGateError as e:
        errors["security_profiles"] = str(e)

    model = (
        status_data.get("model_name")
        or status_data.get("model")
        or status_data.get("platform_name")
        or (device.get("Model") if isinstance(device, dict) else "")
        or ""
    )
    version = (
        status_data.get("version")
        or (device.get("Version") if isinstance(device, dict) else "")
        or ""
    )
    serial = status_data.get("serial") or ""
    profile: FortiGateHWProfile = resolve_profile(
        model=str(model), version=str(version), serial=str(serial),
    )

    recs: list[Dict[str, Any]] = []

    def add_rec(rec_id: str, severity: str, category: str, pid: Optional[str],
                pname: str, title_it: str, title_en: str,
                detail_it: str, detail_en: str, cli: str = "") -> None:
        recs.append({
            "id": rec_id,
            "severity": severity,
            "category": category,
            "policy_id": pid,
            "policy_name": pname,
            "title": title_en if en else title_it,
            "detail": detail_en if en else detail_it,
            "cli": cli,
        })

    for idx, row in enumerate(policies):
        action = str(row.get("action") or "").strip().lower()
        status = str(row.get("status") or "enable").strip().lower()
        if action != "accept" or status == "disable":
            continue
        pid = str(row.get("policyid") if row.get("policyid") is not None else "")
        pname = str(row.get("name") or (f"Policy {pid}" if pid else ""))

        insp_mode = str(row.get("inspection-mode") or row.get("inspection_mode") or "flow").strip().lower()
        if insp_mode == "proxy":
            sev = "CRITICAL" if profile.proxy_removed_2gb else "WARN"
            add_rec(
                f"ADV-PROXY-{pid}", sev, "SPU / Inspection", pid, pname,
                "Modalita' proxy attiva",
                "Proxy inspection mode enabled",
                (
                    "Su modelli 2GB con FortiOS 7.4.4+ la modalita' proxy non e' supportata: convertire a flow."
                    if profile.proxy_removed_2gb else
                    "La modalita' proxy trattiene le sessioni su CPU invece di usare il motore single-pass flow/CP9."
                ),
                (
                    "Proxy mode is unsupported on 2GB RAM units running FortiOS 7.4.4+: switch to flow."
                    if profile.proxy_removed_2gb else
                    "Proxy mode traps sessions on CPU instead of using flow single-pass/CP9 acceleration."
                ),
                f"config firewall policy\n    edit {pid}\n        set inspection-mode flow\n    next\nend",
            )

        asic_offload = str(row.get("auto-asic-offload") or row.get("asic_offload") or "enable").strip().lower()
        if not profile.is_vm and asic_offload == "disable":
            add_rec(
                f"ADV-OFFLOAD-{pid}", "WARN", "SPU / Offload", pid, pname,
                "Offload ASIC disabilitato sulla policy",
                "ASIC offload disabled on policy",
                "auto-asic-offload disable forza il traffico sulla CPU (no_ofld_reason=npu-disabled).",
                "auto-asic-offload disable forces forwarding onto CPU (no_ofld_reason=npu-disabled).",
                f"config firewall policy\n    edit {pid}\n        set auto-asic-offload enable\n    next\nend",
            )

        dst_names = set(_policy_member_names(row.get("dstaddr")))
        is_vip = bool(vip_names and (dst_names & vip_names))
        utm_disabled = str(row.get("utm-status") or "").strip().lower() == "disable"
        ips_name = _profile_name_val(row.get("ips-sensor"))
        if is_vip and (not ips_name or utm_disabled):
            add_rec(
                f"ADV-VIP-L7-{pid}", "HIGH", "Layer 7 / VIP", pid, pname,
                "Policy verso VIP senza sensore IPS attivo",
                "Inbound VIP policy missing active IPS sensor",
                "Pubblicare un VIP senza IPS espone i servizi ad exploit Layer 7. Applicare Protecting SSL Server + IPS mirato.",
                "Publishing a VIP without IPS exposes services to Layer 7 exploits. Apply Protecting SSL Server + targeted IPS.",
                _vip_remediation_cli(pid),
            )

        has_utm_prof = (
            not utm_disabled
            and any(_profile_name_val(row.get(k)) for k in ("av-profile", "ips-sensor", "webfilter-profile", "application-list"))
        )
        ssl_prof = _profile_name_val(row.get("ssl-ssh-profile"))
        if has_utm_prof and (not ssl_prof or ssl_prof.lower() == "no-inspection"):
            add_rec(
                f"ADV-SSL-{pid}", "WARN", "SSL Inspection", pid, pname,
                "Profili UTM attivi senza ispezione SSL/SSH",
                "UTM profiles active without SSL/SSH inspection",
                "Senza ssl-ssh-profile i motori L7 non ispezionano payload HTTPS. Impostare almeno certificate-inspection.",
                "Without ssl-ssh-profile, L7 engines cannot inspect encrypted HTTPS. Enable at least certificate-inspection.",
                f'config firewall policy\n    edit {pid}\n        set ssl-ssh-profile "certificate-inspection"\n    next\nend',
            )

        ips_low = ips_name.lower()
        if not utm_disabled and ips_low and (
            (is_vip and ips_low in _GENERIC_IPS_NAMES)
            or (profile.ram_tier == "2gb" and ips_low in ("high_security", "all_default"))
        ):
            loc = "server" if is_vip else "client"
            target_sensor = f"IPS_{loc.title()}_Scoped"
            add_rec(
                f"ADV-IPS-{pid}", "WARN", "IPS Tuning", pid, pname,
                f"Sensore IPS generico '{ips_name}'",
                f"Generic IPS sensor '{ips_name}'",
                "Sostituire il profilo generico con un sensore mirato per location, OS, applicazione e severity (high/critical) per ridurre CPU/RAM.",
                "Replace the generic profile with a sensor scoped by location, OS, application, and high/critical severity to reduce CPU/RAM load.",
                (
                    "config ips sensor\n"
                    f'    edit "{target_sensor}"\n'
                    "        config entries\n"
                    "            edit 1\n"
                    f"                set location {loc}\n"
                    "                set severity high critical\n"
                    "                set status enable\n"
                    "                set action block\n"
                    "            next\n"
                    "        end\n"
                    "    next\n"
                    "end"
                ),
            )

        l7_summary = _summarize_l7_profiles(row)
        src_names = set(_policy_member_names(row.get("srcaddr")))
        svc_names = set(_policy_member_names(row.get("service")))
        if not l7_summary and asic_offload == "enable":
            if (src_names & {"all", "any"}) or (dst_names & {"all", "any"}) or (svc_names & {"all", "any"}):
                add_rec(
                    f"ADV-BYPASS-{pid}", "WARN", "Bypass Scope", pid, pname,
                    "Policy senza UTM con offload attivo troppo ampia",
                    "UTM-less offloaded policy scope is overly broad",
                    "Le regole di bypass offload vanno limitate a host /32 puntuali e porte applicative specifiche (mai all/ALL).",
                    "Offloaded bypass rules should be scoped to exact /32 hosts and required ports (never all/ALL).",
                    f"config firewall policy\n    edit {pid}\n        set srcaddr <host_32>\n        set dstaddr <host_32>\n        set service <specific_port>\n    next\nend",
                )

        if idx >= 5 and int(row.get("bytes") or 0) >= _BYPASS_TOP_BYTES:
            add_rec(
                f"ADV-ORDER-{pid}", "INFO", "Policy Order", pid, pname,
                "Policy ad alto volume in posizione bassa",
                "High-volume policy positioned low in table",
                "Regola oltre la 5a posizione con traffico >= 100 MB: valutare spostamento in cima o bypass /32 dedicato per sfruttare first-match.",
                "Rule sits below position 5 with >= 100 MB traffic: consider moving higher or creating a /32 fast-path bypass for first-match efficiency.",
            )

    if profile_errors:
        fams = ", ".join(sorted(profile_errors))
        add_rec(
            "ADV-PROFILES-UNAVAIL", "INFO", "Licensing / Profiles", None, "",
            f"Famiglie profili non disponibili via REST: {fams}",
            f"Profile families unavailable via REST: {fams}",
            "Feature non abilitate o licenza FortiGuard assente per queste famiglie su questo apparato.",
            "Feature disabled or FortiGuard license unavailable for these profile families on this unit.",
        )

    recs.sort(key=lambda r: (_ADVISOR_SEVERITY_ORDER.get(r["severity"], 9), str(r.get("policy_id") or "")))
    summary = {
        "total": len(recs),
        "critical": sum(1 for r in recs if r["severity"] == "CRITICAL"),
        "high": sum(1 for r in recs if r["severity"] == "HIGH"),
        "warn": sum(1 for r in recs if r["severity"] == "WARN"),
        "info": sum(1 for r in recs if r["severity"] == "INFO"),
        "policies_analyzed": len(policies),
    }
    return {
        "source": "api",
        "data": {
            "hardware_profile": profile_to_dict(profile, lang=lang),
            "summary": summary,
            "recommendations": recs,
            "sniffer_syntax": profile.sniffer_syntax,
            "errors": errors,
        },
    }
