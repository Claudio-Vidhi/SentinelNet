# -*- coding: utf-8 -*-
"""FortiGate Service — accesso live a un FortiGate per l'osservabilità LAN.

Due trasporti:
  - REST API FortiOS (primario): token API "api-user", header Authorization
    Bearer, endpoint /api/v2/monitor|cmdb|log su HTTPS (porta admin, default
    443). Restituisce JSON strutturato.
  - SSH/CLI (fallback, Netmiko device_type 'fortinet'): usato quando il token
    API non è configurato o la chiamata REST fallisce; output testuale.

I token API sono salvati cifrati (crypto_vault) in data/fortigate_tokens.json,
per IP: {"<ip>": {"token_enc": ..., "port": 443, "verify_tls": false}}.

Le funzioni di alto livello (get_*) accettano il dict `device` dell'inventario
e ritornano sempre {"source": "api"|"ssh", "data": ...} oppure sollevano
FortiGateError con il dettaglio di entrambi i tentativi.
"""

import json
import os
import re
import threading
from typing import Optional, Any, Dict

import requests
import urllib3

from core import data_config
from security.crypto_vault import encrypt_password, decrypt_password

TOKENS_FILE = data_config.get_path("fortigate_tokens.json")

_lock = threading.Lock()


class FortiGateError(Exception):
    pass


# --- Persistenza token API ---------------------------------------------------

def _load_tokens() -> dict:
    try:
        with open(TOKENS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_tokens(tokens: dict):
    os.makedirs(os.path.dirname(TOKENS_FILE) or ".", exist_ok=True)
    with _lock:
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(tokens, f, indent=1)


def set_api_token(ip: str, token: str, port: int = 443, verify_tls: bool = False,
                  name: str = ""):
    """Salva (cifrato) il token API di un FortiGate. Token vuoto = rimozione
    (e, se era il target attivo, azzera anche `_active`)."""
    tokens = _load_tokens()
    if token:
        entry = {"token_enc": encrypt_password(token),
                 "port": int(port or 443), "verify_tls": bool(verify_tls)}
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
                  verify_tls: Optional[bool] = None, token: Optional[str] = None) -> None:
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
    tokens[ip] = entry
    _save_tokens(tokens)


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

def api_request(ip: str, method: str, path: str, params: Optional[dict] = None,
                json_body=None, timeout: int = 30):
    """Richiesta su /api/v2/<path> con Bearer token. Solleva FortiGateError."""
    token, port, verify = get_api_config(ip)
    if not token:
        raise FortiGateError(f"Nessun token API configurato per {ip}.")
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = f"https://{ip}:{port}/api/v2/{path.lstrip('/')}"
    try:
        r = requests.request(method, url,
                             headers={"Authorization": f"Bearer {token}"},
                             params=params or {}, json=json_body,
                             verify=verify, timeout=timeout)
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
    return api_get(device["IP"], "monitor/system/ha-status")


def get_ha_checksums(device: dict) -> dict:
    return api_get(device["IP"], "monitor/system/ha-checksums")


def api_post(ip: str, path: str, json_body=None, params: Optional[dict] = None,
             timeout: int = 60):
    """POST su /api/v2/<path> con Bearer token. Solleva FortiGateError."""
    return api_request(ip, "POST", path, params=params, json_body=json_body,
                       timeout=timeout)


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
    from netmiko import ConnectHandler
    from core.core_engine import get_device_credentials, get_device_port
    username, password, _secret = get_device_credentials(device)
    params = {"device_type": "fortinet", "host": device["IP"],
              "port": get_device_port(device),
              "username": username, "password": password,
              "timeout": timeout, "auth_timeout": 15, "banner_timeout": 15}
    try:
        with ConnectHandler(**params) as conn:
            res = conn.send_command(command, read_timeout=timeout)
            return res if isinstance(res, str) else str(res or "")
    except Exception as e:
        raise FortiGateError(f"SSH {device.get('IP')}: {e}")


# --- Helper API-first con fallback SSH ---------------------------------------

def _api_or_ssh(device, api_path, api_params, ssh_cmd, parser=None):
    ip = device["IP"]
    api_err = None
    try:
        data = api_get(ip, api_path, api_params)
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        api_err = str(e)
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
        return {"source": "api", "data": merged or data}
    except FortiGateError as e:
        api_err = str(e)
    try:
        out = ssh_command(device, "get system status")
        return {"source": "ssh", "api_error": api_err,
                "data": _parse_system_status_cli(out)}
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
                            fmt="name|type|subnet|fqdn|comment")
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        raise FortiGateError(f"firewall/address disponibile solo via REST API: {e}")


def get_firewall_policy_objects(device):
    """Policy firewall (cmdb) con soli campi rilevanti per l'osservabilità
    (policyid, nome, interfacce, indirizzi, servizi, azione, stato,
    logtraffic). Complementare a get_firewall_policies() (full config)."""
    ip = device["IP"]
    try:
        data = api_get_cmdb(ip, "cmdb/firewall/policy",
                            fmt="policyid|name|srcintf|dstintf|srcaddr|dstaddr|"
                                "service|action|status|logtraffic")
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

    merged = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        s = by_id.get(row.get("policyid"))
        merged.append({**row,
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


def policy_lookup(device, src_ip: str, dest: str, protocol: str = "TCP",
                  dest_port: int = 443, srcintf: Optional[str] = None):
    """Chiede al FortiGate QUALE policy matcherebbe un flusso (senza generare
    traffico): fondamentale per 'perché il client X non raggiunge il sito Y'.
    `dest` può essere IP o FQDN."""
    params = {"srcip": src_ip, "protocol": protocol.lower(),
              "dest": dest, "destport": int(dest_port), "ipv6": "false"}
    if srcintf:
        params["srcintf"] = srcintf
    ip = device["IP"]
    try:
        data = api_get(ip, "monitor/firewall/policy-lookup", params)
        return {"source": "api", "data": data.get("results", data)}
    except FortiGateError as e:
        # Nessun equivalente CLI 1:1 affidabile: si riporta l'errore API.
        raise FortiGateError(f"policy-lookup disponibile solo via REST API: {e}")


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
    return _api_or_ssh(device, "monitor/firewall/session", params, ssh_cmd)


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

    ``since``/``until`` sono date ``YYYY-MM-DD`` e diventano un filtro sul
    campo ``date``. Omesse, il comportamento è quello storico (le ultime
    ``count`` righe). Sono applicate solo al percorso REST: la sintassi di
    ``execute log filter`` per gli intervalli varia per versione di FortiOS e
    indovinarla darebbe zero righe travestite da "nessun log" — lo stesso
    rischio che questa funzione documenta già per i sottotipi UTM.
    """
    params: Dict[str, Any] = {"rows": int(count)}
    filters = []
    if src_ip:
        filters.append(f"srcip=={src_ip}")
    if dst_ip:
        filters.append(f"dstip=={dst_ip}")
    if action:
        filters.append(f"action=={action}")
    if since:
        filters.append(f"date>={since}")
    if until:
        filters.append(f"date<={until}")
    if filters:
        params["filter"] = filters
    ip = device["IP"]
    api_err = None
    for dev in (log_device, "memory" if log_device == "disk" else "disk"):
        try:
            data = api_get(ip, f"log/{dev}/{log_type}/{log_subtype}", params)
            rows = data.get("results", data)
            rows, enforced = _enforce_log_subtype(rows, log_subtype)
            return {"source": "api", "log_device": dev,
                    "log_type": log_type, "log_subtype": log_subtype,
                    "subtype_enforced": enforced,
                    "data": rows}
        except FortiGateError as e:
            api_err = str(e)
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
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            r = requests.get(
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
