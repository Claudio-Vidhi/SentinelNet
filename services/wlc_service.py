# -*- coding: utf-8 -*-
"""WLC Service — osservabilità wireless per controller Cisco: AireOS
(2504/3504/5508/8540, vWLC) e Catalyst 9800 (IOS-XE).

Trasporto: SSH/Netmiko (device_type risolto dal driver del vendor:
'cisco_wlc' -> cisco_wlc_ssh / AireOS, 'cisco_9800' o 'cisco' -> cisco_xe).
Le due famiglie usano CLI diverse: la mappa COMMANDS traduce ogni servizio
nel comando giusto per piattaforma. Output testuale grezzo, pensato per
essere interpretato da un LLM (MCP / AI assistant).
"""

import re
from contextlib import contextmanager
from typing import Optional

from core.core_engine import resolve_driver, get_device_credentials


class WlcError(Exception):
    pass


def platform_of(device: dict) -> str:
    """'aireos' oppure 'iosxe', dedotto dal driver associato al vendor.
    Vendor 'cisco' generico viene trattato come 9800/IOS-XE."""
    vendor = (device.get("Vendor") or "").lower()
    if vendor == "cisco_wlc":
        return "aireos"
    return "iosxe"


# servizio -> {piattaforma: comando}; {mac} sostituito nei comandi per-client.
COMMANDS = {
    "status": {
        "aireos": "show sysinfo",
        "iosxe": "show wireless summary",
    },
    "ap_summary": {
        "aireos": "show ap summary",
        "iosxe": "show ap summary",
    },
    "client_summary": {
        "aireos": "show client summary",
        "iosxe": "show wireless client summary",
    },
    "client_detail": {
        "aireos": "show client detail {mac}",
        "iosxe": "show wireless client mac-address {mac} detail",
    },
    "wlan_summary": {
        "aireos": "show wlan summary",
        "iosxe": "show wlan summary",
    },
    "rogue_aps": {
        "aireos": "show rogue ap summary",
        "iosxe": "show wireless wps rogue ap summary",
    },
    "interfaces": {
        "aireos": "show interface summary",
        "iosxe": "show ip interface brief",
    },
}

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}$")


def normalize_mac(mac: str, platform: str) -> str:
    """Normalizza un MAC nel formato atteso dalla piattaforma
    (entrambe accettano aa:bb:cc:dd:ee:ff)."""
    mac = (mac or "").strip()
    if not _MAC_RE.fullmatch(mac.replace(" ", "")):
        raise WlcError(f"MAC address non valido: '{mac}'")
    digits = re.sub(r"[^0-9a-f]", "", mac.lower())
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def detect_platform(sysinfo: str, device: dict) -> str:
    """Piattaforma dedotta dalla risposta a 'show sysinfo': AireOS la
    implementa, IOS-XE la rifiuta. Il vendor dell'inventario resta solo come
    ripiego: un 5508 registrato come 'cisco' generico veniva altrimenti
    interrogato con la CLI del 9800, che non capisce."""
    if "Product Version" in sysinfo:
        return "aireos"
    if "% Invalid input" in sysinfo or "% Ambiguous" in sysinfo:
        return "iosxe"
    return platform_of(device)


def _send(conn, command: str, timeout: int = 30) -> str:
    res = conn.send_command(command, read_timeout=timeout)
    return res if isinstance(res, str) else str(res or "")


@contextmanager
def _session(device: dict, timeout: int = 30):
    """Apre una sola sessione SSH e ne cede (conn, platform, sysinfo).
    AireOS accetta al massimo 5 sessioni SSH concorrenti: un comando per
    connessione esauriva il controller a ogni refresh del tab."""
    from netmiko import ConnectHandler
    vendor = (device.get("Vendor") or "").lower()
    try:
        _, netmiko_type = resolve_driver(vendor)
    except ValueError as e:
        raise WlcError(str(e))
    username, password, secret = get_device_credentials(device)
    params = {"device_type": netmiko_type, "host": device["IP"],
              "username": username, "password": password, "secret": secret,
              "timeout": timeout, "auth_timeout": 15, "banner_timeout": 15}
    try:
        conn = ConnectHandler(**params)
    except Exception as e:
        raise WlcError(f"SSH {device.get('IP')}: {e}")
    try:
        try:
            sysinfo = _send(conn, "show sysinfo", timeout)
        except Exception as e:
            raise WlcError(f"SSH {device.get('IP')}: {e}")
        platform = detect_platform(sysinfo, device)
        try:
            if platform == "aireos":
                # Il driver netmiko cisco_ios manda 'terminal length 0', che
                # AireOS rifiuta: senza questo l'output si ferma al '--More--'
                # e le tabelle arrivano troncate.
                conn.send_command_timing("config paging disable")
            else:
                conn.enable()
        except Exception:
            pass
        yield conn, platform, sysinfo
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


def query(device: dict, service: str, mac: Optional[str] = None) -> dict:
    """Esegue il servizio richiesto sul WLC e ritorna
    {"platform", "command", "data"}."""
    if service not in COMMANDS:
        raise WlcError(f"Servizio WLC sconosciuto: '{service}'")
    needs_mac = any("{mac}" in c for c in COMMANDS[service].values())
    if needs_mac and not mac:
        raise WlcError(f"Il servizio '{service}' richiede un MAC address.")
    timeout = 60 if service == "client_detail" else 30
    with _session(device, timeout) as (conn, platform, sysinfo):
        command = COMMANDS[service][platform]
        if "{mac}" in command:
            command = command.format(mac=normalize_mac(mac or "", platform))
        if service == "status" and platform == "aireos":
            data = sysinfo  # gia' letto in fase di rilevamento
        else:
            try:
                data = _send(conn, command, timeout)
            except Exception as e:
                raise WlcError(f"SSH {device.get('IP')}: {e}")
    return {"platform": platform, "command": command, "data": data}


# --- parsing dell'output CLI -------------------------------------------------
# Il tab Live riceveva {"data": "<testo grezzo>"} e cercava data.aps /
# data.clients: le tabelle restavano vuote su qualunque piattaforma. Qui il
# testo diventa le liste che la UI (e l'MCP) si aspettano.

_RULER_RE = re.compile(r"^[-\s]*-{3,}[-\s]*$")

# frammento di intestazione (minuscolo) -> chiave prodotta. L'ordine conta:
# vince il primo frammento contenuto nel nome di colonna.
_AP_FIELDS = {"ap name": "name", "ip address": "ip", "ethernet mac": "mac",
              "ap model": "model", "clients": "clients", "state": "status",
              "status": "status"}
_CLIENT_FIELDS = {"mac address": "mac", "ap name": "ap_name",
                  "ip address": "ip", "wlan": "wlan", "protocol": "protocol",
                  "state": "status", "status": "status"}
_WLAN_FIELDS = {"ssid": "ssid", "profile name": "ssid", "wlan id": "id",
                "id": "id", "status": "status", "security": "security"}
_ROGUE_FIELDS = {"mac address": "mac", "ssid": "ssid", "channel": "channel",
                 "rssi": "rssi", "status": "status"}


def _table_rows(text: str, fields: dict) -> list:
    """Converte una tabella 'show ...' in lista di dict.

    I confini di colonna vengono dalla riga di trattini quando e' spezzata per
    colonna (AireOS) e dalle posizioni delle intestazioni altrimenti (IOS-XE
    stampa un unico trattino lungo). Ogni colonna arriva fino all'inizio della
    successiva, cosi' un valore piu' largo dell'intestazione non viene tagliato.
    """
    lines = (text or "").splitlines()
    header_i = next((i for i, ln in enumerate(lines)
                     if sum(1 for k in fields if k in ln.lower()) >= 2), None)
    if header_i is None:
        return []
    header = lines[header_i]
    starts, first_row = None, header_i + 1
    if header_i + 1 < len(lines) and lines[header_i + 1].strip() \
            and _RULER_RE.match(lines[header_i + 1]):
        first_row = header_i + 2
        groups = [m.start() for m in re.finditer(r"-+", lines[header_i + 1])]
        if len(groups) > 1:
            starts = groups
    if not starts:
        starts = [m.start() for m in re.finditer(r"\S+(?: \S+)*", header)]
    if not starts:
        return []
    spans = [(s, starts[i + 1] if i + 1 < len(starts) else len(header) + 4096)
             for i, s in enumerate(starts)]

    keymap = {}
    for idx, (a, b) in enumerate(spans):
        col = header[a:b].strip().lower()
        for frag, key in fields.items():
            if frag in col and key not in keymap.values():
                keymap[idx] = key
                break
    if not keymap:
        return []

    rows = []
    for line in lines[first_row:]:
        if not line.strip():
            if rows:
                break
            continue
        if _RULER_RE.match(line):
            continue
        # I valori non stanno sempre sotto la loro intestazione: un modello o
        # una location piu' larghi del titolo spostano a destra tutte le
        # colonne seguenti, e tagliare a posizione fissa spezzava l'IP
        # ("IP Address" prendeva la coda di Country + meta' indirizzo). Quando
        # i campi separati da due o piu' spazi sono tanti quante le colonne,
        # quelli sono i valori veri; altrimenti si torna al taglio a posizione.
        cells = re.split(r"\s{2,}", line.strip())
        if len(cells) != len(spans):
            cells = [line[a:b].strip() for a, b in spans]
        row = {key: cells[idx] for idx, key in keymap.items()
               if idx < len(cells)}
        if any(row.values()):
            rows.append(row)
    return rows


def parse_sysinfo(text: str) -> dict:
    """'show sysinfo' AireOS: righe 'Etichetta.......... valore'."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^(.*?)\.{2,}\s*(.*)$", line)
        if m and m.group(1).strip():
            out[m.group(1).strip().lower()] = m.group(2).strip()
    return out


def parse_ap_autorf(text: str) -> dict:
    """Channel, channel width and 5 GHz load from 'show ap auto-rf 802.11a
    <ap>' (AireOS). 'show ap summary' carries none of it, and the width is the
    first thing to look at on a slow cell: only auto-rf prints it."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(.*?)\s*(?:\.{2,}|:)\s*(\S.*?)\s*$", line)
        if not m or not m.group(1).strip():
            continue
        label, value = m.group(1).strip().lower(), m.group(2)
        if "channel width" in label and "channel_width" not in out:
            out["channel_width"] = value
        elif "current channel" in label and "energy" not in label \
                and "channel" not in out:
            out["channel"] = value
        elif "channel utilization" in label and "channel_utilization" not in out:
            out["channel_utilization"] = value
        elif "noise profile" in label and "noise_profile" not in out:
            out["noise_profile"] = value
    return out


def parse_client_detail(text: str) -> dict:
    """IP, RSSI e SNR dal dettaglio di un client. AireOS scrive
    'Etichetta.......... valore', IOS-XE 'Etichetta : valore'."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(.*?)\s*(?:\.{2,}|:)\s*(\S.*?)\s*$", line)
        if not m or not m.group(1).strip():
            continue
        label, value = m.group(1).strip().lower(), m.group(2)
        if ("signal strength" in label or "rssi" in label) and "rssi" not in out:
            out["rssi"] = re.sub(r"\s*dBm$", "", value, flags=re.I)
        elif ("signal to noise" in label or "snr" in label) and "snr" not in out:
            out["snr"] = re.sub(r"\s*dB$", "", value, flags=re.I)
        elif ("ip address" in label or "ipv4 address" in label) \
                and "ipv6" not in label and "ip" not in out:
            out["ip"] = value
    return out


# Un comando per client: oltre questa soglia il refresh del tab durerebbe piu'
# di quanto il dato resta valido. I client in eccesso restano senza RSSI/SNR,
# il bottone Diagnostica li copre uno per uno.
_CLIENT_DETAIL_LIMIT = 40

# Stessa logica per l'auto-RF: un comando per AP.
_AP_AUTORF_LIMIT = 40
_AP_AUTORF_CMD = "show ap auto-rf 802.11a {ap}"
# Il nome AP arriva dall'output del controller e finisce dentro un comando: si
# accettano solo i caratteri di un nome AP legittimo, cosi' una riga malformata
# non puo' allungare la CLI con un secondo comando.
_AP_NAME_RE = re.compile(r"^[\w.:@-]{1,32}$")


def overview(device: dict) -> dict:
    """Fotografia del controller in una sola sessione SSH: AP, client, WLAN e
    rogue AP gia' strutturati. Ogni comando e' best-effort (un account
    read-only puo' non vedere i rogue AP: il resto del tab resta popolato)."""
    raw, version, uptime = {}, "", ""
    with _session(device) as (conn, platform, sysinfo):
        for svc in ("ap_summary", "client_summary", "wlan_summary", "rogue_aps"):
            try:
                raw[svc] = _send(conn, COMMANDS[svc][platform])
            except Exception as e:
                raw[svc] = ""
                raw[svc + "_error"] = str(e)
        # IP, RSSI e SNR non esistono in 'show client summary' su nessuna delle
        # due piattaforme: solo il dettaglio per client li espone.
        clients = _table_rows(raw["client_summary"], _CLIENT_FIELDS)
        for client in clients[:_CLIENT_DETAIL_LIMIT]:
            try:
                cmd = COMMANDS["client_detail"][platform].format(
                    mac=normalize_mac(client.get("mac", ""), platform))
                client.update(parse_client_detail(_send(conn, cmd, 60)))
            except Exception:
                continue
        aps = _table_rows(raw["ap_summary"], _AP_FIELDS)
        if platform == "aireos":
            # Canale e larghezza di canale non stanno in 'show ap summary':
            # l'auto-RF della radio 5 GHz e' l'unico posto che li stampa.
            for ap in aps[:_AP_AUTORF_LIMIT]:
                name = ap.get("name", "")
                if not _AP_NAME_RE.match(name):
                    continue
                try:
                    ap.update(parse_ap_autorf(_send(conn, _AP_AUTORF_CMD.format(ap=name))))
                except Exception:
                    continue
            info = parse_sysinfo(sysinfo)
            version = info.get("product version", "")
            uptime = info.get("system up time", "")
        else:
            try:
                ver_txt = _send(conn, "show version")
            except Exception:
                ver_txt = ""
            m = re.search(r"Version\s+([\w.:()]+)", ver_txt)
            version = m.group(1).rstrip(",") if m else ""
            m = re.search(r"uptime is (.+)", ver_txt)
            uptime = m.group(1).strip() if m else ""

    wlans = _table_rows(raw["wlan_summary"], _WLAN_FIELDS)
    rogues = _table_rows(raw["rogue_aps"], _ROGUE_FIELDS)
    # 'show client summary' da' solo il WLAN ID: il nome arriva dalla tabella
    # WLAN. Su AireOS la colonna e' 'profilo / SSID', tiene la parte dopo la
    # barra.
    ssid_by_id = {w.get("id"): w.get("ssid", "") for w in wlans}
    for client in clients:
        ssid = ssid_by_id.get(client.get("wlan"), "").split("/")[-1].strip()
        if ssid:
            client["wlan"] = f"{client['wlan']} - {ssid}"
    return {"platform": platform, "version": version, "uptime": uptime,
            "ap_count": len(aps), "client_count": len(clients),
            "aps": aps, "clients": clients, "wlans": wlans, "rogues": rogues,
            "raw": raw}


def diagnose_wifi_client(device: dict, mac: str) -> dict:
    """Diagnosi aggregata di un client wireless: dettaglio client, stato AP,
    WLAN e rogue AP vicini. Ogni sezione è best-effort (errore riportato
    nella sezione, la diagnosi non fallisce)."""
    result = {"wlc": device.get("IP"), "client_mac": mac, "sections": {}}
    # Una sola sessione per tutte le sezioni: con una query per comando erano
    # quattro login SSH di fila, ognuno con il suo rilevamento piattaforma.
    with _session(device, 60) as (conn, platform, _sysinfo):
        result["platform"] = platform
        for svc in ("client_detail", "ap_summary", "wlan_summary", "rogue_aps"):
            command = COMMANDS[svc][platform]
            try:
                if "{mac}" in command:
                    command = command.format(mac=normalize_mac(mac, platform))
                result["sections"][svc] = {
                    "platform": platform, "command": command,
                    "data": _send(conn, command, 60)}
            except Exception as e:
                result["sections"][svc] = {"error": str(e)}
    return result
