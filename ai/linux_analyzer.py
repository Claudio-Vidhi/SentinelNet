# -*- coding: utf-8 -*-
"""Artefatto di backup Linux -> envelope a sezioni per il Config Analyzer.

Stessa forma dell'envelope dei firewall (``fw_analyzers``): ``sections`` con
``columns``/``rows``, cosi' la UI ricava i sotto-pill dai dati e non deve
conoscere niente di Linux.

PERCHE' NON RIUSA IL PARSER IOS — ``detect_config_type`` ripiega su ``'ios'``
per ogni vendor che non riconosce. Su un host Linux quel ripiego non e' una
approssimazione, e' un risultato inventato: il parser cerca VLAN, ACL e
interfacce dentro ``/etc/fstab`` e la scheda esce come uno switch senza VLAN.
Meglio una piattaforma in piu' che un apparato descritto male.

COSA LEGGE — l'artefatto che scrive ``drivers/linux.py`` piu' le sezioni che il
triage appende (``ip -br a``, ``ip route``, ``ss -tuln``, ``df -hT``,
``systemctl --failed``). La divisione in sezioni la fa gia'
``netsec_audit.linux_parser``: qui si interpreta soltanto il contenuto.

Tollerante come gli altri analizzatori: nessuna riga malformata solleva, una
sezione assente produce una tabella vuota e non un errore.
"""

import re
from typing import Any, Dict, List

from services.netsec_audit.linux_parser import (
    SSHD_EFFECTIVE, LinuxConfig, parse_linux)

# Sezioni dell'artefatto prodotte dai comandi extra del triage.
_S_HOSTNAME = "HOSTNAME"
_S_UPTIME = "UPTIME"
_S_ADDR = "IP ADDRESS"
_S_ROUTE = "IP ROUTE"
_S_SOCKETS = "LISTENING SOCKETS"
_S_SOCKETS_PID = "LISTENING SOCKETS PID"
_S_DF = "DF"
_S_FAILED = "SYSTEMCTL FAILED"

_F_OS_RELEASE = "/etc/os-release"
_F_FSTAB = "/etc/fstab"
_F_LOGIN_DEFS = "/etc/login.defs"
_F_SSHD = "/etc/ssh/sshd_config"

# Impostazioni sshd mostrate nella scheda. Non e' l'audit (quello vive in
# netsec_audit e da' verdetti): qui si mostra COM'E' configurato, senza giudizio.
_SSHD_KEYS = ("port", "permitrootlogin", "passwordauthentication",
              "pubkeyauthentication", "permitemptypasswords",
              "hostbasedauthentication", "ignorerhosts", "maxauthtries",
              "logingracetime", "clientaliveinterval", "clientalivecountmax",
              "disableforwarding", "x11forwarding", "loglevel", "banner",
              "usepam", "allowusers", "allowgroups")

_LOGIN_DEFS_KEYS = ("pass_max_days", "pass_min_days", "pass_warn_age",
                    "pass_min_len", "encrypt_method", "umask",
                    "uid_min", "gid_min", "login_retries", "login_timeout")


def _col(key: str) -> Dict[str, str]:
    return {"key": key, "label_key": f"srv.col.{key}"}


def _section(sid: str, columns: List[str], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "id": sid,
        "label_key": f"srv.sec.{sid}",
        "columns": [_col(k) for k in columns],
        "rows": rows,
    }


def _lines(cfg: LinuxConfig, name: str) -> List[str]:
    return [l.text for l in cfg.files.get(name, [])]


def _system_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Identita' dell'host: distribuzione, kernel, hostname, uptime."""
    rows = []

    def add(prop, value):
        if value:
            rows.append({"property": prop, "value": value})

    pretty = ""
    for line in _lines(cfg, _F_OS_RELEASE):
        m = re.match(r'PRETTY_NAME="?([^"]+)"?', line)
        if m:
            pretty = m.group(1).strip()
            break
    add("os", pretty)

    hostname = ""
    for line in _lines(cfg, _S_HOSTNAME):
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == "hostname":
            hostname = parts[1]
            break
    add("hostname", hostname)

    uptime = " ".join(_lines(cfg, _S_UPTIME)[:1])
    add("uptime", uptime)

    # Il kernel arriva dalla configurazione effettiva di sshd solo per caso:
    # la fonte affidabile e' la versione in inventario, non l'artefatto.
    dns = [l.split(None, 1)[1] for l in _lines(cfg, "/etc/resolv.conf")
           if l.lower().startswith("nameserver") and len(l.split()) > 1]
    add("dns", ", ".join(dns))
    return rows


def _interface_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ip -br a``: nome, stato operativo, indirizzi."""
    rows = []
    for line in _lines(cfg, _S_ADDR):
        parts = line.split()
        if len(parts) < 2:
            continue
        rows.append({
            "name": parts[0],
            "state": parts[1],
            # Lista, non stringa: la UI espande le celle multi-valore.
            "addresses": parts[2:] or [],
        })
    return rows


def _route_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ip route``: destinazione, gateway, interfaccia, metrica."""
    rows = []
    for line in _lines(cfg, _S_ROUTE):
        parts = line.split()
        if not parts:
            continue
        def after(token):
            return parts[parts.index(token) + 1] if token in parts \
                and parts.index(token) + 1 < len(parts) else ""
        rows.append({
            "destination": parts[0],
            "via": after("via"),
            "dev": after("dev"),
            "proto": after("proto"),
            "metric": after("metric"),
            "src": after("src"),
        })
    return rows


_PROCESS = re.compile(r'\("([^"]+)",pid=(\d+)')


def _socket_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ss -tuln`` (o ``-tulpn`` sul tier privilegiato): porte in ascolto.

    E' la sezione che dice davvero cosa l'host espone: un servizio su
    ``0.0.0.0`` e' raggiungibile da tutta la rete, uno su ``127.0.0.1`` no, e
    la differenza non si vede da nessun'altra parte dell'applicazione.
    """
    rows = []
    # La sezione privilegiata ha in piu' il processo: quando c'e', vince.
    lines = _lines(cfg, _S_SOCKETS_PID) or _lines(cfg, _S_SOCKETS)
    for line in lines:
        parts = line.split()
        if len(parts) < 5 or parts[0].lower() in ("netid", "state"):
            continue
        local = parts[4]
        address, _, port = local.rpartition(":")
        process = ""
        m = _PROCESS.search(line)
        if m:
            process = f"{m.group(1)} ({m.group(2)})"
        rows.append({
            "protocol": parts[0],
            "address": address or local,
            "port": port,
            # 0.0.0.0 e :: sono "tutte le interfacce": vale la pena dirlo qui
            # invece di lasciarlo dedurre.
            "scope": "any" if address in ("0.0.0.0", "[::]", "*") else "local"
            if address in ("127.0.0.1", "[::1]") else "bound",
            "process": process,
        })
    return rows


def _fstab_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/fstab`` arricchito con l'occupazione da ``df -hT``.

    Due tabelle separate direbbero le stesse cose a meta': le opzioni di mount
    contano proprio sui filesystem che si stanno riempiendo.
    """
    used = {}
    for line in _lines(cfg, _S_DF):
        parts = line.split()
        if len(parts) >= 7 and parts[5].endswith("%"):
            used[parts[6]] = {"size": parts[2], "used_pct": parts[5]}

    rows = []
    for line in _lines(cfg, _F_FSTAB):
        parts = line.split()
        if len(parts) < 4:
            continue
        extra = used.get(parts[1], {})
        rows.append({
            "device": parts[0],
            "mount": parts[1],
            "fstype": parts[2],
            "options": parts[3].split(","),
            "size": extra.get("size", ""),
            "used_pct": extra.get("used_pct", ""),
        })
    # Filesystem montati ma non dichiarati in fstab (tmpfs, overlay): esistono
    # e occupano spazio, ometterli renderebbe la tabella una mezza verita'.
    declared = {r["mount"] for r in rows}
    for line in _lines(cfg, _S_DF):
        parts = line.split()
        if len(parts) >= 7 and parts[5].endswith("%") and parts[6] not in declared:
            rows.append({"device": parts[0], "mount": parts[6],
                         "fstype": parts[1], "options": [],
                         "size": parts[2], "used_pct": parts[5]})
    return rows


def _service_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``systemctl --failed``: unita' che il sistema non e' riuscito ad avviare."""
    rows = []
    for line in _lines(cfg, _S_FAILED):
        parts = line.split(None, 4)
        if len(parts) < 4 or not parts[0].endswith(
                (".service", ".timer", ".mount", ".socket", ".target")):
            continue
        rows.append({"unit": parts[0], "load": parts[1], "active": parts[2],
                     "sub": parts[3],
                     "description": parts[4] if len(parts) > 4 else ""})
    return rows


def _keyed_rows(lines: List[str], keys: tuple, separator: bool = False
                ) -> List[Dict[str, Any]]:
    """Righe ``chiave valore`` filtrate sulle chiavi note, ultima occorrenza."""
    found: Dict[str, str] = {}
    for line in lines:
        text = line.replace("=", " ", 1) if separator else line
        parts = text.split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        if key in keys:
            found[key] = parts[1].strip()
    return [{"setting": k, "value": found[k]} for k in keys if k in found]


def _sshd_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    # sshd -T e' la configurazione EFFETTIVA (tiene conto degli Include):
    # quando il triage privilegiato l'ha raccolta, vince sul file.
    lines = _lines(cfg, SSHD_EFFECTIVE) or _lines(cfg, _F_SSHD)
    return _keyed_rows(lines, _SSHD_KEYS)


def analyze(text) -> Dict[str, Any]:
    """Artefatto Linux -> envelope a sezioni. Puro e tollerante."""
    try:
        return _analyze(text)
    except Exception:
        return {"vendor": "linux", "sections": []}


def _analyze(text) -> Dict[str, Any]:
    cfg = parse_linux(text)
    sections = [
        _section("system", ["property", "value"], _system_rows(cfg)),
        _section("interfaces", ["name", "state", "addresses"],
                 _interface_rows(cfg)),
        _section("routes", ["destination", "via", "dev", "proto", "metric", "src"],
                 _route_rows(cfg)),
        _section("sockets", ["protocol", "address", "port", "scope", "process"],
                 _socket_rows(cfg)),
        _section("storage", ["device", "mount", "fstype", "options", "size",
                             "used_pct"], _fstab_rows(cfg)),
        _section("services", ["unit", "load", "active", "sub", "description"],
                 _service_rows(cfg)),
        _section("ssh", ["setting", "value"], _sshd_rows(cfg)),
        _section("accounts", ["setting", "value"],
                 _keyed_rows(_lines(cfg, _F_LOGIN_DEFS), _LOGIN_DEFS_KEYS)),
    ]
    return {"vendor": "linux", "sections": sections}
