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
_S_UNAME = "UNAME"
_S_UPTIME = "UPTIME"
_S_BOOT = "BOOT TIME"
_S_ADDR = "IP ADDRESS"
_S_LINK_STATS = "LINK STATS"
_S_LINK_SPEED = "LINK SPEED"
_S_ROUTE = "IP ROUTE"
_S_SOCKETS = "LISTENING SOCKETS"
_S_SOCKETS_PID = "LISTENING SOCKETS PID"
_S_DF = "DF"
_S_DISKS = "DISKS"
_S_LSCPU = "LSCPU"
_S_DMIDECODE = "DMIDECODE"
_S_DIMMS = "MEMORY DEVICES"
_S_FAILED = "SYSTEMCTL FAILED"
_S_ENABLED = "SYSTEMCTL ENABLED"
_S_SUDOERS = "SUDOERS"
_S_FIREWALL = "FIREWALL RULES"
_S_CONTAINERS = "CONTAINERS"
_S_DOCKER = "DOCKER VERSION"
_S_KUBELET = "KUBELET VERSION"

_F_OS_RELEASE = "/etc/os-release"
_F_FSTAB = "/etc/fstab"
_F_LOGIN_DEFS = "/etc/login.defs"
_F_SSHD = "/etc/ssh/sshd_config"
_F_PASSWD = "/etc/passwd"
_F_GROUP = "/etc/group"

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

    # ``uname -srm`` -> "Linux <kernel> <arch>": kernel e architettura sono le
    # parole 2 e 3, il resto della riga non serve.
    uname = _lines(cfg, _S_UNAME)[:1]
    if uname:
        parts = uname[0].split()
        add("kernel", parts[1] if len(parts) > 1 else "")
        add("architecture", parts[2] if len(parts) > 2 else "")

    uptime = " ".join(_lines(cfg, _S_UPTIME)[:1])
    add("uptime", uptime)
    add("boot_time", " ".join(_lines(cfg, _S_BOOT)[:1]))

    dns = [l.split(None, 1)[1] for l in _lines(cfg, "/etc/resolv.conf")
           if l.lower().startswith("nameserver") and len(l.split()) > 1]
    add("dns", ", ".join(dns))

    # Runtime dei container: righe di sistema, non una tabella a se'. Se il
    # comando non esiste la sezione e' vuota e la riga non compare, che e' la
    # risposta giusta: su questo host non c'e'.
    add("docker", " ".join(_lines(cfg, _S_DOCKER)[:1]))
    # ``kubelet --version`` -> "Kubernetes v1.29.0": interessa la versione.
    kubelet = _lines(cfg, _S_KUBELET)[:1]
    if kubelet:
        add("kubernetes", kubelet[0].split()[-1])
    return rows


def _after(parts: List[str], token: str) -> str:
    """Parola che segue ``token`` in una riga gia' divisa, "" se assente."""
    return parts[parts.index(token) + 1] if token in parts \
        and parts.index(token) + 1 < len(parts) else ""


_LINK_HEAD = re.compile(r'^\d+:\s+([^:@\s]+)[@:]')


def _link_stats(cfg: LinuxConfig) -> Dict[str, Dict[str, str]]:
    """``ip -s link`` -> per interfaccia: MTU, stato e contatori RX/TX.

    I contatori stanno sulla riga SUCCESSIVA all'intestazione ``RX:``/``TX:``,
    quindi non si legge una riga per volta in isolamento: l'intestazione arma
    la lettura e la riga dopo la consuma.
    """
    out: Dict[str, Dict[str, str]] = {}
    cur: Dict[str, str] = {}
    pending = ""
    for line in _lines(cfg, _S_LINK_STATS):
        head = _LINK_HEAD.match(line)
        if head:
            parts = line.split()
            cur = {"mtu": _after(parts, "mtu"), "state": _after(parts, "state")}
            out[head.group(1)] = cur
            pending = ""
            continue
        if not cur:
            continue
        if line.startswith("RX:") or line.startswith("TX:"):
            pending = line[:2].lower()
            continue
        if pending:
            fields = line.split()
            if len(fields) >= 4:
                cur[f"{pending}_bytes"] = fields[0]
                cur[f"{pending}_packets"] = fields[1]
                cur[f"{pending}_errors"] = fields[2]
                cur[f"{pending}_dropped"] = fields[3]
            pending = ""
    return out


def _link_speed(cfg: LinuxConfig) -> Dict[str, Dict[str, str]]:
    """``/sys/class/net/*/speed`` e ``duplex``. Il kernel scrive -1 su una
    interfaccia giu': e' un "non lo so", non una velocita', e non va mostrato."""
    out = {}
    for line in _lines(cfg, _S_LINK_SPEED):
        parts = line.split()
        if not parts:
            continue
        speed = parts[1] if len(parts) > 1 else ""
        out[parts[0]] = {"speed": "" if speed in ("-1", "") else speed,
                         "duplex": parts[2] if len(parts) > 2 else ""}
    return out


def _interface_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ip -br a`` per indirizzi e stato, arricchito con MTU (``ip -s link``)
    e velocita'/duplex (sysfs)."""
    stats = _link_stats(cfg)
    speeds = _link_speed(cfg)
    rows = []
    for line in _lines(cfg, _S_ADDR):
        parts = line.split()
        if len(parts) < 2:
            continue
        st = stats.get(parts[0], {})
        sp = speeds.get(parts[0], {})
        rows.append({
            "name": parts[0],
            "state": parts[1],
            "mtu": st.get("mtu", ""),
            "speed": sp.get("speed", ""),
            "duplex": sp.get("duplex", ""),
            # Lista, non stringa: la UI espande le celle multi-valore.
            "addresses": parts[2:] or [],
        })
    return rows


def _counter_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """Contatori per interfaccia. Tabella separata dalle interfacce: unirle
    darebbe una riga da tredici colonne dove le due meta' si leggono per
    motivi diversi (com'e' configurata / come sta andando)."""
    rows = []
    for name, st in _link_stats(cfg).items():
        rows.append({
            "name": name,
            "rx_bytes": st.get("rx_bytes", ""),
            "rx_packets": st.get("rx_packets", ""),
            "rx_errors": st.get("rx_errors", ""),
            "rx_dropped": st.get("rx_dropped", ""),
            "tx_bytes": st.get("tx_bytes", ""),
            "tx_packets": st.get("tx_packets", ""),
            "tx_errors": st.get("tx_errors", ""),
            "tx_dropped": st.get("tx_dropped", ""),
        })
    return rows


def _route_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``ip route``: destinazione, gateway, interfaccia, metrica."""
    rows = []
    for line in _lines(cfg, _S_ROUTE):
        parts = line.split()
        if not parts:
            continue
        rows.append({
            "destination": parts[0],
            "via": _after(parts, "via"),
            "dev": _after(parts, "dev"),
            "proto": _after(parts, "proto"),
            "metric": _after(parts, "metric"),
            "src": _after(parts, "src"),
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


# Tipi di unita' che rappresentano qualcosa che qualcuno ha deciso di far
# partire. Le .mount le genera automaticamente ogni snap installato: sono
# decine, sono tutte "enabled" per costruzione, e sommergono le poche righe che
# dicono davvero cosa gira su questa macchina.
_ENABLED_UNIT_TYPES = (".service", ".socket", ".timer", ".path")


def _enabled_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``systemctl list-unit-files --state=enabled``: cosa parte da solo al boot.

    Lo stato non si mostra: la query filtra gia' su ``--state=enabled``, quindi
    la colonna direbbe "enabled" su ogni riga. Si mostra il PRESET, cioe' cosa
    prevedeva la distribuzione: ``preset=disabled`` su una unita' abilitata
    significa che qualcuno l'ha accesa a mano, ed e' l'unica informazione della
    tabella che distingua una riga dall'altra.
    """
    rows = []
    for line in _lines(cfg, _S_ENABLED):
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(_ENABLED_UNIT_TYPES):
            rows.append({"unit": parts[0],
                         "preset": parts[2] if len(parts) > 2 else ""})
    return rows


# Shell che NON danno accesso interattivo: un account di servizio con una di
# queste non e' una via d'ingresso, uno con /bin/bash si'. E' la sola colonna
# della tabella utenti che richieda un giudizio, e vale la pena calcolarla qui
# invece di lasciare l'operatore a riconoscere i percorsi a occhio.
_NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                   "/usr/bin/false", "/bin/sync", "")


def _user_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/passwd``: utenti locali, con l'indicazione di chi puo' loggarsi."""
    rows = []
    for line in _lines(cfg, _F_PASSWD):
        f = line.split(":")
        if len(f) < 7:
            continue
        shell = f[6].strip()
        rows.append({"user": f[0], "uid": f[2], "gid": f[3], "home": f[5],
                     "shell": shell,
                     "login": "no" if shell in _NOLOGIN_SHELLS else "yes"})
    return rows


def _group_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/group``: gruppi locali e membri secondari."""
    rows = []
    for line in _lines(cfg, _F_GROUP):
        f = line.split(":")
        if len(f) < 4:
            continue
        members = [m for m in f[3].split(",") if m]
        rows.append({"group": f[0], "gid": f[2], "members": members})
    return rows


def _sudoers_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``/etc/sudoers`` e ``/etc/sudoers.d/*``: chi puo' diventare root.

    Niente interpretazione della grammatica sudoers: la riga si mostra intera,
    con davanti il soggetto (utente, ``%gruppo`` o ``Defaults``), perche' e' su
    quello che si cerca.
    """
    rows = []
    for line in _lines(cfg, _S_SUDOERS):
        parts = line.split(None, 1)
        if not parts:
            continue
        rows.append({"principal": parts[0],
                     "rule": parts[1] if len(parts) > 1 else ""})
    return rows


def _container_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``docker ps``, campi separati da TAB.

    Il separatore non e' lo spazio perche' STATUS lo contiene ("Up 3 hours") e
    PORTS pure: dividere sugli spazi spezzerebbe due colonne su quattro.
    """
    rows = []
    for line in _lines(cfg, _S_CONTAINERS):
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        rows.append({"name": fields[0].strip(), "image": fields[1].strip(),
                     "status": fields[2].strip() if len(fields) > 2 else "",
                     "ports": fields[3].strip() if len(fields) > 3 else ""})
    return rows


def _firewall_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``nft list ruleset`` o ``iptables -S``: firewall dell'host.

    Le due sintassi non si normalizzano in una terza: ogni riga si mostra com'e',
    ed e' anche cosi' che si incolla in una shell per verificarla.
    """
    return [{"rule": line} for line in _lines(cfg, _S_FIREWALL)]


def _colon_keyed(lines: List[str], keys: tuple) -> Dict[str, str]:
    """Righe ``Chiave: valore`` (lscpu, dmidecode -s) ridotte alle chiavi note."""
    found = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() in keys:
            found[key.strip().lower()] = value.strip()
    return found


_LSCPU_KEYS = ("model name", "architecture", "cpu(s)", "socket(s)",
               "core(s) per socket", "thread(s) per core", "vendor id",
               "hypervisor vendor", "virtualization type")
_DMI_KEYS = ("system-manufacturer", "system-product-name",
             "system-serial-number", "bios-version", "bios-release-date")


def _hardware_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """CPU (``lscpu``) e identita' della macchina (``dmidecode -s``, tier sudo)."""
    rows = []
    for key, value in _colon_keyed(_lines(cfg, _S_LSCPU), _LSCPU_KEYS).items():
        rows.append({"property": key, "value": value})
    for key in _DMI_KEYS:
        value = _colon_keyed(_lines(cfg, _S_DMIDECODE), _DMI_KEYS).get(key)
        if value:
            rows.append({"property": key, "value": value})
    return rows


def _disk_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``lsblk -dno NAME,MODEL,SERIAL,SIZE``: dischi fisici, non le partizioni.

    Il modello puo' contenere spazi, quindi si tiene la dimensione dal fondo e
    il seriale dalla penultima posizione: dividere da sinistra spezzerebbe il
    nome del modello su ogni disco che ne ha uno lungo.
    """
    rows = []
    for line in _lines(cfg, _S_DISKS):
        parts = line.split()
        if len(parts) < 2:
            continue
        rows.append({
            "name": parts[0],
            "size": parts[-1],
            "serial": parts[-2] if len(parts) >= 4 else "",
            "model": " ".join(parts[1:-2]) if len(parts) >= 4 else "",
        })
    return rows


_DIMM_KEYS = {"size": "size", "locator": "locator", "type": "type",
              "speed": "speed", "manufacturer": "manufacturer",
              "part number": "part_number"}


def _dimm_rows(cfg: LinuxConfig) -> List[Dict[str, Any]]:
    """``dmidecode -t 17``: banchi di memoria.

    I record sono separati da righe vuote, che il parser ha gia' scartato:
    l'inizio di un banco si riconosce dall'intestazione ``Memory Device``.
    Gli slot vuoti ("No Module Installed") si omettono.
    """
    rows: List[Dict[str, Any]] = []
    cur: Dict[str, Any] = {}
    for line in _lines(cfg, _S_DIMMS):
        if line == "Memory Device":
            cur = {}
            rows.append(cur)
            continue
        if not rows:
            continue
        key, sep, value = line.partition(":")
        field = _DIMM_KEYS.get(key.strip().lower())
        if sep and field:
            cur[field] = value.strip()
    return [r for r in rows
            if r.get("size") and "no module" not in r["size"].lower()]


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
        _section("hardware", ["property", "value"], _hardware_rows(cfg)),
        _section("interfaces", ["name", "state", "mtu", "speed", "duplex",
                                "addresses"], _interface_rows(cfg)),
        _section("counters", ["name", "rx_bytes", "rx_packets", "rx_errors",
                              "rx_dropped", "tx_bytes", "tx_packets",
                              "tx_errors", "tx_dropped"], _counter_rows(cfg)),
        _section("routes", ["destination", "via", "dev", "proto", "metric", "src"],
                 _route_rows(cfg)),
        _section("sockets", ["protocol", "address", "port", "scope", "process"],
                 _socket_rows(cfg)),
        _section("firewall", ["rule"], _firewall_rows(cfg)),
        _section("storage", ["device", "mount", "fstype", "options", "size",
                             "used_pct"], _fstab_rows(cfg)),
        _section("disks", ["name", "model", "serial", "size"], _disk_rows(cfg)),
        _section("dimms", ["locator", "size", "type", "speed", "manufacturer",
                           "part_number"], _dimm_rows(cfg)),
        _section("containers", ["name", "image", "status", "ports"],
                 _container_rows(cfg)),
        _section("services", ["unit", "load", "active", "sub", "description"],
                 _service_rows(cfg)),
        _section("enabled_units", ["unit", "preset"], _enabled_rows(cfg)),
        _section("ssh", ["setting", "value"], _sshd_rows(cfg)),
        _section("accounts", ["setting", "value"],
                 _keyed_rows(_lines(cfg, _F_LOGIN_DEFS), _LOGIN_DEFS_KEYS)),
        _section("users", ["user", "uid", "gid", "home", "shell", "login"],
                 _user_rows(cfg)),
        _section("groups", ["group", "gid", "members"], _group_rows(cfg)),
        _section("sudoers", ["principal", "rule"], _sudoers_rows(cfg)),
    ]
    return {"vendor": "linux", "sections": sections}
