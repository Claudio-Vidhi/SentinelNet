"""Storicizzazione e ricerca degli avvistamenti MAC address (SQLite, WAL).

Modello dati: per ogni (mac, switch, interfaccia, vlan) si tiene UNA riga con
first_seen/last_seen/seen_count. Quando un MAC compare in una posizione diversa
(altra porta/switch/vlan) si crea una nuova riga: la sequenza di righe di uno
stesso MAC ne racconta lo storico degli spostamenti nell'infrastruttura.

Smart retention: le righe non più aggiornate da 'retention_days' (default 30)
vengono eliminate al termine di ogni scan, così il DB non cresce all'infinito.
Il layer storage è indipendente dal trasporto usato per raccogliere i dati
(NETCONF/RESTCONF/CLI): riceve semplicemente una lista di avvistamenti.
"""
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional, Any, List

from core import data_config
from collectors.mac_collector import expand_iface

DB_PATH = data_config.get_path("mac_history.db")
RETENTION_DAYS_DEFAULT = 30

_lock = threading.Lock()
_init_done = False

_HEXONLY = re.compile(r'[^0-9a-fA-F]')


def normalize_mac(raw: str):
    """Canonicalizza un MAC nel formato 'aa:bb:cc:dd:ee:ff'.

    Accetta i formati vendor più comuni ('aabb.ccdd.eeff', 'AA-BB-CC-DD-EE-FF',
    'aabbccddeeff', ...). Ritorna None se non sono 12 cifre esadecimali.
    """
    if not raw:
        return None
    raw_str = str(raw) if not isinstance(raw, str) else raw
    hexs = _HEXONLY.sub('', raw_str).lower()
    if len(hexs) != 12:
        return None
    return ':'.join(hexs[i:i + 2] for i in range(0, 12, 2))


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    global _init_done
    with _lock:
        if _init_done:
            return
        with _connect() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS mac_sightings (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac          TEXT    NOT NULL,
                    oui_vendor   TEXT    DEFAULT '',
                    vlan         TEXT    DEFAULT '',
                    switch_ip    TEXT    NOT NULL,
                    switch_name  TEXT    DEFAULT '',
                    interface    TEXT    DEFAULT '',
                    port_channel TEXT    DEFAULT '',
                    is_uplink    INTEGER DEFAULT 0,
                    uplink_to    TEXT    DEFAULT '',
                    tenant       TEXT    DEFAULT '',
                    first_seen   TEXT    NOT NULL,
                    last_seen    TEXT    NOT NULL,
                    seen_count   INTEGER DEFAULT 1
                )
            """)
            try:
                c.execute("ALTER TABLE mac_sightings ADD COLUMN uplink_to TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            # 'site': sede multi-sede di provenienza (default 'central'). Attribuzione
            # indipendente dal 'tenant' (gruppo) usato per lo scoping utente.
            try:
                c.execute("ALTER TABLE mac_sightings ADD COLUMN site TEXT DEFAULT 'central'")
            except sqlite3.OperationalError:
                pass
            # Una posizione = (mac, switch, interfaccia, vlan): chiave di upsert.
            c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_mac_pos
                         ON mac_sightings(mac, switch_ip, interface, vlan)""")
            c.execute("CREATE INDEX IF NOT EXISTS ix_mac       ON mac_sightings(mac)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_switch    ON mac_sightings(switch_ip)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_last_seen ON mac_sightings(last_seen)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_tenant    ON mac_sightings(tenant)")
            c.execute("CREATE TABLE IF NOT EXISTS mac_settings (key TEXT PRIMARY KEY, value TEXT)")
            # Override comando ad-hoc per apparati non ordinari (es. C8000V con
            # bridge-domain, dove la FDB sta in 'show bridge-domain' e non in
            # 'show mac address-table').
            c.execute("""CREATE TABLE IF NOT EXISTS mac_cmd_overrides (
                switch_ip TEXT PRIMARY KEY,
                command   TEXT NOT NULL,
                fmt       TEXT DEFAULT 'generic'
            )""")
            # MAC delle interfacce PROPRIE degli switch (infrastruttura): servono a
            # classificare quei MAC come "switch-interface" invece che endpoint.
            c.execute("""
                CREATE TABLE IF NOT EXISTS switch_if_macs (
                  mac TEXT NOT NULL, switch_ip TEXT NOT NULL, switch_name TEXT DEFAULT '',
                  interface TEXT NOT NULL, last_seen TEXT NOT NULL,
                  PRIMARY KEY (mac, switch_ip, interface))
            """)
            # Corrispondenze MAC <-> IP raccolte dalle tabelle ARP dei gateway
            # L3 (switch con SVI o firewall, a seconda di chi ruota la VLAN).
            # Una riga per (mac, ip, source_ip): lo stesso MAC può avere più IP
            # (multi-VLAN) e lo stesso binding può essere visto da più gateway.
            c.execute("""
                CREATE TABLE IF NOT EXISTS arp_entries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac         TEXT NOT NULL,
                    ip          TEXT NOT NULL,
                    vlan        TEXT DEFAULT '',
                    interface   TEXT DEFAULT '',
                    source_ip   TEXT NOT NULL,
                    source_name TEXT DEFAULT '',
                    source_type TEXT DEFAULT '',
                    tenant      TEXT DEFAULT '',
                    site        TEXT DEFAULT 'central',
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL,
                    seen_count  INTEGER DEFAULT 1
                )
            """)
            c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_arp
                         ON arp_entries(mac, ip, source_ip)""")
            c.execute("CREATE INDEX IF NOT EXISTS ix_arp_mac ON arp_entries(mac)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_arp_ip  ON arp_entries(ip)")
            _migrate_unexpanded_interfaces(c)
        _init_done = True


def _migrate_unexpanded_interfaces(c):
    rows = c.execute("SELECT id, mac, vlan, switch_ip, interface, port_channel, seen_count, last_seen FROM mac_sightings").fetchall()
    for r in rows:
        exp_if = expand_iface(r["interface"])
        exp_pc = expand_iface(r["port_channel"])
        if exp_if != r["interface"] or exp_pc != r["port_channel"]:
            dup = c.execute(
                "SELECT id, seen_count, last_seen FROM mac_sightings WHERE mac=? AND switch_ip=? AND interface=? AND vlan=? AND id!=?",
                (r["mac"], r["switch_ip"], exp_if, r["vlan"], r["id"])).fetchone()
            if dup:
                max_last = max(r["last_seen"], dup["last_seen"])
                tot_count = r["seen_count"] + dup["seen_count"]
                c.execute("UPDATE mac_sightings SET seen_count=?, last_seen=?, interface=?, port_channel=? WHERE id=?",
                          (tot_count, max_last, exp_if, exp_pc, dup["id"]))
                c.execute("DELETE FROM mac_sightings WHERE id=?", (r["id"],))
            else:
                c.execute("UPDATE mac_sightings SET interface=?, port_channel=? WHERE id=?",
                          (exp_if, exp_pc, r["id"]))


# --- Retention (smart, configurabile) ---

def get_retention_days() -> int:
    init_db()
    with _lock, _connect() as c:
        row = c.execute("SELECT value FROM mac_settings WHERE key='retention_days'").fetchone()
    try:
        return int(row["value"]) if row else RETENTION_DAYS_DEFAULT
    except (TypeError, ValueError):
        return RETENTION_DAYS_DEFAULT


def set_retention_days(days: int) -> int:
    init_db()
    days = max(1, min(3650, days))
    with _lock, _connect() as c:
        c.execute("""INSERT INTO mac_settings(key, value) VALUES('retention_days', ?)
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value""", (str(days),))
    return days


# --- Override comando ad-hoc per apparato ---

def get_override(switch_ip: str):
    """Ritorna {command, fmt} per l'apparato, o None se non configurato."""
    init_db()
    with _lock, _connect() as c:
        row = c.execute("SELECT command, fmt FROM mac_cmd_overrides WHERE switch_ip=?",
                        (switch_ip,)).fetchone()
    return {"command": row["command"], "fmt": row["fmt"]} if row else None


def set_override(switch_ip: str, command: str, fmt: str = "generic") -> bool:
    init_db()
    if not switch_ip or not (command or "").strip():
        return False
    with _lock, _connect() as c:
        c.execute("""INSERT INTO mac_cmd_overrides(switch_ip, command, fmt) VALUES(?,?,?)
                     ON CONFLICT(switch_ip) DO UPDATE
                     SET command=excluded.command, fmt=excluded.fmt""",
                  (switch_ip, command.strip(), (fmt or "generic")))
    return True


def delete_override(switch_ip: str) -> bool:
    init_db()
    with _lock, _connect() as c:
        return c.execute("DELETE FROM mac_cmd_overrides WHERE switch_ip=?",
                         (switch_ip,)).rowcount > 0


def list_overrides() -> list:
    init_db()
    with _lock, _connect() as c:
        rows = c.execute("SELECT switch_ip, command, fmt FROM mac_cmd_overrides "
                         "ORDER BY switch_ip").fetchall()
    return [dict(r) for r in rows]


def prune(retention_days: Optional[int] = None) -> int:
    """Elimina gli avvistamenti non aggiornati da più di 'retention_days'.
    Ritorna il numero di righe rimosse."""
    init_db()
    days = retention_days if retention_days is not None else get_retention_days()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds')
    with _lock, _connect() as c:
        cur = c.execute("DELETE FROM mac_sightings WHERE last_seen < ?", (cutoff,))
        removed = cur.rowcount
        c.execute("DELETE FROM arp_entries WHERE last_seen < ?", (cutoff,))
        return removed


# --- Scrittura avvistamenti (upsert) ---

def record_sightings(rows, switch_ip: str, switch_name: str = "", tenant: str = "",
                     site: str = "central") -> dict:
    """Registra una lista di avvistamenti di UNO switch.

    rows: iterabile di dict con chiavi: mac (obbligatoria), vlan, interface,
    port_channel, is_uplink (bool), oui_vendor.
    Upsert sulla posizione (mac, switch, interfaccia, vlan): se esiste aggiorna
    last_seen e seen_count, altrimenti crea la riga (nuova posizione = spostamento).
    """
    init_db()
    now = _now_iso()
    n_new = n_upd = n_skip = 0
    with _lock, _connect() as c:
        for r in rows:
            mac = normalize_mac(r.get("mac"))
            if not mac:
                n_skip += 1
                continue
            vlan = str(r.get("vlan") or "")
            iface = expand_iface((r.get("interface") or "").strip())
            pc = expand_iface((r.get("port_channel") or "").strip())
            up = 1 if r.get("is_uplink") else 0
            uplink_to = (r.get("uplink_to") or "").strip()
            oui = (r.get("oui_vendor") or "").strip()
            existing = c.execute(
                "SELECT id FROM mac_sightings WHERE mac=? AND switch_ip=? AND interface=? AND vlan=?",
                (mac, switch_ip, iface, vlan)).fetchone()
            if existing:
                c.execute("""UPDATE mac_sightings
                             SET last_seen=?, seen_count=seen_count+1, is_uplink=?,
                                 port_channel=?, oui_vendor=?, switch_name=?, tenant=?, uplink_to=?, site=?
                             WHERE id=?""",
                          (now, up, pc, oui, switch_name, tenant, uplink_to, site, existing["id"]))
                n_upd += 1
            else:
                c.execute("""INSERT INTO mac_sightings
                             (mac, oui_vendor, vlan, switch_ip, switch_name, interface,
                              port_channel, is_uplink, uplink_to, tenant, site, first_seen, last_seen, seen_count)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                          (mac, oui, vlan, switch_ip, switch_name, iface, pc, up, uplink_to, tenant, site, now, now))
                n_new += 1
    return {"new": n_new, "updated": n_upd, "skipped": n_skip}


# --- MAC delle interfacce proprie degli switch (infrastruttura) ---

def record_switch_if_macs(rows, switch_ip: str, switch_name: str = "") -> dict:
    """Registra (upsert) i MAC delle interfacce proprie di UNO switch.

    rows: iterabile di dict con chiavi 'interface' e 'mac' (grezzo). Chiave di
    upsert: (mac, switch_ip, interface); aggiorna last_seen/switch_name.
    """
    init_db()
    now = _now_iso()
    n_new = n_upd = n_skip = 0
    with _lock, _connect() as c:
        for r in rows:
            mac = normalize_mac(r.get("mac"))
            iface = expand_iface((r.get("interface") or "").strip())
            if not mac or not iface:
                n_skip += 1
                continue
            existing = c.execute(
                "SELECT 1 FROM switch_if_macs WHERE mac=? AND switch_ip=? AND interface=?",
                (mac, switch_ip, iface)).fetchone()
            if existing:
                c.execute("""UPDATE switch_if_macs SET last_seen=?, switch_name=?
                             WHERE mac=? AND switch_ip=? AND interface=?""",
                          (now, switch_name, mac, switch_ip, iface))
                n_upd += 1
            else:
                c.execute("""INSERT INTO switch_if_macs
                             (mac, switch_ip, switch_name, interface, last_seen)
                             VALUES (?,?,?,?,?)""",
                          (mac, switch_ip, switch_name, iface, now))
                n_new += 1
    return {"new": n_new, "updated": n_upd, "skipped": n_skip}


def get_switch_if_macs() -> dict:
    """Ritorna { mac_normalizzato: {switch_ip, switch_name, interface} } per la
    classificazione read-time degli avvistamenti come infrastruttura."""
    init_db()
    with _lock, _connect() as c:
        rows = c.execute("SELECT mac, switch_ip, switch_name, interface "
                         "FROM switch_if_macs").fetchall()
    return {r["mac"]: {"switch_ip": r["switch_ip"], "switch_name": r["switch_name"],
                       "interface": r["interface"]} for r in rows}


# --- MAC <-> IP (tabelle ARP dei gateway L3) ---

def record_arp_entries(rows, source_ip: str, source_name: str = "",
                       source_type: str = "", tenant: str = "",
                       site: str = "central") -> dict:
    """Registra (upsert) i binding MAC<->IP letti dalla tabella ARP di UN
    gateway L3 (switch SVI o firewall).

    rows: iterabile di dict con chiavi: mac e ip (obbligatorie), vlan,
    interface. Chiave di upsert: (mac, ip, source_ip).
    """
    init_db()
    now = _now_iso()
    n_new = n_upd = n_skip = 0
    with _lock, _connect() as c:
        for r in rows:
            mac = normalize_mac(r.get("mac"))
            ip = (r.get("ip") or "").strip()
            if not mac or not ip:
                n_skip += 1
                continue
            vlan = str(r.get("vlan") or "")
            iface = expand_iface((r.get("interface") or "").strip())
            existing = c.execute(
                "SELECT id FROM arp_entries WHERE mac=? AND ip=? AND source_ip=?",
                (mac, ip, source_ip)).fetchone()
            if existing:
                c.execute("""UPDATE arp_entries
                             SET last_seen=?, seen_count=seen_count+1, vlan=?,
                                 interface=?, source_name=?, source_type=?, tenant=?, site=?
                             WHERE id=?""",
                          (now, vlan, iface, source_name, source_type, tenant,
                           site, existing["id"]))
                n_upd += 1
            else:
                c.execute("""INSERT INTO arp_entries
                             (mac, ip, vlan, interface, source_ip, source_name,
                              source_type, tenant, site, first_seen, last_seen, seen_count)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,1)""",
                          (mac, ip, vlan, iface, source_ip, source_name,
                           source_type, tenant, site, now, now))
                n_new += 1
    return {"new": n_new, "updated": n_upd, "skipped": n_skip}


def search_arp(mac: Optional[str] = None, ip: Optional[str] = None, source_ip: Optional[str] = None,
               tenants=None, limit: int = 500) -> list:
    """Ricerca i binding MAC<->IP. mac accetta anche frammenti (come search)."""
    init_db()
    q = ["SELECT * FROM arp_entries WHERE 1=1"]
    args: List[Any] = []
    if mac:
        norm = normalize_mac(mac)
        if norm:
            q.append("AND mac = ?")
            args.append(norm)
        else:
            frag = _HEXONLY.sub('', mac).lower()
            if frag:
                q.append("AND REPLACE(mac, ':', '') LIKE ?")
                args.append('%' + frag + '%')
    if ip:
        q.append("AND ip LIKE ?")
        args.append(ip + '%')
    if source_ip:
        q.append("AND source_ip = ?")
        args.append(source_ip)
    if tenants is not None:
        if not tenants:
            return []
        q.append("AND tenant IN (%s)" % ",".join("?" * len(tenants)))
        args.extend(list(tenants))
    q.append("ORDER BY last_seen DESC LIMIT ?")
    args.append(max(1, min(5000, limit)))
    with _lock, _connect() as c:
        rows = c.execute(" ".join(q), args).fetchall()
    return [dict(r) for r in rows]


def vlans_for_ips(ip_tenant_map: dict) -> dict:
    """Ritorna { ip: vlan } per gli IP richiesti, dal binding ARP più recente
    con VLAN non vuota (match esatto, niente prefix-LIKE), **vincolato al
    tenant** di ciascun IP (``ip_tenant_map``: { ip: tenant }).

    IMPORTANTE (scoping multi-tenant): IP privati possono ripetersi su sedi
    diverse (RFC1918 dietro NAT indipendenti). Senza il filtro tenant, un
    binding ARP della sede B potrebbe "trapelare" nel grafo flussi della
    sede A solo perché condividono lo stesso IP. Ogni lookup è quindi
    ``ip = ? AND tenant = ?`` — mai un IN(...) globale sugli ip.

    Usato dal grafo dei flussi (Task 3, osservabilità) per mostrare la VLAN
    reale quando nota, invece di un valore sintetico. IP senza binding ARP
    noto (per quel tenant) sono assenti dal dict ritornato (fallback
    lasciato al chiamante)."""
    pairs = [(ip, tenant) for ip, tenant in ip_tenant_map.items() if ip]
    if not pairs:
        return {}
    init_db()
    out = {}
    with _lock, _connect() as c:
        for ip, tenant in pairs:
            row = c.execute(
                """SELECT vlan FROM arp_entries
                   WHERE ip = ? AND tenant = ? AND vlan != ''
                   ORDER BY last_seen DESC LIMIT 1""",
                (ip, tenant or "")).fetchone()
            if row:
                out[ip] = row["vlan"]
    return out


def client_history(mac: str, tenants=None, limit: int = 50) -> dict:
    """Dove è stato questo MAC e che IP ha avuto, dal dato già raccolto.

    Le due tabelle sono già storiche e nessuno lo sfruttava: la chiave unica di
    ``mac_sightings`` è (mac, switch_ip, interface, vlan), quindi un client che
    cambia porta o VLAN lascia una riga NUOVA e la vecchia resta; quella di
    ``arp_entries`` è (mac, ip, source_ip), quindi un cambio di IP — o un
    secondo gateway che lo vede — lascia anch'esso la sua riga. Sommate a
    ``first_seen``/``last_seen``/``seen_count`` raccontano già la storia del
    client, fin dove arriva ``retention_days``.

    Limite noto: le righe aggregano, non sono un giornale. Un client che
    rimbalza A→B→A→B è indistinguibile da uno che si è spostato una volta,
    ``seen_count`` a parte. Contare il flapping richiederebbe una tabella di
    eventi, che qui non serve.

    Gli uplink restano fuori dalle posizioni, come in ``client_map``: la porta
    di un uplink dice dov'è il *cavo*, non dov'è il client.
    """
    init_db()
    norm = normalize_mac(mac)
    if not norm:
        return {"mac": mac, "known": False,
                "reason": "MAC non riconoscibile", "positions": [], "addresses": []}
    tenant_list = list(tenants) if tenants is not None else None
    if tenant_list is not None and not tenant_list:
        return {"mac": norm, "known": False, "reason": "nessun tenant visibile",
                "positions": [], "addresses": []}
    cap = max(1, min(500, limit))

    def _q(sql: str, extra_args: list) -> list:
        args: List[Any] = [norm] + extra_args
        if tenant_list is not None:
            sql += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
            args.extend(tenant_list)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(cap)
        with _lock, _connect() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    positions = _q(
        "SELECT switch_ip, switch_name, interface, vlan, tenant, first_seen, "
        "last_seen, seen_count FROM mac_sightings WHERE mac=? AND is_uplink=0", [])
    addresses = _q(
        "SELECT ip, vlan, source_ip, source_name, source_type, tenant, "
        "first_seen, last_seen, seen_count FROM arp_entries WHERE mac=?", [])
    # ``known`` = "ho potuto rispondere", non "ho trovato righe". Uno storico
    # vuoto È una risposta — un client visto per la prima volta oggi — e farlo
    # passare per sezione ignota trascinerebbe giù il ``complete`` dell'intero
    # referto. Stessa convenzione della sezione blocchi, dove zero blocchi è
    # ``known: True`` con ``total: 0``.
    return {"mac": norm, "known": True,
            "empty": not (positions or addresses),
            "positions": positions, "addresses": addresses,
            "retention_days": get_retention_days()}


def _access_positions_for(macs, tenants=None) -> dict:
    """Per un insieme di MAC ritorna { (mac, tenant): sighting_di_accesso_più_recente },
    escludendo gli uplink. La chiave include il tenant per evitare che la posizione
    di un tenant venga associata a un binding ARP di un altro tenant (stesso MAC).
    UNA sola query (a chunk per il limite di parametri di SQLite)."""
    macs = [m for m in dict.fromkeys(macs) if m]      # unici, ordine preservato
    if not macs:
        return {}
    rows = []
    tenant_list = list(tenants) if tenants is not None else None
    CHUNK = 400                                       # < limite ~999 parametri SQLite
    with _lock, _connect() as c:
        for i in range(0, len(macs), CHUNK):
            batch = macs[i:i + CHUNK]
            # NON si filtra su is_uplink in SQL: il valore scritto in raccolta
            # non riconosce i Port-channel (vedi reclassify_sightings), e
            # fidarsene qui faceva passare per porta di accesso un'interfaccia
            # aggregata verso un altro switch — cioè indicava come "posizione
            # del client" un punto di transito.
            q = ("SELECT mac, tenant, switch_ip, switch_name, interface, "
                 "port_channel, vlan, is_uplink, last_seen "
                 "FROM mac_sightings WHERE mac IN (%s)" % ",".join("?" * len(batch)))
            args = list(batch)
            if tenant_list is not None:
                q += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
                args.extend(tenant_list)
            q += " ORDER BY last_seen DESC"           # il primo per (MAC, tenant) = più recente
            rows.extend(dict(r) for r in c.execute(q, args).fetchall())

    reclassify_sightings(rows)
    best = {}
    for r in rows:
        if r.get("is_uplink"):
            continue
        key = (r["mac"], r["tenant"])
        if key not in best:
            best[key] = r
    return best


def client_map(mac: Optional[str] = None, ip: Optional[str] = None, tenants=None,
               limit: int = 500, source_ip: Optional[str] = None) -> list:
    """Vista unificata client: binding MAC<->IP (ARP dei gateway) arricchito
    con l'ultima posizione fisica nota (switch/porta della MAC table, uplink
    esclusi). Risponde a 'che IP ha questo MAC e a quale porta è attaccato'.
    source_ip filtra per gateway di provenienza."""
    entries = search_arp(mac=mac, ip=ip, source_ip=source_ip,
                         tenants=tenants, limit=limit)
    best = _access_positions_for((e["mac"] for e in entries), tenants=tenants)
    # Tipo del client: certo SOLO se assegnato nella scheda "Dispositivi e
    # categorie" (assignments per IP); altrimenti generico "client". Mai
    # ereditare source_type, che descrive il gateway, non il client.
    from services import inventory_manager
    assignments = inventory_manager.get_category_assignments()
    out = []
    for e in entries:
        access = best.get((e["mac"], e["tenant"]))  # join per-tenant: stessa MAC, stesso tenant
        assigned = assignments.get(e["ip"]) or {}
        out.append({
            **e,
            "client_type": assigned.get("category") or "client",
            "switch_ip": access.get("switch_ip") if access else "",
            "switch_name": access.get("switch_name") if access else "",
            "switch_port": access.get("interface") if access else "",
            "port_vlan": access.get("vlan") if access else "",
            "port_last_seen": access.get("last_seen") if access else "",
        })
    return out


def arp_stats(tenants=None) -> dict:
    """Statistiche ARP. tenants: None = nessuna restrizione (admin); lista = solo quei tenant."""
    init_db()
    where, args = "", []
    if tenants is not None:
        if not tenants:
            return {"bindings": 0, "unique_macs": 0, "sources": 0}
        where = " WHERE tenant IN (%s)" % ",".join("?" * len(tenants))
        args = list(tenants)
    with _lock, _connect() as c:
        total = c.execute("SELECT COUNT(*) n FROM arp_entries" + where, args).fetchone()["n"]
        macs = c.execute("SELECT COUNT(DISTINCT mac) n FROM arp_entries" + where, args).fetchone()["n"]
        sources = c.execute("SELECT COUNT(DISTINCT source_ip) n FROM arp_entries" + where, args).fetchone()["n"]
    return {"bindings": total, "unique_macs": macs, "sources": sources}


# --- Ricerca storica ---

def _row_to_dict(row) -> dict:
    d = dict(row)
    d["is_uplink"] = bool(d.get("is_uplink"))
    return d


def search(mac: Optional[str] = None, vlan: Optional[str] = None, interface: Optional[str] = None,
           switch_ip: Optional[str] = None, tenants=None, frm: Optional[str] = None, to: Optional[str] = None,
           limit: int = 500, site: Optional[str] = None) -> list:
    """Ricerca avvistamenti con filtri combinabili.

    - mac: MAC completo (match esatto) oppure frammento/OUI (ricerca parziale,
      ignora i separatori).
    - tenants: None = nessuna restrizione (admin); lista = solo quei tenant.
    """
    init_db()
    q = ["SELECT * FROM mac_sightings WHERE 1=1"]
    args: List[Any] = []

    if mac:
        norm = normalize_mac(mac)
        if norm:
            q.append("AND mac = ?")
            args.append(norm)
        else:
            frag = _HEXONLY.sub('', mac).lower()
            if frag:
                # Ricerca parziale/OUI: confronta ignorando i due punti.
                q.append("AND REPLACE(mac, ':', '') LIKE ?")
                args.append('%' + frag + '%')
    if vlan:
        q.append("AND vlan = ?")
        args.append(str(vlan) if not isinstance(vlan, str) else vlan)
    if interface:
        q.append("AND (interface LIKE ? OR port_channel LIKE ?)")
        args.extend(['%' + interface + '%', '%' + interface + '%'])
    if switch_ip:
        q.append("AND switch_ip = ?")
        args.append(switch_ip)
    if site:
        q.append("AND site = ?")
        args.append(site)
    if tenants is not None:
        if not tenants:
            return []
        q.append("AND tenant IN (%s)" % ",".join("?" * len(tenants)))
        args.extend(list(tenants))
    if frm:
        q.append("AND last_seen >= ?")
        args.append(frm)
    if to:
        q.append("AND first_seen <= ?")
        args.append(to)

    q.append("ORDER BY last_seen DESC LIMIT ?")
    args.append(max(1, min(5000, limit)))

    with _lock, _connect() as c:
        rows = c.execute(" ".join(q), args).fetchall()
    return [_row_to_dict(r) for r in rows]


def switch_table(switch_ip: str, tenants=None, limit: int = 2000) -> list:
    """Ultimo stato noto della MAC-table di uno switch."""
    return search(switch_ip=switch_ip, tenants=tenants, limit=limit)


def stats(tenants=None) -> dict:
    init_db()
    if tenants is not None and not tenants:
        return {"sightings": 0, "unique_macs": 0, "switches": 0,
                "retention_days": get_retention_days()}
    where = ""
    args = []
    if tenants is not None:
        where = " WHERE tenant IN (%s)" % ",".join("?" * len(tenants))
        args = list(tenants)
    with _lock, _connect() as c:
        total = c.execute("SELECT COUNT(*) n FROM mac_sightings" + where, args).fetchone()["n"]
        macs = c.execute("SELECT COUNT(DISTINCT mac) n FROM mac_sightings" + where, args).fetchone()["n"]
        switches = c.execute("SELECT COUNT(DISTINCT switch_ip) n FROM mac_sightings" + where, args).fetchone()["n"]
    return {"sightings": total, "unique_macs": macs, "switches": switches,
            "retention_days": get_retention_days()}


# --- Accesso o transito? -----------------------------------------------
# La marcatura fatta in raccolta (mark_uplinks) non riconosce i Port-channel:
# CDP/LLDP annunciano i vicini sulle porte fisiche membro, mai sull'interfaccia
# aggregata, quindi un MAC imparato su Po10 resta is_uplink=0 e sembra una
# porta di accesso. Qui si ricalcola contro la topologia, dove il Port-channel
# ha un nome (pc_name) e si sa dove va.
#
# Import locali di core_engine: e' lui a possedere la mappa di rete, e questo
# modulo e' storage — a livello di modulo sarebbe una dipendenza al contrario.
_INFRA_TYPES = {"switch", "router"}


def topology_uplinks():
    """Ritorna (uplink_map, known_switches).

    uplink_map: { switch_ip: { porta_normalizzata: etichetta_vicino } } — solo le
                porte che vanno verso un altro apparato di rete (infrastruttura).
    known_switches: insieme degli IP inventariati presenti in mappa (per cui la
                topologia è autorevole: assenza di una porta = porta di accesso).
    """
    from collections import defaultdict
    from core import core_engine
    uplink_map: dict = defaultdict(dict)
    known_switches: set = set()
    try:
        data = core_engine.generate_network_map(group_filter="all")
    except Exception:
        return uplink_map, known_switches

    nodes = data.get("nodes", [])
    node_type = {n["id"]: n.get("device_type") for n in nodes}
    node_label = {n["id"]: (n.get("label") or n["id"]) for n in nodes}
    known_switches = {n["id"] for n in nodes if n.get("group") != "Discovered"}

    def add(sw, port, neigh_id):
        if not port:
            return
        uplink_map[sw][core_engine._normalize_iface(port)] = node_label.get(neigh_id, neigh_id)

    for l in data.get("links", []):
        src, tgt = l.get("source"), l.get("target")
        tgt_infra = node_type.get(tgt) in _INFRA_TYPES
        src_infra = node_type.get(src) in _INFRA_TYPES
        pc = l.get("pc_name")
        # Le porte locali di src vanno verso tgt: sono uplink solo se tgt è infra.
        if tgt_infra:
            for p in l.get("local_ports", []):
                add(src, p, tgt)
            if pc:
                add(src, pc, tgt)
        if src_infra:
            for p in l.get("remote_ports", []):
                add(tgt, p, src)
            if pc:
                add(tgt, pc, src)
    return uplink_map, known_switches

def reclassify_sightings(rows, uplink_map=None, known_switches=None):
    """Ricalcola is_uplink/uplink_to di ogni avvistamento contro la topologia
    globale. Per gli switch noti la topologia è autorevole; per gli switch senza
    dati topologici si conserva il valore rilevato in raccolta (fallback)."""
    from core import core_engine
    if uplink_map is None or known_switches is None:
        uplink_map, known_switches = topology_uplinks()
    # MAC delle interfacce proprie degli switch: tali MAC sono infrastruttura
    # ("switch-interface"), non endpoint. Si taggano, non si scartano.
    if_macs = get_switch_if_macs()
    norm = core_engine._normalize_iface
    for r in rows:
        sw = r.get("switch_ip")
        if sw in known_switches:
            ups = uplink_map.get(sw, {})
            ni = norm(r.get("interface") or "")
            npc = norm(r.get("port_channel") or "") if r.get("port_channel") else ""
            neigh = ups.get(ni) or (ups.get(npc) if npc else None)
            r["is_uplink"] = bool(neigh)
            r["uplink_to"] = neigh or ""
        # else: switch senza topologia nota → mantiene is_uplink/uplink_to raccolti
        r["is_uplink"] = bool(r.get("is_uplink"))
        info = if_macs.get(r.get("mac"))
        if info:
            r["origin_type"] = "switch-interface"
            r["origin_switch"] = info.get("switch_name") or info.get("switch_ip") or ""
            r["origin_interface"] = info.get("interface") or ""
        else:
            r["origin_type"] = "endpoint"
    return rows
