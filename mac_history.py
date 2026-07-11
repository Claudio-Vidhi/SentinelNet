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

import data_config

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
    hexs = _HEXONLY.sub('', str(raw)).lower()
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
        _init_done = True


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
    days = max(1, min(3650, int(days)))
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


def prune(retention_days: int = None) -> int:
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
            iface = (r.get("interface") or "").strip()
            pc = (r.get("port_channel") or "").strip()
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
            iface = (r.get("interface") or "").strip()
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
            iface = (r.get("interface") or "").strip()
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


def search_arp(mac: str = None, ip: str = None, source_ip: str = None,
               tenants=None, limit: int = 500) -> list:
    """Ricerca i binding MAC<->IP. mac accetta anche frammenti (come search)."""
    init_db()
    q = ["SELECT * FROM arp_entries WHERE 1=1"]
    args = []
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
    args.append(max(1, min(5000, int(limit))))
    with _lock, _connect() as c:
        rows = c.execute(" ".join(q), args).fetchall()
    return [dict(r) for r in rows]


def _access_positions_for(macs, tenants=None) -> dict:
    """Per un insieme di MAC ritorna { mac: sighting_di_accesso_più_recente },
    escludendo gli uplink. UNA sola query (a chunk per il limite di parametri di
    SQLite), invece di una query per MAC."""
    macs = [m for m in dict.fromkeys(macs) if m]      # unici, ordine preservato
    if not macs:
        return {}
    best = {}
    tenant_list = list(tenants) if tenants is not None else None
    CHUNK = 400                                       # < limite ~999 parametri SQLite
    with _lock, _connect() as c:
        for i in range(0, len(macs), CHUNK):
            batch = macs[i:i + CHUNK]
            q = ("SELECT mac, switch_ip, switch_name, interface, vlan, last_seen "
                 "FROM mac_sightings WHERE is_uplink=0 "
                 "AND mac IN (%s)" % ",".join("?" * len(batch)))
            args = list(batch)
            if tenant_list is not None:
                q += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
                args.extend(tenant_list)
            q += " ORDER BY last_seen DESC"           # il primo per MAC = più recente
            for r in c.execute(q, args).fetchall():
                if r["mac"] not in best:
                    best[r["mac"]] = dict(r)
    return best


def client_map(mac: str = None, ip: str = None, tenants=None,
               limit: int = 500) -> list:
    """Vista unificata client: binding MAC<->IP (ARP dei gateway) arricchito
    con l'ultima posizione fisica nota (switch/porta della MAC table, uplink
    esclusi). Risponde a 'che IP ha questo MAC e a quale porta è attaccato'."""
    entries = search_arp(mac=mac, ip=ip, tenants=tenants, limit=limit)
    access_by_mac = _access_positions_for((e["mac"] for e in entries), tenants=tenants)
    out = []
    for e in entries:
        access = access_by_mac.get(e["mac"])
        out.append({
            **e,
            "switch_ip": access.get("switch_ip") if access else "",
            "switch_name": access.get("switch_name") if access else "",
            "switch_port": access.get("interface") if access else "",
            "port_vlan": access.get("vlan") if access else "",
            "port_last_seen": access.get("last_seen") if access else "",
        })
    return out


def arp_stats() -> dict:
    init_db()
    with _lock, _connect() as c:
        total = c.execute("SELECT COUNT(*) n FROM arp_entries").fetchone()["n"]
        macs = c.execute("SELECT COUNT(DISTINCT mac) n FROM arp_entries").fetchone()["n"]
        sources = c.execute("SELECT COUNT(DISTINCT source_ip) n FROM arp_entries").fetchone()["n"]
    return {"bindings": total, "unique_macs": macs, "sources": sources}


# --- Ricerca storica ---

def _row_to_dict(row) -> dict:
    d = dict(row)
    d["is_uplink"] = bool(d.get("is_uplink"))
    return d


def search(mac: str = None, vlan: str = None, interface: str = None,
           switch_ip: str = None, tenants=None, frm: str = None, to: str = None,
           limit: int = 500, site: str = None) -> list:
    """Ricerca avvistamenti con filtri combinabili.

    - mac: MAC completo (match esatto) oppure frammento/OUI (ricerca parziale,
      ignora i separatori).
    - tenants: None = nessuna restrizione (admin); lista = solo quei tenant.
    """
    init_db()
    q = ["SELECT * FROM mac_sightings WHERE 1=1"]
    args = []

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
        args.append(str(vlan))
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
    args.append(max(1, min(5000, int(limit))))

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
