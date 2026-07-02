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
                    tenant       TEXT    DEFAULT '',
                    first_seen   TEXT    NOT NULL,
                    last_seen    TEXT    NOT NULL,
                    seen_count   INTEGER DEFAULT 1
                )
            """)
            # Una posizione = (mac, switch, interfaccia, vlan): chiave di upsert.
            c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_mac_pos
                         ON mac_sightings(mac, switch_ip, interface, vlan)""")
            c.execute("CREATE INDEX IF NOT EXISTS ix_mac       ON mac_sightings(mac)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_switch    ON mac_sightings(switch_ip)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_last_seen ON mac_sightings(last_seen)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_tenant    ON mac_sightings(tenant)")
            c.execute("CREATE TABLE IF NOT EXISTS mac_settings (key TEXT PRIMARY KEY, value TEXT)")
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


def prune(retention_days: int = None) -> int:
    """Elimina gli avvistamenti non aggiornati da più di 'retention_days'.
    Ritorna il numero di righe rimosse."""
    init_db()
    days = retention_days if retention_days is not None else get_retention_days()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds')
    with _lock, _connect() as c:
        cur = c.execute("DELETE FROM mac_sightings WHERE last_seen < ?", (cutoff,))
        return cur.rowcount


# --- Scrittura avvistamenti (upsert) ---

def record_sightings(rows, switch_ip: str, switch_name: str = "", tenant: str = "") -> dict:
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
            oui = (r.get("oui_vendor") or "").strip()
            existing = c.execute(
                "SELECT id FROM mac_sightings WHERE mac=? AND switch_ip=? AND interface=? AND vlan=?",
                (mac, switch_ip, iface, vlan)).fetchone()
            if existing:
                c.execute("""UPDATE mac_sightings
                             SET last_seen=?, seen_count=seen_count+1, is_uplink=?,
                                 port_channel=?, oui_vendor=?, switch_name=?, tenant=?
                             WHERE id=?""",
                          (now, up, pc, oui, switch_name, tenant, existing["id"]))
                n_upd += 1
            else:
                c.execute("""INSERT INTO mac_sightings
                             (mac, oui_vendor, vlan, switch_ip, switch_name, interface,
                              port_channel, is_uplink, tenant, first_seen, last_seen, seen_count)
                             VALUES (?,?,?,?,?,?,?,?,?,?,?,1)""",
                          (mac, oui, vlan, switch_ip, switch_name, iface, pc, up, tenant, now, now))
                n_new += 1
    return {"new": n_new, "updated": n_upd, "skipped": n_skip}


# --- Ricerca storica ---

def _row_to_dict(row) -> dict:
    d = dict(row)
    d["is_uplink"] = bool(d.get("is_uplink"))
    return d


def search(mac: str = None, vlan: str = None, interface: str = None,
           switch_ip: str = None, tenants=None, frm: str = None, to: str = None,
           limit: int = 500) -> list:
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


def stats() -> dict:
    init_db()
    with _lock, _connect() as c:
        total = c.execute("SELECT COUNT(*) n FROM mac_sightings").fetchone()["n"]
        macs = c.execute("SELECT COUNT(DISTINCT mac) n FROM mac_sightings").fetchone()["n"]
        switches = c.execute("SELECT COUNT(DISTINCT switch_ip) n FROM mac_sightings").fetchone()["n"]
    return {"sightings": total, "unique_macs": macs, "switches": switches,
            "retention_days": get_retention_days()}
