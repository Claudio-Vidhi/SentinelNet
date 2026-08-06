"""Historization and search of MAC address sightings (SQLite, WAL).

Data model: for each (mac, switch, interface, vlan) ONE row is kept with
first_seen/last_seen/seen_count. When a MAC appears in a different position
(different port/switch/vlan) a new row is created: the sequence of rows of
the same MAC tells the history of its movements through the infrastructure.

Smart retention: rows no longer updated within 'retention_days' (default 30)
are deleted at the end of each scan, so the DB does not grow indefinitely.
The storage layer is independent of the transport used to collect the data
(NETCONF/RESTCONF/CLI): it simply receives a list of sightings.
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
    """Canonicalize a MAC into the 'aa:bb:cc:dd:ee:ff' format.

    Accepts the most common vendor formats ('aabb.ccdd.eeff', 'AA-BB-CC-DD-EE-FF',
    'aabbccddeeff', ...). Returns None if there are not 12 hexadecimal digits.
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
            # 'site': multi-site origin (default 'central'). Attribution
            # independent of the 'tenant' (group) used for user scoping.
            try:
                c.execute("ALTER TABLE mac_sightings ADD COLUMN site TEXT DEFAULT 'central'")
            except sqlite3.OperationalError:
                pass
            # A position = (mac, switch, interface, vlan): the upsert key.
            c.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_mac_pos
                         ON mac_sightings(mac, switch_ip, interface, vlan)""")
            c.execute("CREATE INDEX IF NOT EXISTS ix_mac       ON mac_sightings(mac)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_switch    ON mac_sightings(switch_ip)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_last_seen ON mac_sightings(last_seen)")
            c.execute("CREATE INDEX IF NOT EXISTS ix_tenant    ON mac_sightings(tenant)")
            c.execute("CREATE TABLE IF NOT EXISTS mac_settings (key TEXT PRIMARY KEY, value TEXT)")
            # Ad-hoc command override for non-standard devices (e.g. C8000V with
            # bridge-domain, where the FDB lives in 'show bridge-domain' and not
            # in 'show mac address-table').
            c.execute("""CREATE TABLE IF NOT EXISTS mac_cmd_overrides (
                switch_ip TEXT PRIMARY KEY,
                command   TEXT NOT NULL,
                fmt       TEXT DEFAULT 'generic'
            )""")
            # MACs of the switches' OWN interfaces (infrastructure): used to
            # classify those MACs as "switch-interface" rather than endpoints.
            c.execute("""
                CREATE TABLE IF NOT EXISTS switch_if_macs (
                  mac TEXT NOT NULL, switch_ip TEXT NOT NULL, switch_name TEXT DEFAULT '',
                  interface TEXT NOT NULL, last_seen TEXT NOT NULL,
                  PRIMARY KEY (mac, switch_ip, interface))
            """)
            # MAC <-> IP mappings collected from the ARP tables of L3 gateways
            # (switches with SVI or firewalls, depending on who owns the VLAN).
            # One row per (mac, ip, source_ip): the same MAC can have multiple IPs
            # (multi-VLAN) and the same binding can be seen by multiple gateways.
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


# --- Retention (smart, configurable) ---

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


# --- Ad-hoc command override per device ---

def get_override(switch_ip: str):
    """Returns {command, fmt} for the device, or None if not configured."""
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
    """Deletes sightings not updated within 'retention_days'.
    Returns the number of rows removed."""
    init_db()
    days = retention_days if retention_days is not None else get_retention_days()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec='seconds')
    with _lock, _connect() as c:
        cur = c.execute("DELETE FROM mac_sightings WHERE last_seen < ?", (cutoff,))
        removed = cur.rowcount
        c.execute("DELETE FROM arp_entries WHERE last_seen < ?", (cutoff,))
        return removed


# --- Writing sightings (upsert) ---

def record_sightings(rows, switch_ip: str, switch_name: str = "", tenant: str = "",
                     site: str = "central") -> dict:
    """Records a list of sightings from ONE switch.

    rows: iterable of dicts with keys: mac (mandatory), vlan, interface,
    port_channel, is_uplink (bool), oui_vendor.
    Upsert on the position (mac, switch, interface, vlan): if it exists it
    updates last_seen and seen_count, otherwise it creates the row (new
    position = movement).
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


# --- MACs of the switches' own interfaces (infrastructure) ---

def record_switch_if_macs(rows, switch_ip: str, switch_name: str = "") -> dict:
    """Records (upsert) the MACs of the own interfaces of ONE switch.

    rows: iterable of dicts with keys 'interface' and 'mac' (raw). Upsert
    key: (mac, switch_ip, interface); updates last_seen/switch_name.
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
    """Returns { normalized_mac: {switch_ip, switch_name, interface} } for
    read-time classification of sightings as infrastructure."""
    init_db()
    with _lock, _connect() as c:
        rows = c.execute("SELECT mac, switch_ip, switch_name, interface "
                         "FROM switch_if_macs").fetchall()
    return {r["mac"]: {"switch_ip": r["switch_ip"], "switch_name": r["switch_name"],
                       "interface": r["interface"]} for r in rows}


# --- MAC <-> IP (ARP tables of L3 gateways) ---

def record_arp_entries(rows, source_ip: str, source_name: str = "",
                       source_type: str = "", tenant: str = "",
                       site: str = "central") -> dict:
    """Records (upsert) the MAC<->IP bindings read from the ARP table of ONE
    L3 gateway (switch SVI or firewall).

    rows: iterable of dicts with keys: mac and ip (mandatory), vlan,
    interface. Upsert key: (mac, ip, source_ip).
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
    """Search MAC<->IP bindings. mac also accepts fragments (like search)."""
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
    """Returns { ip: vlan } for the requested IPs, from the most recent ARP
    binding with a non-empty VLAN (exact match, no prefix-LIKE), **constrained
    to the tenant** of each IP (``ip_tenant_map``: { ip: tenant }).

    IMPORTANT (multi-tenant scoping): private IPs can repeat across different
    sites (RFC1918 behind independent NATs). Without the tenant filter, an
    ARP binding from site B could "leak" into the flow graph of site A just
    because they share the same IP. Each lookup is therefore
    ``ip = ? AND tenant = ?`` — never a global IN(...) on the IPs.

    Used by the flow graph (Task 3, observability) to show the real VLAN
    when known, instead of a synthetic value. IPs with no known ARP binding
    (for that tenant) are absent from the returned dict (fallback left to
    the caller)."""
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


def positions_for_mac(mac: str, tenants=None) -> list:
    """Where this MAC is attached, from the MAC table alone — without ARP.

    ``client_map`` starts from ARP bindings: it answers "what IP does this
    MAC have and where is it", and without an interrogable gateway it does
    not answer at all. But "which port of which switch is it attached to"
    is a layer-2 question, and the MAC table alone satisfies it. Whoever
    has no L3 visibility — unmanaged gateway, VLAN owned by a third-party
    device — must still be able to locate a MAC, without an IP and without
    a gateway.

    One position per tenant, the most recent, uplinks excluded: same rule
    as ``client_map``, same function (``_access_positions_for``).
    """
    init_db()
    norm = normalize_mac(mac)
    if not norm:
        return []
    best = _access_positions_for([norm], tenants=tenants)
    out = [dict(v) for k, v in best.items() if k[0] == norm]
    out.sort(key=lambda r: r.get("last_seen") or "", reverse=True)
    return out


def client_history(mac: str, tenants=None, limit: int = 50) -> dict:
    """Where this MAC has been and what IPs it has had, from already-collected data.

    The two tables are already historical and nobody was taking advantage of
    it: the unique key of ``mac_sightings`` is (mac, switch_ip, interface,
    vlan), so a client that changes port or VLAN leaves a NEW row and the old
    one remains; that of ``arp_entries`` is (mac, ip, source_ip), so a change
    of IP — or a second gateway that sees it — also leaves its row. Combined
    with ``first_seen``/``last_seen``/``seen_count`` they already tell the
    client's story, as far back as ``retention_days`` reaches.

    Known limitation: rows aggregate, they are not a journal. A client that
    bounces A→B→A→B is indistinguishable from one that moved once, ``seen_count``
    aside. Counting flapping would require an events table, which is not
    needed here.

    Uplinks stay out of positions, as in ``client_map``: the port of an uplink
    tells where the *cable* is, not where the client is.
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
    # ``known`` = "I could answer", not "I found rows". An empty history
    # IS an answer — a client seen for the first time today — and letting it
    # pass for an unknown section would drag down the ``complete`` of the
    # entire report. Same convention as the blocks section, where zero blocks
    # is ``known: True`` with ``total: 0``.
    return {"mac": norm, "known": True,
            "empty": not (positions or addresses),
            "positions": positions, "addresses": addresses,
            "retention_days": get_retention_days()}


def _access_positions_for(macs, tenants=None) -> dict:
    """For a set of MACs returns { (mac, tenant): most_recent_access_sighting },
    excluding uplinks. The key includes the tenant to prevent the position of
    one tenant from being associated with an ARP binding of another tenant
    (same MAC). ONE single query (in chunks due to SQLite's parameter limit)."""
    macs = [m for m in dict.fromkeys(macs) if m]      # unique, order preserved
    if not macs:
        return {}
    rows = []
    tenant_list = list(tenants) if tenants is not None else None
    CHUNK = 400                                       # < SQLite ~999 param limit
    with _lock, _connect() as c:
        for i in range(0, len(macs), CHUNK):
            batch = macs[i:i + CHUNK]
            # is_uplink is NOT filtered in SQL: the value written at collection
            # time does not recognize Port-channels (see reclassify_sightings),
            # and trusting it here would pass off an aggregated interface toward
            # another switch as an access port — i.e. it would indicate a
            # transit point as the "client position".
            q = ("SELECT mac, tenant, switch_ip, switch_name, interface, "
                 "port_channel, vlan, is_uplink, last_seen "
                 "FROM mac_sightings WHERE mac IN (%s)" % ",".join("?" * len(batch)))
            args = list(batch)
            if tenant_list is not None:
                q += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
                args.extend(tenant_list)
            q += " ORDER BY last_seen DESC"           # first per (MAC, tenant) = most recent
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
    """Unified client view: MAC<->IP binding (gateway ARP) enriched with the
    last known physical position (switch/port from the MAC table, uplinks
    excluded). Answers 'what IP does this MAC have and which port is it
    attached to'. source_ip filters by source gateway."""
    entries = search_arp(mac=mac, ip=ip, source_ip=source_ip,
                         tenants=tenants, limit=limit)
    best = _access_positions_for((e["mac"] for e in entries), tenants=tenants)
    # Client type: certain ONLY if assigned in the "Devices and categories"
    # tab (assignments per IP); otherwise generic "client". Never inherit
    # source_type, which describes the gateway, not the client.
    from services import inventory_manager
    assignments = inventory_manager.get_category_assignments()
    out = []
    for e in entries:
        access = best.get((e["mac"], e["tenant"]))  # per-tenant join: same MAC, same tenant
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
    """ARP statistics. tenants: None = no restriction (admin); list = only those tenants."""
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


# --- Endpoint inventory (derived, never stored) -------------------------

# Interfaces into which no cable is plugged: they remain visible, but outside
# the count of free ports.
_NON_PHYSICAL_IF = ("vlan", "loopback", "null", "port-channel", "tunnel", "bdi")


def _is_physical_iface(name: str) -> bool:
    return not (name or "").lower().startswith(_NON_PHYSICAL_IF)


def _age_days(iso: str, now=None):
    """Days elapsed since an ISO timestamp, None if not interpretable.

    Timestamps written by this module carry the timezone; those coming from
    an older import may be naive. An unreadable value is not "zero days old":
    it is None, and whoever reads it marks nothing.
    """
    if not iso:
        return None
    try:
        ts = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ((now or datetime.now(timezone.utc)) - ts).total_seconds() / 86400.0


def endpoint_inventory(tenants=None, site: Optional[str] = None,
                       switch_ip: Optional[str] = None, vlan: Optional[str] = None,
                       q: Optional[str] = None, stale_days: int = 7,
                       limit: int = 2000) -> dict:
    """One endpoint per (MAC, tenant), from already-collected data.

    It starts from ``mac_sightings`` — the L2 truth, every MAC ever seen —
    and left-joins ``arp_entries`` for the IPs. The opposite, i.e. starting
    from the bindings as ``client_map()`` does, would lose every endpoint of
    a VLAN whose gateway is not interrogable: exactly the ones an inventory
    must list.

    The key is (MAC, tenant), the same as ``_access_positions_for()``: a
    tenant is a network of its own, and the same MAC in two sites is
    legitimately two rows.

    Everything is DERIVED and nothing is saved, for the same reason written
    in ``observability/endpoints.py``: the day the classification learns
    something new, what was collected yesterday improves too.
    """
    from observability import endpoints as ep_kb
    from services import inventory_manager

    init_db()
    tenant_list = list(tenants) if tenants is not None else None
    empty = {"results": [], "total": 0, "truncated": False,
             "counts": {"endpoints": 0, "switches": 0, "vlans": 0,
                        "stale": 0, "new": 0, "no_ip": 0, "random": 0}}
    # [] = "no tenant visible", which is not None = "no restriction".
    if tenant_list is not None and not tenant_list:
        return empty

    where, args = [], []
    if tenant_list is not None:
        where.append("tenant IN (%s)" % ",".join("?" * len(tenant_list)))
        args.extend(tenant_list)
    if site:
        where.append("site = ?")
        args.append(site)
    if switch_ip:
        where.append("switch_ip = ?")
        args.append(switch_ip)
    if vlan:
        where.append("vlan = ?")
        args.append(vlan)
    if q:
        where.append("(mac LIKE ? OR oui_vendor LIKE ? OR switch_name LIKE ? "
                     "OR interface LIKE ?)")
        args.extend(["%" + q + "%"] * 4)
    clause = (" WHERE " + " AND ".join(where)) if where else ""

    with _lock, _connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT mac, oui_vendor, vlan, switch_ip, switch_name, interface, "
            "port_channel, is_uplink, uplink_to, tenant, site, first_seen, "
            "last_seen, seen_count FROM mac_sightings" + clause, args).fetchall()]
        infra = {r["mac"] for r in c.execute(
            "SELECT DISTINCT mac FROM switch_if_macs").fetchall()}

    # The raw value does not recognize Port-channels: trusting it here would
    # pass off an aggregated interface toward another switch as an access
    # port, i.e. a transit point.
    reclassify_sightings(rows)
    rows = [r for r in rows if r["mac"] not in infra]
    if not rows:
        return empty

    macs = list(dict.fromkeys(r["mac"] for r in rows))
    arp: dict = {}
    CHUNK = 400                                   # < SQLite ~999 param limit
    with _lock, _connect() as c:
        for i in range(0, len(macs), CHUNK):
            batch = macs[i:i + CHUNK]
            sql = ("SELECT mac, ip, tenant FROM arp_entries WHERE mac IN (%s)"
                   % ",".join("?" * len(batch)))
            a = list(batch)
            if tenant_list is not None:
                sql += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
                a.extend(tenant_list)
            for r in c.execute(sql, a).fetchall():
                arp.setdefault((r["mac"], r["tenant"] or ""), []).append(dict(r))

    assignments = inventory_manager.get_category_assignments()
    now = datetime.now(timezone.utc)
    groups: dict = {}
    for r in rows:
        groups.setdefault((r["mac"], r["tenant"] or ""), []).append(r)

    results: List[dict] = []
    for (mac, tenant), grp in groups.items():
        access = [s for s in grp if not s.get("is_uplink")]
        access.sort(key=lambda s: s.get("last_seen") or "", reverse=True)
        distinct = {(s["switch_ip"], (s.get("interface") or "").lower())
                    for s in access}
        best = access[0] if access else {}

        ips = sorted({b["ip"] for b in arp.get((mac, tenant), []) if b.get("ip")})
        first_seen = min(s["first_seen"] for s in grp)
        last_seen = max(s["last_seen"] for s in grp)
        info = ep_kb.classify_mac(mac) or {}

        flags = []
        if len(distinct) > 1:
            flags.append("AMBIGUOUS")
        if info.get("vendor_kind"):
            flags.append("VM")
        elif not ep_kb.is_stable_identity(mac):
            flags.append("RANDOM")
        if len(ips) > 1:
            flags.append("MULTI-IP")
        if not ips:
            flags.append("NO-IP")
        if not access:
            flags.append("TRANSIT-ONLY")
        age = _age_days(last_seen, now)
        born = _age_days(first_seen, now)
        if age is not None and age > stale_days:
            flags.append("STALE")
        if born is not None and born <= stale_days:
            flags.append("NEW")

        # Client type: certain ONLY if assigned by hand in the "Devices and
        # categories" tab. Never inherit the gateway's type.
        assigned = next((assignments[ip] for ip in ips if assignments.get(ip)), {})
        results.append({
            "mac": mac, "tenant": tenant,
            "oui_vendor": next((s["oui_vendor"] for s in grp if s.get("oui_vendor")), ""),
            "site": grp[0].get("site") or "",
            "ips": ips,
            "switch_ip": best.get("switch_ip", ""),
            "switch_name": best.get("switch_name", ""),
            "interface": best.get("interface", ""),
            "vlan": best.get("vlan", ""),
            "first_seen": first_seen, "last_seen": last_seen,
            "seen_count": sum(s.get("seen_count") or 0 for s in grp),
            "access_port_count": len(distinct),
            "client_type": assigned.get("category") or "client",
            "flags": flags,
        })

    results.sort(key=lambda e: e["last_seen"], reverse=True)
    total = len(results)
    counts = {
        "endpoints": total,
        "switches": len({e["switch_ip"] for e in results if e["switch_ip"]}),
        "vlans": len({e["vlan"] for e in results if e["vlan"]}),
        "stale": sum(1 for e in results if "STALE" in e["flags"]),
        "new": sum(1 for e in results if "NEW" in e["flags"]),
        "no_ip": sum(1 for e in results if "NO-IP" in e["flags"]),
        "random": sum(1 for e in results if "RANDOM" in e["flags"]),
    }
    cap = max(1, min(20000, limit))
    return {"results": results[:cap], "total": total,
            "truncated": total > cap, "counts": counts}


# --- Historical search ---

def _row_to_dict(row) -> dict:
    d = dict(row)
    d["is_uplink"] = bool(d.get("is_uplink"))
    return d


def search(mac: Optional[str] = None, vlan: Optional[str] = None, interface: Optional[str] = None,
           switch_ip: Optional[str] = None, tenants=None, frm: Optional[str] = None, to: Optional[str] = None,
           limit: int = 500, site: Optional[str] = None) -> list:
    """Search sightings with combinable filters.

    - mac: full MAC (exact match) or fragment/OUI (partial search,
      ignores separators).
    - tenants: None = no restriction (admin); list = only those tenants.
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
                # Partial/OUI search: compare ignoring colons.
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
    """Last known state of a switch's MAC table."""
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


# --- Access or transit? -----------------------------------------------
# The marking done at collection time (mark_uplinks) does not recognize
# Port-channels: CDP/LLDP announce neighbors on the physical member ports,
# never on the aggregated interface, so a MAC learned on Po10 stays
# is_uplink=0 and looks like an access port. Here it is recomputed against
# the topology, where the Port-channel has a name (pc_name) and we know
# where it goes.
#
# Local imports of core_engine: it owns the network map, and this module is
# storage — at the module level this would be a backward dependency.
_INFRA_TYPES = {"switch", "router"}


def topology_uplinks():
    """Returns (uplink_map, known_switches).

    uplink_map: { switch_ip: { normalized_port: neighbor_label } } — only the
                ports that go toward another network device (infrastructure).
    known_switches: set of inventoried IPs present on the map (for which the
                topology is authoritative: absence of a port = access port).
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
        # src's local ports go toward tgt: they are uplinks only if tgt is infra.
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
    """Recomputes is_uplink/uplink_to of each sighting against the global
    topology. For known switches the topology is authoritative; for switches
    without topological data the value detected at collection time is kept
    (fallback)."""
    from core import core_engine
    if uplink_map is None or known_switches is None:
        uplink_map, known_switches = topology_uplinks()
    # MACs of the switches' own interfaces: those MACs are infrastructure
    # ("switch-interface"), not endpoints. They are tagged, not discarded.
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
        # else: switch without known topology → keeps collected is_uplink/uplink_to
        r["is_uplink"] = bool(r.get("is_uplink"))
        info = if_macs.get(r.get("mac"))
        if info:
            r["origin_type"] = "switch-interface"
            r["origin_switch"] = info.get("switch_name") or info.get("switch_ip") or ""
            r["origin_interface"] = info.get("interface") or ""
        else:
            r["origin_type"] = "endpoint"
    return rows


def port_occupancy(switch_ip: str, tenants=None) -> dict:
    """State of each port of a switch: occupied, uplink, or free.

    The interface list already exists: ``switch_if_macs`` is populated at
    every MAC scan by ``collect_interface_macs()`` (``show interfaces``, or
    ``ietf-interfaces`` via NETCONF/RESTCONF). When that collection failed —
    it is not fatal, the list stays empty — it is SAID with
    ``port_list_known: False`` instead of answering "zero free ports": zero
    rows disguised as "no data" are worse than a declared gap.

    ``free`` means "no learned MAC", NOT "no cable": a silent device reads as
    a free port. It is stated in the UI.
    """
    from core.core_engine import _normalize_iface

    init_db()
    tenant_list = list(tenants) if tenants is not None else None
    unknown = {"switch": switch_ip, "port_list_known": False,
               "if_list_age_s": None, "ports": [],
               "counts": {"total": 0, "occupied": 0, "uplink": 0, "free": 0}}
    if tenant_list is not None and not tenant_list:
        return unknown

    with _lock, _connect() as c:
        ifaces = [dict(r) for r in c.execute(
            "SELECT interface, MAX(last_seen) AS last_seen FROM switch_if_macs "
            "WHERE switch_ip=? GROUP BY interface ORDER BY interface",
            (switch_ip,)).fetchall()]
        sql = ("SELECT mac, tenant, switch_ip, switch_name, interface, "
               "port_channel, vlan, is_uplink, last_seen FROM mac_sightings "
               "WHERE switch_ip=?")
        args = [switch_ip]
        if tenant_list is not None:
            sql += " AND tenant IN (%s)" % ",".join("?" * len(tenant_list))
            args.extend(tenant_list)
        sightings = [dict(r) for r in c.execute(sql, args).fetchall()]

    if not ifaces:
        return unknown

    reclassify_sightings(sightings)
    uplink_map, _known = topology_uplinks()
    ups = {k: v for k, v in (uplink_map.get(switch_ip) or {}).items()}

    by_port: dict = {}
    for s in sightings:
        by_port.setdefault(_normalize_iface(s.get("interface") or ""), []).append(s)

    ports, counts = [], {"total": 0, "occupied": 0, "uplink": 0, "free": 0}
    for row in ifaces:
        name = row["interface"]
        norm = _normalize_iface(name)
        physical = _is_physical_iface(name)
        neigh = ups.get(norm)
        seen = by_port.get(norm, [])
        access = [s for s in seen if not s.get("is_uplink")]
        if neigh or (seen and not access):
            state = "uplink"
        elif access:
            state = "occupied"
        else:
            state = "free"
        ports.append({"interface": name, "state": state, "physical": physical,
                      "uplink_to": neigh or "",
                      "macs": sorted({s["mac"] for s in access}),
                      "last_seen": row["last_seen"]})
        # The count concerns the ports into which a cable is plugged: a Vlan10
        # among the "free" ones would be a port that does not exist.
        if physical:
            counts["total"] += 1
            counts[state] += 1

    # Age of the interface list: how old the most recent MAC scan of THIS
    # switch is. None if the timestamp is not interpretable — which is not
    # "updated now".
    age_days = _age_days(max(r["last_seen"] for r in ifaces))
    return {"switch": switch_ip, "port_list_known": True,
            "if_list_age_s": None if age_days is None else age_days * 86400.0,
            "ports": ports, "counts": counts}
