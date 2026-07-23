import json
import sqlite3

from core.data_config import get_path

_DB_PATH = None


def set_db_path(path: str):
    global _DB_PATH
    _DB_PATH = path


def get_db_path() -> str:
    if _DB_PATH is not None:
        return _DB_PATH
    return get_path("redundancy.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path(), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS redundancy_groups (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              group_name TEXT NOT NULL,
              group_type TEXT NOT NULL CHECK (group_type IN ('ha_pair','stack','sso')),
              name TEXT NOT NULL,
              virtual_ip TEXT,
              logical_device_ip TEXT,
              health TEXT NOT NULL,
              detection_source TEXT NOT NULL,
              last_verified TEXT,
              UNIQUE(group_name, group_type, name),
              UNIQUE(logical_device_ip)
            );

            CREATE TABLE IF NOT EXISTS redundancy_members (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              redundancy_group_id INTEGER NOT NULL REFERENCES redundancy_groups(id) ON DELETE CASCADE,
              device_ip TEXT,
              member_index INTEGER,
              role TEXT NOT NULL,
              serial TEXT,
              norm_serial TEXT,
              model TEXT,
              firmware TEXT,
              state TEXT NOT NULL,
              mgmt_ip TEXT,
              priority INTEGER,
              details_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_members_group_norm_serial
              ON redundancy_members(redundancy_group_id, norm_serial)
              WHERE norm_serial IS NOT NULL;

            CREATE UNIQUE INDEX IF NOT EXISTS idx_members_group_index
              ON redundancy_members(redundancy_group_id, member_index)
              WHERE member_index IS NOT NULL;
            """
        )
        conn.commit()


def _format_group(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    group = dict(row)
    cur = conn.execute(
        """
        SELECT id, redundancy_group_id, device_ip, member_index, role, serial,
               norm_serial, model, firmware, state, mgmt_ip, priority, details_json
        FROM redundancy_members
        WHERE redundancy_group_id = ?
        ORDER BY member_index ASC, id ASC
        """,
        (group["id"],),
    )
    members = []
    for m in cur.fetchall():
        m_dict = dict(m)
        m_dict["details"] = json.loads(m_dict.pop("details_json", "{}") or "{}")
        members.append(m_dict)
    group["members"] = members
    return group


def list_groups(group_scope=None) -> list[dict]:
    init_db()
    with get_connection() as conn:
        if group_scope is not None:
            placeholders = ",".join(["?"] * len(group_scope))
            if not placeholders:
                return []
            cur = conn.execute(
                f"SELECT * FROM redundancy_groups WHERE group_name IN ({placeholders}) ORDER BY id ASC",
                tuple(group_scope),
            )
        else:
            cur = conn.execute("SELECT * FROM redundancy_groups ORDER BY id ASC")
        rows = cur.fetchall()
        return [_format_group(conn, row) for row in rows]


def get_group(group_id: int) -> dict | None:
    init_db()
    with get_connection() as conn:
        cur = conn.execute("SELECT * FROM redundancy_groups WHERE id = ?", (group_id,))
        row = cur.fetchone()
        if not row:
            return None
        return _format_group(conn, row)


def find_group_by_name(group_name: str, group_type: str, name: str) -> dict | None:
    init_db()
    with get_connection() as conn:
        cur = conn.execute(
            "SELECT * FROM redundancy_groups WHERE group_name = ? AND group_type = ? AND name = ?",
            (group_name, group_type, name),
        )
        row = cur.fetchone()
        if not row:
            return None
        return _format_group(conn, row)


def save_group(payload: dict) -> int:
    init_db()
    with get_connection() as conn:
        group_id = payload.get("id")
        if group_id:
            conn.execute(
                """
                UPDATE redundancy_groups
                SET group_name = ?, group_type = ?, name = ?, virtual_ip = ?,
                    logical_device_ip = ?, health = ?, detection_source = ?, last_verified = ?
                WHERE id = ?
                """,
                (
                    payload["group_name"],
                    payload["group_type"],
                    payload["name"],
                    payload.get("virtual_ip"),
                    payload.get("logical_device_ip"),
                    payload["health"],
                    payload["detection_source"],
                    payload.get("last_verified"),
                    group_id,
                ),
            )
            conn.execute("DELETE FROM redundancy_members WHERE redundancy_group_id = ?", (group_id,))
        else:
            cur = conn.execute(
                """
                INSERT INTO redundancy_groups
                  (group_name, group_type, name, virtual_ip, logical_device_ip, health, detection_source, last_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["group_name"],
                    payload["group_type"],
                    payload["name"],
                    payload.get("virtual_ip"),
                    payload.get("logical_device_ip"),
                    payload["health"],
                    payload["detection_source"],
                    payload.get("last_verified"),
                ),
            )
            group_id = cur.lastrowid

        for idx, m in enumerate(payload.get("members", [])):
            conn.execute(
                """
                INSERT INTO redundancy_members
                  (redundancy_group_id, device_ip, member_index, role, serial, norm_serial, model, firmware, state, mgmt_ip, priority, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    group_id,
                    m.get("device_ip"),
                    m.get("member_index", idx),
                    m.get("role", "unknown"),
                    m.get("serial"),
                    m.get("norm_serial"),
                    m.get("model"),
                    m.get("firmware"),
                    m.get("state", "ready"),
                    m.get("mgmt_ip"),
                    m.get("priority"),
                    json.dumps(m.get("details", {})),
                ),
            )
        conn.commit()
        return group_id


def delete_group(group_id: int) -> bool:
    init_db()
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM redundancy_groups WHERE id = ?", (group_id,))
        conn.commit()
        return cur.rowcount > 0
