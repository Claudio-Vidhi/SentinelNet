# -*- coding: utf-8 -*-
"""Timeline di un incidente: fonde in ordine cronologico le fonti già
raccolte dalla piattaforma, così che l'ingegnere veda la SEQUENZA di ciò che è
successo invece di una tabella di eventi.

Fonti unite (nessuna nuova raccolta dati):
- ``correlated``: gli eventi correlati dell'incidente, con la loro evidenza;
- ``syslog``: le righe syslog grezze attorno alla finestra, per le entità
  coinvolte (contesto che l'evento correlato da solo non mostra);
- ``flow``: i volumi al minuto da ``flow_aggregates`` per le stesse entità;
- ``api``: gli snapshot REST periodici dei dispositivi (``api_observations``);
- ``location``: posizione fisica e VLAN da mac_history/ARP.

ATTENZIONE ai timestamp: observability.db usa interi unix, mac_history.db usa
testo ISO-8601. La conversione avviene qui, al confine (``_iso_to_unix``): non
confrontare mai i due formati direttamente.
"""

import json
import logging
from datetime import datetime
from typing import Optional

from core import db

logger = logging.getLogger("sentinelnet.obs")

PAD_S = 300           # finestra allargata attorno all'incidente
MAX_SYSLOG = 200
MAX_FLOW_BUCKETS = 200
MAX_API = 50


def _iso_to_unix(value) -> Optional[int]:
    """'2026-07-27 09:31:00' | ISO-8601 → unix. None se non interpretabile."""
    if not value:
        return None
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _evidence(raw) -> dict:
    try:
        data = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} GB"


def build(incident_id: int) -> list:
    """Voci ordinate per ts: {ts, source, severity, text, ref}."""
    conn = db.get_observability_connection()
    try:
        incident = conn.execute(
            "SELECT id, tenant, opened_ts, last_event_ts FROM incidents WHERE id = ?",
            (incident_id,)).fetchone()
        if incident is None:
            return []
        tenant = incident["tenant"]
        frm = incident["opened_ts"] - PAD_S
        to = incident["last_event_ts"] + PAD_S

        events = conn.execute(
            """SELECT ce.id, ce.created_ts, ce.kind, ce.src_ip, ce.dst_ip,
                      ce.switch_port, ce.severity, ce.evidence_json
               FROM incident_events ie
               JOIN correlated_events ce ON ce.id = ie.correlated_event_id
               WHERE ie.incident_id = ?""", (incident_id,)).fetchall()

        entries = []
        ips = set()
        for ev in events:
            evidence = _evidence(ev["evidence_json"])
            ts = evidence.get("syslog_ts")
            ts = int(ts) if isinstance(ts, (int, float)) else int(ev["created_ts"])
            for ip in (ev["src_ip"], ev["dst_ip"]):
                if ip:
                    ips.add(ip)
            flow = evidence.get("flow") or {}
            detail = f"{ev['src_ip'] or '?'} → {ev['dst_ip'] or '?'}"
            if flow.get("dst_port"):
                detail += f":{flow['dst_port']}"
            if ev["switch_port"]:
                detail += f" ({ev['switch_port']})"
            entries.append({
                "ts": ts, "source": "correlated", "severity": ev["severity"],
                "text": f"{ev['kind']}: {detail}",
                "ref": {"correlated_event_id": ev["id"], "evidence": evidence},
            })

        ip_list = sorted(ips)
        if ip_list:
            entries += _syslog_entries(conn, tenant, ip_list, frm, to)
            entries += _flow_entries(conn, tenant, ip_list, frm, to)
            entries += _api_entries(conn, tenant, ip_list, frm, to)
            entries += _location_entries(tenant, ip_list)

        entries.sort(key=lambda e: e["ts"])
        return entries
    finally:
        conn.close()


def _syslog_entries(conn, tenant, ips, frm, to) -> list:
    """Righe syslog grezze del contesto: device fra le entità oppure IP citato
    nel messaggio."""
    like = " OR ".join(["message LIKE ?"] * len(ips))
    device = ",".join("?" * len(ips))
    rows = conn.execute(
        f"""SELECT ts, device_ip, severity, action, message
            FROM syslog_events
            WHERE tenant = ? AND ts BETWEEN ? AND ?
              AND (device_ip IN ({device}) OR {like})
            ORDER BY ts ASC LIMIT ?""",
        (tenant, frm, to, *ips, *[f"%{ip}%" for ip in ips], MAX_SYSLOG)).fetchall()
    return [{
        "ts": r["ts"], "source": "syslog", "severity": r["severity"],
        "text": (r["message"] or "")[:300],
        "ref": {"device_ip": r["device_ip"], "action": r["action"]},
    } for r in rows]


def _flow_entries(conn, tenant, ips, frm, to) -> list:
    """Volume al minuto per le entità coinvolte: mostra il picco di traffico
    che accompagna gli eventi."""
    placeholders = ",".join("?" * len(ips))
    rows = conn.execute(
        f"""SELECT window_start, SUM(total_bytes) AS total_bytes,
                   SUM(total_packets) AS total_packets, COUNT(*) AS pairs
            FROM flow_aggregates
            WHERE tenant = ? AND window_start BETWEEN ? AND ?
              AND (src_ip IN ({placeholders}) OR dst_ip IN ({placeholders}))
            GROUP BY window_start
            ORDER BY window_start ASC LIMIT ?""",
        (tenant, frm, to, *ips, *ips, MAX_FLOW_BUCKETS)).fetchall()
    return [{
        "ts": r["window_start"], "source": "flow", "severity": None,
        "text": f"{_human_bytes(r['total_bytes'] or 0)} in {r['pairs']} flussi",
        "ref": {"bytes": r["total_bytes"], "packets": r["total_packets"]},
    } for r in rows]


def _api_entries(conn, tenant, ips, frm, to) -> list:
    """Stato del dispositivo al momento dei fatti (snapshot REST periodici)."""
    placeholders = ",".join("?" * len(ips))
    rows = conn.execute(
        f"""SELECT ts, device_ip, kind, summary_json
            FROM api_observations
            WHERE tenant = ? AND ts BETWEEN ? AND ?
              AND device_ip IN ({placeholders})
            ORDER BY ts ASC LIMIT ?""",
        (tenant, frm, to, *ips, MAX_API)).fetchall()
    return [{
        "ts": r["ts"], "source": "api", "severity": None,
        "text": f"snapshot {r['kind']} da {r['device_ip']}",
        "ref": {"device_ip": r["device_ip"], "kind": r["kind"],
                "summary": (r["summary_json"] or "")[:500]},
    } for r in rows]


def _location_entries(tenant, ips) -> list:
    """Posizione fisica e VLAN note per le entità (DB separato, ts ISO)."""
    try:
        from collectors import mac_history
    except Exception as e:
        logger.debug("mac_history non disponibile: %s", e)
        return []
    out = []
    for ip in ips:
        for entry in mac_history.client_map(ip=ip, tenants=[tenant], limit=5):
            ts = _iso_to_unix(entry.get("port_last_seen") or entry.get("last_seen"))
            if ts is None:
                continue
            where = entry.get("switch_name") or entry.get("switch_ip") or "?"
            port = entry.get("switch_port") or "?"
            vlan = entry.get("port_vlan") or entry.get("vlan") or "?"
            out.append({
                "ts": ts, "source": "location", "severity": None,
                "text": f"{ip} ({entry.get('mac')}) su {where}:{port}, VLAN {vlan}",
                "ref": {"mac": entry.get("mac"), "switch_ip": entry.get("switch_ip"),
                        "switch_port": entry.get("switch_port"), "vlan": vlan},
            })
    return out
