# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Industrial ring and redundancy monitoring (MRP, DLR, PRP/HSR, RSTP).

Combines two passive/read-only telemetry feeds:
1. Standard and vendor SNMP tables/scalars walked during ``snmp_poller``
   rounds (IEC 62439-2 MRP, CISCO-DLR-MIB, IEC 62439-3 PRP/HSR, IEEE 802.1w
   RSTP BRIDGE-MIB).
2. Immediate parsing of industrial syslog and SNMP trap-to-syslog messages
   on UDP ingest for sub-second detection of ring open, loss of redundancy,
   or Ring Manager / Supervisor changes.

State transitions trigger immediate notifications via
``services.notifications.emit`` and structured ``ring.state`` / ``ring.alert``
events in observability.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinelnet.obs.ring")

# --- SNMP OIDs ---------------------------------------------------------------

# IEC 62439-2 Media Redundancy Protocol (MRP)
MRP_OIDS = {
    "domain_name": "1.0.62439.2.1.1.1.1.2",
    "admin_role": "1.0.62439.2.1.1.1.1.4",
    "oper_role": "1.0.62439.2.1.1.1.1.5",
    "state": "1.0.62439.2.1.1.1.1.12",
    "blocked": "1.0.62439.2.1.1.1.1.13",
    "ring_open_count": "1.0.62439.2.1.1.1.1.14",
}

# Enterprise MRP fallbacks (Siemens SCALANCE SN-MRP / Hirschmann HM2)
SCALANCE_MRP_OIDS = {
    "oper_role": "1.3.6.1.4.1.4329.20.1.1.1.1.33.1.2",
    "state": "1.3.6.1.4.1.4329.20.1.1.1.1.33.1.3",
}
HIRSCHMANN_MRP_OIDS = {
    "oper_role": "1.3.6.1.4.1.248.14.2.1.1.3",
    "state": "1.3.6.1.4.1.248.14.2.1.1.4",
}

# Cisco / ODVA Device Level Ring (CISCO-DLR-MIB)
DLR_OIDS = {
    "state": "1.3.6.1.4.1.9.9.796.1.1.1.1.2",
    "node_state": "1.3.6.1.4.1.9.9.796.1.1.1.1.3",
    "supervisor": "1.3.6.1.4.1.9.9.796.1.1.1.1.4",
    "faults": "1.3.6.1.4.1.9.9.796.1.1.1.1.7",
}

# IEC 62439-3 Parallel Redundancy Protocol (PRP) / High-availability Seamless Redundancy (HSR)
PRP_HSR_OIDS = {
    "dup_mode": "1.0.62439.3.1.2.1.1.4",
    "hsr_mode": "1.0.62439.3.1.2.1.1.6",
    "link_a": "1.0.62439.3.1.2.1.1.9",
    "link_b": "1.0.62439.3.1.2.1.1.10",
    "err_wrong_lan_a": "1.0.62439.3.1.3.1.1.5",
    "err_wrong_lan_b": "1.0.62439.3.1.3.1.1.6",
}

# IEEE 802.1d / 802.1w RSTP (BRIDGE-MIB)
RSTP_SCALARS = {
    "top_changes": "1.3.6.1.2.1.17.2.4.0",
    "designated_root": "1.3.6.1.2.1.17.2.5.0",
}
RSTP_PORT_STATE_OID = "1.3.6.1.2.1.17.2.15.1.3"

# --- Value normalization maps ------------------------------------------------

_MRP_ROLES = {
    1: "disabled",
    2: "client",
    3: "manager",
    4: "manager_auto",
}
_MRP_STATES = {
    1: "disabled",
    2: "undefined",
    3: "ring_open",
    4: "ring_closed",
}
_DLR_STATES = {
    1: "ring_closed",
    2: "ring_open",
    3: "ring_loop",
    4: "redundancy_lost",
    5: "ring_open",
    6: "disabled",
}
_DLR_NODE_STATES = {
    1: "backup",
    2: "active_supervisor",
    3: "ring_node",
    4: "disabled",
}
_PRP_LINK_STATES = {
    1: "up",
    2: "down",
}
_RSTP_PORT_STATES = {
    1: "disabled",
    2: "blocking",
    3: "listening",
    4: "learning",
    5: "forwarding",
    6: "broken",
}

# In-memory last known ring state per device IP for immediate SNMP transition alerting.
_state_lock = threading.Lock()
_last_ring_state: Dict[str, Dict[str, Any]] = {}


def clear_state_cache() -> None:
    """Reset the in-memory transition cache (useful in tests)."""
    with _state_lock:
        _last_ring_state.clear()


def _norm_mrp_state(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, int):
        return _MRP_STATES.get(val, str(val))
    low = str(val).strip().lower()
    if "open" in low:
        return "ring_open"
    if "closed" in low or "ok" in low:
        return "ring_closed"
    if "disable" in low:
        return "disabled"
    return low or None


def _norm_mrp_role(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, int):
        return _MRP_ROLES.get(val, str(val))
    low = str(val).strip().lower()
    if "auto" in low:
        return "manager_auto"
    if "manager" in low or low == "mrm":
        return "manager"
    if "client" in low or low == "mrc":
        return "client"
    if "disable" in low:
        return "disabled"
    return low or None


def _norm_dlr_state(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, int):
        return _DLR_STATES.get(val, str(val))
    low = str(val).strip().lower()
    if "normal" in low or "closed" in low:
        return "ring_closed"
    if "partial" in low:
        return "redundancy_lost"
    if "loop" in low:
        return "ring_loop"
    if "fault" in low or "open" in low:
        return "ring_open"
    if "disable" in low:
        return "disabled"
    return low or None


def _norm_dlr_node(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, int):
        return _DLR_NODE_STATES.get(val, str(val))
    low = str(val).strip().lower()
    if "active" in low and "supervisor" in low:
        return "active_supervisor"
    if "backup" in low:
        return "backup"
    if "node" in low:
        return "ring_node"
    if "non" in low or "disable" in low:
        return "disabled"
    return low or None


def _norm_prp_link(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, int):
        return _PRP_LINK_STATES.get(val, str(val))
    low = str(val).strip().lower()
    if low in ("up", "ok", "active"):
        return "up"
    if low in ("down", "fault", "fail", "error"):
        return "down"
    return low or None


def evaluate_ring_snmp(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Convert raw walked SNMP tables/scalars into normalized ring state & metrics.

    ``raw`` may contain keys: ``mrp``, ``dlr``, ``prp_hsr``, ``rstp``.
    Each protocol produces entries under ``results[protocol][instance]`` and
    numeric counters under ``metrics``. Protocols with no data are omitted.
    """
    results: Dict[str, Any] = {}
    metrics: Dict[str, int] = {}

    # 1. MRP
    mrp_raw = raw.get("mrp") or {}
    mrp_states = mrp_raw.get("state") or {}
    mrp_roles = mrp_raw.get("oper_role") or {}
    mrp_admin = mrp_raw.get("admin_role") or {}
    mrp_names = mrp_raw.get("domain_name") or {}
    mrp_opens = mrp_raw.get("ring_open_count") or {}
    mrp_indices = sorted(
        set(mrp_states) | set(mrp_roles) | set(mrp_admin) | set(mrp_names)
    )
    if mrp_indices:
        mrp_out: Dict[str, Any] = {}
        for idx in mrp_indices:
            state = _norm_mrp_state(mrp_states.get(idx))
            role = _norm_mrp_role(mrp_roles.get(idx))
            admin = _norm_mrp_role(mrp_admin.get(idx))
            if not state and not role:
                continue
            entry: Dict[str, Any] = {}
            if mrp_names.get(idx):
                entry["domain"] = str(mrp_names[idx])
            if state:
                entry["state"] = state
            if role:
                entry["oper_role"] = role
            if admin:
                entry["admin_role"] = admin
            mrp_out[str(idx)] = entry
            if isinstance(mrp_opens.get(idx), int):
                metrics[f"mrp.{idx}.ring_open_count"] = int(mrp_opens[idx])
        if mrp_out:
            results["mrp"] = mrp_out

    # 2. DLR
    dlr_raw = raw.get("dlr") or {}
    dlr_states = dlr_raw.get("state") or {}
    dlr_nodes = dlr_raw.get("node_state") or {}
    dlr_sups = dlr_raw.get("supervisor") or {}
    dlr_faults = dlr_raw.get("faults") or {}
    dlr_indices = sorted(set(dlr_states) | set(dlr_nodes) | set(dlr_sups))
    if dlr_indices:
        dlr_out: Dict[str, Any] = {}
        for idx in dlr_indices:
            state = _norm_dlr_state(dlr_states.get(idx))
            node_state = _norm_dlr_node(dlr_nodes.get(idx))
            sup = dlr_sups.get(idx)
            if not state and not node_state and not sup:
                continue
            entry = {}
            if state:
                entry["state"] = state
            if node_state:
                entry["node_state"] = node_state
            if sup is not None and str(sup).strip():
                entry["supervisor"] = str(sup).strip()
            dlr_out[str(idx)] = entry
            if isinstance(dlr_faults.get(idx), int):
                metrics[f"dlr.{idx}.faults"] = int(dlr_faults[idx])
        if dlr_out:
            results["dlr"] = dlr_out

    # 3. PRP / HSR
    prp_raw = raw.get("prp_hsr") or {}
    prp_dup = prp_raw.get("dup_mode") or {}
    prp_hsr = prp_raw.get("hsr_mode") or {}
    prp_la = prp_raw.get("link_a") or {}
    prp_lb = prp_raw.get("link_b") or {}
    prp_ea = prp_raw.get("err_wrong_lan_a") or {}
    prp_eb = prp_raw.get("err_wrong_lan_b") or {}
    prp_indices = sorted(set(prp_la) | set(prp_lb) | set(prp_dup) | set(prp_hsr))
    if prp_indices:
        prp_out: Dict[str, Any] = {}
        for idx in prp_indices:
            link_a = _norm_prp_link(prp_la.get(idx))
            link_b = _norm_prp_link(prp_lb.get(idx))
            mode_val = prp_hsr.get(idx) or prp_dup.get(idx)
            mode = "hsr" if prp_hsr.get(idx) and str(prp_hsr[idx]) not in ("0", "1", "disabled") else "prp"
            if isinstance(mode_val, str) and "hsr" in mode_val.lower():
                mode = "hsr"
            if link_a == "down" and link_b == "down":
                state = "ring_open"
            elif link_a == "down" or link_b == "down":
                state = "redundancy_lost"
            elif link_a == "up" and link_b == "up":
                state = "redundant"
            else:
                state = "unknown"
            prp_out[str(idx)] = {
                "mode": mode,
                "state": state,
                "link_a": link_a or "unknown",
                "link_b": link_b or "unknown",
            }
            if isinstance(prp_ea.get(idx), int):
                metrics[f"prp_hsr.{idx}.wrong_lan_a"] = int(prp_ea[idx])
            if isinstance(prp_eb.get(idx), int):
                metrics[f"prp_hsr.{idx}.wrong_lan_b"] = int(prp_eb[idx])
        if prp_out:
            results["prp_hsr"] = prp_out

    # 4. RSTP
    rstp_raw = raw.get("rstp") or {}
    root = rstp_raw.get("designated_root")
    top_changes = rstp_raw.get("top_changes")
    port_states = rstp_raw.get("port_states") or {}
    broken_ports = [
        str(p) for p, st in sorted(port_states.items())
        if _RSTP_PORT_STATES.get(st, str(st).lower()) == "broken"
    ]
    if root is not None or isinstance(top_changes, int) or port_states:
        rstp_entry: Dict[str, Any] = {
            "state": "redundancy_lost" if broken_ports else "normal",
        }
        if root is not None and str(root).strip():
            rstp_entry["designated_root"] = str(root).strip()
        if broken_ports:
            rstp_entry["broken_ports"] = broken_ports
        if port_states:
            rstp_entry["port_count"] = len(port_states)
        results["rstp"] = {"0": rstp_entry}
        if isinstance(top_changes, int):
            metrics["rstp.0.top_changes"] = int(top_changes)

    return results, metrics


async def poll_ring_snmp(
    engine, auth, target, context, walk_column_fn
) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Walk MRP, DLR, PRP/HSR, and RSTP OIDs on an SNMP target.

    Returns ``(results, metrics)``; both dicts are empty when the device
    exposes none of these protocols.
    """
    from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, get_cmd
    from observability.ingesters.snmp_poller import _scalar

    raw: Dict[str, Any] = {}

    # MRP: try IEC 62439-2 first, then vendor fallbacks if state+role silent.
    mrp_state = await walk_column_fn(engine, auth, target, context, MRP_OIDS["state"])
    mrp_role = await walk_column_fn(engine, auth, target, context, MRP_OIDS["oper_role"])
    if mrp_state or mrp_role:
        raw["mrp"] = {
            "state": mrp_state,
            "oper_role": mrp_role,
            "domain_name": await walk_column_fn(
                engine, auth, target, context, MRP_OIDS["domain_name"]
            ),
            "admin_role": await walk_column_fn(
                engine, auth, target, context, MRP_OIDS["admin_role"]
            ),
            "ring_open_count": await walk_column_fn(
                engine, auth, target, context, MRP_OIDS["ring_open_count"]
            ),
        }
    else:
        for enterprise in (SCALANCE_MRP_OIDS, HIRSCHMANN_MRP_OIDS):
            s = await walk_column_fn(engine, auth, target, context, enterprise["state"])
            r = await walk_column_fn(engine, auth, target, context, enterprise["oper_role"])
            if s or r:
                raw["mrp"] = {"state": s, "oper_role": r}
                break

    # DLR
    dlr_state = await walk_column_fn(engine, auth, target, context, DLR_OIDS["state"])
    dlr_node = await walk_column_fn(engine, auth, target, context, DLR_OIDS["node_state"])
    if dlr_state or dlr_node:
        raw["dlr"] = {
            "state": dlr_state,
            "node_state": dlr_node,
            "supervisor": await walk_column_fn(
                engine, auth, target, context, DLR_OIDS["supervisor"]
            ),
            "faults": await walk_column_fn(
                engine, auth, target, context, DLR_OIDS["faults"]
            ),
        }

    # PRP / HSR
    prp_la = await walk_column_fn(engine, auth, target, context, PRP_HSR_OIDS["link_a"])
    prp_lb = await walk_column_fn(engine, auth, target, context, PRP_HSR_OIDS["link_b"])
    if prp_la or prp_lb:
        raw["prp_hsr"] = {
            "link_a": prp_la,
            "link_b": prp_lb,
            "dup_mode": await walk_column_fn(
                engine, auth, target, context, PRP_HSR_OIDS["dup_mode"]
            ),
            "hsr_mode": await walk_column_fn(
                engine, auth, target, context, PRP_HSR_OIDS["hsr_mode"]
            ),
            "err_wrong_lan_a": await walk_column_fn(
                engine, auth, target, context, PRP_HSR_OIDS["err_wrong_lan_a"]
            ),
            "err_wrong_lan_b": await walk_column_fn(
                engine, auth, target, context, PRP_HSR_OIDS["err_wrong_lan_b"]
            ),
        }

    # RSTP scalars + port states
    rstp_data: Dict[str, Any] = {}
    err, status, _, var_binds = await get_cmd(
        engine,
        auth,
        target,
        context,
        ObjectType(ObjectIdentity(RSTP_SCALARS["top_changes"])),
        ObjectType(ObjectIdentity(RSTP_SCALARS["designated_root"])),
    )
    if not err and not status:
        for name, value in var_binds:
            val = _scalar(value)
            if val is None:
                continue
            oid_str = str(name)
            if oid_str == RSTP_SCALARS["top_changes"]:
                rstp_data["top_changes"] = val
            elif oid_str == RSTP_SCALARS["designated_root"]:
                rstp_data["designated_root"] = val
    port_states = await walk_column_fn(engine, auth, target, context, RSTP_PORT_STATE_OID)
    if port_states:
        rstp_data["port_states"] = port_states
    if rstp_data:
        raw["rstp"] = rstp_data

    return evaluate_ring_snmp(raw)


# --- Transition analysis & immediate alarming --------------------------------

def diff_ring_states(
    prev_results: Optional[Dict[str, Any]],
    curr_results: Dict[str, Any],
    prev_metrics: Optional[Dict[str, int]] = None,
    curr_metrics: Optional[Dict[str, int]] = None,
) -> List[Dict[str, Any]]:
    """Detect alarmable ring/redundancy events between consecutive SNMP polls."""
    alerts: List[Dict[str, Any]] = []
    prev = prev_results or {}
    pm = prev_metrics or {}
    cm = curr_metrics or {}

    # MRP transitions
    for idx, cur in (curr_results.get("mrp") or {}).items():
        old = (prev.get("mrp") or {}).get(idx) or {}
        domain = cur.get("domain") or idx
        st = cur.get("state")
        if st == "ring_open" and old.get("state") != "ring_open":
            alerts.append({
                "protocol": "mrp",
                "instance": idx,
                "condition": "ring_open",
                "severity": "critical",
                "title": f"MRP anello aperto (dominio {domain})",
                "before": old.get("state"),
                "after": st,
            })
        elif old.get("oper_role") and cur.get("oper_role") and old["oper_role"] != cur["oper_role"]:
            alerts.append({
                "protocol": "mrp",
                "instance": idx,
                "condition": "ring_manager_changed",
                "severity": "high",
                "title": f"MRP cambio ruolo Ring Manager (dominio {domain}: {old['oper_role']} -> {cur['oper_role']})",
                "before": old["oper_role"],
                "after": cur["oper_role"],
            })

    # DLR transitions
    for idx, cur in (curr_results.get("dlr") or {}).items():
        old = (prev.get("dlr") or {}).get(idx) or {}
        st = cur.get("state")
        if st in ("ring_open", "ring_loop") and old.get("state") != st:
            alerts.append({
                "protocol": "dlr",
                "instance": idx,
                "condition": "ring_open",
                "severity": "critical",
                "title": f"DLR anello aperto/guasto ({idx}: {st})",
                "before": old.get("state"),
                "after": st,
            })
        elif st == "redundancy_lost" and old.get("state") != st:
            alerts.append({
                "protocol": "dlr",
                "instance": idx,
                "condition": "redundancy_lost",
                "severity": "high",
                "title": f"DLR perdita di ridondanza ({idx}: partial fault)",
                "before": old.get("state"),
                "after": st,
            })
        if old.get("supervisor") and cur.get("supervisor") and old["supervisor"] != cur["supervisor"]:
            alerts.append({
                "protocol": "dlr",
                "instance": idx,
                "condition": "ring_manager_changed",
                "severity": "high",
                "title": f"DLR cambio Active Ring Supervisor ({old['supervisor']} -> {cur['supervisor']})",
                "before": old["supervisor"],
                "after": cur["supervisor"],
            })
        elif old.get("node_state") and cur.get("node_state") and (
            old["node_state"] != cur["node_state"]
            and "active_supervisor" in (old["node_state"], cur["node_state"])
        ):
            alerts.append({
                "protocol": "dlr",
                "instance": idx,
                "condition": "ring_manager_changed",
                "severity": "high",
                "title": f"DLR cambio stato Supervisor ({old['node_state']} -> {cur['node_state']})",
                "before": old["node_state"],
                "after": cur["node_state"],
            })

    # PRP / HSR transitions
    for idx, cur in (curr_results.get("prp_hsr") or {}).items():
        old = (prev.get("prp_hsr") or {}).get(idx) or {}
        proto_label = str(cur.get("mode") or "prp").upper()
        st = cur.get("state")
        if st == "ring_open" and old.get("state") != "ring_open":
            alerts.append({
                "protocol": "prp_hsr",
                "instance": idx,
                "condition": "ring_open",
                "severity": "critical",
                "title": f"{proto_label} entrambi i link LAN A/B down ({idx})",
                "before": old.get("state"),
                "after": st,
            })
        elif st == "redundancy_lost" and old.get("state") != "redundancy_lost":
            alerts.append({
                "protocol": "prp_hsr",
                "instance": idx,
                "condition": "redundancy_lost",
                "severity": "critical",
                "title": f"{proto_label} perdita di ridondanza (A={cur.get('link_a')}, B={cur.get('link_b')})",
                "before": old.get("state"),
                "after": st,
            })

    # RSTP transitions
    for idx, cur in (curr_results.get("rstp") or {}).items():
        old = (prev.get("rstp") or {}).get(idx) or {}
        if cur.get("state") == "redundancy_lost" and old.get("state") != "redundancy_lost":
            alerts.append({
                "protocol": "rstp",
                "instance": idx,
                "condition": "redundancy_lost",
                "severity": "high",
                "title": f"RSTP porta in stato broken ({', '.join(cur.get('broken_ports') or [])})",
                "before": old.get("state"),
                "after": cur.get("state"),
            })
        if (
            old.get("designated_root")
            and cur.get("designated_root")
            and old["designated_root"] != cur["designated_root"]
        ):
            alerts.append({
                "protocol": "rstp",
                "instance": idx,
                "condition": "ring_manager_changed",
                "severity": "high",
                "title": f"RSTP cambio Root Bridge ({old['designated_root']} -> {cur['designated_root']})",
                "before": old["designated_root"],
                "after": cur["designated_root"],
            })
        else:
            prev_tc = pm.get(f"rstp.{idx}.top_changes")
            curr_tc = cm.get(f"rstp.{idx}.top_changes")
            if isinstance(prev_tc, int) and isinstance(curr_tc, int) and curr_tc > prev_tc:
                alerts.append({
                    "protocol": "rstp",
                    "instance": idx,
                    "condition": "rstp_topology_change",
                    "severity": "medium",
                    "title": f"RSTP cambio topologia rilevato (TC count {prev_tc} -> {curr_tc})",
                    "before": prev_tc,
                    "after": curr_tc,
                })

    return alerts


def notify_ring_event(
    device_ip: str,
    tenant: str,
    event: Dict[str, Any],
    source: str = "snmp",
) -> int:
    """Emit an immediate notification for a detected ring/redundancy alert."""
    from services import notifications

    proto = str(event.get("protocol") or "ring")
    cond = str(event.get("condition") or "alert")
    inst = str(event.get("instance") or "0")
    severity = str(event.get("severity") or "high")
    title = str(event.get("title") or f"Allarme ring {proto}: {cond}")
    return notifications.emit(
        kind="siem.alert",
        device_ip=device_ip,
        severity=severity,
        title=f"{title} ({device_ip})",
        ctx={
            "category": "ring_redundancy",
            "source": source,
            "protocol": proto,
            "instance": inst,
            "condition": cond,
            "before": event.get("before"),
            "after": event.get("after"),
        },
        dedup_key=f"ring:{device_ip}:{proto}:{inst}:{cond}",
        tenant=tenant or None,
    )


def process_snmp_ring(
    device_ip: str,
    tenant: str,
    curr_results: Dict[str, Any],
    curr_metrics: Dict[str, int],
    ts: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Compare ``curr_results`` against previous snapshot for ``device_ip`` and emit alarms."""
    with _state_lock:
        prev = _last_ring_state.get(device_ip) or {}
        prev_results = prev.get("results")
        prev_metrics = prev.get("metrics")
        _last_ring_state[device_ip] = {
            "ts": ts or int(time.time()),
            "results": curr_results,
            "metrics": dict(curr_metrics),
        }

    alerts = diff_ring_states(prev_results, curr_results, prev_metrics, curr_metrics)
    for alert in alerts:
        try:
            notify_ring_event(device_ip, tenant, alert, source="snmp")
        except Exception:
            logger.debug("Ring notification failed for %s", device_ip, exc_info=True)
    return alerts


# --- Syslog / SNMP trap parsing ----------------------------------------------

_SYSLOG_RING_RULES: Tuple[Tuple[re.Pattern, str, str, str, str], ...] = (
    # MRP
    (
        re.compile(
            r"(?:%MRP[^\n]*RING[_\s]*OPEN|\bMRP\b[^\n]*\b(?:ring\s*(?:is\s*)?open|ring\s*broken|lost\s*redundancy)\b|\bmrpDomainState\b[^\n]*ringOpen\b)",
            re.IGNORECASE,
        ),
        "mrp",
        "ring_open",
        "critical",
        "MRP anello aperto rilevato via syslog/trap",
    ),
    (
        re.compile(
            r"(?:\bMRP\b|\bmrpDomainOperRole\b|\bMRM\b)[^\n]*(?:manager\s*(?:changed|elected|takeover|mismatch)|multiple\s*(?:ring\s*)?managers?|role\s*changed)",
            re.IGNORECASE,
        ),
        "mrp",
        "ring_manager_changed",
        "high",
        "MRP cambio/conflitto Ring Manager rilevato via syslog/trap",
    ),
    # DLR
    (
        re.compile(
            r"(?:%DLR[^\n]*RING[_\s]*FAULT|\bDLR\b[^\n]*(?:ring\s*fault|ring\s*open|broken|unexpected\s*loop)|\bcdlrRingState\b[^\n]*(?:ringFault|rapidFault))",
            re.IGNORECASE,
        ),
        "dlr",
        "ring_open",
        "critical",
        "DLR anello aperto/guasto rilevato via syslog/trap",
    ),
    (
        re.compile(
            r"(?:\bDLR\b|\bcdlrRingState\b)[^\n]*(?:partial\s*fault|partialFault|redundancy\s*lost)",
            re.IGNORECASE,
        ),
        "dlr",
        "redundancy_lost",
        "high",
        "DLR perdita di ridondanza rilevata via syslog/trap",
    ),
    (
        re.compile(
            r"(?:\bDLR\b|\bcdlr)[^\n]*(?:supervisor\s*(?:changed|elected|takeover)|active\s*(?:ring\s*)?supervisor\s*changed)",
            re.IGNORECASE,
        ),
        "dlr",
        "ring_manager_changed",
        "high",
        "DLR cambio Active Ring Supervisor rilevato via syslog/trap",
    ),
    # PRP / HSR
    (
        re.compile(
            r"(?:\b(?:PRP|HSR)\b|\blreLinkStatus[AB]\b)[^\n]*(?:(?:LAN\s*[AB]|port|link|redundancy)[^\n]*(?:down|fail|fault|lost|broken)|redundancy\s*lost)",
            re.IGNORECASE,
        ),
        "prp_hsr",
        "redundancy_lost",
        "critical",
        "PRP/HSR perdita di ridondanza rilevata via syslog/trap",
    ),
    # Vendor rings (Turbo Ring, FRNT, REP)
    (
        re.compile(
            r"\b(?:Turbo[\s-]*Ring|FRNT|REP)\b[^\n]*(?:open|broken|fault|break|down|redundancy\s*lost)",
            re.IGNORECASE,
        ),
        "mrp",
        "ring_open",
        "critical",
        "Apertura anello industriale rilevata via syslog/trap",
    ),
    (
        re.compile(
            r"\b(?:Turbo[\s-]*Ring|FRNT)\b[^\n]*(?:master|focal\s*point|manager)[^\n]*changed",
            re.IGNORECASE,
        ),
        "mrp",
        "ring_manager_changed",
        "high",
        "Cambio Master/Manager anello rilevato via syslog/trap",
    ),
    # RSTP / STP
    (
        re.compile(
            r"(?:\b(?:RSTP|STP|SPANTREE)\b[^\n]*(?:root\s*(?:bridge\s*)?(?:changed|elected|lost)|designated\s*root\s*changed))",
            re.IGNORECASE,
        ),
        "rstp",
        "ring_manager_changed",
        "high",
        "RSTP cambio Root Bridge rilevato via syslog/trap",
    ),
    (
        re.compile(
            r"(?:%SPANTREE[^\n]*TOPOTRAP|\b(?:RSTP|STP)\b[^\n]*topolog(?:y|ie)\s*change)",
            re.IGNORECASE,
        ),
        "rstp",
        "rstp_topology_change",
        "medium",
        "RSTP cambio topologia rilevato via syslog/trap",
    ),
)


def parse_ring_syslog(message: str) -> Optional[Dict[str, Any]]:
    """Extract a ring/redundancy condition from a syslog or trap message."""
    if not message:
        return None
    for pattern, protocol, condition, severity, title in _SYSLOG_RING_RULES:
        if pattern.search(message):
            return {
                "protocol": protocol,
                "instance": "0",
                "condition": condition,
                "severity": severity,
                "title": title,
            }
    return None
