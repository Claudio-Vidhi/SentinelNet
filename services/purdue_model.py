# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Purdue Enterprise Reference Architecture & IEC 62443 Zone/Conduit helpers.

Provides:
- Canonical Purdue level validation (L0..L4, L3.5 DMZ) for devices & segments.
- OT production VLAN validation for static-network rogue MAC detection.
- IP-to-Purdue-zone resolution (device > segment > RFC1918/external).
- IT/OT boundary violation checks (blueprint conduits, firewall rules, syslog).
- Immediate alerts (`events` + `notifications.emit`) for IT/OT violations
  and rogue MACs on OT VLANs.
"""
import functools
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from core import db

logger = logging.getLogger("sentinelnet.purdue")

PURDUE_LEVELS = ("", "L0", "L1", "L2", "L3", "L3.5", "L4")
PURDUE_NON_EMPTY = ("L0", "L1", "L2", "L3", "L3.5", "L4")
PURDUE_RANK = {
    "L0": 0.0,
    "L1": 1.0,
    "L2": 2.0,
    "L3": 3.0,
    "L3.5": 3.5,
    "L4": 4.0,
}
OT_LEVELS = frozenset(("L0", "L1", "L2"))
OT_SHOPFLOOR_LEVELS = frozenset(("L0", "L1"))

PURDUE_META = {
    "L0":   {"label_it": "L0 · Campo / Sensori",      "label_en": "L0 · Field / Sensors",    "color": "#ef4444"},
    "L1":   {"label_it": "L1 · Controllo (PLC/RTU)",  "label_en": "L1 · Control (PLC/RTU)",  "color": "#f97316"},
    "L2":   {"label_it": "L2 · Supervisione (SCADA)", "label_en": "L2 · Supervisory (SCADA)","color": "#eab308"},
    "L3":   {"label_it": "L3 · Site Operations",      "label_en": "L3 · Site Operations",    "color": "#22c55e"},
    "L3.5": {"label_it": "L3.5 · DMZ IT/OT",          "label_en": "L3.5 · IT/OT DMZ",        "color": "#06b6d4"},
    "L4":   {"label_it": "L4 · Enterprise IT",        "label_en": "L4 · Enterprise IT",      "color": "#3b82f6"},
}

# Private LAN ranges (RFC 1918 + CGNAT RFC 6598). Addresses outside these and
# outside any configured tenant segment/device are treated as "external".
_INTERNAL_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)

_SECURITY_STOP_ACTIONS = frozenset((
    "deny", "denied", "blocked", "block", "drop", "dropped",
    "reset", "reset-both", "reset-client", "reset-server",
    "clear_session", "redirect", "sinkhole",
))


def normalize_purdue_level(raw: Any) -> str:
    """Validate and canonicalize a Purdue level string ('' or L0..L4 / L3.5)."""
    val = str(raw or "").strip().upper()
    if not val:
        return ""
    if val in ("0", "1", "2", "3", "3.5", "4"):
        val = "L" + val
    if val not in PURDUE_LEVELS:
        raise ValueError(f"Livello Purdue non valido: {raw}")
    return val


def normalize_ot_vlans(raw: Any) -> list[str]:
    """Normalize VLAN list or comma-separated string to validated '1'..'4094' strings."""
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        items = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(part).strip() for part in raw]
    else:
        raise ValueError("Formato VLAN OT non valido.")
    out: set[str] = set()
    for item in items:
        if not item:
            continue
        try:
            vid = int(item)
        except ValueError:
            raise ValueError(f"VLAN OT non valida: {item}")
        if not (1 <= vid <= 4094):
            raise ValueError(f"VLAN OT fuori intervallo (1-4094): {item}")
        out.add(str(vid))
    return sorted(out, key=lambda v: int(v))


def _ip_obj(raw: Any):
    try:
        return ipaddress.ip_address(str(raw or "").strip())
    except ValueError:
        return None


def _net_obj(raw: Any):
    try:
        return ipaddress.ip_network(str(raw or "").strip(), strict=False)
    except ValueError:
        return None


def _is_external_ip(addr) -> bool:
    if addr is None:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    return not any(addr.version == n.version and addr in n for n in _INTERNAL_NETS)


def _split_addrs(raw: Any) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, (list, tuple, set)):
        out = []
        for item in raw:
            out.extend(_split_addrs(item))
        return out
    return [p.strip() for p in str(raw).replace(";", ",").split(",") if p.strip()]


def _index_segments(segments: list[dict]) -> list[dict]:
    indexed = []
    for s in segments or []:
        if not isinstance(s, dict):
            continue
        nets = [n for n in (_net_obj(c) for c in (s.get("subnets") or [])) if n is not None]
        indexed.append({
            "id": str(s.get("id") or ""),
            "name": str(s.get("name") or ""),
            "purdue_level": str(s.get("purdue_level") or ""),
            "ot_vlans": [str(v) for v in (s.get("ot_vlans") or [])],
            "subnets": nets,
            "members": set(str(m) for m in (s.get("members") or [])),
            "excluded": set(str(e) for e in (s.get("excluded") or [])),
        })
    return indexed


def resolve_ip_zone(
    ip_str: str,
    devices: list[dict],
    segments: list[dict],
    _indexed_segments: Optional[list[dict]] = None,
    _dev_by_ip: Optional[dict[str, dict]] = None,
) -> dict:
    """Resolve an IP address to its Purdue level and segment context.

    Precedence:
    1. Explicit ``Purdue Level`` on an inventoried device with matching ``IP``.
    2. Explicit segment membership or CIDR match (excluding ``excluded``).
    3. External / Internet if not internal RFC1918/CGNAT and not matching any asset/segment.
    """
    ip_clean = str(ip_str or "").strip()
    dev_map = _dev_by_ip if _dev_by_ip is not None else {
        str(d.get("IP") or ""): d for d in (devices or []) if d.get("IP")
    }
    segs = _indexed_segments if _indexed_segments is not None else _index_segments(segments)

    dev = dev_map.get(ip_clean)
    addr = _ip_obj(ip_clean)

    matched_seg = None
    for s in segs:
        if ip_clean in s["excluded"]:
            continue
        if ip_clean in s["members"] or (
            addr is not None and any(addr.version == n.version and addr in n for n in s["subnets"])
        ):
            matched_seg = s
            break

    dev_level = str((dev or {}).get("Purdue Level") or "").strip()
    if dev_level:
        return {
            "level": dev_level,
            "segment_id": matched_seg["id"] if matched_seg else "",
            "segment_name": matched_seg["name"] if matched_seg else "",
            "source": "device",
        }
    if matched_seg and matched_seg["purdue_level"]:
        return {
            "level": matched_seg["purdue_level"],
            "segment_id": matched_seg["id"],
            "segment_name": matched_seg["name"],
            "source": "segment",
        }
    if dev is None and matched_seg is None and _is_external_ip(addr):
        return {
            "level": "external",
            "segment_id": "",
            "segment_name": "",
            "source": "external",
        }
    return {
        "level": "",
        "segment_id": matched_seg["id"] if matched_seg else "",
        "segment_name": matched_seg["name"] if matched_seg else "",
        "source": "unknown",
    }


def resolve_target_zone(
    target_str: str,
    devices: list[dict],
    segments: list[dict],
    _indexed_segments: Optional[list[dict]] = None,
    _dev_by_ip: Optional[dict[str, dict]] = None,
) -> dict:
    """Resolve either an IP or CIDR string (e.g. from a firewall address object)."""
    text = str(target_str or "").strip()
    if not text:
        return {"level": "", "segment_id": "", "segment_name": "", "source": "unknown"}
    if "/" not in text:
        return resolve_ip_zone(text, devices, segments, _indexed_segments, _dev_by_ip)

    net = _net_obj(text)
    if net is None:
        return {"level": "", "segment_id": "", "segment_name": "", "source": "unknown"}
    if net.prefixlen == 0:
        return {"level": "external", "segment_id": "", "segment_name": "any", "source": "external"}
    if net.num_addresses == 1:
        return resolve_ip_zone(str(net.network_address), devices, segments, _indexed_segments, _dev_by_ip)

    segs = _indexed_segments if _indexed_segments is not None else _index_segments(segments)
    for s in segs:
        if not s["purdue_level"]:
            continue
        if any(net.version == sn.version and net.overlaps(sn) for sn in s["subnets"]):
            return {
                "level": s["purdue_level"],
                "segment_id": s["id"],
                "segment_name": s["name"],
                "source": "segment",
            }
    if _is_external_ip(net.network_address):
        return {"level": "external", "segment_id": "", "segment_name": "", "source": "external"}
    return {"level": "", "segment_id": "", "segment_name": "", "source": "unknown"}


def classify_conduit_pair(level_a: str, level_b: str) -> Optional[dict]:
    """Classify whether communication/linking between two Purdue zones violates IEC 62443.

    Returns finding template dict ``{code, severity}`` or None if compliant.
    """
    if not level_a or not level_b or level_a == level_b:
        return None
    pair = {level_a, level_b}

    # L0 / L1 shop-floor assets communicating directly with Internet/External.
    if pair & OT_SHOPFLOOR_LEVELS and "external" in pair:
        return {"code": "ot_external_communication", "severity": "critical"}

    # L2 talking directly to External/Internet without DMZ mediation.
    if "L2" in pair and "external" in pair:
        return {"code": "it_ot_dmz_bypass", "severity": "critical"}

    # Direct OT (L0/L1/L2) <-> Enterprise IT (L4) bypassing L3.5 DMZ.
    if (pair & OT_LEVELS) and "L4" in pair:
        return {"code": "it_ot_dmz_bypass", "severity": "critical"}

    # Direct L0/L1 <-> L3 Operations skipping Supervisory L2.
    if (pair & OT_SHOPFLOOR_LEVELS) and "L3" in pair:
        return {"code": "it_ot_layer_skip", "severity": "high"}

    return None


def check_purdue_blueprint(
    devices: list[dict],
    segments: list[dict],
    segment_links: list[dict],
) -> list[dict]:
    """Deterministic blueprint/architecture checks for IEC 62443 Purdue conduits."""
    segs = _index_segments(segments)
    seg_by_id = {s["id"]: s for s in segs if s["id"]}
    dev_by_ip = {str(d.get("IP") or ""): d for d in (devices or []) if d.get("IP")}

    findings: list[dict] = []
    # Check segment_links (discovered/classified links between devices in different segments)
    for lk in segment_links or []:
        a = str(lk.get("a") or "")
        b = str(lk.get("b") or "")
        decision = lk.get("decision") or ""
        za = resolve_ip_zone(a, devices, segments, segs, dev_by_ip)
        zb = resolve_ip_zone(b, devices, segments, segs, dev_by_ip)
        verdict = classify_conduit_pair(za["level"], zb["level"])
        if not verdict:
            continue
        # Even if marked 'allowed', bypassing L3.5 DMZ directly is an architecture error
        code = "purdue_dmz_bypass" if verdict["code"] == "it_ot_dmz_bypass" else "purdue_layer_skip"
        sev = "error" if code == "purdue_dmz_bypass" else "warning"
        findings.append({
            "code": code,
            "severity": sev,
            "subject": {"conduit": f"{a}<->{b}"},
            "params": {
                "a": a,
                "b": b,
                "level_a": za["level"],
                "level_b": zb["level"],
                "segment_a": za["segment_name"] or a,
                "segment_b": zb["segment_name"] or b,
                "decision": decision or "unverified",
            },
            "proposal": None,
        })

    # Check direct subnet overlap between segments at different Purdue levels
    for i, sa in enumerate(segs):
        if not sa["purdue_level"]:
            continue
        for sb in segs[i + 1:]:
            if not sb["purdue_level"] or sa["purdue_level"] == sb["purdue_level"]:
                continue
            for na in sa["subnets"]:
                for nb in sb["subnets"]:
                    if na.version == nb.version and na.overlaps(nb):
                        findings.append({
                            "code": "purdue_subnet_overlap",
                            "severity": "error",
                            "subject": {"segment": sa["id"] or sa["name"]},
                            "params": {
                                "segment_a": sa["name"],
                                "segment_b": sb["name"],
                                "level_a": sa["purdue_level"],
                                "level_b": sb["purdue_level"],
                                "subnet_a": str(na),
                                "subnet_b": str(nb),
                            },
                            "proposal": None,
                        })
    _ = seg_by_id
    return findings


def check_flow_record_violation(
    src_ip: str,
    dst_ip: str,
    action: Optional[str],
    devices: list[dict],
    segments: list[dict],
    _indexed_segments: Optional[list[dict]] = None,
    _dev_by_ip: Optional[dict[str, dict]] = None,
) -> Optional[dict]:
    """Return an IT/OT violation dict if a non-denied flow/log crosses zones."""
    if not src_ip or not dst_ip:
        return None
    if (action or "").strip().lower() in _SECURITY_STOP_ACTIONS:
        return None
    segs = _indexed_segments if _indexed_segments is not None else _index_segments(segments)
    dev_map = _dev_by_ip if _dev_by_ip is not None else {
        str(d.get("IP") or ""): d for d in (devices or []) if d.get("IP")
    }
    z_src = resolve_ip_zone(src_ip, devices, segments, segs, dev_map)
    z_dst = resolve_ip_zone(dst_ip, devices, segments, segs, dev_map)
    verdict = classify_conduit_pair(z_src["level"], z_dst["level"])
    if not verdict:
        return None
    return {
        "code": verdict["code"],
        "severity": verdict["severity"],
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_level": z_src["level"],
        "dst_level": z_dst["level"],
        "src_segment": z_src["segment_name"],
        "dst_segment": z_dst["segment_name"],
        "action": (action or "accept").lower(),
    }


def check_policy_violations(
    policy_rows: list[dict],
    devices: list[dict],
    segments: list[dict],
) -> list[dict]:
    """Check collected firewall accept policies (from ``firewall_traffic``) for IT/OT breaches."""
    segs = _index_segments(segments)
    dev_map = {str(d.get("IP") or ""): d for d in (devices or []) if d.get("IP")}
    findings: list[dict] = []

    for row in policy_rows or []:
        action = (row.get("action") or "").strip().lower()
        status = (row.get("status") or "enable").strip().lower()
        if action != "accept" or status == "disable":
            continue

        srcs = _split_addrs(row.get("srcaddr_ips")) or _split_addrs(row.get("srcaddr"))
        dsts = _split_addrs(row.get("dstaddr_ips")) or _split_addrs(row.get("dstaddr"))
        # Recognize wildcard address names like "all" / "any" as external when paired with OT
        src_zones = [
            {"level": "external", "segment_id": "", "segment_name": s, "source": "external"}
            if s.lower() in ("all", "any", "internet", "0.0.0.0/0")
            else resolve_target_zone(s, devices, segments, segs, dev_map)
            for s in srcs
        ]
        dst_zones = [
            {"level": "external", "segment_id": "", "segment_name": d, "source": "external"}
            if d.lower() in ("all", "any", "internet", "0.0.0.0/0")
            else resolve_target_zone(d, devices, segments, segs, dev_map)
            for d in dsts
        ]

        seen_pairs: set[tuple[str, str, str]] = set()
        for sz in src_zones:
            if not sz["level"]:
                continue
            for dz in dst_zones:
                if not dz["level"]:
                    continue
                verdict = classify_conduit_pair(sz["level"], dz["level"])
                if not verdict:
                    continue
                sig = (verdict["code"], sz["level"], dz["level"])
                if sig in seen_pairs:
                    continue
                seen_pairs.add(sig)
                findings.append({
                    "code": verdict["code"],
                    "severity": verdict["severity"],
                    "source": "firewall_policy",
                    "device": row.get("device") or row.get("device_ip") or "",
                    "device_ip": row.get("device_ip") or "",
                    "policy_id": row.get("policyid"),
                    "policy_name": row.get("name") or "",
                    "src_level": sz["level"],
                    "dst_level": dz["level"],
                    "src_segment": sz["segment_name"] or (srcs[0] if srcs else ""),
                    "dst_segment": dz["segment_name"] or (dsts[0] if dsts else ""),
                    "service": row.get("service") or "",
                    "bytes": row.get("bytes") or 0,
                    "hit_count": row.get("hit_count") or 0,
                })
    return findings


def scan_recent_syslog_violations(
    org: str,
    devices: list[dict],
    segments: list[dict],
    lookback_s: int = 86400,
    limit: int = 500,
) -> list[dict]:
    """Scan recent normalized traffic events in observability DB for IT/OT breaches."""
    segs = _index_segments(segments)
    dev_map = {str(d.get("IP") or ""): d for d in (devices or []) if d.get("IP")}
    since = int(time.time()) - max(60, int(lookback_s))
    conn = db.get_observability_connection()
    rows = conn.execute(
        """SELECT ts, device_ip, src_ip, dst_ip, dst_port, protocol, attrs_json
           FROM events
           WHERE tenant = ? AND ts >= ? AND src_ip IS NOT NULL AND dst_ip IS NOT NULL
             AND event_type IN ('log.event', 'log.security')
           ORDER BY ts DESC LIMIT ?""",
        (org, since, max(1, min(2000, int(limit)))),
    ).fetchall()

    out: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for r in rows:
        try:
            attrs = json.loads(r["attrs_json"] or "{}")
        except ValueError:
            attrs = {}
        action = attrs.get("action")
        v = check_flow_record_violation(
            r["src_ip"], r["dst_ip"], action, devices, segments, segs, dev_map,
        )
        if not v:
            continue
        key = (v["code"], v["src_ip"], v["dst_ip"])
        if key in seen:
            continue
        seen.add(key)
        v["ts"] = r["ts"]
        v["device_ip"] = r["device_ip"] or ""
        v["dst_port"] = r["dst_port"]
        v["protocol"] = r["protocol"] or ""
        v["source"] = "syslog"
        out.append(v)
    return out


def notify_it_ot_violation(
    tenant: str,
    device_ip: str,
    violation: dict,
) -> None:
    """Persist an observability event and dispatch an immediate alert for an IT/OT breach."""
    if not tenant:
        return
    now = int(time.time())
    code = violation.get("code") or "it_ot_dmz_bypass"
    sev_str = violation.get("severity") or "critical"
    src_ip = violation.get("src_ip") or ""
    dst_ip = violation.get("dst_ip") or ""
    src_lv = violation.get("src_level") or "?"
    dst_lv = violation.get("dst_level") or "?"

    dedup = f"ot-itot:{tenant}:{code}:{src_ip}:{dst_ip}"
    try:
        db.enqueue_write(
            """INSERT INTO events
                   (ts, ingested_ts, tenant, source, source_id, event_type, entity_type,
                    entity_id, severity, device_ip, src_ip, dst_ip, attrs_json, dedup_key)
               VALUES (?, ?, ?, 'purdue', NULL, 'ot.it_ot_violation', 'device', ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(dedup_key) DO NOTHING""",
            (
                now,
                now,
                tenant,
                device_ip or src_ip or "purdue",
                2 if sev_str == "critical" else 3,
                device_ip or src_ip,
                src_ip or None,
                dst_ip or None,
                json.dumps(violation, ensure_ascii=False),
                f"{dedup}:{now // 300}",
            ),
        )
    except Exception:
        logger.exception("Errore registrazione evento violazione IT/OT su %s", src_ip)

    try:
        from services import notifications
        title = (
            f"[{tenant}] Violazione IT/OT ({code}): "
            f"{src_ip} ({src_lv}) -> {dst_ip} ({dst_lv})"
        )
        notifications.emit(
            kind="siem.alert",
            device_ip=device_ip or src_ip,
            severity=sev_str,
            title=title,
            ctx={
                "category": "it_ot_violation",
                "tenant": tenant,
                "code": code,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_level": src_lv,
                "dst_level": dst_lv,
            },
            dedup_key=dedup,
        )
    except Exception:
        logger.exception("Errore invio notifica violazione IT/OT per %s", tenant)


_SYSLOG_CTX_CACHE: dict[str, tuple[tuple[int, int], list[dict], list[dict], list[dict], dict[str, dict], bool]] = {}


def _tenant_syslog_ctx(tenant: str):
    from services import inventory_manager, segment_manager

    sig = (inventory_manager.inventory_version(), segment_manager.segment_version())
    cached = _SYSLOG_CTX_CACHE.get(tenant)
    if cached and cached[0] == sig:
        return cached
    devices = [d for d in inventory_manager.get_all_devices() if d.get("Group") == tenant]
    segs = segment_manager.list_segments(tenant).get("segments") or []
    has_rules = any(d.get("Purdue Level") for d in devices) or any(s.get("purdue_level") for s in segs)
    indexed = _index_segments(segs) if has_rules else []
    dev_map = {str(d.get("IP") or ""): d for d in devices if d.get("IP")} if has_rules else {}
    entry = (sig, devices, segs, indexed, dev_map, has_rules)
    _SYSLOG_CTX_CACHE[tenant] = entry
    return entry


def inspect_syslog_it_ot(
    exporter_ip: str,
    tenant: str,
    fields: dict,
    action: Optional[str] = None,
) -> Optional[dict]:
    """Inspect a parsed syslog record against tenant Purdue zones; emit alert if violated."""
    src_ip = fields.get("src_ip")
    dst_ip = fields.get("dst_ip")
    if not tenant or not src_ip or not dst_ip:
        return None
    _sig, devices, segs, indexed, dev_map, has_rules = _tenant_syslog_ctx(tenant)
    if not has_rules:
        return None
    eff_action = action if action is not None else fields.get("action")
    violation = check_flow_record_violation(
        src_ip, dst_ip, eff_action, devices, segs,
        _indexed_segments=indexed, _dev_by_ip=dev_map,
    )
    if violation:
        notify_it_ot_violation(tenant, exporter_ip, violation)
    return violation


# ---------------------------------------------------------------------------
# Rogue Device Detection on Static OT VLANs
# ---------------------------------------------------------------------------

def is_ot_protected_vlan(
    switch_ip: str,
    vlan: str,
    tenant: str,
    devices: Optional[list[dict]] = None,
    segments: Optional[list[dict]] = None,
) -> tuple[bool, str]:
    """Return ``(protected, reason)`` for a switch + VLAN within a tenant.

    A port/VLAN sighting is monitored as static OT production when either:
    - ``vlan`` is declared in any segment's ``ot_vlans`` for ``tenant``, or
    - the switch belongs to Purdue level ``L0``, ``L1``, or ``L2`` (explicitly or via segment).
    """
    from services import inventory_manager, segment_manager

    if devices is None:
        all_devs = inventory_manager.get_all_devices()
        devices = [d for d in all_devs if not tenant or d.get("Group") == tenant]
    if segments is None and tenant:
        segments = segment_manager.list_segments(tenant).get("segments") or []

    v_clean = str(vlan or "").strip()
    for seg in segments or []:
        seg_vlans = {str(v).strip() for v in (seg.get("ot_vlans") or []) if str(v).strip()}
        if v_clean and v_clean in seg_vlans:
            return True, f"vlan_ot:{seg.get('name') or v_clean}"

    zone = resolve_ip_zone(switch_ip, devices, segments or [])
    if zone["level"] in OT_LEVELS:
        return True, f"purdue_switch:{zone['level']}"

    return False, ""


def handle_new_mac_sightings(
    switch_ip: str,
    switch_name: str,
    tenant: str,
    new_candidates: list[dict],
    prior_baseline_vlans: set[str],
) -> list[dict]:
    """Evaluate newly discovered non-uplink MACs on a switch for Rogue OT alerts.

    Only VLANs that already had an established baseline (prior sightings on that
    ``switch_ip`` and ``vlan``) fire immediate rogue alarms, so the very first
    scan of an OT switch populates the known baseline without false positives.
    """
    if not new_candidates or not switch_ip:
        return []

    from services import inventory_manager, segment_manager

    all_devs = inventory_manager.get_all_devices()
    devices = [d for d in all_devs if not tenant or d.get("Group") == tenant]
    if not tenant:
        match_dev = next((d for d in all_devs if d.get("IP") == switch_ip), None)
        tenant = (match_dev or {}).get("Group") or ""
    segments = segment_manager.list_segments(tenant).get("segments") or [] if tenant else []

    alerts: list[dict] = []
    now = int(time.time())
    for item in new_candidates:
        vlan = str(item.get("vlan") or "").strip()
        if vlan not in prior_baseline_vlans:
            continue
        protected, reason = is_ot_protected_vlan(
            switch_ip, vlan, tenant, devices=devices, segments=segments,
        )
        if not protected:
            continue
        mac = item.get("mac") or ""
        iface = item.get("interface") or ""
        oui = item.get("oui_vendor") or ""
        alert = {
            "switch_ip": switch_ip,
            "switch_name": switch_name or switch_ip,
            "tenant": tenant,
            "mac": mac,
            "oui_vendor": oui,
            "vlan": vlan,
            "interface": iface,
            "reason": reason,
            "ts": now,
        }
        alerts.append(alert)

        dedup = f"ot-rogue:{tenant}:{switch_ip}:{vlan}:{iface}:{mac}"
        try:
            db.enqueue_write(
                """INSERT INTO events
                       (ts, ingested_ts, tenant, source, source_id, event_type, entity_type,
                        entity_id, severity, device_ip, interface, attrs_json, dedup_key)
                   VALUES (?, ?, ?, 'mac_collector', NULL, 'ot.rogue_device', 'device',
                           ?, 2, ?, ?, ?, ?)
                   ON CONFLICT(dedup_key) DO NOTHING""",
                (
                    now,
                    now,
                    tenant or "_global_",
                    switch_ip,
                    switch_ip,
                    iface or None,
                    json.dumps(alert, ensure_ascii=False),
                    f"{dedup}:{uuid.uuid4().hex[:8]}",
                ),
            )
        except Exception:
            logger.exception("Errore scrittura evento rogue OT per %s", mac)

        try:
            from services import notifications
            sw_label = switch_name or switch_ip
            vlan_label = f"VLAN {vlan}" if vlan else "VLAN N/A"
            oui_label = f" ({oui})" if oui else ""
            title = (
                f"[{tenant or 'OT'}] Dispositivo rogue su rete OT statica: "
                f"{mac}{oui_label} su {sw_label} {iface or ''} ({vlan_label})"
            ).strip()
            notifications.emit(
                kind="siem.alert",
                device_ip=switch_ip,
                severity="critical",
                title=title,
                ctx={
                    "category": "ot_rogue_device",
                    "tenant": tenant,
                    "switch_ip": switch_ip,
                    "switch_name": sw_label,
                    "mac": mac,
                    "oui_vendor": oui,
                    "vlan": vlan,
                    "interface": iface,
                    "reason": reason,
                },
                dedup_key=dedup,
            )
        except Exception:
            logger.exception("Errore notifica rogue OT per %s su %s", mac, switch_ip)

    return alerts


def list_rogue_ot_events(org: Optional[str] = None, limit: int = 100) -> list[dict]:
    """Return recent ``ot.rogue_device`` alerts from the observability DB."""
    conn = db.get_observability_connection()
    if org:
        rows = conn.execute(
            """SELECT ts, tenant, device_ip, interface, attrs_json
               FROM events
               WHERE event_type = 'ot.rogue_device' AND tenant = ?
               ORDER BY ts DESC LIMIT ?""",
            (org, max(1, min(500, int(limit)))),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT ts, tenant, device_ip, interface, attrs_json
               FROM events
               WHERE event_type = 'ot.rogue_device'
               ORDER BY ts DESC LIMIT ?""",
            (max(1, min(500, int(limit))),),
        ).fetchall()

    out = []
    for r in rows:
        try:
            attrs = json.loads(r["attrs_json"] or "{}")
        except ValueError:
            attrs = {}
        out.append({
            "ts": r["ts"],
            "tenant": r["tenant"],
            "switch_ip": attrs.get("switch_ip") or r["device_ip"] or "",
            "switch_name": attrs.get("switch_name") or r["device_ip"] or "",
            "mac": attrs.get("mac") or "",
            "oui_vendor": attrs.get("oui_vendor") or "",
            "vlan": attrs.get("vlan") or "",
            "interface": attrs.get("interface") or r["interface"] or "",
            "reason": attrs.get("reason") or "",
        })
    return out


# ---------------------------------------------------------------------------
# Passive OT exposure detectors (MAC/ARP history + firewall backups)
# ---------------------------------------------------------------------------

_IT_LEVELS = frozenset(("L3.5", "L4"))
_RECENT_DAYS = 7
# First-hop redundancy virtual MACs (VRRP v4/v6, HSRP v1/v2, GLBP): one MAC
# answering for gateway IPs in every VLAN it serves.
_VIRTUAL_MAC_PREFIXES = ("00:00:5e:00:01:", "00:00:5e:00:02:", "00:00:0c:07:ac:",
                         "00:00:0c:9f:f", "00:07:b4:00:")
_FORTI_ACCEPT_RE = re.compile(r"^\s*set action accept\b", re.M)


def _recent_cutoff() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=_RECENT_DAYS)).isoformat(timespec="seconds")


def _vlan_key(v: str) -> int:
    return int(v) if v.isdigit() else 0


def _infra_macs(dev_ips: list[str]) -> set:
    """MACs owned by inventoried devices: switch interface MACs plus the ARP
    bindings of every inventory IP (the union of ``own_macs`` over them, in
    one query). A FortiGate answers for all its VLAN subinterfaces with one
    MAC, which would otherwise look dual-homed."""
    from collectors import mac_history
    out = set(mac_history.get_switch_if_macs())
    with mac_history._connect() as c:
        out |= {r["mac"] for r in c.execute(
            "SELECT DISTINCT mac FROM arp_entries WHERE ip IN (SELECT value FROM json_each(?))",
            (json.dumps(dev_ips),))}
    return out


def detect_dual_homed(org: str, devices: list[dict], segments: list[dict]) -> list[dict]:
    """Hosts bridging IT (L3.5/L4) and OT (L0-L2): one MAC with recent ARP IPs
    on both sides, or seen on access ports in an OT-protected and a non-OT
    VLAN; plus a low-confidence sibling-NIC heuristic (adjacent MACs)."""
    from collectors import industrial_oui, mac_history
    mac_history.init_db()
    segs = _index_segments(segments)
    dev_by_ip = {str(d.get("IP") or ""): d for d in devices if d.get("IP")}
    ot_vlans = {v for s in segs for v in s["ot_vlans"]}
    cutoff = _recent_cutoff()
    with mac_history._connect() as c:
        arp = c.execute(
            "SELECT mac, ip, vlan, last_seen FROM arp_entries "
            "WHERE tenant = ? AND last_seen >= ?", (org, cutoff)).fetchall()
        sights = c.execute(
            "SELECT mac, vlan, switch_ip, switch_name, interface, last_seen FROM mac_sightings "
            "WHERE tenant = ? AND is_uplink = 0 AND last_seen >= ?", (org, cutoff)).fetchall()
    skip = _infra_macs(list(dev_by_ip))

    zones: dict[str, dict] = {}
    by_mac: dict[str, dict] = {}

    def entry(mac: str) -> dict:
        return by_mac.setdefault(mac, {"ips": {}, "vlans": set(), "port_vlans": set(),
                                       "ports": [], "last_seen": ""})

    for r in arp:
        mac, ip = r["mac"], r["ip"]
        if mac in skip or mac.startswith(_VIRTUAL_MAC_PREFIXES):
            continue
        if ip not in zones:
            zones[ip] = resolve_ip_zone(ip, devices, segments, segs, dev_by_ip)
        e = entry(mac)
        e["ips"][ip] = {"ip": ip, "level": zones[ip]["level"], "segment": zones[ip]["segment_name"]}
        if r["vlan"]:
            e["vlans"].add(str(r["vlan"]))
        e["last_seen"] = max(e["last_seen"], r["last_seen"] or "")
    for r in sights:
        mac = r["mac"]
        if mac in skip or mac.startswith(_VIRTUAL_MAC_PREFIXES):
            continue
        e = entry(mac)
        vlan = str(r["vlan"] or "")
        if vlan:
            e["vlans"].add(vlan)
            e["port_vlans"].add(vlan)
        e["ports"].append({"switch": r["switch_name"] or r["switch_ip"], "switch_ip": r["switch_ip"],
                           "interface": r["interface"] or "", "vlan": vlan})
        e["last_seen"] = max(e["last_seen"], r["last_seen"] or "")

    findings: list[dict] = []
    side: dict[str, str] = {}
    for mac, e in by_mac.items():
        levels = {i["level"] for i in e["ips"].values()}
        pv = e["port_vlans"]
        if (levels & OT_LEVELS and levels & _IT_LEVELS) or (pv & ot_vlans and pv - ot_vlans):
            findings.append({
                "code": "ot_dual_homed", "signal": "same_mac", "severity": "high",
                "macs": [mac], "ips": sorted(e["ips"].values(), key=lambda x: x["ip"]),
                "vlans": sorted(e["vlans"], key=_vlan_key),
                "ports": e["ports"][:5], "last_seen": e["last_seen"],
            })
        elif levels & OT_LEVELS:
            side[mac] = "ot"
        elif levels & _IT_LEVELS:
            side[mac] = "it"

    # ponytail: sibling-NIC is a guess on adjacent MAC serials. Without
    # persisted hostnames (DHCP leases are only queried live) a two-NIC host
    # whose MACs are unrelated is undetectable; persisting leases closes it.
    it_by_nic = {(m[:8], int(m[9:].replace(":", ""), 16)): m for m, s in side.items() if s == "it"}
    for mac, s in side.items():
        # Industrial vendors number PLC/IO MACs sequentially: adjacency means nothing.
        if s != "ot" or industrial_oui.is_industrial_oui(mac):
            continue
        nic = int(mac[9:].replace(":", ""), 16)
        for delta in (-2, -1, 1, 2):
            other = it_by_nic.get((mac[:8], nic + delta))
            if not other:
                continue
            a, b = by_mac[mac], by_mac[other]
            findings.append({
                "code": "ot_dual_homed_possible", "signal": "sibling_nic", "severity": "low",
                "macs": [mac, other],
                "ips": sorted([*a["ips"].values(), *b["ips"].values()], key=lambda x: x["ip"]),
                "vlans": sorted(a["vlans"] | b["vlans"], key=_vlan_key),
                "ports": (a["ports"] + b["ports"])[:5],
                "last_seen": max(a["last_seen"], b["last_seen"]),
            })
    return findings


def detect_multi_mac_ports(
    org: str, devices: list[dict], segments: list[dict], threshold: int = 3,
) -> list[dict]:
    """OT access ports learning ``threshold`` or more endpoint MACs: an
    unmanaged switch, hub or bridging host behind a PLC/HMI port. PC + IP
    phone (2) is normal, hence the default of 3."""
    from collectors import mac_history
    mac_history.init_db()
    segs = _index_segments(segments)
    dev_by_ip = {str(d.get("IP") or ""): d for d in devices if d.get("IP")}
    ot_vlans = {v for s in segs for v in s["ot_vlans"]}
    infra = set(mac_history.get_switch_if_macs())
    with mac_history._connect() as c:
        rows = c.execute(
            "SELECT mac, oui_vendor, vlan, switch_ip, switch_name, interface, last_seen "
            "FROM mac_sightings WHERE tenant = ? AND is_uplink = 0 AND last_seen >= ?",
            (org, _recent_cutoff())).fetchall()

    ports: dict[tuple, list] = {}
    for r in rows:
        if r["mac"] not in infra:
            ports.setdefault((r["switch_ip"], r["interface"] or ""), []).append(r)
    sw_ot: dict[str, bool] = {}
    findings: list[dict] = []
    for (sw, iface), prs in ports.items():
        if sw not in sw_ot:
            # Inventory Purdue Level first, then segment membership / subnet.
            sw_ot[sw] = resolve_ip_zone(sw, devices, segments, segs, dev_by_ip)["level"] in OT_LEVELS
        vlans = {str(r["vlan"] or "") for r in prs} - {""}
        if not (sw_ot[sw] or vlans & ot_vlans):
            continue
        macs = {r["mac"]: r["oui_vendor"] or "" for r in prs}
        if len(macs) < threshold:
            continue
        findings.append({
            "code": "ot_multi_mac_port", "severity": "medium",
            "switch_ip": sw, "switch_name": prs[0]["switch_name"] or sw, "interface": iface,
            "count": len(macs),
            "macs": [{"mac": m, "oui_vendor": v} for m, v in sorted(macs.items())[:5]],
            "vlans": sorted(vlans, key=_vlan_key),
            "last_seen": max(r["last_seen"] or "" for r in prs),
        })
    return findings


@functools.lru_cache(maxsize=16)
def _parse_fw_backup(path: str, mtime: float, kind: str) -> Any:
    """Parsed policy environment of one backup. ``mtime`` is only the cache
    key: a newer backup of the same device is parsed again."""
    from ai import config_analyzer
    from services.policy_test.fortios import parse_fortios_config
    from services.policy_test.panos import parse_panos_config
    with open(path, encoding="utf-8", errors="ignore") as fh:
        content = "\n".join(config_analyzer.running_config(fh.read()))
    return parse_fortios_config(content) if kind == "fortios" else parse_panos_config(content)


def detect_wan_exposure(
    org: str, devices: list[dict], segments: list[dict],
) -> tuple[list[dict], int]:
    """Firewall DNAT (FortiGate VIP in an accept policy / PAN-OS NAT rule)
    publishing an L0-L2 asset. Returns ``(findings, firewalls_parsed)`` so an
    empty list can be told apart from "no firewall backup evaluated"."""
    from ai import config_analyzer
    from services.policy_test.model import int_to_ip, mask_to_prefix_len
    segs = _index_segments(segments)
    dev_by_ip = {str(d.get("IP") or ""): d for d in devices if d.get("IP")}

    def ot_zone(ip_text: str) -> Optional[dict]:
        z = resolve_ip_zone(ip_text, devices, segments, segs, dev_by_ip)
        return z if z["level"] in OT_LEVELS else None

    def cube_external(cube) -> bool:
        plen = mask_to_prefix_len(cube.mask)
        text = int_to_ip(cube.value) + (f"/{plen}" if plen is not None else "")
        return resolve_target_zone(text, devices, segments, segs, dev_by_ip)["level"] == "external"

    findings: list[dict] = []
    checked = 0
    for d in devices:
        kind = config_analyzer.detect_config_type("", d)
        if kind not in ("fortios", "panos"):
            continue
        ip = str(d.get("IP") or "")
        path, _ = config_analyzer._find_freshest_backup(ip, org)
        if not path:
            continue
        try:
            env = _parse_fw_backup(path, os.path.getmtime(path), kind)
        except OSError:
            continue
        checked += 1
        base = {"code": "ot_wan_exposure", "device": d.get("Hostname") or ip, "device_ip": ip}
        if kind == "fortios":
            for rule in env.policies:
                # Raw action: a VIP with a mapped range leaves the rule
                # 'unknown' in the parsed model, yet it still accepts.
                if rule.disabled or not _FORTI_ACCEPT_RE.search(rule.raw_text):
                    continue
                src = rule.fields.src_ips
                open_src = any(c.is_any() or cube_external(c) for c in src)
                # ponytail: VIP groups (firewall vipgrp) are not parsed, so a
                # policy reaching OT through a group is not reported.
                for name in env.policy_dst_names.get(rule.id, []):
                    vip = env.vips.get(name)
                    if not vip:
                        continue
                    mapped = str(vip.get("mappedip") or "").split("-")[0].strip()
                    z = ot_zone(mapped)
                    if z:
                        findings.append({
                            **base, "severity": "critical" if open_src else "high",
                            "rule_id": rule.id, "rule_name": rule.name, "nat_name": name,
                            "ext_ip": vip.get("extip") or "", "ext_intf": vip.get("extintf") or "",
                            "mapped_ip": mapped, "level": z["level"], "segment": z["segment_name"],
                        })
        else:
            for nr in env.nat_rules:
                if nr.get("disabled") or not nr.get("dnat"):
                    continue
                mapped = str(nr["dnat"])
                if env.addresses.get(mapped):
                    mapped = int_to_ip(env.addresses[mapped][0].value)
                mapped = mapped.split("/")[0].split("-")[0].strip()
                z = ot_zone(mapped)
                if not z:
                    continue
                srcs = nr.get("source") or []
                dsts = nr.get("destination") or []
                findings.append({
                    **base, "severity": "critical" if (not srcs or "any" in srcs) else "high",
                    "rule_id": nr["name"], "rule_name": nr["name"], "nat_name": nr["name"],
                    "ext_ip": dsts[0] if dsts else "", "ext_intf": ",".join(nr.get("from") or []),
                    "mapped_ip": mapped, "level": z["level"], "segment": z["segment_name"],
                })
    return findings, checked


def ot_security_summary(org: str) -> dict:
    """Consolidated IT/OT conduit violations and rogue OT MAC alerts for a tenant."""
    from services import inventory_manager, segment_manager

    devices = [d for d in inventory_manager.get_all_devices() if d.get("Group") == org]
    seg_data = segment_manager.list_segments(org)
    segments = seg_data.get("segments") or []
    seg_links = seg_data.get("links") or []

    conduit_findings = check_purdue_blueprint(devices, segments, seg_links)
    traffic_findings = scan_recent_syslog_violations(org, devices, segments)
    rogue_events = list_rogue_ot_events(org=org, limit=100)
    wan_findings, wan_checked = detect_wan_exposure(org, devices, segments)

    return {
        "org": org,
        "conduit_violations": conduit_findings,
        "traffic_violations": traffic_findings,
        "rogue_ot_devices": rogue_events,
        "dual_homed_hosts": detect_dual_homed(org, devices, segments),
        "multi_mac_ports": detect_multi_mac_ports(org, devices, segments),
        "wan_exposures": wan_findings,
        "wan_firewalls_checked": wan_checked,
    }
