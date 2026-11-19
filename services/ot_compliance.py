# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""IEC 62443 & NIS2 automatic compliance checks for network status reports.

Evaluates:
1. Active insecure protocols (Telnet, unencrypted HTTP, SNMPv1/v2c, and
   unsegregated cleartext Modbus TCP / S7comm paths).
2. Unused physical switch ports left ``admin up`` (via SNMP interface.state).
3. Remote vendor access / teleassistance segregation (jump hosts, agents,
   L3.5 DMZ, and firewall/flow bypasses into OT levels L0-L2).
4. OT Config / Project Vault coverage and SHA-256 integrity.
"""

import json
import os
import re
import time
from typing import Any

from core import backup_store, db

_OT_VENDORS = frozenset((
    "siemens_scalance", "siemens", "rockwell", "rockwell automation",
    "allen-bradley", "allen bradley", "schneider", "schneider electric",  # check-private-data: ok
    "beckhoff", "omron", "moxa", "hirschmann", "westermo",
    "phoenix_contact", "phoenix contact", "phoenixcontact",
    "cisco_ie", "wago", "fanuc", "abb", "honeywell", "emerson",
    "yokogawa", "ge", "mitsubishi",
))

_SWITCH_VENDORS = frozenset((
    "siemens_scalance", "hirschmann", "moxa", "westermo", "phoenix_contact",
    "cisco_ie", "cisco_ios", "aruba", "hp", "hpe", "juniper", "netgear",
    "tplink", "dell", "extreme", "brocade", "alcatel", "huawei",
    "mikrotik", "ubiquiti",
))

_NON_SWITCH_CATS = frozenset((
    "firewall", "router", "ap", "wlc", "plc", "rtu", "hmi", "scada",
    "pc", "phone", "camera", "printer", "server", "endpoint", "ups",
))

_VIRTUAL_IFACE_RE = re.compile(
    r"^(?:vlan|vl\d|lo\d*$|loopback|null|tunnel|tu\d|port-channel|po\d|ae\d|"
    r"bond\d|br\d*$|bvi|irb|nve|vxlan|mgmt|fxp|em\d|me\d|ucse|virtual|dialer|"
    r"stack|cpu|internal|console|bme|jsrv|lsi|pim|pip|tap|vtep|vti|wan\d)",
    re.I,
)

# Config line patterns for insecure management protocols.
_TELNET_LINE_RE = re.compile(
    r"^(?!\s*no\b).*(?:"
    r"\btransport\s+input\b[^\n]*\btelnet\b"
    r"|\bip\s+telnet\s+server\b"
    r"|\btelnet[- ]server\s+(?:enable|start)\b"
    r"|\btelnetd?\s+enable\b"
    r"|\ballowaccess\b[^\n]*\btelnet\b"
    r")",
    re.I | re.M,
)

_HTTP_LINE_RE = re.compile(
    r"^(?!\s*no\b).*(?:"
    r"^\s*ip\s+http\s+server\b"
    r"|\b(?:http[- ]server|management\s+http|web\s+http)\s+enable\b"
    r"|\ballowaccess\b[^\n]*\bhttp\b"
    r")",
    re.I | re.M,
)

_SNMP_LEGACY_LINE_RE = re.compile(
    r"^(?!\s*no\b).*(?:"
    r"^\s*snmp-server\s+community\b"
    r"|\bconfig\s+system\s+snmp\s+community\b"
    r"|\bsnmp[- ]server\s+(?:version\s+)?(?:v?1|v?2c)\b"
    r"|\bsnmp\s+(?:v1|v2c)\s+enable\b"
    r")",
    re.I | re.M,
)

_REMOTE_ACCESS_PORTS = frozenset((22, 23, 3389, 5900, 5901, 5938, 7070, 4899, 8291))
_REMOTE_ACCESS_PROTOS = frozenset(("ssh", "telnet", "rdp", "vnc", "teamviewer", "anydesk"))
_STOP_ACTIONS = frozenset((
    "deny", "denied", "blocked", "block", "drop", "dropped",
    "reset", "reset-both", "reset-client", "reset-server",
    "clear_session", "redirect", "sinkhole",
))


def _label(device: dict) -> str:
    return str(device.get("Hostname") or device.get("IP") or "")


def _parse_transports(device: dict) -> set[str]:
    raw = device.get("Transports") or ""
    if not raw:
        return set()
    if isinstance(raw, dict):
        return {str(t).strip().lower() for t in raw.keys() if str(t).strip()}
    if isinstance(raw, (list, tuple, set)):
        return {str(t).strip().lower() for t in raw if str(t).strip()}
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return {str(t).strip().lower() for t in parsed.keys() if str(t).strip()}
                if isinstance(parsed, list):
                    return {str(t).strip().lower() for t in parsed if str(t).strip()}
            except (ValueError, TypeError):
                pass
        return {part.strip().lower() for part in text.split(",") if part.strip()}
    return set()


def _latest_config_text(device: dict) -> str:
    from services.config_drift import history
    versions = history.list_versions(device)
    if versions:
        text = history.read_version(device, versions[0].get("seen_at", ""))
        if text:
            return text
    ip = str(device.get("IP") or "").strip()
    if not ip:
        return ""
    tenant_dir = os.path.join(
        backup_store.BACKUP_FOLDER,
        backup_store.sanitize_filename(str(device.get("Group") or "") or "unknown"),
    )
    if not os.path.isdir(tenant_dir):
        return ""
    for root, dirs, files in os.walk(tenant_dir):
        dirs[:] = [d for d in dirs if d not in (".history", ".ot-vault")]
        for fn in files:
            if fn.endswith(f"-{ip}.txt") or fn.endswith(f"_{ip}.txt") or fn == f"{ip}.txt":
                try:
                    with open(os.path.join(root, fn), "r", encoding="utf-8", errors="ignore") as fh:
                        return fh.read()
                except OSError:
                    return ""
    return ""


def _is_ot_device(device: dict, segs: list) -> bool:
    from services import purdue_model
    lvl = str(device.get("Purdue Level") or "").strip().upper()
    if lvl in purdue_model.OT_LEVELS:
        return True
    vendor = str(device.get("Vendor") or "").strip().lower()
    if vendor in _OT_VENDORS:
        return True
    ip = str(device.get("IP") or "").strip()
    if ip and segs:
        z = purdue_model.resolve_ip_zone(ip, [device], segs)
        if z.get("level") in purdue_model.OT_LEVELS:
            return True
    return False


def _is_physical_interface(name: str) -> bool:
    if not name:
        return False
    return _VIRTUAL_IFACE_RE.match(name.strip()) is None


def _is_switch_device(device: dict, categories: dict, tenant: str) -> bool:
    from services import inventory_manager
    ip = str(device.get("IP") or "")
    meta = categories.get(inventory_manager._akey(tenant, ip), {})
    cat = str(meta.get("category") or "").strip().lower()
    if cat == "switch":
        return True
    if cat in _NON_SWITCH_CATS:
        return False
    vendor = str(device.get("Vendor") or "").strip().lower()
    if vendor in _SWITCH_VENDORS:
        return True
    lvl = str(device.get("Purdue Level") or "").strip().upper()
    if lvl in ("L0", "L1", "L2", "L3") and vendor not in ("fortinet", "fortigate", "paloalto", "panos"):
        return True
    return False


def _attrs_dict(raw: Any) -> dict:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


def evaluate_insecure_protocols(tenant: str, devices: list, period_days: int) -> dict:
    """Detect Telnet, unencrypted HTTP, SNMPv1/v2c, and unsegregated Modbus/S7 flows."""
    from services import purdue_model, segment_manager

    if not devices:
        return {
            "available": False,
            "metrics": {
                "devices": 0, "devices_with_findings": 0,
                "telnet_devices": 0, "http_devices": 0,
                "snmp_v1_v2c_devices": 0, "unsegregated_ot_flows": 0,
                "total_findings": 0,
            },
            "rows": [],
        }

    telnet_ips: set[str] = set()
    http_ips: set[str] = set()
    snmp_ips: set[str] = set()
    flagged_ips: set[str] = set()
    rows: list[dict] = []

    for d in devices:
        ip = str(d.get("IP") or "")
        name = _label(d)
        transports = _parse_transports(d)
        cfg = _latest_config_text(d)

        if "telnet" in transports or (cfg and _TELNET_LINE_RE.search(cfg)):
            telnet_ips.add(ip)
            flagged_ips.add(ip)
            src = "transport+config" if ("telnet" in transports and cfg and _TELNET_LINE_RE.search(cfg)) else (
                "inventory" if "telnet" in transports else "config"
            )
            rows.append({
                "device": name, "ip": ip, "protocol": "Telnet",
                "detail": "Cleartext CLI management (Telnet) active",
                "source": src,
            })

        if cfg and _HTTP_LINE_RE.search(cfg):
            http_ips.add(ip)
            flagged_ips.add(ip)
            rows.append({
                "device": name, "ip": ip, "protocol": "HTTP",
                "detail": "Unencrypted HTTP management interface enabled",
                "source": "config",
            })

        has_inv_snmp = bool(str(d.get("SNMP Community") or "").strip()) and not bool(d.get("SNMP Disabled"))
        has_cfg_snmp = bool(cfg and _SNMP_LEGACY_LINE_RE.search(cfg))
        if has_inv_snmp or has_cfg_snmp:
            snmp_ips.add(ip)
            flagged_ips.add(ip)
            rows.append({
                "device": name, "ip": ip, "protocol": "SNMPv1/v2c",
                "detail": "Legacy plaintext SNMP community configured",
                "source": "inventory+config" if (has_inv_snmp and has_cfg_snmp) else (
                    "inventory" if has_inv_snmp else "config"
                ),
            })

    # Unsegregated cleartext Modbus TCP (502) / S7comm (102) in observability events.
    segs = segment_manager.list_segments(tenant).get("segments", [])
    indexed_segs = purdue_model._index_segments(segs)
    dev_by_ip = {str(d.get("IP") or ""): d for d in devices if d.get("IP")}
    since = int(time.time()) - max(1, int(period_days or 30)) * 86400

    conn = db.get_observability_connection()
    try:
        ev_rows = conn.execute(
            "SELECT src_ip, dst_ip, dst_port, protocol, device_ip, attrs_json "
            "FROM events WHERE tenant = ? AND ts >= ? "
            "AND (dst_port IN (502, 102) OR attrs_json LIKE '%modbus_tcp%' OR attrs_json LIKE '%s7comm%')",
            (tenant, since),
        ).fetchall()
    finally:
        conn.close()

    unseg_seen: set[tuple[str, str, str]] = set()
    for r in ev_rows:
        attrs = _attrs_dict(r["attrs_json"])
        ot_proto = str(attrs.get("ot_protocol") or "").lower()
        dport = r["dst_port"]
        if ot_proto == "modbus_tcp" or dport == 502:
            proto_label = "Modbus TCP"
        elif ot_proto == "s7comm" or dport == 102:
            proto_label = "S7comm"
        else:
            continue

        src_ip = str(r["src_ip"] or "").strip()
        dst_ip = str(r["dst_ip"] or r["device_ip"] or "").strip()
        if not src_ip or not dst_ip:
            continue

        src_z = purdue_model.resolve_ip_zone(src_ip, devices, segs, indexed_segs, dev_by_ip)
        dst_z = purdue_model.resolve_ip_zone(dst_ip, devices, segs, indexed_segs, dev_by_ip)
        violation = purdue_model.classify_conduit_pair(src_z["level"], dst_z["level"])
        same_ot_seg = (
            bool(src_z["segment_id"])
            and src_z["segment_id"] == dst_z["segment_id"]
            and violation is None
        )
        both_ot_cells = (
            src_z["level"] in purdue_model.OT_LEVELS
            and dst_z["level"] in purdue_model.OT_LEVELS
            and bool(src_z["segment_id"] or dst_z["segment_id"])
            and violation is None
        )
        if same_ot_seg or both_ot_cells:
            continue

        key = (src_ip, dst_ip, proto_label)
        if key in unseg_seen:
            continue
        unseg_seen.add(key)
        flagged_ips.add(dst_ip)
        detail = f"Cleartext {proto_label} across unsegregated path ({src_ip} [{src_z['level'] or 'unassigned'}] -> {dst_ip} [{dst_z['level'] or 'unassigned'}])"
        rows.append({
            "device": _label(dev_by_ip[dst_ip]) if dst_ip in dev_by_ip else dst_ip,
            "ip": dst_ip,
            "protocol": proto_label,
            "detail": detail,
            "source": "observability",
        })

    return {
        "available": True,
        "metrics": {
            "devices": len(devices),
            "devices_with_findings": len(flagged_ips),
            "telnet_devices": len(telnet_ips),
            "http_devices": len(http_ips),
            "snmp_v1_v2c_devices": len(snmp_ips),
            "unsegregated_ot_flows": len(unseg_seen),
            "total_findings": len(rows),
        },
        "rows": rows,
    }


def evaluate_unused_ports(tenant: str, devices: list, period_days: int) -> dict:
    """Detect physical switch ports left admin up while operationally down."""
    from services import inventory_manager

    categories = inventory_manager.get_category_assignments()
    switch_by_ip = {
        str(d.get("IP") or ""): d
        for d in devices
        if d.get("IP") and _is_switch_device(d, categories, tenant)
    }
    if not switch_by_ip:
        return {
            "available": False,
            "metrics": {
                "switches_evaluated": 0,
                "physical_ports_checked": 0,
                "unused_admin_up": 0,
                "field_switches_affected": 0,
            },
            "rows": [],
        }

    conn = db.get_observability_connection()
    try:
        state_rows = conn.execute(
            """SELECT e.device_ip, e.interface, e.attrs_json
               FROM events e
               JOIN (SELECT MAX(id) AS mid FROM events
                     WHERE event_type = 'interface.state' AND tenant = ?
                     GROUP BY entity_id) m ON m.mid = e.id""",
            (tenant,),
        ).fetchall()
    finally:
        conn.close()

    checked_switches: set[str] = set()
    affected_switches: set[str] = set()
    physical_ports_checked = 0
    rows: list[dict] = []

    for r in state_rows:
        ip = str(r["device_ip"] or "").strip()
        if ip not in switch_by_ip:
            continue
        iface = str(r["interface"] or "").strip()
        if not _is_physical_interface(iface):
            continue
        attrs = _attrs_dict(r["attrs_json"])
        admin = str(attrs.get("admin_status") or "").strip().lower()
        link = str(attrs.get("link") or "").strip().lower()
        if not admin and not link:
            continue
        checked_switches.add(ip)
        physical_ports_checked += 1
        if admin == "up" and link in ("down", "notpresent", "lowerlayerdown"):
            dev = switch_by_ip[ip]
            affected_switches.add(ip)
            rows.append({
                "device": _label(dev),
                "ip": ip,
                "purdue_level": str(dev.get("Purdue Level") or ""),
                "interface": iface,
                "admin_status": admin,
                "link": link,
            })

    return {
        "available": bool(checked_switches and physical_ports_checked > 0),
        "metrics": {
            "switches_evaluated": len(checked_switches),
            "physical_ports_checked": physical_ports_checked,
            "unused_admin_up": len(rows),
            "field_switches_affected": len(affected_switches),
        },
        "rows": rows,
    }


def evaluate_remote_access(tenant: str, devices: list, period_days: int) -> dict:
    """Verify remote vendor / teleassistance access uses jump hosts or L3.5 DMZ."""
    from services import probe_manager, purdue_model, segment_manager

    seg_data = segment_manager.list_segments(tenant)
    segs = seg_data.get("segments", [])
    dmz_segs = [s for s in segs if str(s.get("purdue_level") or "").upper() == "L3.5"]
    indexed_segs = purdue_model._index_segments(segs)
    probes = {p.get("id"): p for p in probe_manager.list_probes()}

    ot_devs = [d for d in devices if _is_ot_device(d, segs)]
    mediated_ot = 0
    unmediated_ot = 0
    used_jump_probes: set[str] = set()
    rows: list[dict] = []

    for d in ot_devs:
        ip = str(d.get("IP") or "")
        probe_id = str(d.get("Probe") or probe_manager.DEFAULT_PROBE_ID)
        probe = probes.get(probe_id) or {"id": probe_id, "mode": "central"}
        mode = str(probe.get("mode") or "central").lower()
        if mode == "jump":
            used_jump_probes.add(probe_id)
            mediated_ot += 1
            rows.append({
                "device": _label(d), "ip": ip, "probe_mode": "jump",
                "source": "probe",
                "detail": f"Bastion jump-host configured ({probe.get('jump_host') or probe_id})",
            })
        elif mode == "agent":
            mediated_ot += 1
            rows.append({
                "device": _label(d), "ip": ip, "probe_mode": "agent",
                "source": "probe",
                "detail": "Outbound remote agent (no inbound exposure)",
            })
        elif dmz_segs:
            mediated_ot += 1
            rows.append({
                "device": _label(d), "ip": ip, "probe_mode": "central+dmz",
                "source": "segment",
                "detail": "L3.5 IT/OT DMZ segment present in tenant",
            })
        else:
            unmediated_ot += 1
            rows.append({
                "device": _label(d), "ip": ip, "probe_mode": mode or "central",
                "source": "probe",
                "detail": "Direct central reachability to OT asset without jump-host or L3.5 DMZ",
            })

    # Inspect Purdue conduit violations bypassing L3.5 DMZ directly between external/L4 and OT
    bypasses = 0
    for f in purdue_model.check_purdue_blueprint(devices, segs, seg_data.get("links") or []):
        if f.get("code") == "purdue_dmz_bypass":
            params = f.get("params") or {}
            bypasses += 1
            rows.append({
                "device": str(params.get("b") or params.get("a") or ""),
                "ip": str(params.get("b") or params.get("a") or ""),
                "probe_mode": "bypass",
                "source": "conduit",
                "detail": f"Purdue conduit {params.get('a')} ({params.get('level_a')}) <-> {params.get('b')} ({params.get('level_b')}) bypasses L3.5 DMZ",
            })

    # Inspect remote-access protocol traffic from external/L4 straight to OT assets
    dev_by_ip = {str(d.get("IP") or ""): d for d in devices if d.get("IP")}
    since = int(time.time()) - max(1, int(period_days or 30)) * 86400
    conn = db.get_observability_connection()
    try:
        rem_rows = conn.execute(
            "SELECT src_ip, dst_ip, dst_port, protocol, attrs_json FROM events "
            "WHERE tenant = ? AND ts >= ? AND src_ip IS NOT NULL AND dst_ip IS NOT NULL",
            (tenant, since),
        ).fetchall()
    finally:
        conn.close()

    seen_bypasses: set[tuple[str, str, str]] = set()
    for r in rem_rows:
        dport = r["dst_port"]
        proto = str(r["protocol"] or "").strip().lower()
        if (dport not in _REMOTE_ACCESS_PORTS) and (proto not in _REMOTE_ACCESS_PROTOS):
            continue
        attrs = _attrs_dict(r["attrs_json"])
        action = str(attrs.get("action") or "").strip().lower()
        if action in _STOP_ACTIONS:
            continue
        src_ip = str(r["src_ip"] or "").strip()
        dst_ip = str(r["dst_ip"] or "").strip()
        src_z = purdue_model.resolve_ip_zone(src_ip, devices, segs, indexed_segs, dev_by_ip)
        dst_z = purdue_model.resolve_ip_zone(dst_ip, devices, segs, indexed_segs, dev_by_ip)
        if src_z["level"] in ("external", "L4") and dst_z["level"] in purdue_model.OT_LEVELS:
            tag = proto or f"port-{dport}"
            key = (src_ip, dst_ip, tag)
            if key in seen_bypasses:
                continue
            seen_bypasses.add(key)
            bypasses += 1
            rows.append({
                "device": _label(dev_by_ip[dst_ip]) if dst_ip in dev_by_ip else dst_ip,
                "ip": dst_ip,
                "probe_mode": "bypass",
                "source": "observability",
                "detail": f"Direct remote access ({tag}) from {src_z['level']} ({src_ip}) to OT {dst_z['level']} bypassing jump-host/DMZ",
            })

    available = bool(ot_devs or bypasses or used_jump_probes)
    return {
        "available": available,
        "metrics": {
            "ot_devices": len(ot_devs),
            "mediated_ot_devices": mediated_ot,
            "unmediated_ot_devices": unmediated_ot,
            "jump_probes": len(used_jump_probes),
            "dmz_zones": len(dmz_segs),
            "direct_remote_bypasses": bypasses,
        },
        "rows": rows,
    }


def evaluate_ot_vault(tenant: str, devices: list, period_days: int) -> dict:
    """Summarize OT Project Vault coverage and SHA-256 integrity for a tenant."""
    from services import segment_manager

    segs = segment_manager.list_segments(tenant).get("segments", [])
    summary = backup_store.ot_vault_summary(devices, verify=True)
    by_ip = summary["by_ip"]

    ot_devs = [d for d in devices if _is_ot_device(d, segs)]
    ot_missing = [d for d in ot_devs if str(d.get("IP") or "") not in by_ip]

    rows: list[dict] = []
    seen_ips: set[str] = set()
    for d in devices:
        ip = str(d.get("IP") or "")
        info = by_ip.get(ip)
        if info:
            seen_ips.add(ip)
            rows.append({
                "device": _label(d),
                "ip": ip,
                "artifacts": info["count"],
                "integrity_status": info["integrity_status"],
                "last_artifact_at": info["latest_uploaded_at"],
            })
    for d in ot_missing:
        ip = str(d.get("IP") or "")
        if ip in seen_ips:
            continue
        rows.append({
            "device": _label(d),
            "ip": ip,
            "artifacts": 0,
            "integrity_status": "missing",
            "last_artifact_at": "",
        })

    return {
        "available": bool(ot_devs or summary["total_artifacts"] > 0),
        "metrics": {
            "ot_devices": len(ot_devs),
            "devices_with_artifacts": summary["devices_with_artifacts"],
            "ot_without_artifacts": len(ot_missing),
            "total_artifacts": summary["total_artifacts"],
            "integrity_failures": summary["integrity_failures"],
        },
        "rows": rows,
    }
