from datetime import datetime, timezone
from typing import Any, Optional

from redundancy.models import (
    DetectionSource,
    GroupHealth,
    GroupInfo,
    GroupType,
    MemberInfo,
    MemberRole,
    MemberState,
    normalize_serial,
)
from redundancy import store


class ConflictError(Exception):
    pass


def _invalidate_cache():
    try:
        from core import core_engine
        core_engine.invalidate_netmap_cache()
    except Exception:
        pass


def save_manual_group(payload: dict) -> dict:
    group_type = payload.get("group_type")
    if group_type not in (GroupType.HA_PAIR.value, GroupType.STACK.value, GroupType.SSO.value):
        raise ValueError(f"Invalid group_type: {group_type}")

    if group_type == GroupType.HA_PAIR.value and not payload.get("virtual_ip"):
        raise ValueError("HA pair requires virtual_ip")

    if group_type in (GroupType.STACK.value, GroupType.SSO.value) and not payload.get("logical_device_ip"):
        raise ValueError("Stack/SSO group requires logical_device_ip")

    logical_ip = payload.get("logical_device_ip")
    if logical_ip:
        existing_groups = store.list_groups()
        for g in existing_groups:
            if g.get("id") != payload.get("id") and g.get("logical_device_ip") == logical_ip:
                raise ConflictError(f"Logical device IP {logical_ip} already bound to group {g.get('name')}")

    members_raw = payload.get("members", [])
    members = [
        MemberInfo(
            role=MemberRole(m.get("role", MemberRole.UNKNOWN.value)),
            serial=m.get("serial"),
            model=m.get("model"),
            firmware=m.get("firmware"),
            mgmt_ip=m.get("mgmt_ip"),
            priority=m.get("priority"),
            state=MemberState(m.get("state", MemberState.READY.value)),
            details=m.get("details", {}),
            device_ip=m.get("device_ip"),
        )
        for m in members_raw
    ]

    g_info = GroupInfo(
        group_type=GroupType(group_type),
        name=payload["name"],
        members=members,
        virtual_ip=payload.get("virtual_ip"),
        health=GroupHealth(payload.get("health", GroupHealth.OK.value)),
        detection_source=DetectionSource.MANUAL,
    )
    g_info.health = g_info.compute_health()

    group_dict = {
        "id": payload.get("id"),
        "group_name": payload["group_name"],
        "group_type": group_type,
        "name": payload["name"],
        "virtual_ip": payload.get("virtual_ip"),
        "logical_device_ip": logical_ip,
        "health": g_info.health.value,
        "detection_source": DetectionSource.MANUAL.value,
        "last_verified": datetime.now(timezone.utc).isoformat(),
        "members": [
            {
                "device_ip": m.device_ip,
                "member_index": idx,
                "role": m.role.value,
                "serial": m.serial,
                "norm_serial": m.norm_serial,
                "model": m.model,
                "firmware": m.firmware,
                "state": m.state.value,
                "mgmt_ip": m.mgmt_ip,
                "priority": m.priority,
                "details": m.details,
            }
            for idx, m in enumerate(members)
        ],
    }

    group_id = store.save_group(group_dict)
    _invalidate_cache()
    return store.get_group(group_id)


def upsert_fgcp(group_name: str, group: GroupInfo, managed_devices: list[dict]) -> int:
    existing = store.find_group_by_name(group_name, GroupType.HA_PAIR.value, group.name)

    device_serial_map = {}
    for dev in managed_devices:
        ip = dev.get("IP")
        ser = dev.get("Serial") or dev.get("serial")
        norm_ser = normalize_serial(ser)
        if ip and norm_ser:
            device_serial_map[norm_ser] = ip

    formatted_members = []
    for idx, m in enumerate(group.members):
        matched_ip = device_serial_map.get(m.norm_serial) if m.norm_serial else None
        formatted_members.append(
            {
                "device_ip": matched_ip,
                "member_index": idx,
                "role": m.role.value,
                "serial": m.serial,
                "norm_serial": m.norm_serial,
                "model": m.model,
                "firmware": m.firmware,
                "state": m.state.value,
                "mgmt_ip": m.mgmt_ip,
                "priority": m.priority,
                "details": m.details,
            }
        )

    payload = {
        "id": existing["id"] if existing else None,
        "group_name": group_name,
        "group_type": GroupType.HA_PAIR.value,
        "name": group.name,
        "virtual_ip": group.virtual_ip,
        "logical_device_ip": None,
        "health": group.health.value,
        "detection_source": DetectionSource.FORTIOS_API.value,
        "last_verified": datetime.now(timezone.utc).isoformat(),
        "members": formatted_members,
    }

    gid = store.save_group(payload)
    _invalidate_cache()
    return gid


def discover_fgcp(device: dict) -> Optional[int]:
    from services import fortigate_service, inventory_manager
    from redundancy.parsers.fortios import parse_ha_status
    from security.security_manager import log_audit

    group_name = device.get("Group", "Generale")
    try:
        ha_status = fortigate_service.get_ha_status(device)
    except Exception:
        res = ha_status_cluster_name(device)
        if res:
            mark_fgcp_unknown(group_name, res)
        return None

    try:
        ha_checksums = fortigate_service.get_ha_checksums(device)
    except Exception:
        ha_checksums = None

    group_info = parse_ha_status(ha_status, ha_checksums)
    if group_info.health == GroupHealth.SPLIT_BRAIN:
        log_audit(f"Split brain detected in HA pair '{group_info.name}' for group '{group_name}'")

    managed_devices = inventory_manager.get_all_devices()
    return upsert_fgcp(group_name, group_info, managed_devices)


def ha_status_cluster_name(device: dict) -> Optional[str]:
    all_groups = store.list_groups()
    device_ip = device.get("IP")
    for g in all_groups:
        for m in g.get("members", []):
            if m.get("device_ip") == device_ip:
                return g.get("name")
    return None


def mark_fgcp_unknown(group_name: str, cluster_name: str):
    existing = store.find_group_by_name(group_name, GroupType.HA_PAIR.value, cluster_name)
    if existing:
        existing["health"] = GroupHealth.UNKNOWN.value
        existing["last_verified"] = datetime.now(timezone.utc).isoformat()
        store.save_group(existing)
        _invalidate_cache()


def delete_group(group_id: int) -> bool:
    res = store.delete_group(group_id)
    if res:
        _invalidate_cache()
    return res


def list_groups(group_scope=None) -> list[dict]:
    return store.list_groups(group_scope)


def get_group(group_id: int) -> dict | None:
    return store.get_group(group_id)


def device_redundancy_badge(device_ip: str) -> Optional[dict]:
    all_groups = store.list_groups()
    for g in all_groups:
        if g.get("logical_device_ip") == device_ip:
            return {
                "type": g["group_type"],
                "role": "logical",
                "health": g["health"],
                "group_id": g["id"],
                "virtual_ip": g.get("virtual_ip"),
                "member_count": len(g.get("members", [])),
            }
        for m in g.get("members", []):
            if m.get("device_ip") == device_ip:
                return {
                    "type": g["group_type"],
                    "role": m.get("role"),
                    "health": g["health"],
                    "group_id": g["id"],
                    "virtual_ip": g.get("virtual_ip"),
                    "member_count": len(g.get("members", [])),
                }
    return None
