from typing import Any, Optional

from redundancy.models import (
    DetectionSource,
    GroupHealth,
    GroupInfo,
    GroupType,
    MemberInfo,
    MemberRole,
    MemberState,
    _prefer_worse,
)


def _safe_int(val: Any) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def parse_ha_status(
    ha_status: dict, ha_checksums: Optional[dict] = None
) -> GroupInfo:
    res = ha_status.get("results", ha_status)
    if isinstance(res, list) and len(res) > 0:
        res = res[0]
    if not isinstance(res, dict):
        res = {}

    raw_members = res.get("member") or res.get("statistics", {}).get("member", [])
    if not isinstance(raw_members, list):
        raw_members = []

    members = [
        MemberInfo(
            role=(
                MemberRole.ACTIVE
                if (m.get("is_root_master") or m.get("is_root_primary"))
                else MemberRole.STANDBY
            ),
            serial=m.get("serial_no") or m.get("serial"),
            model=m.get("model") or m.get("model_name"),
            firmware=m.get("version") or m.get("os_version"),
            mgmt_ip=m.get("mgmt_ip") or m.get("hostname_ip"),
            priority=_safe_int(m.get("priority")),
            state=MemberState.READY,
            details={
                k: m.get(k)
                for k in ("hostname", "sync_status", "uptime")
                if m.get(k) is not None
            },
        )
        for m in raw_members
        if isinstance(m, dict)
    ]

    name_val = res.get("group_name") or res.get("cluster_id") or "FGCP-cluster"
    group = GroupInfo(
        group_type=GroupType.HA_PAIR,
        name=str(name_val),
        members=members,
        virtual_ip=res.get("cluster_virtual_ip") or res.get("vcluster_ip"),
        detection_source=DetectionSource.FORTIOS_API,
    )

    if ha_checksums is not None:
        checksums = ha_checksums.get("results", ha_checksums)
        if isinstance(checksums, dict):
            checksums = checksums.get("member", [])
        if not isinstance(checksums, list):
            checksums = []

        values = {
            row.get("checksum")
            for row in checksums
            if isinstance(row, dict) and row.get("checksum")
        }

        if len(checksums) < 2:
            group.health = GroupHealth.DEGRADED
        elif len(values) > 1:
            group.health = GroupHealth.OUT_OF_SYNC
        else:
            group.health = GroupHealth.OK
    else:
        group.health = GroupHealth.OK

    group.health = _prefer_worse(group.health, group.compute_health())
    return group
