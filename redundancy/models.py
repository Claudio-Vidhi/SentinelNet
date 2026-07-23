from dataclasses import dataclass, field
import enum
import re
from typing import Any, Optional


class GroupType(str, enum.Enum):
    HA_PAIR = "ha_pair"
    STACK = "stack"
    SSO = "sso"


class MemberRole(str, enum.Enum):
    ACTIVE = "active"
    STANDBY = "standby"
    MASTER = "master"
    MEMBER = "member"
    UNKNOWN = "unknown"


class MemberState(str, enum.Enum):
    READY = "ready"
    DOWN = "down"
    VERSION_MISMATCH = "version_mismatch"
    STANDBY_HOT = "standby_hot"
    RP_DOWN = "rp_down"
    PROVISIONED = "provisioned"
    UNKNOWN = "unknown"


class GroupHealth(str, enum.Enum):
    OK = "ok"
    DEGRADED = "degraded"
    OUT_OF_SYNC = "out_of_sync"
    SPLIT_BRAIN = "split_brain"
    UNKNOWN = "unknown"


class DetectionSource(str, enum.Enum):
    MANUAL = "manual"
    FORTIOS_API = "fortios_api"
    CLI_PARSER = "cli_parser"
    CDP_LLDP = "cdp_lldp"
    SNMP_MIB = "snmp_mib"
    VRRP_HSRP = "vrrp_hsrp"


def normalize_serial(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r"[^A-Za-z0-9]", "", str(val)).upper()
    return cleaned if cleaned else None


def normalize_mac(val: Optional[str]) -> Optional[str]:
    if not val:
        return None
    cleaned = re.sub(r"[^a-fA-F0-9]", "", str(val)).lower()
    return cleaned if len(cleaned) == 12 else None


def classify_virtual_mac(mac: Optional[str]) -> Optional[str]:
    norm = normalize_mac(mac)
    if not norm:
        return None
    if norm.startswith("00090f09"):
        return "fortigate_fgcp"
    if norm.startswith("00005e0001") or norm.startswith("00005e0002"):
        return "vrrp"
    if norm.startswith("00000c07ac") or norm.startswith("00000c9ff0"):
        return "hsrp"
    return None


@dataclass
class MemberInfo:
    role: MemberRole = MemberRole.UNKNOWN
    serial: Optional[str] = None
    norm_serial: Optional[str] = field(init=False, default=None)
    model: Optional[str] = None
    firmware: Optional[str] = None
    mgmt_ip: Optional[str] = None
    priority: Optional[int] = None
    state: MemberState = MemberState.READY
    details: dict[str, Any] = field(default_factory=dict)
    device_ip: Optional[str] = None

    def __post_init__(self):
        self.norm_serial = normalize_serial(self.serial)


HEALTH_PRIORITY = {
    GroupHealth.SPLIT_BRAIN: 4,
    GroupHealth.OUT_OF_SYNC: 3,
    GroupHealth.DEGRADED: 2,
    GroupHealth.UNKNOWN: 1,
    GroupHealth.OK: 0,
}


def _prefer_worse(h1: GroupHealth, h2: GroupHealth) -> GroupHealth:
    return h1 if HEALTH_PRIORITY.get(h1, 0) >= HEALTH_PRIORITY.get(h2, 0) else h2


@dataclass
class GroupInfo:
    group_type: GroupType
    name: str
    members: list[MemberInfo] = field(default_factory=list)
    virtual_ip: Optional[str] = None
    health: GroupHealth = GroupHealth.OK
    detection_source: DetectionSource = DetectionSource.MANUAL
    last_verified: Optional[str] = None

    def compute_health(self) -> GroupHealth:
        active_count = sum(1 for m in self.members if m.role in (MemberRole.ACTIVE, MemberRole.MASTER))
        if active_count > 1:
            return GroupHealth.SPLIT_BRAIN
        if self.group_type == GroupType.HA_PAIR and len(self.members) < 2:
            return GroupHealth.DEGRADED
        return GroupHealth.OK
