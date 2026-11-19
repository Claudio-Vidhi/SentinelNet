# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Synthetic workspace for demo mode (docs/demo.md).

Three organizations: ``acme-hq`` (IT corporate, two locations: Cisco IOS
campus, FortiGate edge and branch), ``plant-demo`` (compliant multi-vendor OT
cell) and ``plant-legacy`` (OT site full of findings). Everything is written
through the same functions a real collection uses, so every screen reads it
the way it reads real data.

All values are synthetic: RFC 5737 documentation subnets, private ranges,
generic hostnames, ``aa:bb:cc:..`` MACs, ``CVE-2024-6xxxx`` ids that do not
exist. Refuses to run outside demo mode: it must never write the real data
directory.
"""
import json
import os
import secrets
import time

from core import data_config

DEMO_USER = "admin"
CREDENTIALS_FILE = "DEMO-CREDENTIALS.txt"
_SEEDED_MARKER = ".demo-seeded"


def credentials() -> tuple:
    """(username, password) of the demo super-admin, generated once.

    Lives in the demo directory, so the start endpoint (still running on the
    real data) can show it before the restart and the seed (running in demo
    mode) creates the account with the same password."""
    path = os.path.join(data_config.DEMO_DIR, CREDENTIALS_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            fields = dict(line.split(": ", 1) for line in fh.read().splitlines() if ": " in line)
        return fields["username"], fields["password"]
    except (OSError, KeyError, ValueError):
        pass
    password = secrets.token_urlsafe(15)
    os.makedirs(data_config.DEMO_DIR, exist_ok=True)
    data_config.atomic_write(
        path, (f"SentinelNet demo workspace (synthetic data)\n"
               f"username: {DEMO_USER}\npassword: {password}\n").encode("utf-8"),
        restrict=True)
    return DEMO_USER, password


# --- Configurations -----------------------------------------------------------

def _cdp(*neighbors) -> str:
    """CDP detail section as the triage appends it: (id, ip, platform, local, remote)."""
    from services.config_drift.normalize import TRIAGE_MARKER
    blocks = []
    for dev_id, ip, platform, local, remote in neighbors:
        blocks.append(
            f"-------------------------\nDevice ID: {dev_id}\nEntry address(es):\n"
            f"  IP address: {ip}\nPlatform: {platform},  Capabilities: Switch IGMP\n"
            f"Interface: {local},  Port ID (outgoing port): {remote}\nHoldtime : 150 sec\n")
    return f"\n{TRIAGE_MARKER}\n--- SHOW CDP NEIGHBORS DETAIL ---\n" + "".join(blocks)


CORE_SW_V1 = """hostname core-sw-01
service password-encryption
aaa new-model
ip routing
ip ssh version 2
ntp server 10.100.20.5
logging host 10.100.20.6
!
vlan 10
 name USERS
vlan 20
 name SERVERS
vlan 30
 name GUEST
!
ip access-list extended SERVERS-IN
 permit tcp 10.100.10.0 0.0.0.255 10.100.20.0 0.0.0.255 eq 443
 permit tcp 10.100.10.0 0.0.0.255 10.100.20.0 0.0.0.255 eq 22
 deny ip any 10.100.20.0 0.0.0.255
 permit ip any any
ip access-list extended GUEST-IN
 deny ip 10.100.30.0 0.0.0.255 10.100.0.0 0.0.255.255
 permit ip any any
!
interface GigabitEthernet1/0/1
 description to access-sw-01
 switchport mode trunk
!
interface GigabitEthernet1/0/2
 description to access-sw-02
 switchport mode trunk
!
interface GigabitEthernet1/0/48
 description to fw-edge-01
 no switchport
 ip address 10.100.255.2 255.255.255.252
!
interface Vlan10
 ip address 10.100.10.1 255.255.255.0
!
interface Vlan20
 ip address 10.100.20.1 255.255.255.0
 ip access-group SERVERS-IN out
!
interface Vlan30
 ip address 10.100.30.1 255.255.255.0
 ip access-group GUEST-IN in
!
interface Vlan99
 ip address 10.100.0.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 10.100.255.1
!
line vty 0 4
 transport input ssh
!
end
"""
# v2: someone opened SSH to the servers from the guest VLAN (drift).
CORE_SW_V2 = CORE_SW_V1.replace(
    " deny ip any 10.100.20.0 0.0.0.255\n",
    " permit tcp 10.100.30.0 0.0.0.255 10.100.20.0 0.0.0.255 eq 22\n"
    " deny ip any 10.100.20.0 0.0.0.255\n")


def _access_sw(name: str, ip: str, port: str) -> str:
    return f"""hostname {name}
service password-encryption
aaa new-model
ip ssh version 2
ntp server 10.100.20.5
no ip http server
!
vlan 10
 name USERS
vlan 30
 name GUEST
!
interface GigabitEthernet1/0/1
 switchport access vlan 10
 switchport mode access
 spanning-tree portfast
!
interface GigabitEthernet1/0/2
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/24
 switchport access vlan 30
 switchport mode access
!
interface GigabitEthernet1/0/49
 description uplink core-sw-01
 switchport mode trunk
!
interface Vlan99
 ip address {ip} 255.255.255.0
!
ip default-gateway 10.100.0.1
!
line vty 0 4
 transport input ssh
!
end
""" + _cdp(("core-sw-01", "10.100.0.1", "cisco C9300-48P", "GigabitEthernet1/0/49", port))


ACCESS_SW1 = _access_sw("access-sw-01", "10.100.0.11", "GigabitEthernet1/0/1")
ACCESS_SW2_V1 = _access_sw("access-sw-02", "10.100.0.12", "GigabitEthernet1/0/2")
# v2: web management turned on, telnet allowed, a community string: findings
# for the audit, drift against the tenant baseline.
ACCESS_SW2_V2 = (ACCESS_SW2_V1
                 .replace("no ip http server\n", "ip http server\nsnmp-server community public RO\n")
                 .replace(" transport input ssh\n", " transport input telnet ssh\n"))

CORE_SW_CDP = _cdp(
    ("access-sw-01", "10.100.0.11", "cisco WS-C2960X-48FPD-L", "GigabitEthernet1/0/1", "GigabitEthernet1/0/49"),
    ("access-sw-02", "10.100.0.12", "cisco WS-C2960X-48FPD-L", "GigabitEthernet1/0/2", "GigabitEthernet1/0/49"))

FW_EDGE_V1 = """config system global
    set hostname "fw-edge-01"
    set admin-lockout-threshold 3
    set strong-crypto enable
end
config system interface
    edit "port1"
        set ip 203.0.113.100 255.255.255.0
        set allowaccess ping
        set alias "wan"
    next
    edit "port2"
        set ip 10.100.255.1 255.255.255.252
        set allowaccess ping https ssh
        set alias "core-transit"
    next
    edit "port3"
        set ip 10.100.50.1 255.255.255.0
        set allowaccess ping
        set alias "dmz"
    next
end
config firewall address
    edit "HQ-USERS"
        set subnet 10.100.10.0 255.255.255.0
    next
    edit "HQ-GUEST"
        set subnet 10.100.30.0 255.255.255.0
    next
    edit "DMZ-WEB"
        set subnet 10.100.50.10 255.255.255.255
    next
    edit "OLD-VENDOR-HOST"
        set subnet 198.51.100.44 255.255.255.255
    next
end
config firewall vip
    edit "VIP-WEB"
        set extip 203.0.113.110
        set mappedip 10.100.50.10
        set extintf "port1"
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "port1"
    next
    edit 2
        set dst 10.100.0.0 255.255.0.0
        set gateway 10.100.255.2
        set device "port2"
    next
end
config router policy
    edit 1
        set input-device "port2"
        set src "10.100.30.0/255.255.255.0"
        set dst "0.0.0.0/0.0.0.0"
        set gateway 203.0.113.1
        set output-device "port1"
        set comments "Guest traffic straight to the internet"
    next
end
config firewall policy
    edit 1
        set name "LAN-to-Internet"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "HQ-USERS"
        set dstaddr "all"
        set action accept
        set service "HTTP" "HTTPS" "DNS"
        set nat enable
    next
    edit 2
        set name "Guest-to-Internet"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "HQ-GUEST"
        set dstaddr "all"
        set action accept
        set service "HTTP" "HTTPS"
        set nat enable
    next
    edit 3
        set name "Publish-Web"
        set srcintf "port1"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "VIP-WEB"
        set action accept
        set service "HTTPS"
    next
    edit 4
        set name "Legacy-Vendor-Access"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "OLD-VENDOR-HOST"
        set dstaddr "HQ-USERS"
        set action accept
        set service "ALL"
    next
end
"""
# v2: a "temporary" any-any rule appeared: drift, hygiene and audit findings.
FW_EDGE_V2 = FW_EDGE_V1.replace("""    edit 4
        set name "Legacy-Vendor-Access\"""", """    edit 9
        set name "Temp-Any-Any"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 4
        set name "Legacy-Vendor-Access\"""")

FW_BRANCH = """config system global
    set hostname "fw-branch-01"
end
config system interface
    edit "wan1"
        set ip 203.0.113.120 255.255.255.0
        set allowaccess ping https ssh
    next
    edit "internal"
        set ip 10.110.0.254 255.255.255.0
        set allowaccess ping https ssh
    next
end
config firewall address
    edit "BRANCH-LAN"
        set subnet 10.110.0.0 255.255.255.0
    next
    edit "HQ-NET"
        set subnet 10.100.0.0 255.255.0.0
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
end
config firewall policy
    edit 1
        set name "Branch-to-Internet"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "BRANCH-LAN"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
    next
end
"""

BRANCH_SW = """hostname branch-sw-01
vlan 10
   name USERS
interface 1/1/1
    no shutdown
    vlan access 10
interface 1/1/48
    description uplink fw-branch-01
    no shutdown
interface vlan 10
    ip address 10.110.0.11/24
ip route 0.0.0.0/0 10.110.0.254
ssh server vrf default
"""

# OT workspace (plant-demo / plant-legacy), including the path-trace scenario
# of 614e91c9: IT engineers reach the PLC through the FortiGate VIP, the core
# ACL and the IPS-shielded second cell.
FW_DMZ = """config system interface
    edit "port1"
        set ip 10.20.0.1 255.255.255.0
        set alias "it-uplink"
    next
    edit "port2"
        set ip 172.16.10.1 255.255.255.252
        set alias "ot-core-transit"
    next
    edit "port3"
        set ip 10.40.0.1 255.255.255.0
        set alias "ot-cell2"
    next
end
config ips sensor
    edit "OT-CVE-BLOCK"
        config entries
            edit 1
                set cve "CVE-2024-60003"
                set action block
            next
        end
    next
end
config firewall address
    edit "OT-CELL2-NET"
        set subnet 10.40.0.0 255.255.255.0
    next
    edit "IT-ENG-NET"
        set subnet 10.20.0.0 255.255.255.0
    next
    edit "OT-CELL-NET"
        set subnet 192.0.2.0 255.255.255.0
    next
    edit "LEGACY-ENG-NET"
        set subnet 10.99.0.0 255.255.255.0
    next
    edit "LEGACY-TEMP-HOST"
        set subnet 198.51.100.88 255.255.255.255
    next
end
config firewall vip
    edit "VIP-PLC-MODBUS"
        set extip 10.20.0.50
        set mappedip 192.0.2.10
        set extintf "port1"
        set portforward enable
        set protocol tcp
        set extport 502
        set mappedport 502
    next
    edit "VIP-HMI-WEB"
        set extip 203.0.113.60
        set mappedip 192.0.2.30
        set extintf "port1"
    next
end
config firewall service custom
    edit "MODBUS-TCP"
        set tcp-portrange 502
    next
    edit "OLD-TELNET-SVC"
        set tcp-portrange 23
    next
end
config router static
    edit 1
        set dst 192.0.2.0 255.255.255.0
        set gateway 172.16.10.2
        set device "port2"
    next
end
config firewall policy
    edit 10
        set name "Allow-Eng-Modbus-VIP"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "IT-ENG-NET"
        set dstaddr "VIP-PLC-MODBUS"
        set action accept
        set service "MODBUS-TCP"
        set nat enable
    next
    edit 20
        set name "Block-IT-SSH-To-OT"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "OT-CELL-NET"
        set action deny
        set service "SSH"
    next
    edit 50
        set name "Temp-Commissioning-Any"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "OT-CELL-NET"
        set action accept
        set service "ALL"
    next
    edit 99
        set name "Unused-Legacy-Vendor"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "LEGACY-ENG-NET"
        set dstaddr "OT-CELL-NET"
        set action accept
        set service "ALL"
    next
    edit 60
        set name "Publish-HMI-Web"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "VIP-HMI-WEB"
        set action accept
        set service "HTTPS"
    next
    edit 70
        set name "Eng-Web-To-Cell2-IPS"
        set srcintf "port1"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "OT-CELL2-NET"
        set action accept
        set service "HTTP" "HTTPS"
        set utm-status enable
        set ips-sensor "OT-CVE-BLOCK"
    next
end
"""
# Earlier version, before the commissioning rule was opened.
FW_DMZ_V1 = FW_DMZ.replace("""    edit 50
        set name "Temp-Commissioning-Any"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "OT-CELL-NET"
        set action accept
        set service "ALL"
    next
""", "")

SW_CORE_OT = """hostname sw-core-01
ip routing
!
ip access-list extended OT-CELL-IN
 permit tcp host 172.16.10.1 host 192.0.2.10 eq 502
 deny tcp any 192.0.2.0 0.0.0.255 eq 22
 permit ip any any
!
interface GigabitEthernet0/0
 ip address 172.16.10.2 255.255.255.252
 ip access-group OT-CELL-IN in
!
interface Vlan10
 ip address 192.0.2.254 255.255.255.0
!
interface Vlan20
 ip address 10.30.0.1 255.255.255.0
 ip access-group OT-CELL-IN in
!
ip route 0.0.0.0 0.0.0.0 172.16.10.1
!
end
"""

PA_EDGE = """set deviceconfig system hostname fw-edge-pa
set deviceconfig setting management http-ocsp yes
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.10/24
set network interface ethernet ethernet1/2 layer3 ip 172.16.10.5/30
set zone untrust network layer3 ethernet1/1
set zone ot-dmz network layer3 ethernet1/2
set address IT-CORP ip-netmask 10.20.0.0/24
set address OT-CELL ip-netmask 192.0.2.0/24
set address UNUSED-PAN-HOST ip-netmask 198.51.100.77/32
set service HTTPS-OT protocol tcp port 443
set network virtual-router default routing-table ip static-route ot-cell destination 192.0.2.0/24 nexthop ip-address 172.16.10.6 interface ethernet1/2
set rulebase security rules Allow-HTTPS-HMI from untrust
set rulebase security rules Allow-HTTPS-HMI to ot-dmz
set rulebase security rules Allow-HTTPS-HMI source IT-CORP
set rulebase security rules Allow-HTTPS-HMI destination OT-CELL
set rulebase security rules Allow-HTTPS-HMI service HTTPS-OT
set rulebase security rules Allow-HTTPS-HMI action allow
set rulebase security rules Temp-Any-Any-Audit from untrust
set rulebase security rules Temp-Any-Any-Audit to ot-dmz
set rulebase security rules Temp-Any-Any-Audit source any
set rulebase security rules Temp-Any-Any-Audit destination any
set rulebase security rules Temp-Any-Any-Audit service any
set rulebase security rules Temp-Any-Any-Audit action allow
set rulebase nat rules DNAT-HMI from untrust
set rulebase nat rules DNAT-HMI to ot-dmz
set rulebase nat rules DNAT-HMI source IT-CORP
set rulebase nat rules DNAT-HMI destination 203.0.113.50/32
set rulebase nat rules DNAT-HMI destination-translation translated-address 192.0.2.30
"""

SRX_BRANCH = """set system host-name fw-branch-srx
set system services ssh protocol-version v2
set system services telnet
set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.20/24
set interfaces ge-0/0/1 unit 0 family inet address 172.16.20.1/30
set security zones security-zone untrust interfaces ge-0/0/0.0
set security zones security-zone ot-zone interfaces ge-0/0/1.0
set security address-book global address IT-ENG-NET 10.20.0.0/24
set security address-book global address OT-PLC-NET 192.0.2.0/24
set security address-book global address UNUSED-SRX-ADDR 198.51.100.99/32
set applications application MODBUS-TCP protocol tcp destination-port 502
set routing-options static route 192.0.2.0/24 next-hop 172.16.20.2
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS match source-address IT-ENG-NET
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS match destination-address OT-PLC-NET
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS match application MODBUS-TCP
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS then permit
"""

NXOS_DC = """hostname sw-dc-nxos
feature vpc
feature ospf
feature interface-vlan
!
vrf context management
!
object-group ip address UNUSED-NXOS-GRP
  10 host 198.51.100.66
!
ip access-list extended NXOS-OT-IN
  10 permit tcp 10.20.0.0 0.0.0.255 192.0.2.0 0.0.0.255 eq 502
  20 deny tcp any any eq 23
  30 permit ip any any
!
interface Vlan10
  ip address 203.0.113.30/24
  ip access-group NXOS-OT-IN in
!
interface Ethernet1/1
  no switchport
  ip address 172.16.30.1/30
!
ip route 192.0.2.0/24 172.16.30.2
"""

SCALANCE = """hostname switch-01
service password-encryption
no ip http server
!
ip access-list extended OT-SCALANCE-IN
  10 permit tcp 192.0.2.0 0.0.0.255 192.0.2.0 0.0.0.255 eq 502
  20 deny ip any any
!
interface Vlan10
  ip address 192.0.2.20 255.255.255.0
  ip access-group OT-SCALANCE-IN in
!
line vty 0 4
  transport input ssh
!
ip route 0.0.0.0 0.0.0.0 192.0.2.254
end
"""

MOXA_LEGACY = """hostname switch-legacy-01
ip http server
snmp-server community public RO
!
ip access-list extended OT-LEGACY-IN
  10 permit tcp any any eq 23
  20 permit ip any any
!
interface Vlan1
  ip address 198.51.100.10 255.255.255.0
  ip access-group OT-LEGACY-IN in
!
interface FastEthernet0/4
  no shutdown
!
line vty 0 4
  transport input telnet ssh
!
ip route 0.0.0.0 0.0.0.0 198.51.100.1
end
"""


# --- Seeders ------------------------------------------------------------------

def _device(ip, hostname, vendor, group, location, probe="central", transports=None, **kw):
    from services import inventory_manager
    inventory_manager.add_or_update_device(
        ip=ip, hostname=hostname, vendor=vendor, profile="default",
        username="", password="", enable_secret="", group=group,
        location=location, transports=transports or {"manual": True},
        snmp_disabled=kw.pop("snmp_disabled", True), probe=probe, **kw)


def _seed_inventory() -> None:
    from services import inventory_manager, inventory_store, probe_manager

    inventory_manager.save_groups({
        "acme-hq": {"description": "Demo IT corporate (campus + branch)"},
        "plant-demo": {"description": "Demo Plant OT (Compliant + Multi-Vendor)"},
        "plant-legacy": {"description": "Demo Legacy Plant OT (Findings)"},
    })
    with inventory_manager._db() as conn:
        inventory_store.write_locations(conn, {
            "loc-acme-hq": {"org": "acme-hq", "name": "HQ Campus", "role": "hq",
                            "subnets": ["10.100.0.0/16", "203.0.113.96/28"], "probe": "central"},
            "loc-acme-branch": {"org": "acme-hq", "name": "Branch Office", "role": "branch",
                                "subnets": ["10.110.0.0/16"], "probe": "central"},
            "loc-cell1": {"org": "plant-demo", "name": "Cell L1 (Compliant)", "role": "branch",
                          "subnets": ["192.0.2.0/24"], "probe": "central"},
            "loc-legacy": {"org": "plant-legacy", "name": "Legacy Line", "role": "branch",
                           "subnets": ["198.51.100.0/24"], "probe": "central"},
        })

    jump, _ = probe_manager.create_probe(
        name="ot-bastion", mode="jump", jump_host="10.10.0.5", jump_port=22,
        jump_identity="ot-jump-id")
    j = jump["id"]

    # acme-hq: IT campus and branch
    _device("10.100.0.1", "core-sw-01", "cisco", "acme-hq", "loc-acme-hq")
    _device("10.100.0.11", "access-sw-01", "cisco", "acme-hq", "loc-acme-hq")
    _device("10.100.0.12", "access-sw-02", "cisco", "acme-hq", "loc-acme-hq")
    _device("10.100.255.1", "fw-edge-01", "fortinet", "acme-hq", "loc-acme-hq")
    _device("10.100.20.10", "srv-linux-01", "linux", "acme-hq", "loc-acme-hq")
    _device("10.110.0.254", "fw-branch-01", "fortinet", "acme-hq", "loc-acme-branch")
    _device("10.110.0.11", "branch-sw-01", "aruba", "acme-hq", "loc-acme-branch")

    # plant-demo: compliant OT cell + multi-vendor edge/core
    _device("192.0.2.10", "plc-01", "siemens", "plant-demo", "loc-cell1", j,
            {"ssh": 22}, purdue_level="L1",
            process_criticality="scheduled_shutdown", maintenance_window="Sun 02:00-06:00")
    _device("192.0.2.20", "switch-01", "siemens_scalance", "plant-demo", "loc-cell1", j,
            {"ssh": 22}, purdue_level="L2")
    _device("192.0.2.30", "hmi-01", "rockwell", "plant-demo", "loc-cell1", j,
            {"restconf": 443}, purdue_level="L2",
            process_criticality="mission_critical", maintenance_window="Planned turnaround only")
    _device("192.0.2.40", "fw-dmz-01", "fortinet", "plant-demo", "loc-cell1", j, purdue_level="L3.5")
    _device("192.0.2.254", "sw-core-01", "cisco", "plant-demo", "loc-cell1", purdue_level="L3")
    _device("203.0.113.10", "fw-edge-pa", "paloalto", "plant-demo", "loc-cell1", purdue_level="L3.5")
    _device("203.0.113.20", "fw-branch-srx", "juniper", "plant-demo", "loc-cell1", purdue_level="L3.5")
    _device("203.0.113.30", "sw-dc-nxos", "cisco_nxos", "plant-demo", "loc-cell1", purdue_level="L3")
    # Second cell behind the FortiGate, shielded by a CVE-specific IPS entry.
    _device("10.40.0.10", "plc-cell-02", "siemens", "plant-demo", "loc-cell1", j,
            {"ssh": 22}, purdue_level="L1")

    # plant-legacy: findings
    _device("198.51.100.10", "switch-legacy-01", "moxa", "plant-legacy", "loc-legacy",
            transports={"telnet": 23}, snmp_disabled=False, snmp_community="public",
            purdue_level="L2")
    _device("198.51.100.20", "plc-legacy-01", "siemens", "plant-legacy", "loc-legacy",
            transports={"telnet": 23}, purdue_level="L1")

    versions = {
        "10.100.0.1": ("cisco", "17.9.4", "C9300-48P"),
        "10.100.0.11": ("cisco", "15.2(7)E8", "WS-C2960X-48FPD-L"),
        "10.100.0.12": ("cisco", "15.2(7)E8", "WS-C2960X-48FPD-L"),
        "10.100.255.1": ("fortinet", "v7.2.8", "FortiGate-100F"),
        "10.110.0.254": ("fortinet", "v7.0.15", "FortiGate-40F"),
        "10.110.0.11": ("aruba", "10.13.1000", "6100"),
        "192.0.2.40": ("fortinet", "v7.4.3", "FortiGate-60F"),
        "192.0.2.254": ("cisco", "17.6.5", "C9300-24T"),
    }
    for ip, (vendor, version, model) in versions.items():
        inventory_manager.update_version_inventory(ip, vendor, version, "online", model=model)


def _backup(device: dict, *texts: str) -> None:
    """One archived version per text, the last one current: the path every
    collected config takes (core_engine)."""
    from core import backup_store
    from services.config_drift import history
    for text in texts:
        backup_store.save_backup(device, device["Hostname"], text)
        history.record_version(device, text)


def _seed_backups(by_ip: dict) -> None:
    from core import backup_store
    _backup(by_ip["10.100.0.1"], CORE_SW_V1 + CORE_SW_CDP, CORE_SW_V2 + CORE_SW_CDP)
    _backup(by_ip["10.100.0.11"], ACCESS_SW1)
    _backup(by_ip["10.100.0.12"], ACCESS_SW2_V1, ACCESS_SW2_V2)
    _backup(by_ip["10.100.255.1"], FW_EDGE_V1, FW_EDGE_V2)
    _backup(by_ip["10.110.0.254"], FW_BRANCH)
    _backup(by_ip["10.110.0.11"], BRANCH_SW)
    _backup(by_ip["192.0.2.40"], FW_DMZ_V1, FW_DMZ)
    _backup(by_ip["192.0.2.254"], SW_CORE_OT)
    _backup(by_ip["192.0.2.20"], SCALANCE)
    _backup(by_ip["203.0.113.10"], PA_EDGE)
    _backup(by_ip["203.0.113.20"], SRX_BRANCH)
    _backup(by_ip["203.0.113.30"], NXOS_DC)
    _backup(by_ip["198.51.100.10"], MOXA_LEGACY)

    backup_store.save_ot_artifact(
        by_ip["192.0.2.10"], "line1_plc.zap18", b"TIA-PORTAL-DEMO-V18",
        uploaded_by=DEMO_USER, project_version="v1.8", notes="Commissioning golden backup")
    backup_store.save_ot_artifact(
        by_ip["192.0.2.20"], "switch01_scl.scd", b"<SCL version='2007B'/>",
        uploaded_by=DEMO_USER, project_version="rev-2", notes="IEC 61850 substation config")
    backup_store.save_ot_artifact(
        by_ip["192.0.2.30"], "hmi01_panel.hmi", b"HMI-RUNTIME-DEMO",
        uploaded_by=DEMO_USER, project_version="v3.1", notes="Operator HMI backup")

    # Tenant baseline the access switch v2 drifts from.
    from services.config_drift import baseline
    baseline.save("acme-hq", "ios", "+ service password-encryption\n+ aaa new-model\n"
                                    "+ ip ssh version 2\n- ip http server\n"
                                    "- /transport input .*telnet/\n- snmp-server community public\n")


def _seed_segments() -> None:
    from services import segment_manager
    segment_manager.save_segment("acme-hq", None, "Users", "sky",
                                 subnets=["10.100.10.0/24"], members=["10.100.0.11", "10.100.0.12"])
    segment_manager.save_segment("acme-hq", None, "Servers", "teal",
                                 subnets=["10.100.20.0/24"], members=["10.100.20.10"])
    segment_manager.save_segment("acme-hq", None, "DMZ", "rose",
                                 subnets=["10.100.50.0/24", "203.0.113.96/28"], members=["10.100.255.1"])
    segment_manager.save_segment(
        "plant-demo", None, "Cell L1 PLC/HMI", "sky",
        subnets=["192.0.2.0/24"], purdue_level="L1",
        members=["192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.254"])
    segment_manager.save_segment(
        "plant-demo", None, "IT/OT DMZ", "amber",
        subnets=["10.20.0.0/24", "203.0.113.0/24"], purdue_level="L3.5",
        members=["192.0.2.40", "203.0.113.10", "203.0.113.20", "203.0.113.30"])
    segment_manager.save_segment(
        "plant-demo", None, "Cell 2 PLC", "sky",
        subnets=["10.40.0.0/24"], purdue_level="L1", members=["10.40.0.10"])


def _seed_events() -> None:
    from core import db
    now = int(time.time())

    def iface(tenant, ip, name, admin, link, sev=6):
        return (now, now, tenant, "snmp", "interface.state", "interface", f"{ip}:{name}", sev,
                ip, name, "", "", None, "",
                json.dumps({"admin_status": admin, "link": link}), f"demo-{ip}-{name}")

    def flow(tenant, src, dst, port, via, sev, attrs, key):
        return (now, now, tenant, "syslog", "flow", "flow", f"{src}>{dst}", sev, via, "",
                src, dst, port, "tcp", json.dumps(attrs), key)

    rows = [
        iface("acme-hq", "10.100.0.1", "Gi1/0/1", "up", "up"),
        iface("acme-hq", "10.100.0.1", "Gi1/0/2", "up", "up"),
        iface("acme-hq", "10.100.0.1", "Gi1/0/48", "up", "up"),
        iface("acme-hq", "10.100.0.11", "Gi1/0/1", "up", "up"),
        iface("acme-hq", "10.100.0.11", "Gi1/0/2", "up", "down", 4),
        iface("acme-hq", "10.100.0.12", "Gi1/0/1", "up", "up"),
        iface("acme-hq", "10.100.0.12", "Gi1/0/24", "down", "down"),
        iface("plant-demo", "192.0.2.20", "Gi1/0/1", "up", "up"),
        iface("plant-demo", "192.0.2.20", "Vlan10", "up", "down"),
        iface("plant-legacy", "198.51.100.10", "Fa0/4", "up", "down", 4),
        # Segregated Modbus TCP + HTTPS HMI flows inside the plant-demo L1 cell
        flow("plant-demo", "192.0.2.30", "192.0.2.10", 502, "192.0.2.40", 6,
             {"ot_protocol": "modbus_tcp", "action": "accept"}, "demo-pd-modbus"),
        flow("plant-demo", "10.20.0.5", "192.0.2.10", 443, "192.0.2.40", 6,
             {"action": "accept"}, "demo-pd-https-plc"),
        flow("plant-demo", "10.20.0.5", "192.0.2.30", 443, "203.0.113.10", 6,
             {"action": "accept"}, "demo-pd-https-hmi"),
        # Unsegregated S7comm flow into the legacy line
        flow("plant-legacy", "203.0.113.50", "198.51.100.20", 102, "198.51.100.1", 3,
             {"ot_protocol": "s7comm", "action": "accept"}, "demo-pl-s7"),
    ]
    conn = db.get_observability_connection()
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO events "
            "(ts, ingested_ts, tenant, source, event_type, entity_type, entity_id, severity, "
            "device_ip, interface, src_ip, dst_ip, dst_port, protocol, attrs_json, dedup_key) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()


def _seed_policy_snapshots() -> None:
    """Hit counters 35 days ago, 7 days ago and now: deltas, dead and rarely
    used rules for firewall hygiene."""
    from core import db
    now = int(time.time())
    stamps = (now - 35 * 86400, now - 7 * 86400, now)
    # (tenant, device, policy id, name, hits at each stamp, bytes per hit)
    series = [
        ("acme-hq", "10.100.255.1", "1", "LAN-to-Internet", (510_000, 880_000, 1_020_000), 900),
        ("acme-hq", "10.100.255.1", "2", "Guest-to-Internet", (42_000, 61_000, 70_500), 700),
        ("acme-hq", "10.100.255.1", "3", "Publish-Web", (9_800, 15_200, 17_900), 1_200),
        ("acme-hq", "10.100.255.1", "4", "Legacy-Vendor-Access", (0, 0, 0), 0),
        ("acme-hq", "10.100.255.1", "9", "Temp-Any-Any", (3, 4, 4), 500),
        ("plant-demo", "192.0.2.40", "10", "Allow-Eng-Modbus-VIP", (12_000, 18_400, 19_850), 800),
        ("plant-demo", "192.0.2.40", "20", "Block-IT-SSH-To-OT", (40, 112, 138), 80),
        ("plant-demo", "192.0.2.40", "50", "Temp-Commissioning-Any", (18, 24, 26), 130),
        ("plant-demo", "192.0.2.40", "99", "Unused-Legacy-Vendor", (0, 0, 0), 0),
        ("plant-demo", "203.0.113.10", "Allow-HTTPS-HMI", "Allow-HTTPS-HMI", (4_200, 5_900, 6_420), 800),
        ("plant-demo", "203.0.113.10", "Temp-Any-Any-Audit", "Temp-Any-Any-Audit", (12, 15, 16), 125),
    ]
    snaps = [(ts, tenant, ip, pid, name, hits, hits * per_hit, ts if hits else None)
             for tenant, ip, pid, name, counts, per_hit in series
             for ts, hits in zip(stamps, counts)]
    conn = db.get_observability_connection()
    try:
        conn.executemany(
            "INSERT INTO policy_hit_snapshots "
            "(ts, tenant, device_ip, policy_id, policy_name, hit_count, bytes, last_used) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", snaps)
        conn.commit()
    finally:
        conn.close()


def _seed_mac_history() -> None:
    from collectors import mac_history
    # acme-hq: ARP from the core SVIs, endpoints behind the access ports.
    mac_history.record_arp_entries(
        [{"mac": f"aa:bb:cc:10:00:{i:02x}", "ip": f"10.100.10.{20 + i}", "vlan": "10"}
         for i in range(1, 9)]
        + [{"mac": "aa:bb:cc:20:00:01", "ip": "10.100.20.10", "vlan": "20"},
           {"mac": "aa:bb:cc:30:00:01", "ip": "10.100.30.50", "vlan": "30"}],
        source_ip="10.100.0.1", source_name="core-sw-01", source_type="switch", tenant="acme-hq")
    mac_history.record_sightings(
        [{"mac": f"aa:bb:cc:10:00:{i:02x}", "vlan": "10", "interface": f"Gi1/0/{i}",
          "is_uplink": False} for i in range(1, 5)]
        + [{"mac": "aa:bb:cc:00:99:01", "vlan": "10", "interface": "Gi1/0/49", "is_uplink": True}],
        switch_ip="10.100.0.11", switch_name="access-sw-01", tenant="acme-hq")
    mac_history.record_sightings(
        [{"mac": f"aa:bb:cc:10:00:{i:02x}", "vlan": "10", "interface": f"Gi1/0/{i - 4}",
          "is_uplink": False} for i in range(5, 9)]
        + [{"mac": "aa:bb:cc:30:00:01", "vlan": "30", "interface": "Gi1/0/24", "is_uplink": False}],
        switch_ip="10.100.0.12", switch_name="access-sw-02", tenant="acme-hq")
    # plant-demo: one host with an ARP binding on each side of the DMZ
    # (dual-homed finding) and four endpoints behind one OT access port.
    mac_history.record_arp_entries(
        [{"mac": "aa:bb:cc:00:00:01", "ip": "192.0.2.77", "vlan": "10"},
         {"mac": "aa:bb:cc:00:00:01", "ip": "10.20.0.77", "vlan": "20"}],
        source_ip="192.0.2.254", source_name="sw-core-01", source_type="switch", tenant="plant-demo")
    mac_history.record_sightings(
        [{"mac": f"aa:bb:cc:00:01:0{i}", "vlan": "10", "interface": "Gi1/0/5", "is_uplink": False}
         for i in range(1, 5)],
        switch_ip="192.0.2.20", switch_name="switch-01", tenant="plant-demo")


def _seed_cve_snapshots(devices: list) -> None:
    """Synthetic CVE snapshots. OT: hmi-01 exposed (KEV), plc-01 behind the
    core ACL, plc-cell-02 behind the FortiGate IPS entry, plc-legacy-01 with
    no gateway. IT: a KEV on an access switch, a high on the edge firewall."""
    from services import cve_intel
    from services.config_drift import history
    cves = {
        "192.0.2.30": ("CVE-2024-60001", 9.8, ["http"], {"dateAdded": "2024-06-01"}),
        "192.0.2.10": ("CVE-2024-60002", 8.1, ["ssh"], None),
        "10.40.0.10": ("CVE-2024-60003", 9.8, ["http"], None),
        "198.51.100.20": ("CVE-2024-60004", 9.8, [], None),
        "10.100.0.12": ("CVE-2024-60010", 9.8, ["http"], {"dateAdded": "2024-09-15"}),
        "10.100.255.1": ("CVE-2024-60011", 8.6, ["https"], None),
    }
    for d in devices:
        if d["IP"] not in cves:
            continue
        cid, cvss, services, kev = cves[d["IP"]]
        cve_intel._save(d, {
            "device": d["IP"], "fetched_at": history._now(), "version_seen_at": history._now(),
            "source": "nvd", "query": {"kind": "keyword", "value": "demo", "confidence": "product"},
            "total_available": 1,
            "cves": [{"id": cid, "cvss": cvss, "severity": "CRITICAL" if cvss >= 9 else "HIGH",
                      "published": "2024-05-01", "summary": "Synthetic demo vulnerability.",
                      "cpe_hardware": [], "model_scope": "generic", "exploited": bool(kev),
                      "kev": kev, "ics_advisories": [], "services": services}],
        })


def _seed_audits(by_ip: dict) -> None:
    """One saved NetSec audit per IOS/FortiOS device: the status report's
    hardening section and the audit history read these."""
    from services import netsec_audit
    from services.netsec_audit import history
    texts = {"10.100.0.1": CORE_SW_V2, "10.100.0.12": ACCESS_SW2_V2,
             "10.100.255.1": FW_EDGE_V2, "10.110.0.254": FW_BRANCH,
             "192.0.2.40": FW_DMZ, "192.0.2.254": SW_CORE_OT}
    for ip, text in texts.items():
        dev = by_ip[ip]
        result = netsec_audit.run_netsec_audit(config_text=text, device_name=dev["Hostname"], lang="en")
        history.save(result, tenant=dev["Group"], device_name=dev["Hostname"],
                     device_ip=ip, actor=DEMO_USER, run_name="Demo baseline audit")


def seed() -> bool:
    """Seed the demo workspace once; returns True when it seeded."""
    if not data_config.DEMO_MODE:
        raise RuntimeError("demo_seed.seed() runs only in demo mode")
    marker = data_config.get_path(_SEEDED_MARKER)
    if os.path.isfile(marker):
        return False

    from core import db
    from security import user_manager
    from services import inventory_manager, tenant_telemetry

    db.migrate()
    username, password = credentials()
    if user_manager.get_role(username) is None:
        user_manager.create_user(username, password, role="super_admin", groups=None)

    _seed_inventory()
    by_ip = {d["IP"]: d for d in inventory_manager.get_all_devices()}
    _seed_backups(by_ip)
    _seed_segments()
    _seed_cve_snapshots(list(by_ip.values()))
    _seed_events()
    _seed_policy_snapshots()
    _seed_mac_history()
    _seed_audits(by_ip)
    # The legacy line is passive-only: no active scan, no polling.
    tenant_telemetry.save_tenant_telemetry("plant-legacy", {"ot_safe_mode": True}, username)

    with open(marker, "w", encoding="utf-8") as fh:
        fh.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    return True
