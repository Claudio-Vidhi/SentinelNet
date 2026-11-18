# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Launch SentinelNet with an isolated, seeded OT demo workspace.

All seeded data is synthetic (RFC 5737 documentation subnets and generic OT
hostnames) and lives under ``data/ot-demo`` (gitignored).

Usage::

    uv run python scripts/dev/run_ot_demo.py
    uv run python scripts/dev/run_ot_demo.py --reset --port 8931
    uv run python scripts/dev/run_ot_demo.py --seed-only
"""

import argparse
import json
import os
import shutil
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEMO_DATA_DIR = os.path.join(REPO_ROOT, "data", "ot-demo")
DEMO_USER = "admin"
DEMO_PASS = "Sentinel!Demo2026"


def _seed_events(db) -> None:
    now = int(time.time())
    rows = [
        # Healthy physical interface on plant-demo L2 switch + ignored virtual SVI
        (
            now, now, "plant-demo", "snmp", "interface.state", "interface",
            "192.0.2.20:Gi1/0/1", 6, "192.0.2.20", "Gi1/0/1", "", "", None, "",
            json.dumps({"admin_status": "up", "link": "up"}), "demo-pd-gi1",
        ),
        (
            now, now, "plant-demo", "snmp", "interface.state", "interface",
            "192.0.2.20:Vlan10", 6, "192.0.2.20", "Vlan10", "", "", None, "",
            json.dumps({"admin_status": "up", "link": "down"}), "demo-pd-vlan10",
        ),
        # Segregated Modbus TCP flow inside plant-demo L1 cell
        (
            now, now, "plant-demo", "syslog", "flow", "flow",
            "192.0.2.30>192.0.2.10", 6, "192.0.2.40", "", "192.0.2.30", "192.0.2.10", 502, "tcp",
            json.dumps({"ot_protocol": "modbus_tcp", "action": "accept"}), "demo-pd-modbus",
        ),
        # plant-legacy findings: unused physical port left admin_up + unsegregated S7comm flow
        (
            now, now, "plant-legacy", "snmp", "interface.state", "interface",
            "198.51.100.10:Fa0/4", 4, "198.51.100.10", "Fa0/4", "", "", None, "",
            json.dumps({"admin_status": "up", "link": "down"}), "demo-pl-fa04",
        ),
        (
            now, now, "plant-legacy", "syslog", "flow", "flow",
            "203.0.113.50>198.51.100.20", 3, "198.51.100.1", "", "203.0.113.50", "198.51.100.20", 102, "tcp",
            json.dumps({"ot_protocol": "s7comm", "action": "accept"}), "demo-pl-s7",
        ),
    ]
    conn = db.get_observability_connection()
    try:
        conn.executemany(
            "INSERT OR IGNORE INTO events "
            "(ts, ingested_ts, tenant, source, event_type, entity_type, entity_id, severity, "
            "device_ip, interface, src_ip, dst_ip, dst_port, protocol, attrs_json, dedup_key) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def seed_demo(reset: bool = False) -> None:
    if reset:
        shutil.rmtree(DEMO_DATA_DIR, ignore_errors=True)
    already_seeded = os.path.isfile(os.path.join(DEMO_DATA_DIR, "users.json"))
    os.makedirs(DEMO_DATA_DIR, exist_ok=True)

    from core import backup_store, db
    from security import user_manager
    from services import inventory_manager, inventory_store, probe_manager, segment_manager

    db.migrate()
    if already_seeded and not reset:
        return

    if user_manager.get_role(DEMO_USER) is None:
        user_manager.create_user(DEMO_USER, DEMO_PASS, role="super_admin", groups=None)

    inventory_manager.save_groups({
        "plant-demo": {"description": "Demo Plant OT (Compliant)"},
        "plant-legacy": {"description": "Demo Legacy Plant OT (Findings)"},
    })
    with inventory_manager._db() as conn:
        inventory_store.write_locations(conn, {
            "loc-cell1": {
                "org": "plant-demo",
                "name": "Cell L1 (Compliant)",
                "role": "branch",
                "subnets": ["192.0.2.0/24"],
                "probe": "central",
            },
            "loc-legacy": {
                "org": "plant-legacy",
                "name": "Legacy Line",
                "role": "branch",
                "subnets": ["198.51.100.0/24"],
                "probe": "central",
            },
        })

    jump, _ = probe_manager.create_probe(
        name="ot-bastion",
        mode="jump",
        jump_host="10.10.0.5",
        jump_port=22,
        jump_identity="ot-jump-id",
    )

    # Compliant OT cell (plant-demo)
    inventory_manager.add_or_update_device(
        ip="192.0.2.10", hostname="plc-01", vendor="siemens", profile="default",
        username="", password="", enable_secret="", group="plant-demo",
        location="loc-cell1", transports={"ssh": 22}, snmp_disabled=True,
        purdue_level="L1", probe=jump["id"],
        process_criticality="scheduled_shutdown", maintenance_window="Sun 02:00-06:00",
    )
    inventory_manager.add_or_update_device(
        ip="192.0.2.20", hostname="switch-01", vendor="siemens_scalance", profile="default",
        username="", password="", enable_secret="", group="plant-demo",
        location="loc-cell1", transports={"ssh": 22}, snmp_disabled=True,
        purdue_level="L2", probe=jump["id"],
    )
    inventory_manager.add_or_update_device(
        ip="192.0.2.30", hostname="hmi-01", vendor="rockwell", profile="default",
        username="", password="", enable_secret="", group="plant-demo",
        location="loc-cell1", transports={"restconf": 443}, snmp_disabled=True,
        purdue_level="L2", probe=jump["id"],
        process_criticality="mission_critical", maintenance_window="Planned turnaround only",
    )
    inventory_manager.add_or_update_device(
        ip="192.0.2.40", hostname="fw-dmz-01", vendor="fortinet", profile="default",
        username="", password="", enable_secret="", group="plant-demo",
        location="loc-cell1", transports={"manual": True}, snmp_disabled=True,
        purdue_level="L3.5", probe=jump["id"],
    )
    inventory_manager.add_or_update_device(
        ip="192.0.2.254", hostname="sw-core-01", vendor="cisco", profile="default",
        username="", password="", enable_secret="", group="plant-demo",
        location="loc-cell1", transports={"manual": True}, snmp_disabled=True,
        purdue_level="L3", probe="central",
    )

    # Legacy OT site with findings (plant-legacy)
    inventory_manager.add_or_update_device(
        ip="198.51.100.10", hostname="switch-legacy-01", vendor="moxa", profile="default",
        username="", password="", enable_secret="", group="plant-legacy",
        location="loc-legacy", transports={"telnet": 23}, snmp_community="public",
        purdue_level="L2", probe="central",
    )
    inventory_manager.add_or_update_device(
        ip="198.51.100.20", hostname="plc-legacy-01", vendor="siemens", profile="default",
        username="", password="", enable_secret="", group="plant-legacy",
        location="loc-legacy", transports={"telnet": 23}, snmp_disabled=True,
        purdue_level="L1", probe="central",
    )

    by_ip = {d["IP"]: d for d in inventory_manager.get_all_devices()}
    backup_store.save_ot_artifact(
        by_ip["192.0.2.10"], "line1_plc.zap18", b"TIA-PORTAL-DEMO-V18",
        uploaded_by=DEMO_USER, project_version="v1.8", notes="Commissioning golden backup",
    )
    backup_store.save_ot_artifact(
        by_ip["192.0.2.20"], "switch01_scl.scd", b"<SCL version='2007B'/>",
        uploaded_by=DEMO_USER, project_version="rev-2", notes="IEC 61850 substation config",
    )
    backup_store.save_ot_artifact(
        by_ip["192.0.2.30"], "hmi01_panel.hmi", b"HMI-RUNTIME-DEMO",
        uploaded_by=DEMO_USER, project_version="v3.1", notes="Operator HMI backup",
    )
    fw_demo_cfg = """config system interface
    edit "port1"
        set ip 10.20.0.1 255.255.255.0
        set alias "it-uplink"
    next
    edit "port2"
        set ip 172.16.10.1 255.255.255.252
        set alias "ot-core-transit"
    next
end
config firewall address
    edit "IT-ENG-NET"
        set subnet 10.20.0.0 255.255.255.0
    next
    edit "OT-CELL-NET"
        set subnet 192.0.2.0 255.255.255.0
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
end
config firewall service custom
    edit "MODBUS-TCP"
        set tcp-portrange 502
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
end
"""
    sw_core_cfg = """hostname sw-core-01
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
    backup_store.save_backup(by_ip["192.0.2.40"], "fw-dmz-01", fw_demo_cfg)
    backup_store.save_backup(by_ip["192.0.2.254"], "sw-core-01", sw_core_cfg)
    backup_store.save_backup(by_ip["198.51.100.10"], "switch-legacy-01", "ip http server\n")

    segment_manager.save_segment(
        "plant-demo", None, "Cell L1 PLC/HMI", "sky",
        subnets=["192.0.2.0/24"], purdue_level="L1",
        members=["192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.254"],
    )
    segment_manager.save_segment(
        "plant-demo", None, "IT/OT DMZ", "amber",
        subnets=["10.20.0.0/24"], purdue_level="L3.5",
        members=["192.0.2.40"],
    )
    _seed_events(db)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SentinelNet OT demo instance")
    parser.add_argument("--port", type=int, default=8931, help="HTTP port (default: 8931)")
    parser.add_argument("--reset", action="store_true", help="Reset demo workspace before starting")
    parser.add_argument("--seed-only", action="store_true", help="Seed demo workspace and exit")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()

    os.environ["SENTINELNET_DATA_DIR"] = DEMO_DATA_DIR
    os.environ["SENTINELNET_PORT"] = str(args.port)
    if args.no_browser:
        os.environ["SENTINELNET_NO_BROWSER"] = "true"

    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)

    seed_demo(reset=args.reset)
    print(f"OT demo workspace ready in: {DEMO_DATA_DIR}")
    print(f"Login: {DEMO_USER} / {DEMO_PASS}")
    if args.seed_only:
        return 0

    import app_server

    sys.argv = [sys.argv[0]] + (["--no-browser"] if args.no_browser else [])
    app_server.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
