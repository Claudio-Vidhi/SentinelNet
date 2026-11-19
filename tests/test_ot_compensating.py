# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""OT compensating controls: one test per class and its boundaries, the
FortiOS IPS sensor parser, the route's tenant gate and the report collector.
Synthetic data only."""

import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from core import core_engine
from services import cve_intel, ot_compensating, ot_vuln_intel, segment_manager
from services.policy_test.fortios import parse_fortios_config

T = "tenant-a"
ASSET = {"IP": "192.0.2.10", "Hostname": "plc-cell-01", "Vendor": "siemens",
         "Group": T, "Purdue Level": "L1"}
FW = {"IP": "10.0.0.1", "Hostname": "fw-cell-01", "Vendor": "fortinet", "Group": T}
SEGMENTS = [
    {"id": "s1", "name": "Cell", "purdue_level": "L1", "subnets": ["192.0.2.0/24"]},
    {"id": "s2", "name": "Enterprise", "purdue_level": "L4", "subnets": ["198.51.100.0/24"]},
    {"id": "s3", "name": "DMZ", "purdue_level": "L3.5", "subnets": ["10.35.0.0/24"]},
]

_FGT_HEAD = """config system interface
    edit "port1"
        set ip 198.51.100.254 255.255.255.0
    next
    edit "port2"
        set ip 192.0.2.254 255.255.255.0
    next
    edit "port3"
        set ip 10.35.0.254 255.255.255.0
    next
end
config firewall address
    edit "JUMP-01"
        set subnet 10.35.0.5 255.255.255.255
    next
    edit "ENT-NET"
        set subnet 198.51.100.0 255.255.255.0
    next
end
"""


def _policy(srcaddr, extra=""):
    return f"""config firewall policy
    edit 7
        set name "To-Cell"
        set dstintf "port2"
        set srcaddr "{srcaddr}"
        set dstaddr "all"
        set action accept
        set service "ALL"
{extra}    next
end
"""


def _ips(action="block", cve='set cve "CVE-2024-60001"'):
    return f"""config ips sensor
    edit "OT-CVE"
        config entries
            edit 1
                {cve}
                set action {action}
            next
        end
    next
end
"""


_UTM = '        set utm-status enable\n        set ips-sensor "OT-CVE"\n'


def _snapshot(*cves):
    return {"device": ASSET["IP"], "query": {"confidence": "exact"},
            "cves": [dict({"id": "CVE-2024-60001", "cvss": 9.8, "kev": None, "services": []}, **c)
                     for c in cves]}


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="otcomp_")
        self.snapshots = {ASSET["IP"]: _snapshot({})}
        self.services = {}
        self.segments = list(SEGMENTS)
        for p in (
            patch.object(core_engine, "BACKUP_FOLDER", self.tmp),
            patch.object(cve_intel, "load", lambda d: self.snapshots.get(d.get("IP"), {})),
            patch.object(cve_intel, "device_services", lambda d: self.services),
            patch.object(segment_manager, "list_segments", lambda org: {"segments": self.segments}),
            patch.object(ot_vuln_intel, "lookup_kev", lambda cid: None),
            patch.object(ot_vuln_intel, "advisories_for_cve", lambda cid: []),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _backup(self, device, text):
        folder = os.path.join(self.tmp, T, device["Vendor"])
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{device['Hostname']}-{device['IP']}.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write(text)

    def _classify(self, devices=None):
        return ot_compensating.classify_tenant(T, devices or [ASSET, FW])

    def _one(self, devices=None):
        rows = self._classify(devices)["rows"]
        self.assertEqual(len(rows), 1, rows)
        return rows[0]


class TestFirewallClasses(_Base):
    def test_jump_host_32_from_l35_is_not_exposure(self):
        self._backup(FW, _FGT_HEAD + _policy("JUMP-01"))
        r = self._one()
        self.assertEqual(r["class"], "MITIGATED_BY_FIREWALL")
        self.assertEqual(r["severity"], "info")
        self.assertIn("jump_host", {e["kind"] for e in r["evidence"]})
        self.assertEqual(r["gateways"], [{"ip": "10.0.0.1", "config_type": "fortios"}])

    def test_subnet_24_from_l4_is_exposed(self):
        self._backup(FW, _FGT_HEAD + _policy("ENT-NET"))
        r = self._one()
        self.assertEqual(r["class"], "EXPOSED")
        self.assertEqual(r["severity"], "high")
        self.assertEqual((r["exposure"]["src_level"], r["exposure"]["rule_id"]), ("L4", "7"))

    def test_all_source_exposed_and_kev_is_critical(self):
        self.snapshots[ASSET["IP"]] = _snapshot({"kev": {"dateAdded": "2024-01-01"}})
        self._backup(FW, _FGT_HEAD + _policy("all"))
        r = self._one()
        self.assertEqual((r["class"], r["severity"], r["kev"]), ("EXPOSED", "critical", True))
        self.assertEqual(r["exposure"]["src_level"], "internet")
        self.assertFalse(r["ips_present_unverified"])

    def test_no_permit_is_mitigated_by_firewall(self):
        self._backup(FW, _FGT_HEAD)
        r = self._one()
        self.assertEqual(r["class"], "MITIGATED_BY_FIREWALL")
        self.assertEqual(r["exposure"], None)

    def test_cisco_svi_outbound_acl(self):
        sw = {"IP": "10.0.0.2", "Hostname": "sw-l3-01", "Vendor": "cisco", "Group": T}
        self._backup(sw, """hostname sw-l3-01
ip access-list extended OT-OUT
 permit tcp host 10.35.0.5 any eq 22
 deny ip any any
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group OT-OUT out
interface Vlan20
 ip address 10.35.0.1 255.255.255.0
end
""")
        self.snapshots[ASSET["IP"]] = _snapshot({"services": ["ssh"]})
        r = self._one([ASSET, sw])
        self.assertEqual(r["class"], "MITIGATED_BY_FIREWALL", r)
        self.assertEqual(r["ports"], ["tcp/22"])

    def test_cisco_unnumbered_aces_are_not_confused_with_the_jump_host_ace(self):
        # Both ACEs carry the parser id 'ext': the permit-any one must not
        # inherit the jump-host exception of the first.
        sw = {"IP": "10.0.0.2", "Hostname": "sw-l3-01", "Vendor": "cisco", "Group": T}
        self._backup(sw, """hostname sw-l3-01
ip access-list extended OT-OUT
 permit tcp host 10.35.0.5 any eq 22
 permit ip any any
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 ip access-group OT-OUT out
end
""")
        self.snapshots[ASSET["IP"]] = _snapshot({"services": ["ssh"]})
        r = self._one([ASSET, sw])
        self.assertEqual(r["class"], "EXPOSED", r)
        self.assertEqual(r["exposure"]["rule_name"], "OT-OUT")


    _L2_SWITCH = {"IP": "10.0.0.3", "Hostname": "sw-cell-01", "Vendor": "cisco", "Group": T}
    _L2_CFG = """hostname sw-cell-01
{routing}interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
interface Vlan10
 ip address 192.0.2.2 255.255.255.0
end
"""

    def test_l2_switch_management_svi_is_not_a_gateway(self):
        # Behind a denying firewall, an ACL-less management SVI must not
        # turn the asset into EXPOSED.
        self._backup(FW, _FGT_HEAD)
        self._backup(self._L2_SWITCH, self._L2_CFG.format(routing=""))
        r = self._one([ASSET, FW, self._L2_SWITCH])
        self.assertEqual(r["class"], "MITIGATED_BY_FIREWALL", r)
        self.assertEqual([g["ip"] for g in r["gateways"]], [FW["IP"]])

    def test_switch_with_ip_routing_is_a_gateway(self):
        self._backup(FW, _FGT_HEAD)
        self._backup(self._L2_SWITCH, self._L2_CFG.format(routing="ip routing\n"))
        r = self._one([ASSET, FW, self._L2_SWITCH])
        self.assertIn(self._L2_SWITCH["IP"], [g["ip"] for g in r["gateways"]])
        self.assertEqual(r["class"], "EXPOSED", r)

    def test_router_with_no_ip_routing_is_not_a_gateway(self):
        sw = dict(self._L2_SWITCH, Hostname="rtr-cell-01")
        self._backup(FW, _FGT_HEAD)
        self._backup(sw, "hostname rtr-cell-01\nno ip routing\ninterface Vlan10\n"
                         " ip address 192.0.2.2 255.255.255.0\nend\n")
        r = self._one([ASSET, FW, sw])
        self.assertEqual([g["ip"] for g in r["gateways"]], [FW["IP"]])


class TestIpsClasses(_Base):
    def test_ips_block_naming_cve_is_mitigated_by_ips(self):
        self._backup(FW, _FGT_HEAD + _ips("block") + _policy("all", _UTM))
        r = self._one()
        self.assertEqual(r["class"], "MITIGATED_BY_IPS")
        self.assertEqual((r["evidence"][0]["sensor"], r["evidence"][0]["entry"]), ("OT-CVE", "1"))

    def test_ips_monitor_is_exposed_unverified(self):
        self._backup(FW, _FGT_HEAD + _ips("monitor") + _policy("all", _UTM))
        r = self._one()
        self.assertEqual(r["class"], "EXPOSED")
        self.assertTrue(r["ips_present_unverified"])

    def test_generic_sensor_is_exposed_unverified(self):
        self._backup(FW, _FGT_HEAD + _ips("block", "set severity high critical") + _policy("all", _UTM))
        r = self._one()
        self.assertEqual(r["class"], "EXPOSED")
        self.assertTrue(r["ips_present_unverified"])

    def test_sensor_without_utm_status_is_plain_exposed(self):
        self._backup(FW, _FGT_HEAD + _ips("block") + _policy("all", '        set ips-sensor "OT-CVE"\n'))
        r = self._one()
        self.assertEqual(r["class"], "EXPOSED")
        self.assertFalse(r["ips_present_unverified"])


class TestScopeAndAttributes(_Base):
    def test_missing_gateway_backup_is_not_evaluated(self):
        fw_nobackup = dict(FW, IP="192.0.2.254")
        r = self._one([ASSET, fw_nobackup])
        self.assertEqual((r["class"], r["severity"]), ("NOT_EVALUATED", "medium"))
        self.assertEqual(r["reason"], "gateway_no_backup:192.0.2.254")

    def test_no_gateway_is_not_evaluated(self):
        r = self._one([ASSET])
        self.assertEqual((r["class"], r["reason"]), ("NOT_EVALUATED", "no_gateway"))

    def test_low_cvss_without_kev_is_excluded(self):
        self.snapshots[ASSET["IP"]] = _snapshot({"cvss": 5.0})
        self._backup(FW, _FGT_HEAD + _policy("all"))
        res = self._classify()
        self.assertEqual((res["rows"], res["assets_evaluated"]), ([], 0))

    def test_non_ot_asset_is_excluded(self):
        self._backup(FW, _FGT_HEAD + _policy("all"))
        it_host = dict(ASSET, IP="198.51.100.20", **{"Purdue Level": ""})
        self.snapshots = {it_host["IP"]: _snapshot({})}
        self.assertEqual(self._classify([it_host, FW])["rows"], [])

    def test_maintenance_window_sets_patch_planned_only(self):
        self._backup(FW, _FGT_HEAD + _policy("all"))
        plain = self._one()
        planned = self._one([dict(ASSET, **{"Maintenance Window": "Sun 02:00-06:00"}), FW])
        self.assertFalse(plain["patch_planned"])
        self.assertTrue(planned["patch_planned"])
        self.assertEqual(plain["class"], planned["class"])
        self.assertEqual(plain["severity"], planned["severity"])

    def test_service_disabled_only_when_every_named_service_is_disabled(self):
        self._backup(FW, _FGT_HEAD + _policy("all"))
        self.services = {"ssh": False, "http": False}
        self.snapshots[ASSET["IP"]] = _snapshot({"services": ["ssh"]})
        self.assertEqual(self._one()["class"], "SERVICE_DISABLED")
        # snmp state unknown: not every named service is known-disabled.
        self.snapshots[ASSET["IP"]] = _snapshot({"services": ["ssh", "snmp"]})
        r = self._one()
        self.assertEqual(r["class"], "EXPOSED")
        self.assertEqual(r["ports"], ["tcp/22", "udp/161"])
        # No services named: never SERVICE_DISABLED, full surface checked.
        self.snapshots[ASSET["IP"]] = _snapshot({})
        r = self._one()
        self.assertEqual(r["class"], "EXPOSED")
        self.assertIn("tcp/502", r["ports"])
        self.assertIn("udp/47808", r["ports"])

    def test_other_tenant_devices_are_ignored(self):
        self._backup(FW, _FGT_HEAD + _policy("all"))
        foreign = dict(ASSET, Group="tenant-b")
        self.assertEqual(self._classify([foreign, FW])["rows"], [])


class TestFortiosIpsParser(unittest.TestCase):
    def test_ips_sensor_and_policy_fields(self):
        env = parse_fortios_config(_FGT_HEAD + _ips("block", 'set cve "cve-2024-60001" "CVE-2024-60002"')
                                   + _policy("all", _UTM))
        self.assertEqual(env.ips_sensors["OT-CVE"], [{
            "id": "1", "cve": ["CVE-2024-60001", "CVE-2024-60002"], "action": "block",
            "status": "enable", "filtered": False}])
        self.assertEqual(env.policy_ips["7"], {"utm_status": True, "ips_sensor": "OT-CVE"})
        generic = parse_fortios_config(_ips("block", "set severity critical"))
        self.assertTrue(generic.ips_sensors["OT-CVE"][0]["filtered"])
        self.assertEqual(generic.ips_sensors["OT-CVE"][0]["cve"], [])


_JUNOS_ZONES = """set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.2/30
set interfaces ge-0/0/1 unit 0 family inet address 10.10.0.1/24
set interfaces ge-0/0/2 unit 0 family inet address 10.20.0.1/24
set security zones security-zone untrust interfaces ge-0/0/0.0
set security zones security-zone ot interfaces ge-0/0/1.0
set security zones security-zone mgmt interfaces ge-0/0/2.0
{route}set security policies from-zone mgmt to-zone ot policy deny-mgmt match source-address any
set security policies from-zone mgmt to-zone ot policy deny-mgmt match destination-address any
set security policies from-zone mgmt to-zone ot policy deny-mgmt match application any
set security policies from-zone mgmt to-zone ot policy deny-mgmt then deny
set security policies from-zone untrust to-zone ot policy open match source-address any
set security policies from-zone untrust to-zone ot policy open match destination-address any
set security policies from-zone untrust to-zone ot policy open match application any
set security policies from-zone untrust to-zone ot policy open then permit
"""


class TestIngressDerivation(unittest.TestCase):
    """The ingress of a remote source decides which zone-scoped policy or
    inbound ACL applies: guessing wrong turns an open path into a mitigation."""

    def _junos(self, route):
        from services.policy_test.junos import parse_junos_config
        return parse_junos_config(_JUNOS_ZONES.format(route=route))

    def test_junos_nexthop_only_static_resolves_ingress(self):
        env = self._junos("set routing-options static route 0.0.0.0/0 next-hop 198.51.100.1\n")
        trace = ot_compensating._evaluate_flow(env, "203.0.113.1", "10.10.0.5", "tcp", 502)
        self.assertEqual(trace.verdict, "PERMIT", trace.to_dict())
        self.assertEqual([s.rule_id for s in trace.steps if s.kind == "policy"],
                         ["untrust->ot:open"])

    def test_junos_no_route_to_source_is_unknown(self):
        trace = ot_compensating._evaluate_flow(self._junos(""), "203.0.113.1", "10.10.0.5",
                                               "tcp", 502)
        self.assertEqual(trace.verdict, "UNKNOWN", trace.to_dict())

    def test_ios_inbound_acl_without_route_to_source_is_unknown(self):
        from services.policy_test.ios import parse_ios_config
        env = parse_ios_config("""hostname rtr-01
ip access-list extended WAN-IN
 deny ip any any
interface GigabitEthernet0/0
 ip address 10.1.0.1 255.255.255.0
 ip access-group WAN-IN in
interface GigabitEthernet0/1
 ip address 10.10.0.1 255.255.255.0
end
""")
        trace = ot_compensating._evaluate_flow(env, "203.0.113.1", "10.10.0.5", "tcp", 502)
        self.assertEqual(trace.verdict, "UNKNOWN", trace.to_dict())
        # The downstream row builder must digest the note-only trace.
        gw = {"env": env, "config_type": "ios", "device": {"IP": "10.1.0.1"}}
        r = ot_compensating._flow_result(gw, "203.0.113.1", "internet", "10.10.0.5",
                                         "tcp", 502, lambda ip: "")
        self.assertEqual((r["verdict"], r["rule_id"]), ("UNKNOWN", ""))
        self.assertIn("ingress interface", r["rule_name"])


class TestGatewayCandidates(unittest.TestCase):
    def test_backup_removed_after_lookup_is_unsupported_not_a_crash(self):
        from ai import config_analyzer
        # IOS takes the routing pre-check, which read the file outside the try.
        sw = {"IP": "10.0.0.2", "Hostname": "sw-l3-01", "Vendor": "cisco", "Group": T}
        gone = os.path.join(tempfile.gettempdir(), "otcomp-missing", "sw.txt")
        with patch.object(config_analyzer, "_find_freshest_backup", lambda ip, t: (gone, None)):
            out = ot_compensating._load_gateway_candidates(T, [sw])
        self.assertEqual([(c["env"], c["reason"]) for c in out], [(None, "gateway_unsupported")])


class TestStatusReportCollector(_Base):
    def test_kev_exposed_is_gap(self):
        from services.status_report import evidence
        self.snapshots[ASSET["IP"]] = _snapshot({"kev": {"dateAdded": "2024-01-01"}},
                                                {"id": "CVE-2024-60002", "cvss": 7.5})
        self._backup(FW, _FGT_HEAD + _policy("all"))
        res = evidence.collect_ot_compensating_controls(T, [ASSET, FW], 30)
        m = res["metrics"]
        self.assertTrue(res["available"])
        self.assertEqual((m["cves_in_scope"], m["exposed"], m["kev_exposed"]), (2, 2, 1))
        self.assertEqual(m["exposed_pct"], 100.0)
        spec = evidence.load_mapping()["evidence"]["ot_compensating_controls"]
        self.assertEqual(evidence.status_of(res, spec), "gap")
        self.assertEqual(res["rows"][0]["control_class"], "EXPOSED")

    def test_not_evaluated_is_partial_and_empty_is_not_available(self):
        from services.status_report import evidence
        spec = evidence.load_mapping()["evidence"]["ot_compensating_controls"]
        res = evidence.collect_ot_compensating_controls(T, [ASSET], 30)
        self.assertEqual(evidence.status_of(res, spec), "partial")
        self.snapshots = {}
        res = evidence.collect_ot_compensating_controls(T, [ASSET], 30)
        self.assertEqual(evidence.status_of(res, spec), "not_available")


class TestRoute(unittest.TestCase):
    PW = "PasswordSicura1!"

    def setUp(self):
        from core import data_config, db
        from security import security_manager, user_manager
        from services import inventory_manager
        self.tmp = tempfile.mkdtemp(prefix="otcomp_route_")
        for p in (
            patch.object(data_config, "DATA_DIR", self.tmp),
            patch.object(user_manager, "USERS_JSON", os.path.join(self.tmp, "users.json")),
            patch.object(inventory_manager, "HOSTS_CSV", os.path.join(self.tmp, "network_hosts.csv")),
            patch.object(core_engine, "BACKUP_FOLDER", self.tmp),
        ):
            p.start()
            self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        db.migrate()
        inventory_manager.save_groups({T: {"description": ""}, "tenant-b": {"description": ""}})
        user_manager.create_user("op_a", self.PW, role="operator", groups=[T])

    def test_auth_and_tenant_boundary(self):
        import app_server
        url = "/api/cve/ot/compensating"
        client = TestClient(app_server.app, raise_server_exceptions=False)
        self.assertEqual(client.get(url, params={"tenant": T}).status_code, 401)
        r = client.post("/api/auth/login", json={"username": "op_a", "password": self.PW})
        self.assertEqual(r.status_code, 200, r.text)
        headers = {"Authorization": f"Bearer {r.json()['access_token']}", "X-Requested-With": "1"}
        self.assertEqual(client.get(url, params={"tenant": "tenant-b"}, headers=headers).status_code, 403)
        self.assertEqual(client.get(url, headers=headers).status_code, 400)
        r = client.get(url, params={"tenant": T}, headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["summary"]["EXPOSED"], 0)
        self.assertEqual(set(r.json()), {"rows", "summary", "assets_evaluated"})


if __name__ == "__main__":
    unittest.main()
