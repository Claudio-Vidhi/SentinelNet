# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-vendor parity tests for PAN-OS, Junos, Cisco NX-OS, and OT switches."""

import unittest

from ai import config_analyzer
from drivers.paloalto_panos import parse_panos_xml_config, parse_panos_xml_routes
from services import route_table
from services.netsec_audit.benchmarks import cis_junos, cis_nxos, cis_panos, iec62443_ot
from services.path_trace import trace
from services.policy_test.engine import evaluate
from services.policy_test.junos import parse_junos_config
from services.policy_test.model import Flow
from services.policy_test.panos import parse_panos_config

PANOS_XML = """<config>
  <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
    <zone>
      <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="ot-dmz"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <address>
      <entry name="IT-NET"><ip-netmask>10.20.0.0/24</ip-netmask></entry>
      <entry name="OT-PLC"><ip-netmask>192.0.2.10/32</ip-netmask></entry>
      <entry name="UNUSED-OBJ"><ip-netmask>198.51.100.77/32</ip-netmask></entry>
    </address>
    <service>
      <entry name="MODBUS-502"><protocol><tcp><port>502</port></tcp></protocol></entry>
    </service>
    <rulebase>
      <nat><rules>
        <entry name="DNAT-PLC">
          <from><member>untrust</member></from>
          <to><member>ot-dmz</member></to>
          <source><member>IT-NET</member></source>
          <destination><member>203.0.113.50</member></destination>
          <destination-translation><translated-address>192.0.2.10</translated-address></destination-translation>
        </entry>
      </rules></nat>
      <security><rules>
        <entry name="ALLOW-MODBUS">
          <from><member>untrust</member></from>
          <to><member>ot-dmz</member></to>
          <source><member>IT-NET</member></source>
          <destination><member>OT-PLC</member></destination>
          <service><member>MODBUS-502</member></service>
          <action>allow</action>
        </entry>
        <entry name="DISABLED-TELNET" disabled="yes">
          <from><member>any</member></from>
          <to><member>any</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <service><member>any</member></service>
          <action>allow</action>
        </entry>
      </rules></security>
    </rulebase>
  </entry></vsys></entry></devices>
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.10/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="172.16.10.1/30"/></ip></layer3></entry>
  </ethernet></interface>
  <virtual-router><entry name="default"><routing-table><ip><static-route>
    <entry name="to-ot"><destination>192.0.2.0/24</destination><nexthop><ip-address>172.16.10.2</ip-address></nexthop><interface>ethernet1/2</interface></entry>
  </static-route></ip></routing-table></entry></virtual-router></network>
</config>"""

PANOS_SET = """set deviceconfig system hostname pa-ot-gw
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.10/24
set network interface ethernet ethernet1/2 layer3 ip 172.16.10.1/30
set zone untrust network layer3 ethernet1/1
set zone ot-dmz network layer3 ethernet1/2
set address IT-NET ip-netmask 10.20.0.0/24
set address OT-PLC ip-netmask 192.0.2.10/32
set service MODBUS-502 protocol tcp port 502
set network virtual-router default routing-table ip static-route ot destination 192.0.2.0/24 nexthop ip-address 172.16.10.2 interface ethernet1/2
set rulebase security rules ALLOW-MODBUS from untrust
set rulebase security rules ALLOW-MODBUS to ot-dmz
set rulebase security rules ALLOW-MODBUS source IT-NET
set rulebase security rules ALLOW-MODBUS destination OT-PLC
set rulebase security rules ALLOW-MODBUS service MODBUS-502
set rulebase security rules ALLOW-MODBUS action allow
"""

JUNOS_SET = """set system host-name srx-ot-01
set system services telnet
set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.20/24
set interfaces ge-0/0/1 unit 0 family inet address 172.16.20.1/30
set security zones security-zone untrust interfaces ge-0/0/0.0
set security zones security-zone ot-zone interfaces ge-0/0/1.0
set security address-book global address IT-NET 10.20.0.0/24
set security address-book global address OT-PLC 192.0.2.10/32
set applications application MODBUS-TCP protocol tcp destination-port 502
set routing-options static route 192.0.2.0/24 next-hop 172.16.20.2
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS match source-address IT-NET
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS match destination-address OT-PLC
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS match application MODBUS-TCP
set security policies from-zone untrust to-zone ot-zone policy ALLOW-MODBUS then permit
"""


class TestMultiVendorParity(unittest.TestCase):
    def test_detect_config_type_multivendor(self):
        self.assertEqual(config_analyzer.detect_config_type(PANOS_SET), "panos")
        self.assertEqual(config_analyzer.detect_config_type(PANOS_XML), "panos")
        self.assertEqual(config_analyzer.detect_config_type(JUNOS_SET), "junos")
        nxos = "feature vpc\nfeature ospf\nvrf context OT\n"
        self.assertEqual(config_analyzer.detect_config_type(nxos), "nxos")

    def test_panos_xml_and_set_policy_evaluation(self):
        parsed_xml = parse_panos_xml_config(PANOS_XML)
        self.assertEqual(len(parsed_xml["security_rules"]), 2)
        self.assertEqual(len(parsed_xml["nat_rules"]), 1)

        for cfg in (PANOS_XML, PANOS_SET):
            env = parse_panos_config(cfg)
            permit_trace = evaluate(
                env, Flow(src_ip="10.20.0.5", dst_ip="192.0.2.10", proto="tcp", dport=502, ingress_intf="ethernet1/1")
            )
            self.assertEqual(permit_trace.verdict, "PERMIT")

            deny_trace = evaluate(
                env, Flow(src_ip="10.20.0.5", dst_ip="192.0.2.10", proto="tcp", dport=22, ingress_intf="ethernet1/1")
            )
            self.assertEqual(deny_trace.verdict, "DENY")

    def test_junos_policy_evaluation(self):
        env = parse_junos_config(JUNOS_SET)
        self.assertEqual(env.hostname, "srx-ot-01")
        ok = evaluate(
            env, Flow(src_ip="10.20.0.8", dst_ip="192.0.2.10", proto="tcp", dport=502, ingress_intf="ge-0/0/0.0")
        )
        self.assertEqual(ok.verdict, "PERMIT")

        blocked = evaluate(
            env, Flow(src_ip="10.20.0.8", dst_ip="192.0.2.10", proto="tcp", dport=23, ingress_intf="ge-0/0/0.0")
        )
        self.assertEqual(blocked.verdict, "DENY")

    def test_route_parsers_panos_junos_nxos_ot(self):
        panos_routes_xml = """<response status="success"><result>
          <entry><destination>192.0.2.0/24</destination><nexthop>172.16.10.2</nexthop><interface>ethernet1/2</interface><flags>A S</flags><metric>10</metric><virtual-router>default</virtual-router></entry>
          <entry><destination>203.0.113.0/24</destination><nexthop>0.0.0.0</nexthop><interface>ethernet1/1</interface><flags>A C</flags><metric>0</metric><virtual-router>default</virtual-router></entry>
        </result></response>"""
        pr = parse_panos_xml_routes(panos_routes_xml)
        self.assertEqual(len(pr), 2)
        self.assertEqual(pr[0]["type"], "static")
        self.assertEqual(pr[1]["type"], "connected")

        junos_out = (
            "inet.0: 2 destinations, 2 routes\n"
            "192.0.2.0/24 *[Static/5] 1d 02:00:00\n"
            "              > to 172.16.20.2 via ge-0/0/1.0\n"
            "203.0.113.0/24 *[Direct/0] 2d 00:00:00\n"
            "              > via ge-0/0/0.0\n"
        )
        jr = route_table.parse_junos_routes(junos_out)
        self.assertEqual(len(jr), 2)
        self.assertEqual(jr[0]["gateway"], "172.16.20.2")
        self.assertEqual(jr[1]["type"], "connected")

        nxos_out = (
            "IP Route Table for VRF \"default\"\n"
            "192.0.2.0/24, ubest/mbest: 1/0\n"
            "    *via 172.16.30.2, Vlan10, [1/0], 01:02:03, static\n"
        )
        nr = route_table.parse_nxos_routes(nxos_out)
        self.assertEqual(len(nr), 1)
        self.assertEqual(nr[0]["type"], "static")

        ot_out = "ip default-gateway 198.51.100.1\n192.0.2.0 255.255.255.0 198.51.100.254 1 Vlan1\n"
        otr = route_table.parse_ot_switch_routes(ot_out)
        self.assertGreaterEqual(len(otr), 1)

    def test_netsec_benchmarks_cover_all_new_vendors(self):
        self.assertGreater(len(cis_panos.RULES), 0)
        self.assertGreater(len(cis_junos.RULES), 0)
        self.assertGreater(len(cis_nxos.RULES), 0)
        self.assertGreater(len(iec62443_ot.RULES), 0)

    def test_path_trace_multivendor_panos_to_junos(self):
        rows_by_device = {
            "203.0.113.10": [
                {"device": "fw-edge-pa", "device_ip": "203.0.113.10",
                 "network": "192.0.2.0/24", "gateway": "203.0.113.20",
                 "interface": "ethernet1/2", "type": "static", "distance": 10, "metric": 0, "from_backup": True},
            ],
            "203.0.113.20": [
                {"device": "fw-branch-srx", "device_ip": "203.0.113.20",
                 "network": "192.0.2.0/24", "gateway": "",
                 "interface": "ge-0/0/1.0", "type": "connected", "distance": 0, "metric": 0, "from_backup": True},
            ],
        }
        addresses = {
            "203.0.113.10": [{"iface": "ethernet1/2", "ip": "203.0.113.10", "network": "203.0.113.0/24"}],
            "203.0.113.20": [
                {"iface": "ge-0/0/0.0", "ip": "203.0.113.20", "network": "203.0.113.0/24"},
                {"iface": "ge-0/0/1.0", "ip": "192.0.2.1", "network": "192.0.2.0/24"},
            ],
        }
        devices_by_ip = {
            "203.0.113.10": {"IP": "203.0.113.10", "Hostname": "fw-edge-pa", "Vendor": "paloalto"},
            "203.0.113.20": {"IP": "203.0.113.20", "Hostname": "fw-branch-srx", "Vendor": "juniper"},
        }
        res = trace("192.0.2.10", "203.0.113.10", rows_by_device, addresses, devices_by_ip,
                    src_ip="10.20.0.5", proto="tcp", dport=502)
        self.assertEqual(res["outcome"], "consegna")
        self.assertEqual(len(res["hops"]), 2)


if __name__ == "__main__":
    unittest.main()
