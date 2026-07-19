"""
Unit tests for fw_analyzers.panos.analyze (generic sections envelope).

Copre l'analizzatore firewall PAN-OS (Palo Alto) in formato 'set' CLI che
alimenta il tab Firewall del Config Analyzer: envelope
{"vendor","sections":[{id,label_key,columns,rows}]} con address/service
objects e gruppi, security/NAT rules, zone, VPN IKE/IPsec, amministratori e
autenticazione. Limitazione nota: XML PAN-OS non supportato (v1).
"""
import os
import unittest

import config_analyzer as ca
from fw_analyzers import panos

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "tests_data", "panos_sample.conf"),
          encoding="utf-8") as _fh:
    SAMPLE_CONFIG = _fh.read()


def _section(env, sid):
    return next(s for s in env["sections"] if s["id"] == sid)


def _rows(env, sid):
    return _section(env, sid)["rows"]


class TestPanosDetect(unittest.TestCase):
    def test_sniff_panos(self):
        self.assertEqual(ca.detect_config_type(SAMPLE_CONFIG), "panos")

    def test_vendor_override(self):
        self.assertEqual(ca.detect_config_type("hostname X",
                                               {"Vendor": "palo_alto"}), "panos")

    def test_not_panos(self):
        self.assertEqual(ca.detect_config_type("hostname SW\n!"), "ios")


class TestPanosEnvelope(unittest.TestCase):

    def setUp(self):
        self.env = panos.analyze(SAMPLE_CONFIG)

    def test_vendor_and_section_ids(self):
        self.assertEqual(self.env["vendor"], "panos")
        ids = [s["id"] for s in self.env["sections"]]
        self.assertEqual(ids, [
            "addresses", "address_groups", "services", "service_groups",
            "security_rules", "nat_rules", "zones", "vpn_ipsec",
            "administrators", "authentication",
        ])

    def test_sections_have_label_keys_and_columns(self):
        for s in self.env["sections"]:
            self.assertEqual(s["label_key"], f"fw.sec.{s['id']}")
            for c in s["columns"]:
                self.assertEqual(c["label_key"], f"fw.col.{c['key']}")

    def test_addresses(self):
        addr = {r["name"]: r for r in _rows(self.env, "addresses")}
        self.assertEqual(addr["SRV-WEB"]["type"], "ip-netmask")
        self.assertEqual(addr["SRV-WEB"]["value"], "10.1.10.5/32")
        self.assertEqual(addr["EXT-HOST"]["type"], "fqdn")
        self.assertEqual(addr["EXT-HOST"]["value"], "www.example.com")

    def test_address_group_members(self):
        grp = _rows(self.env, "address_groups")[0]
        self.assertEqual(grp["name"], "GRP-WEB")
        self.assertEqual(grp["members"], "SRV-WEB, DMZ-NET")

    def test_services_and_group(self):
        svc = {r["name"]: r for r in _rows(self.env, "services")}
        self.assertEqual(svc["SVC-HTTPS"]["protocol"], "tcp")
        self.assertEqual(svc["SVC-HTTPS"]["port"], "8443")
        self.assertEqual(svc["SVC-DNS"]["protocol"], "udp")
        sg = _rows(self.env, "service_groups")[0]
        self.assertEqual(sg["members"], "SVC-HTTPS, SVC-DNS")

    def test_security_rules(self):
        rows = {r["name"]: r for r in _rows(self.env, "security_rules")}
        self.assertEqual(rows["allow-web"]["from"], "trust")
        self.assertEqual(rows["allow-web"]["to"], "untrust")
        self.assertEqual(rows["allow-web"]["source"], "SRV-WEB")
        self.assertEqual(rows["allow-web"]["application"], "web-browsing")
        self.assertEqual(rows["allow-web"]["action"], "allow")
        self.assertEqual(rows["deny-all"]["action"], "deny")

    def test_nat_rules(self):
        nat = _rows(self.env, "nat_rules")[0]
        self.assertEqual(nat["name"], "snat-out")
        self.assertEqual(nat["source"], "DMZ-NET")
        self.assertEqual(nat["translation"], "ethernet1/3")

    def test_zones(self):
        zones = {r["name"]: r for r in _rows(self.env, "zones")}
        self.assertEqual(zones["trust"]["interfaces"], "ethernet1/1, ethernet1/2")
        self.assertEqual(zones["untrust"]["interfaces"], "ethernet1/3")

    def test_vpn(self):
        rows = {r["name"]: r for r in _rows(self.env, "vpn_ipsec")}
        self.assertEqual(rows["GW-SITE2"]["kind"], "ike-gateway")
        self.assertEqual(rows["GW-SITE2"]["peer"], "198.51.100.1")
        self.assertEqual(rows["TUN-SITE2"]["kind"], "ipsec-tunnel")
        self.assertEqual(rows["TUN-SITE2"]["peer"], "GW-SITE2")
        self.assertEqual(rows["TUN-SITE2"]["interface"], "tunnel.1")

    def test_administrators(self):
        rows = {r["name"]: r for r in _rows(self.env, "administrators")}
        self.assertEqual(rows["admin"]["role"], "superuser")
        self.assertEqual(rows["auditor"]["role"], "read-only")

    def test_authentication(self):
        rows = {r["name"]: r for r in _rows(self.env, "authentication")}
        self.assertEqual(rows["CORP-AUTH"]["kind"], "auth-profile")
        self.assertEqual(rows["CORP-AUTH"]["server"], "radius")
        self.assertEqual(rows["RAD-1"]["kind"], "radius")
        self.assertEqual(rows["RAD-1"]["server"], "10.0.0.50")
        self.assertEqual(rows["LDAP-1"]["server"], "10.0.0.60")

    def test_tolerant_of_empty_or_garbage_input(self):
        empty = panos.analyze("")
        self.assertEqual(empty["vendor"], "panos")
        self.assertTrue(all(s["rows"] == [] for s in empty["sections"]))
        panos.analyze("not a panos config\n\t***")
        panos.analyze(None)


if __name__ == "__main__":
    unittest.main()
