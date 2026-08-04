# -*- coding: utf-8 -*-
"""Chi instrada questa VLAN: la risposta si deduce dai backup, e quando non si
puo' dedurre lo si dice invece di indovinare.

Le due distinzioni che contano: un apparato illeggibile rende la risposta
IGNOTA, non "nessuna rotta"; e un tenant None (non si sa) non e' un tenant
vuoto (quello predefinito).
"""
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_vlanroute_"))

from services import vlan_routing  # noqa: E402


def _ios(ip, vlan, svi_ip, shutdown=False, tenant="sede-a", backup_ts=1000):
    return {"ip": ip, "tenant": tenant, "backup_ts": backup_ts,
            "vlans": [{"id": str(vlan), "svi": {"ip": svi_ip,
                                                "shutdown": shutdown}}],
            "firewall": None}


def _fgt(ip, vlan, iface_ip, status="up", tenant="sede-a", backup_ts=1000):
    return {"ip": ip, "tenant": tenant, "backup_ts": backup_ts, "vlans": [],
            "firewall": {"vendor": "fortios", "sections": [],
                         "vlan_interfaces": [{"name": f"vlan{vlan}",
                                              "vlan": str(vlan),
                                              "ip": iface_ip,
                                              "status": status,
                                              "parent": "port1"}]}}


class _Base(unittest.TestCase):
    def _run(self, analyses, devices, vlan="226", tenant="sede-a",
             client_ip=None):
        with patch("ai.config_analyzer.analyze_all",
                   return_value={"devices": analyses}), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=devices):
            return vlan_routing.route_owner(vlan, tenant, client_ip)


class TestTenantIsABoundary(_Base):

    def test_none_tenant_refuses_and_never_scans(self):
        called = []
        with patch("ai.config_analyzer.analyze_all",
                   side_effect=lambda **kw: called.append(kw) or {"devices": []}):
            out = vlan_routing.route_owner("226", None)
        self.assertFalse(out["known"])
        self.assertEqual(called, [], "un tenant ignoto non deve far scansionare")

    def test_empty_tenant_is_the_default_one_not_unknown(self):
        # arp_collector scrive "" per un apparato senza Group, analyze_all
        # legge "Generale": e' la stessa rete, e deve funzionare.
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24",
                              tenant="Generale")],
                        [{"IP": "192.0.2.20", "Group": ""}],
                        tenant="", client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["device_ip"], "192.0.2.20")

    def test_tenant_key_folds_the_empty_forms_together(self):
        self.assertEqual(vlan_routing.tenant_key(""), "Generale")
        self.assertEqual(vlan_routing.tenant_key("  "), "Generale")
        self.assertEqual(vlan_routing.tenant_key("sede-a"), "sede-a")


class TestDerivation(_Base):

    def test_the_subnet_containing_the_client_wins(self):
        out = self._run(
            [_ios("192.0.2.20", 226, "192.0.2.1/24"),
             _ios("192.0.2.21", 226, "198.51.100.1/24")],
            [{"IP": "192.0.2.20", "Group": "sede-a"},
             {"IP": "192.0.2.21", "Group": "sede-a"}],
            client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["device_ip"], "192.0.2.20")
        self.assertEqual(out["svi_ip"], "192.0.2.1/24")
        self.assertEqual(out["source"], "config")

    def test_a_pair_on_the_same_subnet_is_a_declared_tie(self):
        out = self._run(
            [_ios("192.0.2.20", 226, "192.0.2.1/24"),
             _ios("192.0.2.21", 226, "192.0.2.2/24")],
            [{"IP": "192.0.2.20", "Group": "sede-a"},
             {"IP": "192.0.2.21", "Group": "sede-a"}],
            client_ip="192.0.2.50")
        self.assertFalse(out["known"])
        self.assertEqual(sorted(out["candidates"]), ["192.0.2.20", "192.0.2.21"])

    def test_a_shutdown_svi_does_not_route(self):
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24", shutdown=True)],
                        [{"IP": "192.0.2.20", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertFalse(out["known"])

    def test_a_fortigate_vlan_interface_is_a_candidate(self):
        out = self._run([_fgt("192.0.2.254", 226, "192.0.2.1/24")],
                        [{"IP": "192.0.2.254", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["device_ip"], "192.0.2.254")

    def test_a_down_fortigate_vlan_interface_does_not_route(self):
        out = self._run([_fgt("192.0.2.254", 226, "192.0.2.1/24", status="down")],
                        [{"IP": "192.0.2.254", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertFalse(out["known"])

    def test_the_backup_age_is_reported(self):
        import time
        ts = int(time.time()) - 3600
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24", backup_ts=ts)],
                        [{"IP": "192.0.2.20", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertGreaterEqual(out["backup_age_s"], 3600)


class TestUnknownIsNotAbsent(_Base):

    def test_a_device_without_a_backup_makes_the_answer_unknown(self):
        out = self._run([], [{"IP": "192.0.2.20", "Group": "sede-a"}])
        self.assertFalse(out["known"])
        self.assertEqual(out["unreadable"], ["192.0.2.20"])
        self.assertIn("192.0.2.20", out["reason"])

    def test_everything_readable_and_nothing_found_is_not_unknown(self):
        out = self._run([_ios("192.0.2.20", 999, "192.0.2.1/24")],
                        [{"IP": "192.0.2.20", "Group": "sede-a"}])
        self.assertFalse(out["known"])
        self.assertEqual(out["unreadable"], [])

    def test_unreadable_is_reported_even_when_the_answer_is_known(self):
        out = self._run([_ios("192.0.2.20", 226, "192.0.2.1/24")],
                        [{"IP": "192.0.2.20", "Group": "sede-a"},
                         {"IP": "192.0.2.99", "Group": "sede-a"}],
                        client_ip="192.0.2.50")
        self.assertTrue(out["known"], out.get("reason"))
        self.assertEqual(out["unreadable"], ["192.0.2.99"])


if __name__ == "__main__":
    unittest.main()
