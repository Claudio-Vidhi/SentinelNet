# -*- coding: utf-8 -*-
"""Test dell'Endpoint Knowledge Base.

Arricchimento puramente descrittivo: dice cosa È un indirizzo, mai cosa
farne. Le regole consumano ``category``/``role``/``scope`` e non conoscono
nessun range: se questa distinzione si rompe, la conoscenza dei range torna a
spargersi dentro le regole.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_endpoints_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from observability import endpoints, rules  # noqa: E402


class TestClassification(unittest.TestCase):

    def test_well_known_multicast_has_a_role(self):
        info = endpoints.classify("224.0.0.5")
        self.assertEqual(info["category"], "multicast")
        self.assertEqual(info["role"], "ospf_allspfrouters")
        self.assertEqual(info["scope"], "link-local")
        self.assertEqual(info["label"], "OSPF AllSPFRouters")
        self.assertEqual(info["family"], "ipv4")

    def test_global_multicast_is_not_link_local(self):
        info = endpoints.classify("239.255.255.250")
        self.assertEqual((info["category"], info["scope"], info["role"]),
                         ("multicast", "global", "ssdp"))

    def test_categories_cover_the_special_ranges(self):
        cases = {
            "10.1.0.5": ("private", "site"),
            "192.168.1.1": ("private", "site"),
            "172.16.0.1": ("private", "site"),
            "8.8.8.8": ("public", "global"),
            "127.0.0.1": ("loopback", "host"),
            "169.254.10.3": ("link_local", "link-local"),
            "255.255.255.255": ("broadcast", "link-local"),
            "0.0.0.0": ("unspecified", "host"),
            "100.64.0.1": ("cgnat", "site"),
            "203.0.113.7": ("documentation", "global"),
            "198.18.0.1": ("benchmark", "global"),
            "240.0.0.1": ("reserved", "global"),
        }
        for address, expected in cases.items():
            info = endpoints.classify(address)
            self.assertIsNotNone(info, address)
            self.assertEqual((info["category"], info["scope"]), expected, address)

    def test_valid_address_without_a_known_role_is_still_classified(self):
        # None significa "non interpretabile", non "sconosciuto".
        info = endpoints.classify("203.0.113.99")
        self.assertIsNotNone(info)
        self.assertIsNone(info["role"])
        self.assertEqual(info["category"], "documentation")

    def test_garbage_is_none_not_a_guess(self):
        for value in ("non-un-ip", "", None, "999.1.1.1", "10.1.0"):
            self.assertIsNone(endpoints.classify(value), value)


class TestDescribe(unittest.TestCase):

    def test_known_role_becomes_readable(self):
        self.assertEqual(endpoints.describe("224.0.0.18"), "VRRP (224.0.0.18)")

    def test_plain_address_stays_plain(self):
        self.assertEqual(endpoints.describe("10.1.0.5"), "10.1.0.5")

    def test_unparseable_does_not_explode(self):
        self.assertEqual(endpoints.describe(None), "?")
        self.assertEqual(endpoints.describe("boh"), "boh")


class TestIsEndpoint(unittest.TestCase):
    """Chi può avere una porta di switch, un'abitudine di traffico, una prima
    apparizione. Gli altri no, e chiederglielo produce lookup a vuoto."""

    def test_real_hosts_are_endpoints(self):
        for address in ("10.1.0.5", "8.8.8.8", "100.64.0.9", "169.254.1.1"):
            self.assertTrue(endpoints.is_endpoint(address), address)

    def test_non_unicast_are_not(self):
        for address in ("224.0.0.5", "255.255.255.255", "127.0.0.1",
                        "0.0.0.0", "240.0.0.1"):
            self.assertFalse(endpoints.is_endpoint(address), address)

    def test_unparseable_is_not_an_endpoint(self):
        self.assertFalse(endpoints.is_endpoint("boh"))


class TestTrafficDirection(unittest.TestCase):
    """East-West Analysis: che genere di conversazione è, dai soli metadati.

    La distinzione che conta davvero non è interno/esterno ma
    conversazione/annuncio: su una rete reale i bucket verso multicast e
    broadcast sono la maggioranza, e contarli come traffico fra host cambia il
    significato di qualunque media."""

    def test_internal_to_internal_is_east_west(self):
        for src, dst in (("10.1.0.5", "10.1.0.9"),
                         ("192.168.1.2", "172.16.0.3"),
                         ("100.64.0.1", "10.0.0.1")):
            self.assertEqual(endpoints.traffic_direction(src, dst), "east_west",
                             f"{src}->{dst}")

    def test_crossing_the_perimeter_is_north_south(self):
        self.assertEqual(endpoints.traffic_direction("10.1.0.5", "8.8.8.8"),
                         "north_south")
        self.assertEqual(endpoints.traffic_direction("8.8.8.8", "10.1.0.5"),
                         "north_south")

    def test_discovery_and_routing_are_control_plane(self):
        for dst in ("224.0.0.5", "224.0.0.251", "239.255.255.250",
                    "255.255.255.255"):
            self.assertEqual(endpoints.traffic_direction("10.1.0.5", dst),
                             "control_plane", dst)

    def test_a_failed_dhcp_is_still_control_plane(self):
        # 0.0.0.0 → broadcast: la destinazione decide, e non è una
        # conversazione fra due host.
        self.assertEqual(endpoints.traffic_direction("0.0.0.0",
                                                     "255.255.255.255"),
                         "control_plane")

    def test_loopback_is_local(self):
        self.assertEqual(endpoints.traffic_direction("127.0.0.1", "127.0.0.1"),
                         "local")

    def test_unparseable_is_none_not_a_guess(self):
        self.assertIsNone(endpoints.traffic_direction("boh", "10.1.0.5"))
        self.assertIsNone(endpoints.traffic_direction("10.1.0.5", None))


class TestMacClassification(unittest.TestCase):
    """Le due informazioni utili stanno nel primo byte, non in un database di
    produttori da tenere aggiornato."""

    def test_separators_do_not_matter(self):
        for value in ("aa:bb:cc:80:01:00", "AA-BB-CC-80-01-00",
                      "aabb.cc80.0100", "AABBCC800100"):
            self.assertEqual(endpoints.classify_mac(value)["mac"],
                             "aa:bb:cc:80:01:00", value)

    def test_locally_administered_is_flagged(self):
        # Il MAC dei nodi CML: secondo bit del primo byte a 1.
        info = endpoints.classify_mac("aa:bb:cc:80:01:00")
        self.assertEqual(info["administration"], "locale")
        self.assertEqual(info["category"], "unicast")
        self.assertIsNone(info["vendor_kind"])

    def test_vendor_assigned_is_universal(self):
        info = endpoints.classify_mac("00:11:22:33:44:55")
        self.assertEqual(info["administration"], "universale")
        self.assertIsNone(info["label"])

    def test_virtualization_oui_is_named(self):
        for value, kind in (("00:50:56:aa:bb:cc", "VMware"),
                            ("00:15:5d:01:02:03", "Hyper-V"),
                            ("52:54:00:12:34:56", "QEMU/KVM")):
            self.assertEqual(endpoints.classify_mac(value)["vendor_kind"], kind)

    def test_l2_broadcast_and_multicast(self):
        self.assertEqual(endpoints.classify_mac("ff:ff:ff:ff:ff:ff")["category"],
                         "broadcast")
        self.assertEqual(endpoints.classify_mac("01:00:5e:00:00:fb")["category"],
                         "multicast")

    def test_garbage_is_none(self):
        for value in ("", None, "aa:bb:cc", "zz:bb:cc:dd:ee:ff", "10.1.0.5"):
            self.assertIsNone(endpoints.classify_mac(value), value)

    def test_stable_identity_separates_trackable_from_ephemeral(self):
        # Un MAC randomizzato di un telefono vale per la sessione corrente:
        # correlare lo storico su di esso inventa continuità che non c'è.
        self.assertFalse(endpoints.is_stable_identity("fa:d7:28:11:22:33"))
        # Una VM invece conserva il proprio indirizzo fra i riavvii.
        self.assertTrue(endpoints.is_stable_identity("00:50:56:aa:bb:cc"))
        self.assertTrue(endpoints.is_stable_identity("00:11:22:33:44:55"))
        self.assertFalse(endpoints.is_stable_identity("ff:ff:ff:ff:ff:ff"))

    def test_describe_mac_says_something_only_when_there_is_something_to_say(self):
        self.assertEqual(endpoints.describe_mac("00:11:22:33:44:55"),
                         "00:11:22:33:44:55")
        self.assertIn("VMware", endpoints.describe_mac("00:50:56:aa:bb:cc"))
        self.assertIn("localmente", endpoints.describe_mac("aa:bb:cc:80:01:00"))


class TestRulesConsumeMetadataOnly(unittest.TestCase):
    """Il principio architetturale, verificato sul codice: le regole non devono
    contenere conoscenza dei range IP. Se qualcuno la reintroduce, questo test
    lo intercetta."""

    def test_rules_module_has_no_hardcoded_ip_knowledge(self):
        import inspect
        import re
        source = inspect.getsource(rules)
        # Nessun indirizzo o prefisso IPv4 letterale nel motore delle regole.
        # Quattro ottetti: le versioni delle regole ("1.0.0") ne hanno tre.
        literals = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b',
                              source)
        self.assertEqual(literals, [],
                         f"conoscenza di range IP rientrata in rules.py: {literals}")

    def test_summaries_use_the_knowledge_base(self):
        import inspect
        source = inspect.getsource(rules)
        self.assertIn("endpoints.describe", source,
                      "i summary delle evidenze devono passare dalla Endpoint KB")


if __name__ == "__main__":
    unittest.main()
