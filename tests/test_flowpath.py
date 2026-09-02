# -*- coding: utf-8 -*-
"""Flow Path: il percorso ricostruito dalla topologia già raccolta.

Il punto non è la completezza — è che un salto sconosciuto venga DETTO. Un
percorso parziale e onesto vale più di uno completo e inventato, perché
l'ingegnere decide dove guardare in base a questo.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_flowpath_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from observability import flowpath  # noqa: E402

# Come lo restituisce mac_history.client_map().
CLIENT_A = {"mac": "00:11:22:33:44:55", "ip": "10.1.0.5", "vlan": "10",
            "source_ip": "10.1.0.1", "source_name": "SW1", "source_type": "switch",
            "switch_ip": "10.1.0.20", "switch_name": "ACC-SW1",
            "switch_port": "GigabitEthernet1/0/5", "port_vlan": "10"}
CLIENT_B = {"mac": "00:50:56:aa:bb:cc", "ip": "10.1.0.9", "vlan": "10",
            "source_ip": "10.1.0.1", "source_name": "SW1", "source_type": "switch",
            "switch_ip": "10.1.0.21", "switch_name": "ACC-SW2",
            "switch_port": "GigabitEthernet1/0/9", "port_vlan": "10"}
CLIENT_C = dict(CLIENT_B, ip="172.16.0.9", source_ip="172.16.0.1",
                source_name="FGT", source_type="firewall")


def _lookup(mapping):
    """Sostituisce client_map: ritorna il binding dell'IP richiesto."""
    def fake(ip=None, mac=None, tenants=None, limit=500, source_ip=None):
        entry = mapping.get(ip)
        return [entry] if entry else []
    return patch("collectors.mac_history.client_map", side_effect=fake)


class TestEastWest(unittest.TestCase):

    def test_both_ends_are_reconstructed(self):
        with _lookup({"10.1.0.5": CLIENT_A, "10.1.0.9": CLIENT_B}):
            path = flowpath.build("10.1.0.5", "10.1.0.9", "sede-a")
        self.assertEqual(path["direction"], "east_west")
        self.assertTrue(path["complete"])
        self.assertEqual([h["kind"] for h in path["hops"]],
                         ["endpoint", "access", "gateway", "access", "endpoint"])
        self.assertIn("ACC-SW1:GigabitEthernet1/0/5", path["hops"][1]["label"])
        self.assertIn("ACC-SW2:GigabitEthernet1/0/9", path["hops"][3]["label"])

    def test_the_shared_gateway_appears_once(self):
        # Due host della stessa VLAN dietro lo stesso apparato: il traffico non
        # lo attraversa due volte, e mostrarlo due volte sarebbe una bugia.
        with _lookup({"10.1.0.5": CLIENT_A, "10.1.0.9": CLIENT_B}):
            path = flowpath.build("10.1.0.5", "10.1.0.9", "sede-a")
        self.assertEqual(sum(1 for h in path["hops"] if h["kind"] == "gateway"), 1)

    def test_two_gateways_are_both_shown(self):
        with _lookup({"10.1.0.5": CLIENT_A, "172.16.0.9": CLIENT_C}):
            path = flowpath.build("10.1.0.5", "172.16.0.9", "sede-a")
        gateways = [h["device"] for h in path["hops"] if h["kind"] == "gateway"]
        self.assertEqual(gateways, ["SW1", "FGT"])


class TestAcrossTenants(unittest.TestCase):
    """Un server in datacenter non sta nel tenant del client: cercarlo con
    quello della sorgente lo darebbe per ignoto sempre — un buco prodotto
    dalla domanda, non dai dati."""

    def _per_tenant(self, mapping):
        """client_map che rispetta il tenant chiesto, come il vero."""
        def fake(ip=None, mac=None, tenants=None, limit=500, source_ip=None):
            entry = mapping.get(ip)
            if not entry:
                return []
            if tenants is not None and entry["tenant"] not in tenants:
                return []
            return [entry]
        return patch("collectors.mac_history.client_map", side_effect=fake)

    def test_destination_in_another_tenant_is_found_when_declared(self):
        src = dict(CLIENT_A, tenant="sede-a")
        dst = dict(CLIENT_B, tenant="datacenter")
        with self._per_tenant({"10.1.0.5": src, "10.1.0.9": dst}):
            path = flowpath.build("10.1.0.5", "10.1.0.9", "sede-a",
                                  dst_tenant="datacenter")
        self.assertTrue(path["complete"])
        self.assertIn("ACC-SW2", path["hops"][3]["label"])

    def test_without_it_the_far_end_stays_unknown(self):
        src = dict(CLIENT_A, tenant="sede-a")
        dst = dict(CLIENT_B, tenant="datacenter")
        with self._per_tenant({"10.1.0.5": src, "10.1.0.9": dst}):
            path = flowpath.build("10.1.0.5", "10.1.0.9", "sede-a")
        self.assertFalse(path["complete"])

    def test_existing_callers_are_unaffected(self):
        """Omesso, dst_tenant vale il tenant della sorgente."""
        with _lookup({"10.1.0.5": CLIENT_A, "10.1.0.9": CLIENT_B}):
            a = flowpath.build("10.1.0.5", "10.1.0.9", "sede-a")
            b = flowpath.build("10.1.0.5", "10.1.0.9", "sede-a", None)
        self.assertEqual(a, b)


class TestHonestGaps(unittest.TestCase):

    def test_a_missing_access_port_is_declared_not_skipped(self):
        with _lookup({"10.1.0.5": dict(CLIENT_A, switch_port="")}):
            path = flowpath.build("10.1.0.5", "8.8.8.8", "sede-a")
        access = next(h for h in path["hops"] if h["kind"] == "access")
        self.assertFalse(access["known"])
        self.assertIn("MAC scan", access["label"])
        self.assertFalse(path["complete"])

    def test_an_unknown_host_still_produces_a_path(self):
        with _lookup({}):
            path = flowpath.build("10.1.0.5", "8.8.8.8", "sede-a")
        self.assertEqual(path["direction"], "north_south")
        self.assertFalse(path["complete"])
        # L'endpoint resta: sappiamo l'IP anche se non sappiamo dov'è attaccato.
        self.assertEqual(path["hops"][0]["ip"], "10.1.0.5")
        self.assertIsNone(path["hops"][0]["mac"])

    def test_unparseable_endpoints_produce_no_invented_path(self):
        with _lookup({}):
            path = flowpath.build("boh", "10.1.0.9", "sede-a")
        self.assertIsNone(path["direction"])
        self.assertEqual(path["hops"], [])


class TestDirections(unittest.TestCase):

    def test_leaving_the_perimeter_ends_at_the_perimeter(self):
        with _lookup({"10.1.0.5": CLIENT_A}):
            path = flowpath.build("10.1.0.5", "8.8.8.8", "sede-a")
        self.assertEqual(path["direction"], "north_south")
        self.assertEqual(path["hops"][-1]["kind"], "perimeter")

    def test_control_plane_has_no_second_host(self):
        with _lookup({"10.1.0.5": CLIENT_A}):
            path = flowpath.build("10.1.0.5", "224.0.0.5", "sede-a")
        self.assertEqual(path["direction"], "control_plane")
        self.assertEqual(path["hops"][-1]["kind"], "destination")
        self.assertIn("OSPF AllSPFRouters", path["hops"][-1]["label"])
        self.assertNotIn("endpoint",
                         [h["kind"] for h in path["hops"][1:]])


if __name__ == "__main__":
    unittest.main()
