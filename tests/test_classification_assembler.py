# -*- coding: utf-8 -*-
"""The tab and the export read the same assembler, so they cannot drift."""
import unittest
from unittest import mock

MAP = {
    "nodes": [
        {"id": "192.0.2.1", "label": "switch-01", "group": "ACME",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
        {"id": "discovered_ap-lobby", "label": "ap-lobby", "group": "ACME",
         "status": "discovered", "device_type": "ap", "reported_ip": "192.0.2.50"},
    ],
    "links": [
        {"source": "192.0.2.1", "target": "discovered_ap-lobby",
         "local_port": "Gi1/0/1", "remote_port": "Gi0"},
    ],
}
CATS = {"categories": {}, "assignments": {}}


class AssembleClassification(unittest.TestCase):
    def _assemble(self, scope=None):
        from routers import catalog
        with mock.patch("core.core_engine.generate_network_map", return_value=MAP), \
             mock.patch("services.inventory_manager.get_device_categories", return_value=CATS), \
             mock.patch("services.inventory_manager.get_all_vendors", return_value={}), \
             mock.patch("services.inventory_manager.get_models", return_value={}):
            return catalog.assemble_classification(scope)

    def test_it_returns_the_links_the_tab_endpoint_drops(self):
        self.assertEqual(1, len(self._assemble()["links"]))

    def test_a_discovered_node_reports_its_announced_ip(self):
        ap = next(n for n in self._assemble()["nodes"] if n["id"] == "discovered_ap-lobby")
        self.assertEqual("192.0.2.50", ap["display_ip"])
        self.assertTrue(ap["discovered"])

    def test_an_inventoried_node_reports_its_own_ip(self):
        sw = next(n for n in self._assemble()["nodes"] if n["id"] == "192.0.2.1")
        self.assertEqual("192.0.2.1", sw["display_ip"])
        self.assertFalse(sw["discovered"])


if __name__ == "__main__":
    unittest.main()
