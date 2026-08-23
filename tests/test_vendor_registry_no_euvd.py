# -*- coding: utf-8 -*-
"""Vendor registry no longer carries the obsolete euvd_term field.

The vulnerability scanner uses NVD NIST directly and resolves vendor search
terms via VENDOR_NVD_MAP in inventory_manager.
"""
import json
import os
import tempfile
import unittest
from unittest import mock

from services import inventory_manager


class VendorRegistryNoEuvd(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._vendors_file = os.path.join(self._tmp.name, "vendors.json")
        patcher = mock.patch("services.inventory_manager.get_vendors_file",
                             return_value=self._vendors_file)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_default_vendors_have_no_euvd_term(self):
        vendors = inventory_manager.get_all_vendors()
        self.assertIn("cisco", vendors)
        for vname, vmeta in vendors.items():
            self.assertNotIn("euvd_term", vmeta, f"Vendor {vname} still contains euvd_term")

    def test_legacy_vendors_json_with_euvd_term_loads_cleanly(self):
        legacy = {
            "cisco": {"euvd_term": "cisco", "driver": "cisco_ios"},
            "custom_vendor": {"euvd_term": "custom", "driver": None},
        }
        with open(self._vendors_file, "w", encoding="utf-8") as fh:
            json.dump(legacy, fh)

        vendors = inventory_manager.get_all_vendors()
        self.assertIn("custom_vendor", vendors)
        for vname, vmeta in vendors.items():
            self.assertNotIn("euvd_term", vmeta, f"Vendor {vname} still has euvd_term after loading legacy file")

    def test_resolve_euvd_term_still_resolves_nvd_terms(self):
        self.assertEqual("palo alto", inventory_manager.resolve_euvd_term("paloalto"))
        self.assertEqual("cisco", inventory_manager.resolve_euvd_term("cisco_cbs"))
        self.assertEqual("hpe", inventory_manager.resolve_euvd_term("hpe"))


if __name__ == "__main__":
    unittest.main()
