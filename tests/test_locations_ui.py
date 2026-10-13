# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Locations UI (spec 2026-10-09 organizations-locations): the controls exist,
are bound, every entry point that adds or moves a device sends a location,
and every new string is in both dictionaries."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(*parts):
    return (ROOT.joinpath(*parts)).read_text(encoding="utf-8")


HTML = _read("templates", "dashboard.html")
JS = {name: _read("static", "js", name) for name in (
    "core.js", "devices.js", "provisioning.js", "home.js", "manual-config.js",
    "topology.js", "settings.js")}
I18N = _read("static", "js", "i18n.js")

# id -> module that binds or fills it
BOUND = {
    "devLocationSelect": "provisioning.js",
    "btnSaveLocation": "devices.js",
    "locName": "devices.js",
    "locRole": "devices.js",
    "locSubnets": "devices.js",
    "locProbe": "devices.js",
    "locApplyProbe": "devices.js",
    "locationPickModal": "core.js",
    "locPickSelect": "core.js",
    "homeLocationsBanner": "home.js",
    "btnDismissLocationsReview": "home.js",
    "mcAllLocation": "manual-config.js",
}

NEW_KEYS = (
    "lblDeviceLocation", "optSelectLocation", "optNoLocation", "alertSelectLocation",
    "alertOrgHasNoLocations", "devMoveToAnotherLocation", "thLocation", "thLocationSubnets",
    "thLocationDevices", "noLocations", "btnNewLocation", "btnEditLocation",
    "btnDeleteLocation", "confirmDeleteLocation", "lblLocationOrg", "lblLocationName",
    "phLocationName", "lblLocationRole", "locRole_hq", "locRole_branch",
    "locRole_datacenter", "locRole_warehouse", "locRole_other", "lblLocationSubnets",
    "lblLocationProbe", "lblApplyProbeToDevices", "titlePickLocation", "btnConfirm",
    "mcLblLocation", "swSubnetsOnLocations", "chipUnlocatedDevices",
    "homeLocationsReview", "homeLegacyOrgDevices", "btnReviewLocations",
    "btnLocationsReviewed",
)


class TestLocationsUi(unittest.TestCase):
    def test_controls_exist_and_are_bound(self):
        for el_id, module in BOUND.items():
            with self.subTest(id=el_id):
                self.assertIn(f'id="{el_id}"', HTML)
                self.assertIn(f"'{el_id}'", JS[module])

    def test_new_keys_are_in_both_dictionaries(self):
        for key in NEW_KEYS:
            with self.subTest(key=key):
                self.assertEqual(len(re.findall(rf"^\s+{key}:", I18N, re.M)), 2)

    def test_every_entry_point_sends_a_location(self):
        self.assertIn("location: document.getElementById('devLocationSelect').value", JS["devices.js"])
        self.assertIn("new_location: loc.id", JS["devices.js"])
        self.assertIn("group, location,", JS["devices.js"])            # subnet scan add
        self.assertIn("group: n.group, location: locs.get(n.group)", JS["topology.js"])  # promote
        self.assertIn("location: r.location", JS["manual-config.js"])

    def test_probe_wizard_no_longer_edits_subnets(self):
        self.assertNotIn('id="swSubnets"', HTML)
        save = JS["settings.js"].split("async function saveProbeWizard")[1][:400]
        self.assertNotIn("subnets", save)


if __name__ == "__main__":
    unittest.main()
