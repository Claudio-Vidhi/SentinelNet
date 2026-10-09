# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual classification and model catalogue, stored in SQLite."""

import json
import os
import tempfile
import unittest
from unittest import mock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_devmeta_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from services import inventory_manager as im  # noqa: E402


def _reset_store():
    path = im.meta_db_path()
    if os.path.exists(path):
        os.remove(path)
    im._meta_ready.discard(path)


class TestStore(unittest.TestCase):
    def setUp(self):
        _reset_store()

    def test_deleting_a_custom_category_frees_its_devices(self):
        im.add_category("kiosk", "Chiosco", "lobby")
        im.set_device_meta("192.0.2.10", tenant="sede-a", category="kiosk", model="K1")
        im.set_device_meta("192.0.2.11", tenant="sede-a", category="pc")
        self.assertTrue(im.delete_category("kiosk"))
        self.assertNotIn("kiosk", im.get_device_categories()["categories"])
        self.assertEqual(list(im.get_category_assignments()), ["sede-a|192.0.2.11"])
        self.assertFalse(im.delete_category("switch"), "builtin categories stay")

    def test_unknown_category_is_refused_and_nothing_is_written(self):
        im.get_models()  # create the store first: the refusal must not touch it
        sig = im.meta_signature()
        self.assertFalse(im.set_device_meta("192.0.2.10", tenant="sede-a", category="nope"))
        self.assertEqual(im.get_category_assignments(), {})
        self.assertEqual(im.meta_signature(), sig)

    def test_deleting_a_subcategory_unhooks_it(self):
        im.add_category("switch", "", "core")
        im.set_device_meta("192.0.2.10", tenant="sede-a", category="switch", subcategory="core")
        self.assertEqual(im.get_device_categories()["categories"]["switch"]["subcategories"], ["core"])
        self.assertTrue(im.delete_subcategory("switch", "core"))
        self.assertEqual(im.get_category_assignments()["sede-a|192.0.2.10"], {"category": "switch"})

    def test_clearing_every_field_drops_the_row(self):
        im.set_device_meta("192.0.2.10", tenant="sede-a", vendor="cisco")
        im.set_device_meta("192.0.2.10", tenant="sede-a", vendor="")
        self.assertEqual(im.get_category_assignments(), {})

    def test_merge_models_rewrites_catalogue_and_devices(self):
        im.add_model("cisco", "C2960X")
        im.add_model("cisco", "WS-C2960X")
        im.set_device_meta("192.0.2.10", tenant="sede-a", vendor="Cisco", model="C2960X")
        im.set_device_meta("192.0.2.11", tenant="sede-a", vendor="hpe", model="C2960X")
        self.assertEqual(im.merge_models("cisco", "WS-C2960X", ["C2960X"]), 1)
        self.assertEqual(im.get_models(), {"cisco": ["WS-C2960X"]})
        a = im.get_category_assignments()
        self.assertEqual(a["sede-a|192.0.2.10"]["model"], "WS-C2960X")
        self.assertEqual(a["sede-a|192.0.2.11"]["model"], "C2960X")

    def test_signature_changes_on_every_write(self):
        before = im.meta_signature()
        im.set_device_meta("192.0.2.10", tenant="sede-a", category="pc")
        mid = im.meta_signature()
        im.set_device_meta("192.0.2.10", tenant="sede-a", category="phone")
        self.assertNotEqual(before, mid)
        self.assertNotEqual(mid, im.meta_signature())

    def test_legacy_model_catalogue_is_imported(self):
        legacy = data_config.get_path("device_models.json")
        with open(legacy, "w", encoding="utf-8") as f:
            json.dump({"cisco": ["C9300", "C2960X"]}, f)
        self.assertEqual(im.get_models(), {"cisco": ["C2960X", "C9300"]})
        self.assertTrue(os.path.exists(legacy + ".migrated"))
        os.remove(legacy + ".migrated")


class TestClassificationReadsTheSavedAssignment(unittest.TestCase):
    """The tab used to look the assignment up by bare node id while the store
    keys it by (tenant, node): a classified device never left the queue."""

    MAP = {"nodes": [
        {"id": "192.0.2.1", "label": "switch-01", "group": "sede-a",
         "status": "online", "device_type": "switch"},
        {"id": "discovered_ap-01", "label": "ap-01", "group": "sede-a",
         "status": "discovered", "device_type": "ap"},
    ], "links": []}

    def setUp(self):
        _reset_store()

    def test_manual_fields_reach_the_tab(self):
        from routers import catalog
        im.set_device_meta("192.0.2.1", tenant="sede-a", category="switch", subcategory="core")
        im.set_device_meta("discovered_ap-01", tenant="Generale", category="ap", ha_group="ha-1")
        with mock.patch("core.core_engine.generate_network_map", return_value=self.MAP):
            nodes = {n["id"]: n for n in catalog.assemble_classification(None)["nodes"]}
        self.assertTrue(nodes["192.0.2.1"]["is_manual"])
        self.assertEqual(nodes["192.0.2.1"]["subcategory"], "core")
        self.assertTrue(nodes["discovered_ap-01"]["is_manual"])
        self.assertEqual(nodes["discovered_ap-01"]["ha_group"], "ha-1")


class TestMapAppliesSavedOverrides(unittest.TestCase):
    """Saved name/version/vendor/model were looked up by bare node id against
    'tenant|node' keys: every save was silently ignored by the map."""

    def setUp(self):
        self.backup_dir = tempfile.mkdtemp(prefix="devmeta_backup_")
        vdir = os.path.join(self.backup_dir, "sede-a", "cisco")
        os.makedirs(vdir)
        with open(os.path.join(vdir, "switch-01-192.0.2.7.txt"), "w", encoding="utf-8") as f:
            f.write("hostname switch-01\n")

    def _map(self, assignments):
        from core import core_engine
        devices = [{"IP": "192.0.2.7", "Group": "sede-a", "Vendor": "cisco"}]
        with mock.patch.object(core_engine, "BACKUP_FOLDER", self.backup_dir), \
             mock.patch.object(core_engine, "get_all_devices", return_value=devices), \
             mock.patch.object(core_engine, "get_detected_versions", return_value={}), \
             mock.patch.object(core_engine, "get_category_assignments", return_value=assignments):
            return next(n for n in core_engine._generate_network_map()["nodes"] if n["id"] == "192.0.2.7")

    def test_saved_name_and_version_reach_the_node(self):
        node = self._map({"sede-a|192.0.2.7": {"name": "core-sw-01", "ver": "17.9", "model": "C9300"}})
        self.assertEqual(node["label"], "core-sw-01")
        self.assertEqual(node["version"], "17.9")
        self.assertEqual(node["model"], "C9300")

    def test_another_tenants_override_is_not_applied(self):
        node = self._map({"sede-b|192.0.2.7": {"name": "other-tenant"}})
        self.assertEqual(node["label"], "switch-01")


class TestChosenNameClosesTheConflict(unittest.TestCase):
    MAP = {"nodes": [
        {"id": "discovered_sw-12", "label": "sw-12", "group": "sede-a",
         "status": "discovered", "device_type": "switch",
         "name_options": [{"name": "sw-12", "version": ""}, {"name": "58df592a3d0c", "version": "4.1"}]},
    ], "links": []}

    def setUp(self):
        _reset_store()

    def _node(self):
        from routers import catalog
        with mock.patch("core.core_engine.generate_network_map", return_value=self.MAP):
            return catalog.assemble_classification(None)["nodes"][0]

    def test_conflict_is_open_until_a_name_is_saved(self):
        self.assertEqual(len(self._node()["name_options"]), 2)
        im.set_device_meta("discovered_sw-12", tenant="Generale", name="sw-12")
        self.assertEqual(self._node()["name_options"], [])


if __name__ == "__main__":
    unittest.main()
