# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Le assegnazioni manuali di categoria sono per (sede, nodo), non per nodo.

Indicizzate per solo indirizzo, due clienti sullo stesso indirizzo privato si
dividevano l'etichetta: chi classificava 192.0.2.50 in una sede lo
rinominava anche in tutte le altre. Una sede e' una rete a se', esattamente
come in ``mac_sightings``.
"""

import json
import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_cattenant_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from services import inventory_manager  # noqa: E402


def _reset_store():
    path = inventory_manager.meta_db_path()
    if os.path.exists(path):
        os.remove(path)
    inventory_manager._meta_ready.discard(path)


class _Base(unittest.TestCase):
    def setUp(self):
        # Empty store for every test: its content is the subject.
        _reset_store()
        # Le sedi vanno create prima: add_or_update_device riporta a 'Generale'
        # un gruppo che non esiste, e il test misurerebbe quel fallback.
        inventory_manager.add_group("sede-a")
        inventory_manager.add_group("sede-b")
        inventory_manager.add_or_update_device(
            "192.0.2.50", "cisco", "custom", "u", "p", "", "sede-a")
        inventory_manager.add_or_update_device(
            "198.51.100.50", "cisco", "custom", "u", "p", "", "sede-b")

    def _assignments(self):
        return inventory_manager.get_category_assignments()


class TestScopingPerSede(_Base):

    def test_the_same_address_in_two_tenants_keeps_two_labels(self):
        # Lo stesso indirizzo privato esiste in ogni sede del mondo: e' il caso
        # normale, non quello limite.
        inventory_manager.set_device_meta("10.0.0.1", tenant="sede-a", category="pc")
        inventory_manager.set_device_meta("10.0.0.1", tenant="sede-b", category="phone")
        a = self._assignments()
        self.assertEqual(a["sede-a|10.0.0.1"]["category"], "pc")
        self.assertEqual(a["sede-b|10.0.0.1"]["category"], "phone")

    def test_the_tenant_is_taken_from_inventory_when_not_given(self):
        # Il chiamante (la rotta di assegnazione) non conosce la sede: la porta
        # il dispositivo, in inventario.
        inventory_manager.set_device_meta("192.0.2.50", category="pc")
        self.assertIn("sede-a|192.0.2.50", self._assignments())

    def test_a_node_outside_inventory_lands_in_generale(self):
        # Nodo scoperto via CDP/LLDP e mai promosso: non ha una sede propria.
        inventory_manager.set_device_meta("203.0.113.9", category="pc")
        self.assertIn("Generale|203.0.113.9", self._assignments())

    def test_clearing_one_tenant_leaves_the_other_alone(self):
        inventory_manager.set_device_meta("10.0.0.1", tenant="sede-a", category="pc")
        inventory_manager.set_device_meta("10.0.0.1", tenant="sede-b", category="pc")
        inventory_manager.set_device_meta("10.0.0.1", tenant="sede-a", category="")
        a = self._assignments()
        self.assertNotIn("sede-a|10.0.0.1", a)
        self.assertEqual(a["sede-b|10.0.0.1"]["category"], "pc")

    def test_promotion_moves_the_label_into_the_new_tenant(self):
        # Il nodo scoperto sta sotto 'Generale'; promosso, appartiene alla sede.
        inventory_manager.set_device_meta("203.0.113.9", category="pc")
        inventory_manager.migrate_assignment("203.0.113.9", "192.0.2.50",
                                             new_tenant="sede-a")
        a = self._assignments()
        self.assertNotIn("Generale|203.0.113.9", a)
        self.assertEqual(a["sede-a|192.0.2.50"]["category"], "pc")


class TestMigrazioneChiaviVecchie(_Base):
    """The JSON file written before the key carried the tenant, imported once
    into the SQLite store."""

    def _write_legacy(self, assignments):
        _reset_store()
        with open(self._legacy, "w", encoding="utf-8") as f:
            json.dump({"categories": {}, "assignments": assignments}, f)

    @property
    def _legacy(self):
        return data_config.get_path("device_categories.json")

    def test_a_bare_key_is_resolved_from_inventory(self):
        self._write_legacy({"192.0.2.50": {"category": "pc"}})
        a = self._assignments()
        self.assertEqual(a, {"sede-a|192.0.2.50": {"category": "pc"}})

    def test_a_bare_key_with_no_device_falls_back_to_generale(self):
        self._write_legacy({"203.0.113.9": {"category": "pc"}})
        self.assertIn("Generale|203.0.113.9", self._assignments())

    def test_the_import_runs_once_and_keeps_the_old_file(self):
        self._write_legacy({"192.0.2.50": {"category": "pc"}})
        self._assignments()
        self.assertFalse(os.path.exists(self._legacy))
        self.assertTrue(os.path.exists(self._legacy + ".migrated"))
        # A JSON reappearing later (restored by hand) is not merged again.
        with open(self._legacy, "w", encoding="utf-8") as f:
            json.dump({"assignments": {"198.51.100.50": {"category": "phone"}}}, f)
        inventory_manager.set_device_meta("192.0.2.50", category="camera")
        self.assertEqual(self._assignments(), {"sede-a|192.0.2.50": {"category": "camera"}})
        os.remove(self._legacy)

    def test_nothing_is_lost_in_the_migration(self):
        self._write_legacy({"192.0.2.50": {"category": "pc", "name": "sw-a"},
                            "198.51.100.50": {"category": "phone"},
                            "203.0.113.9": {"category": "camera"}})
        a = self._assignments()
        self.assertEqual(len(a), 3)
        self.assertEqual(a["sede-a|192.0.2.50"]["name"], "sw-a")
        self.assertEqual(a["sede-b|198.51.100.50"]["category"], "phone")
        self.assertEqual(a["Generale|203.0.113.9"]["category"], "camera")


if __name__ == "__main__":
    unittest.main()
