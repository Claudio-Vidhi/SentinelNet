# -*- coding: utf-8 -*-
"""Poller SNMP: sorgente di stato per gli apparati senza API REST.

Il punto non è il protocollo — è che uno snapshot SNMP entri nella STESSA
pipeline degli snapshot REST. Se ci riesce, regole, evidenze, incidenti e
timeline funzionano senza sapere da dove arriva il dato.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_snmp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import correlator, normalize  # noqa: E402
from observability.ingesters import snmp_poller  # noqa: E402
from security import crypto_vault  # noqa: E402

NOW = int(time.time())

# Colonne come le restituisce il walk: {ifIndex: valore}.
COLUMNS = {
    "name": {"1": "GigabitEthernet1/0/1", "2": "GigabitEthernet1/0/2"},
    "link": {"1": 1, "2": 2},
    "admin_status": {"1": 1, "2": 1},
    "in_octets": {"1": 9000, "2": 12},
    "out_octets": {"1": 4000},
    "speed_mbps": {"1": 1000, "2": 1000},
}


class TestInterfaceAssembly(unittest.TestCase):

    def test_ifname_is_the_key_not_ifindex(self):
        # ifIndex viene rinumerato al riavvio su diversi vendor: usarlo come
        # chiave farebbe sembrare ogni riavvio un cambio su tutte le porte.
        ifaces = snmp_poller._interfaces(COLUMNS)
        self.assertEqual(sorted(ifaces), ["GigabitEthernet1/0/1",
                                          "GigabitEthernet1/0/2"])
        self.assertEqual(ifaces["GigabitEthernet1/0/1"]["ifindex"], 1)

    def test_status_integers_become_words(self):
        ifaces = snmp_poller._interfaces(COLUMNS)
        self.assertEqual(ifaces["GigabitEthernet1/0/1"]["link"], "up")
        self.assertEqual(ifaces["GigabitEthernet1/0/2"]["link"], "down")
        self.assertEqual(ifaces["GigabitEthernet1/0/2"]["admin_status"], "up")

    def test_a_missing_column_value_is_omitted_not_invented(self):
        ifaces = snmp_poller._interfaces(COLUMNS)
        self.assertNotIn("out_octets", ifaces["GigabitEthernet1/0/2"])
        self.assertEqual(ifaces["GigabitEthernet1/0/1"]["out_octets"], 4000)

    def test_an_interface_without_a_name_is_skipped(self):
        columns = dict(COLUMNS, name={"1": "Gi1", "2": None, "3": ""})
        self.assertEqual(sorted(snmp_poller._interfaces(columns)), ["Gi1"])


class TestPortVlan(unittest.IsolatedAsyncioTestCase):
    """La VLAN di accesso non esiste in IF-MIB. Senza di lei, spostare una
    porta di VLAN non produceva alcun evento: lo snapshot non conteneva la
    VLAN, quindi non poteva cambiare."""

    def _walks(self, mapping):
        """Sostituisce _walk_column: risponde per OID, {} per gli altri."""
        async def fake(engine, auth, target, context, oid):
            return dict(mapping.get(oid, {}))
        return patch.object(snmp_poller, "_walk_column", side_effect=fake)

    async def test_cisco_vmvlan_is_used_when_it_answers(self):
        with self._walks({snmp_poller._VLAN_OID_CISCO: {"1": 10, "2": 20}}):
            vlans = await snmp_poller._port_vlans(None, None, None, None)
        self.assertEqual(vlans, {"1": 10, "2": 20})

    async def test_qbridge_pvid_is_translated_to_ifindex(self):
        """dot1qPvid è indicizzata per dot1dBasePort: senza la traduzione le
        VLAN finirebbero sulle porte sbagliate, che è peggio di non averle."""
        with self._walks({
                snmp_poller._VLAN_OID_QBRIDGE: {"3": 10, "4": 20},
                snmp_poller._BRIDGE_PORT_IFINDEX: {"3": 101, "4": 102}}):
            vlans = await snmp_poller._port_vlans(None, None, None, None)
        self.assertEqual(vlans, {"101": 10, "102": 20})

    async def test_a_bridge_port_without_a_mapping_is_dropped(self):
        with self._walks({
                snmp_poller._VLAN_OID_QBRIDGE: {"3": 10, "9": 99},
                snmp_poller._BRIDGE_PORT_IFINDEX: {"3": 101}}):
            vlans = await snmp_poller._port_vlans(None, None, None, None)
        self.assertEqual(vlans, {"101": 10})

    async def test_a_non_switch_reports_nothing_rather_than_zero(self):
        """Un router o un firewall non risponde a nessuna delle due: la porta
        non porta il campo, invece di uno zero che sembrerebbe una VLAN."""
        with self._walks({}):
            vlans = await snmp_poller._port_vlans(None, None, None, None)
        self.assertEqual(vlans, {})

    async def test_the_vlan_lands_on_the_interface(self):
        ifaces = snmp_poller._interfaces({**COLUMNS, "port_vlan": {"1": 10}})
        self.assertEqual(ifaces["GigabitEthernet1/0/1"]["port_vlan"], 10)
        self.assertNotIn("port_vlan", ifaces["GigabitEthernet1/0/2"])


class TestDeviceSelection(unittest.TestCase):

    def _devices(self, rows):
        return patch("services.inventory_manager.get_all_devices",
                     return_value=rows)

    def test_only_devices_with_a_community_are_polled(self):
        rows = [
            {"IP": "10.1.0.1", "Group": "sede-a",
             "SNMP Community": crypto_vault.encrypt_password("segreta")},
            {"IP": "10.1.0.2", "Group": "sede-a", "SNMP Community": ""},
            {"IP": "10.1.0.3", "Group": "sede-a"},
        ]
        with self._devices(rows):
            selected = snmp_poller._snmp_devices()
        self.assertEqual([d["ip"] for d in selected], ["10.1.0.1"])
        # Cifrata a riposo, in chiaro solo in memoria al momento del poll.
        self.assertEqual(selected[0]["community"], "segreta")
        self.assertNotEqual(rows[0]["SNMP Community"], "segreta")


class TestSnapshotsReachTheEngine(unittest.TestCase):
    """La prova che conta: uno snapshot SNMP percorre tutta la pipeline."""

    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()

    def setUp(self):
        conn = db.get_observability_connection()
        for table in ("events", "normalize_cursors", "evidence", "incidents",
                      "incident_conclusions", "api_observations"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _observe(self, ts, interfaces):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO api_observations (ts, tenant, device_ip, kind, summary_json) "
            "VALUES (?, 'sede-a', '10.1.0.1', 'snmp_interfaces', ?)",
            (ts, json.dumps({"results": interfaces})))
        conn.commit()
        conn.close()

    def _rows(self, sql, params=()):
        conn = db.get_observability_connection()
        try:
            return [dict(r) for r in conn.execute(sql, params)]
        finally:
            conn.close()

    def test_provenance_says_snmp_not_rest(self):
        self._observe(NOW - 60, {"Gi1/0/1": {"link": "up", "speed_mbps": 1000}})
        normalize.normalize_once(NOW)
        events = self._rows("SELECT * FROM events WHERE event_type = 'interface.state'")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source"], "snmp")
        self.assertEqual(events[0]["entity_id"], "10.1.0.1:Gi1/0/1")
        self.assertEqual(events[0]["interface"], "Gi1/0/1")

    def test_a_port_going_down_becomes_evidence(self):
        self._observe(NOW - 300, {"Gi1/0/1": {"link": "up", "speed_mbps": 1000}})
        self._observe(NOW - 60, {"Gi1/0/1": {"link": "down", "speed_mbps": 1000}})
        with patch("observability.rules.get_app_settings", return_value={}), \
             patch("collectors.mac_history.client_map", return_value=[]):
            correlator.correlate_once(NOW)
        ev = self._rows("SELECT * FROM evidence WHERE rule_id = 'IFACE_DOWN_001'")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["role"], "symptom")
        self.assertIn("Gi1/0/1", ev[0]["summary"])

    def test_counters_do_not_invent_a_change_every_poll(self):
        # I contatori crescono a ogni giro per costruzione: se entrassero nel
        # confronto, ogni apparato avrebbe un "cambiamento" ogni intervallo.
        self._observe(NOW - 300, {"Gi1/0/1": {"link": "up", "in_octets": 1000}})
        self._observe(NOW - 60, {"Gi1/0/1": {"link": "up", "in_octets": 9999}})
        normalize.normalize_once(NOW)
        self.assertEqual(
            self._rows("SELECT * FROM events WHERE event_type = 'interface.change'"),
            [])


if __name__ == "__main__":
    unittest.main()
