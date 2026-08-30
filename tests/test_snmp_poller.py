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

    def setUp(self):
        # La selezione dipende anche dal default di tenant, che vive in un file
        # condiviso da tutto il processo: senza fissarlo, questi test leggono
        # quello che un altro modulo ha lasciato in giro invece del proprio.
        from security import snmp_defaults
        self.snmp_defaults = snmp_defaults
        for tenant in ("sede-a", "Generale"):
            snmp_defaults.set_tenant_community(tenant, "")

    def tearDown(self):
        for tenant in ("sede-a", "Generale"):
            self.snmp_defaults.set_tenant_community(tenant, "")

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

    def test_a_tenant_default_brings_in_the_devices_without_one(self):
        """L'altra meta' della regola, che qui non era coperta: il default di
        tenant e' esattamente cio' che rendeva intermittente il test sopra."""
        rows = [
            {"IP": "10.1.0.1", "Group": "sede-a",
             "SNMP Community": crypto_vault.encrypt_password("propria")},
            {"IP": "10.1.0.2", "Group": "sede-a", "SNMP Community": ""},
        ]
        self.snmp_defaults.set_tenant_community("sede-a", "del-tenant")
        with self._devices(rows):
            selected = snmp_poller._snmp_devices()

        self.assertEqual([d["ip"] for d in selected], ["10.1.0.1", "10.1.0.2"])
        # La community dell'apparato batte quella del tenant.
        self.assertEqual([d["community"] for d in selected],
                         ["propria", "del-tenant"])


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


class TestConcorrenza(unittest.TestCase):
    """Un apparato muto non deve fermare gli altri.

    Non e' un'ottimizzazione: con TIMEOUT_S=2 e RETRIES=1 ogni apparato
    irraggiungibile costa ~4s, e in sequenza venti apparati muti allungano
    ogni giro di oltre un minuto. Il default di tenant li aggiunge in blocco,
    quindi il costo va tolto prima, non dopo.
    """

    def test_gli_apparati_sono_interrogati_in_parallelo(self):
        import asyncio
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        in_volo = {"ora": 0, "max": 0}

        async def lento(ip, community, port=161):
            in_volo["ora"] += 1
            in_volo["max"] = max(in_volo["max"], in_volo["ora"])
            await asyncio.sleep(0.05)
            in_volo["ora"] -= 1
            return []

        devices = [{"ip": f"192.0.2.{i}", "tenant": "sede-a",
                    "community": "esempio-community"} for i in range(6)]

        with patch.object(snmp_poller, "_snmp_devices", return_value=devices), \
             patch.object(snmp_poller, "_poll_device", side_effect=lento):
            asyncio.run(snmp_poller.poll_once())

        self.assertGreater(in_volo["max"], 1,
                           "in sequenza il massimo in volo resta 1")

    def test_il_parallelismo_ha_un_tetto(self):
        """Senza tetto, mille apparati aprirebbero mille socket UDP insieme."""
        import asyncio
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        in_volo = {"ora": 0, "max": 0}

        async def lento(ip, community, port=161):
            in_volo["ora"] += 1
            in_volo["max"] = max(in_volo["max"], in_volo["ora"])
            await asyncio.sleep(0.02)
            in_volo["ora"] -= 1
            return []

        devices = [{"ip": f"192.0.2.{i}", "tenant": "sede-a",
                    "community": "esempio-community"} for i in range(40)]

        with patch.object(snmp_poller, "_snmp_devices", return_value=devices), \
             patch.object(snmp_poller, "_poll_device", side_effect=lento):
            asyncio.run(snmp_poller.poll_once())

        self.assertLessEqual(in_volo["max"], snmp_poller.MAX_CONCURRENT_POLLS)

    def test_un_apparato_che_solleva_non_ferma_il_giro(self):
        """Gia' vero oggi e deve restarlo: SNMP su UDP tace di continuo."""
        import asyncio
        from unittest.mock import patch
        from observability.ingesters import snmp_poller

        async def uno_esplode(ip, community, port=161):
            if ip.endswith(".2"):
                raise OSError("rete irraggiungibile")
            return [("snmp_system", "{}")]

        devices = [{"ip": f"192.0.2.{i}", "tenant": "sede-a",
                    "community": "esempio-community"} for i in (1, 2, 3)]

        with patch.object(snmp_poller, "_snmp_devices", return_value=devices), \
             patch.object(snmp_poller, "_poll_device", side_effect=uno_esplode), \
             patch("core.db.enqueue_write"):
            scritti = asyncio.run(snmp_poller.poll_once())

        self.assertEqual(scritti, 2, "gli altri due passano comunque")


if __name__ == "__main__":
    unittest.main()
