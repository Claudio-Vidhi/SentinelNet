# -*- coding: utf-8 -*-
"""Diagnosi client: L2 e L3 nello stesso referto.

Il punto non e' che tutte le sezioni riescano — e' che una sezione che non sa
lo DICA, e che le altre continuino comunque. Chi legge sta per andare a
toccare la rete: un buco dichiarato lo manda a guardare nel posto giusto, un
buco taciuto lo manda a guardare nel posto sbagliato.
"""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_diag_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from services import client_diagnosis  # noqa: E402

NOW = int(time.time())

# Come lo restituisce mac_history.client_map().
CLIENT = {
    "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.10", "vlan": "10",
    "tenant": "sede-a", "site": "central", "client_type": "client",
    "source_ip": "192.0.2.1", "source_name": "FGT", "source_type": "firewall",
    "switch_ip": "192.0.2.20", "switch_name": "ACC-SW1",
    "switch_port": "GigabitEthernet1/0/5", "port_vlan": "10",
    "last_seen": "2026-08-01T10:00:00", "port_last_seen": "2026-08-01T10:00:00",
}
FGT_DEVICE = {"IP": "192.0.2.1", "Vendor": "fortinet", "Group": "sede-a"}
SWITCH_DEVICE = {"IP": "192.0.2.20", "Vendor": "cisco", "Group": "sede-a"}


def _client_map(entries):
    def fake(ip=None, mac=None, tenants=None, limit=500, source_ip=None):
        return list(entries)
    return patch("collectors.mac_history.client_map", side_effect=fake)


def _fortigate(diagnose_result=None, targets=None, exc=None):
    """Sostituisce il livello FortiGate: elenco target, inventario e diagnosi."""
    targets = [{"ip": "192.0.2.1", "name": "FGT", "port": 443,
                "verify_tls": False, "active": True}] if targets is None else targets
    diag = diagnose_result or {"client": "192.0.2.10", "sections": {}}
    return (
        patch("services.fortigate_service.list_targets", return_value=targets),
        patch("services.inventory_manager.get_all_devices",
              return_value=[FGT_DEVICE, SWITCH_DEVICE]),
        patch("services.fortigate_service.diagnose_client",
              side_effect=exc) if exc else
        patch("services.fortigate_service.diagnose_client", return_value=diag),
    )


class _Base(unittest.TestCase):
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
        for table in ("events", "syslog_events"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        conn.close()

    def _iface_sample(self, ts, in_errors, out_errors, link="up",
                      interface="Gi1/0/5", device_ip="192.0.2.20",
                      port_vlan=None):
        attrs = {"link": link, "admin_status": "up",
                 "in_errors": in_errors, "out_errors": out_errors}
        if port_vlan is not None:
            attrs["port_vlan"] = port_vlan
        conn = db.get_observability_connection()
        conn.execute(
            """INSERT INTO events (ts, ingested_ts, tenant, source, event_type,
                                   entity_type, entity_id, device_ip, interface,
                                   attrs_json, dedup_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (ts, ts, "sede-a", "snmp", "interface.state", "interface",
             f"{device_ip}:{interface}", device_ip, interface,
             json.dumps(attrs), f"t:{device_ip}:{interface}:{ts}"))
        conn.commit()
        conn.close()

    def _syslog(self, ts, message, action, tenant="sede-a"):
        conn = db.get_observability_connection()
        conn.execute(
            """INSERT INTO syslog_events (ts, tenant, device_ip, severity,
                                          action, message, exporter_ip)
               VALUES (?,?,?,?,?,?,?)""",
            (ts, tenant, "192.0.2.1", 5, action, message, "192.0.2.1"))
        conn.commit()
        conn.close()


class TestPosition(_Base):

    def test_exact_ip_match_only(self):
        """search_arp filtra con LIKE 'ip%': 192.0.2.1 pesca anche 192.0.2.10 e
        192.0.2.100. Su una diagnosi vorrebbe dire descrivere un altro host."""
        neighbour = dict(CLIENT, ip="192.0.2.100", mac="11:22:33:44:55:66")
        with _client_map([neighbour, dict(CLIENT, ip="192.0.2.1")]):
            pos = client_diagnosis._position("192.0.2.1", False, None)
        self.assertTrue(pos["known"])
        self.assertEqual(pos["ip"], "192.0.2.1")

    def test_unknown_client_says_why(self):
        with _client_map([]):
            pos = client_diagnosis._position("192.0.2.77", False, None)
        self.assertFalse(pos["known"])
        self.assertIn("scansione ARP", pos["reason"])

    def test_staleness_is_carried_through(self):
        """La raccolta ARP/MAC e' manuale: senza le date, una porta vista tre
        settimane fa si legge come una vista adesso."""
        with _client_map([CLIENT]):
            pos = client_diagnosis._position("192.0.2.10", False, None)
        self.assertEqual(pos["binding_last_seen"], "2026-08-01T10:00:00")
        self.assertEqual(pos["port_last_seen"], "2026-08-01T10:00:00")

    def test_multiple_bindings_are_reported_not_hidden(self):
        other = dict(CLIENT, mac="11:22:33:44:55:66")
        with _client_map([CLIENT, other]):
            pos = client_diagnosis._position("192.0.2.10", False, None)
        self.assertEqual(len(pos["ambiguous"]), 1)


class TestInterfaceHealth(_Base):

    def test_error_counters_become_a_delta(self):
        """I contatori erano raccolti da sempre e non li leggeva nessuno."""
        self._iface_sample(NOW - 600, in_errors=100, out_errors=0)
        self._iface_sample(NOW - 60, in_errors=350, out_errors=0)
        h = client_diagnosis._interface_health("192.0.2.20", "GigabitEthernet1/0/5")
        self.assertTrue(h["known"])
        self.assertEqual(h["error_delta"]["in_errors"], 250)
        self.assertTrue(h["erroring"])

    def test_short_and_long_interface_names_match(self):
        """La MAC table scrive 'GigabitEthernet1/0/5', SNMP 'Gi1/0/5'."""
        self._iface_sample(NOW - 600, 0, 0, interface="Gi1/0/5")
        self._iface_sample(NOW - 60, 0, 0, interface="Gi1/0/5")
        h = client_diagnosis._interface_health("192.0.2.20", "GigabitEthernet1/0/5")
        self.assertTrue(h["known"])

    def test_counter_reset_is_not_a_negative_delta(self):
        """Riavvio dell'apparato o wrap: la differenza non vorrebbe dire nulla."""
        self._iface_sample(NOW - 600, in_errors=9000, out_errors=0)
        self._iface_sample(NOW - 60, in_errors=12, out_errors=0)
        h = client_diagnosis._interface_health("192.0.2.20", "GigabitEthernet1/0/5")
        self.assertIsNone(h["error_delta"]["in_errors"])
        self.assertFalse(h["erroring"])

    def test_single_sample_refuses_to_pretend(self):
        self._iface_sample(NOW - 60, in_errors=5000, out_errors=0)
        h = client_diagnosis._interface_health("192.0.2.20", "GigabitEthernet1/0/5")
        self.assertTrue(h["known"])
        self.assertIsNone(h["error_delta"])
        self.assertIn("un solo campione", h["error_note"])

    def test_no_snmp_says_so(self):
        h = client_diagnosis._interface_health("192.0.2.20", "GigabitEthernet1/0/5")
        self.assertFalse(h["known"])
        self.assertIn("SNMP", h["reason"])


class TestVlanMismatch(_Base):
    """La VLAN arriva da due fonti con eta' diverse: la MAC table (scansione
    manuale) e SNMP (poll automatico). Se non coincidono, la porta e' stata
    spostata dopo l'ultima scansione — il caso in cui il client 'e' ancora
    li'' ma non e' piu' nella rete di prima."""

    def _analysis(self, trunk_allowed):
        return patch("ai.config_analyzer.analyze_device",
                     return_value={"interfaces": [
                         {"name": "Gi1/0/24", "mode": "trunk",
                          "trunk_allowed": trunk_allowed}]})

    def test_moved_port_is_flagged(self):
        self._iface_sample(NOW - 600, 0, 0, port_vlan=20)
        self._iface_sample(NOW - 60, 0, 0, port_vlan=20)
        with self._analysis("10,20"):
            h = client_diagnosis._l2_health(dict(CLIENT, known=True))
        self.assertEqual(h["vlan_mismatch"]["live"], "20")
        self.assertEqual(h["vlan_mismatch"]["mac_table"], "10")
        self.assertIn("MAC scan", h["vlan_mismatch"]["note"])

    def test_the_live_vlan_drives_the_trunk_check(self):
        """Controllare la VLAN vecchia risponderebbe alla domanda di ieri: la
        porta ora e' in VLAN 20, ed e' la 20 che deve passare sul trunk."""
        self._iface_sample(NOW - 600, 0, 0, port_vlan=20)
        self._iface_sample(NOW - 60, 0, 0, port_vlan=20)
        with self._analysis("10,30"):          # la 20 NON passa
            h = client_diagnosis._l2_health(dict(CLIENT, known=True))
        self.assertFalse(h["trunk"]["ok"])
        self.assertEqual(h["trunk"]["vlan"], "20")

    def test_agreement_raises_nothing(self):
        self._iface_sample(NOW - 600, 0, 0, port_vlan=10)
        self._iface_sample(NOW - 60, 0, 0, port_vlan=10)
        with self._analysis("10,20"):
            h = client_diagnosis._l2_health(dict(CLIENT, known=True))
        self.assertNotIn("vlan_mismatch", h)

    def test_without_snmp_vlan_the_mac_table_still_drives_the_check(self):
        """Un apparato senza SNMP non deve perdere il controllo sui trunk."""
        with self._analysis("10,20"):
            h = client_diagnosis._l2_health(dict(CLIENT, known=True))
        self.assertNotIn("vlan_mismatch", h)
        self.assertEqual(h["trunk"]["vlan"], "10")


class TestTrunkCheck(unittest.TestCase):

    def _analysis(self, interfaces):
        return patch("ai.config_analyzer.analyze_device",
                     return_value={"interfaces": interfaces})

    def test_vlan_missing_from_trunk_is_flagged(self):
        with self._analysis([{"name": "Gi1/0/24", "mode": "trunk",
                              "trunk_allowed": "20,30"}]):
            t = client_diagnosis._trunk_check("192.0.2.20", "10")
        self.assertTrue(t["known"])
        self.assertFalse(t["ok"])
        self.assertEqual(t["missing"][0]["interface"], "Gi1/0/24")

    def test_vlan_present_in_a_range_is_not_flagged(self):
        with self._analysis([{"name": "Gi1/0/24", "mode": "trunk",
                              "trunk_allowed": "5,8-14,30"}]):
            t = client_diagnosis._trunk_check("192.0.2.20", "10")
        self.assertTrue(t["ok"])

    def test_trunk_without_allowed_list_carries_everything(self):
        """'switchport mode trunk' senza allowed-vlan = tutte le VLAN passano.
        Segnalarlo sarebbe il falso positivo piu' facile da produrre."""
        with self._analysis([{"name": "Gi1/0/24", "mode": "trunk",
                              "trunk_allowed": ""}]):
            t = client_diagnosis._trunk_check("192.0.2.20", "10")
        self.assertTrue(t["ok"])
        self.assertEqual(t["carrying"][0]["allowed"], "all (default)")

    def test_no_backup_says_so(self):
        with patch("ai.config_analyzer.analyze_device", return_value=None):
            t = client_diagnosis._trunk_check("192.0.2.20", "10")
        self.assertFalse(t["known"])
        self.assertIn("backup", t["reason"])


class TestFortigateResolution(unittest.TestCase):

    def test_arp_gateway_wins(self):
        with patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[FGT_DEVICE,
                                 {"IP": "192.0.2.2", "Vendor": "fortinet"}]):
            fgt = client_diagnosis._resolve_fortigate(
                {"known": True, "gateway_ip": "192.0.2.1"})
        self.assertTrue(fgt["known"])
        self.assertEqual(fgt["ip"], "192.0.2.1")
        self.assertIn("ARP", fgt["resolved_by"])

    def test_single_target_is_used_when_gateway_is_a_switch(self):
        with patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[FGT_DEVICE, SWITCH_DEVICE]):
            fgt = client_diagnosis._resolve_fortigate(
                {"known": True, "gateway_ip": "192.0.2.20"})
        self.assertTrue(fgt["known"])
        self.assertEqual(fgt["ip"], "192.0.2.1")

    def test_several_firewalls_and_no_match_refuses_to_guess(self):
        """Indovinare quale firewall e' sul percorso e' peggio che ammettere
        di non saperlo: manderebbe a leggere le policy sbagliate."""
        with patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}, {"ip": "192.0.2.2"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[FGT_DEVICE,
                                 {"IP": "192.0.2.2", "Vendor": "fortinet"},
                                 SWITCH_DEVICE]):
            fgt = client_diagnosis._resolve_fortigate(
                {"known": True, "gateway_ip": "192.0.2.20"})
        self.assertFalse(fgt["known"])
        self.assertEqual(sorted(fgt["candidates"]), ["192.0.2.1", "192.0.2.2"])


class TestDenies(_Base):

    def test_blocks_are_attributed_to_a_policy(self):
        for _ in range(3):
            self._syslog(NOW - 100,
                         'action="deny" policyid=12 subtype="forward" '
                         'srcip=192.0.2.10 dstip=198.51.100.20 dstport=443',
                         "deny")
        self._syslog(NOW - 100,
                     'utmaction="blocked" policyid=7 subtype="webfilter" '
                     'srcip=192.0.2.10 dstip=198.51.100.30', "blocked")
        d = client_diagnosis._denies({"known": True, "ip": "192.0.2.10"},
                                     "192.0.2.10", None, None)
        self.assertEqual(d["total"], 4)
        self.assertEqual(d["by_policy"][0], {"policy_id": "12",
                                             "subtype": "forward", "count": 3})

    def test_other_clients_are_not_counted(self):
        self._syslog(NOW - 100,
                     'action="deny" srcip=192.0.2.99 dstip=198.51.100.20', "deny")
        d = client_diagnosis._denies({"known": True, "ip": "192.0.2.10"},
                                     "192.0.2.10", None, None)
        self.assertEqual(d["total"], 0)

    def test_allowed_traffic_is_not_a_deny(self):
        self._syslog(NOW - 100,
                     'action="accept" srcip=192.0.2.10 dstip=198.51.100.20',
                     "accept")
        d = client_diagnosis._denies({"known": True, "ip": "192.0.2.10"},
                                     "192.0.2.10", None, None)
        self.assertEqual(d["total"], 0)

    def test_empty_tenant_scope_returns_nothing(self):
        self._syslog(NOW - 100,
                     'action="deny" srcip=192.0.2.10 dstip=198.51.100.20', "deny")
        d = client_diagnosis._denies({"known": True, "ip": "192.0.2.10"},
                                     "192.0.2.10", None, [])
        self.assertEqual(d["total"], 0)


class TestReport(_Base):

    def test_full_report_is_complete(self):
        self._iface_sample(NOW - 600, 0, 0)
        self._iface_sample(NOW - 60, 0, 0)
        targets, inv, diag = _fortigate()
        with _client_map([CLIENT]), targets, inv, diag, \
             patch("ai.config_analyzer.analyze_device",
                   return_value={"interfaces": [
                       {"name": "Gi1/0/24", "mode": "trunk",
                        "trunk_allowed": "10,20"}]}):
            r = client_diagnosis.diagnose("192.0.2.10", dest="198.51.100.20")
        self.assertTrue(r["complete"], r["sections"])
        self.assertEqual(r["resolved_ip"], "192.0.2.10")
        self.assertEqual(set(r["sections"]),
                         {"position", "l2_health", "path", "firewall",
                          "denies", "across_sites"})

    def test_unknown_client_still_asks_the_firewall(self):
        """Il client non e' in mac_history, ma il FortiGate potrebbe conoscerlo
        lo stesso: rinunciare a chiederglielo butterebbe via meta' referto."""
        targets, inv, diag = _fortigate()
        with _client_map([]), targets, inv, diag:
            r = client_diagnosis.diagnose("192.0.2.77")
        self.assertFalse(r["complete"])
        self.assertFalse(r["sections"]["position"]["known"])
        self.assertTrue(r["sections"]["firewall"]["known"])

    def test_a_failing_section_does_not_sink_the_others(self):
        targets, inv, diag = _fortigate(exc=RuntimeError("FGT irraggiungibile"))
        with _client_map([CLIENT]), targets, inv, diag:
            r = client_diagnosis.diagnose("192.0.2.10")
        self.assertIn("irraggiungibile", r["sections"]["firewall"]["error"])
        self.assertTrue(r["sections"]["position"]["known"])
        self.assertFalse(r["complete"])

    def test_partial_path_is_not_a_known_path(self):
        """flowpath parla di 'complete', il referto di 'known'. Un percorso con
        un salto ignoto non e' noto, e il salto mancante va nominato."""
        blind = dict(CLIENT, switch_ip="", switch_name="", switch_port="")
        with _client_map([blind]):
            p = client_diagnosis._path("192.0.2.10", "198.51.100.20", "sede-a")
        self.assertFalse(p["known"])
        self.assertIn("porta di accesso sconosciuta", p["reason"])
        self.assertTrue(p["hops"])

    def test_path_needs_both_ends(self):
        targets, inv, diag = _fortigate()
        with _client_map([CLIENT]), targets, inv, diag:
            r = client_diagnosis.diagnose("192.0.2.10")
        self.assertFalse(r["sections"]["path"]["known"])
        self.assertIn("destinazione", r["sections"]["path"]["reason"])


class TestAgentSiteRelay(_Base):
    """Nelle sedi agent il centrale non raggiunge l'apparato. Fingere di
    provarci significherebbe un timeout; tacere significherebbe far credere
    che non ci sia una policy. Si accoda e si dice."""

    def _agent_site(self):
        return patch("services.client_diagnosis._is_agent_site",
                     return_value=True)

    def test_pending_relay_is_declared(self):
        with self._agent_site(), \
             patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[dict(FGT_DEVICE, Site="milano")]), \
             patch("services.site_manager.find_recent_rest_result",
                   return_value=None), \
             patch("services.site_manager.has_pending_rest_job",
                   return_value=False), \
             patch("services.site_manager.enqueue_job",
                   return_value={"id": "j1"}) as enq:
            f = client_diagnosis._firewall(
                "192.0.2.10", {"known": True, "ip": "192.0.2.10",
                               "gateway_ip": "192.0.2.1"},
                "198.51.100.20", 443, "TCP")
        self.assertFalse(f["known"])
        self.assertTrue(f["policy_lookup"]["pending"])
        # Il job accodato e' un job REST, non una stringa CLI.
        self.assertEqual(enq.call_args.kwargs["kind"], "rest")

    def test_a_ready_relay_result_is_used(self):
        ready = {"status": "done",
                 "result": json.dumps({"results": {"policy_id": 9}})}
        with self._agent_site(), \
             patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[dict(FGT_DEVICE, Site="milano")]), \
             patch("services.site_manager.find_recent_rest_result",
                   return_value=ready):
            f = client_diagnosis._firewall(
                "192.0.2.10", {"known": True, "ip": "192.0.2.10",
                               "gateway_ip": "192.0.2.1"},
                "198.51.100.20", 443, "TCP")
        self.assertTrue(f["policy_lookup"]["known"])
        self.assertEqual(f["policy_lookup"]["data"]["policy_id"], 9)

    def test_no_duplicate_job_while_one_is_queued(self):
        with self._agent_site(), \
             patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[dict(FGT_DEVICE, Site="milano")]), \
             patch("services.site_manager.find_recent_rest_result",
                   return_value=None), \
             patch("services.site_manager.has_pending_rest_job",
                   return_value=True), \
             patch("services.site_manager.enqueue_job") as enq:
            client_diagnosis._firewall(
                "192.0.2.10", {"known": True, "ip": "192.0.2.10",
                               "gateway_ip": "192.0.2.1"},
                "198.51.100.20", 443, "TCP")
        enq.assert_not_called()


class TestResolveEndpoint(_Base):
    """Di quale sede e' un indirizzo, e chi lo fronteggia."""

    def test_observed_arp_wins(self):
        with _client_map([]), \
             patch("collectors.mac_history.search_arp",
                   return_value=[dict(CLIENT, ip="198.51.100.20",
                                      tenant="dc", site="datacenter")]):
            e = client_diagnosis.resolve_endpoint("198.51.100.20")
        self.assertTrue(e["known"])
        self.assertEqual(e["derived"], "observed-arp")
        self.assertEqual(e["site"], "datacenter")
        self.assertEqual(e["gateway_ip"], "192.0.2.1")

    def test_exact_match_only(self):
        """Il LIKE 'ip%' di search_arp non deve far passare un vicino."""
        with patch("collectors.mac_history.search_arp",
                   return_value=[dict(CLIENT, ip="198.51.100.200")]), \
             patch("services.site_manager.list_sites", return_value=[]):
            e = client_diagnosis.resolve_endpoint("198.51.100.20")
        self.assertFalse(e["known"])

    def test_declared_subnet_is_the_fallback(self):
        """Il campo 'subnets' delle sedi esisteva da sempre e non lo leggeva
        nessuno: qui diventa la risposta quando l'indirizzo non e' osservato."""
        with patch("collectors.mac_history.search_arp", return_value=[]), \
             patch("services.site_manager.list_sites", return_value=[
                 {"id": "datacenter", "subnets": ["198.51.100.0/24"]}]):
            e = client_diagnosis.resolve_endpoint("198.51.100.20")
        self.assertTrue(e["known"])
        self.assertEqual(e["derived"], "declared-subnet")
        self.assertEqual(e["site"], "datacenter")

    def test_a_malformed_subnet_does_not_break_the_others(self):
        """Il campo non e' mai stato validato: una riga scritta male non deve
        impedire di leggere quelle giuste."""
        with patch("collectors.mac_history.search_arp", return_value=[]), \
             patch("services.site_manager.list_sites", return_value=[
                 {"id": "rotta", "subnets": ["non-una-subnet", "///"]},
                 {"id": "datacenter", "subnets": ["198.51.100.0/24"]}]):
            e = client_diagnosis.resolve_endpoint("198.51.100.20")
        self.assertEqual(e["site"], "datacenter")

    def test_unlocatable_address_says_so(self):
        with patch("collectors.mac_history.search_arp", return_value=[]), \
             patch("services.site_manager.list_sites", return_value=[]):
            e = client_diagnosis.resolve_endpoint("203.0.113.9")
        self.assertFalse(e["known"])
        self.assertIn("subnet dichiarata", e["reason"])


class TestAcrossSites(_Base):
    """Un flusso fra due sedi attraversa DUE firewall: basta che uno neghi."""

    def _resolve(self, dst):
        return patch("services.client_diagnosis.resolve_endpoint",
                     return_value=dst)

    def test_same_site_needs_no_far_end(self):
        with self._resolve({"known": True, "site": "central",
                            "gateway_ip": "192.0.2.1"}):
            a = client_diagnosis._across_sites(
                {"known": True, "site": "central", "gateway_ip": "192.0.2.1",
                 "ip": "192.0.2.10"}, "192.0.2.50", 443, "TCP", None)
        self.assertTrue(a["same_site"])
        self.assertNotIn("far_end_policy", a)

    def test_far_end_policy_is_consulted(self):
        dst_fgt = {"IP": "203.0.113.1", "Vendor": "fortinet"}
        with self._resolve({"known": True, "site": "datacenter",
                            "gateway_ip": "203.0.113.1"}), \
             patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}, {"ip": "203.0.113.1"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[FGT_DEVICE, dst_fgt]), \
             patch("services.fortigate_service.policy_lookup",
                   return_value={"source": "api", "data": {"policy_id": 9}}), \
             patch("services.fortigate_service.get_vpn_tunnels",
                   return_value={"source": "api", "data": [{"name": "to-dc"}]}), \
             patch("services.fortigate_service.get_route_for",
                   return_value={"source": "api", "data": {"matched": True}}):
            a = client_diagnosis._across_sites(
                {"known": True, "site": "central", "gateway_ip": "192.0.2.1",
                 "ip": "192.0.2.10"}, "198.51.100.20", 443, "TCP", None)
        self.assertFalse(a["same_site"])
        self.assertEqual(a["far_end_policy"]["data"]["policy_id"], 9)
        self.assertTrue(a["tunnels"]["data"])
        self.assertTrue(a["route"]["data"]["matched"])

    def test_unmanaged_far_end_is_declared_not_hidden(self):
        with self._resolve({"known": True, "site": "datacenter",
                            "gateway_ip": "203.0.113.1"}), \
             patch("services.fortigate_service.list_targets",
                   return_value=[{"ip": "192.0.2.1"}]), \
             patch("services.inventory_manager.get_all_devices",
                   return_value=[FGT_DEVICE]), \
             patch("services.fortigate_service.get_vpn_tunnels",
                   return_value={"source": "api", "data": []}), \
             patch("services.fortigate_service.get_route_for",
                   return_value={"source": "api", "data": {"matched": False}}):
            a = client_diagnosis._across_sites(
                {"known": True, "site": "central", "gateway_ip": "192.0.2.1",
                 "ip": "192.0.2.10"}, "198.51.100.20", 443, "TCP", None)
        self.assertFalse(a["far_end_policy"]["known"])
        self.assertIn("non e' fra i target", a["far_end_policy"]["reason"])

    def test_unlocatable_destination_stops_the_comparison(self):
        with self._resolve({"known": False, "reason": "mai osservato"}):
            a = client_diagnosis._across_sites(
                {"known": True, "site": "central", "gateway_ip": "192.0.2.1",
                 "ip": "192.0.2.10"}, "203.0.113.9", 443, "TCP", None)
        self.assertIsNone(a["same_site"])
        self.assertIn("non e' collocabile", a["note"])


class TestEndpoint(_Base):
    """Lo scoping non e' un dettaglio del referto: e' cio' che impedisce a un
    utente di una sede di diagnosticare i client di un'altra."""

    PASS = "PasswordSicura1!"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from security import user_manager
        for user, role, groups in (("adm_diag", "admin", None),
                                   ("op_diag_a", "operator", ["sede-a"])):
            try:
                user_manager.create_user(user, cls.PASS, role=role, groups=groups)
            except Exception:
                pass

    def _client(self, user):
        from fastapi.testclient import TestClient
        import app_server
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login",
                   json={"username": user, "password": self.PASS})
        assert r.status_code == 200, r.text
        # Auth via cookie: sulle POST il deps richiede l'header anti-CSRF,
        # che un form cross-site non puo' impostare.
        c.headers.update({"X-Requested-With": "XMLHttpRequest"})
        return c

    def test_admin_gets_an_unrestricted_report(self):
        seen = {}

        def spy(client, dest, dest_port, protocol, tenants):
            seen["tenants"] = tenants
            return {"client": client, "sections": {}, "complete": False}

        with patch("services.client_diagnosis.diagnose", side_effect=spy):
            r = self._client("adm_diag").post(
                "/api/diagnose/client", json={"client": "192.0.2.10"})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(seen["tenants"])

    def test_operator_is_scoped_to_its_sites(self):
        seen = {}

        def spy(client, dest, dest_port, protocol, tenants):
            seen["tenants"] = tenants
            return {"client": client, "sections": {}, "complete": False}

        with patch("services.client_diagnosis.diagnose", side_effect=spy):
            r = self._client("op_diag_a").post(
                "/api/diagnose/client", json={"client": "192.0.2.10"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(seen["tenants"], ["sede-a"])

    def test_anonymous_is_refused(self):
        from fastapi.testclient import TestClient
        import app_server
        r = TestClient(app_server.app).post(
            "/api/diagnose/client", json={"client": "192.0.2.10"})
        self.assertIn(r.status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
