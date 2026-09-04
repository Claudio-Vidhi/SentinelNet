# -*- coding: utf-8 -*-
"""Accesso o transito: la posizione del client non e' dove il MAC si vede.

La marcatura fatta in raccolta non riconosce i Port-channel — CDP/LLDP
annunciano i vicini sulle porte fisiche membro, mai sull'interfaccia aggregata
— quindi un MAC imparato su Po10 restava is_uplink=0. La tab MAC lo
ricalcolava contro la topologia, la diagnosi no: stessa riga, due verdetti, e
il referto indicava come "porta del client" un punto di transito.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_pos_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP

from collectors import mac_history  # noqa: E402

MAC = "00:11:22:33:44:55"
ACCESS_SW, UPLINK_SW = "192.0.2.6", "192.0.2.7"


def _sighting(switch_ip, interface, port_channel="", is_uplink=0, last_seen="2026-08-01T20:00:00+00:00"):
    return {"mac": MAC, "switch_ip": switch_ip, "switch_name": "sw",
            "interface": interface, "port_channel": port_channel,
            "vlan": "10", "is_uplink": is_uplink, "uplink_to": "",
            "tenant": "t1", "last_seen": last_seen}


class TestAccessPosition(unittest.TestCase):

    def setUp(self):
        self._orig_db = mac_history.DB_PATH
        mac_history.DB_PATH = os.path.join(_TMP, f"mac_{id(self)}.db")
        mac_history._init_done = False
        mac_history.init_db()

    def tearDown(self):
        # DB_PATH e' un globale del modulo: lasciarlo puntare fuori dalla
        # directory della suite faceva fallire test_shared_paths_are_pinned
        # ogni volta che xdist gli assegnava questo worker per secondo --
        # circa una run completa su tre, mai in isolamento. Stesso ripristino
        # che fa gia' test_arp_collector.
        mac_history.DB_PATH = self._orig_db
        mac_history._init_done = False

    def _store(self, rows):
        with mac_history._lock, mac_history._connect() as c:
            for r in rows:
                c.execute(
                    "INSERT INTO mac_sightings(mac, switch_ip, switch_name, interface,"
                    " port_channel, vlan, is_uplink, uplink_to, tenant, first_seen, last_seen)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (r["mac"], r["switch_ip"], r["switch_name"], r["interface"],
                     r["port_channel"], r["vlan"], r["is_uplink"], r["uplink_to"],
                     r["tenant"], r["last_seen"], r["last_seen"]))

    def _topology(self, uplink_map):
        return patch.object(mac_history, "topology_uplinks",
                            return_value=(uplink_map, set(uplink_map)))

    def test_a_portchannel_uplink_is_not_the_client_position(self):
        # Po10 e' piu' recente della porta di accesso: senza la
        # riclassificazione vincerebbe lui, ed e' esattamente cio' che il
        # referto mostrava.
        self._store([
            _sighting(ACCESS_SW, "Ethernet0/0", last_seen="2026-08-01T20:00:00+00:00"),
            _sighting(UPLINK_SW, "Port-channel10", "Port-channel10",
                      last_seen="2026-08-01T20:22:00+00:00"),
        ])
        with self._topology({UPLINK_SW: {"po10": "SW1"}, ACCESS_SW: {"et0/1": "SW2"}}):
            best = mac_history._access_positions_for([MAC], tenants=["t1"])
        pos = best[(MAC, "t1")]
        self.assertEqual(pos["switch_ip"], ACCESS_SW)
        self.assertEqual(pos["interface"], "Ethernet0/0")

    def test_a_portchannel_the_topology_does_not_know_stays_access(self):
        # Un server con bond LACP verso lo switch e' legittimamente su un
        # Port-channel: escluderli tutti perche' 'aggregati' perderebbe la
        # posizione dei server, che e' meta' del punto dello strumento.
        self._store([_sighting(ACCESS_SW, "Port-channel3", "Port-channel3")])
        with self._topology({ACCESS_SW: {"et0/1": "SW2"}}):
            best = mac_history._access_positions_for([MAC], tenants=["t1"])
        self.assertEqual(best[(MAC, "t1")]["interface"], "Port-channel3")

    def test_a_physical_uplink_is_still_excluded(self):
        self._store([
            _sighting(ACCESS_SW, "Ethernet0/3"),
            _sighting(UPLINK_SW, "Ethernet0/0", last_seen="2026-08-01T20:22:00+00:00"),
        ])
        with self._topology({UPLINK_SW: {"et0/0": "SW1"}, ACCESS_SW: {}}):
            best = mac_history._access_positions_for([MAC], tenants=["t1"])
        self.assertEqual(best[(MAC, "t1")]["switch_ip"], ACCESS_SW)

    def test_a_switch_outside_the_topology_keeps_what_was_collected(self):
        # Senza dati topologici la raccolta resta l'unica fonte: sovrascriverla
        # con "accesso" inventerebbe una posizione.
        self._store([_sighting(UPLINK_SW, "Ethernet0/0", is_uplink=1)])
        with self._topology({}):
            best = mac_history._access_positions_for([MAC], tenants=["t1"])
        self.assertEqual(best, {})


if __name__ == "__main__":
    unittest.main()
