# -*- coding: utf-8 -*-
"""Inventario endpoint: una riga per (MAC, tenant), derivata e mai memorizzata.

Parte da mac_sightings — la verita' L2 — e aggancia l'ARP a sinistra. Il
contrario (partire dai binding, come client_map) perderebbe ogni endpoint di
una VLAN il cui gateway non e' interrogabile: proprio quelli che un inventario
deve elencare.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_epinv_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from collectors import mac_history  # noqa: E402

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_RANDOM = "7a:bb:cc:dd:ee:02"      # bit U/L a 1 = amministrato localmente
MAC_VM = "00:50:56:dd:ee:03"          # OUI VMware
MAC_INFRA = "aa:bb:cc:dd:ee:99"


def _iso(days_ago=0):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")


class _Base(unittest.TestCase):
    """DB vero, svuotato a ogni test: la query e' il soggetto della prova."""

    def setUp(self):
        mac_history.init_db()
        with mac_history._lock, mac_history._connect() as c:
            for table in ("mac_sightings", "arp_entries", "switch_if_macs"):
                c.execute(f"DELETE FROM {table}")
        # La topologia non e' il soggetto di questi test: senza switch noti,
        # reclassify_sightings conserva l'is_uplink scritto in raccolta.
        self.topo = patch("collectors.mac_history.topology_uplinks",
                          return_value=({}, set()))
        self.topo.start()
        self.addCleanup(self.topo.stop)
        self.assign = patch("services.inventory_manager.get_category_assignments",
                            return_value={})
        self.assign.start()
        self.addCleanup(self.assign.stop)

    def _sighting(self, mac=MAC_A, tenant="sede-a", switch_ip="192.0.2.1",
                  interface="GigabitEthernet1/0/4", vlan="10", is_uplink=0,
                  first_days=10, last_days=0, site="central",
                  switch_name="switch-01", oui="Example Corp"):
        with mac_history._lock, mac_history._connect() as c:
            c.execute(
                """INSERT INTO mac_sightings
                   (mac, oui_vendor, vlan, switch_ip, switch_name, interface,
                    port_channel, is_uplink, uplink_to, tenant, site,
                    first_seen, last_seen, seen_count)
                   VALUES (?,?,?,?,?,?,'',?,'',?,?,?,?,1)""",
                (mac, oui, vlan, switch_ip, switch_name, interface, is_uplink,
                 tenant, site, _iso(first_days), _iso(last_days)))

    def _arp(self, mac=MAC_A, ip="192.0.2.10", tenant="sede-a",
             source_ip="192.0.2.254"):
        with mac_history._lock, mac_history._connect() as c:
            c.execute(
                """INSERT INTO arp_entries
                   (mac, ip, vlan, interface, source_ip, source_name,
                    source_type, tenant, site, first_seen, last_seen, seen_count)
                   VALUES (?,?,'','',?,'gw','firewall',?,'central',?,?,1)""",
                (mac, ip, source_ip, tenant, _iso(10), _iso(0)))

    def _infra_mac(self, mac=MAC_INFRA, switch_ip="192.0.2.1",
                   interface="Vlan10"):
        with mac_history._lock, mac_history._connect() as c:
            c.execute(
                """INSERT INTO switch_if_macs
                   (mac, switch_ip, switch_name, interface, last_seen)
                   VALUES (?,?,'switch-01',?,?)""",
                (mac, switch_ip, interface, _iso(0)))


class TestRollup(_Base):

    def test_una_riga_per_mac_e_tenant(self):
        """Un tenant e' una rete a se': lo stesso MAC in due sedi e'
        legittimamente due righe, non un duplicato da fondere."""
        self._sighting(tenant="sede-a", switch_ip="192.0.2.1")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["total"], 2)
        self.assertEqual({r["tenant"] for r in out["results"]}, {"sede-a", "sede-b"})

    def test_i_mac_di_interfaccia_switch_sono_esclusi(self):
        """Infrastruttura, non endpoint. Contarli gonfia l'inventario di
        dispositivi che il cliente non possiede."""
        self._sighting(mac=MAC_A)
        self._sighting(mac=MAC_INFRA)
        self._infra_mac(MAC_INFRA)

        out = mac_history.endpoint_inventory()

        self.assertEqual([r["mac"] for r in out["results"]], [MAC_A])

    def test_gli_ip_arrivano_dall_arp_dello_stesso_tenant(self):
        self._sighting(tenant="sede-a")
        self._arp(ip="192.0.2.10", tenant="sede-a")
        self._arp(ip="192.0.2.11", tenant="sede-a")

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["results"][0]["ips"], ["192.0.2.10", "192.0.2.11"])

    def test_la_posizione_e_l_ultima_di_accesso(self):
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/4",
                       last_days=5)
        self._sighting(switch_ip="192.0.2.2", interface="GigabitEthernet2/0/9",
                       last_days=0)

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["results"][0]["switch_ip"], "192.0.2.2")

    def test_gli_uplink_non_sono_una_posizione(self):
        """La porta di un uplink dice dov'e' il cavo, non dov'e' il client."""
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/4",
                       last_days=5)
        self._sighting(switch_ip="192.0.2.9", interface="Port-channel1",
                       is_uplink=1, last_days=0)

        out = mac_history.endpoint_inventory()

        self.assertEqual(out["results"][0]["switch_ip"], "192.0.2.1")
        self.assertEqual(out["results"][0]["access_port_count"], 1)


class TestFlag(_Base):

    def _flags(self, **kw):
        return mac_history.endpoint_inventory(**kw)["results"][0]["flags"]

    def test_ambiguous_due_porte_di_accesso(self):
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/4")
        self._sighting(switch_ip="192.0.2.2", interface="GigabitEthernet2/0/9")
        self._arp()

        self.assertIn("AMBIGUOUS", self._flags())

    def test_no_ip_senza_binding_arp(self):
        """Chi non ha visibilita' L3 localizza comunque il client dalla MAC
        table: l'endpoint c'e', l'IP no, e va detto."""
        self._sighting()

        self.assertIn("NO-IP", self._flags())

    def test_multi_ip(self):
        self._sighting()
        self._arp(ip="192.0.2.10")
        self._arp(ip="192.0.2.11")

        self.assertIn("MULTI-IP", self._flags())

    def test_random_mac_amministrato_localmente(self):
        """Il binding vale per questa sessione e basta: correlare uno storico
        su di esso inventa continuita' dove non ce n'e'."""
        self._sighting(mac=MAC_RANDOM)

        self.assertIn("RANDOM", self._flags())

    def test_vm_oui_di_virtualizzazione(self):
        self._sighting(mac=MAC_VM)

        flags = self._flags()
        self.assertIn("VM", flags)
        self.assertNotIn("RANDOM", flags)

    def test_transit_only_visto_solo_su_uplink(self):
        """Endpoint reale dietro uno switch non gestito: resta in elenco."""
        self._sighting(interface="Port-channel1", is_uplink=1)

        out = mac_history.endpoint_inventory()
        self.assertEqual(out["total"], 1)
        self.assertIn("TRANSIT-ONLY", out["results"][0]["flags"])
        self.assertEqual(out["results"][0]["access_port_count"], 0)

    def test_stale_oltre_la_soglia(self):
        self._sighting(first_days=40, last_days=30)

        self.assertIn("STALE", self._flags(stale_days=7))

    def test_non_stale_dentro_la_soglia(self):
        self._sighting(first_days=40, last_days=2)

        self.assertNotIn("STALE", self._flags(stale_days=7))

    def test_new_primo_avvistamento_recente(self):
        self._sighting(first_days=1, last_days=0)

        self.assertIn("NEW", self._flags(stale_days=7))

    def test_non_new_se_visto_da_tempo(self):
        self._sighting(first_days=40, last_days=0)

        self.assertNotIn("NEW", self._flags(stale_days=7))


class TestFiltriEScoping(_Base):

    def test_lo_scoping_per_tenant_e_una_barriera(self):
        """Un utente della sede A non vede mai una riga della sede B."""
        self._sighting(tenant="sede-a")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        out = mac_history.endpoint_inventory(tenants=["sede-a"])

        self.assertEqual(out["total"], 1)
        self.assertEqual(out["results"][0]["tenant"], "sede-a")

    def test_scope_vuoto_non_e_scope_assente(self):
        """[] significa 'nessun tenant visibile'. Trattarlo come None
        mostrerebbe tutto proprio a chi non puo' vedere niente."""
        self._sighting(tenant="sede-a")

        self.assertEqual(mac_history.endpoint_inventory(tenants=[])["total"], 0)

    def test_filtro_per_switch(self):
        self._sighting(switch_ip="192.0.2.1")
        self._sighting(mac=MAC_VM, switch_ip="192.0.2.2")

        out = mac_history.endpoint_inventory(switch_ip="192.0.2.2")

        self.assertEqual([r["mac"] for r in out["results"]], [MAC_VM])

    def test_ricerca_libera_su_mac_e_vendor(self):
        self._sighting(mac=MAC_A, oui="Example Corp")
        self._sighting(mac=MAC_VM, oui="Altro Vendor")

        self.assertEqual(mac_history.endpoint_inventory(q="ee:01")["total"], 1)
        self.assertEqual(mac_history.endpoint_inventory(q="Example")["total"], 1)

    def test_limite_dichiarato_non_silenzioso(self):
        """Una tabella HTML non regge decine di migliaia di righe: si taglia e
        lo si DICE, cosi' l'export puo' avvertire che esporta cio' che vede."""
        for i in range(5):
            self._sighting(mac=f"aa:bb:cc:dd:ee:1{i}")

        out = mac_history.endpoint_inventory(limit=2)

        self.assertEqual(len(out["results"]), 2)
        self.assertEqual(out["total"], 5)
        self.assertTrue(out["truncated"])

    def test_contatori(self):
        self._sighting(mac=MAC_A, switch_ip="192.0.2.1", vlan="10")
        self._sighting(mac=MAC_VM, switch_ip="192.0.2.2", vlan="20")
        self._arp(mac=MAC_A)

        counts = mac_history.endpoint_inventory()["counts"]

        self.assertEqual(counts["endpoints"], 2)
        self.assertEqual(counts["switches"], 2)
        self.assertEqual(counts["vlans"], 2)
        self.assertEqual(counts["no_ip"], 1)


class TestOccupazionePorte(_Base):
    """L'elenco interfacce viene da switch_if_macs, popolata a ogni scansione
    MAC da collect_interface_macs(). Quando manca, si dice che manca."""

    def setUp(self):
        super().setUp()
        self._porta_n = 0

    def _porta(self, interface, switch_ip="192.0.2.1"):
        """Una porta nell'elenco interfacce dello switch. Il MAC e' quello
        DELL'INTERFACCIA (infrastruttura): un contatore basta, purche' sia
        deterministico — un hash di stringa cambia a ogni processo."""
        self._porta_n += 1
        self._infra_mac(mac=f"aa:bb:cc:00:00:{self._porta_n:02d}",
                        switch_ip=switch_ip, interface=interface)

    def test_porta_occupata_e_porta_libera(self):
        self._porta("GigabitEthernet1/0/1")
        self._porta("GigabitEthernet1/0/2")
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/1")

        out = mac_history.port_occupancy("192.0.2.1")
        stati = {p["interface"]: p["state"] for p in out["ports"]}

        self.assertTrue(out["port_list_known"])
        self.assertEqual(stati["GigabitEthernet1/0/1"], "occupied")
        self.assertEqual(stati["GigabitEthernet1/0/2"], "free")

    def test_elenco_assente_non_e_zero_porte_libere(self):
        """Se la raccolta if_macs e' fallita — non e' fatale — rispondere
        'zero porte libere' manderebbe a cercare nel posto sbagliato."""
        self._sighting(switch_ip="192.0.2.7", interface="GigabitEthernet1/0/1")

        out = mac_history.port_occupancy("192.0.2.7")

        self.assertFalse(out["port_list_known"])
        self.assertEqual(out["ports"], [])

    def test_un_uplink_noto_alla_topologia_non_e_libero(self):
        """Una porta di trunk momentaneamente muta non e' una porta libera:
        proporla come tale manda a infilare un cavo in un uplink.

        La chiave della mappa e' il nome NORMALIZZATO da
        ``core_engine._normalize_iface()``: alias sul prefisso ('gigabit...'
        -> 'gi') e numerazione con le barre invariata, quindi
        'GigabitEthernet1/0/24' diventa 'gi1/0/24'.
        Un patch annidato sullo stesso bersaglio ripristina il mock esterno
        all'uscita: non serve fermare quello di setUp.
        """
        self._porta("GigabitEthernet1/0/24")
        with patch("collectors.mac_history.topology_uplinks",
                   return_value=({"192.0.2.1": {"gi1/0/24": "switch-02"}},
                                 {"192.0.2.1"})):
            out = mac_history.port_occupancy("192.0.2.1")

        porta = next(p for p in out["ports"]
                     if p["interface"] == "GigabitEthernet1/0/24")
        self.assertEqual(porta["state"], "uplink")
        self.assertEqual(porta["uplink_to"], "switch-02")

    def test_le_interfacce_non_fisiche_non_contano_come_libere(self):
        """Vlan10 resta visibile, ma non e' una porta in cui infilare un cavo."""
        self._porta("GigabitEthernet1/0/1")
        self._porta("Vlan10")

        out = mac_history.port_occupancy("192.0.2.1")
        vlan_port = next(p for p in out["ports"] if p["interface"] == "Vlan10")

        self.assertFalse(vlan_port["physical"])
        self.assertEqual(out["counts"]["free"], 1)      # solo la Gi, non la Vlan

    def test_scoping_per_tenant(self):
        self._porta("GigabitEthernet1/0/1")
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/1",
                       tenant="sede-b")

        out = mac_history.port_occupancy("192.0.2.1", tenants=["sede-a"])
        porta = next(p for p in out["ports"]
                     if p["interface"] == "GigabitEthernet1/0/1")

        self.assertEqual(porta["state"], "free", "il MAC di sede-b non e' visibile")


class TestRotte(_Base):
    """Sola lettura: get_current_user basta, require_operator no."""

    def setUp(self):
        super().setUp()
        from routers import endpoint_inventory as ep_router
        self.router = ep_router

    def test_tenant_indicato_restringe(self):
        self._sighting(tenant="sede-a")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        out = self.router.endpoints_list(tenant="sede-a",
                                         current_user={"sub": "a", "role": "admin"})

        self.assertEqual(out["total"], 1)

    def test_tenant_fuori_scope_e_403(self):
        from fastapi import HTTPException
        with patch("routers.endpoint_inventory.user_group_scope",
                   return_value={"sede-a"}):
            with self.assertRaises(HTTPException) as ctx:
                self.router.endpoints_list(tenant="sede-b",
                                           current_user={"sub": "v", "role": "viewer"})
        self.assertEqual(ctx.exception.status_code, 403)

    def test_lo_scope_dell_utente_e_applicato_senza_chiederlo(self):
        """Il filtro non e' un'opzione: senza parametro vale comunque il
        profilo dell'utente."""
        self._sighting(tenant="sede-a")
        self._sighting(tenant="sede-b", switch_ip="198.51.100.1")

        with patch("routers.endpoint_inventory.user_group_scope",
                   return_value={"sede-b"}):
            out = self.router.endpoints_list(current_user={"sub": "v", "role": "viewer"})

        self.assertEqual([r["tenant"] for r in out["results"]], ["sede-b"])

    def test_ports_richiede_lo_switch(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self.router.endpoints_ports(switch="  ",
                                        current_user={"sub": "a", "role": "admin"})
        self.assertEqual(ctx.exception.status_code, 400)


class TestRotteRegistrate(unittest.TestCase):
    def test_le_rotte_sono_nell_app(self):
        import app_server
        paths = {r.path for r in app_server.app.routes}
        self.assertIn("/api/endpoints/list", paths)
        self.assertIn("/api/endpoints/ports", paths)
