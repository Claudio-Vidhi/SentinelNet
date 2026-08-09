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

    def test_gli_avvistamenti_sono_scopati_per_tenant(self):
        """Questo livello (``port_occupancy``) scopa solo gli AVVISTAMENTI: un
        MAC di un tenant non visibile non compare fra quelli occupanti la
        porta. Non prova — e non deve provare — che l'intero switch sia
        raggiungibile da chi chiama: quel controllo sta nel router
        (``assert_device_allowed`` in ``endpoints_ports()``), perche'
        ``switch_if_macs`` non ha una colonna tenant e questa funzione non sa
        a chi appartiene lo switch."""
        self._porta("GigabitEthernet1/0/1")
        self._sighting(switch_ip="192.0.2.1", interface="GigabitEthernet1/0/1",
                       tenant="sede-b")

        out = mac_history.port_occupancy("192.0.2.1", tenants=["sede-a"])
        porta = next(p for p in out["ports"]
                     if p["interface"] == "GigabitEthernet1/0/1")

        self.assertEqual(porta["state"], "free",
                         "il MAC di sede-b non e' fra gli avvistamenti visibili")


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

    def test_ports_e_403_per_uno_switch_fuori_dal_tenant(self):
        """``switch_if_macs`` non ha colonna tenant: senza un controllo
        sull'apparato stesso, un operatore di sede-a poteva chiedere le porte
        di uno switch di sede-b e riceverne comunque l'elenco completo — con
        una porta occupata da sede-b che tornava pure "free"."""
        from fastapi import HTTPException
        with patch("services.inventory_manager.get_all_devices",
                   return_value=[{"IP": "198.51.100.1", "Group": "sede-b"}]), \
             patch("routers.deps.user_group_scope", return_value={"sede-a"}):
            with self.assertRaises(HTTPException) as ctx:
                self.router.endpoints_ports(
                    switch="198.51.100.1",
                    current_user={"sub": "op", "role": "operator"})
        self.assertEqual(ctx.exception.status_code, 403)

    def test_ports_e_404_per_switch_non_in_inventario(self):
        from fastapi import HTTPException
        with patch("services.inventory_manager.get_all_devices", return_value=[]):
            with self.assertRaises(HTTPException) as ctx:
                self.router.endpoints_ports(
                    switch="192.0.2.250",
                    current_user={"sub": "a", "role": "admin"})
        self.assertEqual(ctx.exception.status_code, 404)


class TestLetturaSenzaLock(_Base):
    """Il lock serializza gli SCRITTORI: SQLite ne ammette uno solo. I lettori
    non lo prendono — il DB e' in WAL, dove un lettore non blocca ne' lo
    scrittore ne' gli altri lettori. Tenerlo anche in lettura faceva si' che un
    endpoint_inventory() completo fermasse ogni altra query del processo per
    tutta la sua durata.

    Prova deterministica: si tiene il lock nel thread principale e si verifica
    che una lettura in un altro thread arrivi in fondo lo stesso. Misurare i
    tempi sarebbe instabile; questo o passa o va in timeout."""

    def _read_while_locked(self, fn):
        import threading
        done, box = threading.Event(), {}

        def run():
            try:
                box["res"] = fn()
            except Exception as e:      # pragma: no cover - solo diagnostica
                box["err"] = e
            finally:
                done.set()

        with mac_history._lock:
            threading.Thread(target=run, daemon=True).start()
            arrived = done.wait(timeout=10)
        self.assertTrue(arrived, f"{fn.__name__} ha atteso il lock di scrittura")
        self.assertNotIn("err", box, f"lettura fallita: {box.get('err')}")
        return box["res"]

    def test_endpoint_inventory_non_attende_il_lock(self):
        self._read_while_locked(mac_history.endpoint_inventory)

    def test_search_arp_non_attende_il_lock(self):
        self._read_while_locked(mac_history.search_arp)

    def test_search_non_attende_il_lock(self):
        self._read_while_locked(mac_history.search)

    def test_stats_non_attende_il_lock(self):
        self._read_while_locked(mac_history.stats)

    def test_le_scritture_il_lock_lo_prendono_ancora(self):
        # Il complemento: se anche gli scrittori smettessero di prenderlo, due
        # scansioni concorrenti tornerebbero a corrersi addosso su SQLite.
        import threading
        started = threading.Event()

        def write():
            started.set()
            mac_history.set_retention_days(21)

        with mac_history._lock:
            t = threading.Thread(target=write, daemon=True)
            t.start()
            started.wait(timeout=5)
            t.join(timeout=0.5)
            self.assertTrue(t.is_alive(), "una scrittura NON deve passare "
                                          "mentre il lock e' tenuto")
        t.join(timeout=10)
        self.assertEqual(mac_history.get_retention_days(), 21)


class TestRotteRegistrate(unittest.TestCase):
    def test_le_rotte_sono_nell_app(self):
        import app_server
        paths = {r.path for r in app_server.app.routes}
        self.assertIn("/api/endpoints/list", paths)
        self.assertIn("/api/endpoints/ports", paths)


class TestTabFrontend(unittest.TestCase):
    """Verifica grep-style: non c'e' un runner JS."""

    @classmethod
    def setUpClass(cls):
        from tests.test_helpers_frontend import frontend_source
        cls.src = frontend_source()

    def _fn(self, signature):
        """Il corpo di UNA funzione, dalla sua firma alla successiva.

        Le fette a lunghezza fissa (``src[start:start+900]``) sembrano
        innocue e si rompono in silenzio: quando la funzione cresce, la
        riga cercata finisce fuori dalla fetta e il test fallisce (o peggio,
        passa) per un motivo che non c'entra con cio' che verifica.
        """
        start = self.src.index(signature)
        rest = self.src[start + len(signature):]
        ends = [i for i in (rest.find("\nfunction "), rest.find("\nasync function "),
                            rest.find("\nconst "), rest.find("\nlet ")) if i != -1]
        return self.src[start:start + len(signature) + (min(ends) if ends else len(rest))]

    def _file(self, rel):
        """Un file solo. ``frontend_source()`` concatena tutto il frontend,
        quindi non distingue "questa chiamata sta nel markup" da "sta in un
        altro script": per contare i chiamanti serve il file singolo."""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, *rel.split("/")), encoding="utf-8") as fh:
            return fh.read()

    def test_la_tab_esiste_ed_e_raggiungibile(self):
        self.assertIn('id="tab-endpoints"', self.src)
        self.assertIn("switchTab('tab-endpoints')", self.src)

    def test_e_la_quarta_sorella_del_gruppo_client(self):
        """Le altre tre sotto-tab devono puntarle, altrimenti si raggiunge
        solo da una direzione."""
        self.assertIn('data-tabs="tab-mac tab-clientmap tab-diagnosi tab-endpoints"',
                      self.src)

    def test_lo_script_e_incluso(self):
        self.assertIn('src="/static/js/endpoint-inventory.js"', self.src)

    def test_le_chiavi_i18n_esistono_in_entrambe_le_lingue(self):
        for key in ("tabEndpoints", "epKpiEndpoints", "epKpiStale", "epThMac",
                    "epExportCsv", "epPortsFreeWarn"):
            self.assertGreaterEqual(self.src.count(key + ":"), 2,
                                    f"chiave {key} assente in una delle due lingue")

    def test_le_icone_stanno_dentro_le_stringhe_i18n(self):
        """changeLanguage() sostituisce innerHTML in blocco: un'icona fuori
        dalla stringa sparisce al cambio lingua."""
        self.assertIn("tabEndpoints: '<i class=", self.src)

    def test_l_export_e_lato_client(self):
        """Stesso schema di topology.js: nessuna rotta di export, nessun
        secondo formattatore che col tempo diverge dall'ordine di colonne."""
        self.assertIn("function endpointsExport(", self.src)
        self.assertIn("new Blob(", self.src)
        self.assertNotIn("/api/endpoints/export", self.src)

    def test_l_export_avverte_quando_le_righe_sono_tagliate(self):
        """Esportare 2000 righe di 4711 senza dirlo consegna un inventario
        parziale spacciato per intero."""
        self.assertIn("epExportPartial", self.src)

    def test_il_click_di_riga_passa_anche_il_tenant(self):
        """La riga sa gia' la sede: passarla evita alla diagnosi di dover
        chiedere quello che qui e' gia' noto."""
        self.assertIn("function endpointsDiagnose(mac, tenant)", self.src)
        self.assertIn("_diagTenant = tenant", self.src)

    def test_nessun_secondo_renderer_del_referto(self):
        """Il referto si rende in un posto solo: due copie sarebbero due
        copie da tenere allineate."""
        self.assertEqual(self.src.count("function renderDiagnosi("), 1)

    def test_il_selettore_switch_viene_dall_inventario_non_dagli_endpoint(self):
        """Costruirlo da _epRows mostrava solo gli switch che erano la
        posizione di accesso VINCENTE di almeno un endpoint: uno switch senza
        endpoint non compariva mai, cioe' proprio quello con piu' porte
        libere. La domanda della vista e' 'dove ho spazio', non 'dove ho
        gia' qualcosa'."""
        body = self._fn("function endpointsMode(mode)")
        self.assertIn("globalDevices", body)
        self.assertNotIn("_epRows.forEach", body)

    def test_la_select_del_tenant_ricarica_da_sola(self):
        """Senza onchange la select non era agganciata a niente: cambiare
        tenant lasciava a schermo i dispositivi di quello precedente."""
        self.assertIn('id="epFilterTenant" onchange="endpointsApplyFilters()"',
                      self.src)

    def test_nessun_filtro_scavalca_la_modalita(self):
        """Un controllo di filtro che chiama endpointsSearch() ridipinge
        elenco e KPI anche in modalita' porte, sovrapponendo due viste. Il
        markup deve passare SEMPRE da endpointsApplyFilters()."""
        dash = self._file("templates/dashboard.html")

        self.assertNotIn("endpointsSearch()", dash)
        # ricerca (invio), tenant (change), soglia (change e invio), pulsante.
        self.assertEqual(dash.count("endpointsApplyFilters()"), 5)

    def test_applica_filtri_ridisegna_nella_modalita_corrente(self):
        """Con il tenant cambiato gli switch sono altri: in modalita' porte il
        selettore va ricostruito, non lasciato a quello di prima."""
        body = self._fn("async function endpointsApplyFilters()")
        self.assertIn("await endpointsSearch()", body)
        self.assertIn("_epMode === 'ports'", body)
        self.assertLess(body.index("await endpointsSearch()"),
                        body.index("_epMode === 'ports'"))

    def test_il_client_e_impostato_prima_di_lanciare_la_diagnosi(self):
        """runDiagnosi() azzera _diagTenant quando il client cambia: se
        endpointsDiagnose non impostasse _diagClient prima, il tenant appena
        passato verrebbe buttato e la diagnosi tornerebbe a chiedere la sede."""
        body = self._fn("function endpointsDiagnose(mac, tenant)")
        self.assertLess(body.index("_diagClient = mac"), body.index("runDiagnosi()"))

    def test_le_avvertenze_sulle_porte_sono_a_schermo(self):
        """Le quattro avvertenze della spec vivono nella UI, non nei commenti:
        chi legge sta per andare a infilare un cavo.

        Scoped al corpo di endpointsPortsRender: le chiavi i18n esistono gia'
        in i18n.js da un task precedente, quindi cercarle su self.src intero
        passerebbe anche se il renderer non le usasse mai."""
        body = self._fn("function endpointsPortsRender(")
        self.assertIn("L.epPortsFreeWarn", body)     # libera != nessun cavo
        self.assertIn("L.epPortsUnknown", body)      # elenco assente != 0 libere
        self.assertIn("L.epPortsAge", body)          # eta' dell'elenco

    def test_elenco_porte_assente_non_mostra_zero_libere(self):
        """Il ramo dell'elenco mancante deve uscire PRIMA di qualunque
        conteggio, altrimenti mostrerebbe 0 libere su 0 porte."""
        body = self._fn("function endpointsPortsRender(")
        self.assertLess(body.index("port_list_known"), body.index("counts"))

    def test_le_porte_non_fisiche_sono_visibili_ma_marcate(self):
        self.assertIn("p.physical", self.src)

    def test_il_filtro_tenant_viene_popolato_al_caricamento_della_tab(self):
        """La select epFilterTenant restava vuota per sempre: nessuno la
        popolava, quindi il parametro tenant non veniva mai spedito."""
        body = self._fn("function loadEndpointsTab(")
        self.assertIn("populateEndpointsTenantFilter()", body)
        self.assertIn("function populateEndpointsTenantFilter(", self.src)
        self.assertIn("getElementById('epFilterTenant')", self.src)

    def test_i_kpi_si_svuotano_in_modalita_porte(self):
        """Sei numeri validi per l'intero inventario non possono restare a
        schermo sopra la tabella di UN solo switch: leggerebbero come fatti
        su quello switch."""
        body = self._fn("function endpointsMode(")
        self.assertLess(body.index("epKpis"), body.index("endpointsPorts()"))

    def test_ports_in_errore_mostra_un_messaggio_non_la_tabella_vecchia(self):
        """Stesso schema di endpointsSearch() per la stessa condizione: un
        fetch fallito non deve lasciare a schermo l'elenco endpoint della
        modalita' precedente spacciato per occupazione porte."""
        body = self._fn("async function endpointsPorts(")
        self.assertIn("host.innerHTML", body)
        self.assertIn("!res || !res.ok", body)

    def test_la_riga_ha_le_azioni_esplicite(self):
        """Il click sulla riga diagnosticava gia', ma non lo sapeva nessuno:
        niente lo diceva. Le tre azioni sono ora visibili come pulsanti."""
        body = self._fn("function endpointsRender(d)")
        self.assertIn("endpointsDiagnose(", body)
        self.assertIn("macLocate(", body)
        self.assertIn("showPortConfig(", body)

    def test_i_pulsanti_non_fanno_partire_anche_il_click_di_riga(self):
        """Senza stopPropagation il pulsante lancia la sua azione E la
        diagnosi della riga: due schermate per un click. La chiamata sta
        UNA volta nell'helper `act`, comune ai tre pulsanti.

        Si asserisce sulle TRE icone distintive e non su un conteggio di
        ``act(``: quel token di tre lettere lo produrrebbe anche un futuro
        ``compact(`` o la parola dentro un commento, e su questo ramo i
        conteggi di sottostringhe generiche hanno gia' rotto due test.
        """
        body = self._fn("function endpointsRender(d)")
        self.assertIn("event.stopPropagation()", body)
        for icon in ("fa-stethoscope", "fa-magnifying-glass-location",
                     "fa-file-lines"):
            self.assertIn(icon, body)

    def test_la_configurazione_porta_si_offre_solo_se_c_e_una_porta(self):
        """Un endpoint TRANSIT-ONLY non ha switch ne' interfaccia: il
        pulsante aprirebbe la configurazione di un'interfaccia vuota."""
        body = self._fn("function endpointsRender(d)")
        self.assertIn("r.switch_ip && r.interface", body)

    def test_le_nuove_chiavi_i18n_esistono_in_entrambe_le_lingue(self):
        """Stessa convenzione del test analogo gia' in questa classe: una
        chiave presente in un solo dizionario darebbe un titolo vuoto
        nell'altra lingua."""
        for key in ("epThActions", "epActDiagnose", "epActLocate",
                    "epActPortCfg"):
            self.assertGreaterEqual(self.src.count(key + ":"), 2,
                                    f"chiave {key} assente in una delle lingue")

class TestInventarioMemoizzato(_Base):
    """Il referto si ricalcola quando i dati cambiano, non ad ogni chiamata.

    I sette KPI non sono esprimibili in SQL: per contarli onestamente bisogna
    materializzare ogni riga del tenant. La domanda aperta era se renderli
    approssimati; la risposta e no, basta non rifare lo stesso lavoro fra
    una scansione e laltra. Questi test fissano il patto: stessa versione
    dei dati = stesso referto senza ricalcolo, dati nuovi = referto nuovo.
    """

    def setUp(self):
        super().setUp()
        mac_history._INVENTORY_CACHE.clear()
        self.addCleanup(mac_history._INVENTORY_CACHE.clear)

    def _conta_ricalcoli(self):
        vero = mac_history.reclassify_sightings
        self.calls = 0

        def spia(rows):
            self.calls += 1
            return vero(rows)

        p = patch("collectors.mac_history.reclassify_sightings", side_effect=spia)
        p.start()
        self.addCleanup(p.stop)

    def test_stessa_versione_dei_dati_niente_ricalcolo(self):
        self._sighting(mac=MAC_A)
        self._conta_ricalcoli()
        primo = mac_history.endpoint_inventory(tenants=["sede-a"])
        secondo = mac_history.endpoint_inventory(tenants=["sede-a"])
        self.assertEqual(self.calls, 1, "il secondo referto ha rifatto il lavoro")
        self.assertEqual(primo, secondo)

    def test_un_avvistamento_nuovo_invalida_il_referto(self):
        self._sighting(mac=MAC_A)
        self._conta_ricalcoli()
        prima = mac_history.endpoint_inventory(tenants=["sede-a"])
        self.assertEqual(prima["counts"]["endpoints"], 1)

        self._sighting(mac=MAC_VM, interface="GigabitEthernet1/0/9")
        dopo = mac_history.endpoint_inventory(tenants=["sede-a"])
        self.assertEqual(self.calls, 2, "la scrittura non ha invalidato il referto")
        self.assertEqual(dopo["counts"]["endpoints"], 2)

    def test_chi_riceve_il_referto_non_puo_corromperlo(self):
        self._sighting(mac=MAC_A)
        primo = mac_history.endpoint_inventory(tenants=["sede-a"])
        primo["results"].clear()
        primo["counts"]["endpoints"] = 999
        secondo = mac_history.endpoint_inventory(tenants=["sede-a"])
        self.assertEqual(secondo["counts"]["endpoints"], 1)
        self.assertEqual(len(secondo["results"]), 1)

    def test_filtri_diversi_referti_diversi(self):
        """La chiave e (filtri + versione): due filtri non devono confondersi."""
        self._sighting(mac=MAC_A, tenant="sede-a")
        self._sighting(mac=MAC_VM, tenant="sede-b", interface="GigabitEthernet1/0/9")
        a = mac_history.endpoint_inventory(tenants=["sede-a"])
        b = mac_history.endpoint_inventory(tenants=["sede-b"])
        self.assertEqual(a["counts"]["endpoints"], 1)
        self.assertEqual(b["counts"]["endpoints"], 1)
        self.assertNotEqual(a["results"][0]["mac"], b["results"][0]["mac"])
