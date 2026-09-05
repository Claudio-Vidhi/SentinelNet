# -*- coding: utf-8 -*-
"""Una tabella di routing sola, dagli apparati che gia' la pubblicano.

Non c'e' raccolta nuova: la vista chiama lo stesso get_routes della tab
FortiGate su piu' apparati e ne normalizza le risposte. Quello che va
sorvegliato e' percio' il confine, non il protocollo: lo scope per sede, il
fatto che un apparato irraggiungibile non svuoti la tabella degli altri, e che
un tipo di rotta sconosciuto non venga ribattezzato.
"""
import os
import unittest
from unittest import mock

from fastapi.testclient import TestClient  # noqa: E402

# Nessun SENTINELNET_DATA_DIR nostro, e nessun data_config.DATA_DIR riscritto:
# conftest.py ha gia' scelto la directory della suite e vi ha legato le
# costanti. Ripuntarla qui la sposterebbe per OGNI modulo importato dopo di
# noi sullo stesso worker xdist, e cio' che quel modulo scrive finirebbe dove
# nessun altro lo cerca. Questo modulo non ne ha bisogno: l'inventario e' un
# mock, e gli utenti stanno bene dove stanno tutti gli altri.
import app_server  # noqa: E402
from security import user_manager  # noqa: E402
from services import fortigate_service, route_table  # noqa: E402

PASS = "PasswordSicura1!"

FGT_A = {"IP": "192.0.2.1", "Hostname": "fw-edge", "Vendor": "fortinet",
         "Group": "sede-a", "Site": "central"}
FGT_B = {"IP": "192.0.2.2", "Hostname": "fw-dc", "Vendor": "fortinet",
         "Group": "sede-b", "Site": "central"}
SWITCH = {"IP": "192.0.2.3", "Hostname": "sw-core", "Vendor": "cisco",
          "Group": "sede-a", "Site": "central"}

ROUTES_A = [
    {"ip_mask": "10.0.0.0/16", "gateway": "192.0.2.254", "interface": "port1",
     "type": "static", "distance": 10, "metric": 0},
    {"ip_mask": "10.1.0.0/24", "gateway": "", "interface": "port2",
     "type": "connect", "distance": 0, "metric": 0},
    {"ip_mask": "0.0.0.0/0", "gateway": "192.0.2.254", "interface": "port1",
     "type": "BGP", "distance": 20, "metric": 100},
]
IOS_OUTPUT = """Codes: L - local, C - connected, S - static, B - BGP, O - OSPF
       IA - OSPF inter area, D - EIGRP

Gateway of last resort is 192.0.2.254 to network 0.0.0.0

S*    0.0.0.0/0 [1/0] via 192.0.2.254
      10.0.0.0/8 is variably subnetted, 4 subnets, 2 masks
C        10.1.10.0/24 is directly connected, Vlan10
L        10.1.10.1/32 is directly connected, Vlan10
O IA     10.2.0.0/16 [110/20] via 10.1.10.2, 00:05:23, Vlan10
B        192.168.0.0/16 [20/0] via 10.1.10.3, 1d02h
S        172.16.0.0/12 [1/0] via 10.1.10.4
                       [1/0] via 10.1.10.5
"""

ROUTES_B = [
    {"ip_mask": "172.16.0.0/12", "gateway": "198.51.100.1", "interface": "port5",
     "type": "ospf", "distance": 110, "metric": 20},
]


class TypeNormalisation(unittest.TestCase):
    def test_the_families_the_view_groups_on(self):
        for raw, want in (("connect", "connected"), ("CONNECTED", "connected"),
                          ("static", "static"), ("ospf-external", "ospf"),
                          ("BGP", "bgp"), ("rip", "rip")):
            self.assertEqual(route_table.normalize_type(raw), want, raw)

    def test_an_unknown_type_is_not_renamed(self):
        # Ribattezzare 'static' cio' che il firewall ha chiamato altrimenti e'
        # il genere di dettaglio che poi si legge come un fatto.
        self.assertEqual(route_table.normalize_type("eigrp-ex"), "other")
        self.assertEqual(route_table.normalize_type(""), "unknown")
        self.assertEqual(route_table.normalize_type(None), "unknown")


class DeviceSelection(unittest.TestCase):
    def test_fortigates_over_rest_and_cisco_over_cli(self):
        got = route_table.routable_devices([FGT_A, SWITCH, FGT_B])
        self.assertEqual([d["IP"] for d in got],
                         ["192.0.2.1", "192.0.2.3", "192.0.2.2"])
        self.assertEqual(route_table.route_source(FGT_A), "rest")
        self.assertEqual(route_table.route_source(SWITCH), "ios-cli")

    def test_a_vendor_without_a_parser_stays_out(self):
        # Aruba risponde a `show ip route` con un'altra impaginazione:
        # includerlo qui senza il suo parser darebbe una tabella vuota
        # presentata come "nessuna rotta".
        aruba = {"IP": "192.0.2.4", "Hostname": "sw-aruba", "Vendor": "aruba"}
        self.assertEqual(route_table.route_source(aruba), "")
        self.assertEqual(route_table.routable_devices([aruba]), [])

    def test_a_device_without_an_address_is_skipped(self):
        self.assertEqual(route_table.routable_devices(
            [{"Vendor": "fortinet", "Hostname": "orphan"}]), [])


class SingleDeviceCollection(unittest.TestCase):
    def test_api_rows_are_normalised(self):
        with mock.patch.object(fortigate_service, "get_routes",
                               return_value={"source": "api", "data": ROUTES_A}):
            out = route_table.collect_for(FGT_A)
        self.assertEqual([r["type"] for r in out["rows"]],
                         ["static", "connected", "bgp"])
        first = out["rows"][0]
        self.assertEqual(first["device"], "fw-edge")
        self.assertEqual(first["network"], "10.0.0.0/16")
        self.assertEqual(first["interface"], "port1")
        # Il tipo grezzo resta accanto a quello normalizzato: la vista raggruppa
        # sul secondo, chi sospetta della normalizzazione legge il primo.
        self.assertEqual(out["rows"][2]["raw_type"], "BGP")

    def test_a_cli_text_answer_is_declared_not_parsed(self):
        with mock.patch.object(
                fortigate_service, "get_routes",
                return_value={"source": "ssh", "data": "S* 0.0.0.0/0 [10/0]"}):
            out = route_table.collect_for(FGT_A)
        self.assertNotIn("rows", out)
        self.assertIn("testo CLI", out["error"])

    def test_an_unreachable_device_returns_an_error_not_an_exception(self):
        with mock.patch.object(
                fortigate_service, "get_routes",
                side_effect=fortigate_service.FortiGateError("timeout")):
            out = route_table.collect_for(FGT_A)
        self.assertIn("timeout", out["error"])


class IosRouteParsing(unittest.TestCase):
    """`show ip route` e' l'unica forma in cui uno switch pubblica la sua RIB.

    Le lettere in prima colonna sono la classificazione che l'apparato fa gia'
    della propria tabella: leggerle e' tradurre. Sbagliarle significa mostrare
    una rotta OSPF come statica, che e' peggio del non mostrarla.
    """

    @classmethod
    def setUpClass(cls):
        cls.rows = route_table.parse_ios_routes(IOS_OUTPUT)

    def test_headers_and_group_lines_are_not_routes(self):
        # 'is variably subnetted' annuncia un blocco: contarlo gonfia ogni
        # totale di una riga per gruppo.
        nets = [r["network"] for r in self.rows]
        self.assertNotIn("10.0.0.0/8", nets)
        self.assertTrue(all(not n.startswith("Codes") for n in nets))
        self.assertEqual(len(self.rows), 7)

    def test_connected_and_local_stay_apart(self):
        # C e' la rete della SVI, L il suo /32. Fonderli fa comparire ogni
        # interfaccia due volte come 'connected'.
        by_net = {r["network"]: r for r in self.rows}
        self.assertEqual(by_net["10.1.10.0/24"]["type"], "connected")
        self.assertEqual(by_net["10.1.10.1/32"]["type"], "local")
        self.assertEqual(by_net["10.1.10.0/24"]["interface"], "Vlan10")
        self.assertEqual(by_net["10.1.10.0/24"]["gateway"], "")

    def test_the_qualifier_does_not_change_the_family(self):
        # 'O IA' e' OSPF quanto 'O'.
        by_net = {r["network"]: r for r in self.rows}
        self.assertEqual(by_net["10.2.0.0/16"]["type"], "ospf")
        self.assertEqual(by_net["10.2.0.0/16"]["distance"], 110)
        self.assertEqual(by_net["10.2.0.0/16"]["metric"], 20)
        self.assertEqual(by_net["10.2.0.0/16"]["interface"], "Vlan10")

    def test_the_default_route_keeps_its_star(self):
        by_net = {r["network"]: r for r in self.rows}
        self.assertEqual(by_net["0.0.0.0/0"]["type"], "static")
        self.assertEqual(by_net["0.0.0.0/0"]["gateway"], "192.0.2.254")

    def test_a_second_next_hop_is_a_second_row(self):
        # Una rotta con due next-hop e' ECMP: tenerne uno solo nasconde meta'
        # del percorso proprio a chi sta cercando dove passa il traffico.
        hops = sorted(r["gateway"] for r in self.rows
                      if r["network"] == "172.16.0.0/12")
        self.assertEqual(hops, ["10.1.10.4", "10.1.10.5"])
        for r in self.rows:
            if r["network"] == "172.16.0.0/12":
                self.assertEqual(r["type"], "static")

    def test_an_age_is_not_mistaken_for_an_interface(self):
        # 'via 10.1.10.3, 1d02h' non ha interfaccia: prendere l'ultimo campo
        # senza guardarlo scriverebbe '1d02h' nella colonna Interfaccia.
        by_net = {r["network"]: r for r in self.rows}
        self.assertEqual(by_net["192.168.0.0/16"]["interface"], "")

    def test_an_l2_switch_answers_with_no_routes(self):
        self.assertEqual(route_table.parse_ios_routes(
            "% Invalid input detected at '^' marker."), [])
        self.assertEqual(route_table.parse_ios_routes(""), [])
        self.assertEqual(route_table.parse_ios_routes(None), [])


class CliCollection(unittest.TestCase):
    def test_the_command_is_fixed(self):
        # Questa vista non e' una shell: l'argv non arriva da nessuna
        # richiesta.
        sent = {}

        def spy(device, command, bypass_blacklist=False):
            sent["cmd"] = command
            return {"status": "success", "output": IOS_OUTPUT}

        with mock.patch.object(route_table, "_is_agent_site", return_value=False),              mock.patch("core.core_engine.send_custom_command", side_effect=spy):
            out = route_table.collect_for(SWITCH)
        self.assertEqual(sent["cmd"], "show ip route")
        self.assertEqual(len(out["rows"]), 7)
        self.assertEqual(out["source"], "ssh")

    def test_an_agent_site_is_not_dialled_at_all(self):
        # Il centrale non ha una rotta verso gli apparati di una sede agent:
        # provarci allunga ogni refresh di un timeout per niente.
        with mock.patch.object(route_table, "_is_agent_site", return_value=True),              mock.patch("core.core_engine.send_custom_command") as ssh:
            out = route_table.collect_for(SWITCH)
        ssh.assert_not_called()
        self.assertIn("agent", out["error"])

    def test_a_switch_without_routing_says_so(self):
        # Sessione riuscita e zero rotte: dirlo evita che l'assenza si legga
        # come un parser rotto.
        with mock.patch.object(route_table, "_is_agent_site", return_value=False),              mock.patch("core.core_engine.send_custom_command",
                        return_value={"status": "success", "output": ""}):
            out = route_table.collect_for(SWITCH)
        self.assertNotIn("rows", out)
        self.assertIn("nessuna rotta", out["error"])

    def test_a_failed_session_is_an_error_row(self):
        with mock.patch.object(route_table, "_is_agent_site", return_value=False),              mock.patch("core.core_engine.send_custom_command",
                        return_value={"status": "error", "message": "auth fallita"}):
            out = route_table.collect_for(SWITCH)
        self.assertIn("auth fallita", out["error"])


class GroupCounts(unittest.TestCase):
    def test_it_counts_routes_and_not_traffic(self):
        with mock.patch.object(fortigate_service, "get_routes",
                               return_value={"source": "api", "data": ROUTES_A}):
            rows = route_table.collect_for(FGT_A)["rows"]
        self.assertEqual(route_table.group_counts(rows),
                         {"fw-edge": {"static": 1, "connected": 1, "bgp": 1}})


class RouteApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for user, role, groups in (("adm_rt", "admin", None),
                                   ("op_a_rt", "operator", ["sede-a"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def _get(self, user, qs="", devices=None, cli=None):
        def fake(device):
            return {"source": "api",
                    "data": ROUTES_A if device["IP"] == FGT_A["IP"] else ROUTES_B}
        cli = cli if cli is not None else {"status": "success", "output": IOS_OUTPUT}
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=devices or [FGT_A, FGT_B, SWITCH]), \
             mock.patch.object(route_table, "_is_agent_site", return_value=False), \
             mock.patch("core.core_engine.send_custom_command", return_value=cli), \
             mock.patch.object(fortigate_service, "get_routes", side_effect=fake):
            r = self._client(user).get("/api/routes" + qs)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_it_needs_a_session(self):
        self.assertIn(TestClient(app_server.app).get("/api/routes").status_code,
                      (401, 403))

    def test_an_admin_sees_every_site(self):
        out = self._get("adm_rt")
        self.assertEqual({r["device"] for r in out["rows"]},
                         {"fw-edge", "fw-dc", "sw-core"})
        self.assertEqual(out["devices_queried"], 3)

    def test_scope_keeps_another_site_out(self):
        # sede-a tiene il firewall e lo switch; fw-dc sta in sede-b.
        out = self._get("op_a_rt")
        self.assertEqual({r["device"] for r in out["rows"]}, {"fw-edge", "sw-core"})

    def test_the_switch_is_queried_over_the_cli(self):
        out = self._get("adm_rt")
        self.assertIn("sw-core", {r["device"] for r in out["rows"]})
        self.assertEqual(out["errors"], [])

    def test_filter_by_type(self):
        # Una rotta BGP per apparato, e vengono da due sorgenti diverse:
        # REST per il firewall, `show ip route` per lo switch.
        out = self._get("adm_rt", "?type=bgp")
        self.assertEqual({(r["device"], r["network"]) for r in out["rows"]},
                         {("fw-edge", "0.0.0.0/0"), ("sw-core", "192.168.0.0/16")})
        self.assertEqual(out["total"], 2)

    def test_search_matches_network_gateway_and_interface(self):
        # 172.16.0.0/12 sta su fw-dc (ospf) e su sw-core con DUE next-hop.
        self.assertEqual(self._get("adm_rt", "?q=172.16")["total"], 3)
        self.assertEqual(self._get("adm_rt", "?q=port5")["total"], 1)
        self.assertEqual(self._get("adm_rt", "?q=Vlan10")["total"], 3)

    def test_the_counts_follow_the_filters(self):
        # Il grafico legge questi numeri: calcolarli prima dei filtri
        # disegnerebbe barre che non corrispondono alla tabella sotto.
        out = self._get("adm_rt", "?type=ospf")
        self.assertEqual(out["counts"], {"fw-dc": {"ospf": 1}, "sw-core": {"ospf": 1}})

    def test_one_unreachable_device_does_not_empty_the_table(self):
        def fake(device):
            if device["IP"] == FGT_B["IP"]:
                raise fortigate_service.FortiGateError("host irraggiungibile")
            return {"source": "api", "data": ROUTES_A}
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[FGT_A, FGT_B]), \
             mock.patch.object(fortigate_service, "get_routes", side_effect=fake):
            r = self._client("adm_rt").get("/api/routes")
        out = r.json()
        self.assertEqual(len(out["rows"]), 3)
        self.assertEqual(len(out["errors"]), 1)
        self.assertEqual(out["errors"][0]["device_ip"], FGT_B["IP"])


class RoutesTabIsWiredEndToEnd(unittest.TestCase):
    """Il tab e il suo modulo.

    Un tab lazy registrato a meta' non da' errore visibile: la voce di menu
    c'e', il pannello si apre vuoto e i pulsanti non fanno niente. Le tre
    meta' sono LAZY_TAB_SCRIPTS, la chiamata del loader in switchTab e gli id
    che il modulo aggancia."""

    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    @classmethod
    def setUpClass(cls):
        read = lambda *parts: open(os.path.join(cls._ROOT, *parts),
                                   encoding="utf-8").read()
        cls.html = read("templates", "dashboard.html")
        cls.core = read("static", "js", "core.js")
        cls.mod = read("static", "js", "routes-view.js")

    def test_the_nav_entry_and_the_panel_both_exist(self):
        self.assertIn('data-tab="tab-routes"', self.html)
        self.assertIn('id="tab-routes"', self.html)

    def test_the_module_is_loaded_and_called_for_that_tab(self):
        self.assertIn("'tab-routes': ['/static/js/routes-view.js']", self.core)
        self.assertIn("tabId === 'tab-routes'", self.core)
        self.assertIn("window.loadRoutesTab = loadRoutesTab", self.mod)

    def test_every_bound_id_exists_in_the_template(self):
        for element_id in ("rtDeviceFilter", "rtTypeFilter", "rtSearch",
                           "btnRtRefresh", "rtTableBody", "rtChartCanvas",
                           "rtErrors", "rtCount"):
            self.assertIn(f'id="{element_id}"', self.html,
                          f"{element_id} e' agganciato da routes-view.js ma "
                          "non esiste nel template")

    def test_the_chart_counts_routes_and_says_so(self):
        # Il mockup di partenza disegnava pkt/s per rotta. Nessun apparato lo
        # espone: la barra conta le rotte, e la nota sotto il grafico lo dice
        # invece di lasciare che il numero venga letto come traffico.
        self.assertIn("rtChartNote", self.html)
        self.assertNotIn("pkt/s", self.mod)

    def test_a_partial_answer_is_shown_and_not_swallowed(self):
        self.assertIn("rtPartial", self.mod)
        self.assertIn('id="rtErrors"', self.html)


if __name__ == "__main__":
    unittest.main()
