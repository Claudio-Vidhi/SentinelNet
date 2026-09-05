# -*- coding: utf-8 -*-
"""Analisi di percorso: dove finisce un indirizzo, e perche' quella rotta.

Il calcolo non manda pacchetti, quindi non c'e' una rete che possa smentirlo a
tempo di esecuzione: l'unica difesa e' che le regole di scelta siano fissate
qui. Prefisso prima della distanza, next-hop attribuito solo a chi possiede
quell'indirizzo esatto, ed esiti distinti fra "consegna", "fuori inventario",
"nessuna rotta", "anello" e "non interrogato" — sono cinque risposte a domande
diverse, e appiattirle e' il modo piu' rapido di far cercare un guasto dove non
c'e'.

L'ultima parte copre la prova sul campo, l'unica che i pacchetti li manda
davvero: deve restare esplicita, riservata agli operatori e mai innescata
dall'apertura di una vista.
"""
import unittest
from unittest import mock

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import user_manager  # noqa: E402
from services import fortigate_service, path_trace, route_table  # noqa: E402

PASS = "PasswordSicura1!"

FW_EDGE = {"IP": "192.0.2.1", "Hostname": "fw-edge", "Vendor": "fortinet",
           "Group": "sede-a", "Site": "central"}
FW_DC = {"IP": "192.0.2.2", "Hostname": "fw-dc", "Vendor": "fortinet",
         "Group": "sede-a", "Site": "central"}
SWITCH = {"IP": "192.0.2.3", "Hostname": "sw-core", "Vendor": "cisco",
          "Group": "sede-a", "Site": "central"}


def _row(device, network, rtype, gateway="", interface="", distance=None, metric=0):
    return {"device": device["Hostname"], "device_ip": device["IP"],
            "network": network, "gateway": gateway, "interface": interface,
            "type": rtype, "distance": distance, "metric": metric,
            "from_backup": False}


# fw-edge: default verso l'ISP, il /16 del datacenter via sw-core.
ROWS_EDGE = [
    _row(FW_EDGE, "0.0.0.0/0", "static", "203.0.113.1", "port1", 1),
    _row(FW_EDGE, "10.10.0.0/16", "connected", "", "port2", 0),
    _row(FW_EDGE, "10.30.0.0/16", "ospf", "10.10.0.2", "port2", 110, 30),
]
# sw-core: lo stesso /16, via fw-dc.
ROWS_SWITCH = [
    _row(SWITCH, "10.10.0.2/32", "local", "", "Vlan10", 0),
    _row(SWITCH, "10.10.0.0/16", "connected", "", "Vlan10", 0),
    _row(SWITCH, "10.20.0.1/32", "local", "", "Vlan20", 0),
    _row(SWITCH, "10.20.0.0/16", "connected", "", "Vlan20", 0),
    _row(SWITCH, "0.0.0.0/0", "static", "10.10.0.1", "Vlan10", 1),
    _row(SWITCH, "10.30.0.0/16", "ospf", "10.20.0.2", "Vlan20", 110, 20),
]
# fw-dc: il /16 e' una sua rete connessa.
ROWS_DC = [
    _row(FW_DC, "10.30.0.0/16", "connected", "", "port4", 0),
    _row(FW_DC, "0.0.0.0/0", "static", "10.20.0.1", "port3", 1),
]

ADDRESSES = {
    FW_EDGE["IP"]: [{"iface": "port1", "ip": "203.0.113.2", "network": "203.0.113.0/30"},
                    {"iface": "port2", "ip": "10.10.0.1", "network": "10.10.0.0/16"}],
    SWITCH["IP"]: [{"iface": "Vlan10", "ip": "10.10.0.2", "network": "10.10.0.2/32"},
                   {"iface": "Vlan20", "ip": "10.20.0.1", "network": "10.20.0.1/32"}],
    FW_DC["IP"]: [{"iface": "port3", "ip": "10.20.0.2", "network": "10.20.0.0/16"},
                  {"iface": "port4", "ip": "10.30.0.1", "network": "10.30.0.0/16"}],
}
ROWS = {FW_EDGE["IP"]: ROWS_EDGE, SWITCH["IP"]: ROWS_SWITCH, FW_DC["IP"]: ROWS_DC}
DEVICES = {d["IP"]: d for d in (FW_EDGE, SWITCH, FW_DC)}


class RouteChoice(unittest.TestCase):
    """Quale rotta vince, e per quale criterio."""

    def test_the_longest_prefix_wins_before_the_distance(self):
        # E' il punto in cui si sbaglia a ragionare piu' spesso: una BGP con
        # distanza 20 non batte una statica /24 solo perche' 20 > 1.
        rows = [_row(FW_DC, "172.16.0.0/12", "bgp", "10.20.0.1", "port3", 20),
                _row(FW_DC, "172.16.5.0/24", "static", "10.30.0.9", "port4", 1)]
        cand = path_trace.candidates(rows, "172.16.5.20")
        self.assertEqual(cand[0]["network"], "172.16.5.0/24")
        self.assertEqual(path_trace.decided_by(cand), "prefisso")

    def test_with_the_same_prefix_the_distance_decides(self):
        rows = [_row(SWITCH, "10.30.0.0/16", "ospf", "10.20.0.2", "Vlan20", 110),
                _row(SWITCH, "10.30.0.0/16", "static", "10.10.0.9", "Vlan10", 1)]
        cand = path_trace.candidates(rows, "10.30.0.7")
        self.assertEqual(cand[0]["type"], "static")
        self.assertEqual(path_trace.decided_by(cand), "distanza")

    def test_a_missing_distance_falls_back_to_the_standard_value(self):
        # Un apparato che non dichiara la AD non deve far vincere l'appresa
        # sulla connessa: i valori standard servono a questo.
        rows = [_row(FW_DC, "10.30.0.0/16", "ospf", "10.20.0.2", "port3"),
                _row(FW_DC, "10.30.0.0/16", "connected", "", "port4")]
        cand = path_trace.candidates(rows, "10.30.0.7")
        self.assertEqual(cand[0]["type"], "connected")

    def test_a_local_route_is_not_a_forwarding_route(self):
        # Il /32 dell'interfaccia e' un indirizzo, non una strada: lasciarlo
        # fra le candidate farebbe "consegnare" il pacchetto sul primo
        # apparato che lo attraversa.
        cand = path_trace.candidates(ROWS_SWITCH, "10.10.0.2")
        self.assertNotIn("local", {r["type"] for r in cand})

    def test_an_invalid_address_yields_no_candidates(self):
        self.assertEqual(path_trace.candidates(ROWS_EDGE, "non-un-ip"), [])


class InterfaceAddresses(unittest.TestCase):
    """Il dato che mancava: chi possiede un certo next-hop."""

    def test_a_switch_gives_its_addresses_through_its_local_routes(self):
        # Nessuna raccolta nuova: `show ip route` le pubblica gia'.
        addrs = path_trace.addresses_for(SWITCH, ROWS_SWITCH)
        self.assertEqual({a["ip"] for a in addrs}, {"10.10.0.2", "10.20.0.1"})
        self.assertEqual({a["iface"] for a in addrs}, {"Vlan10", "Vlan20"})

    def test_a_fortigate_is_asked_for_its_interfaces(self):
        answer = {"source": "api", "data": {
            "port2": {"name": "port2", "ip": "10.10.0.1", "mask": 16},
            "port1": {"name": "port1", "ip": "203.0.113.2", "mask": 30},
        }}
        with mock.patch.object(fortigate_service, "get_interfaces", return_value=answer):
            addrs = path_trace.addresses_for(FW_EDGE, ROWS_EDGE)
        by_ip = {a["ip"]: a for a in addrs}
        self.assertEqual(by_ip["10.10.0.1"]["network"], "10.10.0.0/16")
        self.assertEqual(by_ip["203.0.113.2"]["network"], "203.0.113.0/30")

    def test_a_firewall_that_does_not_answer_leaves_no_addresses(self):
        # Meglio un percorso che si ferma di un salto attribuito all'apparato
        # sbagliato.
        with mock.patch.object(fortigate_service, "get_interfaces",
                               side_effect=fortigate_service.FortiGateError("timeout")):
            self.assertEqual(path_trace.addresses_for(FW_EDGE, []), [])

    def test_the_other_field_name_for_the_address_is_read_too(self):
        # Alcune build di FortiOS chiamano il campo ipv4_address: senza la
        # doppia lettura l'apparato torna zero indirizzi in silenzio e ogni suo
        # next-hop diventa "fuori inventario".
        answer = {"source": "api", "data": {
            "port2": {"name": "port2", "ipv4_address": "10.10.0.1", "mask": 16}}}
        with mock.patch.object(fortigate_service, "get_interfaces", return_value=answer):
            addrs = path_trace.addresses_for(FW_EDGE, [])
        self.assertEqual([a["ip"] for a in addrs], ["10.10.0.1"])

    def test_a_cli_text_answer_is_not_guessed_at(self):
        with mock.patch.object(fortigate_service, "get_interfaces",
                               return_value={"source": "ssh", "data": "== [ port1 ]"}):
            self.assertEqual(path_trace.addresses_for(FW_EDGE, []), [])

    def test_the_owner_is_the_device_with_that_exact_address(self):
        self.assertEqual(path_trace.owner_of("10.20.0.2", ADDRESSES), FW_DC["IP"])
        self.assertIsNone(path_trace.owner_of("10.20.0.99", ADDRESSES))

    def test_the_device_we_are_leaving_is_never_the_owner(self):
        # Il next-hop sta su una rete connessa anche a chi lo usa: senza
        # esclusione ogni salto tornerebbe sull'apparato di partenza.
        self.assertIsNone(
            path_trace.owner_of("10.10.0.1", ADDRESSES, exclude=FW_EDGE["IP"]))


class Trace(unittest.TestCase):
    """Il percorso, e i suoi esiti."""

    def test_three_hops_and_a_delivery(self):
        out = path_trace.trace("10.30.0.7", FW_EDGE["IP"], ROWS, ADDRESSES, DEVICES)
        self.assertEqual(out["outcome"], "consegna")
        self.assertEqual([h["device"] for h in out["hops"]],
                         ["fw-edge", "sw-core", "fw-dc"])
        self.assertEqual(out["hops"][0]["decided_by"], "prefisso")
        self.assertEqual(out["hops"][-1]["best"]["type"], "connected")

    def test_a_next_hop_nobody_owns_leaves_the_perimeter(self):
        out = path_trace.trace("8.8.8.8", FW_EDGE["IP"], ROWS, ADDRESSES, DEVICES)
        self.assertEqual(out["outcome"], "fuori inventario")
        self.assertEqual(out["exit_hop"], "203.0.113.1")
        # Sta su una rete connessa di fw-edge: e' un gateway sulla sua LAN, non
        # un salto verso il nulla, e la frase a schermo cambia.
        self.assertTrue(out["exit_local"])

    def test_no_route_at_all_is_its_own_outcome(self):
        rows = {SWITCH["IP"]: [_row(SWITCH, "10.10.0.0/16", "connected", "", "Vlan10", 0)]}
        out = path_trace.trace("172.16.0.1", SWITCH["IP"], rows, ADDRESSES, DEVICES)
        self.assertEqual(out["outcome"], "nessuna rotta")
        self.assertEqual(out["hops"][-1]["outcome"], "nessuna rotta")

    def test_two_statics_pointing_at_each_other_are_a_loop(self):
        rows = {
            SWITCH["IP"]: [_row(SWITCH, "10.50.0.0/16", "static", "10.20.0.2", "Vlan20", 1)],
            FW_DC["IP"]: [_row(FW_DC, "10.50.0.0/16", "static", "10.20.0.1", "port3", 1)],
        }
        out = path_trace.trace("10.50.0.3", SWITCH["IP"], rows, ADDRESSES, DEVICES)
        self.assertEqual(out["outcome"], "anello")

    def test_two_equivalent_routes_are_a_fork_not_a_choice(self):
        # Prefisso, distanza e metrica identici: l'apparato le usa entrambe, e
        # da li' in poi il percorso non e' uno solo.
        rows = {SWITCH["IP"]: [
            _row(SWITCH, "10.40.0.0/16", "static", "10.20.0.2", "Vlan20", 1),
            _row(SWITCH, "10.40.0.0/16", "static", "10.10.0.1", "Vlan10", 1),
        ]}
        out = path_trace.trace("10.40.0.9", SWITCH["IP"], rows, ADDRESSES, DEVICES)
        self.assertEqual(out["outcome"], "biforcazione")
        self.assertEqual({b["next_device_ip"] for b in out["branches"]},
                         {FW_DC["IP"], FW_EDGE["IP"]})

    def test_a_device_outside_the_selection_stops_the_trace_and_says_so(self):
        # Non e' "il percorso finisce qui": e' "non ho la sua tabella". La
        # differenza dice all'utente di allargare la selezione.
        rows = {FW_EDGE["IP"]: ROWS_EDGE}
        out = path_trace.trace("10.30.0.7", FW_EDGE["IP"], rows, ADDRESSES, DEVICES)
        self.assertEqual(out["outcome"], "non interrogato")
        self.assertEqual(out["device_ip"], SWITCH["IP"])

    def test_running_out_of_hops_is_not_called_a_loop(self):
        # Sedici salti senza mai rivedere un apparato non sono un anello:
        # chiamarli cosi' manda a cercare un giro che non c'e'.
        chain, rows, addrs, devices = {}, {}, {}, {}
        for i in range(path_trace.MAX_HOPS + 2):
            ip = f"192.0.2.{100 + i}"
            nxt = f"10.99.{i}.1"
            chain[ip] = nxt
            devices[ip] = {"IP": ip, "Hostname": f"r{i}", "Vendor": "cisco"}
            rows[ip] = [{"network": "10.30.0.0/16", "gateway": nxt, "interface": "Gi0/0",
                         "type": "static", "distance": 1, "metric": 0}]
            addrs[ip] = [{"iface": "Gi0/0", "ip": f"10.99.{i - 1}.1" if i else "10.99.99.1",
                          "network": f"10.99.{i - 1}.0/24" if i else "10.99.99.0/24"}]
        out = path_trace.trace("10.30.0.7", "192.0.2.100", rows, addrs, devices)
        self.assertEqual(out["outcome"], "limite salti")

    def test_a_numeric_string_is_a_number(self):
        # Alcune risposte REST mandano distanza e metrica come stringhe:
        # scartarle farebbe sembrare identiche due rotte che non lo sono, e
        # nascerebbe un ECMP inventato.
        rows = [{"network": "10.30.0.0/16", "gateway": "10.20.0.2", "interface": "Vlan20",
                 "type": "ospf", "distance": "110", "metric": "200"},
                {"network": "10.30.0.0/16", "gateway": "10.10.0.9", "interface": "Vlan10",
                 "type": "ospf", "distance": "110", "metric": "20"}]
        cand = path_trace.candidates(rows, "10.30.0.7")
        self.assertEqual(cand[0]["gateway"], "10.10.0.9")
        self.assertEqual(path_trace.decided_by(cand), "metrica")

    def test_a_hop_read_from_the_backup_is_marked(self):
        stale = [dict(r, from_backup=True) for r in ROWS_DC]
        rows = dict(ROWS, **{FW_DC["IP"]: stale})
        out = path_trace.trace("10.30.0.7", FW_EDGE["IP"], rows, ADDRESSES, DEVICES)
        self.assertTrue(out["hops"][-1]["from_backup"])
        self.assertFalse(out["hops"][0]["from_backup"])


class TenantSeparation(unittest.TestCase):
    """Il backup si cerca dentro il tenant, non per solo IP.

    Due clienti possono avere lo stesso indirizzo — e' la premessa su cui e'
    scritto assert_device_allowed — e i backup stanno in cartelle separate
    apposta. Cercare per suffisso IP in tutto l'albero consegna a chi chiede la
    copia piu' recente, che puo' essere di un altro cliente."""

    def test_the_backup_lookup_carries_the_tenant(self):
        with mock.patch("ai.config_analyzer.analyze_device",
                        return_value=None) as analyze:
            route_table.routes_from_backup(SWITCH)
        analyze.assert_called_once_with(SWITCH["IP"], SWITCH["Group"])

    def test_the_walk_stays_inside_that_tenant(self):
        import os
        import tempfile
        from ai import config_analyzer
        from core import core_engine
        root = tempfile.mkdtemp(prefix="sentinelnet_tenant_")
        mine = os.path.join(root, "sede-a", "cisco")
        theirs = os.path.join(root, "sede-b", "cisco")
        os.makedirs(mine)
        os.makedirs(theirs)
        ours = os.path.join(mine, f"sw-core-{SWITCH['IP']}.txt")
        with open(ours, "w", encoding="utf-8") as fh:
            fh.write("hostname sw-core")
        # Quello dell'altro cliente e' il piu' fresco: senza scoping vincerebbe.
        other = os.path.join(theirs, f"altro-{SWITCH['IP']}.txt")
        with open(other, "w", encoding="utf-8") as fh:
            fh.write("hostname non-mio")
        os.utime(ours, (1, 1))
        with mock.patch.object(core_engine, "BACKUP_FOLDER", root):
            scoped, _ = config_analyzer._find_freshest_backup(SWITCH["IP"], "sede-a")
            unscoped, _ = config_analyzer._find_freshest_backup(SWITCH["IP"])
        self.assertEqual(scoped, ours)
        self.assertEqual(unscoped, other)   # il comportamento che il tenant evita


class Probe(unittest.TestCase):
    """La prova sul campo: l'unica parte che manda pacchetti."""

    OUTPUT = (
        "traceroute to 10.30.0.7, 8 hops max\n"
        "  1  10.10.0.2  4 msec 3 msec 2 msec\n"
        "  2  * * *\n"
        "  3  10.20.0.2  8 msec 7 msec 9 msec\n"
    )

    def test_a_hop_that_does_not_answer_stays_in_the_list(self):
        # Un salto muto e' un'informazione: cancellarlo farebbe sembrare il
        # percorso piu' corto di quello che e'.
        hops = path_trace.parse_traceroute(self.OUTPUT)
        self.assertEqual([h["ip"] for h in hops], ["10.10.0.2", "", "10.20.0.2"])

    def test_the_command_follows_the_vendor(self):
        self.assertEqual(path_trace.probe_command(FW_EDGE, "10.30.0.7"),
                         "execute traceroute 10.30.0.7")
        self.assertTrue(path_trace.probe_command(SWITCH, "10.30.0.7")
                        .startswith("traceroute 10.30.0.7"))

    def test_a_failed_session_is_an_error_not_an_exception(self):
        with mock.patch("core.core_engine.send_custom_command",
                        return_value={"status": "error", "message": "SSH fallito"}):
            out = path_trace.probe(SWITCH, "10.30.0.7")
        self.assertIn("SSH fallito", out["error"])
        self.assertNotIn("hops", out)

    def test_the_comparison_names_what_the_calculation_expected(self):
        calc = path_trace.trace("10.30.0.7", FW_EDGE["IP"], ROWS, ADDRESSES, DEVICES)
        seen = path_trace.compare(calc, path_trace.parse_traceroute(self.OUTPUT))
        self.assertEqual(seen["expected"], ["10.10.0.2", "10.20.0.2"])
        self.assertEqual(seen["missing"], [])
        partial = path_trace.compare(calc, [{"n": 1, "ip": "10.10.0.2"}])
        self.assertEqual(partial["missing"], ["10.20.0.2"])


class TraceApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            user_manager.create_user("adm_pt", PASS, role="admin", groups=None)
        except Exception:
            pass

    def _client(self, user="adm_pt"):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def _get(self, qs, user="adm_pt"):
        def collect(dev):
            return {"device_ip": dev["IP"], "rows": ROWS[dev["IP"]]}
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[FW_EDGE, FW_DC, SWITCH]), \
             mock.patch.object(route_table, "collect_for", side_effect=collect), \
             mock.patch.object(path_trace, "addresses_for",
                               side_effect=lambda dev, rows: ADDRESSES[dev["IP"]]):
            return self._client(user).get("/api/routes/trace" + qs)

    def test_it_needs_a_session(self):
        self.assertIn(TestClient(app_server.app).get("/api/routes/trace").status_code,
                      (401, 403))

    def test_the_path_across_the_selected_devices(self):
        picked = ",".join(d["IP"] for d in (FW_EDGE, FW_DC, SWITCH))
        out = self._get(f"?device={picked}&src={FW_EDGE['IP']}&dst=10.30.0.7").json()
        self.assertEqual(out["outcome"], "consegna")
        self.assertEqual([h["device"] for h in out["hops"]],
                         ["fw-edge", "sw-core", "fw-dc"])
        self.assertEqual(out["devices_queried"], 3)

    def test_an_address_that_is_not_an_address_is_refused(self):
        r = self._get(f"?device={FW_EDGE['IP']}&src={FW_EDGE['IP']}&dst=ciao")
        self.assertEqual(r.status_code, 400)

    def test_an_ipv6_destination_is_refused(self):
        # Le tabelle e i parser sono IPv4: accettarlo darebbe un "nessuna rotta"
        # incomprensibile invece di un errore.
        r = self._get(f"?device={FW_EDGE['IP']}&src={FW_EDGE['IP']}&dst=2001:db8::1")
        self.assertEqual(r.status_code, 400)

    def test_the_same_ip_in_two_tenants_stops_the_trace(self):
        # Le tabelle qui si indicizzano per indirizzo: una selezione ambigua
        # darebbe un percorso che mescola due reti senza dirlo.
        twin = dict(SWITCH, Group="sede-b", Hostname="sw-altro")
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[SWITCH, twin]):
            r = self._client().get(
                f"/api/routes/trace?device={SWITCH['IP']}&src={SWITCH['IP']}&dst=10.30.0.7")
        self.assertEqual(r.status_code, 409)
        self.assertIn("sede-a", r.json()["detail"])

    def test_a_start_outside_the_selection_is_a_404(self):
        # La vista chiede di scegliere gli apparati: partire da uno non scelto
        # non e' un percorso vuoto, e' una richiesta sbagliata.
        r = self._get(f"?device={FW_DC['IP']}&src={FW_EDGE['IP']}&dst=10.30.0.7")
        self.assertEqual(r.status_code, 404)


class ProbeApi(unittest.TestCase):
    # Le POST autenticate via cookie vogliono l'header anti-CSRF (routers/deps).
    CSRF = {"X-Requested-With": "SentinelNet"}

    @classmethod
    def setUpClass(cls):
        for user, role in (("adm_pp", "admin"), ("view_pp", "viewer")):
            try:
                user_manager.create_user(user, PASS, role=role, groups=None)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_a_viewer_cannot_send_packets(self):
        # Il traceroute e' un'azione sulla rete, non una lettura.
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[SWITCH]):
            r = self._client("view_pp").post(
                "/api/routes/trace/probe",
                json={"device_ip": SWITCH["IP"], "dst": "10.30.0.7"},
                headers=self.CSRF)
        self.assertEqual(r.status_code, 403)

    def test_an_operator_gets_the_hops(self):
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[SWITCH]), \
             mock.patch.object(path_trace, "probe",
                               return_value={"command": "traceroute 10.30.0.7",
                                             "output": "  1  10.10.0.2  4 msec",
                                             "hops": [{"n": 1, "ip": "10.10.0.2"}]}):
            r = self._client("adm_pp").post(
                "/api/routes/trace/probe",
                json={"device_ip": SWITCH["IP"], "dst": "10.30.0.7"},
                headers=self.CSRF)
        self.assertEqual(r.status_code, 200, r.text)
        out = r.json()
        self.assertEqual(out["hops"][0]["ip"], "10.10.0.2")
        self.assertEqual(out["device"], "sw-core")

    def test_the_destination_is_validated_before_it_reaches_a_device(self):
        # Questa stringa finisce in un comando su un apparato di rete: il
        # controllo sta qui, non nel browser.
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[SWITCH]), \
             mock.patch.object(path_trace, "probe") as probe:
            r = self._client("adm_pp").post(
                "/api/routes/trace/probe",
                json={"device_ip": SWITCH["IP"], "dst": "10.30.0.7; reboot"},
                headers=self.CSRF)
        self.assertEqual(r.status_code, 400)
        probe.assert_not_called()

    def test_a_device_outside_the_inventory_is_a_404(self):
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[]):
            r = self._client("adm_pp").post(
                "/api/routes/trace/probe",
                json={"device_ip": "192.0.2.99", "dst": "10.30.0.7"},
                headers=self.CSRF)
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
