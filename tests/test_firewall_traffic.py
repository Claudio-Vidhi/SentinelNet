# -*- coding: utf-8 -*-
"""Traffico per policy firewall, aggregato sugli apparati in scope.

A differenza della vista "Per IP", questi numeri NON vengono da
flow_aggregates: sono i contatori che il FortiGate tiene per se', cumulativi
dall'ultimo azzeramento. La finestra del tab non li filtra, e la vista lo
dichiara — qui si sorveglia che quella nota resti a schermo, insieme al confine
per sede e al fatto che un firewall a meta' non svuoti la tabella degli altri.
"""
import os
import unittest
from unittest import mock

from fastapi.testclient import TestClient  # noqa: E402

# Nessun SENTINELNET_DATA_DIR nostro: conftest.py ha gia' scelto quello della
# suite. Vedi la stessa nota in test_route_table.py.
import app_server  # noqa: E402
from security import user_manager  # noqa: E402
from services import firewall_traffic, fortigate_service  # noqa: E402

PASS = "PasswordSicura1!"

FGT_A = {"IP": "192.0.2.1", "Hostname": "fw-edge", "Vendor": "fortinet",
         "Group": "sede-a", "Site": "central"}
FGT_B = {"IP": "192.0.2.2", "Hostname": "fw-dc", "Vendor": "fortinet",
         "Group": "sede-b", "Site": "central"}
SWITCH = {"IP": "192.0.2.3", "Hostname": "sw-core", "Vendor": "cisco",
          "Group": "sede-a", "Site": "central"}

POLICIES_A = [
    {"policyid": 10, "name": "LAN-to-WAN", "status": "enable", "action": "accept",
     "srcaddr": [{"name": "LAN_Uffici"}], "dstaddr": [{"name": "all"}],
     "srcaddr_ips": ["10.10.0.0/16"], "dstaddr_ips": ["0.0.0.0/0"],
     "service": [{"name": "HTTPS"}, {"name": "DNS"}],
     "bytes": 850_000_000, "hit_count": 12400, "active_sessions": 310,
     "last_used": 1756000000, "never_hit": False},
    {"policyid": 20, "name": "Blocco-Guest", "status": "enable", "action": "deny",
     "srcaddr": [{"name": "Guest"}], "dstaddr": [{"name": "Interno"}],
     "srcaddr_ips": [], "dstaddr_ips": [],
     "service": [{"name": "ALL"}],
     "bytes": 0, "hit_count": 0, "active_sessions": 0,
     "last_used": None, "never_hit": True},
    {"policyid": 30, "name": "Vecchia-Regola", "status": "disable", "action": "accept",
     "srcaddr": [{"name": "all"}], "dstaddr": [{"name": "all"}],
     "srcaddr_ips": [], "dstaddr_ips": [], "service": [{"name": "ALL"}],
     "bytes": 0, "hit_count": 0, "active_sessions": 0,
     "last_used": None, "never_hit": False},
]
POLICIES_B = [
    {"policyid": 5, "name": "DC-Uplink", "status": "enable", "action": "accept",
     "srcaddr": [{"name": "DC"}], "dstaddr": [{"name": "all"}],
     "srcaddr_ips": ["10.20.0.0/16"], "dstaddr_ips": [],
     "service": [{"name": "ANY"}],
     "bytes": 400_000_000, "hit_count": 3100, "active_sessions": 90,
     "last_used": 1756000100, "never_hit": False},
]


class DeviceSelection(unittest.TestCase):
    def test_only_devices_that_keep_per_policy_counters(self):
        # Uno switch non ha policy, e un router con ACL non espone byte per
        # regola: includerlo darebbe righe vuote presentate come "nessun
        # traffico".
        got = firewall_traffic.policy_devices([FGT_A, SWITCH, FGT_B])
        self.assertEqual([d["IP"] for d in got], ["192.0.2.1", "192.0.2.2"])


class SingleDeviceCollection(unittest.TestCase):
    def test_object_names_become_readable_columns(self):
        with mock.patch.object(fortigate_service, "get_policies_with_stats",
                               return_value={"source": "api", "data": POLICIES_A}):
            out = firewall_traffic.collect_for(FGT_A)
        first = out["rows"][0]
        self.assertEqual(first["device"], "fw-edge")
        self.assertEqual(first["srcaddr"], "LAN_Uffici")
        self.assertEqual(first["service"], "HTTPS, DNS")
        self.assertEqual(first["srcaddr_ips"], "10.10.0.0/16")
        self.assertEqual(first["action"], "accept")
        self.assertEqual(first["bytes"], 850_000_000)

    def test_never_hit_is_not_the_same_as_no_counter(self):
        # Una policy senza contatore non e' una regola morta: marcarla
        # produrrebbe un falso positivo davanti a chi ripulisce il firewall.
        with mock.patch.object(fortigate_service, "get_policies_with_stats",
                               return_value={"source": "api", "data": POLICIES_A}):
            rows = firewall_traffic.collect_for(FGT_A)["rows"]
        by_id = {r["policyid"]: r for r in rows}
        self.assertTrue(by_id[20]["never_hit"])
        self.assertFalse(by_id[30]["never_hit"])

    def test_missing_counters_are_named_not_hidden(self):
        # Config arrivata, contatori no: le colonne a zero si leggerebbero
        # come "questa policy non passa traffico".
        with mock.patch.object(
                fortigate_service, "get_policies_with_stats",
                return_value={"source": "api", "data": POLICIES_A,
                              "stats_error": "monitor non raggiungibile"}):
            out = firewall_traffic.collect_for(FGT_A)
        self.assertEqual(len(out["rows"]), 3)
        self.assertIn("monitor", out["stats_error"])

    def test_an_unreachable_firewall_is_an_error_not_an_exception(self):
        with mock.patch.object(
                fortigate_service, "get_policies_with_stats",
                side_effect=fortigate_service.FortiGateError("timeout")):
            out = firewall_traffic.collect_for(FGT_A)
        self.assertIn("timeout", out["error"])
        self.assertNotIn("rows", out)


class PolicyTrafficApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for user, role, groups in (("adm_ft", "admin", None),
                                   ("op_a_ft", "operator", ["sede-a"])):
            try:
                user_manager.create_user(user, PASS, role=role, groups=groups)
            except Exception:
                pass

    def _client(self, user):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": user, "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def _get(self, user, qs="", answer=None):
        def fake(device):
            if answer is not None:
                return answer
            return {"source": "api",
                    "data": POLICIES_A if device["IP"] == FGT_A["IP"] else POLICIES_B}
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[FGT_A, FGT_B, SWITCH]), \
             mock.patch.object(fortigate_service, "get_policies_with_stats",
                               side_effect=fake):
            r = self._client(user).get("/api/firewall-traffic/policies" + qs)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_it_needs_a_session(self):
        self.assertIn(
            TestClient(app_server.app).get(
                "/api/firewall-traffic/policies").status_code, (401, 403))

    def test_an_admin_sees_every_firewall_and_no_switch(self):
        out = self._get("adm_ft")
        self.assertEqual({r["device"] for r in out["rows"]}, {"fw-edge", "fw-dc"})
        self.assertEqual(out["devices_queried"], 2)

    def test_scope_keeps_another_site_out(self):
        out = self._get("op_a_ft")
        self.assertEqual({r["device"] for r in out["rows"]}, {"fw-edge"})

    def test_the_heaviest_policy_comes_first(self):
        # E' l'ordine in cui si guarda una tabella di traffico: mette sotto gli
        # occhi la regola che sposta i dati.
        out = self._get("adm_ft")
        self.assertEqual([r["bytes"] for r in out["rows"]],
                         sorted((r["bytes"] for r in out["rows"]), reverse=True))
        self.assertEqual(out["rows"][0]["policyid"], 10)

    def test_totals_are_computed_after_the_filters(self):
        # Il riepilogo accanto ai filtri legge questi numeri: calcolarli prima
        # mostrerebbe un totale che non corrisponde alle righe sotto.
        allp = self._get("adm_ft")
        self.assertEqual(allp["total_bytes"], 1_250_000_000)
        self.assertEqual(allp["total_sessions"], 400)
        denied = self._get("adm_ft", "?action=deny")
        self.assertEqual([r["policyid"] for r in denied["rows"]], [20])
        self.assertEqual(denied["total_bytes"], 0)

    def test_search_reaches_names_addresses_and_services(self):
        self.assertEqual(self._get("adm_ft", "?q=LAN-to-WAN")["total"], 1)
        self.assertEqual(self._get("adm_ft", "?q=10.20.0.0")["total"], 1)
        self.assertEqual(self._get("adm_ft", "?q=HTTPS")["total"], 1)
        self.assertEqual(self._get("adm_ft", "?q=Guest")["total"], 1)

    def test_filter_by_device(self):
        out = self._get("adm_ft", "?device=fw-dc")
        self.assertEqual({r["device"] for r in out["rows"]}, {"fw-dc"})
        self.assertEqual(out["devices_queried"], 1)

    def test_missing_counters_surface_as_a_partial_answer(self):
        out = self._get("adm_ft", answer={
            "source": "api", "data": POLICIES_A,
            "stats_error": "monitor non raggiungibile"})
        self.assertTrue(out["rows"])
        self.assertTrue(any("contatori" in e["error"] for e in out["errors"]))

    def test_one_unreachable_firewall_does_not_empty_the_table(self):
        def fake(device):
            if device["IP"] == FGT_B["IP"]:
                raise fortigate_service.FortiGateError("host irraggiungibile")
            return {"source": "api", "data": POLICIES_A}
        with mock.patch("services.inventory_manager.get_all_devices",
                        return_value=[FGT_A, FGT_B]), \
             mock.patch.object(fortigate_service, "get_policies_with_stats",
                               side_effect=fake):
            out = self._client("adm_ft").get(
                "/api/firewall-traffic/policies").json()
        self.assertEqual(len(out["rows"]), 3)
        self.assertEqual(len(out["errors"]), 1)
        self.assertEqual(out["errors"][0]["device_ip"], FGT_B["IP"])


class TheCumulativeCaveatIsOnScreen(unittest.TestCase):
    """Il numero piu' pericoloso di questa vista.

    850 MB letti sotto un selettore "ultime 6 ore" si leggono come 850 MB in
    sei ore. Sono invece cumulativi dall'ultimo azzeramento del firewall, e
    l'unica difesa e' che la nota resti a schermo.
    """

    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_the_note_is_in_the_pane_and_in_both_languages(self):
        html = open(os.path.join(self._ROOT, "templates", "dashboard.html"),
                    encoding="utf-8").read()
        i18n = open(os.path.join(self._ROOT, "static", "js", "i18n.js"),
                    encoding="utf-8").read()
        self.assertIn("trafPolCumulativeNote", html)
        self.assertEqual(2, i18n.count("trafPolCumulativeNote:"))

    def test_the_pane_and_its_controls_exist(self):
        html = open(os.path.join(self._ROOT, "templates", "dashboard.html"),
                    encoding="utf-8").read()
        js = open(os.path.join(self._ROOT, "static", "js", "observability.js"),
                  encoding="utf-8").read()
        self.assertIn('id="trafPane-policies"', html)
        self.assertIn('data-traf-view="policies"', html)
        self.assertIn("policies:  () => loadTrafPolicies()", js)
        for element_id in ("trafPolDevice", "trafPolAction", "trafPolSearch",
                           "trafPolBody", "trafPolTotals", "trafPolErrors"):
            self.assertIn(f'id="{element_id}"', html,
                          f"{element_id} e' agganciato da observability.js ma "
                          "non esiste nel template")


if __name__ == "__main__":
    unittest.main()
