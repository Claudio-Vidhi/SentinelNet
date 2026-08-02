# -*- coding: utf-8 -*-
"""Test unitari di fortigate_service (REST primario + fallback SSH, mockati)."""
import json
import os
import tempfile
import unittest
from unittest import mock

from services import fortigate_service as fgs

DEVICE = {"IP": "192.0.2.1", "Vendor": "fortinet", "Profile": "custom",
          "Username": "admin", "Password": "", "Enable Secret": ""}


def _resp(status=200, payload=None, text=""):
    r = mock.Mock()
    r.status_code = status
    r.text = text or json.dumps(payload or {})
    r.json = mock.Mock(return_value=payload if payload is not None else {})
    return r


class TokenStoreTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = fgs.TOKENS_FILE
        fgs.TOKENS_FILE = os.path.join(self._tmp.name, "fortigate_tokens.json")

    def tearDown(self):
        fgs.TOKENS_FILE = self._orig
        self._tmp.cleanup()

    def test_set_get_remove_token(self):
        fgs.set_api_token("192.0.2.1", "tok123", port=8443, verify_tls=True)
        token, port, verify = fgs.get_api_config("192.0.2.1")
        self.assertEqual(token, "tok123")
        self.assertEqual(port, 8443)
        self.assertTrue(verify)
        # il token non compare in chiaro su disco
        raw = open(fgs.TOKENS_FILE, encoding="utf-8").read()
        self.assertNotIn("tok123", raw)
        self.assertIn("192.0.2.1", fgs.token_status())
        fgs.set_api_token("192.0.2.1", "")
        self.assertIsNone(fgs.get_api_config("192.0.2.1")[0])

    def test_default_verify_tls_is_false(self):
        # Senza indicazione esplicita, il default deve restare non-verificato:
        # i FortiGate usano quasi sempre un certificato self-signed.
        fgs.set_api_token("192.0.2.2", "tok")
        _, _, verify = fgs.get_api_config("192.0.2.2")
        self.assertFalse(verify)

    def test_api_get_without_token(self):
        with self.assertRaises(fgs.FortiGateError):
            fgs.api_get("192.0.2.9", "monitor/system/status")


class TestHaGetters(unittest.TestCase):
    @mock.patch("services.fortigate_service.api_get")
    def test_get_ha_status_and_checksums_call_api_get(self, mock_api_get):
        mock_api_get.return_value = {"results": {}}
        dev = {"IP": "10.0.0.1"}
        fgs.get_ha_status(dev)
        mock_api_get.assert_called_with("10.0.0.1", "monitor/system/ha-status")
        fgs.get_ha_checksums(dev)
        mock_api_get.assert_called_with("10.0.0.1", "monitor/system/ha-checksums")


class ApiOrSshTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = fgs.TOKENS_FILE
        fgs.TOKENS_FILE = os.path.join(self._tmp.name, "t.json")

    def tearDown(self):
        fgs.TOKENS_FILE = self._orig
        self._tmp.cleanup()

    def test_api_primary(self):
        fgs.set_api_token(DEVICE["IP"], "tok")
        payload = {"results": [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff"}]}
        with mock.patch.object(fgs.requests, "request", return_value=_resp(200, payload)):
            out = fgs.get_arp_table(DEVICE)
        self.assertEqual(out["source"], "api")
        self.assertEqual(out["data"][0]["ip"], "10.0.0.5")

    def test_ssh_fallback_when_no_token(self):
        with mock.patch.object(fgs, "ssh_command", return_value="arp output") as m:
            out = fgs.get_arp_table(DEVICE)
        self.assertEqual(out["source"], "ssh")
        self.assertIn("token API", out["api_error"])
        self.assertEqual(out["data"], "arp output")
        m.assert_called_once()

    def test_both_fail(self):
        with mock.patch.object(fgs, "ssh_command",
                               side_effect=fgs.FortiGateError("ssh ko")):
            with self.assertRaises(fgs.FortiGateError) as ctx:
                fgs.get_arp_table(DEVICE)
        self.assertIn("API:", str(ctx.exception))
        self.assertIn("SSH:", str(ctx.exception))

    def test_ssl_cert_error_gives_hint(self):
        fgs.set_api_token(DEVICE["IP"], "tok")
        err = fgs.requests.exceptions.SSLError(
            "certificate verify failed: unable to get local issuer certificate")
        with mock.patch.object(fgs.requests, "request", side_effect=err):
            with self.assertRaises(fgs.FortiGateError) as ctx:
                fgs.api_get(DEVICE["IP"], "monitor/system/status")
        msg = str(ctx.exception)
        self.assertIn("self-signed", msg)
        self.assertIn("Verifica certificato TLS", msg)

    def test_policy_lookup_api_only(self):
        fgs.set_api_token(DEVICE["IP"], "tok")
        payload = {"results": {"policy_id": 7, "success": True}}
        with mock.patch.object(fgs.requests, "request", return_value=_resp(200, payload)) as m:
            out = fgs.policy_lookup(DEVICE, "10.0.0.5", "example.com", dest_port=443)
        self.assertEqual(out["data"]["policy_id"], 7)
        params = m.call_args.kwargs["params"]
        self.assertEqual(params["srcip"], "10.0.0.5")
        self.assertEqual(params["dest"], "example.com")


class FirewallCmdbSlimTest(unittest.TestCase):
    """Inventario cmdb 'slim' (address/policy/service) via api_get_cmdb: sola
    REST, con format/filter proiettati come da doc Fortinet 'Using APIs'."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = fgs.TOKENS_FILE
        fgs.TOKENS_FILE = os.path.join(self._tmp.name, "t.json")
        fgs.set_api_token(DEVICE["IP"], "tok")

    def tearDown(self):
        fgs.TOKENS_FILE = self._orig
        self._tmp.cleanup()

    def test_api_get_cmdb_builds_format_and_filter_params(self):
        with mock.patch.object(fgs.requests, "request", return_value=_resp(200, {"results": []})) as m:
            fgs.api_get_cmdb(DEVICE["IP"], "cmdb/firewall/address",
                             fmt="name|type|subnet", flt="name=@LAN")
        params = m.call_args.kwargs["params"]
        self.assertEqual(params["format"], "name|type|subnet")
        self.assertEqual(params["filter"], "name=@LAN")

    def test_get_firewall_addresses(self):
        payload = {"results": [{"name": "LAN", "type": "ipmask",
                                 "subnet": "10.0.0.0 255.255.255.0", "comment": "lan net"}]}
        with mock.patch.object(fgs.requests, "request", return_value=_resp(200, payload)) as m:
            out = fgs.get_firewall_addresses(DEVICE)
        self.assertEqual(out["source"], "api")
        self.assertEqual(out["data"][0]["name"], "LAN")
        url = m.call_args.args[1] if m.call_args.args else m.call_args.kwargs.get("url")
        self.assertIn("cmdb/firewall/address", url)
        self.assertEqual(m.call_args.kwargs["params"]["format"],
                         "name|type|subnet|fqdn|comment")

    def test_get_firewall_policy_objects(self):
        payload = {"results": [{"policyid": 1, "name": "allow-out", "action": "accept",
                                 "status": "enable"}]}
        with mock.patch.object(fgs.requests, "request", return_value=_resp(200, payload)) as m:
            out = fgs.get_firewall_policy_objects(DEVICE)
        self.assertEqual(out["data"][0]["policyid"], 1)
        self.assertIn("policyid", m.call_args.kwargs["params"]["format"])

    def test_get_firewall_custom_services(self):
        payload = {"results": [{"name": "CUSTOM-8080", "tcp-portrange": "8080"}]}
        with mock.patch.object(fgs.requests, "request", return_value=_resp(200, payload)) as m:
            out = fgs.get_firewall_custom_services(DEVICE)
        self.assertEqual(out["data"][0]["name"], "CUSTOM-8080")
        url = m.call_args.args[1] if m.call_args.args else m.call_args.kwargs.get("url")
        self.assertIn("cmdb/firewall.service/custom", url)

    def test_firewall_addresses_raises_without_token(self):
        fgs.set_api_token(DEVICE["IP"], "")
        with self.assertRaises(fgs.FortiGateError):
            fgs.get_firewall_addresses(DEVICE)


class DiagnoseClientTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = fgs.TOKENS_FILE
        fgs.TOKENS_FILE = os.path.join(self._tmp.name, "t.json")

    def tearDown(self):
        fgs.TOKENS_FILE = self._orig
        self._tmp.cleanup()

    def test_mac_resolved_to_ip_and_sections_best_effort(self):
        arp = {"source": "api", "data": [{"ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:FF"}]}
        with mock.patch.object(fgs, "get_device_inventory",
                               side_effect=fgs.FortiGateError("no api")), \
             mock.patch.object(fgs, "get_arp_table", return_value=arp), \
             mock.patch.object(fgs, "get_dhcp_leases", return_value={"source": "api", "data": []}), \
             mock.patch.object(fgs, "get_sessions", return_value={"source": "api", "data": []}), \
             mock.patch.object(fgs, "get_traffic_logs", return_value={"source": "api", "data": []}), \
             mock.patch.object(fgs, "policy_lookup", return_value={"source": "api", "data": {"policy_id": 3}}), \
             mock.patch.object(fgs, "get_wifi_clients", return_value={"source": "api", "data": []}):
            out = fgs.diagnose_client(DEVICE, "aa-bb-cc-dd-ee-ff", dest="example.com")
        self.assertEqual(out["client_type"], "mac")
        self.assertEqual(out["resolved_ip"], "10.0.0.5")
        # sezione fallita riportata come errore, non solleva
        self.assertIn("error", out["sections"]["device_inventory"])
        self.assertEqual(out["sections"]["policy_lookup"]["data"]["policy_id"], 3)


class TrafficLogCategoryTest(unittest.TestCase):
    """Il router deve poter scegliere la categoria di log: i parametri
    esistevano nel service ma nessuno schema li trasportava."""

    @mock.patch("services.fortigate_service.api_get")
    def test_log_type_and_subtype_reach_the_api_path(self, mock_api_get):
        mock_api_get.return_value = {"results": []}
        fgs.get_traffic_logs(DEVICE, log_device="memory",
                             log_type="utm", log_subtype="virus",
                             cli_category="virus")
        path = mock_api_get.call_args[0][1]
        self.assertEqual(path, "log/memory/utm/virus")

    @mock.patch("services.fortigate_service.api_get")
    def test_defaults_are_the_historic_traffic_forward(self, mock_api_get):
        mock_api_get.return_value = {"results": []}
        fgs.get_traffic_logs(DEVICE)
        self.assertEqual(mock_api_get.call_args[0][1], "log/disk/traffic/forward")

    @mock.patch("services.fortigate_service.api_get")
    def test_forward_view_drops_local_rows(self, mock_api_get):
        # La GUI del FortiGate separa Forward Traffic (transito, policy
        # normali) da Local Traffic (verso/da gli IP del FortiGate, local-in
        # policy). Entrambi possono avere policyid 0, quindi l'id non li
        # distingue: il campo che lo fa è `subtype`. Chiedendo forward non
        # deve comparire una riga local.
        mock_api_get.return_value = {"results": [
            {"subtype": "forward", "srcip": "198.51.100.10", "policyid": 2},
            {"subtype": "local", "srcip": "192.0.2.1", "policyid": 0},
            {"subtype": "forward", "srcip": "198.51.100.11", "policyid": 0},
        ]}
        res = fgs.get_traffic_logs(DEVICE, log_subtype="forward")
        self.assertEqual([r["subtype"] for r in res["data"]], ["forward", "forward"])
        self.assertTrue(res["subtype_enforced"])

    @mock.patch("services.fortigate_service.api_get")
    def test_local_view_keeps_only_local_rows(self, mock_api_get):
        mock_api_get.return_value = {"results": [
            {"subtype": "forward", "srcip": "198.51.100.10"},
            {"subtype": "local", "srcip": "192.0.2.1"},
        ]}
        res = fgs.get_traffic_logs(DEVICE, log_subtype="local")
        self.assertEqual([r["srcip"] for r in res["data"]], ["192.0.2.1"])

    @mock.patch("services.fortigate_service.api_get")
    def test_rows_without_subtype_are_never_dropped(self, mock_api_get):
        # Se le righe non dichiarano il sottotipo, filtrare svuoterebbe la
        # vista: "nessun log" è una diagnosi peggiore del problema.
        mock_api_get.return_value = {"results": [
            {"srcip": "198.51.100.10"}, {"srcip": "198.51.100.11"},
        ]}
        res = fgs.get_traffic_logs(DEVICE, log_subtype="forward")
        self.assertEqual(len(res["data"]), 2)
        self.assertFalse(res["subtype_enforced"])

    @mock.patch("services.fortigate_service.api_get")
    def test_enforced_flag_is_false_when_fortios_honoured_the_path(self, mock_api_get):
        mock_api_get.return_value = {"results": [
            {"subtype": "forward"}, {"subtype": "forward"},
        ]}
        res = fgs.get_traffic_logs(DEVICE, log_subtype="forward")
        self.assertEqual(len(res["data"]), 2)
        self.assertFalse(res["subtype_enforced"])

    @mock.patch("services.fortigate_service.api_get")
    def test_subtype_is_also_asked_as_a_filter(self, mock_api_get):
        # `rows` limita le righe che il FortiGate restituisce PRIMA del filtro
        # locale: senza filtro sul sottotipo, chiedere 100 righe forward su un
        # apparato pieno di traffico locale ne restituiva zero.
        mock_api_get.return_value = {"results": [{"subtype": "forward"}]}
        fgs.get_traffic_logs(DEVICE, log_subtype="forward")
        self.assertIn("subtype==forward", mock_api_get.call_args[0][2]["filter"])

    @mock.patch("services.fortigate_service.api_get")
    def test_sterile_subtype_filter_falls_back_to_the_unfiltered_query(self, mock_api_get):
        # Versione che accetta il filtro ma non lo capisce: zero righe. Deve
        # ritentare senza, altrimenti il filtro costa i log che doveva salvare.
        mock_api_get.side_effect = [
            {"results": []},
            {"results": [{"subtype": "forward"}, {"subtype": "local"}]},
        ]
        res = fgs.get_traffic_logs(DEVICE, log_subtype="forward")
        self.assertNotIn("filter", mock_api_get.call_args[0][2])
        self.assertEqual([r["subtype"] for r in res["data"]], ["forward"])
        self.assertTrue(res["subtype_enforced"])

    @mock.patch("services.fortigate_service.api_get")
    def test_rejected_subtype_filter_falls_back_before_changing_log_device(self, mock_api_get):
        # Filtro rifiutato su disk: si ritenta disk senza filtro, non si passa
        # subito a memory (che ha una finestra di log molto più corta).
        mock_api_get.side_effect = [
            fgs.FortiGateError("filtro non supportato"),
            {"results": [{"subtype": "forward"}]},
        ]
        res = fgs.get_traffic_logs(DEVICE, log_subtype="forward")
        self.assertEqual(res["log_device"], "disk")
        self.assertEqual(len(res["data"]), 1)

    @mock.patch("services.fortigate_service.ssh_command")
    @mock.patch("services.fortigate_service.api_get")
    def test_cli_fallback_filters_the_subtype_too(self, mock_api_get, mock_ssh):
        # `execute log filter category traffic` da solo mescola forward, local
        # e multicast: chi chiedeva forward si vedeva il traffico locale. Il
        # percorso REST distingue i due, il fallback deve farlo anche lui.
        mock_api_get.side_effect = fgs.FortiGateError("log REST non disponibile")
        mock_ssh.return_value = "date=2026-08-02 time=10:00:00 srcip=192.0.2.10"
        res = fgs.get_traffic_logs(DEVICE, log_subtype="forward")
        script = mock_ssh.call_args[0][1]
        self.assertIn("execute log filter field subtype forward", script)
        self.assertEqual(res["source"], "ssh")

    @mock.patch("services.fortigate_service.api_get")
    def test_date_range_becomes_a_filter_and_is_absent_by_default(self, mock_api_get):
        mock_api_get.return_value = {"results": []}
        fgs.get_traffic_logs(DEVICE, since="2026-08-01", until="2026-08-02")
        flt = mock_api_get.call_args[0][2]["filter"]
        self.assertIn("date>=2026-08-01", flt)
        self.assertIn("date<=2026-08-02", flt)
        # Omesse, nessun filtro sulla data: il comportamento storico resta.
        mock_api_get.reset_mock()
        fgs.get_traffic_logs(DEVICE)
        self.assertNotIn("filter", mock_api_get.call_args[0][2] or {})


class PoliciesWithStatsTest(unittest.TestCase):
    """Le policy mai colpite sono un rilievo d'audit: il join deve
    distinguere 'zero hit' da 'contatore assente'."""

    CONFIG = [
        {"policyid": 1, "name": "allow-web", "action": "accept", "status": "enable"},
        {"policyid": 2, "name": "dead-rule", "action": "accept", "status": "enable"},
        {"policyid": 3, "name": "no-counter", "action": "deny", "status": "enable"},
    ]
    STATS = [
        {"policyid": 1, "hit_count": 42, "bytes": 1024,
         "active_sessions": 3, "last_used": "2026-08-01 10:00:00"},
        {"policyid": 2, "hit_count": 0, "bytes": 0, "active_sessions": 0},
    ]

    def _run(self, stats_side_effect=None):
        with mock.patch.object(fgs, "get_firewall_policy_objects",
                               return_value={"source": "api", "data": self.CONFIG}), \
             mock.patch.object(fgs, "get_policy_stats",
                               side_effect=stats_side_effect,
                               return_value={"source": "api", "data": self.STATS}):
            return fgs.get_policies_with_stats(DEVICE)

    def test_counters_are_joined_on_policyid(self):
        rows = {r["policyid"]: r for r in self._run()["data"]}
        self.assertEqual(rows[1]["hit_count"], 42)
        self.assertEqual(rows[1]["active_sessions"], 3)
        self.assertFalse(rows[1]["never_hit"])

    def test_zero_hit_policy_is_flagged(self):
        rows = {r["policyid"]: r for r in self._run()["data"]}
        self.assertEqual(rows[2]["hit_count"], 0)
        self.assertTrue(rows[2]["never_hit"], "una policy con hit_count 0 è morta")

    def test_policy_absent_from_stats_is_not_flagged_as_dead(self):
        # Nessun contatore != contatore a zero: senza dato non si può dire
        # che la regola sia morta, e marcarla sarebbe un falso positivo.
        rows = {r["policyid"]: r for r in self._run()["data"]}
        self.assertEqual(rows[3]["hit_count"], 0)
        self.assertFalse(rows[3]["never_hit"])

    def test_config_survives_a_stats_failure(self):
        res = self._run(stats_side_effect=fgs.FortiGateError("monitor down"))
        self.assertEqual(len(res["data"]), 3)
        self.assertIn("monitor down", res["stats_error"])
        self.assertFalse(any(r["never_hit"] for r in res["data"]))


class SystemGroupTest(unittest.TestCase):
    @mock.patch("services.fortigate_service.api_get")
    def test_resources_merges_usage_and_time(self, mock_api_get):
        mock_api_get.side_effect = [{"results": {"cpu": 7}}, {"results": {"time": 1}}]
        res = fgs.get_system_resources(DEVICE)
        self.assertEqual([c[0][1] for c in mock_api_get.call_args_list],
                         ["monitor/system/resource/usage", "monitor/system/time"])
        self.assertEqual(res["data"]["usage"], {"cpu": 7})
        self.assertEqual(res["data"]["time"], {"time": 1})

    @mock.patch("services.fortigate_service.api_get")
    def test_ha_merges_status_and_checksums(self, mock_api_get):
        mock_api_get.side_effect = [{"results": {"mode": "a-p"}}, {"results": {"cs": "x"}}]
        res = fgs.get_ha(DEVICE)
        self.assertEqual(res["data"]["status"], {"mode": "a-p"})
        self.assertEqual(res["data"]["checksums"], {"cs": "x"})

    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_admins_are_projected(self, mock_cmdb):
        mock_cmdb.return_value = {"results": [{"name": "admin"}]}
        fgs.get_admins(DEVICE)
        self.assertEqual(mock_cmdb.call_args[0][1], "cmdb/system/admin")
        self.assertEqual(mock_cmdb.call_args[1]["fmt"], fgs.ADMIN_FIELDS)

    def test_admin_projection_carries_no_secret(self):
        # La proiezione è l'unica barriera fra gli account admin del
        # FortiGate e il browser: nessun campo che possa contenere una
        # credenziale deve comparirci.
        for banned in ("password", "passwd", "secret", "key", "hash"):
            self.assertNotIn(banned, fgs.ADMIN_FIELDS.lower())

    @mock.patch("services.fortigate_service.api_get")
    def test_simple_monitor_getters_hit_the_right_paths(self, mock_api_get):
        mock_api_get.return_value = {"results": []}
        for fn, path in ((fgs.get_banned_users, "monitor/user/banned"),
                         (fgs.get_config_revisions, "monitor/system/config-revision"),
                         (fgs.get_certificates, "monitor/system/available-certificates")):
            fn(DEVICE)
            self.assertEqual(mock_api_get.call_args[0][1], path)


class SdwanHealthTest(unittest.TestCase):
    @mock.patch("services.fortigate_service.api_get")
    def test_hits_the_documented_health_check_path(self, mock_api_get):
        # Percorso confermato da docs/reference/fortios/rest-api.md.
        mock_api_get.return_value = {"results": {}}
        fgs.get_sdwan_health(DEVICE)
        self.assertEqual(mock_api_get.call_args[0][1], "monitor/virtual-wan/health-check")


class FirewallObjectsTest(unittest.TestCase):
    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_each_getter_hits_its_cmdb_path(self, mock_cmdb):
        mock_cmdb.return_value = {"results": []}
        for fn, path in ((fgs.get_address_groups, "cmdb/firewall/addrgrp"),
                         (fgs.get_service_groups, "cmdb/firewall.service/group"),
                         (fgs.get_vips, "cmdb/firewall/vip"),
                         (fgs.get_ip_pools, "cmdb/firewall/ippool")):
            fn(DEVICE)
            self.assertEqual(mock_cmdb.call_args[0][1], path)

    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_security_profiles_aggregate_four_families(self, mock_cmdb):
        mock_cmdb.return_value = {"results": [{"name": "default"}]}
        res = fgs.get_security_profiles(DEVICE)
        self.assertEqual(set(res["data"]), {"antivirus", "ips", "webfilter", "application"})
        self.assertEqual(res["data"]["antivirus"], [{"name": "default"}])

    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_a_missing_profile_family_does_not_sink_the_others(self, mock_cmdb):
        # Una licenza senza IPS non deve svuotare antivirus e webfilter.
        mock_cmdb.side_effect = [{"results": [{"name": "av"}]},
                                 fgs.FortiGateError("404 ips"),
                                 {"results": []}, {"results": []}]
        res = fgs.get_security_profiles(DEVICE)
        self.assertEqual(res["data"]["antivirus"], [{"name": "av"}])
        self.assertEqual(res["data"]["ips"], [])
        self.assertIn("ips", res["errors"])


if __name__ == "__main__":
    unittest.main()
