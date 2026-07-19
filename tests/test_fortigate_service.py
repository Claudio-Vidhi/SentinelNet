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


if __name__ == "__main__":
    unittest.main()
