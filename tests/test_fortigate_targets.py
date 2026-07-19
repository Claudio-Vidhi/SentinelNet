# -*- coding: utf-8 -*-
"""Test unitari per la gestione multi-target FortiGate (nome, target attivo,
test connessione). Segue lo stesso pattern di test_fortigate_service.py:
file token temporaneo per isolare ogni test."""
import json
import os
import tempfile
import unittest
from unittest import mock

from services import fortigate_service as fgs


def _resp(status=200, payload=None, text=""):
    r = mock.Mock()
    r.status_code = status
    r.text = text or json.dumps(payload or {})
    r.json = mock.Mock(return_value=payload if payload is not None else {})
    return r


class MultiTargetTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = fgs.TOKENS_FILE
        fgs.TOKENS_FILE = os.path.join(self._tmp.name, "fortigate_tokens.json")

    def tearDown(self):
        fgs.TOKENS_FILE = self._orig
        self._tmp.cleanup()

    def test_set_api_token_with_name_list_targets_no_token_leak(self):
        fgs.set_api_token("192.0.2.1", "tok123", port=8443, verify_tls=True, name="HQ-FGT")
        targets = fgs.list_targets()
        self.assertEqual(len(targets), 1)
        t = targets[0]
        self.assertEqual(t["ip"], "192.0.2.1")
        self.assertEqual(t["name"], "HQ-FGT")
        self.assertEqual(t["port"], 8443)
        self.assertTrue(t["verify_tls"])
        self.assertNotIn("token", t)
        self.assertNotIn("token_enc", t)

    def test_update_target_name_only(self):
        fgs.set_api_token("192.0.2.1", "tok123")
        fgs.update_target("192.0.2.1", name="Filiale-Roma")
        targets = fgs.list_targets()
        self.assertEqual(targets[0]["name"], "Filiale-Roma")
        # il token resta invariato
        token, _, _ = fgs.get_api_config("192.0.2.1")
        self.assertEqual(token, "tok123")

    def test_update_target_port_and_verify_tls(self):
        fgs.set_api_token("192.0.2.1", "tok123", port=443, verify_tls=False)
        fgs.update_target("192.0.2.1", port=8443, verify_tls=True)
        targets = fgs.list_targets()
        self.assertEqual(targets[0]["port"], 8443)
        self.assertTrue(targets[0]["verify_tls"])

    def test_update_target_omitted_token_keeps_existing(self):
        fgs.set_api_token("192.0.2.1", "tok-original")
        fgs.update_target("192.0.2.1", name="renamed")
        token, _, _ = fgs.get_api_config("192.0.2.1")
        self.assertEqual(token, "tok-original")

    def test_update_target_empty_string_token_keeps_existing(self):
        fgs.set_api_token("192.0.2.1", "tok-original")
        fgs.update_target("192.0.2.1", token="", name="renamed")
        token, _, _ = fgs.get_api_config("192.0.2.1")
        self.assertEqual(token, "tok-original")

    def test_update_target_with_token_replaces_it(self):
        fgs.set_api_token("192.0.2.1", "tok-original")
        fgs.update_target("192.0.2.1", token="tok-new")
        token, _, _ = fgs.get_api_config("192.0.2.1")
        self.assertEqual(token, "tok-new")

    def test_update_target_missing_ip_raises_keyerror(self):
        with self.assertRaises(KeyError):
            fgs.update_target("192.0.2.99", name="ghost")

    def test_update_target_active_key_is_not_a_valid_target(self):
        fgs.set_api_token("192.0.2.1", "tok123")
        fgs.set_active_target("192.0.2.1")
        with self.assertRaises(KeyError):
            fgs.update_target("_active", name="nope")

    def test_set_and_get_active_target_persists(self):
        fgs.set_api_token("192.0.2.1", "tok1")
        fgs.set_api_token("192.0.2.2", "tok2")
        self.assertIsNone(fgs.get_active_target())
        fgs.set_active_target("192.0.2.2")
        self.assertEqual(fgs.get_active_target(), "192.0.2.2")
        # persistenza: nuova lettura dal file
        raw = json.load(open(fgs.TOKENS_FILE, encoding="utf-8"))
        self.assertEqual(raw["_active"], "192.0.2.2")

    def test_active_key_not_listed_as_target(self):
        fgs.set_api_token("192.0.2.1", "tok1")
        fgs.set_active_target("192.0.2.1")
        targets = fgs.list_targets()
        ips = [t["ip"] for t in targets]
        self.assertEqual(ips, ["192.0.2.1"])
        self.assertTrue(targets[0]["active"])

    def test_empty_token_delete_removes_entry_and_clears_active(self):
        fgs.set_api_token("192.0.2.1", "tok1")
        fgs.set_active_target("192.0.2.1")
        fgs.set_api_token("192.0.2.1", "")
        self.assertEqual(fgs.list_targets(), [])
        self.assertIsNone(fgs.get_active_target())

    def test_connection_ok(self):
        fgs.set_api_token("192.0.2.1", "tok1")
        payload = {"version": "7.2.5", "results": {"version": "7.2.5"}}
        with mock.patch.object(fgs.requests, "request", return_value=_resp(200, payload)):
            out = fgs.test_connection("192.0.2.1")
        self.assertTrue(out["ok"])
        self.assertIn("version", out)

    def test_connection_no_token(self):
        out = fgs.test_connection("192.0.2.9")
        self.assertFalse(out["ok"])
        self.assertIn("error", out)

    def test_connection_exception_caught(self):
        fgs.set_api_token("192.0.2.1", "tok1")
        with mock.patch.object(fgs.requests, "request", side_effect=Exception("boom")):
            out = fgs.test_connection("192.0.2.1")
        self.assertFalse(out["ok"])
        self.assertIn("boom", out["error"])


if __name__ == "__main__":
    unittest.main()
