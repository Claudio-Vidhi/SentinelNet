# -*- coding: utf-8 -*-
"""Tool MCP ``diagnose_client``: deve poter restringere a un tenant.

Un indirizzo presente in più sedi fa tornare 'status': 'ambiguous' dalla rotta
REST (/api/diagnose/client). Senza un modo di indicare il tenant, il tool MCP
non poteva far altro che ripetere la stessa domanda ambigua all'infinito."""

import io
import unittest
from unittest.mock import patch

from ai import mcp_server


class TestDiagnoseClientTenant(unittest.TestCase):

    def test_lo_schema_espone_tenant_come_facoltativo(self):
        _desc, schema, _fn = mcp_server.TOOLS["diagnose_client"]
        self.assertIn("tenant", schema["properties"])
        self.assertNotIn("tenant", schema.get("required", []))

    def test_il_tenant_indicato_viene_inoltrato_alla_rotta(self):
        _desc, _schema, fn = mcp_server.TOOLS["diagnose_client"]
        with patch("ai.mcp_server.api") as mock_api:
            fn({"client": "192.0.2.10", "tenant": "sede-a"})
        mock_api.assert_called_once_with(
            "POST", "/api/diagnose/client",
            body={"client": "192.0.2.10", "tenant": "sede-a"})

    def test_il_tenant_omesso_non_compare_nel_corpo(self):
        _desc, _schema, fn = mcp_server.TOOLS["diagnose_client"]
        with patch("ai.mcp_server.api") as mock_api:
            fn({"client": "192.0.2.10"})
        _args, kwargs = mock_api.call_args
        self.assertNotIn("tenant", kwargs["body"])


class TestPolicyMCPTools(unittest.TestCase):

    def test_policy_trace_tool(self):
        self.assertIn("policy_trace", mcp_server.TOOLS)
        _desc, schema, fn = mcp_server.TOOLS["policy_trace"]
        self.assertEqual(schema["required"], ["ip", "src", "dst"])

        with patch("ai.mcp_server.api") as mock_api:
            fn({"ip": "192.0.2.1", "src": "192.0.2.50", "dst": "198.51.100.10", "proto": "tcp", "dport": 443})
        mock_api.assert_called_once_with(
            "POST", "/api/policy-test/192.0.2.1/trace",
            body={"src_ip": "192.0.2.50", "dst_ip": "198.51.100.10", "proto": "tcp", "dport": 443, "ingress_intf": None},
        )

    def test_policy_findings_tool(self):
        self.assertIn("policy_findings", mcp_server.TOOLS)
        _desc, schema, fn = mcp_server.TOOLS["policy_findings"]
        self.assertEqual(schema["required"], ["ip"])

        with patch("ai.mcp_server.api") as mock_api:
            fn({"ip": "192.0.2.1"})
        mock_api.assert_called_once_with("GET", "/api/policy-test/192.0.2.1/findings")


class TestDisabledToolsFailClosed(unittest.TestCase):
    """WP3 (docs/app-review-fix-plan.md): il gating dei tool deve fallire
    chiuso prima del primo sync riuscito, mai aperto con l'insieme vuoto."""

    def setUp(self):
        self._orig = dict(mcp_server._disabled)
        mcp_server._disabled.update({"at": 0.0, "tools": set(), "synced": False})

    def tearDown(self):
        mcp_server._disabled.clear()
        mcp_server._disabled.update(self._orig)

    def test_first_fetch_failure_disables_everything(self):
        with patch("ai.mcp_server.api", side_effect=RuntimeError("centrale irraggiungibile")):
            self.assertEqual(mcp_server.disabled_tools(), set(mcp_server.TOOLS))
        self.assertFalse(mcp_server._disabled["synced"])

    def test_failure_after_sync_keeps_last_known_state(self):
        mcp_server._disabled.update({"at": 0.0, "tools": {"arp_scan"}, "synced": True})
        with patch("ai.mcp_server.api", side_effect=RuntimeError("centrale irraggiungibile")):
            self.assertEqual(mcp_server.disabled_tools(), {"arp_scan"})

    def test_successful_sync_updates_the_set(self):
        with patch("ai.mcp_server.api",
                   return_value={"disabled_tools": ["arp_scan", "send_cli_command"]}):
            self.assertEqual(mcp_server.disabled_tools(),
                             {"arp_scan", "send_cli_command"})
        self.assertTrue(mcp_server._disabled["synced"])

    def test_tool_list_is_empty_when_fail_closed(self):
        with patch("ai.mcp_server.api", side_effect=RuntimeError("centrale irraggiungibile")):
            listing = mcp_server._tool_list()
        self.assertEqual(listing["tools"], [])


class TestAccountPostureWarning(unittest.TestCase):
    """Follow-up WP3: ogni client MCP eredita il ruolo dell'account
    configurato; sopra viewer il modello puo' eseguire strumenti di azione
    e l'operatore deve vederlo."""

    def _warning_for(self, role):
        with patch.object(mcp_server, "api", return_value={"role": role}), \
             patch("sys.stderr", new_callable=io.StringIO) as err:
            mcp_server._warn_if_privileged_account()
            return err.getvalue()

    def test_admin_account_warns(self):
        out = self._warning_for("admin")
        self.assertIn("admin", out)
        self.assertIn("viewer", out)

    def test_operator_account_warns(self):
        self.assertIn("operator", self._warning_for("operator"))

    def test_viewer_account_is_silent(self):
        self.assertEqual(self._warning_for("viewer"), "")

    def test_unreachable_me_is_silent(self):
        with patch.object(mcp_server, "api", side_effect=RuntimeError("giu'")), \
             patch("sys.stderr", new_callable=io.StringIO) as err:
            mcp_server._warn_if_privileged_account()
            self.assertEqual(err.getvalue(), "")


if __name__ == "__main__":
    unittest.main()

