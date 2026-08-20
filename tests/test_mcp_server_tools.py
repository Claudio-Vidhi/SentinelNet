# -*- coding: utf-8 -*-
"""Tool MCP ``diagnose_client``: deve poter restringere a un tenant.

Un indirizzo presente in più sedi fa tornare 'status': 'ambiguous' dalla rotta
REST (/api/diagnose/client). Senza un modo di indicare il tenant, il tool MCP
non poteva far altro che ripetere la stessa domanda ambigua all'infinito."""

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


if __name__ == "__main__":
    unittest.main()

