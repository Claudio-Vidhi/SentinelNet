# -*- coding: utf-8 -*-
"""Attribuzione del client nelle righe di audit (review item 4): una chiamata
partita da uno strumento MCP deve essere riconoscibile nel registro."""

import os
import tempfile
import unittest
from unittest import mock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_audittag_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import security_manager  # noqa: E402
from ai import mcp_server  # noqa: E402


class TestAuditClientTag(unittest.TestCase):

    def tearDown(self):
        security_manager.set_client_tag(None)

    def _logged(self, message: str) -> str:
        with mock.patch.object(security_manager.audit_logger, "info") as m:
            security_manager.log_audit(message)
        return m.call_args[0][0]

    def test_untagged_line_is_unchanged(self):
        self.assertEqual(self._logged("LOGIN: utente 'mario'"),
                         "LOGIN: utente 'mario'")

    def test_tagged_line_names_the_client_and_tool(self):
        security_manager.set_client_tag("mcp/send_cli_command")
        self.assertIn("[client dichiarato: mcp/send_cli_command]",
                      self._logged("CLI: comando su 192.0.2.10"))

    def test_tag_is_sanitized_and_bounded(self):
        # il valore arriva da un header: niente iniezione di righe o rumore
        tag = security_manager.set_client_tag("mcp/x\ny FALSO\r" + "z" * 100)
        self.assertNotIn("\n", tag)
        self.assertNotIn(" ", tag)
        self.assertLessEqual(len(tag), 48)


class TestMcpClientSendsTag(unittest.TestCase):
    """Il bridge MCP dichiara sé stesso e lo strumento in esecuzione."""

    def setUp(self):
        mcp_server._token = "t"
        mcp_server._current_tool = ""
        self.addCleanup(setattr, mcp_server, "_current_tool", "")

    def _header_of_call(self, tool: str) -> str:
        mcp_server._current_tool = tool
        resp = mock.MagicMock(status_code=200)
        resp.json.return_value = {}
        with mock.patch.object(mcp_server._session, "request",
                               return_value=resp) as m:
            mcp_server.api("GET", "/api/devices")
        return m.call_args.kwargs["headers"][mcp_server.CLIENT_TAG_HEADER]

    def test_header_carries_the_running_tool(self):
        self.assertEqual(self._header_of_call("arp_scan"), "mcp/arp_scan")

    def test_header_falls_back_to_the_bare_client(self):
        self.assertEqual(self._header_of_call(""), "mcp")

    def test_tool_name_is_cleared_after_the_call(self):
        with mock.patch.dict(mcp_server.TOOLS,
                             {"probe": ("d", {}, lambda a: "ok")}, clear=False), \
             mock.patch.object(mcp_server, "disabled_tools", return_value=set()):
            mcp_server._tool_call({"name": "probe", "arguments": {}})
        self.assertEqual(mcp_server._current_tool, "")


class TestTagReachesTheAuditLine(unittest.TestCase):
    """Il giro completo: header sulla richiesta -> riga di audit del router.
    E' la meta' che puo' rompersi in silenzio (il ContextVar deve sopravvivere
    al passaggio dal middleware all'handler)."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app)

    def _login_audit_lines(self, headers):
        # Utente dedicato e lockout ripulito: il conteggio dei tentativi
        # falliti e' per (IP, account) e in memoria, quindi due moduli che
        # bussano con lo stesso nome finto si bloccano a vicenda.
        user = "audit-tag-probe"
        self.addCleanup(security_manager.clear_account_lockouts, user)
        with mock.patch.object(security_manager.audit_logger, "info") as m:
            self.client.post("/api/auth/login",
                             json={"username": user, "password": "x"},
                             headers=headers)
        return [c[0][0] for c in m.call_args_list]

    def test_mcp_call_is_attributed(self):
        lines = self._login_audit_lines(
            {security_manager.CLIENT_TAG_HEADER: "mcp/send_cli_command"})
        self.assertTrue(lines)
        self.assertTrue(all("[client dichiarato: mcp/send_cli_command]" in ln
                            for ln in lines), lines)

    def test_dashboard_call_is_not_attributed(self):
        lines = self._login_audit_lines({})
        self.assertTrue(lines)
        self.assertFalse(any("client dichiarato" in ln for ln in lines), lines)


if __name__ == "__main__":
    unittest.main()
