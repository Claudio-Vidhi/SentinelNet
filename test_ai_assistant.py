# -*- coding: utf-8 -*-
"""Unit test per il dispatch multi-provider di ai_assistant.chat, con le
chiamate HTTP (requests.post) mockate: nessuna rete reale coinvolta."""

import unittest
from unittest.mock import patch, MagicMock

import ai_assistant


def _fake_response(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = str(json_data)
    return resp


class TestAiAssistantDispatch(unittest.TestCase):
    def _messages(self):
        return [
            {"role": "system", "content": "Sei un assistente di rete."},
            {"role": "user", "content": "Ciao"},
        ]

    @patch("ai_assistant.requests.post")
    def test_anthropic(self, mock_post):
        mock_post.return_value = _fake_response(
            {"content": [{"type": "text", "text": "Ciao a te"}]}
        )
        reply = ai_assistant.chat(self._messages(), provider="anthropic",
                                   model="claude-3-5-sonnet-latest", api_key="sk-ant-x")
        self.assertEqual(reply, "Ciao a te")
        args, kwargs = mock_post.call_args
        self.assertIn("api.anthropic.com", args[0])
        self.assertEqual(kwargs["headers"]["x-api-key"], "sk-ant-x")
        self.assertEqual(kwargs["json"]["system"], "Sei un assistente di rete.")

    @patch("ai_assistant.requests.post")
    def test_openai(self, mock_post):
        mock_post.return_value = _fake_response(
            {"choices": [{"message": {"content": "Ciao dall'AI"}}]}
        )
        reply = ai_assistant.chat(self._messages(), provider="openai",
                                   model="gpt-4o-mini", api_key="sk-oa-x")
        self.assertEqual(reply, "Ciao dall'AI")
        args, kwargs = mock_post.call_args
        self.assertIn("api.openai.com", args[0])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-oa-x")

    @patch("ai_assistant.requests.post")
    def test_gemini(self, mock_post):
        mock_post.return_value = _fake_response(
            {"candidates": [{"content": {"parts": [{"text": "Ciao Gemini"}]}}]}
        )
        reply = ai_assistant.chat(self._messages(), provider="gemini",
                                   model="gemini-1.5-flash", api_key="AIza-x")
        self.assertEqual(reply, "Ciao Gemini")
        args, _kwargs = mock_post.call_args
        self.assertIn("generativelanguage.googleapis.com", args[0])
        self.assertIn("AIza-x", args[0])

    @patch("ai_assistant.requests.post")
    def test_ollama(self, mock_post):
        mock_post.return_value = _fake_response(
            {"message": {"content": "Ciao locale"}}
        )
        reply = ai_assistant.chat(self._messages(), provider="ollama", model="llama3",
                                   base_url="http://localhost:11434")
        self.assertEqual(reply, "Ciao locale")
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "http://localhost:11434/api/chat")
        self.assertEqual(kwargs["json"]["model"], "llama3")

    def test_unsupported_provider(self):
        with self.assertRaises(ai_assistant.AiAssistantError):
            ai_assistant.chat(self._messages(), provider="does-not-exist")

    def test_missing_api_key(self):
        with self.assertRaises(ai_assistant.AiAssistantError):
            ai_assistant.chat(self._messages(), provider="anthropic", api_key=None)

    @patch("ai_assistant.requests.post")
    def test_http_error_raises_ai_error(self, mock_post):
        mock_post.return_value = _fake_response({"error": "bad"}, status_code=401)
        with self.assertRaises(ai_assistant.AiAssistantError):
            ai_assistant.chat(self._messages(), provider="openai", api_key="sk-bad")


class TestRateLimiter(unittest.TestCase):
    def test_allows_up_to_limit(self):
        limiter = ai_assistant.RateLimiter(rpm=2)
        ok1, _ = limiter.allow()
        ok2, _ = limiter.allow()
        ok3, retry_after = limiter.allow()
        self.assertTrue(ok1)
        self.assertTrue(ok2)
        self.assertFalse(ok3)
        self.assertIsNotNone(retry_after)

    def test_unlimited_when_zero_or_none(self):
        limiter = ai_assistant.RateLimiter(rpm=0)
        for _ in range(50):
            ok, _ = limiter.allow()
            self.assertTrue(ok)

    def test_reconfigure_changes_limit(self):
        limiter = ai_assistant.RateLimiter(rpm=1)
        self.assertTrue(limiter.allow()[0])
        self.assertFalse(limiter.allow()[0])
        limiter.configure(5)
        self.assertTrue(limiter.allow()[0])

    @patch("ai_assistant.requests.post")
    def test_chat_raises_when_rate_limit_exceeded(self, mock_post):
        mock_post.return_value = _fake_response(
            {"message": {"content": "ok"}}
        )
        try:
            ai_assistant.chat(self._msgs(), provider="ollama", rate_limit_rpm=1)
            with self.assertRaises(ai_assistant.RateLimitExceededError):
                ai_assistant.chat(self._msgs(), provider="ollama", rate_limit_rpm=1)
        finally:
            ai_assistant.configure_rate_limit(0)  # reset per non influenzare altri test

    def _msgs(self):
        return [{"role": "user", "content": "ciao"}]


class TestBuildTenantContext(unittest.TestCase):
    def test_includes_only_given_tenant_data(self):
        text = ai_assistant.build_tenant_context(
            "SedeA",
            devices=[{"IP": "10.0.0.1", "Hostname": "sw1", "Vendor": "cisco", "Site": "central"}],
            group_info={"description": "Sede di test"},
            site=[{"name": "central", "mode": "central", "subnets": ["10.0.0.0/24"], "last_seen": None}],
            mac_stats={"sightings": 5, "unique_macs": 3, "switches": 1, "retention_days": 30},
            mac_recent=[{"mac": "aa:bb:cc:dd:ee:ff", "switch_ip": "10.0.0.1",
                         "interface": "Gi1/0/1", "vlan": "10", "last_seen": "2026-01-01"}],
        )
        self.assertIn("SedeA", text)
        self.assertIn("Sede di test", text)
        self.assertIn("10.0.0.1", text)
        self.assertIn("sw1", text)
        self.assertIn("5 avvistamenti", text)
        self.assertIn("aa:bb:cc:dd:ee:ff", text)
        self.assertIn("mode=central", text)

    def test_truncates_large_device_list(self):
        devices = [{"IP": f"10.0.0.{i}", "Hostname": f"h{i}", "Vendor": "cisco"} for i in range(5)]
        text = ai_assistant.build_tenant_context("SedeB", devices=devices, max_devices=2)
        self.assertIn("altri 3 dispositivi", text)

    def test_empty_inputs_do_not_crash(self):
        text = ai_assistant.build_tenant_context("SedeVuota")
        self.assertIn("SedeVuota", text)
        self.assertIn("0 totali", text)


if __name__ == "__main__":
    unittest.main()
