# -*- coding: utf-8 -*-
"""Unit test per il dispatch multi-provider di ai_assistant.chat, con le
chiamate HTTP (requests.post) mockate: nessuna rete reale coinvolta."""

import unittest
from unittest.mock import patch, MagicMock

from ai import ai_assistant


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

    @patch("ai.ai_assistant.requests.post")
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

    @patch("ai.ai_assistant.requests.post")
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

    @patch("ai.ai_assistant.requests.post")
    def test_gemini(self, mock_post):
        mock_post.return_value = _fake_response(
            {"candidates": [{"content": {"parts": [{"text": "Ciao Gemini"}]}}]}
        )
        reply = ai_assistant.chat(self._messages(), provider="gemini",
                                   model="gemini-3-flash", api_key="AIza-x")
        self.assertEqual(reply, "Ciao Gemini")
        args, _kwargs = mock_post.call_args
        self.assertIn("generativelanguage.googleapis.com", args[0])
        self.assertIn("AIza-x", args[0])
        self.assertIn("/models/gemini-3-flash:generateContent", args[0])

    @patch("ai.ai_assistant.requests.post")
    def test_gemini_default_model(self, mock_post):
        mock_post.return_value = _fake_response(
            {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
        )
        ai_assistant.chat(self._messages(), provider="gemini", api_key="AIza-x")
        args, _kwargs = mock_post.call_args
        self.assertIn("/models/gemini-3-flash:generateContent", args[0])

    @patch("ai.ai_assistant.requests.post")
    def test_gemini_model_strips_models_prefix(self, mock_post):
        """Regressione: un nome modello già prefissato con 'models/' (come
        ritornato da ListModels, o incollato dall'utente) non deve produrre
        un percorso doppio 'models/models/...' nell'URL (errore 400)."""
        mock_post.return_value = _fake_response(
            {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}
        )
        ai_assistant.chat(self._messages(), provider="gemini",
                           model="models/gemini-2.5-pro", api_key="AIza-x")
        args, _kwargs = mock_post.call_args
        self.assertIn("/models/gemini-2.5-pro:generateContent", args[0])
        self.assertNotIn("models/models/", args[0])

    def test_normalize_gemini_model_helper(self):
        self.assertEqual(ai_assistant._normalize_gemini_model("models/gemini-3-flash"), "gemini-3-flash")
        self.assertEqual(ai_assistant._normalize_gemini_model("gemini-2.5-pro"), "gemini-2.5-pro")
        self.assertEqual(ai_assistant._normalize_gemini_model(None), "gemini-3-flash")
        self.assertEqual(ai_assistant._normalize_gemini_model(""), "gemini-3-flash")

    @patch("ai.ai_assistant.requests.get")
    def test_list_models_gemini(self, mock_get):
        mock_get.return_value = _fake_response({
            "models": [
                {"name": "models/gemini-3-flash", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent"]},
                {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]},
            ]
        })
        models = ai_assistant.list_models("gemini", api_key="AIza-x")
        self.assertEqual(models, ["gemini-3-flash", "gemini-2.5-pro"])
        args, _kwargs = mock_get.call_args
        self.assertIn("generativelanguage.googleapis.com/v1beta/models", args[0])

    def test_list_models_unsupported_provider(self):
        with self.assertRaises(ai_assistant.AiAssistantError):
            ai_assistant.list_models("does-not-exist", api_key=None)

    @patch("ai.ai_assistant.requests.get")
    def test_list_models_openai(self, mock_get):
        mock_get.return_value = _fake_response({
            "data": [
                {"id": "gpt-4o-mini"},
                {"id": "gpt-4o"},
                {"id": "text-embedding-3-small"},
                {"id": "whisper-1"},
            ]
        })
        models = ai_assistant.list_models("openai", api_key="sk-oa-x")
        self.assertIn("gpt-4o-mini", models)
        self.assertIn("gpt-4o", models)
        self.assertNotIn("text-embedding-3-small", models)
        self.assertNotIn("whisper-1", models)
        args, kwargs = mock_get.call_args
        self.assertIn("api.openai.com/v1/models", args[0])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-oa-x")

    def test_list_models_openai_missing_key(self):
        with self.assertRaises(ai_assistant.AiAssistantError):
            ai_assistant.list_models("openai", api_key=None)

    @patch("ai.ai_assistant.requests.get")
    def test_list_models_anthropic(self, mock_get):
        mock_get.return_value = _fake_response({
            "data": [{"id": "claude-3-5-sonnet-latest"}, {"id": "claude-3-opus-latest"}]
        })
        models = ai_assistant.list_models("anthropic", api_key="sk-ant-x")
        self.assertEqual(models, ["claude-3-5-sonnet-latest", "claude-3-opus-latest"])
        args, kwargs = mock_get.call_args
        self.assertIn("api.anthropic.com/v1/models", args[0])
        self.assertEqual(kwargs["headers"]["x-api-key"], "sk-ant-x")

    @patch("ai.ai_assistant.requests.get")
    def test_list_models_ollama(self, mock_get):
        mock_get.return_value = _fake_response({
            "models": [{"name": "llama3"}, {"name": "mistral"}]
        })
        models = ai_assistant.list_models("ollama", base_url="http://localhost:11434")
        self.assertEqual(models, ["llama3", "mistral"])
        args, _kwargs = mock_get.call_args
        self.assertEqual(args[0], "http://localhost:11434/api/tags")

    def test_default_models_per_provider(self):
        self.assertEqual(ai_assistant.get_default_model("anthropic"), "claude-3-5-sonnet-latest")
        self.assertEqual(ai_assistant.get_default_model("openai"), "gpt-4o-mini")
        self.assertEqual(ai_assistant.get_default_model("gemini"), "gemini-3-flash")
        self.assertEqual(ai_assistant.get_default_model("ollama"), "llama3")
        self.assertEqual(ai_assistant.get_default_model("nope"), "")

    @patch("ai.ai_assistant.requests.post")
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

    @patch("ai.ai_assistant.requests.post")
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

    @patch("ai.ai_assistant.requests.post")
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
