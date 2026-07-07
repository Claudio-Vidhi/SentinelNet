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


if __name__ == "__main__":
    unittest.main()
