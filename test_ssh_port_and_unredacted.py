# -*- coding: utf-8 -*-
"""Test §9.1 (porta SSH per-device) e §9.4 (toggle redazione per LLM locali)."""

import os
import tempfile
import unittest
from unittest import mock

import core_engine
import ai_assistant


class TestGetDevicePort(unittest.TestCase):
    def test_default_22(self):
        self.assertEqual(core_engine.get_device_port({}), 22)
        self.assertEqual(core_engine.get_device_port({'SSH Port': ''}), 22)
        self.assertEqual(core_engine.get_device_port({'SSH Port': None}), 22)

    def test_custom_port(self):
        self.assertEqual(core_engine.get_device_port({'SSH Port': '2222'}), 2222)
        self.assertEqual(core_engine.get_device_port({'SSH Port': 830}), 830)

    def test_invalid_falls_back(self):
        self.assertEqual(core_engine.get_device_port({'SSH Port': 'abc'}), 22)
        self.assertEqual(core_engine.get_device_port({'SSH Port': '99999'}), 22)
        self.assertEqual(core_engine.get_device_port({'SSH Port': '0'}), 22)


class TestInventorySshPortRoundTrip(unittest.TestCase):
    def test_round_trip_and_legacy_default(self):
        import inventory_manager
        with tempfile.TemporaryDirectory() as td:
            csv_path = os.path.join(td, 'hosts.csv')
            with mock.patch.object(inventory_manager, 'HOSTS_CSV', csv_path):
                inventory_manager.add_or_update_device(
                    '10.9.9.9', 'cisco', 'custom', 'u', 'p', 's', 'Generale',
                    ssh_port=2222)
                dev = inventory_manager.get_all_devices()[0]
                self.assertEqual(dev['SSH Port'], '2222')
                # Aggiornamento senza ssh_port: la porta esistente si preserva.
                inventory_manager.add_or_update_device(
                    '10.9.9.9', 'cisco', 'custom', 'u', 'p', 's', 'Generale')
                dev = inventory_manager.get_all_devices()[0]
                self.assertEqual(dev['SSH Port'], '2222')

    def test_invalid_port_rejected(self):
        import inventory_manager
        with self.assertRaises(ValueError):
            inventory_manager.add_or_update_device(
                '10.9.9.8', 'cisco', 'custom', 'u', 'p', 's', 'Generale',
                ssh_port=70000)


class TestUnredactedGate(unittest.TestCase):
    def test_is_local_base_url(self):
        f = ai_assistant._is_local_base_url
        self.assertTrue(f('http://localhost:11434'))
        self.assertTrue(f('http://127.0.0.1:8080'))
        self.assertTrue(f('http://192.168.1.10:8000'))
        self.assertFalse(f('https://api.openai.com/v1'))
        self.assertFalse(f('https://8.8.8.8'))
        self.assertFalse(f(''))
        self.assertFalse(f(None))

    def _chat_capture(self, provider, base_url, allow_unredacted):
        """Invoca chat() con provider mockato; ritorna i messaggi inviati."""
        sent = {}
        def fake(messages, *a, **kw):
            sent['messages'] = messages
            return 'ok'
        target = {'ollama': '_chat_ollama', 'openai': '_chat_openai',
                  'anthropic': '_chat_anthropic'}[provider]
        with mock.patch.object(ai_assistant, target, side_effect=fake):
            ai_assistant.chat(
                [{"role": "user", "content": "username admin password 7 cisco123"}],
                provider=provider, api_key='k', base_url=base_url,
                allow_unredacted=allow_unredacted)
        return sent['messages'][0]['content']

    def test_unredacted_allowed_only_local(self):
        # ollama + toggle ON: NON redatto
        out = self._chat_capture('ollama', 'http://localhost:11434', True)
        self.assertIn('cisco123', out)
        # ollama + toggle OFF: redatto (comportamento attuale)
        out = self._chat_capture('ollama', 'http://localhost:11434', False)
        self.assertNotIn('cisco123', out)
        # provider pubblico + toggle ON: redatto comunque (fail-closed)
        out = self._chat_capture('anthropic', None, True)
        self.assertNotIn('cisco123', out)
        # openai-compatible locale + toggle ON: NON redatto
        out = self._chat_capture('openai', 'http://127.0.0.1:8000/v1', True)
        self.assertIn('cisco123', out)
        # openai pubblico + toggle ON: redatto
        out = self._chat_capture('openai', 'https://api.openai.com/v1', True)
        self.assertNotIn('cisco123', out)


if __name__ == '__main__':
    unittest.main()
