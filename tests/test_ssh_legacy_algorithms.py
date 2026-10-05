# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""SHA-1 SSH algorithms are available, but only as a fallback.

Older Cisco IOS switches offer only SHA-1 key exchanges and an ssh-rsa host
key. paramiko 5 removed both, and a routine lock bump turned every triage on
those switches into "no acceptable kex algorithm" without a test noticing.
core/ssh_legacy.py puts them back; these tests prove it with a real
handshake against a server that offers nothing else, and that a first
attempt never offers them.
"""
import socket
import threading
import unittest
from unittest.mock import patch

import paramiko

from core import net_ssh, ssh_legacy


class _Server(paramiko.ServerInterface):
    pass


def _legacy_only_server(key, kex="diffie-hellman-group14-sha1", ciphers=None, macs=None):
    """A listening socket whose server speaks only ``kex`` + ssh-rsa."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(4)

    def serve():
        while True:
            try:
                conn, _ = lsock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(key)
            opts = t.get_security_options()
            opts.kex = [kex]
            opts.key_types = ["ssh-rsa"]
            if ciphers:
                opts.ciphers = ciphers
            if macs:
                opts.digests = macs
            try:
                t.start_server(server=_Server())
            except Exception:
                pass
    threading.Thread(target=serve, daemon=True).start()
    return lsock


class LegacySshAlgorithmsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(2048)
        cls.lsock = _legacy_only_server(cls.key)
        cls.port = cls.lsock.getsockname()[1]

    @classmethod
    def tearDownClass(cls):
        cls.lsock.close()

    def _handshake(self, disabled):
        t = paramiko.Transport(socket.create_connection(("127.0.0.1", self.port), timeout=5))
        if disabled:
            t.disabled_algorithms = disabled
        try:
            t.start_client(timeout=5)
            return t.get_remote_server_key().get_name()
        finally:
            t.close()

    def test_modern_only_attempt_is_refused_by_a_legacy_device(self):
        with self.assertRaises(paramiko.ssh_exception.IncompatiblePeer):
            self._handshake(ssh_legacy.MODERN_ONLY)

    def test_fallback_completes_the_handshake(self):
        self.assertEqual(self._handshake(None), "ssh-rsa")

    def test_legacy_algorithms_are_offered_last(self):
        kex = paramiko.Transport._preferred_kex
        self.assertEqual(tuple(kex[-len(ssh_legacy.LEGACY_KEX):]), ssh_legacy.LEGACY_KEX)
        self.assertEqual(paramiko.Transport._preferred_keys[-1], "ssh-rsa")


class Group1OnlyDeviceTest(LegacySshAlgorithmsTest):
    """Old IOS: group1-sha1 only, CBC ciphers, SHA-1/MD5 MACs."""

    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(2048)
        cls.lsock = _legacy_only_server(
            cls.key, "diffie-hellman-group1-sha1",
            ciphers=["aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc"],
            macs=["hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"])
        cls.port = cls.lsock.getsockname()[1]

    def test_terminal_shows_what_the_device_offered(self):
        from routers.commands import _ssh_failure_hint

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with self.assertRaises(paramiko.ssh_exception.IncompatiblePeer) as cm:
            client.connect("127.0.0.1", port=self.port, username="u", password="p",
                           look_for_keys=False, allow_agent=False, timeout=5,
                           disabled_algorithms=ssh_legacy.MODERN_ONLY,
                           transport_factory=ssh_legacy.OfferTransport)
        offer = client._transport.remote_offer
        client.close()
        hint = _ssh_failure_hint(cm.exception, offer)
        self.assertIn("kex: diffie-hellman-group1-sha1", hint)
        self.assertIn("cipher: aes128-cbc, 3des-cbc", hint)

    def test_an_algorithm_paramiko_lacks_is_flagged(self):
        text = ssh_legacy.describe_offer({"kex_algo_list": ["made-up-kex"],
                                          "client_encrypt_algo_list": ["aes128-cbc"]})
        self.assertIn("kex: made-up-kex   <-- non supportato", text)
        self.assertNotIn("aes128-cbc   <--", text)


class ConnectFallbackTest(unittest.TestCase):
    """net_ssh._connect: modern first, SHA-1 only after a negotiation refusal."""

    def setUp(self):
        ssh_legacy._needs_legacy.clear()

    def test_a_known_legacy_host_skips_the_refused_attempt(self):
        refusal = Exception("Incompatible ssh peer (no acceptable kex algorithm)")
        self._run([refusal, object()])
        calls, _ = self._run([object()])
        self.assertEqual(calls, [None])

    def _run(self, side_effect):
        calls = []

        def fake(**kw):
            calls.append(kw.get("disabled_algorithms"))
            effect = side_effect.pop(0)
            if isinstance(effect, Exception):
                raise effect
            return effect
        with patch.object(net_ssh, "_netmiko_connect", side_effect=fake), \
             patch.object(net_ssh, "jump_site_for", return_value=None), \
             patch.object(net_ssh, "_device_ssh_params", side_effect=lambda p, s=None: p), \
             patch.object(net_ssh, "_persist_device_key"), \
             patch.object(net_ssh, "_pinned_host_key", return_value=None):
            try:
                result = net_ssh._connect(None, None, host="192.0.2.10", device_type="cisco_ios")
            except Exception as e:
                result = e
        return calls, result

    def test_modern_device_connects_on_the_first_attempt(self):
        conn = object()
        calls, result = self._run([conn])
        self.assertIs(result, conn)
        self.assertEqual(calls, [ssh_legacy.MODERN_ONLY])

    def test_legacy_device_gets_a_second_attempt_with_sha1(self):
        conn = object()
        refusal = Exception("A paramiko SSHException occurred during connection creation:\n\n"
                            "Incompatible ssh peer (no acceptable kex algorithm)")
        calls, result = self._run([refusal, conn])
        self.assertIs(result, conn)
        self.assertEqual(calls, [ssh_legacy.MODERN_ONLY, None])

    def test_other_failures_are_not_retried(self):
        calls, result = self._run([paramiko.AuthenticationException("bad password")])
        self.assertIsInstance(result, paramiko.AuthenticationException)
        self.assertEqual(len(calls), 1)

    def test_caller_disabled_algorithms_are_kept(self):
        self.assertEqual(ssh_legacy.merged({"ciphers": ["3des-cbc"]}, {"keys": ["ssh-rsa"]}),
                         {"ciphers": ["3des-cbc"], "keys": ["ssh-rsa"]})
        self.assertEqual(ssh_legacy.merged({"ciphers": ["3des-cbc"]}, None), {"ciphers": ["3des-cbc"]})


if __name__ == "__main__":
    unittest.main()
