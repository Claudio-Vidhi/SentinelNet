# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Bastion host key: probed without pinning, pinned only once confirmed.

The site wizard shows the fingerprint to the operator before trusting it.
Until then nothing may land in ssh_known_hosts, and what gets pinned must be
the key the SERVER saw — the browser only sends back the fingerprint.
"""
import os
import tempfile
import time
import unittest
from unittest import mock

import paramiko

from core import net_ssh

HOST, PORT = "198.51.100.50", 22


def _fake_transport(key):
    tr = mock.Mock()
    tr.get_remote_server_key.return_value = key
    return tr


class BastionFingerprint(unittest.TestCase):
    def setUp(self):
        net_ssh._probed_keys.clear()
        self.td = tempfile.TemporaryDirectory()
        self.known_hosts = os.path.join(self.td.name, "ssh_known_hosts")
        self.p_path = mock.patch("core.data_config.get_path", return_value=self.known_hosts)
        self.p_path.start()

    def tearDown(self):
        self.p_path.stop()
        self.td.cleanup()

    def _probe(self, key, connect_error=None):
        tr = _fake_transport(key)
        if connect_error:
            tr.connect.side_effect = connect_error
        with mock.patch.object(net_ssh.socket, "create_connection", return_value=mock.Mock()), \
             mock.patch.object(net_ssh.paramiko, "Transport", return_value=tr), \
             mock.patch("security.identity_manager.get_identity_credentials",
                        return_value=("u", "p", "")):
            return net_ssh.probe_bastion_draft(HOST, PORT, "id-hk")

    def test_fingerprint_is_openssh_sha256(self):
        key = paramiko.ECDSAKey.generate()
        fp = net_ssh.fingerprint(key)
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertFalse(fp.endswith("="))
        self.assertEqual(len(fp), len("SHA256:") + 43)

    def test_draft_probe_pins_nothing(self):
        key = paramiko.ECDSAKey.generate()
        out = self._probe(key)
        self.assertEqual(out["fingerprint"], net_ssh.fingerprint(key))
        self.assertEqual(out["key_type"], key.get_name())
        self.assertFalse(out["known"])
        self.assertIsNone(net_ssh._pinned_host_key(HOST, PORT))

    def test_pin_confirmed_pins_the_probed_key(self):
        key = paramiko.ECDSAKey.generate()
        fp = self._probe(key)["fingerprint"]
        self.assertTrue(net_ssh.pin_confirmed(HOST, PORT, fp))
        self.assertEqual(net_ssh._pinned_host_key(HOST, PORT), key)
        # One confirmation, one pin: the cache entry is consumed.
        self.assertFalse(net_ssh.pin_confirmed(HOST, PORT, fp))

    def test_pin_confirmed_refuses_a_different_fingerprint(self):
        self._probe(paramiko.ECDSAKey.generate())
        other = net_ssh.fingerprint(paramiko.ECDSAKey.generate())
        self.assertFalse(net_ssh.pin_confirmed(HOST, PORT, other))
        self.assertIsNone(net_ssh._pinned_host_key(HOST, PORT))

    def test_pin_confirmed_refuses_other_host(self):
        fp = self._probe(paramiko.ECDSAKey.generate())["fingerprint"]
        self.assertFalse(net_ssh.pin_confirmed("198.51.100.51", PORT, fp))

    def test_pin_confirmed_expires(self):
        fp = self._probe(paramiko.ECDSAKey.generate())["fingerprint"]
        key, _ = net_ssh._probed_keys[(HOST, PORT)]
        net_ssh._probed_keys[(HOST, PORT)] = (key, time.time() - net_ssh.PROBE_TTL - 1)
        self.assertFalse(net_ssh.pin_confirmed(HOST, PORT, fp))

    def test_known_key_is_reported(self):
        key = paramiko.ECDSAKey.generate()
        net_ssh._pin_host_key(HOST, PORT, key)
        self.assertTrue(self._probe(key)["known"])

    def test_draft_probe_mismatch_raises(self):
        net_ssh._pin_host_key(HOST, PORT, paramiko.ECDSAKey.generate())
        with self.assertRaises(net_ssh.BastionHostKeyError):
            self._probe(paramiko.ECDSAKey.generate(),
                        connect_error=paramiko.SSHException("Bad host key from server"))
        self.assertEqual(net_ssh._probed_keys, {})


if __name__ == "__main__":
    unittest.main()
