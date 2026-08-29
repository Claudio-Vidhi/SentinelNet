# -*- coding: utf-8 -*-
"""Chiavi host dei dispositivi: verifica sul known_hosts condiviso e pin al
primo uso (review P0-6: le sessioni netmiko erano l'anello TOFU non
persistente)."""

import os
import tempfile
import unittest
from unittest import mock

import paramiko

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_devkeys_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import net_ssh  # noqa: E402


class TestDeviceHostKeys(unittest.TestCase):

    def setUp(self):
        # known_hosts isolato e vuoto per ogni caso
        self.kh = os.path.join(_TMP_DATA_DIR, f"kh_{self._testMethodName}")
        patcher = mock.patch.object(
            net_ssh, "_known_hosts_path",
            side_effect=lambda scope=None: self._kh_for(scope))
        patcher.start()
        self.addCleanup(patcher.stop)
        open(self.kh, "a").close()

    def _kh_for(self, scope=None):
        """known_hosts isolato, uno per bastione come in produzione."""
        path = self.kh if not scope else f"{self.kh}.{scope}"
        if not os.path.exists(path):
            open(path, "a").close()
        return path

    def _fake_conn(self, key):
        conn = mock.MagicMock()
        conn.remote_conn.get_transport.return_value \
            .get_remote_server_key.return_value = key
        return conn

    # --- preparazione parametri ---

    def test_params_inject_known_hosts(self):
        p = net_ssh._device_ssh_params({"host": "192.0.2.10",
                                        "device_type": "cisco_ios"})
        self.assertTrue(p["alt_host_keys"])
        self.assertEqual(p["alt_key_file"], self.kh)

    def test_params_respect_caller_choice(self):
        p = net_ssh._device_ssh_params({"host": "192.0.2.10",
                                        "ssh_strict": True})
        self.assertNotIn("alt_host_keys", p)

    # --- connessione diretta ---

    def test_direct_connect_pins_on_first_use(self):
        key = paramiko.RSAKey.generate(2048)
        with mock.patch.object(net_ssh, "jump_site_for", return_value=None), \
             mock.patch.object(net_ssh, "_netmiko_connect",
                               return_value=self._fake_conn(key)) as m_conn, \
             mock.patch.object(net_ssh, "_pin_host_key") as m_pin:
            net_ssh.ConnectHandler(host="192.0.2.10", port=22,
                                   device_type="cisco_ios")
        _args, kwargs = m_conn.call_args
        self.assertTrue(kwargs.get("alt_host_keys"))
        self.assertEqual(kwargs.get("alt_key_file"), self.kh)
        m_pin.assert_called_once_with("192.0.2.10", 22, key, None)

    def test_direct_connect_does_not_repin_known_host(self):
        key = paramiko.RSAKey.generate(2048)
        net_ssh._pin_host_key("192.0.2.12", 22, key)
        with mock.patch.object(net_ssh, "jump_site_for", return_value=None), \
             mock.patch.object(net_ssh, "_netmiko_connect",
                               return_value=self._fake_conn(key)), \
             mock.patch.object(net_ssh, "_pin_host_key") as m_pin:
            net_ssh.ConnectHandler(host="192.0.2.12", port=22,
                                   device_type="cisco_ios")
        m_pin.assert_not_called()

    def test_direct_connect_rejects_changed_key(self):
        pinned = paramiko.RSAKey.generate(2048)
        net_ssh._pin_host_key("192.0.2.13", 22, pinned)
        with mock.patch.object(net_ssh, "jump_site_for", return_value=None), \
             mock.patch.object(
                 net_ssh, "_netmiko_connect",
                 side_effect=paramiko.BadHostKeyException(
                     "192.0.2.13", paramiko.RSAKey.generate(2048), pinned)):
            with self.assertRaises(net_ssh.DeviceHostKeyError) as ctx:
                net_ssh.ConnectHandler(host="192.0.2.13", port=22,
                                       device_type="cisco_ios")
        self.assertIn("192.0.2.13", str(ctx.exception))

    # --- connessione via bastione ---

    def test_tunnelled_connect_pins_and_closes_channel_on_failure(self):
        key = paramiko.RSAKey.generate(2048)
        site = {"id": "sede-x", "mode": "jump",
                "jump_host": "203.0.113.9", "jump_port": 22}
        scope = "203.0.113.9"
        chan = mock.MagicMock()
        with mock.patch.object(net_ssh, "jump_site_for", return_value=site), \
             mock.patch.object(net_ssh, "jump_channel", return_value=chan), \
             mock.patch.object(net_ssh, "_netmiko_connect",
                               return_value=self._fake_conn(key)) as m_conn, \
             mock.patch.object(net_ssh, "_pin_host_key") as m_pin:
            net_ssh.ConnectHandler(host="192.0.2.14", port=22,
                                   device_type="cisco_ios")
        _args, kwargs = m_conn.call_args
        self.assertIs(kwargs.get("sock"), chan)
        self.assertEqual(kwargs.get("alt_key_file"), self._kh_for(scope))
        m_pin.assert_called_once_with("192.0.2.14", 22, key, scope)

        # al fallimento il canale verso il bastione va richiuso
        with mock.patch.object(net_ssh, "jump_site_for", return_value=site), \
             mock.patch.object(net_ssh, "jump_channel", return_value=chan), \
             mock.patch.object(net_ssh, "_netmiko_connect",
                               side_effect=paramiko.AuthenticationException("no")):
            with self.assertRaises(paramiko.AuthenticationException):
                net_ssh.ConnectHandler(host="192.0.2.14", port=22,
                                       device_type="cisco_ios")
        self.assertTrue(chan.close.called)

    def test_same_ip_behind_two_bastions_does_not_collide(self):
        """Due tenant possono usare lo stesso IP privato dietro bastioni
        diversi: il pin del primo non deve far sembrare il secondo una
        chiave cambiata."""
        ip = "192.0.2.20"
        key_a = paramiko.RSAKey.generate(2048)
        key_b = paramiko.RSAKey.generate(2048)
        site_a = {"mode": "jump", "jump_host": "203.0.113.1", "jump_port": 22}
        site_b = {"mode": "jump", "jump_host": "203.0.113.2", "jump_port": 22}

        for site, key in ((site_a, key_a), (site_b, key_b)):
            with mock.patch.object(net_ssh, "jump_site_for", return_value=site),                  mock.patch.object(net_ssh, "jump_channel",
                                   return_value=mock.MagicMock()),                  mock.patch.object(net_ssh, "_netmiko_connect",
                                   return_value=self._fake_conn(key)):
                net_ssh.ConnectHandler(host=ip, port=22, device_type="cisco_ios")

        self.assertEqual(net_ssh._pinned_host_key(ip, 22, "203.0.113.1"), key_a)
        self.assertEqual(net_ssh._pinned_host_key(ip, 22, "203.0.113.2"), key_b)
        # e il file condiviso (sessioni dirette) resta estraneo ai due
        self.assertIsNone(net_ssh._pinned_host_key(ip, 22))


if __name__ == "__main__":
    unittest.main()
