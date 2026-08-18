# -*- coding: utf-8 -*-
"""Unit tests for the 'jump' site mode (data model, Task 1 of the
jump-host-sites plan). No tunnel here: only the bastion fields on the site
dict.

Isolates SENTINELNET_DATA_DIR in a temp dir BEFORE importing site_manager,
like test_sites.py / test_remote_site.py: SITES_JSON is resolved via
core.data_config.get_path at module import time, so setting the env var
afterwards would have no effect.
"""
import os
import socket
import tempfile
import threading
import time
import unittest
import unittest.mock as mock

import paramiko

_TMP = tempfile.mkdtemp(prefix="sentinelnet_jump_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from services import site_manager  # noqa: E402
from services import inventory_manager  # noqa: E402


class JumpSiteModel(unittest.TestCase):
    def test_create_jump_site_keeps_fields_and_issues_no_token(self):
        site, token = site_manager.create_site(
            "Customer A", "jump", subnets=["192.0.2.0/24"],
            jump_host="198.51.100.10", jump_port=22, jump_identity="id-1")
        self.assertIsNone(token)
        self.assertEqual(site["mode"], "jump")
        self.assertEqual(site["jump_host"], "198.51.100.10")
        self.assertEqual(site["jump_port"], 22)
        self.assertEqual(site["jump_identity"], "id-1")

    def test_jump_site_without_host_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer B", "jump", jump_identity="id-1")

    def test_jump_port_zero_is_rejected(self):
        # 0 is falsy, so a naive `port or 22` would silently swap it for the
        # default instead of raising: this must not happen.
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer C", "jump",
                jump_host="198.51.100.10", jump_port=0, jump_identity="id-1")

    def test_jump_port_above_range_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer D", "jump",
                jump_host="198.51.100.10", jump_port=65536, jump_identity="id-1")

    def test_jump_port_negative_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer E", "jump",
                jump_host="198.51.100.10", jump_port=-1, jump_identity="id-1")

    def test_jump_port_non_numeric_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer F", "jump",
                jump_host="198.51.100.10", jump_port="abc", jump_identity="id-1")


class JumpChannel(unittest.TestCase):
    def test_connect_handler_injects_sock_for_a_jump_device(self):
        from core import net_ssh
        chan = object()
        # Shape of services.inventory_manager.get_device_by_ip's real cache
        # entry (see get_device_by_ip): lowercase keys, not the raw hosts.csv
        # row. JumpChannelRealDeviceLookup below exercises the real function
        # instead of a hand-picked shape.
        device = {"ip": "192.0.2.5", "hostname": "", "tenant": "Generale",
                  "site": "customer-a"}
        site = {"id": "customer-a", "mode": "jump", "jump_host": "198.51.100.10",
                "jump_port": 22, "jump_identity": "id-1"}
        with mock.patch.object(net_ssh, "_netmiko_connect") as nm, \
             mock.patch.object(net_ssh, "jump_channel", return_value=chan) as jc, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=device), \
             mock.patch("services.site_manager.get_site", return_value=site):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="192.0.2.5",
                                   username="u", password="p")
        jc.assert_called_once_with(site, "192.0.2.5", 22)
        self.assertIs(nm.call_args.kwargs["sock"], chan)

    def test_connect_handler_is_untouched_for_a_central_device(self):
        from core import net_ssh
        device = {"ip": "192.0.2.6", "hostname": "", "tenant": "Generale",
                  "site": "central"}
        site = {"id": "central", "mode": "central"}
        with mock.patch.object(net_ssh, "_netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=device), \
             mock.patch("services.site_manager.get_site", return_value=site):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="192.0.2.6",
                                   username="u", password="p")
        self.assertNotIn("sock", nm.call_args.kwargs)

    def test_unknown_device_is_untouched(self):
        from core import net_ssh
        with mock.patch.object(net_ssh, "_netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=None):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="203.0.113.9",
                                   username="u", password="p")
        self.assertNotIn("sock", nm.call_args.kwargs)


class JumpChannelRealDeviceLookup(unittest.TestCase):
    """Exercises the real services.inventory_manager.get_device_by_ip instead
    of mocking it: the mocked tests above assume a shape, this test proves
    _jump_site_for actually works against the live cache. Isolates hosts.csv
    the way tests/test_bulk_assign_identity.py does (HOSTS_CSV attribute
    override, not the env var, since inventory_manager may already be
    imported with a resolved path by the time this test runs)."""

    def setUp(self):
        fd, self.csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        os.remove(self.csv_path)
        self._orig_csv = inventory_manager.HOSTS_CSV
        inventory_manager.HOSTS_CSV = self.csv_path
        inventory_manager.invalidate_device_ip_cache()

    def tearDown(self):
        inventory_manager.HOSTS_CSV = self._orig_csv
        inventory_manager.invalidate_device_ip_cache()
        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)

    def test_connect_handler_finds_jump_site_via_real_device_lookup(self):
        from core import net_ssh
        inventory_manager.add_or_update_device(
            "192.0.2.5", "cisco", "default", "u", "p", "s", "Generale",
            site="customer-a")
        chan = object()
        site = {"id": "customer-a", "mode": "jump", "jump_host": "198.51.100.10",
                "jump_port": 22, "jump_identity": "id-1"}
        with mock.patch.object(net_ssh, "_netmiko_connect") as nm, \
             mock.patch.object(net_ssh, "jump_channel", return_value=chan) as jc, \
             mock.patch("services.site_manager.get_site", return_value=site):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="192.0.2.5",
                                   username="u", password="p")
        jc.assert_called_once_with(site, "192.0.2.5", 22)
        self.assertIs(nm.call_args.kwargs["sock"], chan)


class JumpTransportLocking(unittest.TestCase):
    """Covers the per-site locking fix: a slow/dead bastion for one site must
    not block a connect to a different, healthy site's bastion."""

    def tearDown(self):
        from core import net_ssh
        for site_id in ("lock-test-a", "lock-test-b", "lock-test-fail"):
            net_ssh._transports.pop(site_id, None)
            net_ssh._site_locks.pop(site_id, None)

    def test_two_sites_connect_concurrently_not_serialized(self):
        from core import net_ssh
        site_a = {"id": "lock-test-a", "jump_host": "198.51.100.40",
                  "jump_port": 22, "jump_identity": "id-a"}
        site_b = {"id": "lock-test-b", "jump_host": "198.51.100.41",
                  "jump_port": 22, "jump_identity": "id-b"}
        started_a = threading.Event()
        release_a = threading.Event()

        def fake_create_connection(addr, timeout=None):
            if addr[0] == site_a["jump_host"]:
                started_a.set()
                # Stands in for a black-holed bastion: site A's connect
                # hangs here until the test releases it.
                release_a.wait(timeout=5)
            return mock.Mock()

        with mock.patch.object(net_ssh.socket, "create_connection",
                                side_effect=fake_create_connection), \
             mock.patch.object(net_ssh.paramiko, "Transport", return_value=mock.Mock()), \
             mock.patch("security.identity_manager.get_identity_credentials",
                        return_value=("u", "p", "s")):
            t = threading.Thread(target=net_ssh._transport, args=(site_a,))
            t.start()
            try:
                self.assertTrue(started_a.wait(timeout=5),
                                "site A's connect never started")

                start = time.monotonic()
                net_ssh._transport(site_b)
                elapsed = time.monotonic() - start
                self.assertLess(elapsed, 1.0,
                                "site B waited on site A's lock: locking is not per-site")
            finally:
                release_a.set()
                t.join(timeout=5)

    def test_connect_timeout_raises_instead_of_hanging(self):
        from core import net_ssh
        site = {"id": "lock-test-timeout", "jump_host": "198.51.100.42",
                "jump_port": 22, "jump_identity": "id-t"}
        with mock.patch.object(net_ssh.socket, "create_connection",
                                side_effect=socket.timeout("timed out")) as cc, \
             mock.patch("security.identity_manager.get_identity_credentials",
                        return_value=("u", "p", "s")):
            with self.assertRaises(socket.timeout):
                net_ssh._transport(site)
        cc.assert_called_once_with(("198.51.100.42", 22), timeout=net_ssh.CONNECT_TIMEOUT)
        net_ssh._transports.pop("lock-test-timeout", None)
        net_ssh._site_locks.pop("lock-test-timeout", None)

    def test_failed_connect_closes_the_socket_and_clears_cache(self):
        from core import net_ssh
        site = {"id": "lock-test-fail", "jump_host": "198.51.100.43",
                "jump_port": 22, "jump_identity": "id-f"}
        fake_sock = mock.Mock()
        fake_transport = mock.Mock()
        fake_transport.connect.side_effect = paramiko.AuthenticationException("bad creds")
        with mock.patch.object(net_ssh.socket, "create_connection", return_value=fake_sock), \
             mock.patch.object(net_ssh.paramiko, "Transport", return_value=fake_transport), \
             mock.patch("security.identity_manager.get_identity_credentials",
                        return_value=("u", "wrong-password", "s")):
            with self.assertRaises(paramiko.AuthenticationException):
                net_ssh._transport(site)
        # The socket the module opened is ours to close on a failed connect —
        # paramiko doesn't do it for us once we hand it an already-open sock.
        fake_sock.close.assert_called_once()
        self.assertNotIn("lock-test-fail", net_ssh._transports)


class NoDirectNetmikoImports(unittest.TestCase):
    """Every SSH call site must go through core.net_ssh, otherwise a jump site
    silently bypasses the tunnel and tries to reach the device directly."""

    # site_agent.py runs inside the remote network: it must NOT tunnel.
    ALLOWED = {"core/net_ssh.py", "services/site_agent.py"}

    def test_no_module_imports_connecthandler_from_netmiko(self):
        import pathlib
        import re
        root = pathlib.Path(__file__).resolve().parents[1]
        offenders = []
        for path in root.rglob("*.py"):
            if ".venv" in path.parts or "tests" in path.parts:
                continue
            rel = path.relative_to(root).as_posix()
            if rel in self.ALLOWED:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r"from netmiko import [^\n]*ConnectHandler", text):
                offenders.append(rel)
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
