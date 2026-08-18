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
        # subnets uses 203.0.113.0/24 (RFC 5737 TEST-NET-3), not 192.0.2.0/24:
        # site_manager binds its storage path at first import across the whole
        # suite (see module docstring), so a site declared here is visible to
        # every test file that runs afterwards in the same process. 192.0.2.x
        # is this codebase's default example device range, so declaring it as
        # an owned site subnet would make any later, unrelated test that scans
        # or probes a 192.0.2.x address collide with this jump site.
        site, token = site_manager.create_site(
            "Customer A", "jump", subnets=["203.0.113.0/24"],
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


class IcmpSkippedForJumpSites(unittest.TestCase):
    """Task 4: a bastion carries TCP only, never ICMP. A jump-site device must
    come back 'unknown', never a false 'down'.

    The plan's brief guessed a `ping_monitor.check_device(device) -> "unknown"`
    entry point that does not exist. The real entry point is `_run_cycle()`
    (services/ping_monitor.py:66), which pings every inventory device and
    keeps per-IP state in `_state`; the per-device pinger `_ping_one` (line 59)
    only ever sees a bare IP, so the jump-site guard has to happen in
    `_run_cycle` where the device's Site is still known. This test drives that
    real path instead."""

    def setUp(self):
        from services import ping_monitor
        with ping_monitor._lock:
            ping_monitor._state.clear()
            ping_monitor._last_run = None

    def test_jump_site_device_is_unknown_not_offline(self):
        from services import ping_monitor
        device = {"IP": "192.0.2.5", "Site": "customer-a"}
        site = {"id": "customer-a", "mode": "jump"}
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("collectors.network_scanner._ping") as p:
            ping_monitor._run_cycle()
        p.assert_not_called()
        with ping_monitor._lock:
            state = dict(ping_monitor._state["192.0.2.5"])
        self.assertEqual(state["status"], "unknown")
        self.assertIsNone(state["up"])

    def test_central_site_device_is_still_pinged(self):
        from services import ping_monitor
        device = {"IP": "192.0.2.6", "Site": "central"}
        site = {"id": "central", "mode": "central"}
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("collectors.network_scanner._ping", return_value=True) as p:
            ping_monitor._run_cycle()
        p.assert_called_once_with("192.0.2.6")
        with ping_monitor._lock:
            state = dict(ping_monitor._state["192.0.2.6"])
        self.assertEqual(state["status"], "up")
        self.assertTrue(state["up"])

    def test_summary_reports_unknown_separately_from_down(self):
        from services import ping_monitor
        devices = [{"IP": "192.0.2.5", "Site": "customer-a"},
                  {"IP": "192.0.2.6", "Site": "central"}]

        def fake_get_site(site_id):
            return {"id": "customer-a", "mode": "jump"} if site_id == "customer-a" \
                else {"id": "central", "mode": "central"}

        with mock.patch("services.inventory_manager.get_all_devices", return_value=devices), \
             mock.patch("services.site_manager.get_site", side_effect=fake_get_site), \
             mock.patch("collectors.network_scanner._ping", return_value=False):
            ping_monitor._run_cycle()
        with mock.patch.object(ping_monitor, "get_app_settings", return_value={}):
            status = ping_monitor.get_status()
        self.assertEqual(status["summary"], {"total": 2, "up": 0, "down": 1, "unknown": 1})


class ScanRejectsJumpSites(unittest.TestCase):
    """routers/scan.py: a subnet scan is an ICMP sweep, which cannot cross a
    bastion tunnel either. Calling the endpoint function directly (it is a
    plain callable under the FastAPI decorator) rather than standing up a full
    authenticated TestClient, since the check under test runs before any
    auth-scoped logic."""

    def test_scan_targeting_a_jump_site_subnet_is_rejected(self):
        from routers import scan as scan_router
        site = {"id": "customer-a", "mode": "jump", "subnets": ["192.0.2.0/24"]}
        with mock.patch("services.site_manager.list_sites", return_value=[site]), \
             mock.patch("services.site_manager.get_site", return_value=site):
            req = scan_router.SubnetScanRequest(network="192.0.2.0/24")
            with self.assertRaises(scan_router.HTTPException) as ctx:
                scan_router.start_subnet_scan(req, current_user={"sub": "tester"})
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(ctx.exception.detail,
                         "Sito jump: la scansione ICMP non e' possibile.")

    def test_scan_targeting_a_central_site_subnet_is_unaffected(self):
        from routers import scan as scan_router
        site = {"id": "central", "mode": "central", "subnets": ["192.0.2.0/24"]}
        with mock.patch("services.site_manager.list_sites", return_value=[site]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("routers.scan._run_scan_job"):
            req = scan_router.SubnetScanRequest(network="192.0.2.0/24")
            result = scan_router.start_subnet_scan(req, current_user={"sub": "tester"})
        self.assertEqual(result["status"], "started")


class NetworkMapReportsUnknownForJumpDevices(unittest.TestCase):
    """core/core_engine.py's _enrich_map_with_redundancy used to fold the ping
    monitor's tri-state 'up' into a bare truthy check, turning a jump-site
    device's None (not measurable) into the same 'offline' string as a real
    down. This is the JSON /api/network-map serves to the topology map, so
    the lie would have painted the map with a false down."""

    def test_jump_device_status_is_unknown_not_offline(self):
        from core import core_engine
        data = {"nodes": [{"id": "192.0.2.5", "status": "offline"},
                          {"id": "192.0.2.6", "status": "offline"},
                          {"id": "192.0.2.7", "status": "offline"}],
                "links": []}
        pm_status = {"devices": [
            {"ip": "192.0.2.5", "up": None},   # jump site: not measurable
            {"ip": "192.0.2.6", "up": True},
            {"ip": "192.0.2.7", "up": False},
        ]}
        with mock.patch("services.ping_monitor.get_status", return_value=pm_status), \
             mock.patch("services.inventory_manager.get_detected_versions", return_value={}), \
             mock.patch("redundancy.service.list_groups", return_value=[]), \
             mock.patch("redundancy.service.device_redundancy_badge", return_value=None):
            result = core_engine._enrich_map_with_redundancy(data)
        by_id = {n["id"]: n["status"] for n in result["nodes"]}
        self.assertEqual(by_id["192.0.2.5"], "unknown")
        self.assertEqual(by_id["192.0.2.6"], "online")
        self.assertEqual(by_id["192.0.2.7"], "offline")


class ScopedPingStatusReportsUnknown(unittest.TestCase):
    """routers/settings.py's ping_monitor_status recomputes its own summary
    for a group-scoped (non-superadmin) caller instead of reusing
    ping_monitor.get_status()'s already-correct one. It must not fold a
    jump-site device's tri-state 'unknown' (up=None) into 'down' via a naive
    truthy check — that would reintroduce the false-down this task removes,
    just for non-admin callers."""

    def setUp(self):
        from services import ping_monitor
        with ping_monitor._lock:
            ping_monitor._state.clear()
            ping_monitor._last_run = None

    def test_scoped_user_sees_jump_device_as_unknown_not_down(self):
        from services import ping_monitor
        from routers import settings as settings_router
        device = {"IP": "192.0.2.5", "Site": "customer-a", "Group": "sede-a"}
        site = {"id": "customer-a", "mode": "jump"}
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("collectors.network_scanner._ping") as p:
            ping_monitor._run_cycle()
        p.assert_not_called()

        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("routers.deps.user_group_scope", return_value=["sede-a"]):
            result = settings_router.ping_monitor_status(current_user={"sub": "scoped"})

        self.assertEqual(result["summary"], {"total": 1, "up": 0, "down": 0, "unknown": 1})
        self.assertIsNone(result["devices"][0]["up"])
        self.assertEqual(result["devices"][0]["status"], "unknown")


class FrontendJumpStatusIsNotCollapsedToOffline(unittest.TestCase):
    """static/js/home.js and static/js/topology.js both re-derive an
    online/offline string from the ping-monitor JSON on the client. `d.up`
    is JSON null for a jump-site device, and null is falsy in JS, so the old
    `d.up ? 'online' : 'offline'` silently painted it as offline in the
    Operations Home KPI and the topology map. No JS test runner exists in
    this repo (see tests/test_bugfix_batch.py for the same grep-on-source
    pattern), so this asserts on the fixed source text directly, plus the
    i18n keys and CSS the fix depends on existing in both languages."""

    def setUp(self):
        import os
        from tests.test_helpers_frontend import frontend_source
        self.src = frontend_source()
        self.base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, *parts):
        import os
        with open(os.path.join(self.base, *parts), encoding="utf-8") as f:
            return f.read()

    def test_home_js_no_longer_collapses_null_to_offline(self):
        self.assertIn(
            "d.status === 'unknown' ? 'unknown' : (d.up ? 'online' : 'offline')",
            self._read("static", "js", "home.js"))

    def test_topology_js_no_longer_collapses_null_to_offline(self):
        self.assertIn(
            "d.status === 'unknown' ? 'unknown' : (d.up ? 'online' : 'offline')",
            self._read("static", "js", "topology.js"))

    def test_unknown_status_keys_exist_in_both_languages(self):
        # i18n.js repeats each language's block verbatim (it/en): both copies
        # of every new key must be present, or changeLanguage() would render
        # 'undefined' for whichever language is not currently active.
        self.assertEqual(self.src.count("homeStUnknown:"), 2)
        self.assertEqual(self.src.count("mapStatusUnknown:"), 2)

    def test_status_idle_css_class_exists(self):
        self.assertIn(".status.idle", self._read("static", "css", "dashboard.css"))


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
