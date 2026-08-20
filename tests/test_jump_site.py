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
import shutil
import socket
import subprocess
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
    jump_site_for actually works against the live cache. Isolates hosts.csv
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
            # Re-raised as BastionAuthError: a refused bastion login must not
            # look like the device's own credentials being wrong.
            with self.assertRaises(net_ssh.BastionAuthError):
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


class ManualPingSkipsJumpSites(unittest.TestCase):
    """routers/triage.py's /api/ping-check and /api/ping/{ip}: unlike the
    background ping_monitor loop (Task 4), these two are fired on-demand by
    the operator clicking a button in the Inventory tab. Left unguarded, a
    click on a jump-site device would run a real ICMP probe, get a real
    (meaningless) failure, persist "offline" to detected_versions.json, and
    overwrite the em-dash the row just showed on load with a false down —
    the exact bug the em dash exists to prevent, reintroduced via a button.
    Calling the endpoint functions directly (plain callables under the
    FastAPI decorator), same technique as ScanRejectsJumpSites above, with
    role: 'admin' so user_group_scope short-circuits before touching
    user_manager."""

    ADMIN = {"sub": "tester", "role": "admin"}

    def test_ping_check_reports_unmeasurable_for_a_jump_device(self):
        from routers import triage as triage_router
        device = {"IP": "192.0.2.5", "Site": "customer-a", "Group": "Generale"}
        site = {"id": "customer-a", "mode": "jump"}
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("services.inventory_manager.get_detected_versions", return_value={}), \
             mock.patch("services.inventory_manager.update_version_inventory") as uvi, \
             mock.patch("collectors.network_scanner._ping") as p:
            result = triage_router.ping_check(
                triage_router.PingCheckRequest(group="all"), current_user=self.ADMIN)
        p.assert_not_called()
        self.assertIsNone(result["results"]["192.0.2.5"])
        uvi.assert_called_once_with("192.0.2.5", "cisco", "Non Rilevata", "unknown")

    def test_ping_check_still_pings_a_central_device(self):
        from routers import triage as triage_router
        device = {"IP": "192.0.2.6", "Site": "central", "Group": "Generale"}
        site = {"id": "central", "mode": "central"}
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("services.inventory_manager.get_detected_versions", return_value={}), \
             mock.patch("services.inventory_manager.update_version_inventory") as uvi, \
             mock.patch("collectors.network_scanner._ping", return_value=True) as p:
            result = triage_router.ping_check(
                triage_router.PingCheckRequest(group="all"), current_user=self.ADMIN)
        p.assert_called_once_with("192.0.2.6")
        self.assertTrue(result["results"]["192.0.2.6"])
        uvi.assert_called_once_with("192.0.2.6", "cisco", "Non Rilevata", "online")

    def test_ping_single_reports_unmeasurable_for_a_jump_device(self):
        from routers import triage as triage_router
        device = {"IP": "192.0.2.5", "Site": "customer-a", "Group": "Generale"}
        site = {"id": "customer-a", "mode": "jump"}
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("services.inventory_manager.get_detected_versions", return_value={}), \
             mock.patch("services.inventory_manager.update_version_inventory") as uvi, \
             mock.patch("collectors.network_scanner._ping") as p:
            result = triage_router.ping_single("192.0.2.5", current_user=self.ADMIN)
        p.assert_not_called()
        self.assertIsNone(result["reachable"])
        uvi.assert_called_once_with("192.0.2.5", "cisco", "Non Rilevata", "unknown")

    def test_ping_single_still_pings_a_central_device(self):
        from routers import triage as triage_router
        device = {"IP": "192.0.2.6", "Site": "central", "Group": "Generale"}
        site = {"id": "central", "mode": "central"}
        with mock.patch("services.inventory_manager.get_all_devices", return_value=[device]), \
             mock.patch("services.site_manager.get_site", return_value=site), \
             mock.patch("services.inventory_manager.get_detected_versions", return_value={}), \
             mock.patch("services.inventory_manager.update_version_inventory") as uvi, \
             mock.patch("collectors.network_scanner._ping", return_value=False) as p:
            result = triage_router.ping_single("192.0.2.6", current_user=self.ADMIN)
        p.assert_called_once_with("192.0.2.6")
        self.assertFalse(result["reachable"])
        uvi.assert_called_once_with("192.0.2.6", "cisco", "Non Rilevata", "offline")


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
        # The original one-liner mapped the monitor's tri-state; it is now a
        # block, because 'unknown' additionally must not overwrite a status the
        # SSH triage established (that erased a real result with a non-result).
        compact = " ".join(self._read("static", "js", "home.js").split())
        marker = "pm.devices.forEach(d => {"
        block = compact[compact.index(marker):]
        block = block[:block.index("});")]
        self.assertIn("d.up ? 'online' : 'offline'", block)
        self.assertNotIn("d.up ? 'online' : 'offline' ; }", block)
        # A monitor 'unknown' is only ever written when nothing is known yet.
        self.assertIn("if (!globalVersions[d.ip].status) "
                      "globalVersions[d.ip].status = 'unknown';", block)

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


class FleetOnelineBayIsNotPaintedDownForUnmeasurable(unittest.TestCase):
    """A fourth consumer in home.js, found on re-review: renderFleetOneline's
    per-tenant bay computed its worst status with
    `st === 'offline' || st === 'unknown' -> down`. That line predates this
    task and was harmless while 'unknown' never reached globalVersions[...]
    .status; home.js:47 (fixed earlier this round) now writes exactly that
    value for a jump-site device, so a tenant reached only through a bastion
    painted its whole bay red, contradicting the correctly-fixed KPI row and
    attention table on the same page."""

    def setUp(self):
        import os
        self.base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, *parts):
        import os
        with open(os.path.join(self.base, *parts), encoding="utf-8") as f:
            return f.read()

    def test_bucket_counting_has_its_own_unknown_bucket(self):
        # Source-text check for the bucket split; the worst-of-bay `state`
        # function itself is covered behaviourally below (real execution, not
        # text matching -- a wrong operator here reads fine as text).
        home_src = self._read("static", "js", "home.js")
        self.assertIn("else if (st === 'unknown') b.unknown++;", home_src)
        self.assertNotIn("st === 'offline' || st === 'unknown'", home_src)

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_bay_state_treats_unknown_as_its_own_state(self):
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        harness = os.path.join(base, "tests", "js", "test_home_fleet_state.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=base)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)

    def test_bay_sub_label_does_not_claim_all_up_when_unmeasurable(self):
        # The line right below the down/unknown split: without its own
        # branch, an unknown-only bay would fall through to "all up" -- the
        # opposite lie the coordinator warned about.
        home_src = self._read("static", "js", "home.js")
        self.assertIn("b.unknown ? escapeHtml(`${b.unknown} ${L.homeBayUnknown}`)", home_src)

    def test_unknown_bay_i18n_keys_exist_in_both_languages(self):
        from tests.test_helpers_frontend import frontend_source
        src = frontend_source()
        self.assertEqual(src.count("homeBayUnknown:"), 2)
        self.assertEqual(src.count("homeLegUnknown:"), 2)

    def test_legend_and_css_declare_the_fourth_state(self):
        # "the legend is the contract of symbols" (home.js/dashboard.html's
        # own comment): a bar state with no legend entry breaks that contract.
        html = self._read("templates", "dashboard.html")
        self.assertIn('data-state="unknown"', html)
        self.assertIn('data-i18n="homeLegUnknown"', html)
        css = self._read("static", "css", "dashboard.css")
        self.assertIn('.oneline-bay[data-state="unknown"] .oneline-sw', css)


class HomeKpiTilesDoNotCollapseTheThirdState(unittest.TestCase):
    """The last consumer in static/js/home.js: the three Operations Home KPI
    tiles. homeStatusInfo and renderFleetOneline were fixed earlier, but the
    tiles above them still counted every non-'online' device as attention and
    divided by the whole fleet, so a customer entirely behind one bastion read
    "Online: 0", "0% of the fleet", "Needs attention: 40 of 40" forever, while
    the bays right below said "not measurable".

    Source-text assertions, like the sibling frontend classes above: the loop
    lives inside the async loadHome() and cannot be sliced out for the node
    harness the way renderFleetOneline's state() can."""

    def setUp(self):
        import os
        self.base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, *parts):
        import os
        with open(os.path.join(self.base, *parts), encoding="utf-8") as f:
            return f.read()

    def test_not_measurable_devices_leave_both_counters(self):
        # Asserted on the shape of the guard, not its exact formatting: the
        # invariant is that such a device increments notMeasurable and returns
        # before either counter, whether the block is one line or five.
        compact = " ".join(self._read("static", "js", "home.js").split())
        guard = "if (d.icmp_reachable === false || scan.status === 'unknown') {"
        self.assertIn(guard, compact, "the not-measurable guard is gone from loadHome")
        start = compact.index(guard)
        block = compact[start:compact.index("if (scan.status === 'online')", start)]
        self.assertIn("notMeasurable++", block)
        self.assertIn("return;", block)
        self.assertNotIn("online++", block)
        self.assertNotIn("attention.push", block)

    def test_percentage_denominator_excludes_what_cannot_be_measured(self):
        src = self._read("static", "js", "home.js")
        self.assertIn("const measurable = devs.length - notMeasurable;", src)
        # The old denominator was the whole fleet; it must be gone, not merely
        # shadowed somewhere further down.
        self.assertNotIn("Math.round((online / devs.length) * 100)", src)
        self.assertIn("Math.round((online / measurable) * 100)", src)

    def test_a_fully_unmeasurable_fleet_shows_the_state_not_a_zero(self):
        # measurable === 0: there is no percentage to give, so the tile shows
        # the state itself (existing key, no new vocabulary).
        src = self._read("static", "js", "home.js")
        self.assertIn(": L.homeStUnknown);", src)

    def test_attention_subline_counts_out_of_the_measurable_fleet(self):
        src = self._read("static", "js", "home.js")
        self.assertIn("setText('homeStatAttention', `${L.homeOutOf} ${measurable}`)", src)


class PingMonitorPanelRendersTheThirdBucket(unittest.TestCase):
    """routers/settings.py and services/ping_monitor.py both emit
    summary.unknown, and static/js/settings.js is that summary's only
    consumer: rendering just total/up/down made every bastion-reached device
    disappear from the panel with no explanation (50 devices, 35 behind a
    bastion, panel reading "Devices: 50 - Up: 10 - Down: 5")."""

    def setUp(self):
        import os
        self.base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _read(self, *parts):
        import os
        with open(os.path.join(self.base, *parts), encoding="utf-8") as f:
            return f.read()

    def test_summary_panel_renders_unknown(self):
        src = self._read("static", "js", "settings.js")
        self.assertIn("${s.unknown || 0}", src)
        self.assertIn("L.invKpiUnknownLabel", src)

    def test_summary_fallback_object_carries_the_third_bucket(self):
        src = self._read("static", "js", "settings.js")
        self.assertIn("{ total: 0, up: 0, down: 0, unknown: 0 }", src)

    def test_the_reused_label_key_exists_in_both_languages(self):
        from tests.test_helpers_frontend import frontend_source
        self.assertEqual(frontend_source().count("invKpiUnknownLabel:"), 2)


class JumpLimitsRestNoLongerClaimsAWlcRestApi(unittest.TestCase):
    """A previous ruling removed the WLC half of this claim from
    docs/remote-sites.md — there is no WLC REST path in this codebase, WLC is
    CLI-only and already works through the tunnel — but the fix never reached
    the string the operator actually reads in the site-creation panel."""

    def test_both_locales_and_the_template_fallback_drop_wlc(self):
        import os
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for parts in (("static", "js", "i18n.js"), ("templates", "dashboard.html")):
            with open(os.path.join(base, *parts), encoding="utf-8") as f:
                text = f.read()
            for line in text.splitlines():
                if "jumpLimitsRest" in line:
                    self.assertNotIn("WLC", line, f"{parts[-1]}: {line.strip()}")

    def test_the_key_is_still_present_in_both_languages(self):
        from tests.test_helpers_frontend import frontend_source
        self.assertEqual(frontend_source().count("jumpLimitsRest:"), 2)


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
            # Two idioms reach netmiko.ConnectHandler, and the second one is
            # what core/net_ssh.py itself demonstrates internally (`import
            # netmiko` + `netmiko.ConnectHandler(...)`), so a future module
            # copied from it bypassed the tunnel with this guard still green.
            if re.search(r"from netmiko import [^\n]*ConnectHandler"
                         r"|netmiko\.ConnectHandler", text):
                offenders.append(rel)
        self.assertEqual(offenders, [])


class JumpSiteApi(unittest.TestCase):
    """Task 5: POST /api/sites accepts mode='jump' and the three bastion
    fields, and GET /api/sites never leaks a secret for it (a jump site has
    no token, unlike an agent site)."""

    @classmethod
    def setUpClass(cls):
        # Same authenticated-client mechanism as RemoteSiteE2E.setUpClass
        # (tests/test_remote_site.py:41): same app import, same login. Copied
        # rather than inventing a second way to authenticate.
        from fastapi.testclient import TestClient
        import app_server
        from security import user_manager
        import bcrypt
        cls.client = TestClient(app_server.app)
        admin = "e2e_jump_admin"
        admin_pw = "adminpw12345"
        users = user_manager.get_users()
        pw_hash = bcrypt.hashpw(admin_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        users[admin] = {"hashed_password": pw_hash, "role": "admin", "disabled": False}
        user_manager._save_users(users)
        r = cls.client.post("/api/auth/login",
                            json={"username": admin, "password": admin_pw})
        assert r.status_code == 200, r.text
        cls.admin_h = {"Authorization": "Bearer " + r.json()["access_token"]}

    def test_post_sites_accepts_jump_mode(self):
        # 203.0.113.0/24 (RFC 5737 TEST-NET-3), not 192.0.2.0/24: site_manager
        # binds its storage path at first import across the whole suite (see
        # JumpSiteModel's docstring above), so this site is visible to every
        # test file that runs afterwards in the same process. 192.0.2.x is
        # this codebase's default example device range, so an owned jump-site
        # subnet there would make later unrelated scan/ping tests probing
        # 192.0.2.x collide with it (409 "scansione ICMP non e' possibile").
        r = self.client.post("/api/sites", headers=self.admin_h, json={
            "name": "Jump API Test Site", "mode": "jump", "jump_host": "198.51.100.11",
            "jump_port": 22, "jump_identity": "id-1", "subnets": ["203.0.113.0/24"]})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()["site"]
        self.assertEqual(body["mode"], "jump")
        self.assertNotIn("token_hash", body)
        self.assertIsNone(r.json()["token"])

    def test_get_sites_round_trips_jump_fields_without_a_secret(self):
        # Same 203.0.113.0/24 reasoning as above; a distinct name/subnet from
        # the other test in this class so the two don't collide in the shared
        # storage (see the comment on test_post_sites_accepts_jump_mode).
        r = self.client.post("/api/sites", headers=self.admin_h, json={
            "name": "Jump GET Roundtrip Site", "mode": "jump",
            "jump_host": "198.51.100.12", "jump_port": 2222,
            "jump_identity": "id-roundtrip", "subnets": ["203.0.113.0/25"]})
        self.assertEqual(r.status_code, 200, r.text)
        site_id = r.json()["site"]["id"]

        r = self.client.get("/api/sites", headers=self.admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        site = next(s for s in r.json()["sites"] if s["id"] == site_id)

        # The bastion fields round-trip exactly as sent.
        self.assertEqual(site["jump_host"], "198.51.100.12")
        self.assertEqual(site["jump_port"], 2222)
        self.assertEqual(site["jump_identity"], "id-roundtrip")

        # jump_identity is a reference (an id string resolved server-side at
        # connect time, see core/net_ssh.py) — never a credential itself, and
        # no key on the site object may carry one either.
        forbidden_keys = {"token_hash", "password", "enable_secret",
                          "enable secret", "username"}
        self.assertEqual(forbidden_keys & set(site.keys()), set())


class JumpChannelIsClosedWhenNetmikoFails(unittest.TestCase):
    """The direct-tcpip channel lives on the shared, long-lived per-site
    transport. `with ConnectHandler(...)` at the call sites cannot reclaim it
    when the netmiko constructor raises, because the context manager never
    binds. Rotated bastion-site credentials plus a scheduled collector would
    then pile one channel per device per cycle onto the transport until the
    process restarts."""

    JUMP_SITE = {"id": "customer-a", "mode": "jump", "jump_host": "198.51.100.10",
                 "jump_port": 22, "jump_identity": "id-1"}
    DEVICE = {"ip": "192.0.2.5", "site": "customer-a"}

    def test_channel_is_closed_and_the_error_propagates(self):
        from core import net_ssh
        chan = mock.MagicMock()
        boom = Exception("Authentication failed")
        with mock.patch.object(net_ssh, "jump_channel", return_value=chan), \
             mock.patch.object(net_ssh, "_netmiko_connect", side_effect=boom), \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=self.DEVICE), \
             mock.patch("services.site_manager.get_site", return_value=self.JUMP_SITE):
            with self.assertRaises(Exception) as ctx:
                net_ssh.ConnectHandler(device_type="cisco_ios", host="192.0.2.5",
                                       username="u", password="p")
        self.assertIs(ctx.exception, boom)   # propagated unchanged, not wrapped
        chan.close.assert_called_once_with()

    def test_channel_is_left_open_when_netmiko_succeeds(self):
        # The live session owns the channel; closing it here would kill it.
        from core import net_ssh
        chan = mock.MagicMock()
        with mock.patch.object(net_ssh, "jump_channel", return_value=chan), \
             mock.patch.object(net_ssh, "_netmiko_connect"), \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=self.DEVICE), \
             mock.patch("services.site_manager.get_site", return_value=self.JUMP_SITE):
            net_ssh.ConnectHandler(device_type="cisco_ios", host="192.0.2.5",
                                   username="u", password="p")
        chan.close.assert_not_called()


class ProvisioningNamesTheSiteExplicitly(unittest.TestCase):
    """A device being provisioned (day 0) is not in hosts.csv yet, so
    core.net_ssh.jump_site_for cannot resolve its site from the inventory and
    the push would be dialled directly — a connect timeout for a switch that
    the bastion could have reached. Both push_via_ssh entry points therefore
    take an explicit site, forwarded to ConnectHandler as site_id; the
    inventory lookup stays the default when no site is named."""

    JUMP_SITE = {"id": "customer-a", "mode": "jump", "jump_host": "198.51.100.10",
                 "jump_port": 22, "jump_identity": "id-1"}

    def test_switch_push_tunnels_when_the_site_is_named(self):
        from services import switch_provisioner
        chan = object()
        with mock.patch("core.net_ssh.jump_channel", return_value=chan) as jc, \
             mock.patch("core.net_ssh._netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=None), \
             mock.patch("services.site_manager.get_site", return_value=self.JUMP_SITE):
            switch_provisioner.push_via_ssh(
                host="192.0.2.20", username="u", password="p", secret="s",
                config_text="hostname switch-01", site="customer-a")
        jc.assert_called_once_with(self.JUMP_SITE, "192.0.2.20", 22)
        self.assertIs(nm.call_args.kwargs["sock"], chan)

    def test_switch_push_without_a_site_is_untouched(self):
        from services import switch_provisioner
        with mock.patch("core.net_ssh.jump_channel") as jc, \
             mock.patch("core.net_ssh._netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=None):
            switch_provisioner.push_via_ssh(
                host="192.0.2.21", username="u", password="p", secret="s",
                config_text="hostname switch-01")
        jc.assert_not_called()
        self.assertNotIn("sock", nm.call_args.kwargs)

    def test_fortigate_push_tunnels_when_the_site_is_named(self):
        from services import fortigate_provisioner
        chan = object()
        with mock.patch("core.net_ssh.jump_channel", return_value=chan) as jc, \
             mock.patch("core.net_ssh._netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=None), \
             mock.patch("services.site_manager.get_site", return_value=self.JUMP_SITE):
            fortigate_provisioner.push_via_ssh(
                host="192.0.2.22", username="u", password="p",
                config_text="config system global", site="customer-a")
        jc.assert_called_once_with(self.JUMP_SITE, "192.0.2.22", 22)
        self.assertIs(nm.call_args.kwargs["sock"], chan)

    def test_fortigate_push_without_a_site_is_untouched(self):
        from services import fortigate_provisioner
        with mock.patch("core.net_ssh.jump_channel") as jc, \
             mock.patch("core.net_ssh._netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=None):
            fortigate_provisioner.push_via_ssh(
                host="192.0.2.23", username="u", password="p",
                config_text="config system global")
        jc.assert_not_called()
        self.assertNotIn("sock", nm.call_args.kwargs)

    def test_a_named_site_that_is_not_jump_mode_is_not_tunnelled(self):
        from services import switch_provisioner
        with mock.patch("core.net_ssh.jump_channel") as jc, \
             mock.patch("core.net_ssh._netmiko_connect") as nm, \
             mock.patch("services.inventory_manager.get_device_by_ip", return_value=None), \
             mock.patch("services.site_manager.get_site",
                        return_value={"id": "central", "mode": "central"}):
            switch_provisioner.push_via_ssh(
                host="192.0.2.24", username="u", password="p", secret="s",
                config_text="hostname switch-01", site="central")
        jc.assert_not_called()
        self.assertNotIn("sock", nm.call_args.kwargs)


class CliPathsSkipTheDirectPrecheckForJumpSites(unittest.TestCase):
    """Every CLI entry point gates on core_engine.is_reachable, a raw socket
    connect from the central to the device. For a jump site that route does
    not exist by definition — the session is tunnelled through the bastion by
    core.net_ssh — so the gate always failed and netmiko was never reached:
    no backup, no inventory, and a false "offline" persisted from a probe of a
    path the product never intended to use.

    The predicate is site_manager.has_direct_path (renamed from
    is_reachable_by_icmp: it always meant "the central has a direct IP path to
    this site's devices", which is what both the ICMP and the TCP callers
    need).

    ConnectHandler is made to fail with an authentication error rather than
    succeed: that keeps the test away from the whole driver/backup pipeline
    while still proving the tunnel layer was reached, and it lands in the
    "auth_failed" branch, so any "offline" write would come from the
    pre-check and nowhere else.
    """

    JUMP_SITE = {"id": "customer-a", "mode": "jump", "jump_host": "198.51.100.10",
                 "jump_port": 22, "jump_identity": "id-1"}
    CENTRAL_SITE = {"id": "central", "mode": "central"}

    def _device(self, ip, site):
        return {"IP": ip, "Vendor": "cisco", "Site": site, "Group": "Generale"}

    def test_triage_of_a_jump_device_reaches_netmiko(self):
        from core import core_engine
        device = self._device("192.0.2.10", "customer-a")
        with mock.patch("services.site_manager.get_site", return_value=self.JUMP_SITE),              mock.patch.object(core_engine, "is_reachable") as reach,              mock.patch.object(core_engine, "get_device_credentials",
                               return_value=("u", "p", "s")),              mock.patch.object(core_engine, "update_version_inventory") as upd,              mock.patch.object(core_engine, "ConnectHandler",
                               side_effect=Exception("Authentication failed")) as ch:
            res = core_engine.run_backup_and_triage(device)
        reach.assert_not_called()
        ch.assert_called_once()
        self.assertEqual(ch.call_args.kwargs["host"], "192.0.2.10")
        self.assertEqual(res["status"], "error")
        self.assertNotIn("offline", [c.args[3] for c in upd.call_args_list])

    def test_triage_of_a_central_device_is_still_prechecked(self):
        from core import core_engine
        device = self._device("192.0.2.11", "central")
        with mock.patch("services.site_manager.get_site", return_value=self.CENTRAL_SITE),              mock.patch.object(core_engine, "is_reachable", return_value=False) as reach,              mock.patch.object(core_engine, "update_version_inventory") as upd,              mock.patch.object(core_engine, "ConnectHandler") as ch:
            res = core_engine.run_backup_and_triage(device)
        reach.assert_called_once_with("192.0.2.11", 22)
        ch.assert_not_called()
        self.assertEqual(res["status"], "error")
        self.assertEqual(upd.call_args.args[3], "offline")

    def test_bulk_command_on_a_jump_device_reaches_netmiko(self):
        from core import core_engine
        device = self._device("192.0.2.12", "customer-a")
        with mock.patch("services.site_manager.get_site", return_value=self.JUMP_SITE),              mock.patch.object(core_engine, "is_reachable") as reach,              mock.patch.object(core_engine, "get_device_credentials",
                               return_value=("u", "p", "s")),              mock.patch.object(core_engine, "ConnectHandler",
                               side_effect=Exception("Authentication failed")) as ch:
            res = core_engine.run_bulk_command(device, ["show version"])
        reach.assert_not_called()
        ch.assert_called_once()
        self.assertEqual(res["status"], "error")

    def test_bulk_command_on_a_central_device_is_still_prechecked(self):
        from core import core_engine
        device = self._device("192.0.2.13", "central")
        with mock.patch("services.site_manager.get_site", return_value=self.CENTRAL_SITE),              mock.patch.object(core_engine, "is_reachable", return_value=False) as reach,              mock.patch.object(core_engine, "ConnectHandler") as ch:
            res = core_engine.run_bulk_command(device, ["show version"])
        reach.assert_called_once_with("192.0.2.13", 22)
        ch.assert_not_called()
        self.assertEqual(res["status"], "error")

    def test_linux_poller_on_a_jump_device_reaches_netmiko(self):
        from observability.ingesters import linux_poller
        from core import core_engine
        device = {"IP": "192.0.2.14", "Vendor": "linux", "Site": "customer-a",
                  "Group": "Generale"}
        with mock.patch("services.site_manager.get_site", return_value=self.JUMP_SITE),              mock.patch.object(core_engine, "is_reachable") as reach,              mock.patch.object(core_engine, "get_device_credentials",
                               return_value=("u", "p", "s")),              mock.patch("core.net_ssh.ConnectHandler",
                        side_effect=Exception("Authentication failed")) as ch:
            out = linux_poller._poll_device(device)
        reach.assert_not_called()
        ch.assert_called_once()
        self.assertEqual(out, [])

    def test_linux_poller_on_a_central_device_is_still_prechecked(self):
        from observability.ingesters import linux_poller
        from core import core_engine
        device = {"IP": "192.0.2.15", "Vendor": "linux", "Site": "central",
                  "Group": "Generale"}
        with mock.patch("services.site_manager.get_site", return_value=self.CENTRAL_SITE),              mock.patch.object(core_engine, "is_reachable", return_value=False) as reach,              mock.patch("core.net_ssh.ConnectHandler") as ch:
            out = linux_poller._poll_device(device)
        reach.assert_called_once_with("192.0.2.15", 22)
        ch.assert_not_called()
        self.assertEqual(out, [])


if __name__ == "__main__":
    unittest.main()


class _FakeWebSocket:
    """Minimal WebSocket double: ws_terminal only accepts, sends and closes on
    the failure paths exercised here."""

    def __init__(self, token, send_exc=None):
        self.query_params = {"token": token}
        self.sent = []
        self.closed = False
        self._send_exc = send_exc

    async def accept(self):
        pass

    async def send_text(self, text):
        self.sent.append(text)
        # Only the failure report blows up: the browser is still there for the
        # banner, and leaves while paramiko is dialling.
        if self._send_exc is not None and "Errore Connessione" in text:
            raise self._send_exc

    async def close(self, code=1000):
        self.closed = True


class WsTerminalThroughBastion(unittest.TestCase):
    """The web terminal drives paramiko directly instead of netmiko, so it does
    not get core.net_ssh's tunnel for free."""

    DEVICE = {"IP": "192.0.2.20", "Group": "Generale", "Site": "customer-a"}

    def _run(self, send_exc=None, site=object()):
        import asyncio
        from routers import commands
        from core import core_engine
        from security import user_manager

        otp = "otp-test"
        commands._ws_tokens[otp] = ("admin-user", time.time())
        ws = _FakeWebSocket(otp, send_exc)
        client = mock.MagicMock()
        client.connect.side_effect = Exception("boom")
        chan = object()
        with mock.patch.object(inventory_manager, "get_all_devices",
                               return_value=[self.DEVICE]),\
             mock.patch.object(user_manager, "get_role", return_value="admin"),\
             mock.patch.object(user_manager, "is_disabled", return_value=False),\
             mock.patch.object(core_engine, "get_device_credentials",
                               return_value=("u", "p", "s")),\
             mock.patch.object(core_engine, "get_cli_transport",
                               return_value=("ssh", 22)),\
             mock.patch.object(commands, "_prepare_host_keys"),\
             mock.patch.object(commands.paramiko, "SSHClient", return_value=client),\
             mock.patch("core.net_ssh.jump_site_for", return_value=site),\
             mock.patch("core.net_ssh.jump_channel", return_value=chan) as jc:
            asyncio.run(commands.ws_terminal(ws, self.DEVICE["IP"]))
        return client, chan, jc, ws

    def test_terminal_to_a_jump_device_goes_through_the_bastion_channel(self):
        client, chan, jc, _ws = self._run()
        jc.assert_called_once()
        self.assertIs(client.connect.call_args.kwargs["sock"], chan)

    def test_terminal_to_a_central_device_still_dials_direct(self):
        client, _chan, jc, _ws = self._run(site=None)
        jc.assert_not_called()
        self.assertIsNone(client.connect.call_args.kwargs["sock"])

    def test_a_browser_that_left_does_not_raise_out_of_the_endpoint(self):
        from fastapi import WebSocketDisconnect
        # No assertion needed beyond _run() returning: before the fix the
        # WebSocketDisconnect escaped and uvicorn logged an ASGI traceback.
        self._run(send_exc=WebSocketDisconnect(code=1006))


class JumpSiteDeviceIdentity(unittest.TestCase):
    """A jump site declares two credentials: one for the bastion, one as the
    default for the devices behind it."""

    def test_device_identity_is_stored_and_clearable(self):
        site, _ = site_manager.create_site(
            "Customer DI", "jump", jump_host="198.51.100.11",
            jump_identity="id-bastion", device_identity="id-devices")
        self.assertEqual(site["device_identity"], "id-devices")
        site_manager.update_site(site["id"], device_identity="")
        self.assertEqual(site_manager.get_site(site["id"])["device_identity"], "")

    def test_device_identity_is_optional(self):
        site, _ = site_manager.create_site(
            "Customer DI2", "jump", jump_host="198.51.100.12",
            jump_identity="id-bastion")
        self.assertEqual(site["device_identity"], "")

    def test_renaming_a_jump_site_keeps_the_device_identity(self):
        # update_site revalidates the whole jump block on every edit; a rename
        # must not drop the field the way an explicit None would.
        site, _ = site_manager.create_site(
            "Customer DI3", "jump", jump_host="198.51.100.13",
            jump_identity="id-bastion", device_identity="id-devices")
        site_manager.update_site(site["id"], name="Customer DI3 rinominata")
        self.assertEqual(site_manager.get_site(site["id"])["device_identity"], "id-devices")


class DeviceCredentialFallback(unittest.TestCase):
    """Profile 'default' on a device behind a bastion must not mean the global
    admin account: that is this installation's credential, sent to somebody
    else's device."""

    SITE = {"id": "customer-a", "mode": "jump", "device_identity": "id-devices"}

    def _creds(self, device, site=None):
        from core import core_engine
        from security import identity_manager
        with mock.patch("services.site_manager.get_site",
                        return_value=self.SITE if site is None else site),\
             mock.patch.object(identity_manager, "get_identity_credentials",
                               side_effect=lambda i: ("site-user", "site-pw", "site-secret")
                               if i == "id-devices" else ("row-user", "row-pw", "row-secret")):
            return core_engine.get_device_credentials(device)

    def test_profile_default_uses_the_site_identity(self):
        creds = self._creds({"IP": "192.0.2.30", "Site": "customer-a", "Profile": "default"})
        self.assertEqual(creds, ("site-user", "site-pw", "site-secret"))

    def test_the_device_own_identity_still_wins(self):
        creds = self._creds({"IP": "192.0.2.31", "Site": "customer-a",
                             "Profile": "identity:id-row"})
        self.assertEqual(creds, ("row-user", "row-pw", "row-secret"))

    def test_a_site_without_a_default_identity_falls_back_to_the_globals(self):
        from core import core_engine
        creds = self._creds({"IP": "192.0.2.32", "Site": "customer-a", "Profile": "default"},
                            site={"id": "customer-a", "mode": "jump", "device_identity": ""})
        self.assertEqual(creds, (core_engine.DEFAULT_USERNAME,
                                 core_engine.DEFAULT_PASSWORD,
                                 core_engine.DEFAULT_SECRET))

    def test_an_empty_username_on_a_custom_row_uses_the_site_identity(self):
        creds = self._creds({"IP": "192.0.2.33", "Site": "customer-a",
                             "Profile": "custom", "Username": "", "Password": ""})
        self.assertEqual(creds, ("site-user", "site-pw", "site-secret"))


class BastionAuthIsReportedSeparately(unittest.TestCase):
    SITE = {"id": "customer-a", "mode": "jump", "jump_host": "198.51.100.10",
            "jump_port": 22, "jump_identity": "id-1"}

    def test_a_refused_bastion_login_is_not_a_device_credential_problem(self):
        from core import net_ssh
        from security import identity_manager
        tr = mock.MagicMock()
        tr.connect.side_effect = paramiko.AuthenticationException("bad password")
        with mock.patch.object(identity_manager, "get_identity_credentials",
                               return_value=("bastion-user", "pw", "")),\
             mock.patch.object(net_ssh.socket, "create_connection"),\
             mock.patch.object(net_ssh.paramiko, "Transport", return_value=tr):
            with self.assertRaises(net_ssh.BastionAuthError) as ctx:
                net_ssh._transport(dict(self.SITE))
        msg = str(ctx.exception)
        self.assertIn("bastion-user", msg)
        self.assertIn("198.51.100.10", msg)
        self.assertNotIn("customer-a", net_ssh._transports)

    def test_probe_bastion_ignores_the_cached_transport(self):
        # Testing a credential against a transport opened with the PREVIOUS one
        # would always answer "fine".
        from core import net_ssh
        cached = mock.MagicMock()
        cached.is_active.return_value = True
        net_ssh._transports["customer-a"] = cached
        try:
            with mock.patch.object(net_ssh, "_dial") as dial:
                net_ssh.probe_bastion(dict(self.SITE))
            dial.assert_called_once()
            dial.return_value.close.assert_called_once()
        finally:
            net_ssh._transports.pop("customer-a", None)

    def test_triage_marks_a_refused_bastion_as_an_auth_failure(self):
        from core import core_engine, net_ssh
        self.assertEqual(core_engine._failure_status(net_ssh.BastionAuthError("x")),
                         "auth_failed")
        self.assertEqual(core_engine._failure_status(OSError("timed out")), "offline")


class DeviceSiteIsEditableFromInventory(unittest.TestCase):
    """The site decides HOW a device is reached (direct, agent, bastion), so it
    has to be changeable after import, not only at creation time."""

    # None is a meaningful value for `site` here ("the site does not
    # exist"), so the default cannot be None.
    _DEFAULT = object()

    def _call(self, ip, new_site, devices, site=_DEFAULT):
        from routers import inventory as inv_router
        if site is self._DEFAULT:
            site = {"id": new_site, "mode": "jump"}
        with mock.patch("services.site_manager.get_site",
                        return_value=site),\
             mock.patch.object(inventory_manager, "get_all_devices", return_value=devices),\
             mock.patch.object(inventory_manager, "safe_write_hosts_csv") as write,\
             mock.patch("routers.inventory.assert_group_allowed"),\
             mock.patch("routers.inventory.log_audit"):
            res = inv_router.reassign_device_site(
                inv_router.DeviceSiteSchema(ip=ip, new_site=new_site),
                {"sub": "admin", "role": "admin"})
        return res, write

    def test_moving_a_device_rewrites_only_its_site(self):
        devices = [{"IP": "192.0.2.40", "Group": "Generale", "Site": "central", "Vendor": "cisco"},
                   {"IP": "192.0.2.41", "Group": "Generale", "Site": "central", "Vendor": "cisco"}]
        res, write = self._call("192.0.2.40", "customer-a", devices)
        self.assertEqual(res["status"], "success")
        write.assert_called_once()
        self.assertEqual(devices[0]["Site"], "customer-a")
        self.assertEqual(devices[1]["Site"], "central")   # untouched
        self.assertEqual(devices[0]["Group"], "Generale")  # tenant untouched

    def test_an_unknown_site_is_refused_before_any_write(self):
        from fastapi import HTTPException
        devices = [{"IP": "192.0.2.42", "Group": "Generale", "Site": "central"}]
        with self.assertRaises(HTTPException) as ctx:
            self._call("192.0.2.42", "does-not-exist", devices, site=None)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(devices[0]["Site"], "central")

    def test_an_unknown_device_is_a_404(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as ctx:
            self._call("192.0.2.99", "customer-a", [])
        self.assertEqual(ctx.exception.status_code, 404)


class ChangingTheBastionIdentityTakesEffect(unittest.TestCase):
    """Editing the bastion login must apply to the next connection.

    Reported from the field: the operator set a site's credential after
    creating the site and 'Test bastion' still authenticated as the original
    user. Two causes, both here: the row dropdown edited the DEVICE identity
    while the bastion one was reachable only in the create-site form, and a
    live transport authenticated with the old credential was reused.
    """

    def test_invalidate_site_drops_and_closes_the_transport(self):
        from core import net_ssh
        cached = mock.MagicMock()
        cached.is_active.return_value = True
        net_ssh._transports["customer-a"] = cached
        try:
            net_ssh.invalidate_site("customer-a")
            self.assertNotIn("customer-a", net_ssh._transports)
            cached.close.assert_called_once()
        finally:
            net_ssh._transports.pop("customer-a", None)

    def test_invalidate_site_survives_an_already_dead_transport(self):
        from core import net_ssh
        cached = mock.MagicMock()
        cached.close.side_effect = OSError("socket already gone")
        net_ssh._transports["customer-a"] = cached
        try:
            net_ssh.invalidate_site("customer-a")  # must not raise
            self.assertNotIn("customer-a", net_ssh._transports)
        finally:
            net_ssh._transports.pop("customer-a", None)

    def test_invalidate_site_on_an_unknown_site_is_a_no_op(self):
        from core import net_ssh
        net_ssh.invalidate_site("never-dialled")

    def test_updating_the_identity_invalidates_the_cached_transport(self):
        from routers import sites as sites_router
        payload = sites_router.SiteUpdateSchema(id="customer-a",
                                                jump_identity="new-identity")
        with mock.patch.object(sites_router.site_manager, "update_site",
                               return_value=True),\
             mock.patch.object(sites_router, "log_audit"),\
             mock.patch("core.net_ssh.invalidate_site") as inv:
            sites_router.update_site_ep(payload, {"sub": "tester"})
        inv.assert_called_once_with("customer-a")

    def test_updating_only_the_device_identity_leaves_the_transport_alone(self):
        """The bastion session is unaffected by the devices' own credential."""
        from routers import sites as sites_router
        payload = sites_router.SiteUpdateSchema(id="customer-a",
                                                device_identity="new-identity")
        with mock.patch.object(sites_router.site_manager, "update_site",
                               return_value=True),\
             mock.patch.object(sites_router, "log_audit"),\
             mock.patch("core.net_ssh.invalidate_site") as inv:
            sites_router.update_site_ep(payload, {"sub": "tester"})
        inv.assert_not_called()


class TheBastionIdentityIsEditableAfterCreation(unittest.TestCase):
    """The settings row must expose BOTH identities, distinguishably.

    A jump site requires a bastion identity, so its select carries no empty
    option; the device one keeps its "global credentials" choice.
    """

    def setUp(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "static", "js",
                            "settings.js")
        with open(path, encoding="utf-8") as fh:
            self.js = fh.read()

    def test_the_row_renders_a_bastion_identity_select(self):
        self.assertIn('data-action="set-site-jump-identity"', self.js)
        self.assertIn("s.jump_identity", self.js)

    def test_the_bastion_select_is_bound(self):
        self.assertIn("setSiteJumpIdentity(jump.dataset.siteId", self.js)

    def test_the_handler_sends_jump_identity(self):
        self.assertIn("jump_identity: identityId", self.js)

    def test_both_selects_are_labelled(self):
        for key in ("lblIdentityBastionShort", "lblIdentityDeviceShort"):
            self.assertIn(key, self.js)

    def test_a_deleted_identity_is_shown_as_missing(self):
        # Otherwise the select falls back to displaying the first identity,
        # which reads as configured.
        self.assertIn("jumpKnown", self.js)
        self.assertIn("optMissingIdentity", self.js)

    def test_the_labels_exist_in_both_languages(self):
        import os
        path = os.path.join(os.path.dirname(__file__), "..", "static", "js",
                            "i18n.js")
        with open(path, encoding="utf-8") as fh:
            i18n = fh.read()
        for key in ("lblIdentityBastionShort", "lblIdentityDeviceShort",
                    "optMissingIdentity"):
            self.assertEqual(i18n.count(key + ":"), 2, key)
