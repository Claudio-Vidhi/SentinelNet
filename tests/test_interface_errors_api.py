# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""/api/interface-errors: window verdicts from the SNMP samples, tenant
scoping, the on-demand read (SNMP first, SSH fallback) and a smoke test that
the routes are mounted behind authentication."""

import asyncio
import json
import os
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_ifaceerrapi_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from fastapi import HTTPException  # noqa: E402

from core import db  # noqa: E402
from routers import interface_errors as api  # noqa: E402

ADMIN = {"sub": "admin", "role": "admin"}
VIEWER_A = {"sub": "viewer", "role": "viewer"}
DEVICES = [
    {"IP": "192.0.2.10", "Group": "sede-a", "Hostname": "switch-01", "Vendor": "cisco"},
    {"IP": "198.51.100.10", "Group": "sede-b", "Hostname": "switch-02", "Vendor": "cisco"},
]


def _run(coro):
    return asyncio.run(coro)


def _scope(user):
    return None if user["role"] == "admin" else {"sede-a"}


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()

    def setUp(self):
        conn = db.get_observability_connection()
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM iface_counter_reads")
        conn.commit()
        conn.close()
        for p in (patch("services.inventory_manager.get_all_devices", return_value=DEVICES),
                  patch("routers.deps.user_group_scope", side_effect=_scope),
                  patch("routers.observability.user_group_scope", side_effect=_scope)):
            p.start()
            self.addCleanup(p.stop)

    def _sample(self, ts, device_ip, tenant, interface, **metrics):
        conn = db.get_observability_connection()
        conn.execute(
            """INSERT INTO events (ts, ingested_ts, tenant, source, event_type,
                                   entity_type, entity_id, device_ip, interface,
                                   attrs_json, metrics_json, dedup_key)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ts, ts, tenant, "snmp", "interface.state", "interface",
             f"{device_ip}:{interface}", device_ip, interface, "{}",
             json.dumps(metrics), f"t:{device_ip}:{interface}:{ts}"))
        conn.commit()
        conn.close()


class TestWindow(_Base):

    def test_growing_crc_is_erroring_and_ranked_first(self):
        now = int(time.time())
        self._sample(now - 600, "192.0.2.10", "sede-a", "Gi1/0/2", crc=5)
        self._sample(now - 60, "192.0.2.10", "sede-a", "Gi1/0/2", crc=5)
        self._sample(now - 600, "192.0.2.10", "sede-a", "Gi1/0/1", crc=10, in_errors=10)
        self._sample(now - 60, "192.0.2.10", "sede-a", "Gi1/0/1", crc=40, in_errors=40)
        out = _run(api.list_interface_errors(window="1h", current_user=ADMIN))

        first = out["ports"][0]
        self.assertEqual((first["interface"], first["status"], first["worst_class"]),
                         ("Gi1/0/1", "erroring", "physical"))
        self.assertEqual(first["hostname"], "switch-01")
        self.assertEqual(first["window"]["delta"]["crc"], 30)
        self.assertEqual(out["counts"]["clean"], 1)

    def test_a_scoped_user_sees_only_their_tenant(self):
        now = int(time.time())
        for ip, tenant in (("192.0.2.10", "sede-a"), ("198.51.100.10", "sede-b")):
            self._sample(now - 600, ip, tenant, "Gi1/0/1", crc=1)
            self._sample(now - 60, ip, tenant, "Gi1/0/1", crc=2)
        out = _run(api.list_interface_errors(window="1h", current_user=VIEWER_A))
        self.assertEqual({p["tenant"] for p in out["ports"]}, {"sede-a"})

    def test_a_device_outside_the_scope_is_refused(self):
        with patch("routers.deps.assert_group_allowed",
                   side_effect=HTTPException(status_code=403, detail="no")):
            with self.assertRaises(HTTPException):
                _run(api.list_interface_errors(window="1h", device="198.51.100.10",
                                               current_user=VIEWER_A))

    def test_port_lookup_matches_short_and_long_names(self):
        now = int(time.time())
        self._sample(now - 600, "192.0.2.10", "sede-a", "Gi1/0/1", crc=0)
        self._sample(now - 60, "192.0.2.10", "sede-a", "Gi1/0/1", crc=3)
        out = _run(api.port_interface_errors(device="192.0.2.10", port="GigabitEthernet1/0/1",
                                             window="1h", current_user=ADMIN))
        self.assertTrue(out["known"])
        self.assertEqual(out["port"]["errors"], 3)

    def test_ports_without_counters_are_not_listed(self):
        now = int(time.time())
        self._sample(now - 600, "192.0.2.10", "sede-a", "port1")
        self._sample(now - 60, "192.0.2.10", "sede-a", "port1")
        out = _run(api.list_interface_errors(window="1h", current_user=ADMIN))
        self.assertEqual(out["ports"], [])


class TestReadNow(_Base):

    def _read(self, community="", snmp=({},), cli=None):
        written = []
        with patch("core.db.enqueue_write", side_effect=lambda sql, p: written.append(p)), \
             patch("routers.interface_errors.asyncio.sleep", new=AsyncMock()), \
             patch("routers.interface_errors.log_audit"), \
             patch("security.snmp_defaults.resolve_snmp_community", return_value=community), \
             patch("observability.ingesters.snmp_poller.read_error_counters",
                   new=AsyncMock(side_effect=list(snmp))), \
             patch("collectors.iface_counters_cli.read_twice",
                   return_value=cli or {"error": "nope"}):
            out = _run(api.read_interface_errors(
                api.InterfaceErrorsReadSchema(device="192.0.2.10"), current_user=ADMIN))
        return out, written

    def test_snmp_is_used_when_it_answers(self):
        out, written = self._read(community="public",
                                  snmp=[{"Gi1/0/1": {"crc": 1}}, {"Gi1/0/1": {"crc": 6}}])
        self.assertEqual(out["source"], "snmp")
        self.assertEqual(out["ports"][0]["delta"], {"crc": 5})
        self.assertEqual(written[0][1:4], ("sede-a", "192.0.2.10", "snmp"))

    def test_ssh_is_the_fallback_when_snmp_is_silent(self):
        out, _ = self._read(community="public", snmp=[{}],
                            cli={"before": {"Gi1/0/1": {"crc": 0}},
                                 "after": {"Gi1/0/1": {"crc": 0}}, "elapsed_s": 10})
        self.assertEqual(out["source"], "cli")
        self.assertEqual(out["ports"][0]["status"], "clean")

    def test_both_failing_is_a_502_that_says_why(self):
        with self.assertRaises(HTTPException) as ctx:
            self._read(community="public", snmp=[{}], cli={"error": "Connessione SSH fallita: x"})
        self.assertEqual(ctx.exception.status_code, 502)
        self.assertIn("SNMP non ha risposto", ctx.exception.detail)

    def test_a_read_shows_up_in_the_list(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO iface_counter_reads(ts, tenant, device_ip, source, interval_s, result_json) "
            "VALUES (?, 'sede-a', '192.0.2.10', 'cli', 10, ?)",
            (int(time.time()), json.dumps({"GigabitEthernet1/0/3": {
                "counters": {"late_collisions": 2}, "delta": {"late_collisions": 2},
                "status": "erroring", "worst_class": "duplex", "errors": 2, "discards": 0}})))
        conn.commit()
        conn.close()
        out = _run(api.list_interface_errors(window="1h", current_user=ADMIN))
        self.assertEqual(out["ports"][0]["status"], "erroring")
        self.assertEqual(out["ports"][0]["last_read"]["source"], "cli")


class TestStoredReadIsJudgedAgain(_Base):

    def test_a_read_saved_as_erroring_with_garbage_counters_is_clean_now(self):
        conn = db.get_observability_connection()
        conn.execute(
            "INSERT INTO iface_counter_reads(ts, tenant, device_ip, source, interval_s, result_json) "
            "VALUES (?, 'sede-a', '192.0.2.10', 'snmp', 10, ?)",
            (int(time.time()), json.dumps({"Gi0/0": {
                "counters": {"in_errors": 0, "crc": 3067064320},
                "delta": {"in_errors": 0, "crc": 3067064320},
                "status": "erroring", "worst_class": "physical", "errors": 3067064320}})))
        conn.commit()
        conn.close()
        out = _run(api.list_interface_errors(window="1h", current_user=ADMIN))
        self.assertEqual(out["ports"][0]["status"], "clean")
        self.assertEqual(out["ports"][0]["errors"], 0)


class TestMounted(unittest.TestCase):
    """The handler bodies above run; this proves the routes are mounted and
    guarded (401 without a session)."""

    def test_routes_require_authentication(self):
        from fastapi.testclient import TestClient
        import app_server
        client = TestClient(app_server.app)
        self.assertEqual(client.get("/api/interface-errors").status_code, 401)
        self.assertEqual(client.get("/api/interface-errors/port?device=x&port=y").status_code, 401)
        self.assertIn(client.post("/api/interface-errors/read", json={"device": "x"}).status_code,
                      (401, 403))


if __name__ == "__main__":
    unittest.main()
