# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Device history: inventory writes leave added/changed/removed events, scoped
by tenant, with no credential ever written to the log."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers import deps
from routers.deps import CSRF_HEADER
from security import crypto_vault, security_manager
from services import device_history, inventory_manager


def _row(ip, group="tenant-a", **kw):
    r = {"IP": ip, "Vendor": "cisco", "Profile": "ios", "Group": group, "Probe": "central",
         "Username": "admin", "Password": crypto_vault.encrypt_password("pw1")}
    r.update(kw)
    return r


class DeviceHistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "device_history.jsonl")
        self.csv = os.path.join(self.tmp, "network_hosts.csv")
        # The suite's shared audit.log must not leak rebuilt events in here.
        patches = [patch.object(device_history, "_path", lambda: self.log),
                   patch.object(device_history, "_audit_lines", lambda: []),
                   patch.object(inventory_manager, "get_hosts_csv", lambda: self.csv)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_backfill_rebuilds_the_audit_past(self):
        lines = [
            (100.0, "Dispositivo '192.0.2.1' (vendor: 'Cisco', gruppo: 'tenant-a') aggiunto/aggiornato dall'utente 'admin'."),
            (200.0, "Dispositivo '192.0.2.1' spostato dalla sede 'central' alla sede 'branch' dall'utente 'op'."),
            (300.0, "Dispositivo '192.0.2.1' (vendor: 'cisco', gruppo: 'tenant-a', sede: 'branch') aggiunto/aggiornato dall'utente 'admin'. [client dichiarato: mcp]"),
            (400.0, "Dispositivo '192.0.2.1' spostato dal gruppo 'tenant-a' al gruppo 'tenant-b' dall'utente 'admin'."),
            (500.0, "Dispositivo '192.0.2.1' eliminato dall'inventario dall'utente 'admin'."),
            (600.0, "Dispositivo scoperto 'sw-x' promosso a gestito (IP 192.0.2.9, vendor hpe, sede central) da 'op'."),
            (700.0, "Triage e backup completati con successo per dispositivo '192.0.2.9' (Firmware: '1.0')."),
            (900.0, "Dispositivo '192.0.2.5' (vendor: 'cisco', gruppo: 'tenant-a') aggiunto/aggiornato dall'utente 'admin'."),
        ]
        inventory = [_row("192.0.2.9"), _row("198.51.100.7", group="tenant-b")]
        live = [{"event": "changed", "ts": 800.0, "tenant": "tenant-a", "device": {"IP": "192.0.2.9"}}]
        ev = device_history.backfill_from_audit(lines, inventory, live)
        got = [(e["ts"], e["event"], e["tenant"], e["device"]["IP"], e["source"]) for e in ev]
        self.assertEqual(got, [
            (100.0, "added", "tenant-a", "192.0.2.1", "audit"),
            (200.0, "changed", "tenant-a", "192.0.2.1", "audit"),
            (300.0, "changed", "tenant-a", "192.0.2.1", "audit"),
            (400.0, "removed", "tenant-a", "192.0.2.1", "audit"),
            (400.0, "added", "tenant-b", "192.0.2.1", "audit"),
            (500.0, "removed", "tenant-b", "192.0.2.1", "audit"),   # tenant from the move
            (600.0, "added", "tenant-a", "192.0.2.9", "audit"),
            # the line at 900 is after the first live event: live owns it
            (100.0, "added", "tenant-b", "198.51.100.7", "baseline"),  # never seen arriving
        ])
        self.assertEqual(ev[1]["changes"], {"Probe": ["central", "branch"]})
        self.assertEqual(ev[2]["changes"], {})   # same vendor/site: fields unknown
        self.assertEqual(ev[0]["actor"], "admin")

    def test_backfill_reads_both_reassign_wordings(self):
        # The move line says "sede" in logs written before the rename and
        # "sonda" since: the rebuilt history must understand both.
        for word in ("sede", "sonda"):
            line = (1.0, f"Dispositivo '192.0.2.1' spostato dalla {word} 'central' "
                         f"alla {word} 'branch' dall'utente 'op'.")
            ev = device_history.backfill_from_audit([line], [_row("192.0.2.1")], [])
            moved = [e for e in ev if e["source"] == "audit"]
            self.assertEqual(moved[0]["changes"], {"Probe": ["central", "branch"]}, word)

    def test_backfill_merges_once_in_time_order(self):
        with open(self.log, "w", encoding="utf-8") as fh:
            fh.write('{"event":"added","ts":5000,"tenant":"tenant-a","device":{"IP":"192.0.2.3"},"id":"x","actor":"a"}\n')
            fh.write("{torn\n")
        lines = [(1000.0, "Dispositivo '192.0.2.2' (vendor: 'cisco', gruppo: 'tenant-a') aggiunto/aggiornato dall'utente 'admin'.")]
        with patch.object(device_history, "_audit_lines", lambda: lines):
            device_history._backfilled.discard(self.log)
            self.assertEqual([e["device"]["IP"] for e in device_history.events()], ["192.0.2.3", "192.0.2.2"])
            device_history._backfilled.discard(self.log)
            self.assertEqual(len(device_history.events()), 2)  # a second pass adds nothing

    def test_diff_added_changed_removed(self):
        old = [_row("192.0.2.1"), _row("192.0.2.2")]
        # Same password re-encrypted: not a change. Site moved: a change.
        new = [_row("192.0.2.1", Probe="branch"), _row("192.0.2.3")]
        ev = {e["device"]["IP"]: e for e in device_history.diff(old, new)}
        self.assertEqual(ev["192.0.2.1"]["event"], "changed")
        self.assertEqual(ev["192.0.2.1"]["changes"], {"Probe": ["central", "branch"]})
        self.assertEqual(ev["192.0.2.2"]["event"], "removed")
        self.assertEqual(ev["192.0.2.3"]["event"], "added")

    def test_password_change_logged_without_value(self):
        old = [_row("192.0.2.1")]
        new = [_row("192.0.2.1", Password=crypto_vault.encrypt_password("pw2"))]
        (e,) = device_history.diff(old, new)
        self.assertEqual(e["changes"], {"Password": ["set", "set"]})

    def test_write_records_and_never_stores_secrets(self):
        inventory_manager.safe_write_hosts_csv([_row("192.0.2.1"), _row("198.51.100.1", group="tenant-b")])
        inventory_manager.safe_write_hosts_csv([_row("198.51.100.1", group="tenant-b")])
        with open(self.log, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn("gAAAA", raw)  # Fernet token prefix
        a = device_history.events({"tenant-a"})
        self.assertEqual([e["event"] for e in a], ["removed", "added"])
        self.assertEqual(len(device_history.events({"tenant-b"})), 1)
        self.assertEqual(len(device_history.events(ip="192.0.2.1")), 2)


class DeviceHistoryRoutesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "device_history.jsonl")
        patches = [
            patch.object(device_history, "_path", lambda: self.log),
            patch.object(device_history, "_ensure_backfill", lambda: None),
            patch.object(deps.user_manager, "effective_tabs", lambda u: None),
            patch.object(deps.user_manager, "get_user_groups", lambda u: ["tenant-a"]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        app_server.app.dependency_overrides[deps.get_current_user] = \
            lambda: {"sub": "op1", "role": "operator"}
        self.addCleanup(app_server.app.dependency_overrides.clear)
        self.client = TestClient(app_server.app)
        device_history.record([], [_row("192.0.2.1"), _row("198.51.100.1", group="tenant-b")])

    def test_list_is_scoped(self):
        r = self.client.get("/api/device-history")
        self.assertEqual(r.status_code, 200)
        self.assertEqual({e["tenant"] for e in r.json()["events"]}, {"tenant-a"})
        self.assertEqual(self.client.get("/api/device-history?tenant=tenant-b").status_code, 403)

    def test_config_out_of_scope_and_missing(self):
        other = device_history.events({"tenant-b"})[0]["id"]
        self.assertEqual(self.client.get(f"/api/device-history/{other}/config").status_code, 403)
        mine = device_history.events({"tenant-a"})[0]["id"]
        self.assertEqual(self.client.get(f"/api/device-history/{mine}/config").status_code, 404)

    def test_actor_comes_from_token(self):
        seen = {}
        token = security_manager.create_access_token({"sub": "op1"})
        with patch.object(inventory_manager, "delete_device",
                          lambda ip: seen.setdefault("actor", security_manager.current_actor())), \
             patch("routers.inventory.assert_device_allowed", lambda u, ip: {}):
            r = self.client.post("/api/delete-device", json={"ip": "192.0.2.1"},
                                 headers={"Authorization": f"Bearer {token}", CSRF_HEADER: "1"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(seen["actor"], "op1")


if __name__ == "__main__":
    unittest.main()
