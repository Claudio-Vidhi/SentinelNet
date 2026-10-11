# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import sqlite3
import tempfile
import unittest

from services import inventory_store as st


def _host(ip, group="acme", **kw):
    row = {f: "" for f in st.HOST_FIELDS}
    row.update({"IP": ip, "Group": group, "Vendor": "cisco", "Probe": "central", "SSH Port": "22"})
    row.update(kw)
    return row


class TestInventoryStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.conn = st.connect(os.path.join(self.dir, "inventory.db"))
        st.write_orgs(self.conn, {"acme": {"description": ""}})
        st.write_locations(self.conn, {"roma": {"org": "acme", "name": "Roma", "role": "branch",
                                                 "subnets": ["10.20.0.0/16"], "probe": "central"}})

    def tearDown(self):
        self.conn.close()

    def test_round_trip_keeps_dict_shape(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1", Location="roma")])
        [row] = st.read_hosts(self.conn, "hosts")
        self.assertEqual(set(row), set(st.HOST_FIELDS))
        self.assertEqual(row["Location"], "roma")

    def test_empty_location_is_null_and_reads_back_empty(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.2", Location="")])
        self.assertEqual(st.read_hosts(self.conn, "hosts")[0]["Location"], "")
        (raw,) = self.conn.execute('SELECT "Location" FROM hosts').fetchone()
        self.assertIsNone(raw)

    def test_read_defaults(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.3", Probe="", **{"SSH Port": ""})])
        row = st.read_hosts(self.conn, "hosts")[0]
        self.assertEqual((row["Probe"], row["SSH Port"]), ("central", "22"))

    def test_unknown_location_is_refused(self):
        with self.assertRaises(sqlite3.IntegrityError):
            st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.4", Location="nowhere")])
        self.assertEqual(st.read_hosts(self.conn, "hosts"), [])

    def test_diff_write_deletes_updates_and_keeps_order(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1"), _host("192.0.2.2"), _host("192.0.2.3")])
        old = st.read_hosts(self.conn, "hosts")
        st.write_hosts(self.conn, "hosts", old, [old[0], dict(old[1], Hostname="sw-02")])
        rows = st.read_hosts(self.conn, "hosts")
        self.assertEqual([r["IP"] for r in rows], ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(rows[1]["Hostname"], "sw-02")

    def test_same_ip_two_orgs_are_two_rows(self):
        st.write_orgs(self.conn, {"acme": {"description": ""}, "beta": {"description": ""}})
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1"), _host("192.0.2.1", group="beta")])
        self.assertEqual(len(st.read_hosts(self.conn, "hosts")), 2)

    def test_duplicate_key_in_new_list_last_wins(self):
        st.write_hosts(self.conn, "hosts", [], [_host("192.0.2.1", Hostname="a"),
                                                _host("192.0.2.1", Hostname="b")])
        self.assertEqual([r["Hostname"] for r in st.read_hosts(self.conn, "hosts")], ["b"])

    def test_decommissioned_table_has_extra_columns(self):
        row = dict(_host("192.0.2.9"), Decommissioned="2026-10-10T00:00:00Z",
                   **{"Decommissioned By": "admin"})
        st.write_hosts(self.conn, "decommissioned_hosts", [], [row])
        self.assertEqual(st.read_hosts(self.conn, "decommissioned_hosts")[0]["Decommissioned By"], "admin")

    def test_location_with_decommissioned_device_cannot_be_deleted(self):
        st.write_hosts(self.conn, "decommissioned_hosts", [],
                       [dict(_host("192.0.2.9", Location="roma"), Decommissioned="x",
                             **{"Decommissioned By": "a"})])
        with self.assertRaises(sqlite3.IntegrityError):
            st.write_locations(self.conn, {})

    def test_orgs_and_locations_round_trip(self):
        st.write_orgs(self.conn, {"acme": {"description": "d", "name": "Acme S.p.A."}})
        self.assertEqual(st.read_orgs(self.conn), {"acme": {"description": "d", "name": "Acme S.p.A."}})
        self.assertEqual(st.read_locations(self.conn)["roma"]["subnets"], ["10.20.0.0/16"])

    def test_org_with_locations_cannot_be_deleted(self):
        with self.assertRaises(sqlite3.IntegrityError):
            st.write_orgs(self.conn, {})


if __name__ == "__main__":
    unittest.main()
