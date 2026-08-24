# -*- coding: utf-8 -*-
"""The classification export: the inventory export's machinery, plus serial
and neighbour."""
import csv
import io
import unittest
from unittest import mock

BADGES = {"192.0.2.1": {"type": "stack", "members": [
    {"index": 1, "role": "master", "serial": "SW0000AAAA", "model": "EXAMPLE-48"},
    {"index": 2, "role": "member", "serial": "SW0000BBBB", "model": "EXAMPLE-48"},
]}}

MAP = {
    "nodes": [
        {"id": "192.0.2.1", "label": "switch-01", "group": "ACME",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
        {"id": "192.0.2.2", "label": "switch-02", "group": "BETA",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
        {"id": "discovered_ap-lobby", "label": "ap-lobby", "group": "ACME",
         "status": "discovered", "device_type": "ap", "reported_ip": "192.0.2.50"},
        {"id": "192.0.2.9", "label": "switch-lonely", "group": "ACME",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
    ],
    "links": [
        {"source": "192.0.2.1", "target": "discovered_ap-lobby",
         "local_port": "Gi1/0/1", "remote_port": "Gi0"},
        {"source": "192.0.2.1", "target": "192.0.2.2",
         "local_port": "Gi1/0/2", "remote_port": "Gi1/0/24"},
    ],
}
CATS = {"categories": {}, "assignments": {}}
VERSIONS = {"192.0.2.1": {"serial": "SW0000AAAA", "version": "1.0", "status": "online"}}
AP_ENTRY = {"serial": "FCW0000AAAA", "model": "AIR-EXAMPLE", "wlc_ip": "192.0.2.10",
            "tenant": "ACME", "seen_at": "2026-08-23T10:00:00+00:00"}
AP_STORE = {"ap-lobby": AP_ENTRY}


def _export(query="", user=None, ap_store_data=None):
    from fastapi.testclient import TestClient
    import app_server
    from routers.deps import get_current_user

    # Default store: only "ap-lobby" is known, reported by an ACME controller.
    # A caller can pass its own ap_store_data (e.g. "no controller has
    # reported it" is {}) -- nesting a second mock.patch of the same target
    # around this call would not work, since the one entered last (this
    # function's) is the one active during the request.
    store = AP_STORE if ap_store_data is None else ap_store_data

    app_server.app.dependency_overrides[get_current_user] = \
        lambda: user or {"sub": "tester", "role": "admin"}
    try:
        with mock.patch("core.core_engine.generate_network_map", return_value=MAP), \
             mock.patch("services.inventory_manager.get_device_categories", return_value=CATS), \
             mock.patch("services.inventory_manager.get_all_vendors", return_value={}), \
             mock.patch("services.inventory_manager.get_models", return_value={}), \
             mock.patch("services.inventory_manager.get_detected_versions", return_value=VERSIONS), \
             mock.patch("services.ap_store.read_all", return_value=store), \
             mock.patch("redundancy.service.redundancy_badges_by_ip", return_value=BADGES), \
             mock.patch("routers.catalog.log_audit"):
            client = TestClient(app_server.app)
            return client.get("/api/export/classification" + query,
                              headers={"X-Requested-With": "x"})
    finally:
        app_server.app.dependency_overrides.pop(get_current_user, None)


def _rows(res):
    return list(csv.reader(io.StringIO(res.text)))


class ColumnRegistry(unittest.TestCase):
    def test_defaults_are_a_subset_of_the_registry(self):
        from routers import catalog
        self.assertTrue(set(catalog._DEFAULT_CLASSIFICATION_COLUMNS)
                        <= set(catalog._CLASSIFICATION_COLUMNS))

    def test_every_column_renders_without_raising(self):
        from routers import catalog
        node = {"id": "192.0.2.1", "label": "switch-01", "group": "ACME",
                "status": "online", "device_type": "switch", "subcategory": "",
                "vendor": "cisco", "model": "", "version": "1.0",
                "display_ip": "192.0.2.1", "discovered": False,
                "serial": "SW0000AAAA", "serial_seen_at": ""}
        for _key, (_header, fn) in catalog._CLASSIFICATION_COLUMNS.items():
            fn(node, {})


class ExportRows(unittest.TestCase):
    def test_without_a_neighbour_column_each_device_is_one_row(self):
        rows = _rows(_export("?columns=hostname,ip"))
        self.assertEqual(["Hostname", "IP"], rows[0])
        self.assertEqual(4, len(rows) - 1)

    def test_a_neighbour_column_gives_one_row_per_link(self):
        body = _rows(_export("?columns=hostname,neighbour_device,neighbour_port"))[1:]
        by_host = {}
        for r in body:
            by_host.setdefault(r[0], []).append(r[1:])
        self.assertEqual(2, len(by_host["switch-01"]))
        # switch-01 is this link's `source`, so the neighbour is switch-02 and
        # the port must be `remote_port` -- switch-02's OWN port, not
        # switch-01's `local_port`. Pins the source-side branch of the
        # direction rule (the target-side branch is pinned separately by
        # test_the_port_reported_is_the_neighbour_s_own_port).
        self.assertIn(["switch-02", "Gi1/0/24"], by_host["switch-01"])

    def test_the_port_reported_is_the_neighbour_s_own_port(self):
        """The AP hangs off switch-01 Gi1/0/1 -- that is the port you patch."""
        rows = _rows(_export("?columns=hostname,neighbour_device,neighbour_port"))[1:]
        row = next(r for r in rows if r[0] == "ap-lobby")
        self.assertEqual(["switch-01", "Gi1/0/1"], row[1:])

    def test_the_neighbour_category_filter_keeps_only_matching_links(self):
        rows = _rows(_export("?columns=hostname,neighbour_device"
                             "&neighbour_categories=ap"))[1:]
        by_host = {}
        for r in rows:
            by_host.setdefault(r[0], []).append(r[1])
        # switch-01 links to an AP and to switch-02: only the AP link survives.
        self.assertEqual(["ap-lobby"], by_host["switch-01"])
        # A device whose every neighbour is filtered out keeps its row, empty.
        self.assertEqual([""], by_host["switch-02"])

    def test_member_columns_give_one_row_per_stack_unit(self):
        """A stack answers on one IP but carries a serial per physical unit:
        without these columns the Serial cell of a stacked switch is empty."""
        rows = [r for r in _rows(_export("?columns=hostname,member_serial"))[1:]
                if r[0] == "switch-01"]
        self.assertEqual(["SW0000AAAA", "SW0000BBBB"], [r[1] for r in rows])

    def test_a_device_outside_any_stack_still_exports_one_row(self):
        rows = [r for r in _rows(_export("?columns=hostname,member_serial"))[1:]
                if r[0] == "switch-lonely"]
        self.assertEqual([["switch-lonely", ""]], rows)

    def test_a_device_with_no_links_still_exports_one_row(self):
        """Selecting a column must never shrink the device list."""
        rows = [r for r in _rows(_export("?columns=hostname,neighbour_device"))[1:]
                if r[0] == "switch-lonely"]
        self.assertEqual(1, len(rows))
        self.assertEqual("", rows[0][1])


class SerialResolution(unittest.TestCase):
    def test_an_inventoried_device_resolves_from_scan_data(self):
        rows = _rows(_export("?columns=hostname,serial"))[1:]
        self.assertEqual("SW0000AAAA", next(r for r in rows if r[0] == "switch-01")[1])

    def test_a_discovered_ap_resolves_from_the_ap_store(self):
        rows = _rows(_export("?columns=hostname,serial"))[1:]
        self.assertEqual("FCW0000AAAA", next(r for r in rows if r[0] == "ap-lobby")[1])

    def test_an_ap_no_controller_has_reported_exports_an_empty_serial(self):
        rows = _rows(_export("?columns=hostname,serial", ap_store_data={}))[1:]
        self.assertEqual("", next(r for r in rows if r[0] == "ap-lobby")[1])

    def test_an_ap_reported_by_a_different_tenant_exports_an_empty_serial(self):
        """A name collision across tenants must never leak a serial: 'ap-lobby'
        is ACME's node here, but the store entry belongs to BETA."""
        beta_entry = dict(AP_ENTRY, tenant="BETA")
        rows = _rows(_export("?columns=hostname,serial",
                             ap_store_data={"ap-lobby": beta_entry}))[1:]
        self.assertEqual("", next(r for r in rows if r[0] == "ap-lobby")[1])

    def test_the_seen_at_date_is_available_so_staleness_is_visible(self):
        rows = _rows(_export("?columns=hostname,serial_seen_at"))[1:]
        row = next(r for r in rows if r[0] == "ap-lobby")
        self.assertTrue(row[1].startswith("2026-08-23"))


class Scoping(unittest.TestCase):
    def test_a_scoped_user_never_sees_another_tenant(self):
        # user_group_scope() does not read scope off the current_user dict: it
        # looks the username up in user_manager (see tests/test_rbac_scope.py,
        # where a scoped user is created with `groups=[...]`). This lightweight
        # export test has no such user on record, so -- following the same
        # pattern as tests/test_export_customizable.py's
        # test_the_tenant_scope_still_wins_over_the_query -- the scope itself is
        # mocked directly; the "groups" key on the user dict below mirrors the
        # real record shape but is not what enforces the scoping here.
        with mock.patch("routers.catalog.user_group_scope", return_value={"ACME"}):
            res = _export("?columns=hostname,tenant",
                          user={"sub": "acme-op", "role": "operator", "groups": ["ACME"]})
        self.assertEqual({"ACME"}, {r[1] for r in _rows(res)[1:]})

    def test_an_unknown_column_is_rejected(self):
        self.assertEqual(400, _export("?columns=hostname,not_a_column").status_code)


if __name__ == "__main__":
    unittest.main()
