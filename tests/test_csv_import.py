# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import os
import tempfile
import unittest
from unittest.mock import patch

from services import csv_import, inventory_manager as im
from tests.conftest import seed_inventory

LOCS = {"roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": ["10.20.0.0/16"], "probe": "central"},
        "bologna": {"org": "acme", "name": "Bologna", "role": "warehouse", "subnets": ["10.30.0.0/16"], "probe": "central"},
        "nosub": {"org": "acme", "name": "Senza subnet", "role": "other", "subnets": [], "probe": "central"}}


class TestClassify(unittest.TestCase):
    def setUp(self):
        p = patch.object(im, "HOSTS_CSV", os.path.join(tempfile.mkdtemp(), "network_hosts.csv"))
        p.start()
        self.addCleanup(p.stop)
        seed_inventory(orgs=["acme", "beta"], locations=LOCS,
                       hosts=[{"IP": "10.20.1.11", "Group": "acme", "Location": "roma",
                               "Hostname": "rm-sw-02", "Vendor": "hp", "Probe": "central"}],
                       decommissioned=[{"IP": "10.20.1.99", "Group": "acme", "Location": "roma",
                                        "Decommissioned": "x", "Decommissioned By": "a"}])

    def run_(self, text, org="acme", loc="roma", decisions=None, scope=None):
        return csv_import.classify(text, org, loc, decisions or {}, scope)

    def row(self, text, n=0, **kw):
        return self.run_(text, **kw)["rows"][n]

    def test_new_row_goes_to_default_location(self):
        r = self.row("ip,hostname\n10.20.1.1,rm-fw-01\n")
        self.assertEqual((r["status"], r["org"], r["location"]), ("new", "acme", "roma"))

    def test_row_columns_override_default(self):
        self.assertEqual(self.row("ip,sede\n10.30.1.1,Bologna\n")["location"], "bologna")

    def test_missing_ip(self):
        self.assertEqual(self.row("ip,hostname\n,x\n")["status"], "error")

    def test_invalid_ip(self):
        self.assertEqual(self.row("ip\n999.1.1.1\n")["status"], "error")

    def test_unknown_org_is_error(self):
        r = self.row("ip,organizzazione\n10.20.1.1,ghost\n")
        self.assertEqual(r["status"], "error")
        self.assertIn("crea prima", r["reason"])

    def test_org_out_of_scope(self):
        self.assertEqual(self.row("ip\n10.20.1.1\n", scope={"beta"})["status"], "error")

    def test_no_destination_and_no_column(self):
        self.assertEqual(self.row("ip\n10.20.1.1\n", org=None, loc=None)["status"], "error")

    def test_location_of_another_org(self):
        self.assertEqual(self.row("ip,organizzazione,sede\n10.20.1.1,beta,roma\n")["status"], "error")

    def test_unknown_probe(self):
        self.assertEqual(self.row("ip,sonda\n10.20.1.1,ghost\n")["status"], "error")

    def test_duplicate_ip_in_file(self):
        rows = self.run_("ip\n10.20.1.1\n10.20.1.1\n")["rows"]
        self.assertEqual([r["status"] for r in rows], ["new", "error"])
        self.assertEqual(rows[1]["action"], {"kind": "skip"})

    def test_ip_in_other_location_suggests_move(self):
        r = self.row("ip\n10.30.4.20\n")
        self.assertEqual((r["status"], r["action"]), ("error", {"kind": "move", "location": "bologna"}))

    def test_ip_outside_every_subnet_is_only_a_warning(self):
        r = self.row("ip\n192.0.2.50\n")
        self.assertEqual(r["status"], "new")
        self.assertTrue(r["warnings"])

    def test_location_without_subnets_has_no_check(self):
        r = self.row("ip\n192.0.2.50\n", loc="nosub")
        self.assertEqual((r["status"], r["warnings"]), ("new", []))

    def test_decommissioned_ip_is_error_and_rest_imports(self):
        out = csv_import.apply("ip\n10.20.1.99\n10.20.1.1\n", "acme", "roma", {}, None)
        self.assertEqual(out["imported"], ["10.20.1.1"])
        self.assertIn("dismesso", out["preview"]["rows"][0]["reason"])

    def test_update_shows_diff(self):
        r = self.row("ip,hostname\n10.20.1.11,rm-sw-p2\n")
        self.assertEqual(r["status"], "update")
        self.assertEqual(r["changes"]["Hostname"], ["rm-sw-02", "rm-sw-p2"])

    def test_update_without_changes(self):
        self.assertEqual(self.row("ip\n10.20.1.11\n")["changes"], {})

    def test_update_without_vendor_keeps_vendor(self):
        self.assertEqual(self.row("ip,hostname\n10.20.1.11,x\n")["vendor"], "hp")
        csv_import.apply("ip,hostname\n10.20.1.11,x\n", "acme", "roma", {}, None)
        self.assertEqual(im.get_all_devices()[0]["Vendor"], "hp")

    def test_password_change_is_flagged_not_shown(self):
        r = self.row("ip,username,password\n10.20.1.11,u,secret\n")
        self.assertEqual(r["changes"]["Password"], ["", "changed"])
        self.assertNotIn("secret", str(csv_import.public(self.run_("ip,password\n10.20.1.11,secret\n"))))

    def test_decision_skip(self):
        self.assertEqual(self.row("ip\n10.20.1.1\n", decisions={"2": {"skip": True}})["status"], "skipped")

    def test_decision_move(self):
        r = self.row("ip\n10.30.4.20\n", decisions={"2": {"location": "bologna"}})
        self.assertEqual((r["status"], r["location"]), ("new", "bologna"))

    def test_credentials_note_levels(self):
        self.assertIn("proprie", self.row("ip,username,password\n10.20.1.1,u,p\n")["credentials_note"])
        self.assertIn("nessuna", self.row("ip\n10.20.1.1\n")["credentials_note"])
        with patch("core.device_credentials.DEFAULT_USERNAME", "a"), \
             patch("core.device_credentials.DEFAULT_PASSWORD", "b"):
            self.assertIn("globale", self.row("ip\n10.20.1.1\n")["credentials_note"])

    def test_preview_and_apply_agree(self):
        text = "ip,hostname\n10.20.1.1,a\n10.20.1.11,b\n10.30.4.20,c\n"
        pre = self.run_(text)
        out = csv_import.apply(text, "acme", "roma", {}, None)
        self.assertEqual(out["imported"], [r["ip"] for r in pre["rows"] if r["status"] == "new"])
        self.assertEqual(out["updated"], [r["ip"] for r in pre["rows"] if r["status"] == "update"])
        stored = {d["IP"]: d for d in im.get_all_devices()}
        for r in pre["rows"]:
            if r["status"] in ("new", "update"):
                d = stored[r["ip"]]
                self.assertEqual((r["vendor"], r["location"], r["probe"]),
                                 (d["Vendor"], d["Location"], d["Probe"]))

    def test_update_keeps_profile(self):
        seed_inventory(hosts=[{"IP": "10.20.1.12", "Group": "acme", "Location": "roma",
                               "Vendor": "hp", "Profile": "identity:abc", "Probe": "central"}])
        text = "ip,hostname\n10.20.1.12,rm-sw-03\n"
        self.assertEqual(self.row(text)["changes"], {"Hostname": ["", "rm-sw-03"]})
        csv_import.apply(text, "acme", "roma", {}, None)
        d = next(d for d in im.get_all_devices() if d["IP"] == "10.20.1.12")
        self.assertEqual((d["Profile"], d["Hostname"]), ("identity:abc", "rm-sw-03"))

    def test_apply_is_one_write(self):
        text = "ip\n" + "".join(f"10.20.{i // 250 + 10}.{i % 250 + 1}\n" for i in range(2000))
        with patch.object(im, "write_devices", wraps=im.write_devices) as w:
            out = csv_import.apply(text, "acme", "roma", {}, None)
        self.assertEqual((len(out["imported"]), w.call_count), (2000, 1))


if __name__ == "__main__":
    unittest.main()
