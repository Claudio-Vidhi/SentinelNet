# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Observed data for the Blueprint checks: offline always, live on demand."""
import os
import tempfile
import unittest
from unittest.mock import patch

from services import blueprint_observe, fortigate_service, inventory_manager, probe_manager
from tests.conftest import seed_inventory

LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.0.0/16"],
                   "probe": "central", "gateway": "10.10.0.1"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": ["10.20.0.0/16"],
                 "probe": "central", "gateway": "10.20.0.1"}}
VIEW = {"locations": LOCS, "links": {}}
ROW = {"network": "10.20.0.0/16", "interface": "to-roma", "gateway": "", "from_backup": False}


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_obs_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json"))):
            p.start()
            self.addCleanup(p.stop)
        seed_inventory(hosts=[
            {"IP": "10.10.0.1", "Group": "acme", "Vendor": "fortinet", "Location": "milano"},
            {"IP": "10.20.0.1", "Group": "acme", "Vendor": "cisco", "Location": "roma"},
            {"IP": "10.30.0.1", "Group": "beta", "Vendor": "cisco"}], locations=LOCS)
        p = patch("collectors.mac_history.search_arp", return_value=[
            {"ip": "10.30.1.5", "source_ip": "10.20.0.1", "mac": "aa:bb:cc:dd:ee:ff"}])
        self.search_arp = p.start()
        self.addCleanup(p.stop)


class TestObserve(_Base):
    def test_live_routes_and_tunnels_one_gateway_failing(self):
        def collect(dev):
            if dev["IP"] == "10.20.0.1":
                return {"device_ip": dev["IP"], "error": "timeout"}
            return {"device_ip": dev["IP"], "rows": [dict(ROW, device="x", vrf="")]}
        tunnels = {"source": "api", "data": [{"name": "to-roma", "rgwy": "198.51.100.7", "proxyid": [
            {"status": "up", "proxy_dst": [{"subnet": "10.20.0.0/255.255.0.0"}]}]}]}
        with patch("services.route_table.collect_for", side_effect=collect), \
                patch.object(fortigate_service, "get_vpn_tunnels", return_value=tunnels):
            summary = blueprint_observe.observe("acme", VIEW)
        self.assertEqual(summary["gateways"]["10.10.0.1"],
                         {"routes": 1, "routes_error": "", "tunnels": 1, "tunnels_error": ""})
        self.assertEqual(summary["gateways"]["10.20.0.1"]["routes_error"], "timeout")
        with patch("services.route_table.routes_from_backup", return_value=None):
            observed = blueprint_observe.gather("acme", VIEW)
        self.assertEqual(observed["tunnels"]["10.10.0.1"]["tunnels"],
                         [{"name": "to-roma", "remote_gw": "198.51.100.7", "up": True, "dst": ["10.20.0.0/16"]}])
        self.assertEqual(observed["routes"]["10.10.0.1"]["from_backup"], False)
        self.assertEqual(observed["observed_at"], summary["at"])

    def test_tunnel_error_is_kept(self):
        with patch("services.route_table.collect_for", return_value={"rows": []}), \
                patch.object(fortigate_service, "get_vpn_tunnels",
                             side_effect=fortigate_service.FortiGateError("401")):
            summary = blueprint_observe.observe("acme", VIEW)
        self.assertEqual(summary["gateways"]["10.10.0.1"]["tunnels_error"], "401")


class TestGather(_Base):
    def test_offline_sources_only_the_org(self):
        backup = {"rows": [dict(ROW, from_backup=True)]}
        with patch("services.route_table.routes_from_backup", return_value=backup):
            observed = blueprint_observe.gather("acme", VIEW)
        self.assertEqual(sorted(d["IP"] for d in observed["devices"]), ["10.10.0.1", "10.20.0.1"])
        self.assertEqual(observed["arp"], [{"ip": "10.30.1.5", "source_ip": "10.20.0.1"}])
        self.assertEqual(self.search_arp.call_args.kwargs["tenants"], ["acme"])
        self.assertEqual(observed["routes"]["10.10.0.1"]["from_backup"], True)
        self.assertEqual((observed["tunnels"], observed["observed_at"]), ({}, None))
