# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint checks: plain dicts in, findings out, no network."""
import unittest

from services import blueprint_checks as bc
from services import blueprint_model as bm


def loc(name, role="branch", subnets=(), gateway=""):
    return {"org": "acme", "name": name, "role": role, "subnets": list(subnets), "probe": "central",
            "gateway": gateway}


def link(a, b, kind="vpn"):
    a, b = sorted((a, b))
    return {bm.link_id(a, b, kind): {"org": "acme", "a": a, "b": b, "kind": kind, "note": ""}}


def dev(ip, location, vendor="cisco"):
    return {"IP": ip, "Location": location, "Vendor": vendor, "Group": "acme", "Hostname": ""}


def obs(**kw):
    base = {"devices": [], "arp": [], "routes": {}, "tunnels": {}, "observed_at": None}
    base.update(kw)
    return base


def view(locations, links=None):
    return {"locations": locations, "links": links or {}}


def found(findings, code):
    return [f for f in findings if f["code"] == code]


class _Proposals(unittest.TestCase):
    def assertProposalsApply(self, v, findings):
        for f in findings:
            if f["proposal"]:
                bm.apply_ops("acme", v["locations"], v["links"], f["proposal"], {"central"})


class TestModelChecks(_Proposals):
    def test_overlap(self):
        v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"]), "roma": loc("Roma", subnets=["10.10.5.0/24"])})
        self.assertEqual(len(found(bc.run(v, obs()), "subnet_overlap")), 1)
        v["locations"]["roma"]["subnets"] = ["10.20.0.0/16"]
        self.assertEqual(found(bc.run(v, obs()), "subnet_overlap"), [])

    def test_no_subnets(self):
        v = view({"roma": loc("Roma")})
        self.assertEqual([f["subject"] for f in found(bc.run(v, obs()), "location_no_subnets")],
                         [{"location": "roma"}])

    def test_isolated_branch_proposes_a_vpn_to_the_hq(self):
        v = view({"milano": loc("Milano", "hq"), "roma": loc("Roma"), "torino": loc("Torino"),
                  "napoli": loc("Napoli")}, {**link("milano", "roma"), **link("roma", "torino")})
        fs = found(bc.run(v, obs()), "location_isolated")
        self.assertEqual([f["subject"]["location"] for f in fs], ["napoli"])   # torino reaches via roma
        self.assertEqual(fs[0]["proposal"], [{"op": "add_link", "a": "milano", "b": "napoli", "kind": "vpn", "note": ""}])
        self.assertProposalsApply(v, fs)

    def test_gateway_missing_one_candidate_or_several(self):
        v = view({"roma": loc("Roma", subnets=["10.20.0.0/16"])})
        one = obs(devices=[dev("10.20.0.1", "roma", "fortinet"), dev("10.20.0.9", "roma", "hp")])
        f = found(bc.run(v, one), "location_no_gateway")[0]
        self.assertEqual(f["proposal"], [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"}])
        self.assertProposalsApply(v, [f])
        two = obs(devices=[dev("10.20.0.1", "roma", "fortinet"), dev("10.20.0.2", "roma", "cisco")])
        f = found(bc.run(v, two), "location_no_gateway")[0]
        self.assertIsNone(f["proposal"])
        self.assertEqual(f["params"]["candidates"], ["10.20.0.1", "10.20.0.2"])

    def test_gateway_not_in_location(self):
        v = view({"roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")})
        self.assertEqual(len(found(bc.run(v, obs(devices=[dev("10.20.0.1", "milano")])), "gateway_not_in_location")), 1)
        self.assertEqual(found(bc.run(v, obs(devices=[dev("10.20.0.1", "roma")])), "gateway_not_in_location"), [])


class TestSubnetChecks(_Proposals):
    def setUp(self):
        self.v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"], gateway="10.10.0.1"),
                       "roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")})

    def test_device_outside_its_subnets(self):
        fs = found(bc.run(self.v, obs(devices=[dev("10.20.9.9", "milano")])), "device_outside_subnets")
        self.assertEqual((fs[0]["params"]["owner"], fs[0]["proposal"]), ("Roma", None))
        fs = found(bc.run(self.v, obs(devices=[dev("10.30.1.5", "milano")])), "device_outside_subnets")
        self.assertEqual(fs[0]["proposal"], [{"op": "add_subnet", "id": "milano", "subnet": "10.30.1.0/24"}])
        self.assertProposalsApply(self.v, fs)
        self.assertEqual(found(bc.run(self.v, obs(devices=[dev("10.10.1.5", "milano")])), "device_outside_subnets"), [])

    def test_arp_uncovered_private_only_and_both_proposals_apply(self):
        arp = [{"ip": "10.30.1.5", "source_ip": "10.20.0.1"}, {"ip": "10.30.1.6", "source_ip": "10.20.0.1"},
               {"ip": "10.31.0.7", "source_ip": "10.20.0.1"},
               {"ip": "203.0.113.9", "source_ip": "10.20.0.1"},      # ISP side: never proposed
               {"ip": "10.20.4.4", "source_ip": "10.20.0.1"},        # covered
               {"ip": "10.40.0.1", "source_ip": "192.0.2.77"}]       # not a gateway
        fs = found(bc.run(self.v, obs(arp=arp)), "arp_uncovered")
        self.assertEqual([(f["params"]["subnet"], f["params"]["count"]) for f in fs],
                         [("10.30.1.0/24", 2), ("10.31.0.0/24", 1)])
        ops = [op for f in fs for op in f["proposal"]]
        locs, _, _ = bm.apply_ops("acme", self.v["locations"], {}, ops, {"central"})
        self.assertEqual(locs["roma"]["subnets"], ["10.20.0.0/16", "10.30.1.0/24", "10.31.0.0/24"])

    def test_subnet_unused(self):
        fs = found(bc.run(self.v, obs(devices=[dev("10.10.0.1", "milano")])), "subnet_unused")
        self.assertEqual([f["params"]["subnet"] for f in fs], ["10.20.0.0/16"])

    def test_sorted_by_severity(self):
        v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"]), "roma": loc("Roma", subnets=["10.10.5.0/24"])})
        sev = [f["severity"] for f in bc.run(v, obs())]
        self.assertEqual(sev, sorted(sev, key=lambda s: bc.SEVERITY_ORDER[s]))


def routes(*rows, backup=False, error=""):
    return {"rows": [{"network": n, "interface": i, "gateway": ""} for n, i in rows],
            "error": error, "from_backup": backup}


class TestRoutingChecks(_Proposals):
    def setUp(self):
        self.v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"], gateway="10.10.0.1"),
                       "roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")},
                      link("milano", "roma"))

    def test_route_present_both_ways(self):
        r = {"10.10.0.1": routes(("10.20.0.0/16", "vpn-roma")), "10.20.0.1": routes(("10.0.0.0/8", "vpn-mi"))}
        self.assertEqual(found(bc.run(self.v, obs(routes=r)), "link_no_route"), [])

    def test_missing_live_is_error_backup_is_warning_default_is_warning(self):
        r = {"10.10.0.1": routes(("10.99.0.0/16", "port1")), "10.20.0.1": routes(("10.10.0.0/16", "x"))}
        f = found(bc.run(self.v, obs(routes=r)), "link_no_route")
        self.assertEqual([(x["severity"], x["params"]["src"]) for x in f], [("error", "Milano")])
        r["10.10.0.1"] = routes(("10.99.0.0/16", "port1"), backup=True)
        f = found(bc.run(self.v, obs(routes=r)), "link_no_route")[0]
        self.assertEqual((f["severity"], f["params"]["backup_only"]), ("warning", True))
        r["10.10.0.1"] = routes(("0.0.0.0/0", "wan1"))
        f = found(bc.run(self.v, obs(routes=r)), "link_no_route")[0]
        self.assertEqual((f["severity"], f["params"]["via"]), ("warning", "default"))

    def test_unknown_without_routes_or_gateway(self):
        f = found(bc.run(self.v, obs()), "link_no_route")
        self.assertEqual({x["severity"] for x in f}, {"unknown"})
        self.assertEqual(len(f), 2)

    def test_route_without_link_proposes_once_per_pair(self):
        v = view(self.v["locations"])                             # no links
        r = {"10.10.0.1": routes(("10.20.0.0/16", "vpn-roma")), "10.20.0.1": routes(("10.10.0.0/16", "wan1"))}
        t = {"10.10.0.1": {"tunnels": [{"name": "vpn-roma", "remote_gw": "", "up": True, "dst": []}], "error": ""}}
        fs = found(bc.run(v, obs(routes=r, tunnels=t)), "route_without_link")
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["proposal"][0]["kind"], "vpn")
        self.assertProposalsApply(v, fs)


class TestVpnChecks(_Proposals):
    def setUp(self):
        self.v = view({"milano": loc("Milano", "hq", ["10.10.0.0/16"], gateway="10.10.0.1"),
                       "roma": loc("Roma", subnets=["10.20.0.0/16"], gateway="10.20.0.1")},
                      link("milano", "roma"))
        self.devs = [dev("10.10.0.1", "milano", "fortinet"), dev("10.20.0.1", "roma", "cisco")]

    def tunnels(self, *ts):
        return {"10.10.0.1": {"tunnels": list(ts), "error": ""}}

    def test_up_by_selector(self):
        t = self.tunnels({"name": "to-roma", "remote_gw": "198.51.100.7", "up": True, "dst": ["10.20.0.0/16"]})
        self.assertEqual(found(bc.run(self.v, obs(devices=self.devs, tunnels=t)), "vpn_link_down"), [])

    def test_down_missing_unknown(self):
        t = self.tunnels({"name": "to-roma", "remote_gw": "", "up": False, "dst": ["10.20.0.0/16"]})
        f = found(bc.run(self.v, obs(devices=self.devs, tunnels=t)), "vpn_link_down")
        self.assertEqual([(x["severity"], x["params"]["state"]) for x in f], [("error", "down")])
        f = found(bc.run(self.v, obs(devices=self.devs, tunnels=self.tunnels())), "vpn_link_down")
        self.assertEqual([x["params"]["state"] for x in f], ["missing"])
        f = found(bc.run(self.v, obs(devices=self.devs)), "vpn_link_down")
        self.assertEqual([(x["severity"], x["params"]["state"]) for x in f], [("unknown", "unknown")])

    def test_tunnel_without_link(self):
        v = view(self.v["locations"])
        t = self.tunnels({"name": "to-roma", "remote_gw": "", "up": True, "dst": ["10.20.0.0/24"]})
        fs = found(bc.run(v, obs(devices=self.devs, tunnels=t)), "tunnel_without_link")
        self.assertEqual(fs[0]["proposal"], [{"op": "add_link", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}])
        self.assertProposalsApply(v, fs)
