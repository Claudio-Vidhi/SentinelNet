# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Draft operations applied to the locations and links tables (pure)."""
import unittest

from services import blueprint_model as bm


def loc(name, org="acme", role="branch", subnets=(), gateway=""):
    return {"org": org, "name": name, "role": role, "subnets": list(subnets), "probe": "central", "gateway": gateway}


LOCS = {"milano": loc("Milano", role="hq", subnets=["10.10.0.0/16"]), "roma": loc("Roma"),
        "zurigo": loc("Zurigo", org="beta")}
LINKS = {"milano--roma--vpn": {"org": "acme", "a": "milano", "b": "roma", "kind": "vpn", "note": ""}}
PROBES = {"central"}


def apply(ops, locs=LOCS, links=LINKS):
    return bm.apply_ops("acme", locs, links, ops, PROBES)


class TestApplyOps(unittest.TestCase):
    def test_create_with_ref_then_link_to_it(self):
        locs, links, refs = apply([
            {"op": "create_location", "ref": "+1", "name": "Torino"},
            {"op": "add_link", "a": "+1", "b": "milano", "kind": "wan"}])
        self.assertEqual(refs, {"+1": "torino"})
        self.assertEqual(locs["torino"], loc("Torino"))
        self.assertEqual(links["milano--torino--wan"]["a"], "milano")
        self.assertNotIn("torino", LOCS)                      # inputs untouched

    def test_slug_clash_gets_a_suffix_and_wanted_id_is_used_when_free(self):
        locs, _, refs = apply([{"op": "create_location", "ref": "+1", "name": "Roma"},
                               {"op": "create_location", "ref": "+2", "name": "X", "id": "napoli"},
                               {"op": "create_location", "ref": "+3", "name": "Y", "id": "zurigo"}])
        self.assertEqual(refs, {"+1": "roma-2", "+2": "napoli", "+3": "zurigo-2"})

    def test_update_gateway_add_subnet(self):
        locs, _, _ = apply([
            {"op": "update_location", "id": "roma", "fields": {"name": "Roma Est", "subnets": ["10.20.0.0/24"]}},
            {"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
            {"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"},
            {"op": "add_subnet", "id": "roma", "subnet": "10.20.2.0/24"}])
        self.assertEqual(locs["roma"]["name"], "Roma Est")
        self.assertEqual(locs["roma"]["gateway"], "10.20.0.1")
        self.assertEqual(locs["roma"]["subnets"], ["10.20.0.0/24", "10.20.1.0/24", "10.20.2.0/24"])

    def test_delete_drops_links_and_remove_link(self):
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"}])
        self.assertNotIn("roma", locs)
        self.assertEqual(links, {})
        _, links, _ = apply([{"op": "remove_link", "id": "milano--roma--vpn"}])
        self.assertEqual(links, {})

    def test_errors_name_the_operation(self):
        bad = [
            [{"op": "update_location", "id": "zurigo", "fields": {"name": "X"}}],   # other org
            [{"op": "update_location", "id": "roma", "fields": {"color": "red"}}],
            [{"op": "update_location", "id": "roma", "fields": {}}],
            [{"op": "update_location", "id": "roma", "fields": {"role": "castle"}}],
            [{"op": "update_location", "id": "roma", "fields": {"probe": "ghost"}}],
            [{"op": "set_gateway", "id": "roma", "ip": "not-an-ip"}],
            [{"op": "add_subnet", "id": "roma", "subnet": "10.0.0.0/33"}],
            [{"op": "create_location", "name": " "}],
            [{"op": "create_location", "ref": "1", "name": "X"}],
            [{"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}],
            [{"op": "add_link", "a": "roma", "b": "milano", "kind": "vpn"}],          # exists
            [{"op": "add_link", "a": "roma", "b": "milano", "kind": "smoke"}],
            [{"op": "add_link", "a": "roma", "b": "+9", "kind": "wan"}],
            [{"op": "remove_link", "id": "nope"}],
            [{"op": "teleport"}],
        ]
        for ops in bad:
            with self.subTest(ops=ops):
                with self.assertRaises(bm.OpError) as cm:
                    apply([{"op": "set_gateway", "id": "milano", "ip": "10.10.0.1"}] + ops)
                self.assertEqual(cm.exception.index, 1)
                self.assertTrue(str(cm.exception).startswith("Modifica 2: "))

    def test_link_id_is_ordered(self):
        self.assertEqual(bm.link_id("roma", "milano", "vpn"), "milano--roma--vpn")

    def test_org_view(self):
        view = bm.org_view(LOCS, LINKS, "beta")
        self.assertEqual((list(view["locations"]), view["links"]), (["zurigo"], {}))
