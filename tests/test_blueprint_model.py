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
    def test_draft_and_names_are_bounded(self):
        # Security review 2026-10-12, A-M2: an MCP loop grew the draft forever.
        too_many = [{"op": "set_gateway", "id": "roma", "ip": "192.0.2.1"}] * (bm.MAX_DRAFT_OPS + 1)
        with self.assertRaises(ValueError):
            apply(too_many)
        with self.assertRaises(ValueError):
            apply([{"op": "create_location", "name": "x" * (bm.MAX_NAME + 1)}])
        _, links, _ = apply([{"op": "add_link", "a": "milano", "b": "roma", "kind": "wan", "note": "n" * 5000}])
        self.assertEqual(len(links["milano--roma--wan"]["note"]), bm.MAX_NOTE)

    def test_full_mesh_preset_fits_the_cap(self):
        self.assertLessEqual(bm.MAX_PRESET + bm.MAX_PRESET * (bm.MAX_PRESET - 1) // 2, bm.MAX_DRAFT_OPS)

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

    def test_malformed_ops_are_op_errors(self):
        for op in ("set_gateway", ["op"], {"op": "add_link", "a": ["x"], "b": "roma", "kind": "vpn"},
                   {"op": "update_location", "id": ["roma"], "fields": {"name": "X"}}):
            with self.subTest(op=op):
                with self.assertRaises(bm.OpError) as cm:
                    apply([{"op": "set_gateway", "id": "milano", "ip": "10.10.0.1"}, op])
                self.assertEqual(cm.exception.index, 1)

    def test_client_id_must_be_a_slug(self):
        for wanted in ("a--b", "+x", "<img>", "Roma"):
            with self.subTest(id=wanted):
                with self.assertRaises(bm.OpError):
                    apply([{"op": "create_location", "name": "X", "id": wanted}])
        locs, _, refs = apply([{"op": "create_location", "ref": "+napoli", "name": "Napoli", "id": "napoli-2"}])
        self.assertEqual(refs, {"+napoli": "napoli-2"})

    def test_link_id_is_ordered(self):
        self.assertEqual(bm.link_id("roma", "milano", "vpn"), "milano--roma--vpn")

    def test_org_view(self):
        view = bm.org_view(LOCS, LINKS, "beta")
        self.assertEqual((list(view["locations"]), view["links"]), (["zurigo"], {}))


class TestDiff(unittest.TestCase):
    def test_added_removed_changed(self):
        old = bm.org_view(LOCS, LINKS, "acme")
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"},
                                {"op": "create_location", "ref": "+1", "name": "Torino"},
                                {"op": "set_gateway", "id": "milano", "ip": "10.10.0.1"}])
        d = bm.diff(old, bm.org_view(locs, links, "acme"))
        self.assertEqual([x["id"] for x in d["locations"]["added"]], ["torino"])
        self.assertEqual([x["id"] for x in d["locations"]["removed"]], ["roma"])
        self.assertEqual(d["locations"]["changed"],
                         [{"id": "milano", "label": "Milano", "fields": {"gateway": ["", "10.10.0.1"]}}])
        self.assertEqual([x["id"] for x in d["links"]["removed"]], ["milano--roma--vpn"])


class TestRestore(unittest.TestCase):
    def test_round_trip_back_to_the_target(self):
        target = bm.org_view(LOCS, LINKS, "acme")
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"},
                                {"op": "create_location", "ref": "+1", "name": "Torino"},
                                {"op": "add_link", "a": "+1", "b": "milano", "kind": "wan"},
                                {"op": "update_location", "id": "milano", "fields": {"name": "HQ"}}])
        ops = bm.restore_ops(bm.org_view(locs, links, "acme"), target)
        back, back_links, _ = bm.apply_ops("acme", locs, links, ops, PROBES)
        self.assertEqual(bm.org_view(back, back_links, "acme"), target)

    def test_taken_id_comes_back_suffixed_with_its_links(self):
        target = bm.org_view(LOCS, LINKS, "acme")
        locs, links, _ = apply([{"op": "delete_location", "id": "roma"}])
        locs["roma"] = loc("Roma", org="beta")                # another org took the id meanwhile
        ops = bm.restore_ops(bm.org_view(locs, links, "acme"), target)
        back, back_links, refs = bm.apply_ops("acme", locs, links, ops, PROBES)
        self.assertEqual(refs["+roma"], "roma-2")
        self.assertIn("milano--roma-2--vpn", back_links)

    def test_nothing_to_do(self):
        view = bm.org_view(LOCS, LINKS, "acme")
        self.assertEqual(bm.restore_ops(view, view), [])


class TestPresets(unittest.TestCase):
    EMPTY = {"locations": {}, "links": {}}

    def run_preset(self, kind, n, view=None):
        view = view or self.EMPTY
        ops = bm.preset_ops(kind, n, view)
        locs, links, _ = bm.apply_ops("acme", dict(view["locations"]), dict(view["links"]), ops, PROBES)
        return locs, links

    def test_single(self):
        locs, _ = self.run_preset("single", 1)
        self.assertEqual([l["role"] for l in locs.values()], ["hq"])
        self.assertEqual(bm.preset_ops("single", 1, bm.org_view(LOCS, LINKS, "acme")), [])

    def test_hub_spoke_reuses_the_existing_hq(self):
        locs, links = self.run_preset("hub_spoke", 2, bm.org_view(LOCS, LINKS, "acme"))
        self.assertEqual(sum(1 for l in locs.values() if l["role"] == "hq"), 1)
        self.assertIn("filiale-2", locs)                       # Roma is branch 1
        self.assertEqual(set(links), {"milano--roma--vpn", "filiale-2--milano--vpn", "filiale-3--milano--vpn"})

    def test_hub_spoke_dc(self):
        locs, links = self.run_preset("hub_spoke_dc", 2)
        self.assertEqual(sorted(l["role"] for l in locs.values()), ["branch", "branch", "datacenter", "hq"])
        self.assertEqual(len(links), 1 + 2 * 2)

    def test_full_mesh(self):
        locs, links = self.run_preset("full_mesh", 4)
        self.assertEqual(len(locs), 4)
        self.assertEqual(len(links), 6)
        self.assertEqual(sum(1 for l in locs.values() if l["role"] == "hq"), 1)

    def test_bounds_and_unknown(self):
        for kind, n in (("hub_spoke", 0), ("hub_spoke", bm.MAX_PRESET + 1), ("ring", 3)):
            with self.subTest(kind=kind, n=n), self.assertRaises(ValueError):
                bm.preset_ops(kind, n, self.EMPTY)
