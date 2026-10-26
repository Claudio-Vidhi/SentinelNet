# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""AI layout of the Schema map: nothing that names a device leaves the process.

The fixture is full of things that must not leak (hostnames, IPs, a site
name, a user-made category); the tests read the messages exactly as the
provider would receive them.
"""
import json
import unittest
from unittest import mock

from ai import map_layout

NODES = [
    {"id": "192.0.2.1", "type": "firewall", "level": 0, "zone": "Sede Milano"},
    {"id": "192.0.2.2", "type": "switch", "level": 1, "zone": "Sede Milano"},
    {"id": "192.0.2.3", "type": "switch", "level": 1, "zone": "Sede Milano"},
    {"id": "discovered_ap-reception-01", "type": "ap", "level": 2, "zone": "Sede Milano"},
    {"id": "192.0.2.40", "type": "contabilita-printers", "level": 2, "zone": "Magazzino Nord"},
]
LINKS = [
    {"a": "192.0.2.1", "b": "192.0.2.2", "kind": "link", "count": 1},
    {"a": "192.0.2.2", "b": "192.0.2.3", "kind": "peer", "count": 2},
    {"a": "192.0.2.2", "b": "discovered_ap-reception-01", "kind": "Gi1/0/7", "count": 1},
]
SECRETS = ["192.0.2", "discovered", "reception", "Sede", "Milano", "Magazzino",
           "contabilita", "Gi1/0/7"]


def _sent(goals=("min_crossings",), selected=()):
    payload, tokens = map_layout.build_payload(NODES, LINKS, list(goals), list(selected))
    return map_layout.build_messages(payload), payload, tokens


class TestNothingLeaks(unittest.TestCase):
    def test_messages_hold_no_identity(self):
        messages, _, _ = _sent(selected=["192.0.2.2", "192.0.2.3"])
        text = json.dumps(messages)
        for s in SECRETS:
            self.assertNotIn(s, text, s)

    def test_only_tokens_and_vocabulary(self):
        _, payload, _ = _sent()
        types = {n["type"] for n in payload["nodes"]}
        self.assertLessEqual(types, set(map_layout.DEVICE_TYPES))
        self.assertIn("other", types)   # the user-made category is not sent
        self.assertEqual({lk["kind"] for lk in payload["links"]}, {"link", "peer"})
        for n in payload["nodes"]:
            self.assertRegex(n["id"], r"^n\d+$")
            self.assertRegex(n["zone"], r"^z\d+$")

    def test_egress_check_refuses_any_other_string(self):
        _, payload, _ = _sent()
        payload["nodes"][0]["type"] = "switch-01"
        with self.assertRaises(ValueError):
            map_layout.build_messages(payload)
        _, payload, _ = _sent()
        payload["links"].append({"a": "n1", "b": "n2", "kind": "link", "count": None})
        with self.assertRaises(ValueError):
            map_layout.egress_check(payload)

    def test_tokens_change_between_requests(self):
        seen = {tuple(sorted(_sent()[2].items())) for _ in range(10)}
        self.assertGreater(len(seen), 1)


class TestUserDirection(unittest.TestCase):
    def test_plain_direction_passes(self):
        for t in ("metti i firewall in alto a sinistra", "AP in fondo, i selezionati vicino al core",
                  "piano 1 a destra"):
            self.assertEqual(map_layout.check_instruction(t), t)
        self.assertEqual(map_layout.check_instruction("  due   spazi \n "), "due spazi")
        self.assertEqual(map_layout.check_instruction(""), "")

    def test_names_addresses_and_numbers_refused(self):
        for t in ("sposta sw-core-01 sotto", "fw1.example in alto", "ap_lobby2 a destra",
                  "192.0.2.5 in alto", "aa:bb:cc:dd:ee:ff", "0011.2233.4455", "2001:db8::1 sopra",
                  "core 9300 al centro", "vlan 120 a sinistra", "x" * 301):
            with self.assertRaises(ValueError, msg=t):
                map_layout.check_instruction(t)

    def test_names_on_the_map_refused(self):
        with self.assertRaises(ValueError):
            map_layout.check_instruction("gli AP di magazzino in basso", ["Magazzino"])
        # a short deny term (2 chars) would refuse half the language: ignored
        self.assertTrue(map_layout.check_instruction("AP in basso", ["AP"]))

    def test_direction_reaches_the_messages(self):
        payload, _ = map_layout.build_payload(NODES, LINKS, ["min_crossings"])
        messages = map_layout.build_messages(payload, "AP in fondo a destra")
        self.assertIn("AP in fondo a destra", messages[1]["content"])
        # the graph stays the last thing in the message, readable as JSON
        json.loads(messages[1]["content"].split("Graph: ", 1)[1])


class TestReadingTheAnswer(unittest.TestCase):
    def test_round_trip_to_real_ids(self):
        _, _, tokens = _sent()
        back = {v: k for k, v in tokens.items()}
        reply = "```json\n" + json.dumps({"rows": [[back["192.0.2.1"]], [back["192.0.2.3"], back["192.0.2.2"]]],
                                          "note": "firewall on top"}) + "\n```"
        rows, note = map_layout.parse_reply(reply, tokens)
        self.assertEqual(rows, [["192.0.2.1"], ["192.0.2.3", "192.0.2.2"]])
        self.assertEqual(note, "firewall on top")

    def test_unknown_and_repeated_tokens_dropped(self):
        _, _, tokens = _sent()
        t = next(iter(tokens))
        rows, _ = map_layout.parse_reply(json.dumps({"rows": [[t, "n999", t], ["zz"]]}), tokens)
        self.assertEqual(rows, [[tokens[t]]])

    def test_unusable_answers_raise(self):
        _, _, tokens = _sent()
        for bad in ("no json here", '{"rows": "n1"}', '{"rows": [["n999"]]}', "{not json}"):
            with self.assertRaises(ValueError, msg=bad):
                map_layout.parse_reply(bad, tokens)


class TestRoute(unittest.TestCase):
    def _post(self, body, reply=None, user=None):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user
        sent = {}

        def fake_chat(messages):
            sent["messages"] = messages
            graph = json.loads(messages[1]["content"].split("Graph: ", 1)[1])
            ids = [n["id"] for n in graph["nodes"]]
            return (reply if reply is not None else json.dumps({"rows": [ids], "note": "ok"})), {"provider": "test"}

        app_server.app.dependency_overrides[get_current_user] = \
            lambda: user or {"sub": "tester", "role": "admin"}
        try:
            with mock.patch("routers.topology.chat_with_active_profile", side_effect=fake_chat), \
                 mock.patch("routers.topology.log_audit"):
                r = TestClient(app_server.app).post("/api/map/ai-layout", json=body)
        finally:
            app_server.app.dependency_overrides.clear()
        return r, sent

    def test_answer_in_real_ids_and_nothing_leaks(self):
        r, sent = self._post({"group": "all", "nodes": NODES, "links": LINKS,
                              "goals": ["min_crossings", "not-a-goal"]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(sorted(r.json()["rows"][0]), sorted(n["id"] for n in NODES))
        text = json.dumps(sent["messages"])
        for s in SECRETS + ["not-a-goal"]:
            self.assertNotIn(s, text, s)

    def test_direction_naming_the_map_is_refused_before_sending(self):
        for text in ("metti switch-milano vicino al firewall",   # a label from the browser's deny list
                     "AP di Sede Milano in basso",                # a site drawn on the map
                     "192.0.2.2 al centro"):                      # an address
            r, sent = self._post({"nodes": NODES, "links": LINKS, "instruction": text,
                                  "deny": ["switch-milano", "Sede Milano"]})
            self.assertEqual(r.status_code, 400, text)
            self.assertNotIn("messages", sent, text)

    def test_direction_sent_and_deny_list_not(self):
        r, sent = self._post({"nodes": NODES, "links": LINKS, "instruction": "AP in fondo a destra",
                              "deny": ["switch-milano", "Sede Milano"]})
        self.assertEqual(r.status_code, 200, r.text)
        text = json.dumps(sent["messages"])
        self.assertIn("AP in fondo a destra", text)
        for s in SECRETS + ["switch-milano"]:
            self.assertNotIn(s, text, s)

    def test_unusable_answer_is_502(self):
        r, _ = self._post({"nodes": NODES, "links": LINKS}, reply="sorry, I cannot")
        self.assertEqual(r.status_code, 502)

    def test_scoped_user_cannot_name_another_group(self):
        with mock.patch("routers.topology.assert_group_allowed",
                        side_effect=__import__("fastapi").HTTPException(status_code=403)):
            r, sent = self._post({"group": "BETA", "nodes": NODES})
        self.assertEqual(r.status_code, 403)
        self.assertNotIn("messages", sent)

    def test_empty_map_is_400(self):
        r, _ = self._post({"nodes": []})
        self.assertEqual(r.status_code, 400)


class TestControlsWired(unittest.TestCase):
    def test_template_and_js_agree(self):
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        html = open(os.path.join(root, "templates", "dashboard.html"), encoding="utf-8").read()
        js = open(os.path.join(root, "static", "js", "topology.js"), encoding="utf-8").read()
        for cid in ("mapAiRunBtn", "mapAiUndoBtn", "mapAiStatus"):
            self.assertIn(f'id="{cid}"', html, cid)
            self.assertIn(f"'{cid}'", js, cid)
        # The goals are read from the section by selector.
        self.assertIn('id="mapAiSec"', html)
        self.assertIn("#mapAiSec input[name=\"mapAiGoal\"]", js)
        # Every goal offered in the panel is one the server knows.
        import re
        offered = set(re.findall(r'name="mapAiGoal" value="([a-z_]+)"', html))
        self.assertEqual(offered, set(map_layout.GOALS))
        self.assertIn("'/api/map/ai-layout'", js)


if __name__ == "__main__":
    unittest.main()
