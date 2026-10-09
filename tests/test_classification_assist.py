# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""AI suggestions for the classification tab: the parsers keep only what the
app can store, and the endpoints spend one request per run and never write a
device record on their own (except an explicit model merge)."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_clsai_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from ai import classification_assist as ca  # noqa: E402
from core import db  # noqa: E402
from routers import catalog  # noqa: E402
from security import user_manager  # noqa: E402
from services import inventory_manager  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}

CATS = {
    "switch": {"label": "Switch", "subcategories": ["Access", "Core"]},
    "ap": {"label": "Access Point", "subcategories": []},
}


class TestParseSuggestions(unittest.TestCase):
    def test_keeps_only_storable_values(self):
        reply = "```json\n" + json.dumps({
            "conventions": {"tenant-a": "LOC-ROLE-NN"},
            "suggestions": [
                {"id": "d1", "category": "Switch", "subcategory": "access",
                 "vendor": "Cisco", "model": "C9200L-48P-4G", "name": "MI-SW-ACC-07",
                 "confidence": 140, "reason": "modello access"},
                {"id": "d2", "category": "toaster", "subcategory": "Core",
                 "name": "bad name with spaces", "confidence": "x"},
                {"id": "not-in-queue", "category": "switch"},
            ]}) + "\n```"
        out, conv = ca.parse_suggestions(reply, ["d1", "d2"], CATS)
        self.assertEqual(out["d1"]["category"], "switch")
        self.assertEqual(out["d1"]["subcategory"], "Access")      # canonical spelling
        self.assertEqual(out["d1"]["confidence"], 100)            # clamped
        self.assertEqual(out["d1"]["name"], "MI-SW-ACC-07")
        # Unknown category, sub of nothing, non-hostname name: nothing usable left.
        self.assertNotIn("d2", out)
        self.assertNotIn("not-in-queue", out)
        self.assertEqual(conv, {"tenant-a": "LOC-ROLE-NN"})

    def test_ha_pair_label_is_kept_when_storable(self):
        reply = json.dumps({"suggestions": [
            {"id": "d1", "ha_group": "FW-CORE"},             # alone is still a proposal
            {"id": "d2", "category": "switch", "ha_group": "not a label!"},
        ]})
        out, _ = ca.parse_suggestions(reply, ["d1", "d2"], CATS)
        self.assertEqual(out["d1"]["ha_group"], "FW-CORE")
        self.assertEqual(out["d2"]["ha_group"], "")

    def test_prompt_asks_for_ha_pairs(self):
        msgs = ca.build_messages([], {"t": [{"name": "fw-a", "ha_group": "FW"}]}, CATS)
        self.assertIn("ha_group", msgs[0]["content"])
        self.assertIn('"ha_group": "FW"', msgs[1]["content"])

    def test_non_json_reply_yields_nothing(self):
        self.assertEqual(ca.parse_suggestions("Non so.", ["d1"], CATS), ({}, {}))

    def test_prompt_carries_no_ip(self):
        msgs = ca.build_messages(
            [{"id": "d1", "name": "sw1", "tenant": "t", "vendor": "", "model": "",
              "version": "", "neighbours": []}], {}, CATS)
        self.assertNotIn("display_ip", msgs[1]["content"])


class TestParseModelMerges(unittest.TestCase):
    def test_only_existing_models_of_one_vendor(self):
        models = {"cisco": ["C2960X-48FPD", "WS-C2960X-48FPD-L", "C9200L-24P"]}
        reply = json.dumps({"merges": [
            {"vendor": "Cisco", "canonical": "WS-C2960X-48FPD-L",
             "duplicates": ["C2960X-48FPD", "WS-C2960X-48FPD-L", "INVENTED"], "reason": "r"},
            {"vendor": "cisco", "canonical": "NOT-THERE", "duplicates": ["C9200L-24P"]},
        ]})
        self.assertEqual(ca.parse_model_merges(reply, models), [
            {"vendor": "cisco", "canonical": "WS-C2960X-48FPD-L",
             "duplicates": ["C2960X-48FPD"], "reason": "r"}])


def _node(i, group="tenant-a", discovered=True, manual=False, dtype="switch"):
    return {"id": i, "display_ip": "", "label": i, "group": group, "status": "",
            "device_type": dtype, "subcategory": "", "is_manual": manual,
            "vendor": "discovered", "model": "", "serial": "", "ha_group": "",
            "version": "", "vtp_domain": None, "vtp_mode": None,
            "discovered": discovered, "name_options": [], "stack": None}


FAKE_DATA = {
    "categories": CATS,
    "nodes": [_node("disc-1"), _node("disc-2"), _node("MI-SW-CORE-01", discovered=False)],
    "links": [{"source": "MI-SW-CORE-01", "target": "disc-1",
               "local_port": "Gi1/0/1", "remote_port": "Gi0/1"}],
    "counts_by_category": {}, "counts_by_group": {"tenant-a": 3},
    "vendors": [], "models": {}, "total": 3,
}


class TestEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        try:
            user_manager.create_user("adm_clsai", PASS, role="admin", groups=None)
        except Exception:
            pass

    def _client(self):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login", json={"username": "adm_clsai", "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_suggest_runs_once_and_is_saved(self):
        # The store skips devices that already have a proposal: a leftover
        # "disc-1" from a shared data dir would drop it from the request.
        if os.path.exists(catalog._ai_suggest_file()):
            os.remove(catalog._ai_suggest_file())
        reply = json.dumps({"conventions": {"tenant-a": "LOC-SW-ROLE-NN"}, "suggestions": [
            {"id": "disc-1", "category": "switch", "subcategory": "Access",
             "name": "MI-SW-ACC-02", "confidence": 80, "reason": "r"}]})
        with patch.object(catalog, "assemble_classification", return_value=FAKE_DATA), \
             patch("routers.ai.chat_with_active_profile",
                   return_value=(reply, {"provider": "gemini"})) as chat:
            c = self._client()
            r = c.post("/api/device-classification/ai-suggest", headers=CSRF, json={"lang": "it"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(chat.call_count, 1)
            sent = chat.call_args[0][0][1]["content"]
            self.assertIn("disc-2", sent)
            self.assertNotIn('"id": "MI-SW-CORE-01"', sent)   # classified: example, not queue
            self.assertIn('"own_port": "Gi0/1"', sent)       # its own port, not the neighbour's
            body = r.json()
            self.assertEqual(body["requested"], 2)
            self.assertEqual(body["suggestions"]["disc-1"]["name"], "MI-SW-ACC-02")

            saved = c.get("/api/device-classification/ai-suggestions").json()
            self.assertIn("disc-1", saved["suggestions"])
            self.assertEqual(saved["conventions"]["tenant-a"], "LOC-SW-ROLE-NN")
        # Proposal only: no device assignment was written.
        self.assertNotIn("disc-1", str(inventory_manager.get_device_categories()["assignments"]))

    def test_model_merge_rewrites_catalogue(self):
        inventory_manager.add_model("cisco", "C2960X-48FPD")
        inventory_manager.add_model("cisco", "WS-C2960X-48FPD-L")
        c = self._client()
        r = c.post("/api/device-models/merge", headers=CSRF, json={
            "vendor": "cisco", "canonical": "WS-C2960X-48FPD-L", "duplicates": ["C2960X-48FPD"]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(inventory_manager.get_models()["cisco"], ["WS-C2960X-48FPD-L"])
        r = c.post("/api/device-models/merge", headers=CSRF, json={
            "vendor": "cisco", "canonical": "WS-C2960X-48FPD-L", "duplicates": ["INVENTED"]})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
