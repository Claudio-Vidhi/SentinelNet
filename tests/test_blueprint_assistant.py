# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Blueprint assistant: describe (fake LLM), derive, instructions (spec 2026-10-11)."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from ai import config_analyzer
from services import blueprint, blueprint_assistant, blueprint_store, inventory_manager, probe_manager
from tests.conftest import seed_inventory

LOCS = {"milano": {"org": "acme", "name": "Milano", "role": "hq", "subnets": ["10.10.1.0/24"], "probe": "central"},
        "roma": {"org": "acme", "name": "Roma", "role": "branch", "subnets": [], "probe": "central"}}
HOSTS = [{"IP": "10.10.0.1", "Group": "acme", "Location": "milano"},
         {"IP": "10.20.0.1", "Group": "acme", "Location": "roma"}]
ROMA_FGT = {"interfaces": [{"name": "internal", "ip": "10.20.1.1/24", "status": "up"}],
            "routing": {"static": [{"prefix": "0.0.0.0/0"}]}, "vpn": {"phase1": [], "phase2": [], "peers": []}}


def reply(ops, notes=""):
    return json.dumps({"ops": ops, "notes": notes})


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="bp_assist_")
        for p in (patch.object(inventory_manager, "HOSTS_CSV", os.path.join(tmp, "network_hosts.csv")),
                  patch.object(probe_manager, "PROBES_JSON", os.path.join(tmp, "probes.json")),
                  patch("routers.ai._get_active_ai_profile", return_value={"provider": "ollama"})):
            p.start()
            self.addCleanup(p.stop)
        seed_inventory(orgs=["acme", "beta"], hosts=HOSTS, locations=LOCS)
        with inventory_manager._db() as conn, conn:
            blueprint_store.record_revisions(conn, "", "migration")

    def chat(self, *replies):
        p = patch("routers.ai.chat_with_active_profile",
                  side_effect=[r if isinstance(r, Exception) else (r, {"provider": "ollama"}) for r in replies])
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def draft_ops(self):
        d = blueprint.state("acme")["draft"]
        return d["ops"] if d else []


class TestDescribe(_Base):
    def test_valid_answer_goes_to_the_draft(self):
        blueprint_assistant.set_instructions("acme", "Le filiali si chiamano come la città.")
        chat = self.chat(reply([{"op": "create_location", "ref": "+1", "name": "Torino", "role": "branch",
                                 "subnets": ["10.30.0.0/16"]},
                                {"op": "add_link", "a": "milano", "b": "+1", "kind": "vpn"}], "Torino aggiunta."))
        out = blueprint_assistant.describe("acme", "Aggiungi la filiale di Torino, 10.30.0.0/16, in VPN con Milano.", "adm")
        self.assertEqual((out["added"], out["notes"]), (2, "Torino aggiunta."))
        self.assertEqual([o["source"] for o in self.draft_ops()], ["assistant", "assistant"])
        self.assertIn("torino", out["state"]["preview"]["locations"])
        system, user = chat.call_args.args[0]
        self.assertEqual((system["role"], user["role"]), ("system", "user"))
        self.assertIn("Le filiali si chiamano come la città.", system["content"])
        self.assertIn('"id": "milano"', user["content"])
        self.assertIn("Aggiungi la filiale di Torino", user["content"])

    def test_fenced_json_is_accepted(self):
        self.chat("```json\n" + reply([{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]) + "\n```")
        self.assertEqual(blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")["added"], 1)

    def test_invalid_then_valid_retries_once_with_the_error(self):
        chat = self.chat("Ecco la rete!", reply([{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}]))
        out = blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")
        self.assertEqual((chat.call_count, out["added"]), (2, 1))
        retry = chat.call_args_list[1].args[0]
        self.assertEqual(retry[-2], {"role": "assistant", "content": "Ecco la rete!"})
        self.assertIn('lista "ops"', retry[-1]["content"])

    def test_invalid_twice_is_a_value_error_and_no_draft(self):
        self.chat("boh", "ancora boh")
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")
        self.assertIn('lista "ops"', str(cm.exception))
        self.assertEqual(self.draft_ops(), [])

    def test_non_object_ops_are_retried_then_422(self):
        self.chat(json.dumps({"ops": ["add roma"]}), json.dumps({"ops": [None]}))
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.describe("acme", "Roma usa 10.20.1.0/24", "adm")
        self.assertIn("operazione 1: non è un oggetto", str(cm.exception))

    def test_error_index_counts_only_the_reply(self):
        blueprint.add_ops("acme", [{"op": "set_gateway", "id": "roma", "ip": "10.20.0.1"},
                                   {"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}], "manual", "adm")
        chat = self.chat(reply([{"op": "add_link", "a": "roma", "b": "roma", "kind": "vpn"}]),
                         reply([{"op": "add_subnet", "id": "milano", "subnet": "10.10.2.0/24"}]))
        out = blueprint_assistant.describe("acme", "Milano ha anche 10.10.2.0/24", "adm")
        self.assertIn("operazione 1: un collegamento unisce due sedi diverse",
                      chat.call_args_list[1].args[0][-1]["content"])
        self.assertEqual((out["added"], len(self.draft_ops())), (1, 3))

    def test_op_error_on_the_retry_too(self):
        bad = reply([{"op": "set_gateway", "id": "zara", "ip": "10.20.0.1"}])
        self.chat(bad, bad)
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.describe("acme", "Il gateway di Zara è 10.20.0.1", "adm")
        self.assertIn("operazione 1: sede 'zara' inesistente", str(cm.exception))

    def test_text_limits_never_reach_the_llm(self):
        chat = self.chat()
        for text in ("", "   ", "x" * (blueprint_assistant.MAX_TEXT + 1)):
            with self.subTest(n=len(text)), self.assertRaises(ValueError):
                blueprint_assistant.describe("acme", text, "adm")
        chat.assert_not_called()


class TestDerive(_Base):
    def analyses(self, table):
        p = patch.object(config_analyzer, "analyze_device", side_effect=lambda ip, tenant=None: table.get(ip))
        m = p.start()
        self.addCleanup(p.stop)
        return m

    def test_deterministic_ops_reach_the_draft(self):
        calls = self.analyses({"10.20.0.1": ROMA_FGT})
        out = blueprint_assistant.derive("acme", "adm", use_ai=False)
        self.assertEqual(out["added"], 2)
        self.assertEqual([(o["op"], o["source"]) for o in self.draft_ops()],
                         [("add_subnet", "assistant"), ("set_gateway", "assistant")])
        self.assertEqual(out["notes"], "1 apparati senza backup della configurazione.")
        self.assertEqual(calls.call_args.args[1], "acme")          # backups searched in the tenant

    def test_reads_the_preview(self):
        blueprint.add_ops("acme", [{"op": "add_subnet", "id": "roma", "subnet": "10.20.1.0/24"}], "manual", "adm")
        self.analyses({"10.20.0.1": ROMA_FGT})
        out = blueprint_assistant.derive("acme", "adm", use_ai=False)
        self.assertEqual([o["op"] for o in self.draft_ops()], ["add_subnet", "set_gateway"])
        self.assertEqual(out["added"], 1)

    def test_nothing_derived_is_a_value_error_with_the_notes(self):
        self.analyses({})
        with self.assertRaises(ValueError) as cm:
            blueprint_assistant.derive("acme", "adm", use_ai=False)
        self.assertIn("Nessuna proposta dalle configurazioni.", str(cm.exception))
        self.assertIn("2 apparati senza backup", str(cm.exception))

    def test_a_backup_the_parser_chokes_on_is_counted(self):
        def boom(ip, tenant=None):
            if ip == "10.10.0.1":
                raise UnicodeError("x")
            return ROMA_FGT
        p = patch.object(config_analyzer, "analyze_device", side_effect=boom)
        p.start()
        self.addCleanup(p.stop)
        self.assertIn("1 backup non leggibili.", blueprint_assistant.derive("acme", "adm", use_ai=False)["notes"])

    def test_ai_pass_keeps_only_names_and_roles(self):
        self.analyses({"10.20.0.1": ROMA_FGT})
        self.chat(reply([{"op": "update_location", "id": "roma", "fields": {"name": "Roma EUR", "subnets": []}},
                         {"op": "update_location", "id": "milano", "fields": {"role": "datacenter"}},
                         {"op": "add_subnet", "id": "roma", "subnet": "10.99.0.0/16"},
                         {"op": "update_location", "id": "zara", "fields": {"name": "Zara"}},
                         {"op": "update_location", "id": ["roma"], "fields": {"name": "X"}},
                         "rinomina tutto"]))
        out = blueprint_assistant.derive("acme", "adm", use_ai=True)
        self.assertEqual(out["added"], 4)
        self.assertEqual([o.get("fields") for o in self.draft_ops()[2:]],
                         [{"name": "Roma EUR"}, {"role": "datacenter"}])

    def test_ai_failure_keeps_the_deterministic_ops(self):
        self.analyses({"10.20.0.1": ROMA_FGT})
        self.chat(HTTPException(status_code=502, detail="provider giù"))
        out = blueprint_assistant.derive("acme", "adm", use_ai=True)
        self.assertEqual(len(self.draft_ops()), 2)
        self.assertIn("provider giù", out["notes"])

    def test_ai_pass_skipped_without_a_profile(self):
        self.analyses({"10.20.0.1": ROMA_FGT})
        chat = self.chat()
        with patch("routers.ai._get_active_ai_profile", return_value=None):
            blueprint_assistant.derive("acme", "adm", use_ai=True)
        chat.assert_not_called()


class TestInstructions(_Base):
    def test_state_carries_them_and_the_ai_flag(self):
        self.assertEqual(blueprint_assistant.set_instructions("acme", "  Sedi: città.  "), "Sedi: città.")
        st = blueprint.state("acme")
        self.assertEqual((st["instructions"], st["ai_available"]), ("Sedi: città.", True))
        self.assertEqual(blueprint.state("beta")["instructions"], "")
        with patch("routers.ai._get_active_ai_profile", return_value=None):
            self.assertFalse(blueprint.state("acme")["ai_available"])

    def test_length_limit(self):
        with self.assertRaises(ValueError):
            blueprint_assistant.set_instructions("acme", "x" * (blueprint_assistant.MAX_TEXT + 1))
