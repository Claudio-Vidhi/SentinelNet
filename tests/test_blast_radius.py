# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
""""E' solo mio?" -- BLAST_RADIUS_001.

Una conclusione per client risponde a "perche' IO non arrivo?", non a "anche
gli altri non arrivano?". Sono due guasti diversi: il primo e' un client, il
secondo e' un servizio o una policy, e chi indaga partendo dal primo client
perde tempo nel posto sbagliato.

La chiave e' la destinazione (scelta dell'utente, 2026-09-13), e contano solo
i blocchi che BLOCKED_TRAFFIC_001 accetterebbe gia': log di blocco
corroborato da un flusso. Due regole in disaccordo su cosa sia "bloccato"
sarebbero due verita'.
"""

import itertools
import json
import time
import unittest
from unittest.mock import patch

from observability import rules

NOW = int(time.time())
RULE = "BLAST_RADIUS_001"
SERVICE = "198.51.100.20"
_ids = itertools.count(1)


def _event(event_type, src, dst, attrs, tenant="sede-a"):
    return {
        "id": next(_ids), "ts": NOW - 120,
        "tenant": tenant, "source": "syslog", "source_id": 1,
        "event_type": event_type, "entity_type": "flow",
        "entity_id": f"{src}>{dst}", "severity": 3, "device_ip": "192.0.2.1",
        "interface": None, "src_ip": src, "dst_ip": dst, "dst_port": None,
        "protocol": None, "metrics_json": "{}",
        "attrs_json": json.dumps(attrs),
    }


def _blocked(src, dst=SERVICE, port=443, tenant="sede-a", corroborated=True):
    """Un blocco come lo vede BLOCKED_TRAFFIC_001: log di deny e, se
    corroborato, il flusso corrispondente nella stessa finestra."""
    out = [_event("log.security", src, dst,
                  {"action": "deny", "dst_port": port}, tenant=tenant)]
    if corroborated:
        out.append(_event("flow.aggregate", src, dst,
                          {"dst_port": port}, tenant=tenant))
    return out


def _run(events, min_sources=None):
    settings = {}
    if min_sources is not None:
        settings = {"correlation_rules": {RULE: {"min_sources": min_sources}}}
    with patch("observability.rules.get_app_settings", return_value=settings):
        return [item for _rid, _v, _p, item
                in rules.evaluate(events, only=[RULE])]


class TestIsItJustMe(unittest.TestCase):

    def test_one_client_blocked_is_not_a_service_problem(self):
        self.assertEqual(_run(_blocked("10.0.1.10")), [])

    def test_three_clients_blocked_towards_one_service_is(self):
        events = (_blocked("10.0.1.10") + _blocked("10.0.1.11")
                  + _blocked("10.0.1.12"))
        found = _run(events)
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual(f.entity_key, f"dst:{SERVICE}:443")
        self.assertEqual(f.role, "trigger")
        self.assertEqual(f.attrs["sources"], 3)
        self.assertEqual(f.attrs["sample"],
                         ["10.0.1.10", "10.0.1.11", "10.0.1.12"])

    def test_the_same_client_blocked_many_times_is_still_one_client(self):
        """Dieci tentativi dello stesso client non sono dieci client: e' la
        differenza fra un utente che riprova e un servizio giu'."""
        events = []
        for _ in range(10):
            events += _blocked("10.0.1.10")
        self.assertEqual(_run(events), [])

    def test_different_ports_on_the_same_host_are_different_services(self):
        events = (_blocked("10.0.1.10", port=443)
                  + _blocked("10.0.1.11", port=22)
                  + _blocked("10.0.1.12", port=3389))
        self.assertEqual(_run(events), [])

    def test_tenants_do_not_add_up(self):
        """Tre client in tre sedi verso lo stesso indirizzo sono tre reti
        diverse, non un servizio."""
        events = (_blocked("10.0.1.10", tenant="sede-a")
                  + _blocked("10.0.1.11", tenant="sede-b")
                  + _blocked("10.0.1.12", tenant="sede-c"))
        self.assertEqual(_run(events), [])

    def test_uncorroborated_blocks_do_not_count(self):
        """La stessa precisione di ogni conclusione per client: un log di
        deny senza flusso non basta a BLOCKED_TRAFFIC_001, e non basta qui."""
        events = (_blocked("10.0.1.10", corroborated=False)
                  + _blocked("10.0.1.11", corroborated=False)
                  + _blocked("10.0.1.12", corroborated=False))
        self.assertEqual(_run(events), [])

    def test_allowed_traffic_is_not_a_block(self):
        events = []
        for src in ("10.0.1.10", "10.0.1.11", "10.0.1.12"):
            events.append(_event("log.security", src, SERVICE,
                                 {"action": "accept", "dst_port": 443}))
            events.append(_event("flow.aggregate", src, SERVICE,
                                 {"dst_port": 443}))
        self.assertEqual(_run(events), [])

    def test_the_threshold_is_the_administrators(self):
        events = _blocked("10.0.1.10") + _blocked("10.0.1.11")
        self.assertEqual(_run(events), [])
        self.assertEqual(len(_run(events, min_sources=2)), 1)

    def test_the_sample_is_bounded(self):
        events = []
        for i in range(40):
            events += _blocked(f"10.0.2.{i + 1}")
        f = _run(events)[0]
        self.assertEqual(f.attrs["sources"], 40)
        self.assertEqual(len(f.attrs["sample"]), 10)


class TestTheRuleDescribesItself(unittest.TestCase):

    def test_the_catalog_carries_it_in_both_languages(self):
        with patch("observability.rules.get_app_settings", return_value={}):
            for lang in ("it", "en"):
                ids = {r["id"] for r in rules.catalog(lang)}
                self.assertIn(RULE, ids, lang)

    def test_two_sources_are_not_enough_by_default(self):
        with patch("observability.rules.get_app_settings", return_value={}):
            self.assertGreaterEqual(rules.params_for(RULE)["min_sources"], 3)


if __name__ == "__main__":
    unittest.main()
