# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""SSH and SNMP spans, read back from the SDK's in-memory exporter.

The point of the spans is finding the slow device, so each one must name it;
the point of truncating commands is that a custom command or a config line
can carry a secret, so a span must never hold more than the first words."""
import asyncio
import unittest
from unittest import mock

from netmiko.base_connection import BaseConnection
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from core import net_ssh
from observability.ingesters import snmp_poller

EXPORTER = InMemorySpanExporter()


def setUpModule():
    # The global provider can be set once per process; nothing else in the
    # suite sets one, so this worker's tracers all report here.
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(EXPORTER))
    trace.set_tracer_provider(provider)


class _Conn:
    host = "192.0.2.10"
    device_type = "cisco_ios"


class TestSshSpans(unittest.TestCase):

    def setUp(self):
        EXPORTER.clear()

    def test_netmiko_methods_are_wrapped(self):
        for name in ("send_command", "send_command_timing", "send_config_set"):
            self.assertTrue(hasattr(getattr(BaseConnection, name), "__wrapped__"), name)

    def test_command_span_keeps_three_words_only(self):
        def send_command(self, command_string):
            return "out"

        out = net_ssh._traced_command(send_command)(
            _Conn(), "show running-config | include secret s3cr3t")
        self.assertEqual("out", out)
        (span,) = EXPORTER.get_finished_spans()
        self.assertEqual("ssh.command", span.name)
        self.assertEqual("show running-config |", span.attributes["cli.command"])
        self.assertEqual("192.0.2.10", span.attributes["server.address"])
        self.assertNotIn("s3cr3t", str(dict(span.attributes)))

    def test_config_set_span_counts_lines_without_content(self):
        def send_config_set(self, config_commands=None):
            return ""

        net_ssh._traced_command(send_config_set)(
            _Conn(), config_commands=["username admin secret s3cr3t", "end"])
        (span,) = EXPORTER.get_finished_spans()
        self.assertEqual(2, span.attributes["cli.lines"])
        self.assertNotIn("cli.command", span.attributes)
        self.assertNotIn("s3cr3t", str(dict(span.attributes)))

    def test_connect_span_names_the_device_and_records_failure(self):
        with mock.patch.object(net_ssh, "_connect", side_effect=TimeoutError("no answer")):
            with self.assertRaises(TimeoutError):
                net_ssh.ConnectHandler(host="192.0.2.20", port=2222, device_type="cisco_ios")
        (span,) = EXPORTER.get_finished_spans()
        self.assertEqual("ssh.connect", span.name)
        self.assertEqual("192.0.2.20", span.attributes["server.address"])
        self.assertEqual(2222, span.attributes["server.port"])
        self.assertEqual(trace.StatusCode.ERROR, span.status.status_code)


class TestSnmpSpans(unittest.TestCase):

    def setUp(self):
        EXPORTER.clear()

    def test_round_holds_one_poll_per_device_and_marks_the_silent_one(self):
        devices = [{"ip": "192.0.2.30", "community": "c", "tenant": "t"},
                   {"ip": "192.0.2.31", "community": "c", "tenant": "t"}]

        async def poll(ip, community):
            return [] if ip == "192.0.2.31" else [("system", "{}")]

        with mock.patch.object(snmp_poller, "_snmp_devices", return_value=devices), \
                mock.patch.object(snmp_poller, "_poll_device", side_effect=poll), \
                mock.patch("core.db.enqueue_write"):
            asyncio.run(snmp_poller.poll_once())

        spans = {s.name: s for s in EXPORTER.get_finished_spans() if s.name == "snmp.round"}
        polls = {s.attributes["server.address"]: s
                 for s in EXPORTER.get_finished_spans() if s.name == "snmp.poll"}
        self.assertEqual(2, spans["snmp.round"].attributes["snmp.devices"])
        self.assertFalse(polls["192.0.2.30"].attributes["snmp.silent"])
        self.assertTrue(polls["192.0.2.31"].attributes["snmp.silent"])
        round_id = spans["snmp.round"].context.span_id
        self.assertTrue(all(p.parent.span_id == round_id for p in polls.values()))


if __name__ == "__main__":
    unittest.main()
