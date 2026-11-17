# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for opt-in, rate-limited, read-only OT probe tasks in probe_agent."""
import json
import struct
import unittest
from unittest.mock import MagicMock, patch

from services import probe_agent


def _make_agent(ot_probes_enabled=False, min_interval_s=300):
    cfg = {
        "central_url": "https://192.0.2.1:8000",
        "probe_id": "ot-site",
        "token": "tok",
        "syslog_enabled": False,
        "ot_probes_enabled": ot_probes_enabled,
        "ot_probe_min_interval_s": min_interval_s,
    }
    return probe_agent.Agent(cfg)


class TestOtProbeOptInAndRateLimit(unittest.TestCase):
    def test_blocked_by_default_when_site_disabled(self):
        agent = _make_agent(ot_probes_enabled=False)
        dev = {"IP": "192.0.2.50", "Vendor": "siemens", "ot_probe_enabled": True}
        with patch("socket.create_connection") as m_conn:
            res = agent.run_ot_probe(dev, "modbus")
            m_conn.assert_not_called()
        self.assertEqual(res["status"], "blocked")

    def test_blocked_when_device_not_opted_in(self):
        agent = _make_agent(ot_probes_enabled=True)
        dev = {"IP": "192.0.2.50", "Vendor": "siemens"}  # no ot_probe_enabled or ot_probes
        with patch("socket.create_connection") as m_conn:
            res = agent.run_ot_probe(dev, "modbus")
            m_conn.assert_not_called()
        self.assertEqual(res["status"], "blocked")

    def test_blocked_for_manual_device(self):
        agent = _make_agent(ot_probes_enabled=True)
        dev = {
            "IP": "192.0.2.50",
            "Vendor": "siemens",
            "Transports": '{"manual": null}',
            "ot_probe_enabled": True,
        }
        with patch("socket.create_connection") as m_conn:
            res = agent.run_ot_probe(dev, "modbus")
            m_conn.assert_not_called()
        self.assertEqual(res["status"], "blocked")

    def test_blocked_when_protocol_not_in_device_allowlist(self):
        agent = _make_agent(ot_probes_enabled=True)
        dev = {"IP": "192.0.2.50", "ot_probes": ["modbus"]}
        with patch("socket.create_connection") as m_conn:
            res = agent.run_ot_probe(dev, "ethernet_ip")
            m_conn.assert_not_called()
        self.assertEqual(res["status"], "blocked")

    def test_rate_limited_on_back_to_back_calls(self):
        agent = _make_agent(ot_probes_enabled=True, min_interval_s=120)
        dev = {"IP": "192.0.2.50", "ot_probe_enabled": True}
        with patch.object(agent, "_probe_modbus", return_value={"vendor_name": "Siemens"}) as m_probe:
            first = agent.run_ot_probe(dev, "modbus")
            second = agent.run_ot_probe(dev, "modbus")
            self.assertEqual(m_probe.call_count, 1)
        self.assertEqual(first["status"], "ok")
        self.assertEqual(second["status"], "rate_limited")
        self.assertGreater(second["retry_after_s"], 0)

    def test_unsupported_protocol_raises_value_error(self):
        agent = _make_agent(ot_probes_enabled=True)
        dev = {"IP": "192.0.2.50", "ot_probe_enabled": True}
        with self.assertRaises(ValueError):
            agent.run_ot_probe(dev, "s7comm_write")


class TestReadOnlyOtPacketBuildersAndParsers(unittest.TestCase):
    def test_enip_list_identity_roundtrip(self):
        req = probe_agent.build_enip_list_identity()
        self.assertEqual(len(req), 24)
        cmd, length, session, status, ctx, opts = struct.unpack("<HHII8sI", req)
        self.assertEqual(cmd, 0x0063)  # ListIdentity only
        self.assertEqual(length, 0)
        self.assertEqual(session, 0)
        self.assertEqual(status, 0)
        self.assertEqual(opts, 0)

        # Build synthetic CIP Identity item response
        prod_name = b"1756-L83E/B"  # (check-private-data: ok)
        cip_item = (
            struct.pack("<H", 1)
            + b"\x00" * 16
            + struct.pack("<HHHBBHI", 1, 14, 166, 33, 11, 0x0060, 0x12345678)
            + bytes([len(prod_name)])
            + prod_name
        )
        body = struct.pack("<HHH", 1, 0x000C, len(cip_item)) + cip_item
        resp = struct.pack("<HHII8sI", 0x0063, len(body), 0, 0, b"SENTINEL", 0) + body

        parsed = probe_agent.parse_enip_list_identity(resp)
        self.assertEqual(parsed["vendor_id"], 1)
        self.assertEqual(parsed["device_type"], 14)
        self.assertEqual(parsed["product_code"], 166)
        self.assertEqual(parsed["revision"], "33.11")
        self.assertEqual(parsed["serial"], "12345678")
        self.assertEqual(parsed["product_name"], "1756-L83E/B")  # (check-private-data: ok)

    def test_modbus_fc43_mei14_roundtrip(self):
        req = probe_agent.build_modbus_read_device_id(unit_id=1, read_code=1, object_id=0)
        self.assertEqual(len(req), 11)
        # Function code at index 7 must be 0x2B (43), MEI type at index 8 must be 0x0E (14)
        self.assertEqual(req[7], 0x2B)
        self.assertEqual(req[8], 0x0E)
        with self.assertRaises(ValueError):
            probe_agent.build_modbus_read_device_id(read_code=99)

        # Synthetic FC 43 / MEI 14 response with 3 objects (VendorName, ProductCode, Revision)
        objs = (
            b"\x00\x07Siemens"  # (check-private-data: ok)
            b"\x01\x07S7-1500"  # (check-private-data: ok)
            b"\x02\x05V2.9 "
        )
        pdu = struct.pack(">BBBBBBB", 0x2B, 0x0E, 1, 1, 0, 0, 3) + objs
        mbap = struct.pack(">HHHB", 1, 0, len(pdu) + 1, 1)
        parsed = probe_agent.parse_modbus_read_device_id(mbap + pdu)
        self.assertEqual(parsed["vendor_name"], "Siemens")  # (check-private-data: ok)
        self.assertEqual(parsed["product_code"], "S7-1500")  # (check-private-data: ok)
        self.assertEqual(parsed["revision"], "V2.9")

    def test_opcua_hello_and_ack_roundtrip(self):
        url = "opc.tcp://192.0.2.60:4840"
        hel = probe_agent.build_opcua_hello(url)
        self.assertTrue(hel.startswith(b"HELF"))
        get_ep = probe_agent.build_opcua_get_endpoints_request(url)
        self.assertTrue(get_ep.startswith(b"MSGF"))

        ack = b"ACKF" + struct.pack("<IIIIII", 28, 0, 65536, 65536, 0, 0)
        parsed = probe_agent.parse_opcua_response(ack)
        self.assertEqual(parsed["message_type"], "ACK")
        self.assertEqual(parsed["receive_buffer_size"], 65536)

    def test_bacnet_who_is_and_i_am_roundtrip(self):
        who_is = probe_agent.build_bacnet_who_is()
        self.assertEqual(who_is, bytes((0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08)))

        # Synthetic BACnet/IP I-Am: Object Identifier (device=8, instance=1234), MaxAPDU=1476, Seg=0, VendorId=7
        obj_id = (8 << 22) | 1234
        apdu = (
            bytes((0x10, 0x00, 0xC4))
            + struct.pack(">I", obj_id)
            + bytes((0x22, 0x05, 0xC4, 0x91, 0x00, 0x21, 0x07))
        )
        pkt = bytes((0x81, 0x0A)) + struct.pack(">H", 6 + len(apdu)) + bytes((0x01, 0x00)) + apdu
        parsed = probe_agent.parse_bacnet_i_am(pkt)
        self.assertEqual(parsed["service"], "I-Am")
        self.assertEqual(parsed["object_type"], 8)
        self.assertEqual(parsed["device_instance"], 1234)
        self.assertEqual(parsed["vendor_id"], 7)

    def test_run_jobs_ot_probe_dispatch(self):
        agent = _make_agent(ot_probes_enabled=True)
        devices = [{"IP": "192.0.2.50", "Vendor": "siemens", "ot_probe_enabled": True}]
        agent._get = MagicMock(
            return_value=MagicMock(
                raise_for_status=lambda: None,
                json=lambda: {
                    "jobs": [
                        {
                            "id": 42,
                            "device_ip": "192.0.2.50",
                            "kind": "ot_probe",
                            "command": json.dumps({"protocol": "modbus"}),
                        }
                    ]
                },
            )
        )
        posted = []
        agent._post = MagicMock(
            side_effect=lambda path, payload: (
                posted.append((path, payload)) or MagicMock(raise_for_status=lambda: None)
            )
        )
        with patch.object(agent, "_probe_modbus", return_value={"vendor_name": "Siemens"}):
            agent.run_jobs(devices)
        self.assertEqual(len(posted), 1)
        self.assertEqual(posted[0][0], "/api/agent/jobs/42/result")
        self.assertEqual(posted[0][1]["status"], "done")
        res_payload = json.loads(posted[0][1]["result"])
        self.assertEqual(res_payload["identity"]["vendor_name"], "Siemens")


if __name__ == "__main__":
    unittest.main()
