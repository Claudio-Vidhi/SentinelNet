# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for passive OT protocol tagging across flow, syslog, and mirror metadata."""
import json
import os
import tempfile
import time
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_ot_proto_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import db  # noqa: E402
from observability import fieldmap, normalize  # noqa: E402
from observability.ingesters import ot_protocols, syslog  # noqa: E402


class TestOtPassiveProtocolClassification(unittest.TestCase):
    def test_all_8_ot_protocols_by_port_and_transport(self):
        cases = [
            ("TCP", 502, "modbus_tcp", "Modbus TCP"),
            ("TCP", 102, "s7comm", "S7comm"),
            ("TCP", 44818, "ethernet_ip", "EtherNet/IP"),
            ("UDP", 2222, "ethernet_ip", "EtherNet/IP"),
            ("TCP", 4840, "opc_ua", "OPC-UA"),
            ("UDP", 34962, "profinet", "PROFINET"),
            ("UDP", 34963, "profinet", "PROFINET"),
            ("UDP", 34964, "profinet", "PROFINET"),
            ("UDP", 47808, "bacnet", "BACnet"),
            ("TCP", 2404, "iec_104", "IEC 60870-5-104"),
            ("TCP", 20000, "dnp3", "DNP3"),
            ("UDP", 20000, "dnp3", "DNP3"),
        ]
        for proto, port, expected_id, expected_name in cases:
            hit = ot_protocols.identify_ot_protocol(protocol=proto, dst_port=port)
            self.assertIsNotNone(hit, f"Expected match for {proto}/{port}")
            self.assertEqual(hit["id"], expected_id)
            self.assertEqual(hit["name"], expected_name)
            self.assertEqual(hit["port"], port)

    def test_source_port_reply_classification(self):
        hit = ot_protocols.identify_ot_protocol(protocol="6", src_port=502, dst_port=51234)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["id"], "modbus_tcp")

    def test_profinet_ethertype_classification(self):
        for et in (0x8892, "0x8892", "34962"):
            hit = ot_protocols.identify_ot_protocol(ethertype=0x8892 if et == "34962" else et)
            self.assertIsNotNone(hit)
            self.assertEqual(hit["id"], "profinet")
            self.assertEqual(hit["transport"], "L2")

    def test_keyword_classification_from_syslog_or_mirror(self):
        messages = {
            'app="Modbus-TCP" action="accept"': "modbus_tcp",
            'service="S7comm" srcip=192.0.2.10 dstip=192.0.2.20': "s7comm",
            'msg="EtherNet/IP CIP session established"': "ethernet_ip",
            'app="OPC-UA" dstip=192.0.2.25': "opc_ua",
            'msg="PROFINET-RT frame seen on mirror port"': "profinet",
            'service="BACnet/IP" srcip=192.0.2.30': "bacnet",
            'app="IEC-60870-5-104" action="accept"': "iec_104",
            'msg="DNP3 outstation response"': "dnp3",
        }
        for text, expected in messages.items():
            hit = ot_protocols.identify_ot_protocol(message=text)
            self.assertIsNotNone(hit, f"Expected match for {text!r}")
            self.assertEqual(hit["id"], expected)

    def test_non_ot_traffic_returns_none(self):
        hit = ot_protocols.identify_ot_protocol(
            protocol="TCP", src_port=54321, dst_port=443, message="HTTPS traffic"
        )
        self.assertIsNone(hit)

    def test_tag_record_enriches_flow_and_mirror_dicts(self):
        flow_rec = {"src_ip": "192.0.2.10", "dst_ip": "192.0.2.20", "proto": "6", "dst_port": 102}
        tagged = ot_protocols.tag_record(flow_rec)
        self.assertEqual(tagged["ot_protocol"], "s7comm")
        self.assertEqual(tagged["ot_protocol_name"], "S7comm")

        mirror_rec = {"src_mac": "00:0e:8c:00:00:01", "ethertype": "0x8892"}  # (check-private-data: ok)
        tagged_l2 = ot_protocols.tag_record(mirror_rec)
        self.assertEqual(tagged_l2["ot_protocol"], "profinet")


class TestFieldmapSyslogAndNormalizeIntegration(unittest.TestCase):
    def setUp(self):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()

    def test_fieldmap_extracts_ot_protocol(self):
        msg = (
            'date=2026-11-18 time=10:00:00 srcip=192.0.2.10 dstip=192.0.2.20 '
            'srcport=49152 dstport=502 proto=6 action="accept"'
        )
        fields = fieldmap.extract(msg)
        self.assertEqual(fields["ot_protocol"], "modbus_tcp")

    def test_syslog_parse_includes_ot_protocol(self):
        raw = (
            b'<134>date=2026-11-18 time=10:00:00 devname="FGT" '
            b'srcip=192.0.2.10 dstip=192.0.2.20 dstport=44818 proto=6 action="accept"'
        )
        parsed = syslog.parse(raw, "192.0.2.1")[0]
        self.assertEqual(parsed["ot_protocol"], "ethernet_ip")

    def test_normalize_projects_ot_protocol_into_event_attrs(self):
        now = int(time.time())
        conn = db.get_observability_connection()
        conn.execute(
            """INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message, exporter_ip)
               VALUES (?, 'sede-ot', '192.0.2.1', 5, 'accept',
                       'srcip=192.0.2.10 dstip=192.0.2.20 dstport=2404 proto=6 action=accept',
                       '192.0.2.1')""",
            (now,),
        )
        conn.commit()
        conn.close()

        counts = normalize.normalize_once(now=now)
        self.assertEqual(counts["syslog"], 1)

        conn = db.get_observability_connection()
        row = conn.execute("SELECT attrs_json FROM events WHERE source = 'syslog'").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        attrs = json.loads(row["attrs_json"])
        self.assertEqual(attrs.get("ot_protocol"), "iec_104")


if __name__ == "__main__":
    unittest.main()
