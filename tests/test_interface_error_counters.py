# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Interface error counters: increments and verdicts, and the per-vendor CLI
parsers against outputs shaped like the vendors' documentation."""

import unittest

from collectors import iface_counters_cli as cli
from observability import iface_errors as ie


class TestIncrements(unittest.TestCase):

    def test_absolute_values_do_not_count_only_growth(self):
        out = ie.summarize([(0, {"crc": 5000}), (60, {"crc": 5000})])
        self.assertEqual(out["status"], "clean")
        self.assertEqual(out["delta"], {"crc": 0})

    def test_a_reset_mid_window_keeps_the_errors_after_it(self):
        # 100 -> 130 (+30), reset (step not counted), 2 -> 7 (+5): 35,
        # not 7 - 100 = -93.
        out = ie.summarize([(0, {"crc": 100}), (60, {"crc": 130}),
                            (120, {"crc": 2}), (180, {"crc": 7})])
        self.assertEqual(out["delta"]["crc"], 35)
        self.assertTrue(out["reset"])
        self.assertEqual(out["worst_class"], "physical")

    def test_garbage_jumping_between_values_invents_no_errors(self):
        out = ie.summarize([(0, {"crc": 3067064320, "in_errors": 0}),
                            (60, {"crc": 2501716344, "in_errors": 0}),
                            (120, {"crc": 3067064320, "in_errors": 0})])
        self.assertEqual(out["status"], "clean")
        out = ie.summarize([(0, {"late_collisions": 900}), (60, {"late_collisions": 10}),
                            (120, {"late_collisions": 900})])
        self.assertEqual(out["delta"]["late_collisions"], 890)

    def test_a_detail_larger_than_its_total_is_dropped(self):
        # Agent garbage: billions of detail errors with ifInErrors at 0.
        self.assertEqual(ie.counters_of({"in_errors": 0, "out_errors": 0, "crc": 255,
                                         "giants": 2501716344, "late_collisions": 7}),
                         {"in_errors": 0, "out_errors": 0})
        self.assertEqual(ie.counters_of({"in_errors": 9, "crc": 7}), {"in_errors": 9, "crc": 7})
        self.assertEqual(ie.counters_of({"crc": 7}), {"crc": 7})

    def test_one_sample_is_not_a_verdict(self):
        self.assertEqual(ie.summarize([(0, {"crc": 9})])["status"], "single_sample")

    def test_no_counters_is_not_clean(self):
        self.assertEqual(ie.summarize([(0, {"link": "up"}), (60, {})])["status"], "no_counters")

    def test_discards_alone_are_not_errors(self):
        out = ie.summarize([(0, {"out_discards": 1, "crc": 0}), (60, {"out_discards": 50, "crc": 0})])
        self.assertEqual(out["status"], "discards")
        self.assertEqual(out["errors"], 0)
        self.assertEqual(out["discards"], 49)

    def test_worst_class_orders_duplex_before_generic_errors(self):
        self.assertEqual(ie.verdict({"in_errors": 10, "late_collisions": 1}),
                         ("erroring", "duplex", 11))

    def test_a_detail_inside_its_total_is_not_counted_twice(self):
        # 13 input errors that were all symbol errors read "26 · physical".
        self.assertEqual(ie.verdict({"in_errors": 13, "symbol": 13}),
                         ("erroring", "physical", 13))
        # Without the total the detail is the only measure, and it counts.
        self.assertEqual(ie.verdict({"crc": 4}), ("erroring", "physical", 4))

    def test_ranking_puts_erroring_ports_first(self):
        rows = [{"status": "clean"}, {"status": "erroring", "worst_class": "errors", "errors": 5},
                {"status": "erroring", "worst_class": "physical", "errors": 1}]
        rows.sort(key=ie.status_rank)
        self.assertEqual([r.get("worst_class") for r in rows], ["physical", "errors", None])

    def test_read_result_marks_ports_without_a_first_reading(self):
        out = ie.read_result({"Gi1/0/1": {"crc": 1}},
                             {"Gi1/0/1": {"crc": 4}, "Gi1/0/2": {"crc": 0}})
        self.assertEqual(out["Gi1/0/1"]["delta"], {"crc": 3})
        self.assertEqual(out["Gi1/0/2"]["status"], "single_sample")


CISCO_IOS = """\
GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aabb.ccdd.ee01 (bia aabb.ccdd.ee01)
  Input queue: 0/2000/12/0 (size/max/drops/flushes); Total output drops: 34
     1,234 packets input, 567890 bytes, 0 no buffer
     3 runts, 4 giants, 0 throttles
     10 input errors, 7 CRC, 2 frame, 0 overrun, 0 ignored
     0 watchdog, 0 multicast, 0 pause input
     5 output errors, 6 collisions, 3 interface resets
     0 babbles, 1 late collision, 0 deferred
     2 lost carrier, 0 no carrier, 0 pause output
GigabitEthernet1/0/2 is administratively down, line protocol is down (disabled)
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
"""

NXOS = """\
Ethernet1/1 is up
admin state is up, Dedicated Interface
  RX
    100 unicast packets  0 multicast packets  0 broadcast packets
    1 runts  2 giants  3 CRC/FCS  0 no buffer
    4 input error  0 short frame  0 overrun   0 underrun  0 ignored
    0 input with dribble  5 input discard
  TX
    6 output error  7 collision  0 deferred  8 late collision
    0 lost carrier  0 no carrier  0 babble  9 output discard
"""

JUNOS = """\
Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Input errors:
    Errors: 11, Drops: 12, Framing errors: 13, Runts: 14, Policed discards: 0,
    L3 incompletes: 0, L2 channel errors: 0, FIFO errors: 0, Resource errors: 0
  Output errors:
    Carrier transitions: 3, Errors: 21, Drops: 22, Collisions: 23, Aged packets: 0
  MAC statistics:                      Receive         Transmit
    Total octets                          1000             2000
    CRC/Align errors                         31                0
    Oversized frames                         32
  Logical interface ge-0/0/0.0 (Index 70) (SNMP ifIndex 520)
    Input errors:
      Errors: 999, Drops: 999
Physical interface: ge-0/0/1, Enabled, Physical link is Down
  Input errors:
    Errors: 0, Drops: 0, Framing errors: 0, Runts: 0
"""

PROCURVE_TABLE = """\
 Status and Counters - Port Counters

  Port  | Total Bytes  Total Frames Errors Rx  Errors Tx  Drops Tx  Flow Ctrl
  ----- + ------------ ------------ ---------- ---------- --------- ---------
  1     | 1,234,567    12,345       4          5          6         off
  A2    | 0            0            0          0          0         off
"""

PROCURVE_DETAIL = """\
 Status and Counters - Port Counters for port 7

  Errors (Since boot or last clear) :
   FCS Rx          : 1                Drops Tx        : 2
   Alignment Rx    : 3                Collisions Tx   : 4
   Runts Rx        : 5                Late Colln Tx   : 6
   Giants Rx       : 7                Excessive Colln : 8
   Total Rx Errors : 9                Deferred Tx     : 0
"""

AOSCX = """\
Interface 1/1/1 is up
 Admin state is up
 Statistics            RX                   TX                   Total
 ---------------------- -------------------- -------------------- --------------------
 Packets                                 10                   20                   30
 Dropped                                 1                    2                    3
 Errors                                  4                    5                    9
   CRC/FCS                               6                  n/a                    6
   Collision                           n/a                    7                    7
"""

AOSCX_OLD = """\
Interface 1/1/2 is up
 RX
            0 input packets              0 bytes
            3 input error                4 dropped
            5 CRC/FCS
 TX
            0 output packets             0 bytes
            6 input error                7 dropped
            8 collision
"""

FORTIOS = """\
if=port1 family=00 type=1 index=3 mtu=1500 link=0 master=0
ref=19 state=start present fw_flags=0 flags=up broadcast run multicast
stat: rxp=101 txp=202 rxb=303 txb=404 rxe=1 txe=2 rxd=3 txd=4 mc=0 collision=5 @ time=1700000000
re: rxl=0 rxo=0 rxc=6 rxf=7 rxfi=0 rxm=0
te: txa=0 txc=8 txfi=0 txh=0 txw=0
"""

PANOS = """\
-------------------------------------------------------------------------------
Interface: ethernet1/1
-------------------------------------------------------------------------------
Hardware interface counters read from MAC:
-------------------------------------------------------------------------------
bytes received                1000
receive errors                1
transmit errors               2
receive discarded             3
-------------------------------------------------------------------------------
Software interface counters:
-------------------------------------------------------------------------------
receive errors                900
"""


class TestCliParsers(unittest.TestCase):

    def test_cisco_ios(self):
        out = cli.parse_cisco(CISCO_IOS)
        self.assertEqual(out["GigabitEthernet1/0/1"], {
            "in_discards": 12, "out_discards": 34, "runts": 3, "giants": 4,
            "in_errors": 10, "crc": 7, "alignment": 2, "out_errors": 5,
            "late_collisions": 1, "carrier_sense": 2})
        self.assertEqual(out["GigabitEthernet1/0/2"]["crc"], 0)

    def test_nxos(self):
        self.assertEqual(cli.parse_cisco(NXOS)["Ethernet1/1"], {
            "runts": 1, "giants": 2, "crc": 3, "in_errors": 4, "in_discards": 5,
            "out_errors": 6, "late_collisions": 8,
            "carrier_sense": 0, "out_discards": 9})

    def test_junos_skips_logical_units(self):
        out = cli.parse_junos(JUNOS)
        self.assertEqual(out["ge-0/0/0"], {
            "in_errors": 11, "in_discards": 12, "alignment": 13, "runts": 14,
            "out_errors": 21, "out_discards": 22,
            "crc": 31, "giants": 32})
        self.assertEqual(out["ge-0/0/1"]["in_errors"], 0)

    def test_procurve_summary_table(self):
        out = cli.parse_procurve(PROCURVE_TABLE)
        self.assertEqual(out["1"], {"in_errors": 4, "out_errors": 5, "out_discards": 6})
        self.assertIn("A2", out)

    def test_procurve_port_detail(self):
        self.assertEqual(cli.parse_procurve(PROCURVE_DETAIL)["7"], {
            "crc": 1, "out_discards": 2, "alignment": 3,
            "runts": 5, "late_collisions": 6, "giants": 7,
            "excessive_collisions": 8, "in_errors": 9})

    def test_aoscx_table(self):
        self.assertEqual(cli.parse_aruba(AOSCX)["1/1/1"], {
            "in_discards": 1, "out_discards": 2, "in_errors": 4, "out_errors": 5,
            "crc": 6})

    def test_aoscx_older_pairs(self):
        self.assertEqual(cli.parse_aruba(AOSCX_OLD)["1/1/2"], {
            "in_errors": 3, "in_discards": 4, "crc": 5,
            "out_errors": 6, "out_discards": 7})

    def test_aruba_falls_back_to_procurve_output(self):
        self.assertIn("1", cli.parse_aruba(PROCURVE_TABLE))

    def test_fortios(self):
        self.assertEqual(cli.parse_fortios(FORTIOS)["port1"], {
            "in_errors": 1, "out_errors": 2, "in_discards": 3, "out_discards": 4,
            "crc": 6, "alignment": 7, "carrier_sense": 8})

    def test_panos_reads_hardware_counters_only(self):
        self.assertEqual(cli.parse_panos(PANOS)["ethernet1/1"],
                         {"in_errors": 1, "out_errors": 2, "in_discards": 3})

    def test_unrecognised_output_is_empty_not_zeros(self):
        for parser in (cli.parse_cisco, cli.parse_junos, cli.parse_procurve,
                       cli.parse_aruba, cli.parse_fortios, cli.parse_panos):
            self.assertEqual(parser("% Invalid input detected at '^' marker."), {})

    def test_every_parsed_field_is_in_the_vocabulary(self):
        for text, parser in ((CISCO_IOS, cli.parse_cisco), (NXOS, cli.parse_cisco),
                             (JUNOS, cli.parse_junos), (PROCURVE_DETAIL, cli.parse_procurve),
                             (AOSCX, cli.parse_aruba), (FORTIOS, cli.parse_fortios),
                             (PANOS, cli.parse_panos)):
            for counters in parser(text).values():
                self.assertLessEqual(set(counters), set(ie.FIELDS))


class TestSnmpErrorColumns(unittest.IsolatedAsyncioTestCase):

    async def test_columns_are_merged_per_ifindex(self):
        from unittest.mock import patch
        from observability.ingesters import snmp_poller
        walks = {"1.3.6.1.2.1.2.2.1.14": {"1": 3},            # ifInErrors
                 "1.3.6.1.2.1.10.7.2.1.3": {"1": 2},          # FCS
                 "1.3.6.1.2.1.10.7.2.1.8": {"1": 4, "2": 1}}  # late collisions

        async def fake(engine, auth, target, context, oid):
            return dict(walks.get(oid, {}))
        with patch.object(snmp_poller, "_walk_column", side_effect=fake):
            out = await snmp_poller._error_counters(None, None, None, None)
        self.assertEqual(out, {"1": {"in_errors": 3, "crc": 2, "late_collisions": 4},
                               "2": {"late_collisions": 1}})

    def test_every_snmp_field_is_in_the_vocabulary(self):
        from observability.ingesters import snmp_poller
        self.assertLessEqual(set(snmp_poller._ERROR_COLUMNS.values()), set(ie.FIELDS))


if __name__ == "__main__":
    unittest.main()
