# -*- coding: utf-8 -*-
"""AP serial comes from one bulk inventory command, never one per AP.

'show ap summary' carries no serial on either platform. The inventory command
does, and it returns every AP in a single round-trip.
"""
import unittest

# Shape of 'show ap inventory all' on AireOS. Invented names and serials.
INVENTORY_OUTPUT = """
AP Name : ap-lobby
NAME: "ap-lobby" , DESCR: "Example Access Point"
PID: AIR-EXAMPLE-K9,  VID: V01,  SN: FCW0000AAAA

AP Name : ap-floor2
NAME: "ap-floor2" , DESCR: "Example Access Point"
PID: AIR-EXAMPLE-K9,  VID: V01,  SN: FCW0000BBBB
"""


class ParseApInventory(unittest.TestCase):
    def test_every_ap_maps_to_its_serial(self):
        from services import wlc_service
        self.assertEqual({"ap-lobby": "FCW0000AAAA", "ap-floor2": "FCW0000BBBB"},
                         wlc_service.parse_ap_inventory(INVENTORY_OUTPUT))

    def test_empty_output_is_an_empty_map_not_an_error(self):
        from services import wlc_service
        self.assertEqual({}, wlc_service.parse_ap_inventory(""))

    def test_output_without_serials_yields_nothing(self):
        from services import wlc_service
        self.assertEqual({}, wlc_service.parse_ap_inventory("AP Name : ap-lobby\n"))


class OverviewRecordsSerials(unittest.TestCase):
    """The tab visit is what fills the store, so the export never needs SSH."""

    def test_a_failing_inventory_command_still_returns_the_other_aps(self):
        from unittest import mock
        from services import wlc_service

        def fake_send(conn, command, timeout=30):
            if "inventory" in command:
                raise RuntimeError("read-only account")
            if "ap summary" in command:
                return ("AP Name          IP Address     AP Model     Status\n"
                        "---------------  -------------  -----------  --------\n"
                        "ap-lobby         192.0.2.50     AIR-EXAMPLE  Registered\n")
            return ""

        @wlc_service.contextmanager
        def fake_session(device, timeout=30):
            yield object(), "aireos", ""

        with mock.patch.object(wlc_service, "_send", fake_send), \
             mock.patch.object(wlc_service, "_session", fake_session), \
             mock.patch("services.ap_store.record_aps", return_value=0) as rec:
            result = wlc_service.overview({"IP": "192.0.2.10", "Group": "ACME"})

        self.assertEqual(1, len(result["aps"]))
        self.assertNotIn("serial", result["aps"][0])
        rec.assert_called_once()


if __name__ == "__main__":
    unittest.main()
