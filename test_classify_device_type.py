"""
Unit tests for core_engine.classify_device_type.

Covers the switch-vs-AP miscategorization fix: a switch whose hostname
contains an AP-ish keyword ("wifi"/"wlan") must still classify as "switch"
when platform/description carries real switch evidence (Catalyst model,
CDP/LLDP capabilities), while a hostname-only AP hint with no stronger
evidence still classifies as "ap".
"""
import unittest

from core_engine import classify_device_type


class TestClassifyDeviceType(unittest.TestCase):

    def test_switch_capability_wins_over_wifi_hostname(self):
        # Pre-existing behavior: CDP "Switch" capability beats hostname noise.
        self.assertEqual(
            classify_device_type("SW-WIFI-01", capabilities="Switch"),
            "switch",
        )

    def test_ap_capability_still_ap(self):
        self.assertEqual(
            classify_device_type("SW-WIFI-01", capabilities="Access Point"),
            "ap",
        )

    def test_catalyst_platform_beats_wifi_hostname(self):
        self.assertEqual(
            classify_device_type("sw-wifi-floor2", platform="Cisco Catalyst 9300"),
            "switch",
        )

    def test_catalyst_description_beats_wifi_hostname(self):
        self.assertEqual(
            classify_device_type("sw-wifi-floor2", description="Cisco Catalyst 9300"),
            "switch",
        )

    def test_ws_c_platform_token_is_switch(self):
        self.assertEqual(
            classify_device_type("wlan-uplink-sw", platform="WS-C2960X-24TS-L"),
            "switch",
        )

    def test_hostname_only_wifi_still_ap_without_stronger_evidence(self):
        self.assertEqual(
            classify_device_type("wlan-ap-01"),
            "ap",
        )

    def test_hostname_switch_keyword_alone_not_confused(self):
        # "switch" keyword in description/platform (not hostname) still wins.
        self.assertEqual(
            classify_device_type("wifi-ap-lobby", description="24-port switch"),
            "switch",
        )

    def test_firewall_still_takes_precedence_over_switch_evidence(self):
        self.assertEqual(
            classify_device_type("fw-catalyst-lab", description="FortiGate switch module"),
            "firewall",
        )

    def test_no_evidence_falls_back_to_client(self):
        self.assertEqual(classify_device_type(), "client")


if __name__ == "__main__":
    unittest.main()
