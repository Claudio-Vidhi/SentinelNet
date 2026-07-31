"""
Unit tests for core_engine.classify_device_type.

Covers the switch-vs-AP miscategorization fix: a switch whose hostname
contains an AP-ish keyword ("wifi"/"wlan") must still classify as "switch"
when platform/description carries real switch evidence (Catalyst model,
CDP/LLDP capabilities), while a hostname-only AP hint with no stronger
evidence still classifies as "ap".
"""
import unittest

from core.core_engine import classify_device_type


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

    def test_platform_router_evidence_beats_firewall_hostname_token(self):
        # Bug reale (segnalato da review): hostname "fw-edge1" contiene il
        # token "fw" (firewall), ma la platform CDP "Cisco ISR4321" e'
        # evidenza reale di router. Platform deve battere l'hostname: prima
        # del fix, hostname e platform erano fusi in un'unica stringa
        # valutata per _TYPE_ORDER (firewall prima di router), quindi il
        # token debole nel nome vinceva sull'evidenza CDP/LLDP reale.
        self.assertEqual(
            classify_device_type("fw-edge1", platform="Cisco ISR4321"),
            "router",
        )

    def test_description_wlc_evidence_beats_firewall_hostname_token(self):
        # Stesso bug lato description: hostname "fw-backup1" (token "fw")
        # contro una System Description LLDP che descrive un vero Wireless
        # LAN Controller Aruba. La description deve prevalere sull'hostname.
        self.assertEqual(
            classify_device_type("fw-backup1", description="Aruba Wireless LAN Controller"),
            "wlc",
        )

    def test_router_capability_beats_server_hostname_token(self):
        # Bug reale: CDP Capabilities "Router" e' il segnale piu' affidabile,
        # ma un hostname con il token debole "srv" (es. "srv-core-01",
        # convenzione di naming del sito) veniva classificato "server" prima
        # ancora di controllare le capabilities, perche' il fallback
        # "router" in caps era in fondo alla funzione, raggiunto solo se
        # nessuna keyword hostname/description/platform avesse gia' fatto
        # match. Le capabilities devono avere precedenza assoluta.
        self.assertEqual(
            classify_device_type("srv-core-01", capabilities="Router"),
            "router",
        )

    def test_ap_software_description_beats_router_capability(self):
        # Bug reale: un AP Cisco lightweight annuncia Capabilities CDP
        # "Router Trans-Bridge". Le capabilities avevano precedenza assoluta,
        # quindi l'AP finiva classificato "router" nonostante la System
        # Description LLDP dicesse esplicitamente "Cisco AP Software".
        self.assertEqual(
            classify_device_type(
                "site-ap-01",
                description="Cisco AP Software, ap1g7-k9w8 Version: 1.2.3",
                capabilities="Router Trans-Bridge",
            ),
            "ap",
        )

    def test_ap_platform_model_beats_router_capability(self):
        # Stesso bug con il solo CDP (nessuna System Description LLDP): il
        # modello nella Platform e' l'unica evidenza di AP disponibile.
        self.assertEqual(
            classify_device_type(
                "node-42",
                platform="cisco C9105AXI-E",
                capabilities="Router Trans-Bridge",
            ),
            "ap",
        )

    def test_router_platform_beats_switch_capability(self):
        # Bug reale: un router L3 annuncia Capabilities CDP "Router Switch IGMP"
        # come qualsiasi switch multilayer, e il ramo "switch in caps" chiudeva
        # la classificazione prima di leggere il modello nella Platform.
        self.assertEqual(
            classify_device_type(
                "site-gw-01",
                platform="cisco ISR4321/K9",
                capabilities="Router Switch IGMP",
            ),
            "router",
        )

    def test_multilayer_switch_still_switch_with_router_capability(self):
        # Contro-prova: stesse Capabilities, ma Platform di switch -> switch.
        self.assertEqual(
            classify_device_type(
                "site-sw-01",
                platform="cisco WS-C3850-12XS",
                capabilities="Router Switch IGMP",
            ),
            "switch",
        )

    def test_network_camera_description_is_camera(self):
        # Le telecamere IP si annunciano solo via LLDP (nessuna Capability CDP)
        # e prima finivano nel generico "client".
        self.assertEqual(
            classify_device_type(
                "site-cam-01",
                description="ACME M1234 Fixed Dome Network Camera 1.2.3",
            ),
            "camera",
        )


if __name__ == "__main__":
    unittest.main()
