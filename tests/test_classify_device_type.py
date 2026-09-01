"""
Unit tests for core_engine.classify_device_type.

Covers the switch-vs-AP miscategorization fix: a switch whose hostname
contains an AP-ish keyword ("wifi"/"wlan") must still classify as "switch"
when platform/description carries real switch evidence (Catalyst model,
CDP/LLDP capabilities), while a hostname-only AP hint with no stronger
evidence still classifies as "ap".
"""
import unittest

from core.core_engine import classify_by_model, classify_device_type


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


class TestClassifyByModel(unittest.TestCase):
    """The model number alone must name the product line.

    Every string below is a family Cisco actually ships. The interesting cases
    are the collisions: the same number means different hardware depending on
    the line it belongs to, which is why the rules are ordered.
    """

    SWITCHES = ("WS-C2960X-24PS-L", "WS-C3850-24T", "C9300-48P", "C9500-16X",
                "Catalyst 9200L", "WS-C6807-XL", "IE-4010-16S12P", "C9350-48T",
                "C9610R", "N9K-C93180YC-EX")
    APS = ("C9105AXW", "C9115AXI-E", "C9124AXD", "C9136I-B", "C9163E",
           "CW9166I-E", "IW9167EH", "AIR-AP1852I-E-K9", "AIR-CAP2702I-E-K9")
    WLCS = ("C9800-40-K9", "C9800-CL", "AIR-CT5520-K9")
    ROUTERS = ("ISR4331/K9", "ASR1001-X", "C8300-1N1S-4T2X", "C8500L-8S4X",
               "C1111-8P")
    FIREWALLS = ("ASA5525-X", "FPR-2110", "FPR9300")

    def test_each_family_resolves_to_its_product_line(self):
        for expected, models in (("switch", self.SWITCHES), ("ap", self.APS),
                                 ("wlc", self.WLCS), ("router", self.ROUTERS),
                                 ("firewall", self.FIREWALLS)):
            for model in models:
                with self.subTest(model=model):
                    self.assertEqual(classify_by_model(model), expected)

    def test_an_unknown_or_empty_model_decides_nothing(self):
        # None, never a guess: the caller has to fall through to the weaker
        # signals instead of being handed a wrong answer with full authority.
        for model in ("", "Non Rilevato", "FortiGate-120G", "VM (VMware)"):
            with self.subTest(model=model):
                self.assertIsNone(classify_by_model(model))

    def test_catalyst_9000_is_split_across_three_product_lines(self):
        # The collision that motivates the ordering: one "c9..." prefix spans
        # an access point, a switch and a wireless controller.
        self.assertEqual(classify_by_model("C9115AXI-E"), "ap")
        self.assertEqual(classify_by_model("C9300-24U"), "switch")
        self.assertEqual(classify_by_model("C9800-80-K9"), "wlc")

    def test_nexus_9800_is_a_switch_not_a_wireless_controller(self):
        # Nexus 9000 includes a 9800: a data-centre switch with nothing to do
        # with the Catalyst 9800 controller.
        self.assertEqual(classify_by_model("Nexus 9800"), "switch")

    def test_firepower_9300_is_a_firewall_not_a_catalyst_9300(self):
        self.assertEqual(classify_by_model("FPR9300"), "firewall")

    def test_catalyst_8000_is_a_router_despite_the_catalyst_name(self):
        # "catalyst" is switch evidence everywhere else in this classifier.
        self.assertEqual(classify_by_model("Catalyst C8300-1N1S-4T2X"), "router")

    def test_a_known_model_outranks_a_misleading_hostname(self):
        # The reported bug: an access switch reporting WS-C2960X in its own
        # backup was classified from its hostname, because the model was
        # computed for display and never handed to the classifier.
        self.assertEqual(
            classify_device_type("site-ap-lab", model="WS-C2960X-24PS-L"),
            "switch",
        )

    def test_a_known_model_outranks_cdp_capabilities(self):
        # A lightweight AP announces "Router Trans-Bridge". The model does not
        # lie about what the box is.
        self.assertEqual(
            classify_device_type("node-7", platform="cisco C9130AXI-E",
                                 capabilities="Router Trans-Bridge"),
            "ap",
        )

    def test_an_unknown_model_leaves_the_other_signals_in_charge(self):
        self.assertEqual(
            classify_device_type("SW-WIFI-01", capabilities="Access Point",
                                 model="Non Rilevato"),
            "ap",
        )


if __name__ == "__main__":
    unittest.main()
