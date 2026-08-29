# -*- coding: utf-8 -*-
"""Vulnerability Matcher (NVD): la query che parte davvero.

Prima della correzione ogni ricerca finiva su keywordSearch, che in NVD e' un
AND sulle parole della DESCRIZIONE del CVE: 'cisco IOS' trova 1176 CVE,
'cisco IOS Version 15.2 4 E10' ne trova zero. Il matcher rispondeva quindi
"nessuna vulnerabilita" per ogni dispositivo. Questi test guardano l'URL
generato, non la rete: NVD non deve essere raggiunto per verificarli.
"""

import os
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlparse, parse_qs

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_nvd_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
import routers.backup as backup  # noqa: E402
from routers.deps import get_current_user  # noqa: E402


class _Resp:
    status_code = 200

    @staticmethod
    def json():
        return {"totalResults": 7, "vulnerabilities": []}


class TestNvdQuery(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app_server.app.dependency_overrides[get_current_user] = lambda: {
            "sub": "t", "role": "admin", "groups": []}
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        app_server.app.dependency_overrides.pop(get_current_user, None)

    def _params(self, **query):
        calls = []

        def fake_get(url, *a, **kw):
            calls.append(url)
            return _Resp()

        with mock.patch.object(backup.requests, "get", fake_get):
            r = self.client.get("/api/search", params=query)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(calls, "nessuna chiamata verso NVD")
        return parse_qs(urlparse(calls[0]).query)

    # --- CPE, non keyword ---

    def test_a_known_vendor_queries_by_cpe(self):
        p = self._params(vendor="cisco", text="IOS Version 15.2(4)E10", size="3")
        self.assertNotIn("keywordSearch", p)
        self.assertEqual(p["virtualMatchString"][0],
                         r"cpe:2.3:o:cisco:ios:15.2\(4\)e10")

    def test_the_version_survives_a_model_in_front_of_it(self):
        # 'WS-C2960X-24TS-L 15.2(4)E10': senza il secondo passaggio la query
        # perdeva la versione e tornava OGNI CVE mai emesso per il prodotto.
        p = self._params(vendor="cisco", text="WS-C2960X-24TS-L 15.2(4)E10")
        self.assertEqual(p["virtualMatchString"][0],
                         r"cpe:2.3:o:cisco:ios:15.2\(4\)e10")

    def test_vendors_map_to_the_cpe_product_not_their_label(self):
        for vendor, text, expected in (
            ("fortinet", "v7.2.5,build1517", "cpe:2.3:o:fortinet:fortios:7.2.5"),
            ("hpe", "KB.16.02.0028",
             "cpe:2.3:o:hp:procurve_switch_software:16.02.0028"),
            ("paloalto", "PAN-OS 10.2.4",
             "cpe:2.3:o:paloaltonetworks:pan-os:10.2.4"),
        ):
            with self.subTest(vendor=vendor):
                p = self._params(vendor=vendor, text=text)
                self.assertEqual(p["virtualMatchString"][0], expected)

    def test_isvulnerable_is_not_sent_with_virtualmatchstring(self):
        # NVD lo accetta solo con cpeName: insieme a virtualMatchString
        # risponde HTTP 404, che il chiamante leggerebbe come "nessun CVE".
        p = self._params(vendor="cisco", text="IOS Version 15.2(4)E10")
        self.assertNotIn("isVulnerable", p)

    # --- fallback ---

    def test_unknown_vendor_falls_back_to_keyword(self):
        p = self._params(vendor="", text="switch-01 firmware 1.2.3")
        self.assertIn("keywordSearch", p)
        self.assertNotIn("virtualMatchString", p)

    def test_an_explicit_cve_id_still_wins(self):
        p = self._params(vendor="cisco", text="CVE-2023-20198")
        self.assertEqual(p["cveId"][0], "CVE-2023-20198")
        self.assertNotIn("virtualMatchString", p)

    def test_a_caller_supplied_cpe_is_not_overridden(self):
        p = self._params(vendor="cisco", text="IOS Version 15.2",
                         virtualMatchString="cpe:2.3:o:cisco:ios_xe")
        self.assertEqual(p["virtualMatchString"][0], "cpe:2.3:o:cisco:ios_xe")


    def test_a_vendor_without_a_version_keeps_the_keyword_path(self):
        # La Vulnerability Watch interroga per solo vendor: un CPE senza
        # versione le renderebbe ogni CVE mai emesso per il prodotto.
        p = self._params(vendor="cisco", size="40")
        self.assertIn("keywordSearch", p)
        self.assertNotIn("virtualMatchString", p)
        self.assertIn("pubStartDate", p)

    def test_the_cpe_query_asks_for_a_window_wide_enough_to_rank(self):
        # NVD non ordina: chiedendo 3 risultati rende i 3 con id piu' basso,
        # cioe' i piu' VECCHI. Con la finestra larga i primi tre mostrati
        # sono davvero i piu' gravi.
        p = self._params(vendor="cisco", text="IOS Version 15.2(4)E10", size="3")
        self.assertGreaterEqual(int(p["resultsPerPage"][0]), 50)


class TestCiscoOsFamily(unittest.TestCase):
    """Cisco spedisce cinque sistemi operativi sotto un solo nome vendor, e
    NVD li cataloga come cinque prodotti diversi. Chiedere quello sbagliato
    non da' errore: da' zero, che a schermo si legge "apparato a posto"."""

    def _cpe(self, version, text):
        from drivers.registry import cpe_match_string
        return cpe_match_string("cisco", version, text)

    def test_classic_ios_from_the_parenthesised_train(self):
        self.assertEqual(
            self._cpe("15.2(4)E10", "Cisco IOS Software, C2960X, Version 15.2(4)E10"),
            r"cpe:2.3:o:cisco:ios:15.2\(4\)e10")

    def test_ios_xe_named_outright(self):
        self.assertEqual(
            self._cpe("17.9.4a", "Cisco IOS-XE Software, C9200 Version 17.9.4a"),
            "cpe:2.3:o:cisco:ios_xe:17.9.4a")

    def test_ios_xe_from_the_version_shape_alone(self):
        # cisco:ios:17.9.4a rende 0 CVE, cisco:ios_xe:17.9.4a ne rende 52:
        # senza questo ramo ogni Catalyst moderno risultava pulito.
        self.assertEqual(self._cpe("17.9.4a", "C9200-48P 17.9.4a"),
                         "cpe:2.3:o:cisco:ios_xe:17.9.4a")

    def test_nexus_asa_and_aireos_do_not_land_on_ios(self):
        for version, text, product in (
            ("9.3(5)", "Cisco NX-OS(tm) n9000, Version 9.3(5)", "nx-os"),
            ("9.16.1", "Cisco Adaptive Security Appliance Version 9.16.1",
             "adaptive_security_appliance_software"),
            ("8.5.140", "Cisco Wireless LAN Controller 8.5.140",
             "wireless_lan_controller_software"),
        ):
            with self.subTest(product=product):
                self.assertIn(":" + product + ":", self._cpe(version, text))


class TestVersionParsing(unittest.TestCase):

    def _v(self, text):
        from routers.backup import _version_of
        return _version_of(text)

    def test_a_parenthesised_train_keeps_its_closing_bracket(self):
        # core_engine.extract_version toglie la punteggiatura finale e
        # rendeva "9.3(5": il CPE che ne usciva trovava 11 CVE invece di 20.
        self.assertEqual(self._v("Cisco NX-OS(tm) n9000, Version 9.3(5)"), "9.3(5)")
        self.assertEqual(self._v("IOS Version 15.2(4)E10"), "15.2(4)E10")

    def test_a_model_in_front_does_not_swallow_the_version(self):
        self.assertEqual(self._v("WS-C2960X-24TS-L 15.2(4)E10"), "15.2(4)E10")
        self.assertEqual(self._v("C9200-48P 17.9.4a"), "17.9.4a")

    def test_no_version_at_all(self):
        self.assertIsNone(self._v("switch-01"))
        self.assertIsNone(self._v(""))


class TestModelScope(unittest.TestCase):
    """Un CVE per IOS 15.2(4)E10 puo' riguardare solo gli ISR 1100: sullo
    stesso treno gira anche un Catalyst 2960X, che non c'entra."""

    def _m(self, mine, nvd):
        from drivers.registry import model_matches
        return model_matches(mine, nvd)

    def test_the_model_is_recognised_through_the_naming_differences(self):
        # NVD scrive 'isr_4331' e 'catalyst_2960x-24ts-l', l'inventario
        # 'ISR4331/K9' e 'WS-C2960X-24TS-L'.
        self.assertTrue(self._m("ISR4331/K9", "isr_4331"))
        self.assertTrue(self._m("WS-C2960X-24TS-L", "catalyst_2960x-24ts-l"))
        self.assertTrue(self._m("C9200-48P", "catalyst_9200"))
        self.assertTrue(self._m("C9300-24P", "catalyst_9300-24p-a"))

    def test_a_different_platform_is_not_a_match(self):
        self.assertFalse(self._m("WS-C2960X-24TS-L", "asr_1002-hx"))
        self.assertFalse(self._m("ISR4331/K9", "1101_integrated_services_router"))
        self.assertFalse(self._m("C9200-48P", "catalyst_9300"))

    def test_an_unknown_model_never_matches(self):
        self.assertFalse(self._m("", "catalyst_9200"))
        self.assertFalse(self._m("C9200-48P", ""))


class TestResultOrdering(unittest.TestCase):
    """I primi risultati sono quelli su cui si decide: prima lo sfruttato."""

    def test_severity_outranks_the_model_heuristic(self):
        # L'elenco hardware di NVD e' incompleto: ordinando per modello un
        # CVE 9.8 attribuito ad altre piattaforme usciva dalle tre schede
        # mostrate. Una euristica non seppellisce il ritrovamento piu' grave.
        rank = {"model": 2, "generic": 1, "other": 0}
        items = [
            {"exploited": False, "score": 8.8, "modelScope": "model", "published": "2020"},
            {"exploited": False, "score": 9.8, "modelScope": "other", "published": "2019"},
        ]
        items.sort(key=lambda x: (bool(x.get("exploited")), x.get("score") or 0,
                                  rank.get(x.get("modelScope"), 1),
                                  x.get("published") or ""), reverse=True)
        self.assertEqual(items[0]["score"], 9.8)

    def test_the_model_breaks_ties_at_equal_severity(self):
        rank = {"model": 2, "generic": 1, "other": 0}
        items = [
            {"exploited": False, "score": 7.5, "modelScope": "other", "published": "2020"},
            {"exploited": False, "score": 7.5, "modelScope": "model", "published": "2020"},
        ]
        items.sort(key=lambda x: (bool(x.get("exploited")), x.get("score") or 0,
                                  rank.get(x.get("modelScope"), 1),
                                  x.get("published") or ""), reverse=True)
        self.assertEqual(items[0]["modelScope"], "model")

    def test_exploited_then_score_then_date(self):
        items = [
            {"exploited": False, "score": 9.9, "published": "2024-01-01"},
            {"exploited": True, "score": 5.0, "published": "2019-01-01"},
            {"exploited": False, "score": 7.5, "published": "2025-01-01"},
        ]
        items.sort(key=lambda x: (bool(x.get("exploited")),
                                  x.get("score") or 0,
                                  x.get("published") or ""), reverse=True)
        self.assertTrue(items[0]["exploited"])
        self.assertEqual(items[1]["score"], 9.9)
        self.assertEqual(items[2]["score"], 7.5)


class TestCpeQuoting(unittest.TestCase):

    def test_special_characters_are_escaped(self):
        from drivers.registry import cpe_quote
        self.assertEqual(cpe_quote("15.2(4)E10"), r"15.2\(4\)e10")
        self.assertEqual(cpe_quote("7.2.5"), "7.2.5")

    def test_a_vendor_without_a_cpe_identity_yields_none(self):
        from drivers.registry import cpe_match_string
        self.assertIsNone(cpe_match_string("acme-networks", "1.0"))
        self.assertIsNone(cpe_match_string("", "1.0"))


if __name__ == "__main__":
    unittest.main()
