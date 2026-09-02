# -*- coding: utf-8 -*-
"""Consegna degli asset statici: compressione HTTP e Cache-Control.

Gzip taglia i JS piu' pesanti (topology.js ~175KB). Vendor e font sono
pinnati in static/ e non cambiano tra release: cache di un anno. Il codice
dell'app resta su TTL corto finche' non esiste il fingerprinting dei nomi.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_static_perf_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402


class TestStaticAssetDelivery(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app)

    def test_js_is_gzipped_when_client_accepts_it(self):
        res = self.client.get("/static/js/core.js",
                              headers={"Accept-Encoding": "gzip"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("content-encoding"), "gzip")

    def test_vendor_css_is_cached_immutable(self):
        res = self.client.get("/static/vendor/fontawesome/css/all.min.css")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("cache-control"),
                         "public, max-age=31536000, immutable")

    def test_fonts_are_cached_immutable(self):
        res = self.client.get("/static/fonts/saira-condensed-600.woff2")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("cache-control"),
                         "public, max-age=31536000, immutable")

    def test_app_code_is_revalidated_never_served_stale(self):
        # max-age=300 significava che dopo un aggiornamento il browser serviva
        # per cinque minuti il JS vecchio senza nemmeno chiedere: l'utente
        # doveva fare Ctrl+F5 per vedere la nuova versione. Con no-cache il
        # browser chiede sempre, e con ETag/Last-Modified la risposta e' un
        # 304 vuoto finche' il file non cambia davvero.
        res = self.client.get("/static/js/core.js")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("cache-control"), "no-cache")
        self.assertTrue(res.headers.get("etag") or res.headers.get("last-modified"),
                        "senza validatore no-cache costerebbe un download intero")

    def test_an_unchanged_asset_costs_a_304_not_a_download(self):
        res = self.client.get("/static/js/core.js")
        etag = res.headers.get("etag")
        self.assertTrue(etag)
        again = self.client.get("/static/js/core.js", headers={"If-None-Match": etag})
        self.assertEqual(again.status_code, 304)

    def test_the_dashboard_itself_is_revalidated(self):
        # Serve a poco rivalidare il JS se la pagina che lo elenca e' vecchia.
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("cache-control"), "no-cache")

    def test_api_responses_get_no_cache_control(self):
        res = self.client.get("/api/auth/status")
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("cache-control", {k.lower() for k in res.headers})


if __name__ == "__main__":
    unittest.main()
