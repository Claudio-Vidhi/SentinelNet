# -*- coding: utf-8 -*-
"""La CSP non deve permettere origini che non usiamo piu'.

Font, FontAwesome, vis.js e xterm.js sono ospitati in ``static/``: una LAN di
management isolata non risolve cdnjs/unpkg/jsdelivr, quindi un asset remoto
non arriverebbe comunque. Le origini rimaste nella policy non servono a
caricare nulla — allargano solo la superficie: con un XSS diventano
destinazioni consentite per esfiltrare o per tirare dentro codice.

Questo test e' anche il guardrail dell'inverso: chi in futuro aggiunge un tag
verso una CDN vede fallire qui, e deve prima decidere se la sede isolata puo'
permetterselo.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_csp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

# Le origini che erano in policy quando gli asset stavano ancora su CDN.
DEAD_ORIGINS = ("cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net",
                "fonts.googleapis.com", "fonts.gstatic.com")


class TestContentSecurityPolicy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import app_server
        cls.csp = app_server._CSP

    def test_no_external_origin_is_allowed(self):
        for origin in DEAD_ORIGINS:
            with self.subTest(origin=origin):
                self.assertNotIn(origin, self.csp)

    def test_no_https_origin_at_all(self):
        # Piu' forte dell'elenco: qualunque origine remota, anche nuova.
        self.assertNotIn("https://", self.csp)

    def test_the_directives_that_matter_are_self(self):
        for directive in ("default-src 'self'", "font-src 'self'",
                          "img-src 'self'", "connect-src 'self'"):
            with self.subTest(directive=directive):
                self.assertIn(directive, self.csp)

    def test_the_clamps_are_still_there(self):
        # Non erano il soggetto della modifica, ma restringere una direttiva
        # e' il momento tipico in cui se ne allenta un'altra per sbaglio.
        self.assertIn("frame-ancestors 'none'", self.csp)
        self.assertIn("object-src 'none'", self.csp)

    def test_the_header_is_actually_sent(self):
        # La costante potrebbe essere giusta e non essere applicata a nulla.
        from fastapi.testclient import TestClient
        import app_server
        client = TestClient(app_server.app)
        res = client.get("/login")
        self.assertIn("content-security-policy", {k.lower() for k in res.headers})
        sent = res.headers["content-security-policy"]
        self.assertNotIn("https://", sent)


if __name__ == "__main__":
    unittest.main()
