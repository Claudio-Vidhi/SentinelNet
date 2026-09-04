# -*- coding: utf-8 -*-
"""Rotte che esistevano senza un modo per raggiungerle dall'interfaccia.

Una rotta senza un pulsante non e' una funzione a meta': e' una funzione che
nessuno usa. `docs/netsec_troubleshooting_qa_v3.md` le elencava come "API-only,
no UI button", e questo file e' la prova che non lo sono piu'.

Non si asserisce l'aspetto: si asserisce che il gestore esista, che la rotta
che chiama sia quella registrata, e che le due azioni distruttive chiedano
conferma prima di partire.
"""

import os
import re
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_uiroutes_"))

import app_server  # noqa: E402
from tests.routes import iter_routes  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _route_exists(method, path):
    for route in iter_routes(app_server.app):
        raw = getattr(route, "path", "")
        if method.upper() not in (getattr(route, "methods", None) or set()):
            continue
        if re.fullmatch(re.sub(r"\{[^}]+\}", "[^/]+", raw), path):
            return True
    return False


class TestSessionKillIsReachable(unittest.TestCase):
    """DELETE /api/fortigate/{ip}/sessions."""

    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "fortigate-management.js")

    def test_route_exists(self):
        self.assertTrue(_route_exists("DELETE", "/api/fortigate/192.0.2.1/sessions"))

    def test_button_and_handler_exist(self):
        self.assertIn('id="btnFgtSessionKill"', self.html)
        self.assertIn("async function fgtKillSessions", self.js)

    def test_button_is_write_gated(self):
        idx = self.html.index('id="btnFgtSessionKill"')
        start = self.html.rindex("<button", 0, idx)
        self.assertIn("requires-write", self.html[start:self.html.index(">", idx)])

    def test_it_refuses_an_empty_filter_and_asks_first(self):
        # La rotta accetta un filtro vuoto e in quel caso terminerebbe TUTTE le
        # sessioni del firewall: il modulo vuoto non deve nemmeno partire.
        body = self.js[self.js.index("async function fgtKillSessions"):]
        body = body[:body.index("\nasync function ")]
        self.assertIn("!src && !dst && !port", body)
        self.assertIn("confirm(", body)
        self.assertIn("method: 'DELETE'", body)


class TestObservabilityHealthAndPruneAreReachable(unittest.TestCase):
    """GET /api/observability/health e POST /api/observability/prune-logs."""

    @classmethod
    def setUpClass(cls):
        cls.js = _read("static", "js", "observability.js")

    def test_routes_exist(self):
        self.assertTrue(_route_exists("GET", "/api/observability/health"))
        self.assertTrue(_route_exists("POST", "/api/observability/prune-logs"))

    def test_health_is_rendered_in_settings(self):
        self.assertIn("async function loadObsHealth", self.js)
        self.assertIn('id="obsHealthBox"', self.js)
        self.assertIn("/api/observability/health", self.js)

    def test_prune_asks_before_deleting(self):
        # Cancellazione definitiva, senza cestino: la domanda e' l'unico modo
        # per tornare indietro.
        body = self.js[self.js.index("async function pruneObsLogs"):]
        body = body[:body.index("\n    }") + 6]
        self.assertIn("confirm(", body)
        self.assertIn("/api/observability/prune-logs", body)
        self.assertIn("days", body)


class TestPortIsolationIsReachable(unittest.TestCase):
    """POST /api/mac/port-control."""

    @classmethod
    def setUpClass(cls):
        cls.js = _read("static", "js", "diagnosi.js")

    def test_route_exists(self):
        self.assertTrue(_route_exists("POST", "/api/mac/port-control"))

    def test_isolate_and_restore_buttons_exist(self):
        self.assertIn("diagIsolatePort()", self.js)
        self.assertIn("diagRestorePort()", self.js)
        self.assertIn("/api/mac/port-control", self.js)

    def test_isolating_needs_the_port_name_typed_but_restoring_does_not(self):
        # Isolare lascia la porta giu': si conferma digitando il nome. Riattivare
        # e' la via di ritorno e non deve avere ostacoli, altrimenti
        # l'isolamento diventa esso stesso il guasto.
        iso = self.js[self.js.index("async function diagIsolatePort"):]
        iso = iso[:iso.index("\n}")]
        self.assertIn("diagBounceConfirm", iso)
        self.assertIn("_diagPortControl('shutdown')", iso)

        res = self.js[self.js.index("async function diagRestorePort"):]
        res = res[:res.index("\n}")]
        self.assertNotIn("diagBounceConfirm", res)
        self.assertIn("_diagPortControl('no-shutdown')", res)

    def test_the_client_mac_travels_with_the_request(self):
        # Senza MAC il server rifiuta lo spegnimento: e' cio' su cui verifica
        # che la porta sia ancora quella di quel client.
        body = self.js[self.js.index("async function _diagPortControl"):]
        body = body[:body.index("\n}")]
        self.assertIn("client_mac: _diagMac", body)


if __name__ == "__main__":
    unittest.main()
