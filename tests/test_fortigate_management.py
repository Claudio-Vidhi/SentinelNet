# -*- coding: utf-8 -*-
"""Guardie della tab Fortigate Management: chi può chiamare cosa, e cosa
non deve mai uscire dal service."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_fgtmgmt_"))

import app_server  # noqa: E402
from routers import deps  # noqa: E402
from tests.routes import iter_routes  # noqa: E402


def _dependency_names(path: str, method: str = "get"):
    for route in iter_routes(app_server.app):
        if getattr(route, "path", None) == path and method.upper() in getattr(route, "methods", ()):
            return {d.call.__name__ for d in route.dependant.dependencies if d.call}
    raise AssertionError(f"rotta non trovata: {method.upper()} {path}")


class AdminOnlyRoutesTest(unittest.TestCase):
    def test_admin_list_is_admin_only(self):
        # L'elenco di chi amministra il firewall non è dato da operatore.
        self.assertIn(deps.require_admin.__name__,
                      _dependency_names("/api/fortigate/{ip}/system/admins"))

    def test_full_config_stays_operator(self):
        self.assertIn(deps.require_operator.__name__,
                      _dependency_names("/api/fortigate/{ip}/full-config"))

    def test_read_only_views_are_open_to_authenticated_users(self):
        for path in ("/api/fortigate/{ip}/system/resources",
                     "/api/fortigate/{ip}/system/ha",
                     "/api/fortigate/{ip}/system/certificates"):
            names = _dependency_names(path)
            self.assertNotIn(deps.require_admin.__name__, names, path)


def _js() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(base, "static", "js", "fortigate-management.js"),
              encoding="utf-8") as f:
        return f.read()


class DatasetRegistryTest(unittest.TestCase):
    """Il registro è l'unica cosa che sa quale URL serve una vista: un
    percorso sbagliato lì diventa un pannello vuoto in produzione, non un
    errore. Si verifica qui, contro l'OpenAPI vera."""

    @classmethod
    def setUpClass(cls):
        src = _js()
        # Solo il blocco del registro: il resto del file contiene la PUT
        # legittima che aggiorna un target FortiGate (saveFgtMgrTarget), che
        # non è una vista e non deve far scattare il controllo di sola lettura.
        start = src.index("const FGT_DATASETS = {")
        cls.registry = src[start:src.index("\n};", start)]
        cls.paths = set(app_server.app.openapi()["paths"])

    def test_every_dataset_url_exists_in_the_openapi(self):
        # url: ip => `/api/fortigate/${ip}/qualcosa`  ->  /api/fortigate/{ip}/qualcosa
        urls = re.findall(r"url:\s*ip\s*=>\s*`([^`]+)`", self.registry)
        self.assertGreaterEqual(len(urls), 15, "registro troppo piccolo: parsing rotto?")
        for u in urls:
            path = u.replace("${ip}", "{ip}")
            self.assertIn(path, self.paths, f"dataset punta a una rotta inesistente: {path}")

    def test_no_dataset_declares_a_write_method(self):
        # La tab è di sola lettura: POST è ammesso solo per le query
        # (sessions, logs, policy-lookup), mai PUT/DELETE/PATCH.
        for verb in ("'PUT'", "'DELETE'", "'PATCH'"):
            self.assertNotIn(verb, self.registry, f"metodo di scrittura nel registro: {verb}")


class PolicyLookupIsAnAnswerNotADict(unittest.TestCase):
    """La lookup risponde "quale policy matcherebbe": consentito/negato e il
    numero devono leggersi subito, e cio' che il firewall NON ha detto non si
    inventa. FortiOS restituisce policy_id e success, non l'azione: quella sta
    nella policy, che la pill Policy scarica quando viene aperta."""

    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_the_lookup_has_its_own_view_not_the_key_value_table(self):
        src = open(os.path.join(self._ROOT, "static", "js",
                                "fortigate-management.js"), encoding="utf-8").read()
        self.assertIn("renderFgtPolicyLookup", src)
        self.assertIn("if (key === 'policyLookup')", src)
        # La risposta grezza resta raggiungibile: la vista aggiunge una
        # lettura, non toglie dati.
        self.assertIn("fgtLookupRawAnswer", src)

    def test_every_verdict_string_exists_in_both_languages(self):
        i18n = open(os.path.join(self._ROOT, "static", "js", "i18n.js"),
                    encoding="utf-8").read()
        for key in ("fgtLookupAllowed", "fgtLookupDenied", "fgtLookupMatched",
                    "fgtLookupNoMatch", "fgtLookupImplicitDeny",
                    "fgtLookupOpenPolicies", "fgtLookupPolicyN",
                    "fgtLookupIngress", "fgtLookupRawAnswer"):
            # count() e non una regex: la chiave e' una stringa letterale e
            # due occorrenze significano "una per lingua".
            self.assertEqual(2, i18n.count(key + ":"),
                             f"{key} non e' definita in entrambe le lingue")

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_the_verdict_mapping_runs_for_real(self):
        harness = os.path.join(self._ROOT, "tests", "js",
                               "test_policy_lookup_verdict.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=self._ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
