# -*- coding: utf-8 -*-
"""Il tab WLC Live chiedeva la lista dispositivi a /api/devices, che non e' mai
esistito in questo repo: la fetch tornava 404, il codice usciva sul !res.ok e la
select restava vuota. Nessun controller e' mai comparso nel menu a tendina, non
solo quello appena aggiunto."""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_wlctab_"))

import app_server  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _registered_api_paths():
    literal, templated = set(), []
    for route in app_server.app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/"):
            continue
        if "{" in path:
            templated.append(re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", path) + "$"))
        else:
            literal.add(path)
    return literal, templated


class TestWlcTabCallsRealRoutes(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_REPO_ROOT, "static", "js", "wlc.js"), encoding="utf-8") as f:
            cls.src = f.read()
        cls.literal, cls.templated = _registered_api_paths()

    def _is_registered(self, path):
        return path in self.literal or any(rx.match(path) for rx in self.templated)

    def test_every_apifetch_path_exists(self):
        # Le rotte per-IP sono template literal: ${ip} diventa un segmento
        # qualunque, come fa FastAPI con {ip}.
        calls = re.findall(r"apiFetch\(\s*[`'\"](/api/[^`'\"?]*)", self.src)
        self.assertTrue(calls, "nessuna chiamata apiFetch trovata in wlc.js")
        for raw in calls:
            probe = re.sub(r"\$\{[^}]*\}", "X", raw).rstrip("/")
            self.assertTrue(
                self._is_registered(probe),
                f"wlc.js chiama {raw!r}, che non e' una rotta registrata",
            )

    def test_device_list_is_read_from_the_envelope(self):
        # /api/local-devices risponde {"devices": [...], ...}: chiamare .filter()
        # sull'oggetto solleverebbe TypeError e la select resterebbe vuota lo
        # stesso, con la fetch ormai corretta.
        start = self.src.index("async function loadWlcTab")
        body = self.src[start:self.src.index("\n}", start)]
        self.assertIn("/api/local-devices", body)
        self.assertRegex(body, r"data\.devices|\.devices\s*\|\|")


class TestWlcTargetPickerIsTenantScoped(unittest.TestCase):
    """The target is picked tenant first, controller second, and the list holds
    only devices recognized as WLC by vendor: the old select fell back to ALL
    devices when none matched, offering switches the router then rejected with
    400."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_REPO_ROOT, "static", "js", "wlc.js"), encoding="utf-8") as f:
            cls.src = f.read()
        with open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"), encoding="utf-8") as f:
            cls.html = f.read()

    def test_tenant_select_exists_and_is_wired(self):
        self.assertIn('id="wlcTenantSelect"', self.html)
        self.assertIn("addEventListener('change', onWlcTenantChanged)", self.src)
        self.assertIn("function onWlcTenantChanged", self.src)

    def test_device_select_starts_disabled(self):
        target = self.html[self.html.index('id="wlcTargetSelect"'):]
        self.assertIn("disabled", target[:target.index(">")])

    def test_only_wlc_vendors_no_fallback(self):
        self.assertNotIn("wlcDevices.length > 0 ? wlcDevices : devices", self.src)
        self.assertIn("WLC_VENDORS = ['cisco_wlc', 'cisco_9800']", self.src)

    def test_devices_are_filtered_by_selected_tenant(self):
        start = self.src.index("function onWlcTenantChanged")
        body = self.src[start:self.src.index("\n}", start)]
        self.assertIn("d.Group", body)


class TestWlcClientSearchAndQuality(unittest.TestCase):
    """Client search box and the RSSI/SNR quality verdict."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_REPO_ROOT, "static", "js", "wlc.js"), encoding="utf-8") as f:
            cls.src = f.read()
        with open(os.path.join(_REPO_ROOT, "templates", "dashboard.html"), encoding="utf-8") as f:
            cls.html = f.read()

    def test_search_box_exists_and_is_wired(self):
        self.assertIn('id="wlcClientSearch"', self.html)
        self.assertIn("addEventListener('input', onWlcClientSearch)", self.src)
        self.assertIn("function onWlcClientSearch", self.src)

    def test_search_filters_the_whole_client_list_not_the_drawn_rows(self):
        # La tabella e' troncata a 100 righe: filtrare il DOM gia' disegnato
        # renderebbe invisibile il client numero 101, che e' esattamente quello
        # che si cerca quando si usa la ricerca.
        start = self.src.index("function renderWlcClientRows")
        body = self.src[start:self.src.index("\n}", start)]
        self.assertIn("wlcClients.filter", body)

    def test_client_table_has_a_quality_column(self):
        head = self.html[self.html.index("wlcClientTableBody") - 900:
                         self.html.index("wlcClientTableBody")]
        self.assertIn("Qualita'", head)
        self.assertIn("wlcQuality(", self.src)

    def test_ap_table_has_a_column_per_radio(self):
        # Le due radio hanno canale e larghezza propri: una colonna sola
        # mostrava solo i 5 GHz, e la congestione sta quasi sempre sui 2.4.
        head = self.html[self.html.index("wlcApTableBody") - 900:
                         self.html.index("wlcApTableBody")]
        self.assertIn("Canale 5 GHz", head)
        self.assertIn("Canale 2.4 GHz", head)
        self.assertIn("ap.channel_24", self.src)
        self.assertIn("ap.channel_width_24", self.src)

    @unittest.skipUnless(shutil.which("node"), "node non disponibile")
    def test_quality_thresholds_run_for_real(self):
        # Le soglie sono la logica: una tabella di livelli sbagliata supera
        # qualunque test per sottostringhe.
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_wlc_quality.mjs")
        proc = subprocess.run([shutil.which("node"), harness],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
