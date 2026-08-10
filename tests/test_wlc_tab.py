# -*- coding: utf-8 -*-
"""Il tab WLC Live chiedeva la lista dispositivi a /api/devices, che non e' mai
esistito in questo repo: la fetch tornava 404, il codice usciva sul !res.ok e la
select restava vuota. Nessun controller e' mai comparso nel menu a tendina, non
solo quello appena aggiunto."""

import os
import re
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


if __name__ == "__main__":
    unittest.main()
