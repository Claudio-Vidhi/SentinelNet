# -*- coding: utf-8 -*-
import os, tempfile
_TMP = tempfile.mkdtemp(prefix="sentinelnet_uirevamp_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
import unittest
from fastapi.testclient import TestClient  # noqa: E402
import data_config  # noqa: E402
data_config.DATA_DIR = _TMP
import app_server  # noqa: E402


def _html():
    return TestClient(app_server.app).get("/").text


class TestComponentLayer(unittest.TestCase):
    def test_component_classes_present(self):
        html = _html()
        for cls in (".hero-card", ".kpi-grid", ".filterbar",
                    ".status", ".led-success", ".split-footer",
                    ".nav-group", ".preview-badge"):
            self.assertIn(cls, html, f"missing component class {cls}")


if __name__ == "__main__":
    unittest.main()
