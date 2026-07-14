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


class TestSidebarIA(unittest.TestCase):
    def test_nav_groups_present_and_flat_strip_gone(self):
        html = _html()
        for grp in (">Operations<", ">Analysis<", ">Provisioning<", ">Administration<"):
            self.assertIn(grp, html)
        # every existing tab still reachable (tab-home is deferred to Task 3)
        for tab in ("tab-devices", "tab-mac", "tab-clientmap", "tab-flows",
                    "tab-map", "tab-map-interactive", "tab-categories", "tab-security",
                    "tab-config", "tab-ai", "tab-provisioner", "tab-import", "tab-groups",
                    "tab-users", "tab-sites", "tab-mcp", "tab-settings"):
            self.assertIn(f"switchTab('{tab}'", html)
        # RBAC preserved on gated nav
        self.assertIn('requires-admin', html)
        self.assertIn('requires-write', html)
        # compound onclicks preserved verbatim
        self.assertIn("switchTab('tab-clientmap', this); loadClientMapTab();", html)
        self.assertIn("switchTab('tab-flows', this); flowsTabShown();", html)
        # old flat tab strip is gone
        self.assertNotIn('class="tab-nav"', html)


class TestHomeTab(unittest.TestCase):
    def test_home_tab_exists_and_default(self):
        html = _html()
        # Home tab body + startup default
        self.assertIn('id="tab-home"', html)
        self.assertIn('<div id="tab-home" class="tab-content active">', html)
        # loadHome function present
        self.assertIn('function loadHome', html)
        # Home nav-item present and active
        self.assertIn("switchTab('tab-home'", html)
        self.assertIn('data-i18n="tabHome"', html)
        # runtime-populated ids
        for eid in ('homeKpiOnline', 'homeKpiAttention',
                    'homeAttentionBody', 'homeAnomBody'):
            self.assertIn(f'id="{eid}"', html)
        # Home wires only to REAL endpoints
        self.assertIn('/api/local-devices', html)
        self.assertIn('/api/run-triage', html)
        self.assertIn("startGroupTriage('all')", html)
        self.assertIn('/api/observability/anomalies', html)
        # no fabricated prototype-only controls
        self.assertNotIn('Open design language', html)
        self.assertNotIn('Customize view', html)

    def test_home_tab_i18n_keys_both_langs(self):
        html = _html()
        # tabHome defined in both maps (label appears twice: it + en)
        self.assertGreaterEqual(html.count('tabHome:'), 2)


class TestFormRelocation(unittest.TestCase):
    def test_device_form_ids_preserved(self):
        html = _html()
        for _id in ('devIp','devGroupSelect','devVendor','btnSaveDevice',
                    'newGroupName','btnCreateGroup','trSshEnabled'):
            self.assertIn(f'id="{_id}"', html)


if __name__ == "__main__":
    unittest.main()
