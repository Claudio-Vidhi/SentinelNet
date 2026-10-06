# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A viewer must never be shown a tab it cannot load.

Config Drift shipped visible to viewers while every one of its GET routes was
require_operator: the tab opened on a 403 and read "Could not load devices".
The sidebar hides a `requires-write` nav button from viewers and the user
editor stops offering it, so the invariant is: a tab with no GET route a
viewer can reach must sit behind requires-write (or, for a secondary panel
riding on a viewer-visible button, in WRITE_ONLY_SECONDARY_TABS). Derived
from the routes, so a new operator-only tab fails here instead of in prod.
"""
import os
import re
import tempfile
import unittest
from collections import defaultdict

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_viewer_tabs_"))

import app_server  # noqa: E402
from routers import deps  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ABOVE_VIEWER = {deps.require_operator, deps.require_admin, deps.require_super_admin}


def _read(*parts) -> str:
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def _walk(dependant, tabs: set) -> bool:
    """Collect require_tab ids; True when some dependency rejects a viewer."""
    above = dependant.call in _ABOVE_VIEWER
    tabs |= set(getattr(dependant.call, "tabs", ()))
    for sub in dependant.dependencies:
        above = _walk(sub, tabs) or above
    return above


def _viewer_readable_gets() -> dict:
    """tab id -> number of its GET routes a viewer can reach."""
    out = defaultdict(int)
    for top in app_server.app.routes:
        routes = top.original_router.routes if hasattr(top, "original_router") else [top]
        for r in routes:
            if "GET" not in getattr(r, "methods", ()) or not hasattr(r, "dependant"):
                continue
            tabs: set = set()
            above = _walk(r.dependant, tabs)
            for t in tabs:
                out[t] += 0 if above else 1
    return out


def _nav_buttons(html: str) -> list:
    return [m.group(1) for m in re.finditer(r'<button([^>]*\bnav-item\b[^>]*)>', html)
            if 'data-tab="' in m.group(1)]


class TestViewerTabs(unittest.TestCase):

    def test_tabs_a_viewer_cannot_load_are_hidden_from_viewers(self):
        html = _read("templates", "dashboard.html")
        m = re.search(r"WRITE_ONLY_SECONDARY_TABS = \[([^\]]*)\]", _read("static", "js", "settings.js"))
        self.assertIsNotNone(m, "WRITE_ONLY_SECONDARY_TABS missing from settings.js")
        secondary_gated = set(re.findall(r"'([^']+)'", m.group(1)))

        gated, admin_only, all_tabs = set(), set(), set()
        for attrs in _nav_buttons(html):
            ids = set((re.search(r'data-tabs="([^"]*)"', attrs) or
                       re.search(r'data-tab="([^"]*)"', attrs)).group(1).split())
            all_tabs |= ids
            if "requires-admin" in attrs:
                admin_only |= ids
            elif "requires-write" in attrs:
                gated |= ids

        readable = _viewer_readable_gets()
        dead = {t for t in all_tabs - admin_only - {"tab-home"}
                if t in readable and readable[t] == 0}
        self.assertEqual(set(), dead - gated - secondary_gated,
                         "tabs with no viewer-readable GET still shown to viewers: "
                         "add requires-write to the nav button (or the id to "
                         "WRITE_ONLY_SECONDARY_TABS), or open the read routes to viewers")
        self.assertEqual(set(), secondary_gated - dead,
                         "WRITE_ONLY_SECONDARY_TABS lists a tab a viewer can load")

    def test_viewer_reads_cve_but_cannot_refresh(self):
        """Threat Intel is read-only for a viewer: the CVE report loads, the
        NVD refresh (an outbound call) stays operator."""
        from fastapi.testclient import TestClient
        from routers.deps import CSRF_HEADER
        viewer = {"sub": "viewer-x", "role": "viewer"}
        app_server.app.dependency_overrides[deps.get_current_user] = lambda: viewer
        try:
            c = TestClient(app_server.app)
            self.assertEqual(200, c.get("/api/cve/summary").status_code)
            self.assertEqual(200, c.get("/api/cve/priority").status_code)
            self.assertEqual(403, c.post("/api/cve/192.0.2.1/refresh",
                                         headers={CSRF_HEADER: "1"}).status_code)
        finally:
            app_server.app.dependency_overrides.pop(deps.get_current_user, None)

    def test_every_nav_label_is_translated(self):
        """The user editor labels each tab by its nav data-i18n key and falls
        back to the raw id ('tab-netsec-audit') when there is none."""
        html = _read("templates", "dashboard.html")
        for m in re.finditer(r'<button([^>]*\bnav-item\b[^>]*)>(.*?)</button>', html, re.S):
            if 'data-tab="' in m.group(1):
                self.assertIn("data-i18n=", m.group(2), m.group(1))


if __name__ == "__main__":
    unittest.main()
