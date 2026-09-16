# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Every /api route sits in exactly one class (TAB, BASE, PUBLIC, MACHINE):
a new route breaks this suite until someone classifies it."""
import re
from pathlib import Path

from fastapi.routing import APIRoute, APIWebSocketRoute

import app_server
from routers import route_classes as rc

TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "dashboard.html"


def _api_routes():
    for r in app_server.app.routes:
        if isinstance(r, APIRoute) and r.path.startswith("/api"):
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                yield m, r.path, r
        elif isinstance(r, APIWebSocketRoute) and r.path.startswith("/api"):
            yield "WS", r.path, r


def test_every_route_in_exactly_one_class():
    problems = []
    for method, path, route in _api_routes():
        key = (method, path)
        classes = [name for name, hit in (
            ("TAB", rc.route_tabs(route) is not None),
            ("BASE", key in rc.BASE_ROUTES),
            ("PUBLIC", key in rc.PUBLIC_ROUTES),
            ("MACHINE", key in rc.MACHINE_ROUTES)) if hit]
        if len(classes) != 1:
            problems.append(f"{method} {path}: {classes or 'unclassified'}")
    assert not problems, "\n".join(problems)


def test_registry_has_no_stale_entries():
    live = {(m, p) for m, p, _ in _api_routes()}
    stale = (rc.BASE_ROUTES | rc.PUBLIC_ROUTES | rc.MACHINE_ROUTES) - live
    assert not stale, sorted(stale)


def test_tab_ids_exist_in_dashboard():
    html = TEMPLATE.read_text(encoding="utf-8")
    known = set(re.findall(r'data-tab="([^"]+)"', html))
    for tabs in re.findall(r'data-tabs="([^"]+)"', html):
        known |= set(tabs.split())
    for method, path, route in _api_routes():
        tabs = rc.route_tabs(route)
        if tabs:
            assert tabs <= known, f"{method} {path}: {sorted(tabs - known)}"
