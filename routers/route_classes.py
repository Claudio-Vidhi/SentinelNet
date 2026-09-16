# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Route classification for the admin-permissions gate.

Every /api/* route (HTTP and WebSocket) belongs to exactly one class:
- TAB: gated by require_tab (its dependant carries a callable with .tabs;
  route_tabs() below finds it), scoped to whichever tab owns it.
- BASE: global admin/operator/viewer routes with no single owning tab.
- PUBLIC: reachable without authentication (login, health checks, ...).
- MACHINE: agent/site-to-site or other non-interactive callers.

Task 2 fills BASE_ROUTES, PUBLIC_ROUTES and MACHINE_ROUTES; TAB routes need
no explicit list here, they are discovered via route_tabs().
"""

# (method, path) pairs, method upper-case, path exactly as it appears in
# app.routes, WebSocket method is "WS".
BASE_ROUTES: frozenset[tuple[str, str]] = frozenset()
PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset()
MACHINE_ROUTES: frozenset[tuple[str, str]] = frozenset()


def route_tabs(route):
    """Union of .tabs from every require_tab dependency on this route, or
    None if the route carries none.

    FastAPI stores dependencies as a tree (route.dependant.dependencies,
    each a Dependant with .call and its own nested .dependencies);
    router-level `dependencies=[...]` are merged into that same tree by
    FastAPI, so a plain recursive walk sees them too.
    """
    found: set[str] = set()

    def walk(dependant):
        for sub in getattr(dependant, "dependencies", ()):
            tabs = getattr(sub.call, "tabs", None)
            if tabs is not None:
                found.update(tabs)
            walk(sub)

    dependant = getattr(route, "dependant", None)
    if dependant is not None:
        walk(dependant)
    return frozenset(found) if found else None
