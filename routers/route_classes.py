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

BASE_ROUTES, PUBLIC_ROUTES and MACHINE_ROUTES are explicit; TAB routes need
no explicit list here, they are discovered via route_tabs().
"""

# (method, path) pairs, method upper-case, path exactly as it appears in
# app.routes, WebSocket method is "WS".
# BASE: session/self routes, data the dashboard loads at boot for every tab
# (appInit, core.js), the terminal (governed by role, opened from device rows
# in many tabs) and the MCP server's own configuration read.
# GET /api/groups is TAB (provisioning/groups), not BASE: every other tab gets groups via BASE /api/local-devices.
BASE_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/change-password"),
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/logout-all"),
    ("GET", "/api/profile"),
    ("POST", "/api/profile/email"),
    ("GET", "/api/local-devices"),
    ("GET", "/api/vendors"),
    ("GET", "/api/settings/snmp-defaults"),
    ("GET", "/api/settings/ui-variant"),
    ("POST", "/api/settings/ui-variant"),
    ("GET", "/api/triage-status"),
    ("POST", "/api/send-command"),
    ("POST", "/api/ws-token"),
    ("WS", "/api/ws-terminal/{ip}"),
    # Read by ai/mcp_server.py with the caller's own account: gating it by a
    # tab would disable every MCP tool for any user with a tab list.
    ("GET", "/api/mcp/tool-config"),
})

# PUBLIC: reachable before a session exists (first run, login screen,
# emailed token links, IdP redirects).
PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/api/version"),
    ("GET", "/api/auth/status"),
    ("POST", "/api/auth/register"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/verify-email"),
    ("POST", "/api/auth/forgot-password"),
    ("POST", "/api/auth/reset-password"),
    ("POST", "/api/auth/accept-invite"),
    ("GET", "/api/auth/sso/config"),
    ("GET", "/api/auth/sso/login"),
    ("GET", "/api/auth/sso/callback"),
})

# MACHINE: site agents, authenticated by X-Site-Token.
MACHINE_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("POST", "/api/agent/heartbeat"),
    ("POST", "/api/agent/inventory"),
    ("POST", "/api/agent/mac"),
    ("POST", "/api/agent/arp"),
    ("POST", "/api/agent/status"),
    ("POST", "/api/agent/backup"),
    ("GET", "/api/agent/jobs"),
    ("POST", "/api/agent/jobs/{job_id}/result"),
    ("POST", "/api/agent/syslog"),
})


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
