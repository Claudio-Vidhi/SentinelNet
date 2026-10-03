# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Every route of the app, however deeply the installed FastAPI nests them.

Eight suites iterate the app's routes to assert what is registered and with
which dependencies. Since fastapi 0.137 ``include_router`` no longer copies
the child routes into the parent: it adds one ``_IncludedRouter`` node per
call, so a flat ``app.routes`` loop sees a handful of nodes, finds none of the
paths it is looking for, and every contract test passes vacuously — the worst
thing a gate can do, staying green while checking nothing.

``fastapi.routing.iter_route_contexts`` expands those nodes into the routes as
the app serves them: prefixed path, methods, and the dependant with the
router-level dependencies merged in.
"""
from fastapi.routing import iter_route_contexts


def _expand(route):
    """The served routes behind one entry of a ``routes`` list."""
    if not hasattr(route, "effective_route_contexts"):
        return [route]
    # A WebSocket context reports an empty path; its served route, prefix
    # included, is the starlette_route the context builds.
    return [ctx if ctx.path else ctx.starlette_route
            for ctx in iter_route_contexts([route])]


def iter_routes(app):
    """Yield every route reachable from ``app``, parents before children.

    ``id()`` and not the route itself: a starlette route defines no __hash__
    contract worth relying on, and identity is what "already walked this
    object" actually means here. The dict holds every walked route alive:
    the contexts ``_expand`` builds are fresh objects, and a freed one would
    hand its id to the next, which the walk would then skip as already seen.
    """
    seen = {}

    def walk(routes):
        for entry in routes:
            for route in _expand(entry):
                if id(route) in seen:
                    continue
                seen[id(route)] = route
                yield route
                # A Mount exposes the sub-app's routes; StaticFiles has none
                # and answers with an empty list, which ends the branch.
                yield from walk(getattr(route, "routes", None) or ())

    yield from walk(app.routes)


def route_paths(app):
    """The set of registered paths — the shape most call sites actually want."""
    return {getattr(r, "path", "") for r in iter_routes(app)}
