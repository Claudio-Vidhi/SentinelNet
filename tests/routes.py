# -*- coding: utf-8 -*-
"""Every route of the app, however deeply the installed FastAPI nests them.

Eight suites iterate ``app.routes`` to assert what is registered and with
which dependencies. That flat loop is only correct while ``include_router``
copies the child routes into the parent: fastapi 0.141 mounts an
``_IncludedRouter`` and keeps them one level down instead, so the flat loop
sees a handful of mounts, finds none of the paths it is looking for, and every
contract test passes vacuously — the worst thing a gate can do, staying green
while checking nothing.

`pyproject.toml` pins `fastapi<0.141` for exactly that reason. Walking the
tree is correct on both sides of the pin, so lifting it is a change to one
line and not to the assertions.
"""


def iter_routes(app):
    """Yield every route reachable from ``app``, parents before children.

    ``id()`` and not the route itself: a starlette route defines no __hash__
    contract worth relying on, and identity is what "already walked this
    object" actually means here.
    """
    seen = set()

    def walk(routes):
        for route in routes:
            if id(route) in seen:
                continue
            seen.add(id(route))
            yield route
            # A Mount exposes the sub-app's routes; StaticFiles has none and
            # answers with an empty list, which ends the branch by itself.
            yield from walk(getattr(route, "routes", None) or ())

    yield from walk(app.routes)


def route_paths(app):
    """The set of registered paths — the shape most call sites actually want."""
    return {getattr(r, "path", "") for r in iter_routes(app)}
