# -*- coding: utf-8 -*-
"""Every route that takes a device IP must reach ``assert_device_allowed``.

AGENTS.md: filtering *data* by tenant is not authorizing the *device*. This
walks the router ASTs and fails on any IP-taking route that cannot reach the
guard, directly or through a module-local helper (``_fgt_device`` and friends).

The waiver list below is the whole set of deliberate exceptions, each with the
reason it is one. A new unguarded route fails here instead of at review time;
adding it to the waiver list is a decision, which is the point.
"""

import ast
import pathlib
import re
import unittest

ROUTERS = pathlib.Path(__file__).resolve().parent.parent / "routers"
GUARD = "assert_device_allowed"
IP_ARG = re.compile(r"(^|_)(ip|host|device_ip|target|mgmt_ip|address)($|_)", re.I)
ROUTE_DEC = re.compile(r"router\.(get|post|put|delete|patch|websocket)")
IP_PATH = re.compile(r"\{[^}]*(ip|host|target)[^}]*\}", re.I)

# (module, handler) -> why this one does not call the guard.
WAIVED = {
    ("analyzer.py", "config_analyzer_device"):
        "Hand-rolled scoping is STRICTER: 403 when the IP is absent from "
        "inventory, where the guard returns None. Backups outlive device rows.",
    ("analyzer.py", "netsec_audit_history"):
        "device_ip is a query filter over tenant-scoped rows, not a target.",
    ("arp.py", "arp_search"):
        "ip/source_ip filter tenant-scoped ARP bindings; no device is contacted.",
    ("arp.py", "arp_client_map"):
        "ip/source_ip filter tenant-scoped ARP bindings; no device is contacted.",
    ("backup.py", "download_backup"):
        "Declined 2026-08-08: the guard returns None for an IP absent from "
        "inventory, so swapping it in would let a scoped user download that "
        "backup. The local check raises 403 instead.",
    ("commands.py", "ws_terminal"):
        "Declined 2026-08-08: HTTPException is meaningless over a WebSocket. "
        "The handler sends a message and closes with 1008.",
    ("mac.py", "mac_switch"):
        "Reads the tenant-scoped switch table; no device is contacted.",
    ("observability.py", "obs_api_context"):
        "Tenant-filtered SQL read of stored snapshots, not a device target.",
    ("observability.py", "obs_host_series"):
        "ip is a host SEEN in flow records - a client, a server on the "
        "internet - not a managed device: assert_device_allowed would return "
        "None for every one of them. The boundary is the tenant filter on the "
        "query, which is applied.",
    ("triage.py", "ping_single"):
        "Probing an IP before it is in inventory is the point; when the IP IS "
        "known, assert_group_allowed runs.",
    ("triage.py", "triage_single_device"):
        "404 when absent from inventory, then assert_group_allowed.",
}


def _called_names(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _ip_routes():
    """Yield (module, handler, reaches_guard) for every IP-taking route."""
    for path in sorted(ROUTERS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        funcs = {n.name: n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        # Transitive closure: a handler is guarded if anything it calls, at any
        # depth inside this module, reaches the guard.
        guarded = {name for name, n in funcs.items() if GUARD in _called_names(n)}
        while True:
            grown = {name for name, n in funcs.items()
                     if name not in guarded and _called_names(n) & guarded}
            if not grown:
                break
            guarded |= grown
        for name, n in funcs.items():
            decorators = [ast.unparse(d) for d in n.decorator_list]
            route = next((d for d in decorators if ROUTE_DEC.search(d)), None)
            if route is None:
                continue
            args = [a.arg for a in n.args.args + n.args.kwonlyargs]
            if not any(IP_ARG.search(a) for a in args) and not IP_PATH.search(route):
                continue
            yield path.name, name, name in guarded


class TestDeviceGuardCoverage(unittest.TestCase):

    def test_every_ip_route_reaches_the_guard_or_is_waived(self):
        routes = list(_ip_routes())
        self.assertGreater(len(routes), 50, "the AST walk found almost nothing")
        unguarded = {(m, h) for m, h, ok in routes if not ok}
        self.assertEqual(
            sorted(unguarded - set(WAIVED)), [],
            "route takes a device IP but never reaches assert_device_allowed; "
            "call the guard, or add it to WAIVED with the reason")

    def test_no_stale_waivers(self):
        """A waiver that no longer describes reality is worse than none."""
        routes = {(m, h): ok for m, h, ok in _ip_routes()}
        for key in WAIVED:
            self.assertIn(key, routes, f"waived route {key} no longer exists")
            self.assertFalse(routes[key],
                             f"{key} now calls the guard; drop its waiver")


if __name__ == "__main__":
    unittest.main()
