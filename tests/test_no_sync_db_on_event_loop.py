# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""No blocking SQLite connection is opened on the event loop.

The rule (CONTRIBUTING.md §3) is about WHERE the call runs, not which module
it sits in: the grep gate it replaces flagged every router that opened a
connection inside a helper handed to ``asyncio.to_thread`` — correct code —
and could not tell it from a call made straight in an ``async def``. This
walks the AST and flags only the second kind: a call in the async body itself,
not inside a nested ``def``/``lambda`` that runs in a thread.
"""
import ast
import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BLOCKING = ("get_observability_connection", "sqlite3.connect")


def _direct_calls(fn: ast.AsyncFunctionDef):
    """Calls in fn's own body, not descending into nested defs/lambdas."""
    stack = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            yield node
        stack.extend(ast.iter_child_nodes(node))


def scan():
    files = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT, capture_output=True,
                           text=True, check=True).stdout.split()
    problems = []
    for rel in files:
        if rel.startswith(("tests/", "scripts/")):
            continue
        tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.AsyncFunctionDef):
                continue
            for call in _direct_calls(fn):
                name = ast.unparse(call.func)
                if name.endswith(BLOCKING):
                    problems.append(f"{rel}:{call.lineno} {fn.name}() -> {name}")
    return problems


class NoSyncDbOnEventLoop(unittest.TestCase):
    def test_no_blocking_connection_in_async_bodies(self):
        problems = scan()
        self.assertEqual(problems, [], "Blocking SQLite on the event loop — wrap it in "
                         "asyncio.to_thread or use await db.read():\n  " + "\n  ".join(problems))

    def test_the_scanner_sees_a_direct_call(self):
        # A gate that never fires proves nothing: the bad shape must be caught,
        # the to_thread shape must not.
        bad = ast.parse("async def h():\n    conn = db.get_observability_connection()\n")
        good = ast.parse("async def h():\n    def _q():\n        return db.get_observability_connection()\n"
                         "    return await asyncio.to_thread(_q)\n")
        self.assertEqual(len(list(_direct_calls(bad.body[0]))), 1)
        self.assertFalse([c for c in _direct_calls(good.body[0])
                          if ast.unparse(c.func).endswith(BLOCKING)])


if __name__ == "__main__":
    unittest.main()
