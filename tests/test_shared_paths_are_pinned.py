# -*- coding: utf-8 -*-
"""Every path resolved at import must be pinned by conftest, not by luck.

`conftest.py` binds the module-level `data_config.get_path(...)` constants to
one directory before any test module runs. A new constant added without adding
its module there goes back to landing wherever import order puts it, which is
what made two failures appear once every few full runs and never in isolation.

This is the guard for that: it rediscovers the constants from the source rather
than from a list, so it notices the nineteenth-plus one on its own.
"""

import ast
import importlib
import os
import pathlib
import re
import unittest

# tests/ is a package, so pytest loads the conftest as tests.conftest.
from tests import conftest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_DIRS = {".venv", "node_modules", "build", "dist", "tests", "graphify-out"}


def _module_level_get_path():
    """{dotted module: [constant names]} for every import-time get_path()."""
    found = {}
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if set(rel.parts) & SKIP_DIRS or rel.name == "conftest.py":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:
            continue
        names = []
        for node in tree.body:                       # module level only
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            src = ast.unparse(node.value)
            if re.search(r"\bdata_config\.get_path\(", src):
                names.append(target.id)
        if names:
            found[".".join(rel.with_suffix("").parts)] = names
    return found


class TestSharedPathsArePinned(unittest.TestCase):

    def setUp(self):
        self.owners = _module_level_get_path()

    def test_the_sweep_still_finds_them(self):
        self.assertGreaterEqual(
            sum(len(v) for v in self.owners.values()), 15,
            "the AST sweep found almost nothing; it has stopped working")

    def test_every_owner_is_imported_by_conftest(self):
        source = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
        missing = [m for m in self.owners
                   if not re.search(rf"^from {re.escape(m.rsplit('.', 1)[0])} "
                                    rf"import .*\b{re.escape(m.rsplit('.', 1)[1])}\b",
                                    source, re.M)]
        self.assertEqual(
            sorted(missing), [],
            "these modules bind a path at import but conftest does not import "
            "them, so where that path lands is decided by test import order")

    def test_every_constant_landed_in_the_suite_directory(self):
        """The point of the pinning, checked against the live values."""
        suite = os.path.realpath(conftest.SUITE_DATA_DIR)
        for module, names in self.owners.items():
            mod = importlib.import_module(module)
            for name in names:
                with self.subTest(constant=f"{module}.{name}"):
                    value = getattr(mod, name, None)
                    self.assertIsNotNone(value, f"{name} disappeared from {module}")
                    self.assertTrue(
                        os.path.realpath(str(value)).startswith(suite),
                        f"{module}.{name} resolved outside the suite directory: "
                        f"{value}")


if __name__ == "__main__":
    unittest.main()
