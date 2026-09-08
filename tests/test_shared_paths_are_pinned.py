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


class TestNoRelativeWritesAtRuntime(unittest.TestCase):
    r"""Nothing may create a directory from a bare relative literal.

    Installed under C:\Program Files, the exe's CWD is its own folder and a
    normal user cannot write there. app_server.main() did
    ``os.makedirs("templates")`` and the app died with WinError 5 before the
    server came up -- on a directory nothing ever read, because bundled
    resources resolve through sys._MEIPASS (get_resource_path).

    A path that must be written belongs to data_config.get_path(), which
    answers with SENTINELNET_DATA_DIR.
    """

    # os.makedirs / os.mkdir / Path(...).mkdir with a literal that is not
    # absolute and does not start with a variable.
    _CREATORS = {"makedirs", "mkdir"}

    def _offenders(self):
        found = []
        for path in sorted(ROOT.rglob("*.py")):
            if set(path.relative_to(ROOT).parts) & SKIP_DIRS:
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                if not isinstance(fn, ast.Attribute) or fn.attr not in self._CREATORS:
                    continue
                if not node.args:
                    continue
                arg = node.args[0]
                if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                    continue
                if os.path.isabs(arg.value):
                    continue
                found.append(f"{path.relative_to(ROOT)}:{node.lineno}: "
                             f"{fn.attr}({arg.value!r})")
        return found

    def test_no_directory_is_created_from_a_relative_literal(self):
        self.assertEqual(
            self._offenders(), [],
            "these resolve against the CWD, which is read-only when the exe "
            "is installed under Program Files; use data_config.get_path()")


if __name__ == "__main__":
    unittest.main()
