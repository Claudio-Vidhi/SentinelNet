# -*- coding: utf-8 -*-
"""Tracked Python parses on the floor declared in pyproject.toml.

Development happens on 3.14 (uv.lock) while the shipped artifacts run on the
floor: the Docker image builds on python:3.11-slim and the site agents run
whatever the customer distro provides. docs/development.md §1 states the rule
and nothing enforced it, so syntax the floor rejects passes every local check
and fails at `docker build` or on first agent start — the two places with no
one watching.

`ast.parse(feature_version=...)` is the whole check: the compiler already
knows which grammar belongs to which release.

ponytail: grammar only, and not all of it. A 3.12 stdlib call
(itertools.batched) parses fine on 3.11, and so does a PEP 701 f-string —
feature_version gates the grammar, not the tokenizer. It does catch the
statement-level additions (PEP 695 `type X = ...`, `def f[T]()`), which is
where the accidents come from. Catching the rest needs a real 3.11
interpreter, which is what requirements.txt's header records doing by hand.
"""
import ast
import pathlib
import subprocess
import sys
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _floor() -> tuple:
    """The (major, minor) from `requires-python = ">=X.Y"`, so raising the
    floor in pyproject.toml moves this guard with it."""
    spec = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    raw = spec["project"]["requires-python"].lstrip(">=~^ ")
    major, minor = raw.split(".")[:2]
    return int(major), int(minor)


class TrackedPythonMatchesTheFloor(unittest.TestCase):
    def test_every_tracked_module_parses_on_the_declared_floor(self):
        floor = _floor()
        if sys.version_info[:2] <= floor:
            self.skipTest(f"interpreter is already {sys.version_info[:2]}")
        files = subprocess.run(["git", "ls-files", "*.py"], cwd=ROOT,
                               capture_output=True, text=True,
                               check=True).stdout.split()
        self.assertTrue(files, "git ls-files returned no Python file")
        offenders = []
        for rel in files:
            path = ROOT / rel
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=rel,
                          feature_version=floor)
            except SyntaxError as exc:
                offenders.append(f"  {rel}:{exc.lineno}: {exc.msg}")
        self.assertEqual(
            offenders, [],
            "Syntax newer than Python %d.%d (the pyproject floor):\n%s"
            % (floor[0], floor[1], "\n".join(offenders)))


if __name__ == "__main__":
    unittest.main()
