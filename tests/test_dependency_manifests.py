# -*- coding: utf-8 -*-
"""requirements.txt and pyproject.toml must declare the same runtime packages.

Two manifests exist on purpose: the Docker image pip-installs
requirements.txt (pinned, so the container gets the resolution the suite was
green on), while local work runs off pyproject.toml + uv.lock. Nothing keeps
the two package LISTS in step, and they had already drifted -- pyserial was
in requirements.txt only, so `uv sync` produced an environment where the
serial provisioning path died on import while Docker was fine.

Versions are deliberately NOT compared: the floors and the pins answer
different questions. Only the set of package names is checked, which is the
half that silently breaks an environment.
"""
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _name(spec: str) -> str:
    """Package name from a requirement line, without version or extras."""
    return re.split(r"[><=!~\[;]", spec, maxsplit=1)[0].strip().lower().replace("_", "-")


def _pyproject_runtime() -> set:
    data = tomllib.loads(ROOT.joinpath("pyproject.toml").read_text(encoding="utf-8"))
    return {_name(d) for d in data["project"]["dependencies"]}


def _requirements() -> set:
    out = set()
    for line in ROOT.joinpath("requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(_name(line))
    return out


class TestDependencyManifests(unittest.TestCase):
    def test_same_runtime_packages_in_both_manifests(self):
        pyproject, requirements = _pyproject_runtime(), _requirements()
        self.assertEqual(
            requirements - pyproject, set(),
            "in requirements.txt but not in pyproject.toml: a `uv sync` "
            "environment is missing these, Docker has them")
        self.assertEqual(
            pyproject - requirements, set(),
            "in pyproject.toml but not in requirements.txt: the Docker image "
            "is missing these")

    def test_every_runtime_package_is_pinned_in_requirements(self):
        """Docker must install the resolution the suite was verified on."""
        unpinned = []
        for line in ROOT.joinpath("requirements.txt").read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line and "==" not in line:
                unpinned.append(line)
        self.assertEqual(unpinned, [], "requirements.txt entries without ==")


if __name__ == "__main__":
    unittest.main()
