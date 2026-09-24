# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Where DATA_DIR lands without SENTINELNET_DATA_DIR.

The installer used to publish the variable machine-wide, so a source checkout
on the same PC opened the installed data under ProgramData. Now only the
frozen exe falls back there; a source run stays on ./data.

Each case runs in a fresh interpreter: data_config binds DATA_DIR at import,
and conftest has already pinned it for this process.
"""

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _resolve(frozen: bool, programdata: str, cwd: str) -> str:
    env = {k: v for k, v in os.environ.items() if k != "SENTINELNET_DATA_DIR"}
    env["PROGRAMDATA"] = programdata
    env["PYTHONPATH"] = str(ROOT)
    code = ("import sys\n"
            + ("sys.frozen = True\n" if frozen else "")
            + "from core import data_config; print(data_config.DATA_DIR)")
    out = subprocess.run([sys.executable, "-c", code], cwd=cwd, env=env,
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


class TestDataDirResolution(unittest.TestCase):

    def setUp(self):
        self.pd = tempfile.mkdtemp(prefix="sentinelnet_pd_")
        self.cwd = tempfile.mkdtemp(prefix="sentinelnet_cwd_")
        os.makedirs(os.path.join(self.pd, "SentinelNet"))

    def test_source_run_ignores_the_installed_folder(self):
        self.assertEqual(_resolve(False, self.pd, self.cwd),
                         os.path.join(self.cwd, "data"))

    def test_installed_exe_finds_programdata(self):
        self.assertEqual(_resolve(True, self.pd, self.cwd),
                         os.path.join(self.pd, "SentinelNet"))

    def test_portable_exe_without_install_stays_on_cwd(self):
        empty = tempfile.mkdtemp(prefix="sentinelnet_pd_empty_")
        self.assertEqual(_resolve(True, empty, self.cwd),
                         os.path.join(self.cwd, "data"))


if __name__ == "__main__":
    unittest.main()
