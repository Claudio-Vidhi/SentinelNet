# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A jump site remembers whether its bastion was verified, and forgets it
when the bastion it points at changes."""
import os
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_probeverified_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP

from services import probe_manager  # noqa: E402

JUMP = {"jump_host": "198.51.100.60", "jump_port": 22, "jump_identity": "id-hk"}


class ProbeVerified(unittest.TestCase):
    def _jump_probe(self, name):
        probe, _ = probe_manager.create_probe(name, "jump", [], **JUMP)
        return probe["id"]

    def test_new_probe_is_not_verified(self):
        sid = self._jump_probe("verif-new")
        self.assertIsNone(probe_manager.get_probe(sid)["bastion_verified_ts"])

    def test_mark_sets_a_timestamp(self):
        sid = self._jump_probe("verif-mark")
        self.assertTrue(probe_manager.mark_bastion_verified(sid))
        self.assertIsInstance(probe_manager.get_probe(sid)["bastion_verified_ts"], float)
        self.assertFalse(probe_manager.mark_bastion_verified("no-such-probe"))

    def test_changing_the_bastion_clears_it(self):
        for field, value in (("jump_host", "198.51.100.61"), ("jump_port", 2222),
                             ("jump_identity", "id-other")):
            with self.subTest(field=field):
                sid = self._jump_probe(f"verif-{field}")
                probe_manager.mark_bastion_verified(sid)
                probe_manager.update_probe(sid, **{field: value})
                self.assertIsNone(probe_manager.get_probe(sid)["bastion_verified_ts"])

    def test_rename_keeps_verified(self):
        sid = self._jump_probe("verif-rename")
        probe_manager.mark_bastion_verified(sid)
        probe_manager.update_probe(sid, name="verif-renamed", subnets=["10.30.0.0/24"])
        self.assertIsNotNone(probe_manager.get_probe(sid)["bastion_verified_ts"])


if __name__ == "__main__":
    unittest.main()
