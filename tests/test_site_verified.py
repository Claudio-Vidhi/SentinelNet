# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A jump site remembers whether its bastion was verified, and forgets it
when the bastion it points at changes."""
import os
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_siteverified_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP

from services import site_manager  # noqa: E402

JUMP = {"jump_host": "198.51.100.60", "jump_port": 22, "jump_identity": "id-hk"}


class SiteVerified(unittest.TestCase):
    def _jump_site(self, name):
        site, _ = site_manager.create_site(name, "jump", [], **JUMP)
        return site["id"]

    def test_new_site_is_not_verified(self):
        sid = self._jump_site("verif-new")
        self.assertIsNone(site_manager.get_site(sid)["bastion_verified_ts"])

    def test_mark_sets_a_timestamp(self):
        sid = self._jump_site("verif-mark")
        self.assertTrue(site_manager.mark_bastion_verified(sid))
        self.assertIsInstance(site_manager.get_site(sid)["bastion_verified_ts"], float)
        self.assertFalse(site_manager.mark_bastion_verified("no-such-site"))

    def test_changing_the_bastion_clears_it(self):
        for field, value in (("jump_host", "198.51.100.61"), ("jump_port", 2222),
                             ("jump_identity", "id-other")):
            with self.subTest(field=field):
                sid = self._jump_site(f"verif-{field}")
                site_manager.mark_bastion_verified(sid)
                site_manager.update_site(sid, **{field: value})
                self.assertIsNone(site_manager.get_site(sid)["bastion_verified_ts"])

    def test_rename_keeps_verified(self):
        sid = self._jump_site("verif-rename")
        site_manager.mark_bastion_verified(sid)
        site_manager.update_site(sid, name="verif-renamed", subnets=["10.30.0.0/24"])
        self.assertIsNotNone(site_manager.get_site(sid)["bastion_verified_ts"])


if __name__ == "__main__":
    unittest.main()
