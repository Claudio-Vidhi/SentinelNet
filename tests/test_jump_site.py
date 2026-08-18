# -*- coding: utf-8 -*-
"""Unit tests for the 'jump' site mode (data model, Task 1 of the
jump-host-sites plan). No tunnel here: only the bastion fields on the site
dict.

Isolates SENTINELNET_DATA_DIR in a temp dir BEFORE importing site_manager,
like test_sites.py / test_remote_site.py: SITES_JSON is resolved via
core.data_config.get_path at module import time, so setting the env var
afterwards would have no effect.
"""
import os
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_jump_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from services import site_manager  # noqa: E402


class JumpSiteModel(unittest.TestCase):
    def test_create_jump_site_keeps_fields_and_issues_no_token(self):
        site, token = site_manager.create_site(
            "Customer A", "jump", subnets=["192.0.2.0/24"],
            jump_host="198.51.100.10", jump_port=22, jump_identity="id-1")
        self.assertIsNone(token)
        self.assertEqual(site["mode"], "jump")
        self.assertEqual(site["jump_host"], "198.51.100.10")
        self.assertEqual(site["jump_port"], 22)
        self.assertEqual(site["jump_identity"], "id-1")

    def test_jump_site_without_host_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer B", "jump", jump_identity="id-1")

    def test_jump_port_zero_is_rejected(self):
        # 0 is falsy, so a naive `port or 22` would silently swap it for the
        # default instead of raising: this must not happen.
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer C", "jump",
                jump_host="198.51.100.10", jump_port=0, jump_identity="id-1")

    def test_jump_port_above_range_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer D", "jump",
                jump_host="198.51.100.10", jump_port=65536, jump_identity="id-1")

    def test_jump_port_negative_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer E", "jump",
                jump_host="198.51.100.10", jump_port=-1, jump_identity="id-1")

    def test_jump_port_non_numeric_is_rejected(self):
        with self.assertRaises(ValueError):
            site_manager.create_site("Customer F", "jump",
                jump_host="198.51.100.10", jump_port="abc", jump_identity="id-1")


if __name__ == "__main__":
    unittest.main()
