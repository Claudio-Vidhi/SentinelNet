# -*- coding: utf-8 -*-
"""The files holding secrets must not be readable by whoever the directory is.

users.json carries every password hash and sites.json every agent site-token
hash, and neither tightened its permissions at all -- not on the temp copy, not
on the final name. On a shared data directory that is offline hash cracking.

The temp copy matters as much as the final name: it already holds the secret,
and on POSIX ``os.replace`` carries the source's mode onto the destination.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_secperm_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from security import user_manager  # noqa: E402
from services import site_manager  # noqa: E402


class _Spy:
    """Records each path handed to restrict_permissions, and whether it was
    still on disk at the time -- restricting a path after the rename that
    consumed it would be a no-op that still looks like a call."""

    def __init__(self):
        self.calls = []

    def __call__(self, path):
        self.calls.append((path, os.path.exists(path)))

    @property
    def paths(self):
        return [p for p, _ in self.calls]


class TestSecretFilePermissions(unittest.TestCase):

    def _assert_tmp_then_final(self, spy, final):
        self.assertTrue(spy.calls, "nothing was restricted at all")
        self.assertEqual(spy.paths[0], final + ".tmp",
                         "the temp copy was not the first thing restricted")
        self.assertTrue(spy.calls[0][1], "the temp copy was already gone")
        self.assertIn(final, spy.paths, "the final file was never restricted")

    def test_users_json_is_restricted(self):
        spy = _Spy()
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "users.json")
            with patch.object(user_manager, "USERS_JSON", target), \
                 patch.object(user_manager.data_config,
                              "restrict_permissions", spy):
                user_manager._save_users({"admin": {"password": "hash"}})
            self._assert_tmp_then_final(spy, target)
            self.assertTrue(os.path.exists(target))

    def test_sites_json_is_restricted(self):
        spy = _Spy()
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "sites.json")
            with patch.object(site_manager, "SITES_JSON", target), \
                 patch.object(site_manager.data_config,
                              "restrict_permissions", spy):
                site_manager._save({"s1": {"id": "s1", "token_hash": "abc"}})
            self._assert_tmp_then_final(spy, target)
            self.assertTrue(os.path.exists(target))


if __name__ == "__main__":
    unittest.main()
