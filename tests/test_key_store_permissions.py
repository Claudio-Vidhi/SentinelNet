# -*- coding: utf-8 -*-
"""The key file must never exist, even briefly, with inherited permissions.

_atomic_write writes the key to "<path>.tmp" and renames it. The ACLs were
tightened only on the final name, so between the write and the rename the key
sat on disk readable by whoever the directory allows.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_keyperm_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from security import secure_key_store  # noqa: E402


class TestAtomicWritePermissions(unittest.TestCase):

    def test_the_temp_file_is_restricted_before_the_rename(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "vault.key")
            seen = []

            def _spy(path):
                # Record the order, and that the temp file still existed when
                # it was restricted -- restricting it after the rename would
                # be a no-op on a path that no longer holds the key.
                seen.append((path, os.path.exists(path)))

            with patch.object(secure_key_store.data_config,
                              "restrict_permissions", _spy):
                secure_key_store._atomic_write(target, b"secret-key-material")

            self.assertTrue(seen, "no permission tightening happened at all")
            self.assertEqual(seen[0][0], target + ".tmp",
                             "the temp file was not the first thing restricted")
            self.assertTrue(seen[0][1], "the temp file was already gone")
            self.assertIn(target, [p for p, _ in seen])

    def test_the_key_still_lands_intact(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "vault.key")
            secure_key_store._atomic_write(target, b"secret-key-material")
            with open(target, "rb") as fh:
                self.assertEqual(fh.read(), b"secret-key-material")
            self.assertFalse(os.path.exists(target + ".tmp"))


if __name__ == "__main__":
    unittest.main()
