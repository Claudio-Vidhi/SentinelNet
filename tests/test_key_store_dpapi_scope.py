# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Keys are DPAPI machine-scoped, so the service and the desktop app share them.

A user-scoped key written by the elevated installer (or by the desktop app)
could not be decrypted by the Windows service running as LocalSystem, which
then crashed at every start.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from security import secure_key_store as ks


@unittest.skipUnless(sys.platform == "win32", "DPAPI is Windows-only")
class TestDpapiScope(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "secret.key")
        # icacls is irrelevant here and slow.
        self._p = patch.object(ks.data_config, "restrict_permissions", lambda p: None)
        self._p.start()

    def tearDown(self):
        self._p.stop()
        self._dir.cleanup()

    def _raw(self):
        with open(self.path, "rb") as fh:
            return fh.read()

    def test_new_key_is_machine_scoped(self):
        key = ks.load_or_create(self.path, lambda: b"k" * 32)
        self.assertTrue(self._raw().startswith(ks._MAGIC_MACHINE))
        self.assertEqual(ks.load_or_create(self.path, lambda: b"other"), key)

    def test_user_scoped_key_is_converted_keeping_its_value(self):
        # The pre-fix format: user-scope blob under the v1 prefix.
        ks.data_config.atomic_write(self.path, ks._MAGIC + self._user_blob(b"legacy-key"))
        self.assertEqual(ks.load_or_create(self.path, lambda: b"other"), b"legacy-key")
        self.assertTrue(self._raw().startswith(ks._MAGIC_MACHINE))
        self.assertEqual(ks.load_or_create(self.path, lambda: b"other"), b"legacy-key")

    def test_undecryptable_key_names_the_file_and_the_way_out(self):
        ks.data_config.atomic_write(self.path, ks._MAGIC + b"not a dpapi blob")
        with self.assertRaises(RuntimeError) as cm:
            ks.load_or_create(self.path, lambda: b"other")
        self.assertIn(self.path, str(cm.exception))
        self.assertIn("jwt_secret.key", str(cm.exception))

    @staticmethod
    def _user_blob(data):
        in_blob = ks._to_blob(data)
        out_blob = ks._DATA_BLOB()
        assert ks._crypt32.CryptProtectData(
            ks.ctypes.byref(in_blob), None, None, None, None,
            ks._CRYPTPROTECT_UI_FORBIDDEN, ks.ctypes.byref(out_blob))
        return ks._from_blob(out_blob)


if __name__ == "__main__":
    unittest.main()
