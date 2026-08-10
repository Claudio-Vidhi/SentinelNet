# -*- coding: utf-8 -*-
"""Migrazione dei file di stato da CWD a DATA_DIR.

Se 'secret.key' non arriva a destinazione, secure_key_store la legge come
primo avvio e ne genera una nuova: le password cifrate in inventario
diventano indecifrabili e decrypt_password ritorna "". Un fallimento su un
file sensibile deve fermare l'avvio, non passare inosservato.
"""

import os
import tempfile
import unittest
from unittest import mock

from core import data_config


class TestSensitiveMigrationFailsClosed(unittest.TestCase):

    def _run_with_failing_replace(self, filename):
        with tempfile.TemporaryDirectory() as cwd, \
             tempfile.TemporaryDirectory() as ddir:
            with open(os.path.join(cwd, filename), "wb") as f:
                f.write(b"placeholder")
            with mock.patch.object(data_config, "DATA_DIR", ddir), \
                 mock.patch("os.getcwd", return_value=cwd), \
                 mock.patch("os.replace", side_effect=OSError("file bloccato")):
                data_config._migrate_legacy_files()

    def test_secret_key_failure_is_fatal(self):
        with self.assertRaises(RuntimeError) as ctx:
            self._run_with_failing_replace("secret.key")
        self.assertIn("secret.key", str(ctx.exception))

    def test_non_sensitive_failure_is_logged_not_fatal(self):
        # audit.log non e' in _SENSITIVE_FILES: si registra e si prosegue.
        with self.assertLogs(level="ERROR") as logs:
            self._run_with_failing_replace("audit.log")
        self.assertTrue(any("audit.log" in m for m in logs.output))

    def test_migration_still_works_when_nothing_fails(self):
        """Le due prove sopra guardano solo i fallimenti: senza questa, un
        `raise` incondizionato le lascerebbe verdi e romperebbe ogni avvio."""
        with tempfile.TemporaryDirectory() as cwd, \
             tempfile.TemporaryDirectory() as ddir:
            src = os.path.join(cwd, "secret.key")
            with open(src, "wb") as f:
                f.write(b"placeholder")
            with mock.patch.object(data_config, "DATA_DIR", ddir), \
                 mock.patch("os.getcwd", return_value=cwd):
                data_config._migrate_legacy_files()

            self.assertFalse(os.path.exists(src), "l'originale doveva spostarsi")
            dst = os.path.join(ddir, "secret.key")
            self.assertTrue(os.path.exists(dst), "il file non e' arrivato")
            with open(dst, "rb") as f:
                self.assertEqual(f.read(), b"placeholder")


if __name__ == "__main__":
    unittest.main()
