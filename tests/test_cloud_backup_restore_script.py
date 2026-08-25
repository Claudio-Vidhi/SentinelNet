# -*- coding: utf-8 -*-
"""The uploaded restore.py must rebuild the archive with no import from this
repo: whoever finds that folder in three years has only Python."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from services.cloud_backup.restore_template import RESTORE_SCRIPT


class TestRestoreScript(unittest.TestCase):

    def _archive(self, encrypted=False, key=None):
        root = tempfile.mkdtemp()
        rel = "site-a/cisco/switch-01-192.0.2.10.txt"
        clear = b"hostname switch-01\n"
        body = clear
        rel_remote = rel
        if encrypted:
            from cryptography.fernet import Fernet
            body = Fernet(key).encrypt(clear)
            rel_remote = rel + ".enc"
        path = os.path.join(root, *rel_remote.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)
        with open(os.path.join(root, "_manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"schema": 1, "encrypted": encrypted,
                       "files": {rel: {"sha256": "sha256:x", "size": len(clear)}}}, fh)
        script = os.path.join(root, "restore.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(RESTORE_SCRIPT)
        return root, script, rel, clear

    def test_rebuilds_a_plaintext_archive(self):
        root, script, rel, clear = self._archive()
        out = tempfile.mkdtemp()
        proc = subprocess.run([sys.executable, script, "--source", root, "--target", out],
                              capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)
        with open(os.path.join(out, *rel.split("/")), "rb") as fh:
            self.assertEqual(clear, fh.read())

    def test_rebuilds_an_encrypted_archive_with_the_key(self):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        root, script, rel, clear = self._archive(encrypted=True, key=key)
        keyfile = os.path.join(root, "fernet.key")
        with open(keyfile, "wb") as fh:
            fh.write(key)
        out = tempfile.mkdtemp()
        proc = subprocess.run([sys.executable, script, "--source", root,
                               "--target", out, "--key-file", keyfile],
                              capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)
        with open(os.path.join(out, *rel.split("/")), "rb") as fh:
            self.assertEqual(clear, fh.read())

    def test_an_encrypted_archive_without_a_key_fails_loudly(self):
        from cryptography.fernet import Fernet
        root, script, _rel, _clear = self._archive(encrypted=True, key=Fernet.generate_key())
        out = tempfile.mkdtemp()
        proc = subprocess.run([sys.executable, script, "--source", root, "--target", out],
                              capture_output=True, text=True)
        self.assertNotEqual(0, proc.returncode)
        self.assertIn("--key-file", proc.stdout + proc.stderr)

    def test_the_script_does_not_import_this_repo(self):
        for forbidden in ("services.", "core.", "security."):
            self.assertNotIn(forbidden, RESTORE_SCRIPT)


if __name__ == "__main__":
    unittest.main()
