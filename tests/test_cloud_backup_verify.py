# -*- coding: utf-8 -*-
"""A remote that accepts writes and discards them must not look like success."""
import tempfile
import unittest
from unittest import mock

from services.cloud_backup import sync
from tests.test_cloud_backup_sync import FakeTarget, _write


class LyingTarget(FakeTarget):
    def size(self, remote_path):
        if remote_path.endswith("_manifest.json") or remote_path.endswith("restore.py"):
            return len(self.written.get(remote_path, b""))
        return 0  # accepted the write, stored nothing


class TestVerification(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        _write(self.root, "site-a/cisco/switch-01-192.0.2.10.txt", "hostname switch-01\n")
        cfg = {"enabled": True, "kind": "sftp", "host": "backup.example.net", "port": 22,
               "username": "sentinelnet", "auth": "password", "password": "s3cret",
               "remote_root": "/srv/backups", "encrypt_payload": False,
               "host_key_fingerprint": ""}
        for p in [mock.patch("services.cloud_backup.sync.BACKUP_FOLDER", self.root),
                  mock.patch("services.cloud_backup.settings.read", return_value=cfg),
                  mock.patch("services.cloud_backup.state.known_hashes", return_value={}),
                  mock.patch("services.cloud_backup.state.record_run")]:
            p.start(); self.addCleanup(p.stop)

    def test_a_discarded_upload_fails_the_run_and_names_the_file(self):
        result = sync.run_mirror(open_target=lambda cfg: LyingTarget())
        self.assertFalse(result["ok"])
        self.assertIn("switch-01-192.0.2.10.txt", result["error"])
        self.assertEqual({}, result["files"])


if __name__ == "__main__":
    unittest.main()
