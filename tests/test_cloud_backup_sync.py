# -*- coding: utf-8 -*-
"""cloud_backup.sync: what gets sent, and what is correctly skipped."""
import json
import os
import tempfile
import unittest
from unittest import mock

from services.cloud_backup import sync


def _write(root, rel, text):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class FakeTarget:
    def __init__(self):
        self.written = {}
        self.fingerprint = "SHA256:example"
        self.pinned_fingerprint = ""

    def verify_host_key(self):
        pass

    def ensure_dir(self, remote_dir):
        pass

    def put(self, data, remote_path):
        self.written[remote_path] = data

    def size(self, remote_path):
        return len(self.written[remote_path]) if remote_path in self.written else None

    def get(self, remote_path):
        return self.written[remote_path]

    def close(self):
        pass


class TestWalkAndPlan(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        _write(self.root, "site-a/cisco/switch-01-192.0.2.10.txt", "hostname switch-01\n")
        _write(self.root, "site-a/cisco/.history/192.0.2.10-index.json",
               '{"device":"192.0.2.10"}')
        _write(self.root, "site-a/cisco/.history/switch-01-192.0.2.10.20260819T110233.451207Z.txt",
               "hostname switch-01\n! older\n")

    def test_walk_includes_history_and_uses_posix_paths(self):
        local = sync.walk_local(self.root)
        self.assertIn("site-a/cisco/switch-01-192.0.2.10.txt", local)
        self.assertIn("site-a/cisco/.history/192.0.2.10-index.json", local)
        self.assertEqual(3, len(local))
        self.assertTrue(local["site-a/cisco/switch-01-192.0.2.10.txt"]["sha256"]
                        .startswith("sha256:"))

    def test_plan_skips_what_is_already_offsite(self):
        local = sync.walk_local(self.root)
        known = {p: e["sha256"] for p, e in local.items()}
        self.assertEqual([], sync.plan_uploads(local, known))

    def test_plan_reuploads_a_changed_file(self):
        local = sync.walk_local(self.root)
        known = {p: e["sha256"] for p, e in local.items()}
        known["site-a/cisco/switch-01-192.0.2.10.txt"] = "sha256:stale"
        self.assertEqual(["site-a/cisco/switch-01-192.0.2.10.txt"],
                         sync.plan_uploads(local, known))

    def test_plan_uploads_everything_when_nothing_is_known(self):
        self.assertEqual(3, len(sync.plan_uploads(sync.walk_local(self.root), {})))

    def test_empty_estate_is_a_no_op(self):
        self.assertEqual({}, sync.walk_local(tempfile.mkdtemp()))


class TestRunMirror(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        _write(self.root, "site-a/cisco/switch-01-192.0.2.10.txt", "hostname switch-01\n")
        self.target = FakeTarget()
        self.cfg = {"enabled": True, "kind": "sftp", "host": "backup.example.net",
                    "port": 22, "username": "sentinelnet", "auth": "password",
                    "password": "s3cret", "remote_root": "/srv/backups",
                    "encrypt_payload": False, "host_key_fingerprint": ""}
        for p in [mock.patch("services.cloud_backup.sync.BACKUP_FOLDER", self.root),
                  mock.patch("services.cloud_backup.settings.read",
                             side_effect=lambda: dict(self.cfg)),
                  mock.patch("services.cloud_backup.state.known_hashes", return_value={}),
                  mock.patch("services.cloud_backup.state.record_run")]:
            p.start(); self.addCleanup(p.stop)

    def test_uploads_then_writes_manifest_and_restore_script(self):
        result = sync.run_mirror(open_target=lambda cfg: self.target)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(1, result["uploaded"])
        self.assertIn("/srv/backups/site-a/cisco/switch-01-192.0.2.10.txt", self.target.written)
        self.assertIn("/srv/backups/_manifest.json", self.target.written)
        self.assertIn("/srv/backups/restore.py", self.target.written)

    def test_encrypted_upload_changes_bytes_but_not_the_manifest_hash(self):
        self.cfg["encrypt_payload"] = True
        result = sync.run_mirror(open_target=lambda cfg: self.target)
        self.assertTrue(result["ok"], result.get("error"))
        rel = "site-a/cisco/switch-01-192.0.2.10.txt"
        self.assertIn(f"/srv/backups/{rel}.enc", self.target.written)
        self.assertNotEqual(b"hostname switch-01\n",
                            self.target.written[f"/srv/backups/{rel}.enc"])
        manifest = json.loads(self.target.written["/srv/backups/_manifest.json"])
        self.assertTrue(manifest["encrypted"])
        self.assertEqual(result["files"][rel], manifest["files"][rel]["sha256"])

    def test_a_disabled_mirror_does_not_connect(self):
        self.cfg["enabled"] = False
        def _boom(cfg):
            raise AssertionError("must not connect when disabled")
        result = sync.run_mirror(open_target=_boom)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
