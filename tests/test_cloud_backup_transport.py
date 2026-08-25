# -*- coding: utf-8 -*-
"""cloud_backup.sftp: the two things a transport must not get wrong --
never trust an unpinned host key, never leave a truncated file in place."""
import unittest
from unittest import mock

from services.cloud_backup import sftp


class FakeSftpClient:
    def __init__(self):
        self.calls = []
        self.files = {}

    def stat(self, path):
        if path not in self.files:
            raise IOError("no such file")
        return mock.Mock(st_size=len(self.files[path]))

    def mkdir(self, path):
        self.calls.append(("mkdir", path))
        self.files[path] = b""

    def open(self, path, mode):
        self.calls.append(("open", path, mode))
        client = self

        class _F:
            def write(self, data):
                client.files[path] = data

            def read(self):
                return client.files.get(path, b"")

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *exc):
                return False

        return _F()

    def posix_rename(self, src, dst):
        self.calls.append(("rename", src, dst))
        self.files[dst] = self.files.pop(src)

    def close(self):
        self.calls.append(("close",))


class FakeHostKey:
    def get_name(self):
        return "ssh-ed25519"

    def get_base64(self):
        return "AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleEx"


class TestSftpTarget(unittest.TestCase):

    def _target(self, pinned=""):
        client = FakeSftpClient()
        transport = mock.Mock()
        transport.get_remote_server_key.return_value = FakeHostKey()
        ssh = mock.Mock()
        ssh.get_transport.return_value = transport
        return sftp.SftpTarget(ssh, client, pinned_fingerprint=pinned), client

    def test_put_writes_a_temp_name_then_renames(self):
        target, client = self._target()
        target.put(b"hostname switch-01\n", "/srv/backups/site-a/switch-01.txt")
        kinds = [c[0] for c in client.calls if c[0] in ("open", "rename")]
        self.assertEqual(["open", "rename"], kinds)
        opened = [c for c in client.calls if c[0] == "open"][0][1]
        self.assertTrue(opened.endswith(".part"), opened)
        self.assertEqual(("rename", opened, "/srv/backups/site-a/switch-01.txt"),
                         [c for c in client.calls if c[0] == "rename"][0])

    def test_a_pinned_fingerprint_that_does_not_match_aborts_before_any_write(self):
        target, client = self._target(pinned="SHA256:something-else")
        with self.assertRaises(sftp.HostKeyMismatch):
            target.verify_host_key()
        self.assertEqual([], client.calls)

    def test_a_matching_fingerprint_passes(self):
        target, _ = self._target()
        target.pinned_fingerprint = target.fingerprint
        target.verify_host_key()  # must not raise

    def test_ensure_dir_creates_each_missing_level_once(self):
        target, client = self._target()
        target.ensure_dir("/srv/backups/site-a/cisco")
        made = [c[1] for c in client.calls if c[0] == "mkdir"]
        self.assertEqual(["/srv", "/srv/backups", "/srv/backups/site-a",
                          "/srv/backups/site-a/cisco"], made)
        client.calls.clear()
        target.ensure_dir("/srv/backups/site-a/cisco")
        self.assertEqual([], [c for c in client.calls if c[0] == "mkdir"])


if __name__ == "__main__":
    unittest.main()
