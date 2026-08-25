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
                if data == b"boom":
                    raise IOError("connection dropped mid-write")
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

    def remove(self, path):
        self.calls.append(("remove", path))
        self.files.pop(path, None)

    def close(self):
        self.calls.append(("close",))


class FakeHostKey:
    def get_name(self):
        return "ssh-ed25519"

    def get_base64(self):
        return "AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExAA"


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

    def test_put_removes_the_temp_file_when_the_write_fails(self):
        target, client = self._target()
        with self.assertRaises(IOError):
            target.put(b"boom", "/srv/backups/site-a/switch-01.txt")
        kinds = [c[0] for c in client.calls if c[0] in ("open", "remove", "rename")]
        self.assertEqual(["open", "remove"], kinds)
        opened = [c for c in client.calls if c[0] == "open"][0][1]
        removed = [c for c in client.calls if c[0] == "remove"][0][1]
        self.assertEqual(opened, removed)
        self.assertNotIn("/srv/backups/site-a/switch-01.txt", client.files)


class TestPinningPolicy(unittest.TestCase):
    """The MissingHostKeyPolicy is what paramiko calls after key exchange but
    before authentication -- raising here is what keeps a spoofed host from
    ever receiving the operator's password or key signature."""

    def test_a_mismatched_pin_raises_from_the_callback_without_touching_the_client(self):
        policy = sftp._PinningPolicy("SHA256:something-else")
        client = mock.Mock()
        with self.assertRaises(sftp.HostKeyMismatch):
            policy.missing_host_key(client, "backup.example.net", FakeHostKey())
        self.assertEqual([], client.method_calls)

    def test_an_unpinned_policy_accepts_and_records_the_observed_fingerprint(self):
        policy = sftp._PinningPolicy("")
        client = mock.Mock()
        policy.missing_host_key(client, "backup.example.net", FakeHostKey())  # must not raise
        self.assertTrue(policy.fingerprint.startswith("SHA256:"))

    def test_open_target_aborts_before_authentication_completes_on_mismatch(self):
        cfg = {
            "host": "192.0.2.10", "port": 22, "username": "svc",
            "auth": "key", "key_path": "irrelevant.key",
            "host_key_fingerprint": "SHA256:something-else",
        }
        with mock.patch.object(sftp.paramiko, "SSHClient") as fake_cls:
            ssh = fake_cls.return_value

            def fake_connect(**kwargs):
                # Mirrors paramiko: the policy callback runs inside connect(),
                # before authentication would occur, and its exception
                # propagates straight out of connect().
                policy = ssh.set_missing_host_key_policy.call_args[0][0]
                policy.missing_host_key(ssh, cfg["host"], FakeHostKey())

            ssh.connect.side_effect = fake_connect

            with self.assertRaises(sftp.HostKeyMismatch):
                sftp.open_target(cfg)

            ssh.open_sftp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
