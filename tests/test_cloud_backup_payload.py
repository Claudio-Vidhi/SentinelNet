# -*- coding: utf-8 -*-
"""cloud_backup.payload: client-side encryption of a single file."""
import unittest

from services.cloud_backup import payload


class TestCloudBackupPayload(unittest.TestCase):

    def test_round_trip(self):
        clear = b"hostname switch-01\ninterface GigabitEthernet1/0/1\n"
        token = payload.encrypt_bytes(clear)
        self.assertNotEqual(clear, token)
        self.assertEqual(clear, payload.decrypt_bytes(token))

    def test_remote_name_marks_encrypted_files(self):
        rel = "site-a/cisco/switch-01-192.0.2.10.txt"
        self.assertEqual(rel, payload.remote_name(rel, False))
        self.assertEqual(rel + ".enc", payload.remote_name(rel, True))

    def test_empty_file_survives_the_round_trip(self):
        self.assertEqual(b"", payload.decrypt_bytes(payload.encrypt_bytes(b"")))


if __name__ == "__main__":
    unittest.main()
