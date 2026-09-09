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


class AclsAreGrantedBySid(unittest.TestCase):
    """Il comando icacls deve nominare SID noti, non %USERNAME%.

    Sotto il servizio Windows il processo gira come LocalSystem, dove USERNAME
    vale l'account macchina ("HOST$"): icacls non lo risolve, esce 1332 e
    fallisce l'INTERO comando, /inheritance:r compreso. I file restavano con
    l'ACL ereditata da C:\\ProgramData, che concede lettura a BUILTIN\\Users --
    e uno di quei file e' secret.key, la chiave con cui si decifra ogni
    password di apparato. Da sorgente non si vedeva: li' USERNAME si risolve.
    """

    class _Res:
        returncode = 0
        stderr = b""

    def _argv_for(self, sid):
        calls = []

        def fake_run(args, **kw):
            calls.append(args)
            return self._Res()

        with patch.object(data_config.sys, "platform", "win32"), \
             patch.object(data_config, "_current_user_sid", lambda: sid), \
             patch.object(data_config.subprocess, "run", fake_run):
            data_config.restrict_permissions(r"C:\fake\secret.key")
        self.assertEqual(len(calls), 1)
        return calls[0]

    def test_command_names_well_known_sids_and_no_account_name(self):
        argv = self._argv_for("S-1-5-18")
        self.assertIn("/inheritance:r", argv)
        self.assertIn("*S-1-5-18:F", argv)          # SYSTEM
        self.assertIn("*S-1-5-32-544:F", argv)      # Administrators
        # Un account macchina finisce sempre per '$': e' la forma che icacls
        # non sapeva risolvere.
        for arg in argv:
            self.assertNotIn("$", arg, f"nome account non risolvibile: {arg!r}")

    def test_system_is_not_granted_twice_when_running_as_system(self):
        argv = self._argv_for("S-1-5-18")
        self.assertEqual(argv.count("*S-1-5-18:F"), 1)

    def test_the_running_account_is_added_by_sid(self):
        argv = self._argv_for("S-1-5-21-1-2-3-1001")
        self.assertIn("*S-1-5-21-1-2-3-1001:F", argv)

    @unittest.skipUnless(os.name == "nt", "ACL di Windows")
    def test_inheritance_is_really_broken_on_disk(self):
        # Il test end-to-end: la riga (I) segna un permesso EREDITATO, e prima
        # restava su ogni file perche' icacls non arrivava mai a rimuoverla.
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "secret.key")
            with open(target, "w", encoding="utf-8") as fh:
                fh.write("x")
            data_config.restrict_permissions(target)
            out = subprocess.run(["icacls", target], capture_output=True,
                                 timeout=15).stdout.decode(errors="ignore")
        self.assertNotIn("(I)", out, f"permessi ancora ereditati:\n{out}")


class ExistingFilesAreRepaired(unittest.TestCase):
    """secret.key si scrive una volta sola: correggere il comando non ripara
    da solo un'installazione nata con le ACL sbagliate."""

    def test_every_sensitive_file_on_disk_is_restricted(self):
        spy = _Spy()
        with tempfile.TemporaryDirectory() as d:
            present = sorted(data_config._SENSITIVE_FILES)[:3]
            for name in present:
                with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                    fh.write("x")
            with patch.dict(os.environ, {"SENTINELNET_DATA_DIR": d}), \
                 patch.object(data_config, "restrict_permissions", spy):
                data_config.enforce_sensitive_permissions()
            self.assertEqual(sorted(os.path.basename(p) for p in spy.paths),
                             present)

    def test_missing_files_are_not_touched(self):
        spy = _Spy()
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, {"SENTINELNET_DATA_DIR": d}), \
                 patch.object(data_config, "restrict_permissions", spy):
                data_config.enforce_sensitive_permissions()
            self.assertEqual(spy.paths, [])


if __name__ == "__main__":
    unittest.main()
