# -*- coding: utf-8 -*-
"""The git mirror is redundancy: a second copy, never a second source.

A redundancy feature that silently is not running is worse than one that is
off, so enabling it without git must fail loudly.
"""
import unittest
from unittest import mock

from services.config_drift import mirror

DEVICE = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco_ios"}


class TheMirrorFailsLoudly(unittest.TestCase):
    def test_enabling_without_git_raises(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(mirror.MirrorUnavailable):
                mirror.enable()

    def test_a_disabled_mirror_commits_nothing(self):
        with mock.patch.object(mirror, "is_enabled", return_value=False), \
             mock.patch("subprocess.run") as run:
            mirror.commit_version(DEVICE, "switch-01.txt")
        run.assert_not_called()

    def test_an_enabled_mirror_commits(self):
        with mock.patch.object(mirror, "is_enabled", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/git"), \
             mock.patch("subprocess.run") as run:
            mirror.commit_version(DEVICE, "switch-01.txt")
        self.assertTrue(run.called)

    def test_git_calls_are_bounded_by_a_timeout(self):
        # commit_version runs on the collection thread, inside the backup
        # path: a wedged git commit (signing prompt, stalled hook, wedged
        # filesystem) must not hang the scheduler for every remaining device.
        with mock.patch.object(mirror, "is_enabled", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/git"), \
             mock.patch("subprocess.run") as run:
            mirror.commit_version(DEVICE, "switch-01.txt")
        self.assertTrue(run.called)
        for call in run.call_args_list:
            self.assertEqual(30, call.kwargs.get("timeout"))

    def test_a_git_timeout_never_escapes(self):
        import subprocess
        with mock.patch.object(mirror, "is_enabled", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/git"), \
             mock.patch("subprocess.run",
                        side_effect=subprocess.TimeoutExpired("git", 30)):
            mirror.commit_version(DEVICE, "switch-01.txt")   # must not raise

    def test_a_git_failure_never_escapes(self):
        import subprocess
        with mock.patch.object(mirror, "is_enabled", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/git"), \
             mock.patch("subprocess.run",
                        side_effect=subprocess.CalledProcessError(1, "git")):
            mirror.commit_version(DEVICE, "switch-01.txt")   # must not raise

    def test_a_failure_before_the_git_calls_never_escapes(self):
        """history_dir() calls os.makedirs, which raises on a full disk or a
        permission problem. It used to sit outside the try, so it escaped into
        the backup path — the one thing this module must never do."""
        with mock.patch.object(mirror, "is_enabled", return_value=True), \
             mock.patch("services.config_drift.history.history_dir",
                        side_effect=OSError("disk full")):
            mirror.commit_version(DEVICE, "switch-01.txt")   # must not raise


if __name__ == "__main__":
    unittest.main()
