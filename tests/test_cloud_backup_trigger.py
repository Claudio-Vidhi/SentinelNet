# -*- coding: utf-8 -*-
"""Il mirror parte dopo un ciclo di backup solo se richiesto, e un suo
fallimento non deve mai far fallire il backup."""
import unittest
from unittest import mock

from core import core_engine


class TestMirrorTrigger(unittest.TestCase):

    def test_disabled_mirror_is_not_called(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": False, "run_after_backup": True}), \
             mock.patch("services.cloud_backup.run_mirror") as run:
            core_engine.maybe_mirror_offsite()
        run.assert_not_called()

    def test_run_after_backup_off_is_not_called(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": True, "run_after_backup": False}), \
             mock.patch("services.cloud_backup.run_mirror") as run:
            core_engine.maybe_mirror_offsite()
        run.assert_not_called()

    def test_enabled_mirror_runs(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": True, "run_after_backup": True}), \
             mock.patch("services.cloud_backup.run_mirror",
                        return_value={"ok": True}) as run:
            core_engine.maybe_mirror_offsite()
        run.assert_called_once()

    def test_a_failing_mirror_never_raises_into_the_backup_cycle(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": True, "run_after_backup": True}), \
             mock.patch("services.cloud_backup.run_mirror",
                        side_effect=OSError("connection refused")):
            core_engine.maybe_mirror_offsite()  # must not raise


if __name__ == "__main__":
    unittest.main()
