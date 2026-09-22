# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A credential that cannot be resolved stops the triage before the device.

An identity whose password no longer decrypted (secret.key replaced) was
sent to every device with an empty password: authentication failures on the
whole tenant, doubled by the auth-failure retry, and device-side login
blocking that then refused the correct password too.
"""

import unittest
from unittest import mock

from core import core_engine
from security.identity_manager import IdentityDecryptError


class TestTriageCredentialErrors(unittest.TestCase):

    def test_undecryptable_identity_returns_an_error_without_connecting(self):
        dev = {"IP": "192.0.2.10", "Vendor": "cisco", "Site": "central",
               "Profile": "identity:abc"}
        with mock.patch.object(core_engine.site_manager, "is_agent_site", return_value=False), \
             mock.patch.object(core_engine.site_manager, "has_direct_path", return_value=True), \
             mock.patch.object(core_engine, "is_reachable", return_value=True), \
             mock.patch.object(core_engine, "get_device_credentials",
                               side_effect=IdentityDecryptError("Credenziali dell'identita' 'adm' non decifrabili")), \
             mock.patch.object(core_engine, "resolve_driver") as driver, \
             mock.patch.object(core_engine, "log_audit"):
            res = core_engine.run_backup_and_triage(dev)
        self.assertEqual(res["status"], "error")
        self.assertIn("non decifrabili", res["message"])
        # Not auth_failed: that would queue a retry against the device.
        self.assertNotIn("inventory_status", res)
        driver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
