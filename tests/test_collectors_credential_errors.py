# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""One device without usable credentials must not sink a whole MAC/ARP scan.

get_device_credentials raised inside the collector pool: the exception left
ex.map, the route answered a bare 500, and the panel showed "Errore:" with
nothing after it -- for all the selected switches, because of one.
"""

import unittest
from unittest import mock

from collectors import arp_collector, mac_collector
from core import core_engine
from core.device_credentials import CredentialResolveError

_DEV = {"IP": "192.0.2.20", "Vendor": "cisco", "Profile": "default", "Group": "T"}
_ERR = CredentialResolveError("Nessuna credenziale per il dispositivo 192.0.2.20")


class TestCollectorsCredentialErrors(unittest.TestCase):

    def test_mac_scan_reports_the_device_instead_of_failing(self):
        with mock.patch.object(core_engine, "get_device_credentials", side_effect=_ERR), \
             mock.patch("collectors.mac_history.prune", return_value=0):
            out = mac_collector.collect_all([_DEV])
        self.assertEqual(out["scanned"], 1)
        self.assertIn("Nessuna credenziale", out["results"][0]["error"])

    def test_arp_collection_reports_the_device_instead_of_failing(self):
        with mock.patch.object(core_engine, "get_device_credentials", side_effect=_ERR):
            res = arp_collector.collect_from_device(_DEV)
        self.assertEqual(res["status"], "error")
        self.assertIn("Nessuna credenziale", res["message"])

    def test_routes_turn_credential_errors_into_409_with_the_reason(self):
        import asyncio
        import json
        import app_server
        from core.device_credentials import CredentialDecryptError
        for cls in (CredentialResolveError, CredentialDecryptError):
            handler = app_server.app.exception_handlers[cls]
            resp = asyncio.run(handler(None, cls("Nessuna credenziale per X")))
            self.assertEqual(resp.status_code, 409)
            self.assertIn("Nessuna credenziale", json.loads(resp.body)["detail"])

if __name__ == "__main__":
    unittest.main()
