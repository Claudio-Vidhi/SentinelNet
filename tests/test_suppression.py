# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Soppressioni: ciò che l'operatore si aspetta, con o senza scadenza.

Un'unica domanda con due forme che altrove sono due funzionalità separate:
"questa porta è giù per progetto" e "questo apparato è in manutenzione
stanotte". 'Per sempre' non è un caso speciale — è il caso senza scadenza.

Il fatto resta: l'evento non sparisce da ``events``. Only the Interfaces
tab's reading of the port changes.
"""

import os
import tempfile
import time
import unittest
from unittest.mock import patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_suppr_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from observability import suppression  # noqa: E402

NOW = int(time.time())
DEVICE = "192.168.31.6"
TENANT = "test_cml"
ENTITY = f"ip:{DEVICE}"


def _rule(interface=None, from_ts=None, to_ts=None, tenant=TENANT):
    return {"tenant": tenant, "entity_key": ENTITY, "device_ip": DEVICE,
            "interface": interface, "from_ts": from_ts, "to_ts": to_ts,
            "note": "", "by": "test", "created_ts": NOW}


def _saved(*rules):
    return {suppression.key(r["tenant"], r["entity_key"], r["interface"]): r
            for r in rules}


class TestMatching(unittest.TestCase):
    """La logica pura, senza database."""

    def _with(self, *rules):
        return patch("observability.suppression.get_app_settings",
                     return_value={"suppressions": _saved(*rules)})

    def test_no_window_means_always(self):
        with self._with(_rule(interface="Vl20")):
            self.assertIsNotNone(
                suppression.active(TENANT, ENTITY, "Vl20", NOW - 86400 * 365))
            self.assertIsNotNone(
                suppression.active(TENANT, ENTITY, "Vl20", NOW + 86400 * 365))

    def test_a_window_covers_only_its_own_time(self):
        with self._with(_rule(interface="Et0/0", from_ts=NOW - 600,
                              to_ts=NOW + 600)):
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW - 900))
            self.assertIsNotNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW))
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW + 900))

    def test_an_open_ended_window_has_a_start_but_no_end(self):
        with self._with(_rule(from_ts=NOW - 60)):
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW - 120))
            self.assertIsNotNone(
                suppression.active(TENANT, ENTITY, "Et0/0", NOW + 86400))

    def test_a_device_suppression_covers_every_interface(self):
        with self._with(_rule(interface=None)):
            for iface in ("Et0/0", "Vl20", None):
                self.assertIsNotNone(
                    suppression.active(TENANT, ENTITY, iface, NOW), iface)

    def test_an_interface_suppression_covers_only_that_one(self):
        with self._with(_rule(interface="Vl20")):
            self.assertIsNotNone(suppression.active(TENANT, ENTITY, "Vl20", NOW))
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW))

    def test_tenants_do_not_bleed(self):
        with self._with(_rule(interface="Vl20", tenant="altra-sede")):
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Vl20", NOW))

    def test_a_broken_settings_section_does_not_break_the_engine(self):
        with patch("observability.suppression.get_app_settings",
                   return_value={"suppressions": "non-un-dizionario"}):
            self.assertEqual(suppression.all_rules(), {})
            self.assertIsNone(suppression.active(TENANT, ENTITY, "Vl20", NOW))

    def test_expired_is_about_the_end_not_the_start(self):
        self.assertTrue(suppression.expired(_rule(to_ts=NOW - 1), NOW))
        self.assertFalse(suppression.expired(_rule(to_ts=NOW + 1), NOW))
        self.assertFalse(suppression.expired(_rule(), NOW))


class TestDeviceScopeFromTheApi(unittest.TestCase):
    """La manutenzione sull'INTERO apparato non aveva un modo per essere
    dichiarata dall'API: si poteva sopprimere una porta alla volta."""

    def _client(self):
        from fastapi.testclient import TestClient
        import app_server
        from routers import deps
        overrides = app_server.app.dependency_overrides
        self._previous = {
            deps.get_current_user: overrides.get(deps.get_current_user),
            deps.user_group_scope: overrides.get(deps.user_group_scope),
        }
        overrides[deps.get_current_user] = lambda: {"sub": "op", "role": "operator"}
        overrides[deps.user_group_scope] = lambda: None
        return TestClient(app_server.app)

    def tearDown(self):
        import app_server
        for dep, previous in getattr(self, "_previous", {}).items():
            if previous is None:
                app_server.app.dependency_overrides.pop(dep, None)
            else:
                app_server.app.dependency_overrides[dep] = previous
        from core.app_settings import save_app_settings
        save_app_settings({"suppressions": {}})

    def test_omitting_the_interface_suppresses_the_whole_device(self):
        client = self._client()
        r = client.post("/api/observability/interfaces/expected",
                        json={"tenant": TENANT, "device_ip": DEVICE,
                              "suppressed": True, "note": "manutenzione"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["suppressed"])
        self.assertEqual(r.json()["key"],
                         suppression.key(TENANT, ENTITY, None))
        # Copre ogni porta senza doverle elencare.
        self.assertIsNotNone(suppression.active(TENANT, ENTITY, "Et0/0", NOW))
        self.assertIsNotNone(suppression.active(TENANT, ENTITY, "Vl20", NOW))

    def test_a_window_that_ends_before_it_starts_is_refused(self):
        client = self._client()
        r = client.post("/api/observability/interfaces/expected",
                        json={"tenant": TENANT, "device_ip": DEVICE,
                              "suppressed": True,
                              "from_ts": NOW, "to_ts": NOW - 60})
        self.assertEqual(r.status_code, 400)

    def test_a_device_without_an_ip_is_refused(self):
        client = self._client()
        r = client.post("/api/observability/interfaces/expected",
                        json={"tenant": TENANT, "suppressed": True})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()
