# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
import unittest
from unittest.mock import patch

from services import tenant_telemetry


class TestTenantTelemetry(unittest.TestCase):

    def test_default_tenant_telemetry(self):
        with patch.object(tenant_telemetry, "get_app_settings", return_value={}):
            cfg = tenant_telemetry.get_tenant_telemetry("Sede-Test")
            self.assertTrue(cfg["ping_enabled"])
            self.assertTrue(cfg["snmp_enabled"])
            self.assertTrue(cfg["triage_enabled"])
            self.assertTrue(tenant_telemetry.is_telemetry_enabled("Sede-Test", "ping"))

    def test_save_tenant_telemetry_override(self):
        saved = {}

        def mock_save(new_data):
            saved.update(new_data)

        with patch.object(tenant_telemetry, "get_app_settings", return_value=saved), \
             patch.object(tenant_telemetry, "save_app_settings", side_effect=mock_save), \
             patch.object(tenant_telemetry, "log_audit"):
            res = tenant_telemetry.save_tenant_telemetry(
                "Sede-01",
                {"ping_enabled": False, "snmp_enabled": True, "api_enabled": False, "triage_enabled": False},
                "admin_tester"
            )
            self.assertFalse(res["ping_enabled"])
            self.assertTrue(res["snmp_enabled"])
            self.assertFalse(res["triage_enabled"])

            self.assertFalse(tenant_telemetry.is_telemetry_enabled("Sede-01", "ping"))
            self.assertTrue(tenant_telemetry.is_telemetry_enabled("Sede-01", "snmp"))
            self.assertFalse(tenant_telemetry.is_telemetry_enabled("Sede-01", "triage"))
            self.assertFalse(tenant_telemetry.is_telemetry_enabled("Sede-01", "api"))

    def test_put_unknown_tenant_is_404(self):
        from fastapi import HTTPException
        from routers import settings as settings_router
        with patch("services.inventory_manager.get_all_groups", return_value={"Sede-01": {}}),              patch.object(tenant_telemetry, "save_app_settings") as save:
            with self.assertRaises(HTTPException) as ctx:
                settings_router.set_tenant_telemetry_settings(
                    "Inesistente", settings_router.TenantTelemetrySchema(), {"sub": "admin"})
        self.assertEqual(ctx.exception.status_code, 404)
        save.assert_not_called()

    def test_api_poller_skips_disabled_tenant(self):
        from observability.ingesters import api_poller
        from services import fortigate_service, inventory_manager, cve_intel
        devs = [{"IP": "192.0.2.1", "Group": "Sede-01"}, {"IP": "192.0.2.2", "Group": "Sede-02"}]
        polled = []
        with patch.object(cve_intel, "refresh_due"), \
             patch.object(fortigate_service, "token_status", return_value={d["IP"]: {} for d in devs}), \
             patch.object(inventory_manager, "get_all_devices", return_value=devs), \
             patch.object(tenant_telemetry, "get_app_settings",
                          return_value={"tenant_telemetry": {"Sede-01": {"api_enabled": False}}}), \
             patch.object(api_poller, "_poll_device", side_effect=lambda d: polled.append(d["IP"]) or []), \
             patch("redundancy.service.discover_fgcp"):
            api_poller.poll_once()
        self.assertEqual(polled, ["192.0.2.2"])
