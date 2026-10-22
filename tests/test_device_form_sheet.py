# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Sidebar after the "Add devices" wizard: the device form is a sheet opened
from the inventory, Credentials sits under Administer on the same permission
id (tab-provisioning), and "Nuova configurazione" has its own entry."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = ROOT.joinpath("templates", "dashboard.html").read_text(encoding="utf-8")
JS = {n: ROOT.joinpath("static", "js", n).read_text(encoding="utf-8")
      for n in ("devices.js", "add-devices.js", "provisioning.js", "core.js")}


def nav_group(name):
    start = HTML.index(f'data-nav-group="{name}"')
    items = HTML.index('class="nav-group-items"', start)
    return HTML[start:HTML.index('\n        </div>', items)]


class TestDeviceFormSheet(unittest.TestCase):
    def test_form_lives_in_a_sheet_outside_any_tab(self):
        sheet = HTML[HTML.index('id="deviceFormSheet"'):]
        sheet = sheet[:sheet.index('id="addDevicesWizard"')]
        for el_id in ("devFormTitle", "devGroupSelect", "devIp", "devVendor", "devTransports",
                      "devProfile", "devSnmp", "devFormStatus", "btnVerifyDevice", "btnSaveDevice"):
            with self.subTest(id=el_id):
                self.assertIn(f'id="{el_id}"', sheet)
        self.assertIn('data-close-modal="deviceFormSheet"', sheet)
        tab = HTML[HTML.index('<div id="tab-provisioning"'):HTML.index('<div id="tab-groups"')]
        self.assertNotIn('id="devIp"', tab)
        self.assertIn('id="identitiesPanel"', tab)

    def test_edit_and_full_form_open_the_sheet(self):
        dev = JS["devices.js"]
        edit = dev[dev.index("async function editDevice(ip)"):dev.index("function resetDeviceForm()")]
        self.assertNotIn("switchTab(", edit)
        self.assertIn("openModal('deviceFormSheet')", edit)
        self.assertIn("window.openDeviceForm = openDeviceForm", dev)
        self.assertIn("window.openDeviceForm(prefill)", JS["add-devices.js"])
        self.assertNotIn("switchTab('tab-provisioning')", JS["add-devices.js"])

    def test_credentials_page_follows_the_global_tenant(self):
        core = JS["core.js"]
        panel = core[core.index("async function renderIdentitiesPanel()"):]
        self.assertIn("window.globalSelectedTenant", panel[:panel.index("\n}\n")])
        self.assertIn("'globalTenantChanged'", JS["provisioning.js"])


class TestSidebarEntries(unittest.TestCase):
    def test_operations_has_new_device_and_no_import(self):
        ops = nav_group("operations")
        self.assertIn('data-tab="tab-provisioner"', ops)
        self.assertNotIn("tab-provisioning", ops)
        self.assertIsNone(re.search(r'class="nav-item[^"]*"[^>]*data-tabs?="[^"]*tab-import', HTML))

    def test_credentials_under_administer_keeps_the_permission_id(self):
        admin = nav_group("admin")
        m = re.search(r'<button class="nav-item([^"]*)" data-tab="tab-provisioning"', admin)
        self.assertIsNotNone(m)
        self.assertIn("requires-write", m.group(1))
        self.assertIn('data-i18n="tabCredentials"', admin)


class TestNewTenantDialog(unittest.TestCase):
    """One dialog creates a tenant from Organizations, the device form and the wizard."""

    def test_dialog_and_its_three_openers(self):
        dialog = HTML[HTML.index('id="newTenantModal"'):HTML.index('id="deviceFormSheet"')]
        for el_id in ("newGroupName", "btnCreateGroup"):
            self.assertIn(f'id="{el_id}"', dialog)
        groups = HTML[HTML.index('<div id="tab-groups"'):HTML.index('<div id="tab-blueprint"')]
        self.assertIn('id="btnOpenNewTenant"', groups)
        self.assertIn('id="adwNewTenant"', HTML)
        self.assertNotIn('id="inlineNewTenantRow"', HTML)
        self.assertIn("window.openNewTenant = openNewTenant", JS["devices.js"])
        self.assertIn("window.openNewTenant(", JS["add-devices.js"])


class TestWizardCreatesTenantAndLocation(unittest.TestCase):
    def test_location_plus_is_admin_only_and_selects_the_new_one(self):
        self.assertRegex(HTML, r'class="btn btn-secondary requires-admin" id="adwNewLocation"')
        self.assertIn("window.openNewLocation = ", JS["devices.js"])
        self.assertIn("_onLocationCreated(created.id)", JS["devices.js"])
        self.assertIn("if (isAdminRole(currentRole)) newLocation();", JS["add-devices.js"])

    def test_a_dialog_opened_from_another_goes_on_top(self):
        # newTenantModal/locationModal come before the wizard in the template:
        # with equal z-index they opened hidden behind it.
        modal = ROOT.joinpath("static", "js", "ui-modal.js").read_text(encoding="utf-8")
        body = modal[modal.index("function openModal("):modal.index("function closeModal(")]
        self.assertIn("el.style.zIndex = below", body)


class TestFortigateKeepaliveUi(unittest.TestCase):
    def test_checkbox_is_saved_and_shown(self):
        fgt = ROOT.joinpath("static", "js", "fortigate-management.js").read_text(encoding="utf-8")
        self.assertIn('<label for="fgtMgrKeepalive"', HTML)
        self.assertEqual(fgt.count("verify_tls: verifyTls, keepalive"), 2)
        self.assertIn("t.keepalive", fgt)


if __name__ == "__main__":
    unittest.main()
