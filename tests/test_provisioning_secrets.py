# -*- coding: utf-8 -*-
"""Test per provisioning_secrets (finding I-2): la config day-0 generata di
default non contiene segreti in chiaro, i placeholder sono presenti e i campi
non sensibili sopravvivono."""

import unittest

from services import fortigate_provisioner
from services import switch_provisioner
from security.provisioning_secrets import mask_secrets

SWITCH_CFG = {
    "hostname": "SW-TEST-01",
    "domain": "lab.local",
    "enable_secret": "EnableSegreto99",
    "admin_user": "admin",
    "admin_password": "AdminPass123",
    "mgmt_vlan": 10,
    "mgmt_ip": "10.0.10.2",
    "mgmt_mask": "255.255.255.0",
    "snmpv3": {"user": "snmpuser", "auth_pass": "AuthP4ss", "priv_pass": "PrivP4ss"},
    "vlans": [{"id": 10, "name": "MGMT"}],
}

FGT_CFG = {
    "hostname": "FGT-TEST-01",
    "admin_user": "secadmin",
    "admin_password": "FgtAdminPass1",
    "snmpv3": {"user": "snmpuser", "auth_pass": "FgtAuthPass", "priv_pass": "FgtPrivPass"},
    "ha": {"group_name": "HA-GRP", "password": "HaSegreta", "hbdev": "ha1"},
}

SWITCH_SECRETS = ["EnableSegreto99", "AdminPass123", "AuthP4ss", "PrivP4ss"]
FGT_SECRETS = ["FgtAdminPass1", "FgtAuthPass", "FgtPrivPass", "HaSegreta"]


class TestMaskSecrets(unittest.TestCase):
    def test_switch_config_no_cleartext(self):
        text = switch_provisioner.build_config(mask_secrets(SWITCH_CFG))
        for s in SWITCH_SECRETS:
            self.assertNotIn(s, text, f"segreto in chiaro: {s}")
        self.assertIn("{{VAULT:enable_secret}}", text)
        self.assertIn("{{VAULT:admin_password}}", text)
        self.assertIn("{{VAULT:snmpv3.auth_pass}}", text)

    def test_switch_non_secrets_survive(self):
        text = switch_provisioner.build_config(mask_secrets(SWITCH_CFG))
        for keep in ("hostname SW-TEST-01", "ip domain-name lab.local",
                     "ip address 10.0.10.2 255.255.255.0", "vlan 10"):
            self.assertIn(keep, text)

    def test_fortigate_config_no_cleartext(self):
        text = fortigate_provisioner.build_config(mask_secrets(FGT_CFG))
        for s in FGT_SECRETS:
            self.assertNotIn(s, text, f"segreto in chiaro: {s}")
        self.assertIn("VAULT:ha.password", text)

    def test_materialized_build_unchanged(self):
        # Il push usa il payload originale: build_config(cfg) resta invariato.
        text = switch_provisioner.build_config(SWITCH_CFG)
        self.assertIn("EnableSegreto99", text)

    def test_mask_preserves_structure_and_empty_values(self):
        masked = mask_secrets({"admin_password": "", "hostname": "X", "nested": {"psk": None}})
        self.assertEqual(masked["admin_password"], "")
        self.assertEqual(masked["hostname"], "X")
        self.assertIsNone(masked["nested"]["psk"])


if __name__ == "__main__":
    unittest.main()
