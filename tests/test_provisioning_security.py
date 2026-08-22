# -*- coding: utf-8 -*-
"""Security regressions in the day-0 provisioning wizard.

Each test here stands for a way the wizard could hand a real device to an
attacker, or lock its owner out of it. The existing provisioning tests only
assert on build_config output and never touch the push paths, which is why
none of these were caught.

RFC 5737 addresses and placeholder hostnames only.
"""

import unittest
from unittest import mock

from pydantic import ValidationError

from routers import provisioner as prov_router
from services import fortigate_provisioner, switch_provisioner


def _switch_cfg(**over):
    cfg = {
        "hostname": "switch-01",
        "admin_user": "netadmin",
        "admin_password": "S3cret-Passphrase",
        "mgmt_vlan": 99,
        "mgmt_ip": "192.0.2.10",
        "mgmt_mask": "255.255.255.0",
    }
    cfg.update(over)
    return cfg


class NoKnownDefaultCredentialEverReachesADevice(unittest.TestCase):
    """'changeme', 'authpass123' and 'privpass123' were substituted whenever a
    field was left empty, so an operator who skipped a box shipped a published
    password to the hardware."""

    def test_the_literal_defaults_are_gone_from_the_generator(self):
        source = open(switch_provisioner.__file__, encoding="utf-8").read()
        for literal in ('"changeme"', '"authpass123"', '"privpass123"'):
            self.assertNotIn(literal, source)

    def test_no_username_line_without_a_password(self):
        text = switch_provisioner.build_config(
            _switch_cfg(admin_user="netadmin", admin_password=""))
        self.assertNotIn("changeme", text)
        self.assertNotIn("username netadmin", text)

    def test_snmpv3_user_is_skipped_when_a_passphrase_is_missing(self):
        text = switch_provisioner.build_config(
            _switch_cfg(snmpv3={"user": "monitor", "auth_pass": "", "priv_pass": ""}))
        self.assertNotIn("snmp-server user", text)
        self.assertNotIn("authpass123", text)
        self.assertNotIn("privpass123", text)


class TheBoundaryRefusesALockedOutSwitch(unittest.TestCase):
    """aaa new-model + 'login local' on con 0 and vty 0 15 are unconditional:
    an empty local user database locks every access path."""

    def test_missing_admin_user_is_rejected(self):
        with self.assertRaises(ValidationError):
            prov_router.SwitchProvisionSchema(**_switch_cfg(admin_user=""))

    def test_missing_admin_password_is_rejected(self):
        with self.assertRaises(ValidationError):
            prov_router.SwitchProvisionSchema(**_switch_cfg(admin_password=""))

    def test_half_configured_snmpv3_is_rejected(self):
        with self.assertRaises(ValidationError):
            prov_router.SwitchProvisionSchema(
                **_switch_cfg(snmpv3={"user": "monitor", "auth_pass": "x"}))

    def test_a_complete_payload_still_validates(self):
        model = prov_router.SwitchProvisionSchema(**_switch_cfg())
        self.assertEqual("netadmin", model.admin_user)


class SshOnlyAlwaysGetsAHostKey(unittest.TestCase):
    """'crypto key generate rsa' refuses to run without a domain name. Emitting
    the domain only when the operator typed one left the device with SSH
    enabled, telnet disabled and no host key: console-only."""

    def test_domain_is_emitted_even_when_the_operator_left_it_blank(self):
        text = switch_provisioner.build_config(_switch_cfg(domain="", ssh_only=True))
        self.assertIn("ip domain-name", text)
        self.assertIn("crypto key generate rsa", text)

    def test_an_explicit_domain_still_wins(self):
        text = switch_provisioner.build_config(_switch_cfg(domain="example.test"))
        self.assertIn("ip domain-name example.test", text)


class APushNeverReportsSuccessOnARejectedConfig(unittest.TestCase):
    """IOS and FortiOS answer a rejected command on the session and carry on,
    so a transport that did not raise says nothing about the config applying."""

    def test_ios_rejection_is_reported_as_partial(self):
        res = switch_provisioner._push_result(
            "interface range Gi1/0/1-24\n% Invalid input detected at '^' marker.\n")
        self.assertEqual("partial", res["status"])
        self.assertEqual(1, len(res["rejected"]))

    def test_a_clean_ios_transcript_is_success(self):
        res = switch_provisioner._push_result("switch-01(config)#\nswitch-01#\n")
        self.assertEqual("success", res["status"])
        self.assertEqual([], res["rejected"])

    def test_fortios_rejection_is_reported_as_partial(self):
        res = fortigate_provisioner._push_result(
            "set hostname fw-01\nCommand fail. Return code -3\n")
        self.assertEqual("partial", res["status"])


class ThePushTranscriptCarriesNoCleartextSecret(unittest.TestCase):
    """The session echoes back every command, so the transcript held every
    password the wizard had just typed — and it is returned to the browser."""

    def test_ios_secrets_are_redacted(self):
        transcript = (
            "enable secret Sup3r-Enable\n"
            "username netadmin privilege 15 secret S3cret-Passphrase\n"
            "snmp-server user monitor G v3 auth sha AuthPhrase priv aes 128 PrivPhrase\n"
        )
        out = switch_provisioner._push_result(transcript)["output"]
        for secret in ("Sup3r-Enable", "S3cret-Passphrase", "AuthPhrase", "PrivPhrase"):
            self.assertNotIn(secret, out)

    def test_fortios_secrets_are_redacted(self):
        out = fortigate_provisioner._push_result(
            'set password "FgtAdminPass"\nset psksecret "TunnelKey"\n')["output"]
        self.assertNotIn("FgtAdminPass", out)
        self.assertNotIn("TunnelKey", out)


class TheWizardRefusesAnAlreadyManagedDevice(unittest.TestCase):
    """The generated config takes policy 1, static route 1 and DHCP server 1
    and rewrites the WAN address: a typo in the host field aimed all of that
    at a production firewall."""

    def test_a_device_in_inventory_is_refused(self):
        from fastapi import HTTPException
        with mock.patch("services.inventory_manager.get_device_by_ip",
                        return_value={"IP": "192.0.2.10", "Hostname": "switch-01"}):
            with self.assertRaises(HTTPException) as ctx:
                prov_router._assert_day_zero("192.0.2.10")
        self.assertEqual(409, ctx.exception.status_code)

    def test_an_unknown_device_passes(self):
        with mock.patch("services.inventory_manager.get_device_by_ip", return_value=None):
            prov_router._assert_day_zero("192.0.2.99")


class APlaceholderConfigSaysSoAboutItself(unittest.TestCase):
    """'{{VAULT:...}}' is a valid password string on both platforms: pasted
    into a console it silently becomes the literal password."""

    def test_the_warning_is_prepended_when_placeholders_are_present(self):
        text = prov_router._with_placeholder_warning(
            "enable secret {{VAULT:enable_secret}}\n", "switch")
        self.assertTrue(text.startswith("!"))
        self.assertIn("segnaposto", text)

    def test_a_materialized_config_is_untouched(self):
        original = "enable secret Sup3r-Enable\n"
        self.assertEqual(original,
                         prov_router._with_placeholder_warning(original, "switch"))

    def test_the_fortios_warning_uses_a_fortios_comment(self):
        text = prov_router._with_placeholder_warning(
            'set password "{{VAULT:admin_password}}"\n', "fortigate")
        self.assertTrue(text.startswith("#"))


class AForcedPasswordChangeAbortsTheSerialPush(unittest.TestCase):
    """A factory FortiGate demands a new password at first console login.
    Typing the config into that prompt sets the first line as the password and
    leaves the unit with a credential nobody knows."""

    def test_the_prompt_is_detected_and_the_push_refuses(self):
        fake_serial = mock.MagicMock()
        fake_serial.__enter__.return_value = fake_serial
        fake_serial.in_waiting = 0
        fake_serial.read.return_value = b"You must change your password now\r\n"
        serial_mod = mock.MagicMock()
        serial_mod.Serial.return_value = fake_serial
        with mock.patch.dict("sys.modules", {"serial": serial_mod}):
            res = fortigate_provisioner.push_via_serial(
                "COM9", "config system global\nend\n")
        self.assertEqual("error", res["status"])
        self.assertIn("cambio password", res["message"])


if __name__ == "__main__":
    unittest.main()
