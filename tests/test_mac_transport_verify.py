# -*- coding: utf-8 -*-
"""Verifica TLS/host-key dei trasporti MAC a comando dell'operatore (WP10,
docs/app-review-fix-plan.md): default spento per compatibilita' con i
certificati self-signed, attivabile dall'impostazione avanzata."""

import unittest
from unittest import mock

from collectors import mac_collector


class TestVerifySetting(unittest.TestCase):

    def test_default_off(self):
        # l'impostazione manca -> verifica disattivata (compat)
        with mock.patch("core.app_settings._app_adv_setting", return_value=None):
            self.assertFalse(mac_collector._transport_verify_tls())

    def test_setting_on(self):
        with mock.patch("core.app_settings._app_adv_setting", return_value=True):
            self.assertTrue(mac_collector._transport_verify_tls())


class TestRestconfUsesSetting(unittest.TestCase):

    def _run(self, verify_setting):
        session = mock.MagicMock()
        session.get.return_value = mock.MagicMock(status_code=404)
        with mock.patch("core.app_settings._app_adv_setting",
                        return_value=verify_setting), \
             mock.patch("requests.Session", return_value=session), \
             mock.patch("urllib3.disable_warnings") as m_dw:
            mac_collector.collect_via_restconf("192.0.2.1", "u", "p")
        return session, m_dw

    def test_verify_off_keeps_legacy_behavior(self):
        session, m_dw = self._run(None)
        self.assertFalse(session.verify)
        m_dw.assert_called()

    def test_verify_on_enables_tls_checks(self):
        session, m_dw = self._run(True)
        self.assertTrue(session.verify)
        m_dw.assert_not_called()


class TestNetconfUsesSetting(unittest.TestCase):

    def _run(self, verify_setting):
        try:
            import ncclient  # noqa: F401
        except ImportError:
            self.skipTest("ncclient non installato")
        with mock.patch("core.app_settings._app_adv_setting",
                        return_value=verify_setting), \
             mock.patch("ncclient.manager.connect",
                        side_effect=RuntimeError("stop")) as m_connect:
            mac_collector.collect_via_netconf("192.0.2.1", "u", "p")
        return m_connect

    def test_hostkey_verify_follows_setting_off(self):
        m_connect = self._run(None)
        _args, kwargs = m_connect.call_args
        self.assertFalse(kwargs["hostkey_verify"])

    def test_hostkey_verify_follows_setting_on(self):
        m_connect = self._run(True)
        _args, kwargs = m_connect.call_args
        self.assertTrue(kwargs["hostkey_verify"])


if __name__ == "__main__":
    unittest.main()
