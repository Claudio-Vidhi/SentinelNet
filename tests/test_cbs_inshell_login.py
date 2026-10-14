# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""CBS / Catalyst 1200-1300 without 'ip ssh password-auth': SSH auth refused,
login asked inside the shell."""
import unittest
from unittest import mock

import paramiko

from core import net_ssh


class PasswordThenNone(unittest.TestCase):
    def test_refused_password_falls_back_to_none(self):
        client = net_ssh._PasswordThenNoneClient()
        transport = mock.Mock()
        with mock.patch.object(paramiko.SSHClient, "_auth",
                               side_effect=paramiko.BadAuthenticationType("x", [""])), \
                mock.patch.object(client, "get_transport", return_value=transport):
            client._auth("admin", "pw", None, None, False, False, None)
        transport.auth_none.assert_called_once_with("admin")


class InShellLogin(unittest.TestCase):
    def _conn(self, screens):
        conn = net_ssh.CiscoS300InShellLogin.__new__(net_ssh.CiscoS300InShellLogin)
        conn.username, conn.password, conn.RETURN = "admin", "pw", "\n"
        conn.read_until_pattern = mock.Mock(side_effect=screens)
        conn.write_channel = mock.Mock()
        return conn

    def test_answers_user_name_and_password(self):
        conn = self._conn(["\r\nUser Name:", "Password:", "\r\nswitch-01#"])
        conn.special_login_handler()
        self.assertEqual([c.args[0] for c in conn.write_channel.call_args_list],
                         ["admin\n", "pw\n"])

    def test_password_auth_device_writes_nothing(self):
        conn = self._conn(["switch-01#"])
        conn.special_login_handler()
        conn.write_channel.assert_not_called()

    def test_rejected_credentials_raise(self):
        conn = self._conn(["User Name:", "Password:"] * 2)
        with self.assertRaises(net_ssh.NetmikoAuthenticationException):
            conn.special_login_handler()


if __name__ == "__main__":
    unittest.main()
