# -*- coding: utf-8 -*-
"""Driver Linux: versione, artefatto di backup, hostname e guardia su enable().

Un host Linux deve diventare un device come gli altri senza toccare la UI: qui
si verificano i quattro punti in cui il flusso esistente era genuinamente
sbagliato per Linux.
"""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_linux_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from core import core_engine  # noqa: E402
from drivers.linux import LinuxDriver  # noqa: E402

OS_RELEASE = """\
PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
6.8.0-59-generic
"""

# Artefatto di backup come lo produce get_backup_command(), piu' la sezione
# hostname appesa dalla catena di comandi extra.
BACKUP = """\
--- /etc/os-release ---
PRETTY_NAME="Ubuntu 24.04.2 LTS"
--- /etc/hosts ---
127.0.0.1 localhost
192.0.2.10 web-01
--- HOSTNAME ---
hostname web-01
"""


class VersionTest(unittest.TestCase):

    def _driver(self, output):
        conn = MagicMock()
        conn.send_command.return_value = output
        return LinuxDriver(conn)

    def test_distro_and_kernel(self):
        self.assertEqual(self._driver(OS_RELEASE).get_version(),
                         "Ubuntu 24.04.2 LTS (6.8.0-59-generic)")

    def test_distro_without_kernel(self):
        self.assertEqual(
            self._driver('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n').get_version(),
            "Debian GNU/Linux 12 (bookworm)")

    def test_garbage_is_unknown(self):
        self.assertEqual(self._driver("bash: cat: command not found").get_version(),
                         "Unknown")
        self.assertEqual(self._driver("").get_version(), "Unknown")


class BackupCommandTest(unittest.TestCase):

    def test_markers_match_the_existing_section_parser(self):
        cmd = LinuxDriver(MagicMock()).get_backup_command()
        self.assertIn('echo "--- $f ---"', cmd)
        self.assertIn("/etc/ssh/sshd_config", cmd)
        # Un solo comando: la sessione netmiko ne manda uno solo per il backup.
        self.assertNotIn("\n", cmd)


class HostnameTest(unittest.TestCase):

    def test_existing_regex_recovers_the_short_name(self):
        # Nessun parser nuovo: la catena scrive 'hostname <nome>' apposta.
        self.assertEqual(core_engine.extract_hostname_from_config(BACKUP),
                         "web-01")


class DriverResolutionTest(unittest.TestCase):

    def test_alias_ubuntu_resolves_to_the_linux_driver(self):
        self.assertEqual(core_engine.resolve_driver("Ubuntu"),
                         (LinuxDriver, "linux"))

    def test_canonical_vendor_resolves_too(self):
        self.assertEqual(core_engine.resolve_driver("linux"),
                         (LinuxDriver, "linux"))


class EnableGuardTest(unittest.TestCase):
    """netmiko traduce enable() in `sudo su`: senza password sudo va evitato."""

    def _run(self, secret):
        conn = MagicMock()
        conn.__enter__.return_value = conn
        conn.__exit__.return_value = False
        conn.send_command.side_effect = lambda cmd, **kw: (
            "web-01" if cmd == "hostname" else BACKUP)
        conn.find_prompt.return_value = "operatore@web-01:~$"

        device = {"IP": "192.0.2.10", "Vendor": "linux", "Group": "Generale"}
        with patch.object(core_engine, "ConnectHandler", return_value=conn), \
                patch.object(core_engine, "is_reachable", return_value=True), \
                patch.object(core_engine, "get_device_credentials",
                             return_value=("operatore", "pw", secret)), \
                patch.object(core_engine, "update_version_inventory"), \
                patch.object(core_engine, "update_device_hostname"), \
                patch.object(core_engine, "save_backup", return_value="/tmp/x"), \
                patch.object(core_engine, "log_audit"):
            result = core_engine.run_backup_and_triage(device)
        return conn, result

    def test_no_sudo_password_means_no_enable(self):
        conn, result = self._run("")
        conn.enable.assert_not_called()
        self.assertEqual(result["status"], "success")
        # Hostname dalla sezione, non dal prompt 'operatore@web-01:~$'.
        self.assertEqual(result["hostname"], "web-01")

    def test_sudo_password_unlocks_the_privileged_tier(self):
        conn, _ = self._run("sudo-pw")
        conn.enable.assert_called_once()
        sent = [c.args[0] for c in conn.send_command.call_args_list]
        self.assertIn("ss -tulpn", sent)
        self.assertIn("sshd -T", sent)

    def test_unprivileged_run_omits_the_privileged_tier(self):
        conn, _ = self._run("")
        sent = [c.args[0] for c in conn.send_command.call_args_list]
        self.assertIn("ss -tuln", sent)
        self.assertNotIn("ss -tulpn", sent)


if __name__ == "__main__":
    unittest.main()
