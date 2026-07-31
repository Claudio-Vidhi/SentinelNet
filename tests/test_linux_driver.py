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
from drivers.linux import LinuxDriver, sanitize_session  # noqa: E402

# Prompt di una Fedora recente: le sequenze OSC di shell integration portano un
# UUID diverso a ogni comando.
FEDORA_PROMPT = (
    "\x1b]8003;end=1dac7fb8-162d-41d8-8d01-0bf492df9163;exit=success\x1b\\"
    "\x1b]8003;start=d1419595-5e27-460f-88db-bf4a08af4564;user=admin;"
    "hostname=fedora;pid=5374;type=shell;cwd=/home/admin\x1b\\"
    "[admin@fedora ~]$ ")

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


class ModelTest(unittest.TestCase):
    """Il modello di un host Linux non e' il "Model:" di lscpu.

    Bug reale: quel campo e' il numero di modello della CPU (es. "186") e il
    pattern Cisco ``^\\s*Model\\s*:`` lo pescava, mettendolo in colonna al posto
    della macchina.
    """

    def _artifact(self, extra):
        return "--- /etc/os-release ---\nID=ubuntu\n" + extra

    def test_lscpu_cpu_model_number_is_not_the_machine_model(self):
        art = self._artifact("--- LSCPU ---\nModel:  186\nCPU(s):  4\n")
        self.assertIsNone(core_engine.extract_model_from_backup(art))

    def test_hypervisor_names_the_machine_when_dmidecode_is_unavailable(self):
        art = self._artifact(
            "--- LSCPU ---\nModel:  186\nHypervisor vendor:  VMware\n")
        self.assertEqual("VM (VMware)",
                         core_engine.extract_model_from_backup(art))

    def test_dmidecode_product_name_wins(self):
        art = self._artifact(
            "--- LSCPU ---\nHypervisor vendor:  KVM\n"
            "--- DMIDECODE ---\nsystem-product-name: ACME Server X1\n")
        self.assertEqual("ACME Server X1",
                         core_engine.extract_model_from_backup(art))

    def test_smbios_placeholders_are_not_models(self):
        art = self._artifact(
            "--- DMIDECODE ---\nsystem-product-name: To Be Filled By O.E.M.\n")
        self.assertIsNone(core_engine.extract_model_from_backup(art))

    def test_cisco_backups_are_unaffected(self):
        self.assertEqual("WS-C2960X-48FPD-L", core_engine.extract_model_from_backup(
            "hostname switch-01\nModel Number: WS-C2960X-48FPD-L\n"))


class DriverResolutionTest(unittest.TestCase):

    def test_alias_ubuntu_resolves_to_the_linux_driver(self):
        self.assertEqual(core_engine.resolve_driver("Ubuntu"),
                         (LinuxDriver, "linux"))

    def test_canonical_vendor_resolves_too(self):
        self.assertEqual(core_engine.resolve_driver("linux"),
                         (LinuxDriver, "linux"))


class ShellIntegrationTest(unittest.TestCase):
    """Il prompt di Fedora porta un UUID diverso a ogni comando.

    netmiko costruisce il pattern di fine comando dal prompt: se l'UUID resta
    dentro, il pattern del comando N non corrisponde mai al prompt del comando
    N+1 e ogni lettura va in timeout ("Pattern not detected").
    """

    def _patched(self):
        conn = MagicMock()
        conn.strip_ansi_escape_codes = lambda text: text   # nessuna CSI qui
        sanitize_session(conn)
        return conn

    def test_the_prompt_survives_without_its_escape_sequences(self):
        conn = self._patched()
        self.assertEqual(conn.strip_ansi_escape_codes(FEDORA_PROMPT),
                         "[admin@fedora ~]$ ")

    def test_two_consecutive_prompts_become_identical(self):
        """Il punto: e' l'UUID che cambia a rompere tutto, non l'escape."""
        conn = self._patched()
        second = FEDORA_PROMPT.replace("d1419595", "9f2e01aa") \
                              .replace("1dac7fb8", "77c0be31")
        self.assertNotEqual(FEDORA_PROMPT, second)
        self.assertEqual(conn.strip_ansi_escape_codes(FEDORA_PROMPT),
                         conn.strip_ansi_escape_codes(second))

    def test_the_base_prompt_is_recomputed_after_patching(self):
        # Quello calcolato alla connessione contiene ancora le sequenze.
        conn = self._patched()
        conn.set_base_prompt.assert_called_once()

    def test_normal_output_is_untouched(self):
        conn = self._patched()
        text = "PermitRootLogin no\n--- /etc/fstab ---\n/dev/sda1 / ext4 x 0 1\n"
        self.assertEqual(conn.strip_ansi_escape_codes(text), text)

    def test_systemd_colour_codes_do_not_reach_the_artefact(self):
        """Bug reale: systemctl colora "enabled" e netmiko rimuove solo un
        elenco chiuso di sequenze, non la forma generale. I codici finivano
        nell'artefatto e da li' nelle celle della tabella."""
        conn = self._patched()
        self.assertEqual(
            conn.strip_ansi_escape_codes(
                "apparmor.service \x1b[0;1;32menabled\x1b[0m "
                "\x1b[0;1;32menabled\x1b[0m\n"),
            "apparmor.service enabled enabled\n")


class BlacklistTest(unittest.TestCase):
    """La blacklist era solo CLI di rete: su un host Linux non proteggeva nulla."""

    def _blocked(self, command):
        device = {"IP": "192.0.2.10", "Vendor": "linux"}
        # La blacklist decide PRIMA di connettersi: la sessione non deve mai
        # aprirsi davvero, altrimenti il test aspetta un timeout di rete.
        with patch.object(core_engine, "ConnectHandler",
                          side_effect=OSError("nessuna sessione nei test")), \
                patch.object(core_engine, "get_device_credentials",
                             return_value=("operatore", "pw", "")), \
                patch.object(core_engine, "log_audit"):
            res = core_engine.send_custom_command(device, command)
        return res["status"] == "error" and "Blacklisted" in res["message"]

    def test_destructive_linux_commands_are_refused(self):
        for command in ("rm -rf /var/log", "mkfs.ext4 /dev/sdb1",
                        "dd if=/dev/zero of=/dev/sda", "reboot",
                        "poweroff", "shred -u /etc/shadow"):
            self.assertTrue(self._blocked(command), command)

    def test_ordinary_linux_commands_are_not(self):
        for command in ("uptime -p", "systemctl status sshd", "df -hT",
                        "ip -br a"):
            self.assertFalse(self._blocked(command), command)

    def test_cisco_shutdown_is_still_allowed(self):
        """Spegnere una porta e' l'uso quotidiano di 'shutdown': bloccarlo per
        via di Linux romperebbe il caso principale del prodotto."""
        self.assertFalse(self._blocked("shutdown"))
        self.assertFalse(self._blocked("interface Gi1/0/1"))


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
