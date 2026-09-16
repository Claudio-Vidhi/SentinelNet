# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Windows via SSH: driver, artefatto e analizzatore.

Perche' SSH e non WinRM: Windows ha un server OpenSSH dal 10 / Server 2019,
quindi il trasporto netmiko esistente lo raggiunge senza una dipendenza nuova e
senza un secondo percorso di esecuzione remota da mettere in sicurezza.

I due punti in cui il flusso esistente era genuinamente sbagliato per Windows:
``enable()`` -- che su questa piattaforma non esiste e finirebbe nell'output
come testo -- e ``detect_config_type``, che ripiegava su ``'ios'`` per ogni
vendor sconosciuto e avrebbe dato un artefatto Windows in pasto al parser
Cisco.

COSA E' VERIFICATO E COSA NO. I venti comandi sono stati eseguiti su un
Windows 11 vero (2026-09-13) e rispondono tutti senza errori; l'artefatto che
producono e' stato dato all'analizzatore, che lo divide in quindici sezioni
senza perdere una riga. Quel giro ha trovato due difetti veri, entrambi
corretti e fissati qui: il gruppo Administrators cercato per nome invece che
per SID ben noto, e una frase italiana dentro una riga di dati.

Resta da provare **il trasporto**: netmiko 'generic' contro il prompt di
cmd.exe su una sessione SSH. I comandi in se' non sono piu' in dubbio.
"""

import os
import re
import tempfile
import unittest
from unittest.mock import MagicMock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_windows_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from ai import config_analyzer, windows_analyzer  # noqa: E402
from core import core_engine  # noqa: E402
from drivers.windows import TRIAGE_COMMANDS, WindowsDriver  # noqa: E402

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Artefatto come lo produce drivers/windows.py: ogni riga la costruisce il
# comando stesso dalle proprieta' degli oggetti, unite da '|'.
ARTIFACT = """\
--- HOSTNAME ---
hostname srv-app-01
--- OS INFO ---
Microsoft Windows Server 2022 Standard|10.0.20348|20348|64-bit|01/03/2024 09:12:44|09/09/2026 03:14:02
--- COMPUTER INFO ---
Dell Inc.|PowerEdge R650|contoso.example|True|34359738368|16
--- BIOS ---
Dell Inc.|2.11.2|15/05/2024|ABC1234
--- CPU ---
Intel(R) Xeon(R) Silver 4310 CPU @ 2.10GHz|8|16|2100
--- NET ADAPTERS ---
Ethernet0|Broadcom NetXtreme Gigabit|Up|1 Gbps|AA-BB-CC-DD-EE-FF|1500
Ethernet1|Broadcom NetXtreme Gigabit|Disconnected|0 bps|AA-BB-CC-DD-EE-01|1500
--- IP ADDRESSES ---
Ethernet0|10.20.0.31|24|IPv4|Manual
Ethernet0|fe80::1|64|IPv6|WellKnown
Loopback Pseudo-Interface 1|127.0.0.1|8|IPv4|WellKnown
--- NET ROUTES ---
0.0.0.0/0|10.20.0.1|Ethernet0|25
10.20.0.0/24|0.0.0.0|Ethernet0|261
--- LISTENING PORTS ---
TCP|0.0.0.0|3389|1284|svchost
TCP|0.0.0.0|445|4|System
TCP|127.0.0.1|5432|3120|postgres
--- SERVICES DOWN ---
Spooler|Print Spooler|Stopped|Automatic
--- SERVICES AUTO ---
Spooler|Print Spooler|Stopped|Automatic
W32Time|Windows Time|Running|Automatic
--- LOCAL USERS ---
Administrator|True||True|09/09/2026 03:20:11|Account amministrativo predefinito
svc_backup|True|31/12/2027 00:00:00|True||Servizio di backup
Guest|False||False||Account guest
--- LOCAL GROUPS ---
Administrators|SRV-APP-01\\Administrator,CONTOSO\\ops
Remote Desktop Users|CONTOSO\\helpdesk
--- LOCAL ADMINS ---
SRV-APP-01\\Administrator|User|Local
CONTOSO\\ops|Group|ActiveDirectory
--- DISKS ---
\\\\.\\PHYSICALDRIVE0|DELL PERC H755 Front|5000C500A1B2C3D4|1000204886016
--- VOLUMES ---
C:|Sistema|NTFS|107374182400|21474836480
D:|Dati|NTFS|893353197568|804017877811
--- FIREWALL PROFILES ---
Domain|True|Block|Allow|False
Private|True|Block|Allow|False
Public|False|Block|Allow|False
--- REMOTE ACCESS ---
rdp_enabled|True
rdp_nla|1
rdp_security_layer|2
rdp_port|3389
--- SMB CONFIG ---
smb1_enabled|False
smb_signing_required|False
smb_encrypt_data|False
--- SMB SHARES ---
C$|C:\\|Condivisione predefinita
dati|D:\\condivisi|Cartella di reparto
"""


class TestTheCommandsSurviveThreeShells(unittest.TestCase):
    """Il comando viaggia come UN argomento fra virgolette doppie verso
    ``powershell -Command``, attraverso la shell locale, netmiko e cmd.exe. Una
    virgoletta doppia dentro dovrebbe sopravvivere a tutti e tre: con la
    concatenazione a apici singoli non ce n'e' nessuna da far sopravvivere."""

    def test_no_inner_double_quote_in_any_command(self):
        for cmd, tag in TRIAGE_COMMANDS:
            body = cmd.split('-Command ', 1)[1]
            self.assertTrue(body.startswith('"') and body.endswith('"'), tag)
            self.assertNotIn('"', body[1:-1], f"virgolette annidate in {tag}")

    def test_every_command_is_a_non_interactive_powershell(self):
        for cmd, tag in TRIAGE_COMMANDS:
            self.assertIn("-NoProfile", cmd, tag)
            # Senza questo un prompt inatteso appende la sessione fino al
            # read timeout invece di fallire.
            self.assertIn("-NonInteractive", cmd, tag)

    def test_the_administrators_group_is_looked_up_by_well_known_sid(self):
        """Il gruppo predefinito puo' essere rinominato, e su alcune
        installazioni localizzate lo e'. S-1-5-32-544 e' lo stesso su ogni
        Windows mai spedito."""
        cmd = next(c for c, t in TRIAGE_COMMANDS if t == "--- LOCAL ADMINS ---")
        self.assertIn("-SID S-1-5-32-544", cmd)
        self.assertNotIn("-Group Administrators", cmd)

    def test_nothing_compares_a_localised_value(self):
        """ObjectClass e' l'unica proprieta' che torna tradotta ('Utente' /
        'Altro' su un host italiano, dove PrincipalSource resta 'AzureAD'):
        e' di sola visualizzazione, e confrontarla in codice sarebbe il
        difetto che tutto questo formato esiste per evitare."""
        import inspect
        from ai import windows_analyzer as wa
        src = inspect.getsource(wa)
        for localised in ("Utente", "Altro", "'User'", '"User"', "'Group'"):
            self.assertNotIn(localised, src,
                             f"l'analizzatore confronta {localised}")

    def test_the_sections_are_the_ones_the_analyzer_reads(self):
        tags = {tag for _cmd, tag in TRIAGE_COMMANDS}
        for needed in ("--- HOSTNAME ---", "--- OS INFO ---",
                       "--- NET ADAPTERS ---", "--- LOCAL ADMINS ---",
                       "--- REMOTE ACCESS ---", "--- SMB CONFIG ---"):
            self.assertIn(needed, tags)

    def test_the_hostname_is_written_in_the_form_the_extractor_reads(self):
        # Il prompt 'C:\\Users\\admin>' non darebbe un hostname usabile: la
        # sezione lo scrive come `hostname <nome>`, come fa il driver Linux.
        cmd = next(c for c, t in TRIAGE_COMMANDS if t == "--- HOSTNAME ---")
        self.assertIn("'hostname '", cmd)
        self.assertEqual("srv-app-01",
                         core_engine.extract_hostname_from_config(ARTIFACT))


class TestDriverReadsIdentity(unittest.TestCase):
    def _driver(self, answer):
        conn = MagicMock()
        conn.send_command.return_value = answer
        return WindowsDriver(conn)

    def test_version_carries_the_build(self):
        d = self._driver("Microsoft Windows Server 2022 Standard|10.0.20348|64-bit")
        # Il build identifica il livello di patch: non va perso.
        self.assertEqual("Windows Server 2022 Standard (10.0.20348, 64-bit)",
                         d.get_version())

    def test_version_survives_an_empty_answer(self):
        self.assertEqual("Unknown", self._driver("").get_version())
        self.assertEqual("Unknown", self._driver("accesso negato").get_version())

    def test_model_joins_manufacturer_and_model(self):
        self.assertEqual("Dell Inc. PowerEdge R650",
                         self._driver("Dell Inc.|PowerEdge R650").get_model())

    def test_model_of_a_vm_is_the_hypervisor_string_not_a_blank(self):
        self.assertEqual(
            "VMware, Inc. VMware Virtual Platform",
            self._driver("VMware, Inc.|VMware Virtual Platform").get_model())

    def test_a_placeholder_serial_is_not_a_serial(self):
        for placeholder in ("To be filled by O.E.M.", "System Serial Number",
                            "Default string", "None"):
            self.assertEqual("", self._driver(placeholder).get_serial(),
                             placeholder)

    def test_a_real_serial_is_returned(self):
        self.assertEqual("ABC1234", self._driver("ABC1234").get_serial())

    def test_the_backup_command_carries_the_hosts_file_marker(self):
        cmd = WindowsDriver(MagicMock()).get_backup_command()
        self.assertIn("--- C:\\Windows\\System32\\drivers\\etc\\hosts ---", cmd)
        self.assertIn("Get-Content", cmd)


class TestWindowsHasNoEnableMode(unittest.TestCase):
    """Su Linux netmiko traduce enable() in `sudo -s`; su una shell Windows non
    esiste niente di equivalente e il comando finirebbe nell'output come
    testo."""

    def test_generic_never_enables(self):
        conn = MagicMock()
        core_engine.maybe_enable(conn, 'generic', '')
        conn.enable.assert_not_called()

    def test_generic_never_enables_even_with_a_secret(self):
        # L'Enable Secret su questo vendor non significa niente: era la
        # condizione che un `!= 'linux'` avrebbe sbagliato.
        conn = MagicMock()
        core_engine.maybe_enable(conn, 'generic', 'qualcosa')
        conn.enable.assert_not_called()

    def test_linux_still_enables_only_with_a_secret(self):
        conn = MagicMock()
        core_engine.maybe_enable(conn, 'linux', '')
        conn.enable.assert_not_called()
        core_engine.maybe_enable(conn, 'linux', 'sudo-pw')
        conn.enable.assert_called_once()

    def test_a_switch_still_enables(self):
        conn = MagicMock()
        core_engine.maybe_enable(conn, 'cisco_ios', '')
        conn.enable.assert_called_once()


class TestVendorWiring(unittest.TestCase):
    def test_the_vendor_resolves_to_the_driver(self):
        driver_cls, netmiko_type = core_engine.resolve_driver('windows')
        self.assertIs(driver_cls, WindowsDriver)
        self.assertEqual('generic', netmiko_type)

    def test_the_common_spellings_normalise(self):
        from services import inventory_manager
        for raw in ("Windows", "WIN", "Windows Server", "winsrv", "Microsoft"):
            self.assertEqual("windows", inventory_manager.normalize_vendor(raw),
                             raw)

    def test_the_vendor_is_selectable(self):
        from services import inventory_manager
        self.assertEqual({"driver": "windows"},
                         inventory_manager.get_all_vendors().get("windows"))


class TestDetectionDoesNotFallBackToIos(unittest.TestCase):
    def test_the_vendor_decides(self):
        self.assertEqual('windows', config_analyzer.detect_config_type(
            "", {"Vendor": "windows"}))

    def test_the_artifact_alone_is_enough(self):
        # Un backup caricato a mano non ha un device in inventario.
        self.assertEqual('windows',
                         config_analyzer.detect_config_type(ARTIFACT))

    def test_a_linux_artifact_is_still_linux(self):
        self.assertEqual('linux', config_analyzer.detect_config_type(
            "--- /etc/os-release ---\nID=ubuntu\n"))


class TestAnalyzer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = windows_analyzer.analyze(ARTIFACT)
        cls.sections = {s["id"]: s for s in cls.env["sections"]}

    def _rows(self, sid):
        return self.sections[sid]["rows"]

    def _value(self, sid, prop):
        for row in self._rows(sid):
            if row.get("property") == prop or row.get("setting") == prop:
                return row["value"]
        return None

    def test_it_did_not_crash(self):
        self.assertNotIn("error", self.env)
        self.assertEqual("windows", self.env["vendor"])

    def test_system_says_edition_build_and_domain(self):
        self.assertEqual("Microsoft Windows Server 2022 Standard",
                         self._value("win_system", "os"))
        self.assertEqual("10.0.20348 build 20348",
                         self._value("win_system", "kernel"))
        # PartOfDomain=True: e' un dominio, non un workgroup.
        self.assertEqual("contoso.example", self._value("win_system", "domain"))
        self.assertIsNone(self._value("win_system", "workgroup"))
        self.assertEqual("32.0 GB", self._value("win_system", "memory"))

    def test_a_workgroup_machine_is_not_called_a_domain(self):
        env = windows_analyzer.analyze(
            "--- COMPUTER INFO ---\nDell|R650|WORKGROUP|False|1024|2\n")
        rows = {r["property"]: r["value"] for r in env["sections"][0]["rows"]}
        self.assertEqual("WORKGROUP", rows.get("workgroup"))
        self.assertNotIn("domain", rows)

    def test_interfaces_join_their_addresses(self):
        rows = {r["name"]: r for r in self._rows("win_interfaces")}
        self.assertEqual("Up", rows["Ethernet0"]["state"])
        self.assertIn("10.20.0.31/24", rows["Ethernet0"]["addresses"])
        self.assertIn("fe80::1/64", rows["Ethernet0"]["addresses"])
        # Una scheda senza indirizzi resta in tabella: "scollegata" e' un
        # fatto, non un motivo per nasconderla.
        self.assertEqual("", rows["Ethernet1"]["addresses"])
        self.assertEqual("Disconnected", rows["Ethernet1"]["state"])

    def test_sockets_say_what_is_exposed_to_the_network(self):
        rows = {r["port"]: r for r in self._rows("win_sockets")}
        self.assertEqual("any", rows["3389"]["scope"])
        self.assertEqual("local", rows["5432"]["scope"])
        # Il PID da solo non dice niente: il nome del processo si risolve
        # sull'host, non nel parser.
        self.assertEqual("svchost (1284)", rows["3389"]["process"])

    def test_only_the_services_that_should_be_running_are_the_finding(self):
        self.assertEqual(["Spooler"],
                         [r["name"] for r in self._rows("win_services")])
        self.assertEqual({"Spooler", "W32Time"},
                         {r["name"] for r in self._rows("win_enabled")})

    def test_remote_access_carries_rdp_and_smb_together(self):
        rows = {r["setting"]: r["value"] for r in self._rows("win_remote")}
        self.assertEqual("True", rows["rdp_enabled"])
        self.assertEqual("3389", rows["rdp_port"])
        # I due reperti classici di un server Windows.
        self.assertEqual("False", rows["smb1_enabled"])
        self.assertEqual("False", rows["smb_signing_required"])

    def test_a_disabled_firewall_profile_is_visible(self):
        rows = {r["name"]: r for r in self._rows("win_firewall")}
        self.assertEqual("True", rows["Domain"]["active"])
        self.assertEqual("False", rows["Public"]["active"])
        self.assertEqual("Block", rows["Public"]["inbound"])

    def test_local_admins_are_their_own_table(self):
        rows = {r["name"]: r for r in self._rows("win_admins")}
        self.assertEqual("ActiveDirectory", rows["CONTOSO\\ops"]["principal"])
        self.assertEqual("Group", rows["CONTOSO\\ops"]["type"])

    def test_an_account_whose_password_never_expires_says_so(self):
        rows = {r["name"]: r for r in self._rows("win_users")}
        # Token e non prosa: una riga e' DATO, e una frase italiana
        # comparirebbe in una dashboard in inglese accanto ai valori non
        # tradotti della piattaforma ('Up', 'Running').
        self.assertEqual("never", rows["Administrator"]["setting"])
        self.assertEqual("True", rows["Administrator"]["active"])
        self.assertEqual("False", rows["Guest"]["active"])

    def test_volumes_carry_size_and_usage(self):
        rows = {r["device"]: r for r in self._rows("win_storage")}
        self.assertEqual("100.0 GB", rows["C:"]["size"])
        self.assertEqual("80%", rows["C:"]["used_pct"])

    def test_disks_carry_model_and_serial(self):
        row = self._rows("win_disks")[0]
        self.assertEqual("DELL PERC H755 Front", row["model"])
        self.assertEqual("931.5 GB", row["size"])

    def test_an_empty_section_is_dropped_not_shown_empty(self):
        # Un account non amministratore non legge i profili del firewall:
        # una pill vuota inviterebbe un click verso una tabella vuota.
        env = windows_analyzer.analyze("--- HOSTNAME ---\nhostname srv-01\n")
        self.assertEqual(["win_system"], [s["id"] for s in env["sections"]])

    def test_garbage_does_not_raise(self):
        for text in (None, "", "\x00\x01",
                     "--- OS INFO ---\nsenza delimitatori\n"):
            env = windows_analyzer.analyze(text)
            self.assertNotIn("error", env)

    def test_a_value_containing_a_pipe_is_not_truncated(self):
        env = windows_analyzer.analyze(
            "--- SMB SHARES ---\ndati|D:\\x|reparto A|B\n")
        row = env["sections"][0]["rows"][0]
        self.assertEqual("reparto A|B", row["description"])

    def test_every_label_key_exists_in_both_languages(self):
        with open(os.path.join(_REPO_ROOT, "static", "js", "i18n.js"),
                  encoding="utf-8") as f:
            dic = f.read()
        for section in self.env["sections"]:
            keys = [section["label_key"]] + \
                   [c["label_key"] for c in section["columns"]]
            # L'aiuto si ricava dall'etichetta (srv.sec.X -> srv.help.X): se
            # manca, la scheda mostra il testo Linux o niente.
            keys.append(section["label_key"].replace(".sec.", ".help."))
            for key in keys:
                self.assertEqual(2, len(re.findall(
                    r'"%s"\s*:' % re.escape(key), dic)),
                    f"{key} non e' in entrambi i dizionari")


class TestConfigAnalyzerShowsWindows(unittest.TestCase):
    """The backend put the Windows envelope under dev.server, but the Server
    pill only accepted config_type 'linux': a triaged Windows host showed
    "No devices available"."""

    def test_server_pill_accepts_windows(self):
        with open(os.path.join(_REPO_ROOT, "static", "js", "config-analyzer.js"),
                  encoding="utf-8") as f:
            src = f.read()
        body = src[src.index("function isServerDevice"):]
        body = body[:body.index("}")]
        self.assertIn("'windows'", body)


if __name__ == "__main__":
    unittest.main()
