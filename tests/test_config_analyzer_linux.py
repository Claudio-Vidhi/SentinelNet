# -*- coding: utf-8 -*-
"""Config Analyzer su un host Linux.

Il test che conta più di tutti è il primo: prima di questa piattaforma
``detect_config_type`` ripiegava su ``'ios'`` per ogni vendor che non
riconosceva, quindi un backup Linux veniva dato in pasto al parser Cisco e la
scheda usciva come uno switch senza VLAN. Un risultato inventato è peggio di
nessun risultato.
"""

import unittest

from ai import config_analyzer, linux_analyzer

# Artefatto come lo produce drivers/linux.py + i comandi extra del triage.
ARTIFACT = """\
--- /etc/os-release ---
PRETTY_NAME="Ubuntu 24.04 LTS"
ID=ubuntu
--- /etc/ssh/sshd_config ---
Port 22
PermitRootLogin no
MaxAuthTries 4
# Banner commentato: non è impostato
# Banner /etc/issue.net
--- /etc/login.defs ---
PASS_MAX_DAYS   365
PASS_MIN_DAYS   1
ENCRYPT_METHOD  YESCRYPT
--- /etc/fstab ---
/dev/mapper/vg0-root  /      ext4  errors=remount-ro             0 1
/dev/mapper/vg0-tmp   /tmp   ext4  defaults,nodev,nosuid,noexec  0 2
--- /etc/resolv.conf ---
nameserver 192.0.2.53

=== NEIGHBOR DISCOVERY ===
--- HOSTNAME ---
hostname web-01
--- UPTIME ---
up 3 weeks, 2 days
--- IP ADDRESS ---
lo               UNKNOWN        127.0.0.1/8 ::1/128
enp1s0           UP             192.0.2.10/24 fe80::5054:ff:fe12:3456/64
--- IP ROUTE ---
default via 192.0.2.1 dev enp1s0 proto static metric 100
192.0.2.0/24 dev enp1s0 proto kernel scope link src 192.0.2.10
--- DF ---
Filesystem     Type  Size  Used Avail Use% Mounted on
/dev/mapper/vg0-root ext4   49G   21G   26G  46% /
/dev/mapper/vg0-tmp  ext4  2.0G  1.9G   36M  92% /tmp
tmpfs          tmpfs 3.9G  1.2M  3.9G   1% /run
--- SYSTEMCTL FAILED ---
  nginx.service loaded failed failed A high performance web server
--- LISTENING SOCKETS ---
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port
tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*
tcp   LISTEN 0      4096       127.0.0.1:5432      0.0.0.0:*
udp   UNCONN 0      0          127.0.0.53:53       0.0.0.0:*
"""


def _section(env, sid):
    return next(s for s in env["sections"] if s["id"] == sid)


def _rows(env, sid):
    return _section(env, sid)["rows"]


class TestDetection(unittest.TestCase):

    def test_a_linux_backup_is_not_parsed_as_cisco_ios(self):
        self.assertEqual("linux",
                         config_analyzer.detect_config_type(ARTIFACT, None))

    def test_the_inventory_vendor_decides_first(self):
        for vendor in ("linux", "Ubuntu", "debian", "Rocky"):
            self.assertEqual("linux", config_analyzer.detect_config_type(
                "", {"Vendor": vendor}), vendor)

    def test_the_other_platforms_are_unaffected(self):
        self.assertEqual("fortios", config_analyzer.detect_config_type(
            "#config-version=FGT-7.4\nconfig system global\nend\n", None))
        self.assertEqual("ios", config_analyzer.detect_config_type(
            "hostname switch-01\ninterface Vlan10\n", None))


class TestEnvelope(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = linux_analyzer.analyze(ARTIFACT)

    def test_sections_have_label_keys_and_columns(self):
        self.assertEqual("linux", self.env["vendor"])
        for s in self.env["sections"]:
            self.assertTrue(s["label_key"].startswith("srv.sec."))
            self.assertTrue(s["columns"])
            for c in s["columns"]:
                self.assertEqual(f"srv.col.{c['key']}", c["label_key"])

    def test_system(self):
        rows = {r["property"]: r["value"] for r in _rows(self.env, "system")}
        self.assertEqual("Ubuntu 24.04 LTS", rows["os"])
        self.assertEqual("web-01", rows["hostname"])
        self.assertEqual("192.0.2.53", rows["dns"])

    def test_interfaces_keep_addresses_as_a_list(self):
        rows = {r["name"]: r for r in _rows(self.env, "interfaces")}
        self.assertEqual("UP", rows["enp1s0"]["state"])
        self.assertEqual(["192.0.2.10/24", "fe80::5054:ff:fe12:3456/64"],
                         rows["enp1s0"]["addresses"])

    def test_routes(self):
        rows = _rows(self.env, "routes")
        default = next(r for r in rows if r["destination"] == "default")
        self.assertEqual("192.0.2.1", default["via"])
        self.assertEqual("enp1s0", default["dev"])
        self.assertEqual("100", default["metric"])

    def test_sockets_say_what_is_exposed_to_the_network(self):
        rows = {r["port"]: r for r in _rows(self.env, "sockets")}
        # La distinzione che nessun'altra vista dà: 0.0.0.0 è tutta la rete.
        self.assertEqual("any", rows["22"]["scope"])
        self.assertEqual("local", rows["5432"]["scope"])
        self.assertEqual("tcp", rows["22"]["protocol"])
        # L'intestazione di ss non è una riga di dati.
        self.assertNotIn("Port", rows)

    def test_storage_merges_fstab_options_with_usage(self):
        rows = {r["mount"]: r for r in _rows(self.env, "storage")}
        self.assertEqual(["defaults", "nodev", "nosuid", "noexec"],
                         rows["/tmp"]["options"])
        self.assertEqual("92%", rows["/tmp"]["used_pct"])
        # Montato ma non in fstab: esiste e occupa spazio, va mostrato.
        self.assertEqual("tmpfs", rows["/run"]["fstype"])
        self.assertEqual([], rows["/run"]["options"])

    def test_failed_services(self):
        rows = _rows(self.env, "services")
        self.assertEqual(1, len(rows))
        self.assertEqual("nginx.service", rows[0]["unit"])
        self.assertEqual("failed", rows[0]["active"])

    def test_ssh_shows_settings_not_verdicts(self):
        rows = {r["setting"]: r["value"] for r in _rows(self.env, "ssh")}
        self.assertEqual("no", rows["permitrootlogin"])
        self.assertEqual("4", rows["maxauthtries"])
        # Commentata = non impostata: mostrarla sarebbe una bugia.
        self.assertNotIn("banner", rows)

    def test_the_effective_config_wins_over_the_file(self):
        env = linux_analyzer.analyze(
            ARTIFACT + "--- SSHD EFFECTIVE CONFIG ---\n"
                       "permitrootlogin prohibit-password\nport 2222\n")
        rows = {r["setting"]: r["value"] for r in _rows(env, "ssh")}
        self.assertEqual("prohibit-password", rows["permitrootlogin"])
        self.assertEqual("2222", rows["port"])

    def test_accounts(self):
        rows = {r["setting"]: r["value"] for r in _rows(self.env, "accounts")}
        self.assertEqual("365", rows["pass_max_days"])
        self.assertEqual("YESCRYPT", rows["encrypt_method"])

    def test_garbage_yields_empty_sections_not_an_error(self):
        for text in (None, "", "spazzatura\n\x00"):
            env = linux_analyzer.analyze(text)
            self.assertEqual("linux", env["vendor"])
            self.assertTrue(all(s["rows"] == [] for s in env["sections"]))


if __name__ == "__main__":
    unittest.main()
