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
--- /etc/passwd ---
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
ops:x:1000:1000:Ops:/home/ops:/bin/bash
--- /etc/group ---
root:x:0:
sudo:x:27:ops
ops:x:1000:

=== NEIGHBOR DISCOVERY ===
--- HOSTNAME ---
hostname web-01
--- UNAME ---
Linux 6.8.0-40-generic x86_64
--- UPTIME ---
up 3 weeks, 2 days
--- BOOT TIME ---
2026-07-01 08:12:33
--- IP ADDRESS ---
lo               UNKNOWN        127.0.0.1/8 ::1/128
enp1s0           UP             192.0.2.10/24 fe80::5054:ff:fe12:3456/64
--- LINK STATS ---
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    RX: bytes  packets  errors  dropped  missed   mcast
    9000       90       0       0        0        0
    TX: bytes  packets  errors  dropped  carrier  collsns
    9000       90       0       0        0        0
2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff
    RX: bytes  packets  errors  dropped  missed   mcast
    123456     789      2       3        0        11
    TX: bytes  packets  errors  dropped  carrier  collsns
    654321     456      0       1        0        0
--- LINK SPEED ---
lo -1
enp1s0 1000 full
--- LSCPU ---
Architecture:                       x86_64
CPU(s):                             8
Model name:                         ACME CPU E5-1234 v4 @ 2.10GHz
NUMA node0 CPU(s):                  0-7
--- DISKS ---
sda ACME SSD 500G SN-DISK-0001 465.8G
vdb 20G
--- DMIDECODE ---
system-manufacturer: ACME
system-product-name: ACME Server X1
system-serial-number: SN-CHASSIS-0001
bios-version: 1.2.3
bios-release-date: 01/01/2025
--- MEMORY DEVICES ---
Memory Device
	Size: 16 GB
	Locator: DIMM_A1
	Type: DDR4
	Speed: 3200 MT/s
	Manufacturer: ACME
	Part Number: PN-16G
Memory Device
	Size: No Module Installed
	Locator: DIMM_A2
--- SYSTEMCTL ENABLED ---
ssh.service                            enabled
cron.service                           enabled
--- SUDOERS ---
Defaults        env_reset
root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
--- FIREWALL RULES ---
-P INPUT DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
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

    def test_system_reports_kernel_architecture_and_boot_time(self):
        rows = {r["property"]: r["value"] for r in _rows(self.env, "system")}
        self.assertEqual("6.8.0-40-generic", rows["kernel"])
        self.assertEqual("x86_64", rows["architecture"])
        self.assertEqual("2026-07-01 08:12:33", rows["boot_time"])

    def test_interfaces_carry_mtu_speed_and_duplex(self):
        rows = {r["name"]: r for r in _rows(self.env, "interfaces")}
        self.assertEqual("1500", rows["enp1s0"]["mtu"])
        self.assertEqual("1000", rows["enp1s0"]["speed"])
        self.assertEqual("full", rows["enp1s0"]["duplex"])
        # -1 e' il "non lo so" del kernel su un'interfaccia senza link: non e'
        # una velocita' e mostrarlo sarebbe peggio di lasciare vuoto.
        self.assertEqual("", rows["lo"]["speed"])

    def test_counters_read_the_line_after_the_rx_tx_header(self):
        rows = {r["name"]: r for r in _rows(self.env, "counters")}
        self.assertEqual("123456", rows["enp1s0"]["rx_bytes"])
        self.assertEqual("789", rows["enp1s0"]["rx_packets"])
        self.assertEqual("2", rows["enp1s0"]["rx_errors"])
        self.assertEqual("3", rows["enp1s0"]["rx_dropped"])
        self.assertEqual("654321", rows["enp1s0"]["tx_bytes"])
        self.assertEqual("1", rows["enp1s0"]["tx_dropped"])

    def test_hardware_merges_lscpu_and_dmidecode(self):
        rows = {r["property"]: r["value"] for r in _rows(self.env, "hardware")}
        self.assertEqual("ACME CPU E5-1234 v4 @ 2.10GHz", rows["model name"])
        self.assertEqual("8", rows["cpu(s)"])
        self.assertEqual("SN-CHASSIS-0001", rows["system-serial-number"])
        self.assertEqual("1.2.3", rows["bios-version"])
        # "NUMA node0 CPU(s)" non e' il conteggio delle CPU: chiave diversa,
        # non deve sovrascrivere quella buona.
        self.assertNotIn("numa node0 cpu(s)", rows)

    def test_disks_keep_a_model_that_contains_spaces(self):
        rows = {r["name"]: r for r in _rows(self.env, "disks")}
        self.assertEqual("ACME SSD 500G", rows["sda"]["model"])
        self.assertEqual("SN-DISK-0001", rows["sda"]["serial"])
        self.assertEqual("465.8G", rows["sda"]["size"])
        # Disco virtuale: lsblk non stampa modello ne' seriale, resta la taglia.
        self.assertEqual("20G", rows["vdb"]["size"])
        self.assertEqual("", rows["vdb"]["model"])

    def test_dimms_skip_the_empty_slots(self):
        rows = _rows(self.env, "dimms")
        self.assertEqual(1, len(rows))
        self.assertEqual("DIMM_A1", rows[0]["locator"])
        self.assertEqual("16 GB", rows[0]["size"])
        self.assertEqual("PN-16G", rows[0]["part_number"])

    def test_users_say_who_can_actually_log_in(self):
        rows = {r["user"]: r for r in _rows(self.env, "users")}
        self.assertEqual("yes", rows["ops"]["login"])
        self.assertEqual("1000", rows["ops"]["uid"])
        self.assertEqual("/home/ops", rows["ops"]["home"])
        self.assertEqual("no", rows["daemon"]["login"])

    def test_groups_list_their_members(self):
        rows = {r["group"]: r for r in _rows(self.env, "groups")}
        self.assertEqual(["ops"], rows["sudo"]["members"])
        self.assertEqual([], rows["root"]["members"])

    def test_sudoers_keeps_the_rule_intact(self):
        rows = {r["principal"]: r["rule"] for r in _rows(self.env, "sudoers")}
        self.assertEqual("ALL=(ALL:ALL) ALL", rows["%sudo"])
        self.assertEqual("env_reset", rows["Defaults"])

    def test_host_firewall_rules_are_shown_verbatim(self):
        rows = [r["rule"] for r in _rows(self.env, "firewall")]
        self.assertIn("-P INPUT DROP", rows)
        self.assertIn("-A INPUT -p tcp --dport 22 -j ACCEPT", rows)

    def test_enabled_units(self):
        rows = {r["unit"]: r["state"] for r in _rows(self.env, "enabled_units")}
        self.assertEqual("enabled", rows["ssh.service"])
        self.assertEqual("enabled", rows["cron.service"])

    def test_garbage_yields_empty_sections_not_an_error(self):
        for text in (None, "", "spazzatura\n\x00"):
            env = linux_analyzer.analyze(text)
            self.assertEqual("linux", env["vendor"])
            self.assertTrue(all(s["rows"] == [] for s in env["sections"]))


if __name__ == "__main__":
    unittest.main()
