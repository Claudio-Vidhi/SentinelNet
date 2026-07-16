# -*- coding: utf-8 -*-
"""Test §11.6 — trasporti multi-protocollo per-device.

Copre: sintesi ssh-only per righe legacy, round-trip dell'upsert, uso della
porta NETCONF dichiarata, protocolli non dichiarati mai tentati, audit di
Telnet, rifiuto di porta/protocollo non validi con 400 in italiano.

Eseguibile come script: `python test_transports.py`.
"""

import csv
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_transports_"))

import inventory_manager  # noqa: E402
import mac_collector      # noqa: E402
from routers import inventory as inventory_router  # noqa: E402         # noqa: E402
from fastapi import HTTPException  # noqa: E402

ADMIN = {"sub": "tester", "role": "admin"}


class TestLegacySynthesis(unittest.TestCase):
    def test_legacy_row_without_transports(self):
        # Riga legacy con sola 'SSH Port', nessuna colonna 'Transports'.
        self.assertEqual(
            inventory_manager.parse_transports({"IP": "10.0.0.1", "SSH Port": "2222"}),
            {"ssh": 2222},
        )

    def test_legacy_row_defaults_22(self):
        self.assertEqual(
            inventory_manager.parse_transports({"IP": "10.0.0.1"}),
            {"ssh": 22},
        )


class TestUpsertRoundTrip(unittest.TestCase):
    def setUp(self):
        # Isola l'inventario in un CSV temporaneo per ogni test.
        fd, self.csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        os.remove(self.csv_path)
        self._orig = inventory_manager.HOSTS_CSV
        inventory_manager.HOSTS_CSV = self.csv_path
        inventory_manager.invalidate_device_ip_cache()

    def tearDown(self):
        inventory_manager.HOSTS_CSV = self._orig
        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)

    def test_roundtrip_transports(self):
        tr = {"ssh": 22, "telnet": None, "netconf": 8300, "restconf": 443}
        inventory_manager.add_or_update_device(
            "10.0.0.5", "cisco", "default", "u", "p", "s", "Generale", transports=tr)
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "10.0.0.5")
        self.assertEqual(inventory_manager.parse_transports(dev), tr)
        # Colonna legacy 'SSH Port' rispecchia la porta ssh dichiarata.
        self.assertEqual(dev["SSH Port"], "22")

    def test_roundtrip_tcp_udp_transports(self):
        # tcp/udp: protocolli generici a porta libera, scelta dall'utente.
        tr = {"ssh": 22, "tcp": 9000, "udp": 161}
        inventory_manager.add_or_update_device(
            "10.0.0.30", "cisco", "default", "u", "p", "s", "Generale", transports=tr)
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "10.0.0.30")
        self.assertEqual(inventory_manager.parse_transports(dev), tr)

    def test_legacy_upsert_synthesizes_ssh(self):
        # Upsert senza transports (chiamante legacy) → ssh-only dalla ssh_port.
        inventory_manager.add_or_update_device(
            "10.0.0.6", "cisco", "default", "u", "p", "s", "Generale", ssh_port=2022)
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "10.0.0.6")
        self.assertEqual(inventory_manager.parse_transports(dev), {"ssh": 2022})

    def test_lazy_migration_of_legacy_csv(self):
        # Scrive a mano una riga legacy priva di 'Transports', poi la rilegge.
        with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["IP", "Vendor", "SSH Port"])
            w.writeheader()
            w.writerow({"IP": "10.0.0.7", "Vendor": "cisco", "SSH Port": "22"})
        dev = next(d for d in inventory_manager.get_all_devices() if d["IP"] == "10.0.0.7")
        self.assertEqual(inventory_manager.parse_transports(dev), {"ssh": 22})


class TestCollectorGating(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._nc = mac_collector.collect_via_netconf
        self._rc = mac_collector.collect_via_restconf
        self._cli = mac_collector.collect_via_cli

        def spy_nc(host, u, p, port=830, timeout=30):
            self.calls.append(("netconf", port))
            return None

        def spy_rc(host, u, p, port=443, timeout=15):
            self.calls.append(("restconf", port))
            return None

        def spy_cli(host, u, p, secret="", device_type="cisco_ios", **kw):
            self.calls.append(("cli", device_type))
            return [{"mac": "aa", "interface": "gi1", "vlan": "1"}]

        mac_collector.collect_via_netconf = spy_nc
        mac_collector.collect_via_restconf = spy_rc
        mac_collector.collect_via_cli = spy_cli

    def tearDown(self):
        mac_collector.collect_via_netconf = self._nc
        mac_collector.collect_via_restconf = self._rc
        mac_collector.collect_via_cli = self._cli

    def test_netconf_uses_declared_port(self):
        mac_collector.collect_mac_table(
            "10.0.0.9", "u", "p", transports={"netconf": 8300})
        self.assertIn(("netconf", 8300), self.calls)

    def test_undeclared_protocols_never_attempted(self):
        # Solo ssh dichiarato → nessun NETCONF/RESTCONF, solo CLI.
        mac_collector.collect_mac_table(
            "10.0.0.10", "u", "p", transports={"ssh": 22})
        protos = [c[0] for c in self.calls]
        self.assertNotIn("netconf", protos)
        self.assertNotIn("restconf", protos)
        self.assertIn("cli", protos)

    def test_telnet_only_uses_telnet_device_type(self):
        mac_collector.collect_mac_table(
            "10.0.0.11", "u", "p", device_type="cisco_ios",
            transports={"telnet": 23})
        cli = [c for c in self.calls if c[0] == "cli"]
        self.assertEqual(cli[0][1], "cisco_ios_telnet")

    def test_legacy_none_attempts_all(self):
        mac_collector.collect_mac_table("10.0.0.12", "u", "p")
        protos = [c[0] for c in self.calls]
        self.assertEqual(protos, ["netconf", "restconf", "cli"])


class TestAddDeviceEndpoint(unittest.TestCase):
    def setUp(self):
        fd, self.csv_path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        os.remove(self.csv_path)
        self._orig = inventory_manager.HOSTS_CSV
        inventory_manager.HOSTS_CSV = self.csv_path
        inventory_manager.invalidate_device_ip_cache()
        self.audits = []
        self._log = inventory_router.log_audit
        inventory_router.log_audit = lambda msg: self.audits.append(msg)

    def tearDown(self):
        inventory_manager.HOSTS_CSV = self._orig
        inventory_router.log_audit = self._log
        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)

    def test_telnet_enable_is_audited(self):
        dev = inventory_router.DeviceSchema(
            ip="10.0.0.20", vendor="cisco", profile="default",
            transports={"ssh": 22, "telnet": 23})
        inventory_router.add_device(dev, current_user=ADMIN)
        self.assertTrue(any("Telnet" in a for a in self.audits),
                        f"nessun audit Telnet: {self.audits}")

    def test_invalid_protocol_returns_400_italian(self):
        dev = inventory_router.DeviceSchema(
            ip="10.0.0.21", vendor="cisco", profile="default",
            transports={"gopher": 70})
        with self.assertRaises(HTTPException) as ctx:
            inventory_router.add_device(dev, current_user=ADMIN)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Protocollo", ctx.exception.detail)

    def test_invalid_port_returns_400_italian(self):
        dev = inventory_router.DeviceSchema(
            ip="10.0.0.22", vendor="cisco", profile="default",
            transports={"ssh": 99999})
        with self.assertRaises(HTTPException) as ctx:
            inventory_router.add_device(dev, current_user=ADMIN)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Porta", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()
