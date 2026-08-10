# -*- coding: utf-8 -*-
"""Due regressioni viste dall'utente: terminale SSH che non connette piu'
e scansione subnet che sembra bloccata."""

import os
import tempfile
import unittest
from unittest import mock

import paramiko

from routers import commands
from collectors import network_scanner as ns


class TestKnownHostsBootstrap(unittest.TestCase):
    """AutoAddPolicy salva con save_host_keys(), che RICARICA il file prima di
    riscriverlo: su file assente solleva FileNotFoundError e la connessione
    muore prima di partire."""

    def test_first_contact_with_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "ssh_known_hosts")
            with mock.patch.object(commands.data_config, "get_path", return_value=path):
                client = paramiko.SSHClient()
                commands._prepare_host_keys(client)

                # Cio' che paramiko fa al primo contatto con un host sconosciuto.
                # _log passa dal transport, che qui non esiste: e' l'ultima riga
                # della policy, dopo il salvataggio che ci interessa.
                key = paramiko.ECDSAKey.generate()
                with mock.patch.object(client, "_log"):
                    client._policy.missing_host_key(client, "192.0.2.1", key)

            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as f:
                self.assertIn("192.0.2.1", f.read())

    def test_the_terminal_actually_uses_it(self):
        """La prova sopra copre l'helper, non il suo uso: se qualcuno rimette
        il blocco inline nel terminale WS, l'helper resta verde e il bug
        torna. Qui si guarda che la rotta lo chiami davvero."""
        import inspect
        source = inspect.getsource(commands)
        self.assertIn("_prepare_host_keys(client)", source)
        # E che non sia tornato il ripiego che nascondeva l'errore.
        self.assertNotIn("except OSError:\n        pass  # primo avvio", source)


class TestScanIsDiscoveryOnly(unittest.TestCase):
    """Discovery must never authenticate. A subnet sweep that logs in produces
    an auth-failure burst on every host that does not use those credentials."""

    def test_scan_never_opens_an_ssh_session(self):
        from core import core_engine
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable", return_value=False), \
             mock.patch.object(core_engine, "probe_device") as probe, \
             mock.patch.object(core_engine, "run_backup_and_triage") as backup:
            ns.scan_subnet(address="192.0.2.0/29", ports=[22])
        probe.assert_not_called()
        backup.assert_not_called()

    def test_host_found_by_port_with_ping_failing(self):
        # ICMP is dropped by most firewalls: a ping pre-filter hides real devices.
        with mock.patch.object(ns, "_ping", return_value=False), \
             mock.patch.object(ns, "is_reachable",
                               side_effect=lambda ip, port, timeout=1: ip.endswith(".1") and port == 443):
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[22, 443])
        by_ip = {r["ip"]: r for r in rows}
        self.assertEqual(list(by_ip), ["192.0.2.1"])
        self.assertFalse(by_ip["192.0.2.1"]["alive"])
        self.assertEqual(by_ip["192.0.2.1"]["open_ports"], [443])

    def test_host_found_by_ping_with_no_open_ports(self):
        with mock.patch.object(ns, "_ping", side_effect=lambda ip: ip.endswith(".2")), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[22])
        self.assertEqual([r["ip"] for r in rows], ["192.0.2.2"])
        self.assertTrue(rows[0]["alive"])
        self.assertEqual(rows[0]["open_ports"], [])

    def test_silent_host_is_absent(self):
        with mock.patch.object(ns, "_ping", return_value=False), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[22])
        self.assertEqual(rows, [])

    def test_empty_port_list_is_ping_only(self):
        with mock.patch.object(ns, "_ping", side_effect=lambda ip: ip.endswith(".1")), \
             mock.patch.object(ns, "is_reachable") as reach:
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[])
        reach.assert_not_called()
        self.assertEqual([r["ip"] for r in rows], ["192.0.2.1"])

    def test_port_connect_timeout_is_one_second(self):
        # is_reachable defaults to 2s (core_engine.py:210). On a silent /24 with
        # 3 ports that is 1524 seconds of connect budget across the pool.
        seen = []
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable",
                               side_effect=lambda ip, port, timeout: seen.append(timeout) or False):
            ns.scan_subnet(address="192.0.2.0/30", ports=[22])
        self.assertEqual(set(seen), {1})

    def test_results_are_sorted_by_ip(self):
        # as_completed yields in completion order; the UI table must be stable.
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            rows = ns.scan_subnet(address="192.0.2.0/28", ports=[])
        self.assertEqual([r["ip"] for r in rows], sorted(
            (r["ip"] for r in rows), key=lambda s: tuple(int(o) for o in s.split("."))))


class TestScanProgress(unittest.TestCase):
    """One phase now: no triage, so the total no longer grows mid-run."""

    def test_progress_is_single_phase(self):
        calls = []
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            ns.scan_subnet(address="192.0.2.0/29", ports=[22],
                           progress_cb=lambda done, total: calls.append((done, total)))
        # 6 usable hosts in a /29, one unit of work each.
        self.assertEqual(calls[-1], (6, 6))
        self.assertEqual({t for _, t in calls}, {6})


if __name__ == "__main__":
    unittest.main()
