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


class TestScanProgress(unittest.TestCase):
    """La fase lenta e' il triage SSH, non il ping: se il progresso si ferma
    alla fine dei ping la barra resta al 100% mentre il lavoro continua."""

    def test_progress_covers_triage_phase(self):
        calls = []

        with mock.patch.object(ns, "_ping", side_effect=lambda ip: ip.endswith(".1")), \
             mock.patch.object(ns, "is_reachable", return_value=True), \
             mock.patch.object(ns, "probe_device",
                               return_value={"status": "success", "hostname": "switch-01"}), \
             mock.patch.object(ns.crypto_vault, "encrypt_password", return_value="enc"):
            ns.scan_subnet(
                address="192.0.2.0/29",
                vendor_hint="cisco",
                credentials={"username": "u", "password": "p", "secret": "s"},
                progress_cb=lambda done, total: calls.append((done, total)),
            )

        # 6 host utili nella /29, 1 vivo -> 6 ping + 1 triage.
        self.assertEqual(calls[-1], (7, 7))
        self.assertEqual(max(t for _, t in calls), 7)


class TestScanIsDiscoveryOnly(unittest.TestCase):
    """La scansione tocca ogni host con la 22 aperta: il backup completo (22+
    comandi, ognuno col suo timeout) rende un solo host non collaborativo
    costoso minuti. La scansione sonda, non fa backup."""

    def _scan(self, probe_result):
        with mock.patch.object(ns, "_ping", side_effect=lambda ip: ip.endswith(".1")), \
             mock.patch.object(ns, "is_reachable", return_value=True), \
             mock.patch.object(ns, "probe_device", return_value=probe_result) as probe, \
             mock.patch.object(ns.crypto_vault, "encrypt_password", return_value="enc"):
            results = ns.scan_subnet(
                address="192.0.2.0/29",
                vendor_hint="linux",
                credentials={"username": "u", "password": "p", "secret": "s"},
            )
        return probe, {r["ip"]: r for r in results}

    def test_probe_instead_of_backup(self):
        # Il backup non deve partire NEMMENO in aggiunta alla sonda:
        # assert_called_once() sulla sonda resterebbe verde se qualcuno
        # rimettesse il backup accanto, che e' proprio la regressione temuta.
        from core import core_engine
        with mock.patch.object(core_engine, "run_backup_and_triage") as backup:
            probe, rows = self._scan({"status": "success", "hostname": "switch-01"})
            backup.assert_not_called()
        probe.assert_called_once()
        self.assertTrue(rows["192.0.2.1"]["ssh_ok"])
        self.assertEqual(rows["192.0.2.1"]["hostname"], "switch-01")

    def test_failed_login_is_not_ssh_ok(self):
        # La 22 aperta non e' una credenziale valida: con auto_add finirebbero
        # in inventario apparati su cui non si entra.
        _, rows = self._scan({"status": "error", "message": "Authentication failed"})
        self.assertFalse(rows["192.0.2.1"]["ssh_ok"])
        self.assertIsNone(rows["192.0.2.1"]["hostname"])


if __name__ == "__main__":
    unittest.main()
