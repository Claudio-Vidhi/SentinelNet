# -*- coding: utf-8 -*-
"""Il backup del triage non si legge in dieci secondi.

Un WLC AireOS raggiungibile dal terminale dell'applicazione falliva il triage
con:

    Pattern not detected: '\\(<hostname>\\)\\ >' in output.

Il messaggio parla del prompt, e mandava a cercare il prompt. Non era quello:
netmiko riporta esattamente quella frase ogni volta che scade `read_timeout`
mentre aspetta il prompt di fine comando. Il triage passava `read_timeout=30`
a tutti i comandi accessori e NIENTE al comando di backup, che e' l'uscita piu'
grande della sessione: restava sul default di netmiko, dieci secondi.

Dati sintetici: RFC 5737, hostname di esempio.
"""

import unittest
from unittest import mock

from core import core_engine
from drivers.cisco_wlc import CiscoWlcDriver


VERSION = "8.10.0.0"  # check-private-data: ok, AireOS version string, not an IP


class _FakeConnection:
    """Registra come vengono chiamati i comandi, senza aprire nulla."""

    def __init__(self, sysinfo="Product Version.................. " + VERSION):
        self.calls = []
        self._sysinfo = sysinfo

    def send_command(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if "sysinfo" in command:
            return self._sysinfo
        return "hostname WLC-01\n"

    def enable(self):
        pass

    def find_prompt(self):
        return "(WLC-01) >"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def timeout_of(self, needle: str):
        """Il read_timeout con cui e' partito il comando che contiene `needle`."""
        for command, kwargs in self.calls:
            if needle in command:
                # 10.0 e' il default di netmiko: assente significa "il default".
                return kwargs.get("read_timeout", 10.0)
        raise AssertionError(f"comando con {needle!r} mai eseguito: {self.calls}")


class IlDriverWlcDaTempoAllaVersione(unittest.TestCase):

    def test_show_sysinfo_non_usa_il_default_di_netmiko(self):
        conn = _FakeConnection()
        self.assertEqual(VERSION, CiscoWlcDriver(conn).get_version())
        self.assertGreater(conn.timeout_of("sysinfo"), 10.0,
                           "AireOS scrive lentamente: il default di netmiko non basta")


class IlBackupDelTriageAspettaAbbastanza(unittest.TestCase):

    DEVICE = {"IP": "192.0.2.50", "Group": "ACME-WLC-TEST", "Vendor": "cisco_wlc",
              "Site": "", "Model": ""}

    def _run(self):
        conn = _FakeConnection()
        with mock.patch.object(core_engine.site_manager, "is_agent_site",
                               lambda site: False), \
             mock.patch.object(core_engine.site_manager, "has_direct_path",
                               lambda site: False), \
             mock.patch.object(core_engine, "get_device_credentials",
                               lambda d: ("u", "p", "")), \
             mock.patch.object(core_engine, "ConnectHandler", lambda **kw: conn), \
             mock.patch.object(core_engine, "update_version_inventory", mock.Mock()), \
             mock.patch.object(core_engine, "update_device_hostname", mock.Mock()), \
             mock.patch.object(core_engine, "save_backup", lambda *a: "backup.txt"), \
             mock.patch.object(core_engine, "log_audit", mock.Mock()):
            result = core_engine.run_backup_and_triage(dict(self.DEVICE))
        return conn, result

    def test_il_triage_arriva_in_fondo(self):
        _conn, result = self._run()
        self.assertEqual("success", result["status"], result.get("message"))
        self.assertEqual(VERSION, result["version"])

    def test_il_comando_di_backup_porta_un_timeout_generoso(self):
        conn, _result = self._run()
        # 'show run-config commands' su un WLC con qualche decina di AP e'
        # lungo e lento: e' il comando che scadeva.
        self.assertGreaterEqual(conn.timeout_of("run-config"),
                                core_engine.BACKUP_READ_TIMEOUT)

    def test_il_backup_non_aspetta_meno_dei_comandi_accessori(self):
        # Era l'incoerenza che ha prodotto il guasto: i comandi di contorno
        # avevano 30 secondi, l'uscita piu' grande della sessione ne aveva 10.
        conn, _result = self._run()
        backup = conn.timeout_of("run-config")
        others = [kw.get("read_timeout", 10.0) for cmd, kw in conn.calls
                  if "run-config" not in cmd and "sysinfo" not in cmd]
        for other in others:
            self.assertGreaterEqual(backup, other)


if __name__ == "__main__":
    unittest.main()
