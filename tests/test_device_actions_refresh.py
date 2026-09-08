# -*- coding: utf-8 -*-
"""Un'azione sui dispositivi ricarica l'inventario, non l'applicazione.

Dieci azioni della scheda Dispositivi (salva, elimina, rinomina, cambio sede,
CRUD tenant, import CSV, aggiungi da scansione, fine triage) chiamavano
``appInit()``, cioe' l'avvio completo: /api/auth/status, /api/auth/me,
/api/version, /api/vendors, /api/local-devices, /api/settings/snmp-defaults e
una ``loadHome()`` che rifaceva /api/local-devices appena caricato. Sei round
trip e un ridisegno completo del cruscotto per cambiare il tenant di un
apparato: e' il motivo per cui "gestire i dispositivi" era la parte lenta.
"""

import os
import re
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(BASE, *parts), encoding="utf-8") as fh:
        return fh.read()


class DeviceActionsDoNotRebootTheApp(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.devices = _read("static", "js", "devices.js")
        cls.core = _read("static", "js", "core.js")

    def _refresh_body(self):
        body = self.core[self.core.index("async function refreshInventory()"):]
        return body[:body.index("\nasync function appInit")]

    def test_no_device_action_calls_appInit(self):
        # appInit resta l'avvio: login, boot, wizard. Non un modo per
        # ridisegnare una tabella.
        self.assertNotIn("appInit(", self.devices)

    def test_the_actions_refresh_the_inventory_instead(self):
        # Le dieci chiamate sostituite: se qualcuna sparisce, la tabella
        # resta ferma dopo l'azione ed e' il difetto opposto.
        self.assertGreaterEqual(self.devices.count("refreshInventory("), 10)

    def test_refresh_inventory_exists_and_reports_failure(self):
        self.assertIn("async function refreshInventory()", self.core)
        body = self._refresh_body()
        # Ritorna false quando l'inventario non arriva: senza questo il
        # chiamante ridisegnerebbe sui globali vecchi credendoli aggiornati.
        self.assertIn("return false", body)
        self.assertIn("return true", body)

    def test_refresh_inventory_does_not_refetch_auth_or_version(self):
        body = self._refresh_body()
        for path in ("/api/auth/status", "/api/auth/me", "/api/version",
                     "/api/vendors", "/api/settings/snmp-defaults"):
            self.assertNotIn(path, body,
                             f"refreshInventory non deve richiedere {path}")

    def test_home_is_refreshed_only_when_it_is_the_visible_tab(self):
        # loadHome() rifa' /api/local-devices per conto suo: chiamarla sempre
        # raddoppiava la richiesta a ogni azione.
        self.assertRegex(self._refresh_body(), r"tab-home'\s*\)\s*loadHome\(\)")

    def test_tenant_crud_still_refreshes_the_snmp_defaults(self):
        # snmpDefaultTenants non sta in /api/local-devices: senza questo la
        # colonna SNMP della tabella Tenant resta indietro dopo un rename.
        self.assertIn("loadSnmpDefaults", self.devices)
        self.assertGreaterEqual(
            len(re.findall(r"refreshInventory\(\)\.then\(loadSnmpDefaults\)",
                           self.devices)), 2)


if __name__ == "__main__":
    unittest.main()
