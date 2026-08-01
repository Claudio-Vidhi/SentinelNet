# -*- coding: utf-8 -*-
"""Test della lettura del CSV di inventario.

Un CSV di inventario arriva quasi sempre da un foglio di calcolo, e i tre modi
in cui falliva erano indistinguibili dall'utente: OGNI riga veniva scartata con
"IP mancante", qualunque fosse la causa reale. I casi coperti qui sono quelli
osservati, non ipotesi: BOM di Excel, punto e virgola come separatore, e
intestazioni scritte in un'altra grafia.
"""

import unittest

from routers.inventory import _canonical_header, _read_inventory_csv

HEADER = "IP,Username,Password,Enable Secret,Hostname,Group,Vendor"
ROW = "192.0.2.1,admin,Pw1!,ena,switch-01,Tenant_Milano,cisco"


class TestHeaderRecognition(unittest.TestCase):
    def test_canonical_names(self):
        self.assertEqual("IP", _canonical_header("IP"))
        self.assertEqual("Enable Secret", _canonical_header("Enable Secret"))

    def test_case_spacing_and_underscores_are_ignored(self):
        for spelling in ("ip", "IP ", " Ip", "IP_ADDRESS", "ipaddress"):
            self.assertEqual("IP", _canonical_header(spelling), spelling)
        for spelling in ("enable_secret", "ENABLE SECRET", "EnableSecret"):
            self.assertEqual("Enable Secret", _canonical_header(spelling),
                             spelling)

    def test_italian_column_names(self):
        self.assertEqual("IP", _canonical_header("Indirizzo"))
        self.assertEqual("Username", _canonical_header("Utente"))
        self.assertEqual("Group", _canonical_header("Gruppo"))
        self.assertEqual("Vendor", _canonical_header("Marca"))

    def test_tenant_and_site_are_two_columns_not_one(self):
        """Prima 'Site' e 'Sede' finivano su Group mentre l'export scriveva
        entrambe le colonne: reimportare un file esportato riscriveva il
        tenant di ogni apparato con il suo id di sede, in silenzio."""
        for spelling in ("Group", "Gruppo", "Tenant"):
            self.assertEqual("Group", _canonical_header(spelling), spelling)
        for spelling in ("Site", "Sede"):
            self.assertEqual("Site", _canonical_header(spelling), spelling)

    def test_exported_file_round_trips_without_losing_the_tenant(self):
        """Il caso che rompeva l'onboarding multi-sede: esporta, reimporta,
        e ogni apparato aveva il tenant sovrascritto dalla sede."""
        exported = ("IP,Vendor,Profile,Username,Password,Enable Secret,Group,"
                    "Hostname,Site,SSH Port,Transports,SNMP Community\n"
                    "192.0.2.1,cisco,,admin,Pw1!,,Tenant_Milano,switch-01,"
                    "sede-milano,22,,\n")
        rows = _read_inventory_csv(exported)
        self.assertEqual(1, len(rows))
        _line, rec = rows[0]
        self.assertEqual("Tenant_Milano", rec["Group"])
        self.assertEqual("sede-milano", rec["Site"])

    def test_unknown_column_is_none_not_an_error(self):
        self.assertIsNone(_canonical_header("Note"))
        self.assertIsNone(_canonical_header(""))


class TestCsvReading(unittest.TestCase):
    def _one(self, text):
        rows = _read_inventory_csv(text)
        self.assertEqual(1, len(rows), rows)
        return rows[0]

    def test_plain_comma_file(self):
        line, rec = self._one(HEADER + "\n" + ROW + "\n")
        self.assertEqual(2, line)
        self.assertEqual("192.0.2.1", rec["IP"])
        self.assertEqual("switch-01", rec["Hostname"])
        self.assertEqual("Tenant_Milano", rec["Group"])

    def test_excel_bom_does_not_hide_the_first_column(self):
        """Col BOM la prima colonna si chiamava '\\ufeffIP' e ogni riga
        falliva per 'IP mancante'."""
        _, rec = self._one("﻿" + HEADER + "\n" + ROW + "\n")
        self.assertEqual("192.0.2.1", rec["IP"])

    def test_semicolon_separator(self):
        """Excel con impostazioni italiane salva con il punto e virgola: letto
        con la virgola, l'intero file diventa una colonna sola."""
        _, rec = self._one(HEADER.replace(",", ";") + "\n"
                           + ROW.replace(",", ";") + "\n")
        self.assertEqual("192.0.2.1", rec["IP"])
        self.assertEqual("cisco", rec["Vendor"])

    def test_tab_separator(self):
        _, rec = self._one(HEADER.replace(",", "\t") + "\n"
                           + ROW.replace(",", "\t") + "\n")
        self.assertEqual("192.0.2.1", rec["IP"])

    def test_mixed_spelling_header(self):
        _, rec = self._one("indirizzo;utente;password;enable_secret;nome;gruppo;marca\n"
                           "192.0.2.9;op;Pw2!;ena;switch-09;Tenant_Roma;hpe\n")
        self.assertEqual("192.0.2.9", rec["IP"])
        self.assertEqual("op", rec["Username"])
        self.assertEqual("switch-09", rec["Hostname"])
        self.assertEqual("Tenant_Roma", rec["Group"])
        self.assertEqual("hpe", rec["Vendor"])

    def test_only_the_ip_column_is_required(self):
        _, rec = self._one("IP\n192.0.2.5\n")
        self.assertEqual("192.0.2.5", rec["IP"])
        self.assertNotIn("Vendor", rec)

    def test_blank_lines_are_skipped_not_reported_as_errors(self):
        rows = _read_inventory_csv(HEADER + "\n" + ROW + "\n\n\n"
                                   + "192.0.2.2,admin,Pw1!,ena,switch-02,G,cisco\n")
        self.assertEqual(2, len(rows))
        self.assertEqual([2, 5], [line for line, _ in rows])

    def test_values_are_stripped(self):
        _, rec = self._one("IP , Hostname\n  192.0.2.7 ,  switch-07  \n")
        self.assertEqual("192.0.2.7", rec["IP"])
        self.assertEqual("switch-07", rec["Hostname"])

    def test_unknown_columns_are_dropped_not_fatal(self):
        _, rec = self._one("IP,Note,Vendor\n192.0.2.8,da sostituire,cisco\n")
        self.assertEqual({"IP": "192.0.2.8", "Vendor": "cisco"}, rec)

    def test_missing_ip_column_says_what_it_read(self):
        """Il messaggio deve nominare le intestazioni trovate: senza, l'utente
        non ha modo di capire quale colonna manca."""
        with self.assertRaises(ValueError) as ctx:
            _read_inventory_csv("Nome,Vendor\nswitch-01,cisco\n")
        msg = str(ctx.exception)
        self.assertIn("IP", msg)
        self.assertIn("Vendor", msg)

    def test_empty_file_is_rejected_clearly(self):
        for text in ("", "   \n\n"):
            with self.assertRaises(ValueError):
                _read_inventory_csv(text)


if __name__ == "__main__":
    unittest.main()
