# -*- coding: utf-8 -*-
"""Origine MAC: l'ambiguita' si calcola DENTRO un tenant, non fra tenant.

Un tenant e' una rete a se'. Lo stesso MAC in due sedi ha due posizioni
entrambe vere, e unirle prima di contare le porte d'accesso distinte produce
un avviso falso — "piu' porte d'accesso possibili, esegui una MAC Scan
aggiornata" — su un client che in ogni sede sta su una porta sola. Peggio:
manda a rifare una scansione per riparare un problema che non esiste, e la
regola "la piu' recente e' la piu' probabile" finisce per attraversare le sedi.

`_mac_group()` non era coperto da nessun test: test_router_smoke e
test_ui_revamp toccano la rotta, non la logica di raggruppamento, ed e'
esattamente li' che stava il difetto.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_maclocate_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

from routers import mac as mac_router  # noqa: E402

MAC = "aa:bb:cc:dd:ee:01"
ADMIN = {"sub": "admin", "role": "admin"}
VIEWER = {"sub": "viewer", "role": "viewer"}


def _sighting(tenant, switch_ip, interface, last_seen, is_uplink=0, **extra):
    """Una riga come la restituisce mac_history.search(), gia' riclassificata."""
    row = {
        "mac": MAC, "oui_vendor": "Example Corp", "vlan": "10",
        "switch_ip": switch_ip, "switch_name": f"switch-{switch_ip[-1]}",
        "interface": interface, "port_channel": "", "is_uplink": is_uplink,
        "uplink_to": "", "tenant": tenant, "site": "central",
        "first_seen": last_seen, "last_seen": last_seen, "seen_count": 1,
    }
    row.update(extra)
    return row


class TestMacGroupPerTenant(unittest.TestCase):
    """Il raggruppamento e' per (MAC, tenant), non per MAC."""

    def test_una_porta_per_tenant_non_e_ambigua(self):
        """Il difetto originale: stesso MAC, una porta d'accesso in ciascuna di
        due sedi. Unito dava access_count=2 e status 'ambiguous'."""
        rows = [
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21"),
            _sighting("sede-b", "198.51.100.1", "Ethernet0/0", "2026-08-01T22:06:04"),
        ]
        results = mac_router._mac_group(rows)

        self.assertEqual(len(results), 2, "una voce per tenant")
        self.assertEqual({r["tenant"] for r in results}, {"sede-a", "sede-b"})
        for r in results:
            self.assertEqual(r["status"], "resolved",
                             f"tenant {r['tenant']} ha una porta sola: non e' ambiguo")
            self.assertEqual(r["access_count"], 1)

    def test_due_porte_nello_stesso_tenant_restano_ambigue(self):
        """L'ambiguita' vera non deve sparire: due porte d'accesso nella STESSA
        rete sono il caso in cui una scansione piu' fresca serve davvero."""
        rows = [
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21"),
            _sighting("sede-a", "192.0.2.2", "GigabitEthernet2/0/9", "2026-08-02T09:00:00"),
        ]
        results = mac_router._mac_group(rows)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "ambiguous")
        self.assertEqual(results[0]["access_count"], 2)

    def test_stessa_porta_vista_due_volte_non_e_ambigua(self):
        """Due righe per (switch, interfaccia) con VLAN diverse sono UNA
        posizione: 'distinct' conta le posizioni, non le righe."""
        rows = [
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21"),
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-02T09:00:00",
                      vlan="31"),
        ]
        results = mac_router._mac_group(rows)

        self.assertEqual(results[0]["status"], "resolved")
        self.assertEqual(results[0]["access_count"], 1)

    def test_origin_ordinato_per_recency_dentro_il_tenant(self):
        rows = [
            _sighting("sede-a", "192.0.2.2", "GigabitEthernet2/0/9", "2026-07-13T15:01:39"),
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21"),
        ]
        results = mac_router._mac_group(rows)

        self.assertEqual(results[0]["origin"][0]["switch_ip"], "192.0.2.1")

    def test_transito_e_accesso_separati_per_tenant(self):
        """Un uplink in una sede non deve rendere 'transit_only' l'altra, ne'
        contare come porta d'accesso da nessuna parte."""
        rows = [
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21"),
            _sighting("sede-a", "192.0.2.9", "Port-channel1", "2026-08-03T14:30:23",
                      is_uplink=1, uplink_to="switch-2"),
            _sighting("sede-b", "198.51.100.9", "Port-channel1", "2026-08-03T14:30:23",
                      is_uplink=1, uplink_to="switch-7"),
        ]
        results = mac_router._mac_group(rows)
        by_tenant = {r["tenant"]: r for r in results}

        self.assertEqual(by_tenant["sede-a"]["status"], "resolved")
        self.assertEqual(by_tenant["sede-a"]["access_count"], 1)
        self.assertEqual(len(by_tenant["sede-a"]["transit"]), 1)
        self.assertEqual(by_tenant["sede-b"]["status"], "transit_only",
                         "in sede-b il MAC si vede solo passare")
        self.assertEqual(by_tenant["sede-b"]["access_count"], 0)

    def test_un_tenant_solo_risposta_invariata(self):
        """Il caso normale — la maggioranza — non cambia forma."""
        rows = [_sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4",
                          "2026-08-03T15:43:21")]
        results = mac_router._mac_group(rows)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["mac"], MAC)
        self.assertEqual(results[0]["status"], "resolved")
        self.assertEqual(results[0]["oui_vendor"], "Example Corp")

    def test_mac_di_interfaccia_switch_resta_marcato_e_in_fondo(self):
        """L'infrastruttura non e' un endpoint: la marcatura sopravvive al
        raggruppamento per tenant e resta ordinata dopo gli endpoint."""
        rows = [
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21",
                      origin_type="switch-interface", origin_switch="switch-1",
                      origin_interface="Vlan10"),
            _sighting("sede-b", "198.51.100.1", "Ethernet0/0", "2026-08-01T22:06:04"),
        ]
        results = mac_router._mac_group(rows)

        self.assertEqual(results[-1]["origin_type"], "switch-interface")
        self.assertEqual(results[-1]["origin_switch"], "switch-1")


class TestMacLocateScoping(unittest.TestCase):
    """Il parametro tenant RESTRINGE lo scoping, non lo allarga."""

    def _run(self, rows, current_user, tenant=None):
        seen = {}

        def fake_search(mac=None, tenants=None, limit=500, **kw):
            seen["tenants"] = tenants
            if tenants is None:
                return list(rows)
            return [r for r in rows if r["tenant"] in tenants]

        with patch("collectors.mac_history.search", side_effect=fake_search), \
             patch("collectors.mac_history.reclassify_sightings"):
            out = mac_router.mac_locate(mac=MAC, tenant=tenant,
                                        current_user=current_user)
        return out, seen

    def test_tenant_indicato_restringe_la_ricerca(self):
        rows = [
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21"),
            _sighting("sede-b", "198.51.100.1", "Ethernet0/0", "2026-08-01T22:06:04"),
        ]
        out, seen = self._run(rows, ADMIN, tenant="sede-a")

        self.assertEqual(seen["tenants"], ["sede-a"])
        self.assertEqual(out["results"][0]["tenant"], "sede-a")
        self.assertEqual(len(out["results"]), 1)

    def test_senza_tenant_l_admin_vede_tutte_le_sedi_ma_separate(self):
        rows = [
            _sighting("sede-a", "192.0.2.1", "GigabitEthernet1/0/4", "2026-08-03T15:43:21"),
            _sighting("sede-b", "198.51.100.1", "Ethernet0/0", "2026-08-01T22:06:04"),
        ]
        out, _ = self._run(rows, ADMIN)

        self.assertEqual(len(out["results"]), 2)
        self.assertTrue(all(r["status"] == "resolved" for r in out["results"]))

    def test_tenant_fuori_scope_e_403(self):
        with patch("routers.mac.user_group_scope", return_value={"sede-a"}):
            with self.assertRaises(HTTPException) as ctx:
                mac_router.mac_locate(mac=MAC, tenant="sede-b", current_user=VIEWER)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_mac_vuoto_e_400(self):
        with self.assertRaises(HTTPException) as ctx:
            mac_router.mac_locate(mac="   ", current_user=ADMIN)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_nessun_avvistamento(self):
        out, _ = self._run([], ADMIN)
        self.assertEqual(out["status"], "not_found")
        self.assertEqual(out["results"], [])


class TestMacLocateFrontend(unittest.TestCase):
    """Verifica grep-style: non c'e' un runner JS, la logica vera sta in Python."""

    @classmethod
    def setUpClass(cls):
        from tests.test_helpers_frontend import frontend_source
        cls.src = frontend_source()

    def test_il_pulsante_passa_il_tenant_del_gruppo(self):
        """La tabella e' raggruppata per switch e il tenant e' gia' a schermo
        come badge: non passarlo era l'origine del difetto."""
        self.assertIn("macLocate('${escapeHtml(jsStr(r.mac))}','${escapeHtml(jsStr(g.tenant || ''))}')",
                      self.src)

    def test_la_chiamata_porta_il_tenant_in_query(self):
        self.assertIn("'&tenant=' + encodeURIComponent(tenant)", self.src)

    def test_un_solo_renderer_del_modale(self):
        """Una sezione per tenant si ottiene ciclando lo stesso renderer. Due
        renderer sarebbero due copie da tenere allineate."""
        self.assertEqual(self.src.count("const entrySection = (g) =>"), 1)
        self.assertEqual(self.src.count("ov.id = 'macLocateModal'"), 1)

    def test_niente_riscansione_consigliata_per_il_multi_tenant(self):
        """Il consiglio di rifare una MAC Scan vale per l'ambiguita' DENTRO una
        rete. Su piu' tenant non c'entra niente: ogni posizione e' vera."""
        self.assertIn("in questo tenant", self.src)
        self.assertIn("non sono alternative fra cui scegliere", self.src)


if __name__ == "__main__":
    unittest.main()
