# -*- coding: utf-8 -*-
"""Correlazione CVE: il rischio di questo lavoro non e' il codice, e' il
significato.

Ogni test qui sotto difende una frase del design
(docs/superpowers/specs/2026-09-09-cve-correlation-design.md), non un ramo:
che i segnali riordinino e non filtrino, che 'servizi ignoti' non diventi
'servizi spenti', che un aggregato non si legga come un tenant pulito.

Dati sintetici ovunque: RFC 5737, CVE inventati, nessun CPE reale.
"""

import itertools
import json
import os
import unittest
from unittest import mock

from drivers import registry
from services import cve_intel

STAMP_OLD = "20200101T000000.000000Z"


def _fresh_stamp():
    from services.config_drift.history import _now
    return _now()


def _cve(cid, cvss=8.0, severity="HIGH", services=()):
    return {"id": cid, "cvss": cvss, "severity": severity,
            "published": "2024-01-10T00:00:00.000",
            "summary": f"Synthetic advisory {cid}.",
            "cpe_hardware": [], "model_scope": "generic",
            "exploited": False, "services": list(services)}


def _snapshot(confidence="exact", cves=None, version_seen_at=None):
    # None = "non specificato, mettici un timestamp fresco"; "" e' un caso di
    # prova a se': la data manca davvero.
    return {
        "device": "192.0.2.10",
        "fetched_at": _fresh_stamp(),
        "version_seen_at": _fresh_stamp() if version_seen_at is None else version_seen_at,
        "source": "nvd",
        "query": {"kind": "cpe", "value": "cpe:2.3:o:vendor:product:1.0",
                  "confidence": confidence},
        "cves": cves if cves is not None else [_cve("CVE-2024-00001")],
    }


class ISegnaliRiordinanoNonFiltrano(unittest.TestCase):
    """Il motore non dice mai "non impattato". Nessun CVE viene mai rimosso."""

    def test_ogni_combinazione_di_segnali_conserva_tutti_i_cve(self):
        cves = [_cve("CVE-2024-00001", 9.8, "CRITICAL", ["snmp"]),
                _cve("CVE-2024-00002", 4.3, "MEDIUM", ["ssh"]),
                _cve("CVE-2024-00003", 7.5, "HIGH")]
        service_states = [{}, {"snmp": True, "ssh": True}, {"snmp": False, "ssh": False},
                          {"snmp": False}, {"http": True}]
        for confidence, services, seen in itertools.product(
                ("exact", "product", "keyword"), service_states,
                (_fresh_stamp(), STAMP_OLD, "")):
            with self.subTest(confidence=confidence, services=services, seen=seen):
                snap = _snapshot(confidence, cves, seen)
                rows = cve_intel.score_rows(snap, services)
                self.assertEqual([c["id"] for c in cves],
                                 sorted(r["id"] for r in rows))

    def test_nessun_punteggio_azzera_un_cve_grave(self):
        rows = cve_intel.score_rows(
            _snapshot("keyword", [_cve("CVE-2024-00001", 9.8, "CRITICAL", ["snmp"])]),
            {"snmp": False})
        self.assertGreater(rows[0]["score"], 0)


class IlPerimetroDelVerdetto(unittest.TestCase):
    """F8: un punteggio senza perimetro viene letto come completo."""

    def test_not_evaluated_non_e_mai_vuoto(self):
        for services in ({}, {"ssh": True}):
            with self.subTest(services=services):
                self.assertTrue(cve_intel.not_evaluated_for(services))

    def test_la_raggiungibilita_resta_non_valutata_finche_f6_non_esiste(self):
        self.assertIn("reachability", cve_intel.not_evaluated_for({"ssh": True}))

    def test_service_state_compare_solo_quando_i_servizi_sono_ignoti(self):
        self.assertIn("service_state", cve_intel.not_evaluated_for({}))
        self.assertNotIn("service_state", cve_intel.not_evaluated_for({"ssh": True}))


class LaConfidenzaDelMatch(unittest.TestCase):
    """F3: un CVE trovato per parole chiave e uno per CPE esatto non possono
    valere uguale."""

    def test_keyword_non_supera_mai_exact_a_parita_di_cvss(self):
        # Il caso peggiore: keyword col servizio acceso contro exact col
        # servizio spento. Anche cosi' l'ordine non si inverte.
        keyword = cve_intel.score_rows(
            _snapshot("keyword", [_cve("CVE-2024-00001", 8.0, "HIGH", ["snmp"])]),
            {"snmp": True})[0]
        exact = cve_intel.score_rows(
            _snapshot("exact", [_cve("CVE-2024-00001", 8.0, "HIGH", ["snmp"])]),
            {"snmp": False})[0]
        self.assertLess(keyword["score"], exact["score"])

    def test_i_tre_livelli_sono_ordinati(self):
        scores = {}
        for confidence in ("exact", "product", "keyword"):
            scores[confidence] = cve_intel.score_rows(
                _snapshot(confidence, [_cve("CVE-2024-00001", 8.0)]), {})[0]["score"]
        self.assertGreater(scores["exact"], scores["product"])
        self.assertGreater(scores["product"], scores["keyword"])

    def test_query_for_distingue_exact_product_e_keyword(self):
        exact = cve_intel.query_for({"IP": "192.0.2.10", "Vendor": "cisco"},
                                    "Cisco IOS Software, Version 15.2(7)E")
        self.assertEqual("exact", exact["confidence"])
        self.assertIn("15.2", exact["value"])

        product = cve_intel.query_for({"IP": "192.0.2.10", "Vendor": "cisco"},
                                      "Cisco Catalyst switch")
        self.assertEqual("product", product["confidence"])

        keyword = cve_intel.query_for({"IP": "192.0.2.10", "Vendor": "acme-unknown"},
                                      "Acme appliance")
        self.assertEqual("keyword", keyword["confidence"])
        self.assertEqual("keyword", keyword["kind"])


class ServiziIgnotiNonSonoServiziSpenti(unittest.TestCase):
    """F5: la confusione piu' facile da introdurre e la piu' dannosa."""

    def _score(self, services):
        return cve_intel.score_rows(
            _snapshot("exact", [_cve("CVE-2024-00001", 8.0, "HIGH", ["snmp"])]),
            services)[0]

    def test_estrattore_assente_lascia_il_punteggio_invariato(self):
        neutral = cve_intel.score_rows(
            _snapshot("exact", [_cve("CVE-2024-00001", 8.0)]), {})[0]
        self.assertEqual(neutral["score"], self._score({})["score"])
        self.assertEqual("unknown", self._score({})["service"])

    def test_servizio_spento_abbassa_servizio_acceso_alza(self):
        self.assertLess(self._score({"snmp": False})["score"],
                        self._score({})["score"])
        self.assertGreater(self._score({"snmp": True})["score"],
                           self._score({})["score"])

    def test_un_servizio_non_coperto_dall_estrattore_resta_ignoto(self):
        # L'estrattore sa dire di ssh, non di snmp: su un CVE che nomina snmp
        # la risposta onesta e' 'ignoto', non 'spento'.
        self.assertEqual("unknown", self._score({"ssh": True})["service"])

    def test_un_cve_che_non_nomina_servizi_non_viene_toccato(self):
        row = cve_intel.score_rows(
            _snapshot("exact", [_cve("CVE-2024-00001", 8.0)]),
            {"snmp": False})[0]
        self.assertEqual("unknown", row["service"])
        self.assertEqual(8.0, row["score"])


class EtaDelDato(unittest.TestCase):
    """F2: 'stale' e' un marchio, non un declassamento."""

    def test_una_lettura_vecchia_marca_ma_non_abbassa(self):
        fresh = cve_intel.score_rows(_snapshot("exact", None, _fresh_stamp()), {})[0]
        old = cve_intel.score_rows(_snapshot("exact", None, STAMP_OLD), {})[0]
        self.assertFalse(fresh["stale"])
        self.assertTrue(old["stale"])
        self.assertEqual(fresh["score"], old["score"])

    def test_eta_ignota_vale_come_vecchia(self):
        self.assertTrue(cve_intel.score_rows(_snapshot("exact", None, ""), {})[0]["stale"])


class LEstrattoreDeiServizi(unittest.TestCase):
    """F5: la configurazione dice cio' che l'apparato FA."""

    IOS = ("hostname switch-01\n"
           "no ip http server\n"
           "ip http secure-server\n"
           "snmp-server community public RO\n"
           "line vty 0 4\n"
           " transport input ssh\n")

    def test_ios_legge_http_https_snmp_ssh_e_telnet(self):
        svc = registry.services_enabled("cisco_ios", self.IOS)
        self.assertEqual({"http": False, "https": True, "snmp": True,
                          "ssh": True, "telnet": False}, svc)

    def test_ios_senza_snmp_server_dice_snmp_spento(self):
        svc = registry.services_enabled("cisco_ios", "hostname switch-01\n")
        self.assertFalse(svc["snmp"])

    def test_ios_senza_transport_input_non_si_pronuncia_su_ssh(self):
        svc = registry.services_enabled("cisco_ios", "hostname switch-01\n")
        self.assertNotIn("ssh", svc)
        self.assertNotIn("telnet", svc)

    def test_fortios_legge_allowaccess(self):
        cfg = ("config system interface\n"
               "    edit \"port1\"\n"
               "        set allowaccess ping https ssh\n"
               "    next\n"
               "end\n")
        self.assertEqual({"ssh": True, "telnet": False, "snmp": False,
                          "http": False, "https": True},
                         registry.services_enabled("fortinet", cfg))

    def test_un_vendor_senza_estrattore_risponde_ignoto(self):
        self.assertEqual({}, registry.services_enabled("juniper_junos", "set system\n"))
        self.assertEqual({}, registry.services_enabled("", self.IOS))

    def test_una_config_non_riconosciuta_risponde_ignoto_non_tutto_spento(self):
        self.assertEqual({}, registry.services_enabled("fortinet",
                                                       "config system global\nend\n"))


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class LoSnapshotPersistito(unittest.TestCase):
    """F1: senza stato nessun risultato e' riproducibile o citabile."""

    DEVICE = {"IP": "192.0.2.10", "Group": "ACME-CVE-TEST", "Vendor": "cisco",
              "Model": "Non Rilevato"}

    def _refresh(self, total=1):
        payload_page = {"vulnerabilities": [{"cve": {
            "id": "CVE-2024-00001",
            "descriptions": [{"lang": "en", "value": "SNMP flaw in the agent."}],
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                "baseScore": 8.6, "baseSeverity": "HIGH"}}]},
            "published": "2024-01-10T00:00:00.000",
        }}]}

        def fake_get(url, params=None, **kw):
            if (params or {}).get("resultsPerPage") == "1":
                return _Resp({"totalResults": total})
            return _Resp(payload_page)

        with mock.patch.object(cve_intel.requests, "get", fake_get):
            return cve_intel.refresh(self.DEVICE,
                                     "Cisco IOS Software, Version 15.2(7)E",
                                     STAMP_OLD)

    def test_lo_schema_e_stabile_e_le_due_date_sono_indipendenti(self):
        snap = self._refresh()
        for key in ("device", "fetched_at", "version_seen_at", "source",
                    "query", "total_available", "cves"):
            self.assertIn(key, snap)
        # Quanti NVD ne conosce, non quanti ne sono stati tenuti.
        self.assertEqual(1, snap["total_available"])
        self.assertEqual("192.0.2.10", snap["device"])
        # Un elenco fresco su una lettura vecchia e' fresco solo all'apparenza:
        # le due date devono poter divergere.
        self.assertEqual(STAMP_OLD, snap["version_seen_at"])
        self.assertNotEqual(STAMP_OLD, snap["fetched_at"])
        self.assertEqual("exact", snap["query"]["confidence"])

    def test_lo_snapshot_finisce_su_disco_e_si_rilegge_uguale(self):
        written = self._refresh()
        path = cve_intel.snapshot_path(self.DEVICE)
        self.assertTrue(os.path.exists(path))
        # Nessun file temporaneo lasciato indietro: la scrittura e' atomica.
        self.assertFalse(os.path.exists(path + ".tmp"))
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(written, json.load(fh))
        self.assertEqual(written, cve_intel.load(self.DEVICE))

    def test_i_servizi_del_cve_si_deducono_dal_testo(self):
        snap = self._refresh()
        self.assertEqual(["snmp"], snap["cves"][0]["services"])

    def test_zero_risultati_non_e_un_errore(self):
        snap = self._refresh(total=0)
        self.assertEqual([], snap["cves"])

    def test_un_apparato_mai_correlato_legge_dizionario_vuoto(self):
        self.assertEqual({}, cve_intel.load(
            {"IP": "198.51.100.5", "Group": "ACME-CVE-VUOTO", "Vendor": "cisco"}))


class IlResocontoPerTenant(unittest.TestCase):
    """F9b: ogni conteggio viaggia con il suo denominatore di copertura."""

    def test_un_tenant_senza_versioni_non_si_legge_come_pulito(self):
        devices = [{"IP": "192.0.2.10", "Group": "BETA-CVE-TEST", "Vendor": "cisco"},
                   {"IP": "192.0.2.11", "Group": "BETA-CVE-TEST", "Vendor": "cisco"}]
        with mock.patch.object(cve_intel, "load", lambda d: {}), \
             mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: {}):
            rows = cve_intel.summary(devices)
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual(2, row["devices"])
        # Copertura zero E conteggi zero: i due numeri insieme sono l'unico
        # modo di non far leggere "tenant a posto".
        self.assertEqual(0, row["with_version"])
        self.assertEqual({"critical": 0, "high": 0, "medium": 0, "low": 0},
                         row["counts"])
        self.assertTrue(row["not_evaluated"])

    def test_la_copertura_parziale_e_visibile_nei_numeri(self):
        devices = [{"IP": "192.0.2.10", "Group": "BETA-CVE-TEST", "Vendor": "cisco"},
                   {"IP": "192.0.2.11", "Group": "BETA-CVE-TEST", "Vendor": "cisco"}]
        snap = _snapshot("exact", [_cve("CVE-2024-00001", 9.8, "CRITICAL")])
        with mock.patch.object(cve_intel, "load",
                               lambda d: snap if d["IP"] == "192.0.2.10" else {}), \
             mock.patch.object(cve_intel, "device_services", lambda d: {}), \
             mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: {"192.0.2.10": {"version": "15.2(7)E"}}):
            row = cve_intel.summary(devices)[0]
        self.assertEqual(2, row["devices"])
        self.assertEqual(1, row["with_version"])
        self.assertEqual(1, row["exact_cpe"])
        self.assertEqual(1, row["counts"]["critical"])

    def test_il_perimetro_viaggia_anche_nell_aggregato(self):
        devices = [{"IP": "192.0.2.10", "Group": "BETA-CVE-TEST", "Vendor": "cisco"}]
        with mock.patch.object(cve_intel, "load", lambda d: _snapshot()), \
             mock.patch.object(cve_intel, "device_services", lambda d: {}), \
             mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: {"192.0.2.10": {"version": "15.2(7)E"}}):
            row = cve_intel.summary(devices)[0]
        self.assertIn("reachability", row["not_evaluated"])
        self.assertIn("service_state", row["not_evaluated"])


class IlTettoNonSiTacePerAggregare(unittest.TestCase):
    """Un elenco tagliato in silenzio si legge come un elenco completo."""

    def test_uno_snapshot_al_tetto_e_dichiarato_tagliato(self):
        full = _snapshot("product", [_cve(f"CVE-2024-{i:05d}")
                                     for i in range(cve_intel.MAX_CVES)])
        full["total_available"] = 1247
        self.assertTrue(cve_intel.is_truncated(full))

    def test_uno_snapshot_completo_non_lo_e(self):
        snap = _snapshot("exact", [_cve("CVE-2024-00001")])
        snap["total_available"] = 1
        self.assertFalse(cve_intel.is_truncated(snap))

    def test_senza_il_totale_il_tetto_raggiunto_vale_come_taglio(self):
        # Gli snapshot scritti prima che il totale venisse registrato: meglio
        # una tilde di troppo che un conteggio parziale spacciato per totale.
        old = _snapshot("product", [_cve(f"CVE-2024-{i:05d}")
                                    for i in range(cve_intel.MAX_CVES)])
        old.pop("total_available", None)
        self.assertTrue(cve_intel.is_truncated(old))

    def test_il_tenant_eredita_il_taglio_di_un_solo_apparato(self):
        devices = [{"IP": "192.0.2.10", "Group": "BETA-CVE-TEST", "Vendor": "cisco"},
                   {"IP": "192.0.2.11", "Group": "BETA-CVE-TEST", "Vendor": "cisco"}]
        small = _snapshot("exact", [_cve("CVE-2024-00001", 9.8, "CRITICAL")])
        small["total_available"] = 1
        big = _snapshot("product", [_cve(f"CVE-2024-{i:05d}", 7.5, "HIGH")
                                    for i in range(cve_intel.MAX_CVES)])
        big["total_available"] = 1247
        with mock.patch.object(cve_intel, "load",
                               lambda d: small if d["IP"] == "192.0.2.10" else big), \
             mock.patch.object(cve_intel, "device_services", lambda d: {}), \
             mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: {"192.0.2.10": {"version": "15.2(7)E"},
                                 "192.0.2.11": {"version": "15.2(7)E"}}):
            row = cve_intel.summary(devices)[0]
        self.assertTrue(row["truncated"])


class IlDettaglioPerApparato(unittest.TestCase):
    """Un totale di tenant e' quasi sempre un apparato solo che lo domina."""

    DEVICES = [
        {"IP": "192.0.2.10", "Group": "BETA-CVE-TEST", "Vendor": "cisco",
         "Hostname": "switch-01"},
        {"IP": "192.0.2.11", "Group": "BETA-CVE-TEST", "Vendor": "cisco",
         "Hostname": "switch-02"},
    ]

    def _summary(self, loader, detected=None):
        with mock.patch.object(cve_intel, "load", loader), \
             mock.patch.object(cve_intel, "device_services", lambda d: {}), \
             mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: detected if detected is not None else {}):
            return cve_intel.summary(list(self.DEVICES))[0]

    def test_il_dettaglio_copre_ogni_apparato_anche_senza_snapshot(self):
        row = self._summary(lambda d: {} if d["IP"] == "192.0.2.11" else _snapshot())
        self.assertEqual(2, len(row["devices_detail"]))
        never = next(d for d in row["devices_detail"] if d["ip"] == "192.0.2.11")
        # Un apparato mai correlato non e' un apparato con zero CVE.
        self.assertEqual("none", never["confidence"])
        self.assertEqual(0, never["cves"])

    def test_chi_pesa_di_piu_sta_in_cima(self):
        heavy = _snapshot("product", [_cve(f"CVE-2024-{i:05d}", 7.5, "HIGH")
                                      for i in range(20)])
        light = _snapshot("exact", [_cve("CVE-2024-90001", 7.5, "HIGH")])
        row = self._summary(lambda d: light if d["IP"] == "192.0.2.10" else heavy)
        self.assertEqual("192.0.2.11", row["devices_detail"][0]["ip"])
        self.assertEqual(20, row["devices_detail"][0]["counts"]["high"])

    def test_la_somma_del_dettaglio_e_il_totale_del_tenant(self):
        # Se le due cifre divergono, aprire la riga smette di spiegare il
        # numero e comincia a contraddirlo.
        heavy = _snapshot("product", [_cve(f"CVE-2024-{i:05d}", 7.5, "HIGH")
                                      for i in range(20)])
        light = _snapshot("exact", [_cve("CVE-2024-90001", 9.8, "CRITICAL")])
        row = self._summary(lambda d: light if d["IP"] == "192.0.2.10" else heavy)
        for sev in ("critical", "high", "medium", "low"):
            self.assertEqual(row["counts"][sev],
                             sum(d["counts"][sev] for d in row["devices_detail"]),
                             f"il dettaglio non somma al totale per {sev}")

    def test_ogni_apparato_porta_il_proprio_perimetro(self):
        # Il rapporto stampa una sezione per apparato e sotto ognuna la riga
        # "Non valutato": deve essere quella di QUEL apparato, non la piu'
        # pessimista del tenant.
        with mock.patch.object(cve_intel, "load", lambda d: _snapshot()), \
             mock.patch.object(cve_intel, "device_services",
                               lambda d: {} if d["IP"] == "192.0.2.10" else {"ssh": True}), \
             mock.patch("services.inventory_manager.get_detected_versions", lambda: {}):
            row = cve_intel.summary(list(self.DEVICES))[0]
        by_ip = {d["ip"]: d["not_evaluated"] for d in row["devices_detail"]}
        self.assertIn("service_state", by_ip["192.0.2.10"])
        self.assertNotIn("service_state", by_ip["192.0.2.11"])
        for scope in by_ip.values():
            self.assertIn("reachability", scope)

    def test_il_dettaglio_porta_la_confidenza_che_spiega_lo_scarto(self):
        heavy = _snapshot("product", [_cve(f"CVE-2024-{i:05d}") for i in range(20)])
        row = self._summary(lambda d: heavy)
        self.assertEqual({"product"}, {d["confidence"] for d in row["devices_detail"]})


class LeRotte(unittest.TestCase):
    """Lo scoping RBAC nasconde i tenant non consentiti, conteggi compresi."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user
        cls.app_server = app_server
        cls.get_current_user = get_current_user
        app_server.app.dependency_overrides[get_current_user] = lambda: {
            "sub": "op", "role": "operator", "groups": ["ACME-CVE-TEST"]}
        cls.client = TestClient(app_server.app)

    @classmethod
    def tearDownClass(cls):
        cls.app_server.app.dependency_overrides.pop(cls.get_current_user, None)

    DEVICES = [
        {"IP": "192.0.2.10", "Group": "ACME-CVE-TEST", "Vendor": "cisco"},
        {"IP": "192.0.2.11", "Group": "BETA-CVE-TEST", "Vendor": "cisco"},
    ]

    def _scoped(self):
        return mock.patch("security.user_manager.get_user_groups",
                          lambda sub: ["ACME-CVE-TEST"])

    def test_il_resoconto_mostra_solo_i_tenant_consentiti(self):
        with self._scoped(), \
             mock.patch("services.inventory_manager.get_all_devices",
                        lambda: list(self.DEVICES)), \
             mock.patch.object(cve_intel, "load", lambda d: {}), \
             mock.patch("services.inventory_manager.get_detected_versions", lambda: {}):
            body = self.client.get("/api/cve/summary").json()
        self.assertEqual(["ACME-CVE-TEST"], [t["tenant"] for t in body["tenants"]])

    def test_la_vista_prioritizzata_porta_il_perimetro_e_ordina(self):
        snap = _snapshot("exact", [_cve("CVE-2024-00001", 4.0, "MEDIUM"),
                                   _cve("CVE-2024-00002", 9.8, "CRITICAL")])
        with self._scoped(), \
             mock.patch("services.inventory_manager.get_all_devices",
                        lambda: list(self.DEVICES)), \
             mock.patch.object(cve_intel, "load",
                               lambda d: snap if d["Group"] == "ACME-CVE-TEST" else {}), \
             mock.patch.object(cve_intel, "device_services", lambda d: {}):
            body = self.client.get("/api/cve/priority").json()
        self.assertEqual(["CVE-2024-00002", "CVE-2024-00001"],
                         [r["id"] for r in body["rows"]])
        self.assertEqual(2, body["total"])
        self.assertTrue(body["not_evaluated"])
        self.assertEqual({"ACME-CVE-TEST"}, {r["tenant"] for r in body["rows"]})

    def test_il_resoconto_rispetta_il_tenant_scelto(self):
        # Il selettore in cima alla pagina non e' decorativo: chiedere un
        # tenant e vedersi rispondere con tutti gli altri e' il modo piu'
        # rapido di leggere i numeri di qualcun altro come i propri.
        admin = lambda: {"sub": "adm", "role": "admin", "groups": []}
        self.app_server.app.dependency_overrides[self.get_current_user] = admin
        try:
            with mock.patch("services.inventory_manager.get_all_devices",
                            lambda: list(self.DEVICES)), \
                 mock.patch.object(cve_intel, "load", lambda d: {}), \
                 mock.patch("services.inventory_manager.get_detected_versions",
                            lambda: {}):
                every = self.client.get("/api/cve/summary").json()
                one = self.client.get(
                    "/api/cve/summary?tenant=BETA-CVE-TEST").json()
        finally:
            self.app_server.app.dependency_overrides[self.get_current_user] = lambda: {
                "sub": "op", "role": "operator", "groups": ["ACME-CVE-TEST"]}
        self.assertEqual(["ACME-CVE-TEST", "BETA-CVE-TEST"],
                         [t["tenant"] for t in every["tenants"]])
        self.assertEqual(["BETA-CVE-TEST"], [t["tenant"] for t in one["tenants"]])

    def test_il_filtro_tenant_non_allarga_mai_lo_scope(self):
        # Chiedere esplicitamente un tenant altrui non lo rende visibile.
        with self._scoped(), \
             mock.patch("services.inventory_manager.get_all_devices",
                        lambda: list(self.DEVICES)), \
             mock.patch.object(cve_intel, "load", lambda d: {}), \
             mock.patch("services.inventory_manager.get_detected_versions", lambda: {}):
            body = self.client.get("/api/cve/summary?tenant=BETA-CVE-TEST").json()
        self.assertEqual([], body["tenants"])

    def test_summary_non_viene_scambiata_per_un_indirizzo_ip(self):
        # /api/cve/{ip} e' dichiarata dopo: se l'ordine si invertisse, questa
        # rotta finirebbe a cercare un apparato chiamato "summary".
        with self._scoped(), \
             mock.patch("services.inventory_manager.get_all_devices", lambda: []), \
             mock.patch("services.inventory_manager.get_detected_versions", lambda: {}):
            r = self.client.get("/api/cve/summary")
        self.assertEqual(200, r.status_code)
        self.assertIn("tenants", r.json())


class LEtaRipiegaSulBackup(unittest.TestCase):
    """`seen_at` e' nato con questa scheda: le voci precedenti non lo hanno."""

    DEVICE = {"IP": "192.0.2.10", "Group": "ACME-CVE-FALLBACK", "Vendor": "cisco"}

    def _refresh(self):
        def fake_get(url, params=None, **kw):
            if (params or {}).get("resultsPerPage") == "1":
                return _Resp({"totalResults": 0})
            return _Resp({"vulnerabilities": []})

        with mock.patch.object(cve_intel.requests, "get", fake_get):
            return cve_intel.refresh(self.DEVICE)

    def test_senza_seen_at_si_usa_la_data_dell_ultimo_backup(self):
        # Versione e configurazione si leggono nello stesso giro, quindi la
        # data del backup e' la stessa data: meglio di una colonna che dice
        # "ignoto" finche' ogni apparato non e' stato ri-analizzato.
        with mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: {"192.0.2.10": {"version": "15.2(7)E"}}), \
             mock.patch("services.config_drift.history.last_seen_at",
                        lambda d: "20260901T083000.000000Z"):
            snap = self._refresh()
        self.assertEqual("20260901T083000.000000Z", snap["version_seen_at"])

    def test_un_seen_at_vero_ha_la_precedenza_sul_ripiego(self):
        with mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: {"192.0.2.10": {"version": "15.2(7)E",
                                                "seen_at": "20260908T120000.000000Z"}}), \
             mock.patch("services.config_drift.history.last_seen_at",
                        lambda d: "20260901T083000.000000Z"):
            snap = self._refresh()
        self.assertEqual("20260908T120000.000000Z", snap["version_seen_at"])

    def test_senza_ne_l_uno_ne_l_altro_resta_ignoto(self):
        with mock.patch("services.inventory_manager.get_detected_versions",
                        lambda: {"192.0.2.10": {"version": "15.2(7)E"}}), \
             mock.patch("services.config_drift.history.last_seen_at", lambda d: ""):
            snap = self._refresh()
        self.assertEqual("", snap["version_seen_at"])


class IlResocontoSiPuoConsegnare(unittest.TestCase):
    """PDF ed esplicitazione del metodo: la scheda esce dall'applicazione."""

    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "templates", "dashboard.html"),
                  encoding="utf-8") as fh:
            cls.html = fh.read()
        with open(os.path.join(root, "static", "js", "threat-intel.js"),
                  encoding="utf-8") as fh:
            cls.js = fh.read()

    def test_il_pulsante_pdf_esiste_ed_e_agganciato(self):
        self.assertIn('id="cveReportPdf"', self.html)
        self.assertIn("async function cveReportPdf", self.js)
        self.assertIn("getElementById('cveReportPdf')?.addEventListener", self.js)

    def test_il_pdf_riusa_la_stampa_gia_esistente(self):
        # Una seconda via di stampa sarebbe una seconda impaginazione da
        # tenere allineata a questa.
        self.assertIn("/api/netsec-audit/report/pdf", self.js)

    def test_il_selettore_del_tenant_esiste_ed_e_agganciato(self):
        self.assertIn('id="cveReportTenant"', self.html)
        self.assertIn("getElementById('cveReportTenant')?.addEventListener", self.js)
        self.assertIn("'/api/cve/summary?tenant='", self.js)

    def _body_of(self, name: str) -> str:
        start = self.js.index(f"function {name}")
        return self.js[start:start + 1500]

    def test_la_riga_del_tenant_si_apre_sul_dettaglio_per_apparato(self):
        self.assertIn('data-action="cve-tenant"', self.js)
        self.assertIn("function cveToggleTenant", self.js)
        self.assertIn("getElementById('cveReportBody')?.addEventListener", self.js)
        # Il dettaglio e' per apparato: e' il singolo apparato a far esplodere
        # il totale, e raggruppare per vendor lo rimescolerebbe con i suoi simili.
        self.assertIn("devices_detail", self.js)

    def test_il_pdf_elenca_le_cve_non_solo_i_conteggi(self):
        # Un rapporto che dice "34 critiche" e non dice QUALI obbliga chi lo
        # riceve a ricominciare da capo.
        self.assertIn("function cvePdfDeviceSection", self.js)
        # Le righe vengono dallo stesso ordinamento della scheda Priorita':
        # il PDF e la schermata non possono mettere in cima due CVE diverse.
        self.assertIn("'/api/cve/priority?limit=", self.js)
        self.assertIn("cvePdfHtml(await cvePdfRows())", self.js)

    def test_il_pdf_e_impaginato_per_apparato(self):
        # Chi riceve il rapporto lavora su un apparato alla volta: una tabella
        # piatta lo obbligava a ricomporre da solo quali CVE fossero sue.
        self.assertIn("function cvePdfDevices", self.js)
        self.assertIn("devices_detail", self.js[self.js.index("function cvePdfDevices"):
                                                self.js.index("function cvePdfDevices") + 400])
        # Le righe arrivano gia' raggruppate tenant -> apparato.
        rows_fn = self.js[self.js.index("async function cvePdfRows"):]
        self.assertIn("t[r.device]", rows_fn[:700])

    def test_la_prima_pagina_porta_i_numeri_col_denominatore(self):
        # "8 con versione" da solo non dice nulla: serve "su 8".
        section = self.js[self.js.index("function cvePdfTenantSection"):]
        section = section[:section.index("function cvePdfIndex")]
        self.assertIn("cveThWithVersion", section)
        self.assertIn("'/ ' + t.devices", section)
        self.assertIn("class=\"kpis\"", section)

    def test_la_prima_pagina_ha_un_indice_degli_apparati(self):
        # In un rapporto impaginato per apparato, l'indice dice da quale
        # cominciare e rende evidente chi domina il totale.
        self.assertIn("function cvePdfIndex", self.js)
        self.assertIn("cvePdfIndexTitle", self.js)

    def test_la_descrizione_sta_sotto_i_dettagli_a_tutta_larghezza(self):
        # In its own column the description took half the page next to five
        # short values: the report ran ~30% more pages than it needed.
        section = self.js[self.js.index("function cvePdfDeviceSection"):]
        section = section[:section.index("function cvePdfDevices")]
        self.assertIn('<tr class="cve-desc"><td colspan="5">', section)
        self.assertNotIn("cveThSummary", section)
        # One tbody per CVE, kept whole: details at the foot of a page with
        # the description on the next one would split a single finding.
        self.assertIn("table.cves tbody { break-inside:avoid", self.js)

    def test_l_indice_porta_alle_sezioni_degli_apparati(self):
        # The index and the sections iterate devices_detail in the same order;
        # both take the anchor from the same function, so they cannot drift.
        index = self.js[self.js.index("function cvePdfIndex"):]
        self.assertIn('href="#${cvePdfAnchor(ti, di)}"', index[:1500])
        devices = self._body_of("cvePdfDevices")
        self.assertIn("cvePdfAnchor(ti, di)", devices)
        self.assertIn('<h3 class="dev-name" id="${anchor}">', self.js)

    def test_un_resoconto_senza_dettaglio_lo_dichiara(self):
        # Mezza pagina bianca si legge come "nessun apparato da segnalare".
        index = self.js[self.js.index("function cvePdfIndex"):]
        self.assertIn("cvePdfNoDetail", index[:900])

    def test_nessuna_descrizione_viene_tagliata_in_js(self):
        # Vale per il PDF e per la scheda. Il taglio del TESTO e' sparito da
        # entrambi; il `slice` che resta e' il tetto sul NUMERO di righe, che
        # e' un'altra cosa e ha la sua riga "e altre N non elencate".
        self.assertNotIn("summary || '').slice(", self.js)
        self.assertEqual(3, self.js.count("escapeHtml(r.summary || '')"))

    def test_nella_gui_il_taglio_e_solo_visivo(self):
        # Il testo intero resta nel DOM: si copia e si trova con la ricerca del
        # browser anche a descrizione chiusa. Tagliarlo in JS faceva il
        # contrario di entrambe le cose.
        self.assertIn('class="cve-desc"', self.js)

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "static", "css", "dashboard.css"),
                  encoding="utf-8") as fh:
            css = fh.read()
        self.assertIn("-webkit-line-clamp", css[css.index(".cve-desc {"):])

    def test_la_descrizione_si_apre_anche_da_tastiera(self):
        # Senza, il testo oltre la seconda riga non esiste per chi non usa
        # il mouse.
        self.assertIn('data-action="cve-desc"', self.js)
        self.assertIn("addEventListener('keydown'", self.js)
        self.assertIn("cve-desc-open", self.js)

    def test_gli_sfondi_non_spariscono_in_stampa(self):
        # Chrome headless li scarta se non glielo si vieta: senza questa riga
        # la barra della severita' esce bianca.
        self.assertIn("print-color-adjust: exact", self.js)

    def test_ogni_apparato_porta_il_suo_perimetro(self):
        # Lo stato dei servizi si sa per un apparato e non per un altro: un
        # perimetro solo aggregato costringerebbe a scrivere sotto ognuno la
        # voce piu' pessimista di tutti.
        section = self.js[self.js.index("function cvePdfDeviceSection"):]
        self.assertIn("cveNotEvaluatedText(d.not_evaluated)", section[:2600])

    def test_la_riga_dell_apparato_si_apre_sulle_sue_cve(self):
        self.assertIn('data-action="cve-device"', self.js)
        self.assertIn("async function cveToggleDevice", self.js)
        self.assertIn("'/api/cve/' + encodeURIComponent(ip)", self.js)

    def test_il_click_sull_apparato_non_richiude_il_tenant(self):
        # I due gestori vivono sulla stessa delega: se il tenant venisse
        # valutato per primo, aprire un apparato chiuderebbe la riga che lo
        # contiene e il pannello sparirebbe sotto il dito.
        listener = self.js[self.js.index("getElementById('cveReportBody')?.addEventListener"):]
        listener = listener[:600]
        self.assertLess(listener.index('cve-device'), listener.index('cve-tenant'))

    def test_il_taglio_arriva_anche_nel_csv_e_nel_pdf(self):
        self.assertIn("'truncated'", self.js)
        self.assertIn("cveTruncatedNote", self.js)

    def test_il_metodo_e_scritto_nella_scheda_e_nel_pdf(self):
        self.assertIn('id="cveReportMethod"', self.html)
        self.assertIn("function cveMethodParagraphs", self.js)
        # Lo stesso testo nelle due uscite: un PDF che spiega i numeri in modo
        # diverso dalla schermata da cui nasce e' peggio di nessuna spiegazione.
        self.assertIn("cveMethodParagraphs()", self._body_of("cveRenderMethod"))
        self.assertIn("cveMethodParagraphs()", self._body_of("cvePdfHtml"))


if __name__ == "__main__":
    unittest.main()
