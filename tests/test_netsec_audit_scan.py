# -*- coding: utf-8 -*-
"""Test dell'endpoint /api/netsec-audit/scan.

Copre il caso in cui non c'e' nulla da analizzare. Il motore, ricevendo una
configurazione vuota, non trova violazioni e restituisce un punteggio alto
(80% / GRADE A sul benchmark CIS): un esito inventato e pericolosamente
rassicurante. L'endpoint deve rifiutare la richiesta invece di produrlo.
"""

import os
import tempfile
import unittest

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_auditscan_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP_DATA_DIR

import app_server  # noqa: E402
from core import db  # noqa: E402
from security import user_manager  # noqa: E402
from services import netsec_audit  # noqa: E402

PASS = "PasswordSicura1!"
CSRF = {"X-Requested-With": "SentinelNet"}


class TestNetSecAuditScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.stop_writer()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db.get_db_path() + suffix)
            except OSError:
                pass
        db.migrate()
        try:
            user_manager.create_user("adm_audit", PASS, role="admin", groups=None)
        except Exception:
            pass

    def _client(self):
        c = TestClient(app_server.app)
        r = c.post("/api/auth/login",
                   json={"username": "adm_audit", "password": PASS})
        assert r.status_code == 200, r.text
        return c

    def test_empty_config_is_not_assessable(self):
        """Perche' la guardia nell'endpoint esiste ancora.

        Storia di questo test: con il vecchio motore una config vuota otteneva
        80% / GRADE A, perche' l'assenza di violazioni rilevabili valeva PASS.
        La guardia serviva a impedire quel punteggio inventato.

        Il motore parsato non ha piu' quel difetto: ogni controllo diventa
        UNKNOWN e il punteggio non e' determinabile. La guardia resta comunque
        giustificata, ma per una ragione diversa: restituire una schermata di
        controlli tutti 'non valutabili' non aiuta l'utente, un errore
        esplicito si'. Il test ora fissa il comportamento nuovo, cosi' un
        eventuale ritorno al vecchio (punteggio alto sul nulla) lo rompe.
        """
        res = netsec_audit.run_netsec_audit(config_text="", benchmark="cis")
        self.assertIsNone(res["score"])
        self.assertEqual(res["summary"]["passed"], 0)
        self.assertEqual(res["summary"]["unknown"], res["summary"]["total"])

    def test_scan_without_config_or_device_is_rejected(self):
        c = self._client()
        r = c.post("/api/netsec-audit/scan", headers=CSRF,
                   json={"benchmark": "cis"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertNotIn("score", r.json())

    def test_scan_with_device_all_is_rejected(self):
        """'all' non seleziona alcun backup: la scansione multi-dispositivo non
        e' implementata e non deve degradare in un audit su config vuota."""
        c = self._client()
        r = c.post("/api/netsec-audit/scan", headers=CSRF,
                   json={"benchmark": "cis", "device_ip": "all"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertNotIn("score", r.json())

    def test_scan_with_blank_config_text_is_rejected(self):
        c = self._client()
        r = c.post("/api/netsec-audit/scan", headers=CSRF,
                   json={"benchmark": "cis", "config_text": "   \n\t  "})
        self.assertEqual(r.status_code, 400, r.text)

    def test_scan_with_unknown_device_is_not_silently_swallowed(self):
        """Un dispositivo inesistente deve dare errore, non un audit vuoto."""
        c = self._client()
        r = c.post("/api/netsec-audit/scan", headers=CSRF,
                   json={"benchmark": "cis", "device_ip": "10.255.255.254"})
        self.assertIn(r.status_code, (400, 404), r.text)
        self.assertNotIn("score", r.json())

    def test_scan_with_real_config_returns_result(self):
        c = self._client()
        cfg = "config system global\n    set admintimeout 5\nend\n"
        r = c.post("/api/netsec-audit/scan", headers=CSRF,
                   json={"benchmark": "cis", "config_text": cfg})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertIn("score", body)
        self.assertTrue(body["rules"])


class TestAuditEngineResults(unittest.TestCase):
    def _cfg(self, name):
        import os
        p = os.path.join(os.path.dirname(__file__), "fixtures", name)
        with open(p, encoding="utf-8") as fh:
            return fh.read()

    def test_violations_config_scores_low_and_cites_lines(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_violations.conf"),
            benchmark="cis")
        self.assertIsNotNone(res["score"])
        self.assertLess(res["score"], 50)
        failing = [r for r in res["rules"] if r["status"] == "FAIL"]
        self.assertTrue(failing)
        for r in failing:
            self.assertTrue(r["evidence"], "%s senza evidenza" % r["id"])
            for e in r["evidence"]:
                self.assertIn("line", e)
                self.assertIn("context", e)

    def test_clean_config_scores_full(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_clean.conf"), benchmark="cis")
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["summary"]["failed"], 0)

    def test_partial_config_reports_unknown_not_pass(self):
        """Regressione: prima una sezione assente valeva PASS e gonfiava il voto."""
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_partial.conf"), benchmark="cis")
        self.assertGreater(res["summary"]["unknown"], 0)
        for r in res["rules"]:
            if r["status"] == "UNKNOWN":
                self.assertEqual(r["evidence"], [])

    def test_all_benchmarks_run(self):
        for bench in ("cis", "nist", "pci"):
            res = netsec_audit.run_netsec_audit(
                config_text=self._cfg("fortigate_violations.conf"),
                benchmark=bench)
            self.assertEqual(res["benchmark"], bench)
            self.assertTrue(res["rules"])

    def test_unknown_benchmark_falls_back_to_cis(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_clean.conf"), benchmark="nope")
        self.assertEqual(res["benchmark"], "cis")

    def test_summary_keys_present(self):
        res = netsec_audit.run_netsec_audit(
            config_text=self._cfg("fortigate_clean.conf"))
        for key in ("total", "passed", "failed", "warned", "unknown"):
            self.assertIn(key, res["summary"])

    def test_empty_config_no_longer_scores_high(self):
        """Il difetto originale: una config vuota otteneva 80% / GRADE A perche'
        l'assenza di violazioni rilevabili valeva PASS. Ora ogni controllo e'
        UNKNOWN e il punteggio non e' determinabile."""
        res = netsec_audit.run_netsec_audit(config_text="", benchmark="cis")
        self.assertIsNone(res["score"])
        self.assertEqual(res["summary"]["passed"], 0)
        self.assertEqual(res["summary"]["unknown"], res["summary"]["total"])

    def test_shared_evaluations_agree_across_benchmarks(self):
        """TLS e' citata da CIS-03 e NIST-03, any-any da CIS-02 e PCI-02,
        syslog da NIST-04 e PCI-04: una sola implementazione, quindi gli esiti
        non possono divergere sulla stessa configurazione."""
        cfg = self._cfg("fortigate_violations.conf")
        def status(bench, rid):
            for r in netsec_audit.run_netsec_audit(
                    config_text=cfg, benchmark=bench)["rules"]:
                if r["id"] == rid:
                    return r["status"]
            self.fail("regola %s assente in %s" % (rid, bench))
        self.assertEqual(status("cis", "AUD-CIS-03"), status("nist", "AUD-NIST-03"))
        self.assertEqual(status("cis", "AUD-CIS-02"), status("pci", "AUD-PCI-02"))
        self.assertEqual(status("nist", "AUD-NIST-04"), status("pci", "AUD-PCI-04"))


if __name__ == "__main__":
    unittest.main()
