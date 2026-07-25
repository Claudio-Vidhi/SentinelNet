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

    def test_empty_config_would_score_high(self):
        """Documenta il motivo della guardia: senza guardia, una config vuota
        produce un punteggio alto invece di un errore."""
        res = netsec_audit.run_netsec_audit(config_text="", benchmark="cis")
        self.assertGreaterEqual(
            res["score"], 50,
            "Se il motore non premia piu' una config vuota la guardia "
            "nell'endpoint puo' essere riconsiderata.")

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


if __name__ == "__main__":
    unittest.main()
