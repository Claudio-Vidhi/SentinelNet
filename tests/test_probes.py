# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit test per il multi-probe: ciclo di vita della coda job e auth agente.

Esegue in una data dir temporanea isolata (SENTINELNET_DATA_DIR) così da non
toccare i dati reali. Avviabile con:  python -m unittest test_probes  oppure
                                       python test_probes.py
"""
import os
import tempfile
import unittest

# Isola i file di stato PRIMA di importare i moduli sotto test.
_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from services import probe_manager  # noqa: E402


class ResetMixin(unittest.TestCase):
    def setUp(self):
        # Stato pulito per ogni test. probes.json è un file JSON non lockato; la
        # coda job SQLite viene svuotata via SQL (su Windows il file .db resta
        # lockato dalle connessioni aperte, quindi non si cancella).
        p = os.path.join(_TMP, "probes.json")
        if os.path.exists(p):
            os.remove(p)
        try:
            probe_manager._init_jobs()
            with probe_manager._connect() as c:
                c.execute("DELETE FROM command_jobs")
        except Exception:
            pass


class TestAgentAuth(ResetMixin):
    def test_default_central_probe_present(self):
        ids = [s["id"] for s in probe_manager.list_probes()]
        self.assertIn("central", ids)

    def test_agent_probe_token_roundtrip(self):
        probe, token = probe_manager.create_probe("Milano", "agent", ["10.0.0.0/24"])
        self.assertIsNotNone(token)
        # Il token in chiaro non è persistito, solo il suo hash.
        self.assertTrue(probe["has_token"])
        self.assertNotIn("token_hash", probe)
        # Autenticazione col token corretto ritorna l'id della sede.
        self.assertEqual(probe_manager.authenticate(token), probe["id"])

    def test_wrong_token_rejected(self):
        probe_manager.create_probe("Roma", "agent", [])
        self.assertIsNone(probe_manager.authenticate("token-sbagliato"))
        self.assertIsNone(probe_manager.authenticate(""))

    def test_central_mode_has_no_token(self):
        probe, token = probe_manager.create_probe("Filiale-Centrale", "central", [])
        self.assertIsNone(token)
        self.assertFalse(probe["has_token"])

    def test_regenerate_token_invalidates_old(self):
        probe, old = probe_manager.create_probe("Torino", "agent", [])
        new = probe_manager.regenerate_token(probe["id"])
        self.assertNotEqual(old, new)
        self.assertIsNone(probe_manager.authenticate(old))
        self.assertEqual(probe_manager.authenticate(new), probe["id"])

    def test_central_default_probe_not_deletable(self):
        self.assertFalse(probe_manager.delete_probe("central"))

    def test_switch_to_central_drops_token(self):
        probe, token = probe_manager.create_probe("Genova", "agent", [])
        probe_manager.update_probe(probe["id"], mode="central")
        self.assertIsNone(probe_manager.authenticate(token))


class TestJobQueueLifecycle(ResetMixin):
    def _probe(self):
        probe, token = probe_manager.create_probe("Napoli", "agent", [])
        return probe["id"], token

    def test_enqueue_creates_pending(self):
        sid, _ = self._probe()
        job = probe_manager.enqueue_job(sid, "192.168.1.10", "show version", "alice")
        self.assertEqual(job["status"], "pending")
        self.assertEqual(job["device_ip"], "192.168.1.10")
        self.assertEqual(job["requested_by"], "alice")

    def test_claim_marks_running_once(self):
        sid, _ = self._probe()
        job = probe_manager.enqueue_job(sid, "10.0.0.1", "show ip int brief")
        claimed = probe_manager.claim_pending_jobs(sid)
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["status"], "running")
        # Un secondo poll non ripropone lo stesso job (già running).
        self.assertEqual(probe_manager.claim_pending_jobs(sid), [])

    def test_complete_job_stores_result(self):
        sid, _ = self._probe()
        job = probe_manager.enqueue_job(sid, "10.0.0.2", "show clock")
        probe_manager.claim_pending_jobs(sid)
        ok = probe_manager.complete_job(job["id"], sid, "done", "12:00 UTC")
        self.assertTrue(ok)
        final = probe_manager.get_job(job["id"])
        self.assertEqual(final["status"], "done")
        self.assertEqual(final["result"], "12:00 UTC")

    def test_complete_rejects_wrong_probe(self):
        sid, _ = self._probe()
        other, _ = probe_manager.create_probe("Bari", "agent", [])
        job = probe_manager.enqueue_job(sid, "10.0.0.3", "show run")
        # Una sede diversa non può chiudere il job di un'altra sede.
        self.assertFalse(probe_manager.complete_job(job["id"], other["id"], "done", "x"))
        self.assertEqual(probe_manager.get_job(job["id"])["status"], "pending")

    def test_error_status_persisted(self):
        sid, _ = self._probe()
        job = probe_manager.enqueue_job(sid, "10.0.0.4", "show foo")
        probe_manager.claim_pending_jobs(sid)
        probe_manager.complete_job(job["id"], sid, "error", "invalid command")
        self.assertEqual(probe_manager.get_job(job["id"])["status"], "error")

    def test_jobs_scoped_per_probe(self):
        sid_a, _ = self._probe()
        sid_b = probe_manager.create_probe("Palermo", "agent", [])[0]["id"]
        probe_manager.enqueue_job(sid_a, "1.1.1.1", "a")
        probe_manager.enqueue_job(sid_b, "203.0.113.2", "b")
        claimed_b = probe_manager.claim_pending_jobs(sid_b)
        self.assertEqual(len(claimed_b), 1)
        self.assertEqual(claimed_b[0]["device_ip"], "203.0.113.2")


if __name__ == "__main__":
    unittest.main()
