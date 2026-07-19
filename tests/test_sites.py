"""Unit test per il multi-site: ciclo di vita della coda job e auth agente.

Esegue in una data dir temporanea isolata (SENTINELNET_DATA_DIR) così da non
toccare i dati reali. Avviabile con:  python -m unittest test_sites  oppure
                                       python test_sites.py
"""
import os
import tempfile
import unittest

# Isola i file di stato PRIMA di importare i moduli sotto test.
_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from services import site_manager  # noqa: E402


class ResetMixin(unittest.TestCase):
    def setUp(self):
        # Stato pulito per ogni test. sites.json è un file JSON non lockato; la
        # coda job SQLite viene svuotata via SQL (su Windows il file .db resta
        # lockato dalle connessioni aperte, quindi non si cancella).
        p = os.path.join(_TMP, "sites.json")
        if os.path.exists(p):
            os.remove(p)
        try:
            site_manager._init_jobs()
            with site_manager._connect() as c:
                c.execute("DELETE FROM command_jobs")
        except Exception:
            pass


class TestAgentAuth(ResetMixin):
    def test_default_central_site_present(self):
        ids = [s["id"] for s in site_manager.list_sites()]
        self.assertIn("central", ids)

    def test_agent_site_token_roundtrip(self):
        site, token = site_manager.create_site("Milano", "agent", ["10.0.0.0/24"])
        self.assertIsNotNone(token)
        # Il token in chiaro non è persistito, solo il suo hash.
        self.assertTrue(site["has_token"])
        self.assertNotIn("token_hash", site)
        # Autenticazione col token corretto ritorna l'id della sede.
        self.assertEqual(site_manager.authenticate(token), site["id"])

    def test_wrong_token_rejected(self):
        site_manager.create_site("Roma", "agent", [])
        self.assertIsNone(site_manager.authenticate("token-sbagliato"))
        self.assertIsNone(site_manager.authenticate(""))

    def test_central_mode_has_no_token(self):
        site, token = site_manager.create_site("Filiale-Centrale", "central", [])
        self.assertIsNone(token)
        self.assertFalse(site["has_token"])

    def test_regenerate_token_invalidates_old(self):
        site, old = site_manager.create_site("Torino", "agent", [])
        new = site_manager.regenerate_token(site["id"])
        self.assertNotEqual(old, new)
        self.assertIsNone(site_manager.authenticate(old))
        self.assertEqual(site_manager.authenticate(new), site["id"])

    def test_central_default_site_not_deletable(self):
        self.assertFalse(site_manager.delete_site("central"))

    def test_switch_to_central_drops_token(self):
        site, token = site_manager.create_site("Genova", "agent", [])
        site_manager.update_site(site["id"], mode="central")
        self.assertIsNone(site_manager.authenticate(token))


class TestJobQueueLifecycle(ResetMixin):
    def _site(self):
        site, token = site_manager.create_site("Napoli", "agent", [])
        return site["id"], token

    def test_enqueue_creates_pending(self):
        sid, _ = self._site()
        job = site_manager.enqueue_job(sid, "192.168.1.10", "show version", "alice")
        self.assertEqual(job["status"], "pending")
        self.assertEqual(job["device_ip"], "192.168.1.10")
        self.assertEqual(job["requested_by"], "alice")

    def test_claim_marks_running_once(self):
        sid, _ = self._site()
        job = site_manager.enqueue_job(sid, "10.0.0.1", "show ip int brief")
        claimed = site_manager.claim_pending_jobs(sid)
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["status"], "running")
        # Un secondo poll non ripropone lo stesso job (già running).
        self.assertEqual(site_manager.claim_pending_jobs(sid), [])

    def test_complete_job_stores_result(self):
        sid, _ = self._site()
        job = site_manager.enqueue_job(sid, "10.0.0.2", "show clock")
        site_manager.claim_pending_jobs(sid)
        ok = site_manager.complete_job(job["id"], sid, "done", "12:00 UTC")
        self.assertTrue(ok)
        final = site_manager.get_job(job["id"])
        self.assertEqual(final["status"], "done")
        self.assertEqual(final["result"], "12:00 UTC")

    def test_complete_rejects_wrong_site(self):
        sid, _ = self._site()
        other, _ = site_manager.create_site("Bari", "agent", [])
        job = site_manager.enqueue_job(sid, "10.0.0.3", "show run")
        # Una sede diversa non può chiudere il job di un'altra sede.
        self.assertFalse(site_manager.complete_job(job["id"], other["id"], "done", "x"))
        self.assertEqual(site_manager.get_job(job["id"])["status"], "pending")

    def test_error_status_persisted(self):
        sid, _ = self._site()
        job = site_manager.enqueue_job(sid, "10.0.0.4", "show foo")
        site_manager.claim_pending_jobs(sid)
        site_manager.complete_job(job["id"], sid, "error", "invalid command")
        self.assertEqual(site_manager.get_job(job["id"])["status"], "error")

    def test_jobs_scoped_per_site(self):
        sid_a, _ = self._site()
        sid_b = site_manager.create_site("Palermo", "agent", [])[0]["id"]
        site_manager.enqueue_job(sid_a, "1.1.1.1", "a")
        site_manager.enqueue_job(sid_b, "2.2.2.2", "b")
        claimed_b = site_manager.claim_pending_jobs(sid_b)
        self.assertEqual(len(claimed_b), 1)
        self.assertEqual(claimed_b[0]["device_ip"], "2.2.2.2")


if __name__ == "__main__":
    unittest.main()
