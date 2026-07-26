# -*- coding: utf-8 -*-
"""Test di unita' e di integrazione per la Checklist Audit Manutenzione Firewall."""

import os
import tempfile
import unittest
from fastapi.testclient import TestClient

from app_server import app
from core import db
from services import audit_checklist

CSRF = {"X-Requested-With": "SentinelNet"}


class TestAuditChecklist(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.tmp_db.close()
        os.environ["SENTINELNET_DATA_DIR"] = os.path.dirname(cls.tmp_db.name)
        os.environ["SENTINELNET_DB_PATH"] = cls.tmp_db.name

        # Esegue la migrazione DB (v4)
        db.migrate()

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(cls.tmp_db.name)
        except OSError:
            pass

    def test_01_seed_template(self):
        """Verifica il seeding del template v1 e conteggio item."""
        tpl_id = audit_checklist.seed_default_template()
        self.assertGreater(tpl_id, 0)

        tpl = audit_checklist.get_template(tpl_id)
        self.assertIsNotNone(tpl)
        self.assertEqual(tpl["version"], 1)
        self.assertGreaterEqual(len(tpl["items"]), 20)

    def test_02_engagement_lifecycle(self):
        """Verifica la creazione, aggiornamento item e storico dell'engagement."""
        eng = audit_checklist.create_engagement(
            customer_name="Azienda Test Srl",
            onsite_or_remote="onsite",
            interviewee="Mario Rossi (IT Manager)",
        )
        self.assertIsNotNone(eng)
        eng_id = eng["id"]
        self.assertEqual(eng["customer_name"], "Azienda Test Srl")
        self.assertEqual(eng["status"], "draft")

        # Aggiorna valutazione item 1.3 (Prerequisito) -> non_conforme
        eng_updated = audit_checklist.update_item_assessment(
            engagement_id=eng_id,
            item_ref="1.3",
            status="non_conforme",
            severity="alta",
            finding_text="Schema logico di rete non fornito",
            recommendation_text="Richiedere il disegno di rete aggiornato",
        )
        self.assertEqual(eng_updated["status"], "in_progress")

        # Genera relazione HTML e verifica avvertimento prerequisiti
        html_report = audit_checklist.generate_audit_relazione(eng_id)
        self.assertIn("AVVERTIMENTO PREREQUISITI NON SODDISFATTI", html_report)
        self.assertIn("Item 1.3", html_report)

        # Ora imposta tutti i prerequisiti a conforme
        for ref in ["1.3", "1.6", "1.7"]:
            audit_checklist.update_item_assessment(
                engagement_id=eng_id,
                item_ref=ref,
                status="conforme",
                severity="bassa",
            )

        html_report_clean = audit_checklist.generate_audit_relazione(eng_id)
        self.assertNotIn("AVVERTIMENTO PREREQUISITI NON SODDISFATTI", html_report_clean)

    def test_03_api_endpoints_smoke(self):
        """Smoke test degli endpoint FastAPI dell'audit checklist."""
        client = TestClient(app)

        # GET /api/audit-checklist/templates
        res = client.get("/api/audit-checklist/templates")
        self.assertEqual(res.status_code, 200)
        templates = res.json()
        self.assertGreaterEqual(len(templates), 1)

        # POST /api/audit-checklist/engagements
        res = client.post(
            "/api/audit-checklist/engagements",
            json={"customer_name": "Cliente API Test", "onsite_or_remote": "remote"},
            headers=CSRF,
        )
        self.assertEqual(res.status_code, 201)
        eng_data = res.json()
        eng_id = eng_data["id"]

        # GET /api/audit-checklist/engagements/{id}
        res = client.get(f"/api/audit-checklist/engagements/{eng_id}")
        self.assertEqual(res.status_code, 200)

        # PUT /api/audit-checklist/engagements/{id}/items/1.1
        res = client.put(
            f"/api/audit-checklist/engagements/{eng_id}/items/1.1",
            json={
                "status": "conforme",
                "severity": "osservazione",
                "finding_text": "Report precedente esaminato",
            },
            headers=CSRF,
        )
        self.assertEqual(res.status_code, 200)

        # GET /api/audit-checklist/engagements/{id}/report
        res = client.get(f"/api/audit-checklist/engagements/{eng_id}/report")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "text/html; charset=utf-8")
        self.assertIn("Relazione Audit Manutenzione Firewall", res.text)
    def test_04_template_item_crud(self):
        """Aggiunta, modifica ed eliminazione di una domanda del template."""
        tpl_id = audit_checklist.seed_default_template()

        # Un engagement gia' aperto PRIMA che la domanda esista.
        eng_id = audit_checklist.create_engagement(customer_name="Cliente CRUD")["id"]

        audit_checklist.create_template_item(
            tpl_id, "9.99",
            section_no=9, section_title="Sezione di prova",
            title="Domanda aggiunta dall'amministratore",
            guidance_why="Motivazione", severity_default="alta",
            is_prerequisite=True, sort_order=999,
        )
        # Backfill: la domanda deve comparire anche nell'audit gia' aperto.
        refs = [i["item_ref"] for i in audit_checklist.get_engagement(eng_id)["items"]]
        self.assertIn("9.99", refs)

        audit_checklist.update_template_item(tpl_id, "9.99", title="Titolo modificato")
        item = next(i for i in audit_checklist.get_template(tpl_id)["items"] if i["ref"] == "9.99")
        self.assertEqual(item["title"], "Titolo modificato")

        # is_prerequisite del template guida l'avvertimento nella relazione.
        audit_checklist.update_item_assessment(eng_id, "9.99", status="non_conforme")
        self.assertIn(
            "AVVERTIMENTO PREREQUISITI NON SODDISFATTI",
            audit_checklist.generate_audit_relazione(eng_id),
        )

        # Valutata -> non eliminabile.
        with self.assertRaises(PermissionError):
            audit_checklist.delete_template_item(tpl_id, "9.99")

        audit_checklist.update_item_assessment(eng_id, "9.99", status="non_valutato")
        audit_checklist.delete_template_item(tpl_id, "9.99")
        refs = [i["ref"] for i in audit_checklist.get_template(tpl_id)["items"]]
        self.assertNotIn("9.99", refs)
        refs = [i["item_ref"] for i in audit_checklist.get_engagement(eng_id)["items"]]
        self.assertNotIn("9.99", refs)

    def test_05_template_item_endpoints_require_admin(self):
        """Gli endpoint di modifica del template sono riservati agli amministratori."""
        client = TestClient(app)
        tpl_id = audit_checklist.seed_default_template()
        res = client.post(
            f"/api/audit-checklist/templates/{tpl_id}/items",
            json={"ref": "9.98", "section_no": 9, "section_title": "X", "title": "Y"},
            headers=CSRF,
        )
        self.assertIn(res.status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
