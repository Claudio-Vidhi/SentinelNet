# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""G1-G3 — una sede si modifica dopo la creazione.

``update_site`` accettava nome, subnet, modalita' e campi del bastione dal
primo giorno; l'unica schermata che li scriveva era il form di creazione.
Cambiare l'indirizzo di un bastione voleva dire una chiamata API a mano.

Il pezzo che NON e' UI: passare a 'agent' lasciava la sede senza token, e
quindi inservibile, perche' ``update_site`` cambia la modalita' e non ne
emette uno. Il token ora si emette nella rotta, non nel browser: cosi' vale
anche per chi chiama l'API direttamente.
"""

import os
import shutil
import subprocess
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_siteedit_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-site-editing")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402

ADMIN, ADMIN_PW = "siteedit_admin", "PasswordSicura1!"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts) -> str:
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class TestSiteEditingApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from security import user_manager
        user_manager.create_user(ADMIN, ADMIN_PW, role="admin")
        cls.client = TestClient(app_server.app)
        r = cls.client.post("/api/auth/login",
                            json={"username": ADMIN, "password": ADMIN_PW})
        assert r.status_code == 200, r.text
        cls.h = {"Authorization": "Bearer " + r.json()["access_token"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP, ignore_errors=True)

    def _create(self, name, mode="central", subnets=None):
        r = self.client.post("/api/sites", headers=self.h,
                             json={"name": name, "mode": mode,
                                   "subnets": subnets or ["10.20.0.0/24"]})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()["site"]["id"]

    def _site(self, site_id):
        r = self.client.get("/api/sites", headers=self.h)
        self.assertEqual(r.status_code, 200, r.text)
        return next(s for s in r.json()["sites"] if s["id"] == site_id)

    def test_name_and_subnets_change_after_creation(self):
        sid = self._create("Prima")
        r = self.client.post("/api/sites/update", headers=self.h,
                             json={"id": sid, "name": "Dopo",
                                   "subnets": ["10.21.0.0/24", "10.22.0.0/24"]})
        self.assertEqual(r.status_code, 200, r.text)
        site = self._site(sid)
        self.assertEqual(site["name"], "Dopo")
        self.assertEqual(site["subnets"], ["10.21.0.0/24", "10.22.0.0/24"])

    def test_switching_to_agent_issues_a_token_once(self):
        sid = self._create("Diventa-Agente")
        self.assertFalse(self._site(sid)["has_token"])
        r = self.client.post("/api/sites/update", headers=self.h,
                             json={"id": sid, "mode": "agent"})
        self.assertEqual(r.status_code, 200, r.text)
        token = r.json().get("token")
        self.assertTrue(token, "nessun token emesso: la sede resta inservibile")
        self.assertTrue(self._site(sid)["has_token"])
        # Mostrato una volta sola: un salvataggio successivo non lo ripete.
        r2 = self.client.post("/api/sites/update", headers=self.h,
                              json={"id": sid, "name": "Diventa-Agente-2"})
        self.assertIsNone(r2.json().get("token"))

    def test_the_issued_token_authenticates_the_agent(self):
        """Un token che non fa entrare l'agente non e' un token."""
        sid = self._create("Agente-Vero")
        r = self.client.post("/api/sites/update", headers=self.h,
                             json={"id": sid, "mode": "agent"})
        token = r.json()["token"]
        hb = self.client.post("/api/agent/heartbeat",
                              headers={"X-Site-Id": sid, "X-Site-Token": token},
                              json={"version": "0.0.0"})
        self.assertEqual(hb.status_code, 200, hb.text)

    def test_switching_to_central_revokes_the_token(self):
        sid = self._create("Torna-Central")
        self.client.post("/api/sites/update", headers=self.h,
                         json={"id": sid, "mode": "agent"})
        self.assertTrue(self._site(sid)["has_token"])
        r = self.client.post("/api/sites/update", headers=self.h,
                             json={"id": sid, "mode": "central"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(self._site(sid)["has_token"])

    def test_a_jump_site_without_a_bastion_is_refused(self):
        sid = self._create("Jump-Incompleto")
        r = self.client.post("/api/sites/update", headers=self.h,
                             json={"id": sid, "mode": "jump"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertEqual(self._site(sid)["mode"], "central")


class TestSiteEditingUi(unittest.TestCase):
    """Il modale e i suoi controlli: id che esistono, azioni delegate, nessun
    handler inline."""

    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "settings.js")

    def test_the_panel_and_its_controls_exist(self):
        for el in ('id="siteWizard"', 'id="swName"', 'id="swSubnets"',
                   'name="swMode"', 'id="swJumpHost"', 'id="swJumpPort"'):
            self.assertIn(el, self.html, el)

    def test_the_row_offers_the_edit_action(self):
        self.assertIn('data-action="edit-site"', self.js)
        self.assertIn("act === 'edit-site'", self.js)

    def test_the_panel_listener_binds_an_id_that_exists(self):
        # getElementById('missing')?.addEventListener raises nothing: it
        # leaves the button silently dead.
        self.assertIn("getElementById('siteWizard')?.addEventListener", self.js)
        self.assertIn('id="siteWizard"', self.html)

    def test_the_panel_goes_through_the_modal_manager(self):
        self.assertIn("createWizard('siteWizard'", self.js)

    def test_a_mode_change_is_explained_before_saving(self):
        self.assertIn("modeChangeWarning(swMode())", self.js)

    def test_the_token_shown_after_the_save_comes_from_the_save(self):
        # Not from a second regenerate-token call: if that one failed the site
        # would be left without a token after a successful save.
        self.assertIn("if (data.token) { showSiteEnrollment(id, data.token)", self.js)




class TestSiteEnrollment(unittest.TestCase):
    """G5 — il token esce insieme al file e ai comandi che lo usano.

    Prima era una stringa nuda in un prompt(): chi installava l'agente doveva
    ricavare agent.json dalla documentazione e incollarci il token a mano,
    nell'unico momento in cui quel token esiste in chiaro."""

    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "settings.js")

    def test_the_enrollment_step_exists(self):
        for el in ('data-step="enroll"', 'id="siteEnrollConfig"',
                   'id="siteEnrollCommands"'):
            self.assertIn(el, self.html, el)

    def test_no_token_is_shown_as_a_bare_string_any_more(self):
        self.assertNotIn("prompt(tr('setSiteTokenShownOnly')", self.js)
        self.assertNotIn("prompt(tr('setNewTokenShownOnly')", self.js)
        # Token-issuing paths: the wizard save (creation AND switch to agent,
        # both answer with data.token) and the regeneration.
        call_sites = (self.js.count("showSiteEnrollment(")
                      - self.js.count("function showSiteEnrollment("))
        self.assertEqual(2, call_sites,
                         "a token-issuing path does not go through the panel")

    def test_the_token_is_written_as_text_not_markup(self):
        self.assertIn("siteEnrollConfig').textContent", self.js)
        self.assertNotIn("siteEnrollConfig').innerHTML", self.js)

    def test_the_listener_binds_an_id_that_exists(self):
        self.assertIn("getElementById('siteWizard')?.addEventListener", self.js)
        self.assertIn("siteWizard.goTo('enroll')", self.js)

    def test_the_config_is_consistent_with_the_token(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        harness = os.path.join(_REPO_ROOT, "tests", "js", "test_site_enrollment.mjs")
        proc = subprocess.run([node, harness], capture_output=True, text=True,
                              cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)


if __name__ == "__main__":
    unittest.main()
