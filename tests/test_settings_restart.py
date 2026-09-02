# -*- coding: utf-8 -*-
"""Riavvio dell'applicazione e generazione del certificato self-signed dalla GUI.

Isola SENTINELNET_DATA_DIR in una dir temporanea PRIMA degli import, come
tests/test_remote_site.py, cosi' non tocca i dati reali.
"""
import os
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_restart_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-settings-restart")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402

ADMIN = "e2e_restart_admin"
ADMIN_PW = "adminpw12345"


class SettingsRestart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app)
        from security import user_manager
        import bcrypt
        users = user_manager.get_users()
        pw_hash = bcrypt.hashpw(ADMIN_PW.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        users[ADMIN] = {"hashed_password": pw_hash, "role": "admin", "disabled": False}
        user_manager._save_users(users)
        r = cls.client.post("/api/auth/login",
                            json={"username": ADMIN, "password": ADMIN_PW})
        assert r.status_code == 200, r.text
        cls.admin_h = {"Authorization": "Bearer " + r.json()["access_token"]}

    def setUp(self):
        # L'endpoint rifiuta quando il processo non e' sotto un supervisore:
        # nel test suite non lo e' mai, quindi si simula la presenza di systemd.
        os.environ["INVOCATION_ID"] = "test-invocation"

    def tearDown(self):
        os.environ.pop("INVOCATION_ID", None)

    def test_the_restart_endpoint_runs_one_fixed_command(self):
        from unittest import mock
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")
            r = self.client.post("/api/settings/restart", headers=self.admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        argv = run.call_args[0][0]
        self.assertEqual(argv, ["sudo", "-n", "systemctl", "start", "--no-block",
                                "sentinelnet-restart.service"])

    def test_a_unit_name_in_the_body_is_ignored(self):
        # Il corpo non deve MAI raggiungere la riga di comando. Se questo test
        # fallisce, l'endpoint e' diventato una shell remota sulla macchina che
        # custodisce le credenziali di ogni sede.
        from unittest import mock
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")
            self.client.post("/api/settings/restart", headers=self.admin_h,
                             json={"unit": "evil.service; rm -rf /"})
        argv = run.call_args[0][0]
        self.assertNotIn("evil.service; rm -rf /", " ".join(argv))

    def test_it_is_admin_only(self):
        # Client dedicato: quello di classe porta il cookie di sessione admin.
        anon = TestClient(app_server.app)
        r = anon.post("/api/settings/restart")
        self.assertIn(r.status_code, (401, 403))

    def test_it_refuses_when_the_app_is_not_supervised(self):
        # Senza supervisore "riavvia" significa solo "termina". Meglio dirlo.
        from unittest import mock
        from routers import settings as settings_router
        with mock.patch.object(settings_router, "_is_supervised", return_value=False):
            r = self.client.post("/api/settings/restart", headers=self.admin_h)
        self.assertEqual(r.status_code, 409, r.text)


class SelfSignedCertificate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = SettingsRestart.client
        cls.admin_h = SettingsRestart.admin_h

    def setUp(self):
        # Ogni test parte senza certificato: la rotta rifiuta di sovrascrivere.
        from core import data_config
        certs = data_config.get_path("certs")
        for name in ("server.crt", "server.key"):
            path = os.path.join(certs, name)
            if os.path.exists(path):
                os.remove(path)

    def test_the_generated_certificate_carries_the_host_in_its_san(self):
        r = self.client.post("/api/settings/tls/self-signed",
                             headers=self.admin_h, json={"host": "192.0.2.10"})
        self.assertEqual(r.status_code, 200, r.text)
        import subprocess
        text = subprocess.run(["openssl", "x509", "-in", r.json()["certfile"],
                               "-noout", "-text"],
                              capture_output=True, text=True).stdout
        self.assertIn("192.0.2.10", text)
        self.assertIn("Subject Alternative Name", text)

    def test_it_refuses_to_overwrite_an_existing_certificate(self):
        # Sovrascrivere il certificato in uso senza chiedere farebbe cadere
        # ogni agente che lo verifica, e non c'e' un undo.
        self.client.post("/api/settings/tls/self-signed",
                         headers=self.admin_h, json={"host": "192.0.2.10"})
        r = self.client.post("/api/settings/tls/self-signed",
                             headers=self.admin_h, json={"host": "192.0.2.10"})
        self.assertEqual(r.status_code, 409, r.text)

    def test_the_host_is_validated_not_interpolated(self):
        r = self.client.post("/api/settings/tls/self-signed", headers=self.admin_h,
                             json={"host": "1.2.3.4/CN=x" + chr(10) + "DNS:evil"})
        self.assertEqual(r.status_code, 400, r.text)


if __name__ == "__main__":
    unittest.main()
