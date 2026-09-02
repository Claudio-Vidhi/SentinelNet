# -*- coding: utf-8 -*-
"""Riavvio dell'applicazione e generazione del certificato self-signed dalla GUI.

Isola SENTINELNET_DATA_DIR in una dir temporanea PRIMA degli import, come
tests/test_remote_site.py, cosi' non tocca i dati reali.
"""
import os
import subprocess
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_restart_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-settings-restart")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402

ADMIN = "e2e_restart_admin"
ADMIN_PW = "adminpw12345"


def _admin_client():
    """TestClient gia' autenticato come admin.

    Funzione e non attributo di classe: agganciare una classe all'altra la
    rompeva appena pytest ne selezionava una sola (-k)."""
    from security import user_manager
    import bcrypt
    client = TestClient(app_server.app)
    users = user_manager.get_users()
    pw_hash = bcrypt.hashpw(ADMIN_PW.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users[ADMIN] = {"hashed_password": pw_hash, "role": "admin", "disabled": False}
    user_manager._save_users(users)
    r = client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PW})
    assert r.status_code == 200, r.text
    return client, {"Authorization": "Bearer " + r.json()["access_token"]}


class SettingsRestart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client, cls.admin_h = _admin_client()

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

    def test_on_a_windows_service_it_runs_one_fixed_powershell_command(self):
        # Su Windows non c'e' una unit oneshot: il riavvio lo fa un powershell
        # STACCATO, perche' Restart-Service ferma questo stesso processo e un
        # subprocess.run atteso non tornerebbe mai.
        from unittest import mock
        from routers import settings as settings_router
        with mock.patch.object(settings_router, "_supervisor",
                               return_value="windows-service"),              mock.patch("subprocess.Popen") as popen:
            r = self.client.post("/api/settings/restart", headers=self.admin_h,
                                 json={"unit": "evil; rm -rf /"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["supervisor"], "windows-service")
        argv = popen.call_args[0][0]
        self.assertEqual(argv, ["powershell", "-NoProfile", "-NonInteractive",
                                "-Command", "Restart-Service", "-Name",
                                "SentinelNet"])
        self.assertNotIn("evil", " ".join(argv))

    def test_the_windows_supervisor_is_declared_by_the_service_installer(self):
        # Un servizio Windows non si distingue dall'esterno da un exe lanciato
        # a mano: senza la variabile la rotta deve rifiutare, non indovinare.
        import sys as _sys
        from unittest import mock
        from routers import settings as settings_router
        os.environ.pop("INVOCATION_ID", None)
        with mock.patch.object(_sys, "platform", "win32"):
            self.assertEqual(settings_router._supervisor(), "")
            os.environ["SENTINELNET_WINDOWS_SERVICE"] = "1"
            try:
                self.assertEqual(settings_router._supervisor(), "windows-service")
            finally:
                os.environ.pop("SENTINELNET_WINDOWS_SERVICE", None)

    def test_systemd_wins_when_both_are_declared(self):
        from unittest import mock
        from routers import settings as settings_router
        os.environ["SENTINELNET_WINDOWS_SERVICE"] = "1"
        try:
            with mock.patch.dict(os.environ, {"INVOCATION_ID": "x"}):
                self.assertEqual(settings_router._supervisor(), "systemd")
        finally:
            os.environ.pop("SENTINELNET_WINDOWS_SERVICE", None)

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
        cls.client, cls.admin_h = _admin_client()

    def setUp(self):
        # Ogni test parte senza certificato: la rotta rifiuta di sovrascrivere.
        from core import data_config
        certs = data_config.get_path("certs")
        for name in ("server.crt", "server.key"):
            path = os.path.join(certs, name)
            if os.path.exists(path):
                os.remove(path)

    def test_the_generated_certificate_carries_the_host_in_its_san(self):
        # Verificato con cryptography e non con "openssl x509": il binario non
        # e' garantito su Windows, ed e' proprio la dipendenza da cui la rotta
        # si e' liberata.
        import ipaddress
        from cryptography import x509
        r = self.client.post("/api/settings/tls/self-signed",
                             headers=self.admin_h, json={"host": "192.0.2.10"})
        self.assertEqual(r.status_code, 200, r.text)
        with open(r.json()["certfile"], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertEqual(san.value.get_values_for_type(x509.IPAddress),
                         [ipaddress.ip_address("192.0.2.10")])

    def test_a_dns_host_lands_in_the_san_as_a_dns_name(self):
        # Un nome DNS messo fra gli IP (o viceversa) e' rifiutato da ogni
        # client: sono due tipi di SAN distinti, non una stringa sola.
        from cryptography import x509
        r = self.client.post("/api/settings/tls/self-signed",
                             headers=self.admin_h, json={"host": "sentinelnet.example.com"})
        self.assertEqual(r.status_code, 200, r.text)
        with open(r.json()["certfile"], "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        self.assertEqual(san.value.get_values_for_type(x509.DNSName),
                         ["sentinelnet.example.com"])

    def test_it_needs_no_openssl_binary_on_the_path(self):
        # La rotta chiamava "openssl", che su Windows di norma non esiste e su
        # macOS e' LibreSSL (che rifiuta -addext). Ora il certificato nasce da
        # `cryptography` e il comportamento e' identico su ogni sistema. Resta
        # un solo sottoprocesso possibile, icacls, che irrigidisce le ACL della
        # chiave su Windows: quello si lascia passare.
        from unittest import mock
        calls = []
        real_run = subprocess.run

        def _spy(argv, *a, **kw):
            calls.append(argv)
            return real_run(argv, *a, **kw)

        with mock.patch("subprocess.run", side_effect=_spy):
            r = self.client.post("/api/settings/tls/self-signed",
                                 headers=self.admin_h, json={"host": "192.0.2.10"})
        self.assertEqual(r.status_code, 200, r.text)
        for argv in calls:
            self.assertNotIn("openssl", str(argv[0]).lower())

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
                             json={"host": "192.0.2.4/CN=x" + chr(10) + "DNS:evil"})
        self.assertEqual(r.status_code, 400, r.text)


class AgentIsLinuxOnlyAndSaysSo(unittest.TestCase):
    """La piattaforma dell'agente e' una promessa, non un dettaglio.

    docs/remote-sites.md conteneva istruzioni NSSM per installare l'agente
    come servizio Windows: chi le seguiva otteneva un agente di cui la
    dashboard non sa leggere il log ne' fare il riavvio. Questi test tengono
    ferma la dichiarazione, e impediscono che quelle istruzioni tornino.
    """

    @staticmethod
    def _read(*parts):
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]
        return root.joinpath(*parts).read_text(encoding="utf-8")

    def test_remote_sites_states_the_agent_is_linux_only(self):
        doc = self._read("docs", "remote-sites.md")
        self.assertIn("## Supported platforms", doc)
        self.assertIn("site agent runs on Linux only", doc)
        self.assertIn("not on the" + chr(10) + "roadmap", doc)

    def test_no_document_explains_how_to_install_the_agent_on_windows(self):
        # La riga NSSM sopravvissuta e' quella del CENTRALE, in hardening.md,
        # che su Windows e' supportato: si distingue dal nome del servizio.
        doc = self._read("docs", "remote-sites.md")
        self.assertNotIn("nssm install", doc.lower())
        self.assertNotIn("SentinelNetAgent", doc)

    def test_the_readme_says_which_part_may_run_on_windows(self):
        readme = self._read("README.md")
        self.assertIn("site agent is Linux-only", readme)

    def test_the_agent_module_says_it_in_its_own_docstring(self):
        # Chi apre il file per portarlo su Windows deve leggerlo li', non
        # scoprirlo dal primo journalctl che fallisce.
        from services import site_agent
        self.assertIn("LINUX SOLTANTO", site_agent.__doc__ or "")


if __name__ == "__main__":
    unittest.main()
