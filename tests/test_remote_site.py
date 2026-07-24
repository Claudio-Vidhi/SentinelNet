# -*- coding: utf-8 -*-
"""Test end-to-end che SIMULA una sede remota (Mode B / agent) contro il
centrale reale, via FastAPI TestClient (nessun processo o rete esterni).

Copre l'intero protocollo agente:
  1. l'admin crea una sede 'agent' e ottiene il token (mostrato una volta);
  2. l'agente si autentica col token (X-Site-Token) e manda un heartbeat;
  3. l'agente spinge il proprio inventario locale -> compare nel centrale,
     taggato con la sede;
  4. l'agente spinge una MAC-table -> storicizzata con attribuzione alla sede;
  5. l'admin accoda un comando CLI per un device della sede (relay);
  6. l'agente preleva il job in polling, lo esegue (qui simulato) e posta il
     risultato; l'admin lo rilegge come 'done';
  7. token errato / job di un'altra sede vengono rifiutati.

Isola SENTINELNET_DATA_DIR in una dir temporanea PRIMA di importare i moduli,
così non tocca i dati reali.
"""
import os
import tempfile
import unittest

# Isolamento dei file di stato prima degli import dei moduli sotto test.
_TMP = tempfile.mkdtemp(prefix="sentinelnet_remote_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-remote-site")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from collectors import mac_history  # noqa: E402

ADMIN = "admin"
ADMIN_PW = "adminpw12345"          # >= MIN_PASSWORD_LENGTH


class RemoteSiteE2E(unittest.TestCase):
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

    # --- helper ---
    def _create_agent_site(self, name):
        r = self.client.post("/api/sites",
                             json={"name": name, "mode": "agent",
                                   "subnets": ["10.9.0.0/24"]},
                             headers=self.admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        return body["site"]["id"], body["token"]

    @staticmethod
    def _agent_headers(site_id, token):
        return {"X-Site-Id": site_id, "X-Site-Token": token}

    # --- test ---
    def test_password_policy_enforced_server_side(self):
        # La policy password minima è applicata lato server: un admin che crea
        # un utente con password troppo corta riceve 400 (il controllo JS del
        # browser è solo UX ed è aggirabile con una chiamata diretta).
        r = self.client.post("/api/users", headers=self.admin_h,
                            json={"username": "weakling", "password": "short",
                                  "role": "viewer"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("almeno", r.json()["detail"])
        # Con una password conforme l'utente viene creato.
        r = self.client.post("/api/users", headers=self.admin_h,
                            json={"username": "gooduser", "password": "longenough1",
                                  "role": "viewer"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_full_agent_lifecycle(self):
        sid, token = self._create_agent_site("Milano-Remota")
        ah = self._agent_headers(sid, token)

        # 2. heartbeat
        r = self.client.post("/api/agent/heartbeat", headers=ah)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["site_id"], sid)

        # 3. push inventario locale
        r = self.client.post("/api/agent/inventory", headers=ah, json={"devices": [
            {"ip": "10.9.0.2", "vendor": "cisco", "hostname": "acc-sw-milano"},
            {"ip": "10.9.0.3", "vendor": "fortinet", "hostname": "fgt-milano"},
        ]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["updated"], 2)
        # I device compaiono nel centrale, taggati con la sede.
        from services import inventory_manager
        devs = {d["IP"]: d for d in inventory_manager.get_all_devices()}
        self.assertIn("10.9.0.2", devs)
        self.assertEqual(devs["10.9.0.2"].get("Site"), sid)

        # 4. push MAC-table -> storicizzata con attribuzione alla sede
        r = self.client.post("/api/agent/mac", headers=ah, json={"collections": [{
            "switch_ip": "10.9.0.2", "switch_name": "acc-sw-milano",
            "rows": [{"mac": "aa:bb:cc:00:09:02", "vlan": "10",
                      "interface": "GigabitEthernet1/0/1"}],
        }]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertGreaterEqual(r.json()["recorded"], 1)
        sightings = mac_history.search(switch_ip="10.9.0.2")
        self.assertTrue(any(s["site"] == sid for s in sightings))

        # 5. l'admin accoda un comando CLI per il device della sede
        r = self.client.post(f"/api/sites/{sid}/command", headers=self.admin_h,
                            json={"ip": "10.9.0.2", "command": "show version"})
        self.assertEqual(r.status_code, 200, r.text)
        job_id = r.json()["job_id"]

        # 6a. l'agente preleva il job (diventa 'running')
        r = self.client.get("/api/agent/jobs", headers=ah)
        self.assertEqual(r.status_code, 200, r.text)
        jobs = r.json()["jobs"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["id"], job_id)
        self.assertEqual(jobs[0]["command"], "show version")

        # 6b. l'agente posta il risultato (esecuzione SSH simulata)
        r = self.client.post(f"/api/agent/jobs/{job_id}/result", headers=ah,
                            json={"status": "done", "result": "Cisco IOS XE 17.9"})
        self.assertEqual(r.status_code, 200, r.text)

        # 6c. l'admin rilegge l'esito
        r = self.client.get(f"/api/command-jobs/{job_id}", headers=self.admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["status"], "done")
        self.assertIn("17.9", r.json()["result"])

        # Un secondo poll non ripropone il job già servito.
        r = self.client.get("/api/agent/jobs", headers=ah)
        self.assertEqual(r.json()["jobs"], [])

    def test_bad_site_token_rejected(self):
        r = self.client.post("/api/agent/heartbeat",
                            headers={"X-Site-Token": "token-inesistente"})
        self.assertEqual(r.status_code, 401)

    def test_relay_blocks_dangerous_command(self):
        sid, token = self._create_agent_site("Roma-Remota")
        # L'admin BYPASSA la blacklist (M-1): il comando viene accodato.
        r = self.client.post(f"/api/sites/{sid}/command", headers=self.admin_h,
                            json={"ip": "10.9.0.9", "command": "write erase"})
        self.assertEqual(r.status_code, 200, r.text)
        # Un operatore (con blacklist attiva, default) viene invece bloccato.
        r = self.client.post("/api/users", headers=self.admin_h,
                            json={"username": "op_relay", "password": "operatorpw1",
                                  "role": "operator", "groups": []})
        self.assertEqual(r.status_code, 200, r.text)
        # Gli account creati dall'admin devono cambiare password al primo login.
        r = self.client.post("/api/auth/login",
                            json={"username": "op_relay", "password": "operatorpw1"})
        self.assertEqual(r.status_code, 200, r.text)
        op_h = {"Authorization": "Bearer " + r.json()["access_token"]}
        r = self.client.post("/api/auth/change-password", headers=op_h,
                            json={"old_password": "operatorpw1",
                                  "new_password": "operatorpw2"})
        if r.status_code == 200:
            r = self.client.post("/api/auth/login",
                                json={"username": "op_relay", "password": "operatorpw2"})
            op_h = {"Authorization": "Bearer " + r.json()["access_token"]}
        r = self.client.post(f"/api/sites/{sid}/command", headers=op_h,
                            json={"ip": "10.9.0.9", "command": "write erase"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("blacklist", r.json()["detail"].lower())

    def test_job_of_other_site_cannot_be_completed(self):
        sid_a, tok_a = self._create_agent_site("SedeA")
        sid_b, tok_b = self._create_agent_site("SedeB")
        # job per SedeA
        r = self.client.post(f"/api/sites/{sid_a}/command", headers=self.admin_h,
                            json={"ip": "10.9.0.5", "command": "show clock"})
        job_id = r.json()["job_id"]
        # SedeB tenta di chiuderlo col PROPRIO token -> 404 (non è suo)
        r = self.client.post(f"/api/agent/jobs/{job_id}/result",
                            headers=self._agent_headers(sid_b, tok_b),
                            json={"status": "done", "result": "hack"})
        self.assertEqual(r.status_code, 404)

    def test_central_site_has_no_relay(self):
        r = self.client.post("/api/sites/central/command", headers=self.admin_h,
                            json={"ip": "10.9.0.2", "command": "show version"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("agent", r.json()["detail"].lower())

    def test_vm_agent_test_helper_cli(self):
        from scripts import vm_agent_test_helper
        temp_dir = tempfile.mkdtemp(prefix="vm_helper_test_")
        cfg_path = os.path.join(temp_dir, "agent.json")
        data_dir = os.path.join(temp_dir, "agent-data")

        # Test setup subcommand logic
        args_setup = type("Args", (), {
            "central_url": "http://127.0.0.1:8765",
            "site_id": "vm-test-site",
            "token": "dummy-token-123",
            "interval": 10,
            "no_verify_tls": True,
            "data_dir": data_dir,
            "config_output": cfg_path,
        })()

        vm_agent_test_helper.setup_agent(args_setup)
        self.assertTrue(os.path.exists(cfg_path))
        self.assertTrue(os.path.exists(os.path.join(data_dir, "network_hosts.csv")))

        # Test add-device subcommand logic
        args_add = type("Args", (), {
            "ip": "192.168.56.50",
            "hostname": "sw-vm-test",
            "vendor": "cisco",
            "username": "admin",
            "password": "pw",
            "secret": "sec",
            "site_id": "vm-test-site",
            "data_dir": data_dir,
        })()

        vm_agent_test_helper.add_device(args_add)
        with open(os.path.join(data_dir, "network_hosts.csv"), "r", encoding="utf-8") as f:
            csv_content = f.read()
        self.assertIn("192.168.56.50", csv_content)
        self.assertIn("sw-vm-test", csv_content)


if __name__ == "__main__":
    unittest.main()
