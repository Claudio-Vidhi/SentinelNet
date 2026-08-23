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

# Mai "admin": questo setUpClass SOVRASCRIVE l'hash dell'account (non usa
# create_user, che si rifiuterebbe), quindi se l'isolamento della directory
# dati saltasse chiuderebbe fuori l'amministratore vero. Con un nome dedicato
# il danno resta un utente di troppo. Vedi tests/__init__.py.
ADMIN = "e2e_admin"
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

        # 4b. push ARP -> e' cio' che da' un IP ai client della sede. Senza,
        # la MAC table dice a quale porta stanno ma non chi sono, e ogni vista
        # a valle (Client Map, flow path, diagnosi) parte dall'IP.
        r = self.client.post("/api/agent/arp", headers=ah, json={"collections": [{
            "source_ip": "10.9.0.3", "source_name": "fgt-milano",
            "source_type": "firewall",
            "entries": [{"mac": "aa:bb:cc:00:09:02", "ip": "10.9.0.50",
                         "vlan": "10", "interface": "port1"}],
        }]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertGreaterEqual(r.json()["recorded"], 1)
        bindings = mac_history.search_arp(ip="10.9.0.50")
        self.assertTrue(bindings)
        self.assertEqual(bindings[0]["site"], sid)
        self.assertEqual(bindings[0]["source_type"], "firewall")
        # Il binding e la posizione fisica si incontrano: e' il join su cui
        # poggia tutta la Client Map.
        cm = mac_history.client_map(ip="10.9.0.50")
        self.assertEqual(cm[0]["switch_ip"], "10.9.0.2")

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

    def test_csv_import_assigns_the_site(self):
        """La colonna Site veniva letta e buttata via: un inventario esportato
        e reimportato perdeva l'assegnazione alle sedi con agente."""
        sid, _token = self._create_agent_site("Bologna-Remota")
        csv = ("IP,Username,Password,Enable Secret,Hostname,Group,Site,Vendor\n"
               f"192.0.2.77,admin,Pw1!,,sw-bologna,Generale,{sid},cisco\n")
        r = self.client.post("/api/import-csv", headers=self.admin_h,
                             json={"csv_data": csv})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["failed"], [])
        from services import inventory_manager
        dev = next(d for d in inventory_manager.get_all_devices()
                   if d["IP"] == "192.0.2.77" and d.get("Group") == "Generale")
        self.assertEqual(dev["Site"], sid)
        # E il tenant NON e' stato sovrascritto dalla sede.
        self.assertEqual(dev["Group"], "Generale")

    def test_csv_import_refuses_an_unknown_site(self):
        """Una sede si inventa con modalita' e token: crearla al volo qui
        produrrebbe un apparato che nessun agente raccogliera' mai."""
        csv = ("IP,Hostname,Group,Site,Vendor\n"
               "192.0.2.78,sw-fantasma,Generale,sede-inesistente,cisco\n")
        r = self.client.post("/api/import-csv", headers=self.admin_h,
                             json={"csv_data": csv})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(r.json()["failed"]), 1)
        self.assertIn("inesistente", r.json()["failed"][0]["error"])

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

    def test_rest_relay_allowlist(self):
        """L'allowlist E' il confine di autorita': senza, un token di sede
        diventa accesso arbitrario alle API di ogni apparato della sede."""
        from services import site_manager
        for ok in ("monitor/firewall/policy-lookup", "monitor/vpn/ipsec",
                   "monitor/router/ipv4", "log/disk/traffic/forward",
                   "log/memory/traffic/forward"):
            self.assertTrue(site_manager.rest_path_allowed(ok), ok)
        for bad in (
                "cmdb/firewall/policy",              # scrive configurazione
                "monitor/system/config-script/upload",
                "monitor/firewall/../../cmdb/system/admin",
                "https://altrove.example/api/v2/cmdb/system/admin",
                "monitor/system/config/backup",      # esfiltrerebbe la config
                "", "log/disk/traffic/forward/../../cmdb/system/admin"):
            self.assertFalse(site_manager.rest_path_allowed(bad), bad)

    def test_rest_job_outside_allowlist_is_refused_at_enqueue(self):
        from services import site_manager
        sid, _token = self._create_agent_site("Torino-Remota")
        with self.assertRaises(ValueError):
            site_manager.enqueue_job(sid, "10.9.0.3",
                                     '{"path": "cmdb/system/admin"}',
                                     kind="rest")
        # E nessun job resta accodato.
        self.assertEqual(site_manager.list_jobs(sid), [])

    def test_rest_job_reaches_the_agent_with_its_kind(self):
        from services import site_manager
        sid, token = self._create_agent_site("Genova-Remota")
        ah = self._agent_headers(sid, token)
        job = site_manager.enqueue_job(
            sid, "10.9.0.3",
            '{"path": "monitor/firewall/policy-lookup", "params": {"srcip": "10.9.0.50"}}',
            kind="rest")
        r = self.client.get("/api/agent/jobs", headers=ah)
        self.assertEqual(r.status_code, 200, r.text)
        jobs = [j for j in r.json()["jobs"] if j["id"] == job["id"]]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["kind"], "rest")

    def test_agent_refuses_a_path_central_should_not_have_sent(self):
        """Doppio controllo voluto: le credenziali restano nella sede anche se
        il centrale e' compromesso, quindi l'agente non si fida di cio' che
        gli viene dettato."""
        from services.site_agent import Agent
        agent = Agent.__new__(Agent)   # nessuna connessione, nessuna config
        out = agent._execute_rest_job({"IP": "10.9.0.3"},
                                      '{"path": "cmdb/system/admin"}')
        self.assertEqual(out["status"], "error")
        self.assertIn("non consentito", out["result"])

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
            "central_url": "http://127.0.0.1:8000",
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

    def test_vendor_typo_normalization(self):
        from services import inventory_manager
        from core import core_engine
        self.assertEqual(inventory_manager.normalize_vendor("fotinet"), "fortinet")
        self.assertEqual(inventory_manager.normalize_vendor("fortigate"), "fortinet")
        self.assertEqual(inventory_manager.normalize_vendor("palo_alto"), "paloalto")
        cls, _ = core_engine.resolve_driver("fotinet")
    def test_agent_syslog_relay(self):
        from services import site_manager
        site_obj, token = site_manager.create_site("Syslog Sede", "agent")
        site_id = site_obj["id"]
        headers = {"X-Site-Token": token, "X-Site-Id": site_id}

        # Test POST /api/agent/syslog
        payload = {
            "events": [
                {
                    "ts": 1700000000,
                    "src_ip": "192.168.1.10",
                    "raw": "<134>1 2026-07-24T15:00:00Z fgt_test - - - Test Syslog Message"
                }
            ]
        }
        res = self.client.post("/api/agent/syslog", json=payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "success")
        self.assertGreaterEqual(res.json()["ingested"], 1)

        # Test SyslogCollector UDP listener
        from services.site_agent import SyslogCollector
        import socket, time
        collector = SyslogCollector(port=15514)
        collector.start()
        time.sleep(0.1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"<13>Test UDP Syslog Packet", ("127.0.0.1", 15514))
        time.sleep(0.2)
        collector.running = False
        items = collector.drain()
        self.assertGreaterEqual(len(items), 1)
    def test_agent_remote_management_rpc(self):
        from services import site_manager
        site_obj, token = site_manager.create_site("RPC Sede", "agent")
        site_id = site_obj["id"]

        # Enqueue self update & restart endpoints
        res_up = self.client.post(f"/api/sites/{site_id}/agent/update", headers=self.admin_h)
        self.assertEqual(res_up.status_code, 200)
        self.assertEqual(res_up.json()["status"], "queued")

        res_rst = self.client.post(f"/api/sites/{site_id}/agent/restart", headers=self.admin_h)
        self.assertEqual(res_rst.status_code, 200)
        self.assertEqual(res_rst.json()["status"], "queued")

        # Test agent _execute_agent_rpc handler
        from services.site_agent import Agent
        cfg = {"central_url": "http://127.0.0.1:8000", "site_id": site_id, "token": token, "syslog_enabled": False}
        agent_inst = Agent(cfg)
        rpc_out = agent_inst._execute_agent_rpc("_agent_self_update")
        self.assertIn("status", rpc_out)
        self.assertIn("git pull", rpc_out["result"])

        # Enqueue inventory get & save endpoints
        res_inv_get = self.client.post(f"/api/sites/{site_id}/agent/inventory/get", headers=self.admin_h)
        self.assertEqual(res_inv_get.status_code, 200)

        res_inv_save = self.client.post(f"/api/sites/{site_id}/agent/inventory/save", json={"content": "IP,Vendor\n10.0.1.1,cisco"}, headers=self.admin_h)
        self.assertEqual(res_inv_save.status_code, 200)

        # Test agent _agent_get_inventory and _agent_save_inventory RPC handlers
        rpc_inv_get = agent_inst._execute_agent_rpc("_agent_get_inventory")
        self.assertEqual(rpc_inv_get["status"], "done")

        rpc_inv_save = agent_inst._execute_agent_rpc("_agent_save_inventory IP,Vendor\n10.0.1.1,cisco")
        self.assertEqual(rpc_inv_save["status"], "done")

    def test_agent_saved_inventory_is_readable_by_the_parser(self):
        """L'editor remoto scriveva il CSV verbatim: nessuno verificava che il
        file risultante fosse poi leggibile. Un foglio Excel italiano (punto e
        virgola) e una colonna 'Tenant' al posto di 'Group' bastavano a mandare
        ogni apparato nel gruppo sbagliato o a far esplodere get_all_devices()
        con KeyError: 'IP'."""
        from services import inventory_manager, site_manager
        from services.site_agent import Agent

        site_obj, token = site_manager.create_site("Conformita Sede", "agent")
        agent_inst = Agent({"central_url": "http://127.0.0.1:8000",
                            "site_id": site_obj["id"], "token": token,
                            "syslog_enabled": False})

        out = agent_inst._execute_agent_rpc(
            "_agent_save_inventory ﻿Indirizzo;Marca;Nome;Tenant\n"
            "192.0.2.77;cisco;switch-77;Tenant_Milano\n")
        self.assertEqual("done", out["status"], out["result"])

        devices = inventory_manager.get_all_devices()
        row = next((d for d in devices if d.get("IP") == "192.0.2.77"), None)
        self.assertIsNotNone(row, devices)
        self.assertEqual("switch-77", row["Hostname"])
        self.assertEqual("Tenant_Milano", row["Group"])   # non 'Generale'
        self.assertEqual("cisco", row["Vendor"])

        # Un salvataggio senza contenuto azzerava il file: ora e' un errore e
        # l'inventario resta quello di prima.
        empty = agent_inst._execute_agent_rpc("_agent_save_inventory")
        self.assertEqual("error", empty["status"])
        self.assertEqual(len(devices), len(inventory_manager.get_all_devices()))

    def test_inventory_save_endpoint_rejects_unreadable_csv(self):
        """Il 400 arriva subito: prima il CSV illeggibile veniva accodato e
        falliva sull'agente, dentro il risultato di un job."""
        from services import site_manager
        site_obj, _ = site_manager.create_site("Validazione Sede", "agent")
        res = self.client.post(
            f"/api/sites/{site_obj['id']}/agent/inventory/save",
            json={"content": "Nome,Vendor\nswitch-01,cisco"}, headers=self.admin_h)
        self.assertEqual(400, res.status_code)
        self.assertIn("IP", res.json()["detail"])


if __name__ == "__main__":
    unittest.main()
