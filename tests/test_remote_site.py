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

    def test_backup_interval_round_trips_through_the_heartbeat(self):
        from services import site_manager
        sid, token = self._create_agent_site("Backup-Interval")
        ah = self._agent_headers(sid, token)
        r = self.client.post("/api/agent/heartbeat", headers=ah,
                             json={"backup_interval": 900})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(site_manager.get_site(sid)["backup_interval"], 900)

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

    def test_agent_status_push_updates_the_central_state(self):
        sid, token = self._create_agent_site("Status-Push")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={"devices": [
            {"ip": "10.9.0.20", "vendor": "cisco", "hostname": "switch-01"},
            {"ip": "10.9.0.21", "vendor": "cisco", "hostname": "switch-02"},
        ]})

        r = self.client.post("/api/agent/status", headers=ah, json={"devices": [
            {"ip": "10.9.0.20", "up": True},
            {"ip": "10.9.0.21", "up": False},
        ]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["updated"], 2)

        from services import inventory_manager
        versions = inventory_manager.get_detected_versions()
        self.assertEqual(versions["10.9.0.20"]["status"], "online")
        self.assertEqual(versions["10.9.0.21"]["status"], "offline")

    def test_agent_status_push_uses_the_inventorys_real_vendor(self):
        # A device with no prior detected_versions entry used to fall back
        # to "cisco" even though the inventory scan just above already
        # knows its real vendor.
        sid, token = self._create_agent_site("Status-Vendor")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={"devices": [
            {"ip": "10.9.0.22", "vendor": "fortinet", "hostname": "fgt-01"},
        ]})

        r = self.client.post("/api/agent/status", headers=ah,
                             json={"devices": [{"ip": "10.9.0.22", "up": True}]})
        self.assertEqual(r.status_code, 200, r.text)

        from services import inventory_manager
        self.assertEqual(
            inventory_manager.get_detected_versions()["10.9.0.22"]["vendor"], "fortinet")

    def test_agent_status_push_cannot_touch_another_sites_device(self):
        # One site's token must never write another site's state: the agent
        # job feed is already over-broad (docs/remote-sites.md), and the
        # write path must not inherit that.
        sid_a, token_a = self._create_agent_site("Status-A")
        sid_b, token_b = self._create_agent_site("Status-B")
        self.client.post("/api/agent/inventory",
                         headers=self._agent_headers(sid_b, token_b),
                         json={"devices": [{"ip": "10.9.0.30", "vendor": "cisco"}]})

        r = self.client.post("/api/agent/status",
                             headers=self._agent_headers(sid_a, token_a),
                             json={"devices": [{"ip": "10.9.0.30", "up": True}]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["updated"], 0)

        from services import inventory_manager
        self.assertNotIn("10.9.0.30", inventory_manager.get_detected_versions())

    def test_agent_backup_push_lands_in_backup_config_and_versions(self):
        sid, token = self._create_agent_site("Backup-Push")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={"devices": [
            {"ip": "10.9.0.40", "vendor": "cisco", "hostname": "switch-01"},
        ]})

        r = self.client.post("/api/agent/backup", headers=ah, json={
            "ip": "10.9.0.40", "hostname": "switch-01", "vendor": "cisco",
            "version": "15.2(7)E2", "serial": "ABC1234DEFG",
            "config": "hostname switch-01\n!\nend\n",
        })
        self.assertEqual(r.status_code, 200, r.text)

        saved = r.json()["file"]
        self.assertTrue(os.path.exists(saved))
        with open(saved, encoding="utf-8") as f:
            self.assertIn("hostname switch-01", f.read())

        from services import inventory_manager
        entry = inventory_manager.get_detected_versions()["10.9.0.40"]
        self.assertEqual(entry["status"], "online")
        self.assertEqual(entry["version"], "15.2(7)E2")

    def test_agent_backup_push_populates_config_drift(self):
        # b9ecd63-era gap: a central-poll triage records drift history, an
        # agent-site push did not, so the Config Drift tab stayed empty.
        sid, token = self._create_agent_site("Drift-Push")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={"devices": [
            {"ip": "10.9.0.45", "vendor": "cisco", "hostname": "switch-05"},
        ]})

        r = self.client.post("/api/agent/backup", headers=ah, json={
            "ip": "10.9.0.45", "hostname": "switch-05", "vendor": "cisco",
            "version": "15.2(7)E2", "serial": "",
            "config": "hostname switch-05\n!\nend\n",
        })
        self.assertEqual(r.status_code, 200, r.text)

        from services import inventory_manager
        from services.config_drift import history
        device = next(d for d in inventory_manager.get_all_devices()
                     if d["IP"] == "10.9.0.45")
        versions = history.list_versions(device)
        self.assertTrue(versions, "config drift history vuota per la sede agent")

    def test_an_empty_config_is_refused_without_overwriting_a_good_backup(self):
        # A partial or empty push must never overwrite a good stored config.
        sid, token = self._create_agent_site("Backup-Empty")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.47", "vendor": "cisco"}]})

        good = self.client.post("/api/agent/backup", headers=ah, json={
            "ip": "10.9.0.47", "hostname": "switch-08", "vendor": "cisco",
            "version": "15.2(7)E2", "serial": "",
            "config": "hostname switch-08\n!\nend\n",
        })
        self.assertEqual(good.status_code, 200, good.text)
        saved = good.json()["file"]
        with open(saved, encoding="utf-8") as f:
            good_text = f.read()

        for empty in ("", "   \n\t  "):
            r = self.client.post("/api/agent/backup", headers=ah, json={
                "ip": "10.9.0.47", "hostname": "switch-08", "vendor": "cisco",
                "version": "15.2(7)E2", "serial": "", "config": empty,
            })
            self.assertEqual(r.status_code, 400, r.text)

        with open(saved, encoding="utf-8") as f:
            self.assertEqual(f.read(), good_text)

    def test_an_oversized_config_is_refused_without_writing(self):
        # Truncating is worse than refusing: config drift would report a
        # spurious change and the model classifier would read half a file.
        sid, token = self._create_agent_site("Backup-Huge")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.41", "vendor": "cisco"}]})

        r = self.client.post("/api/agent/backup", headers=ah, json={
            "ip": "10.9.0.41", "hostname": "switch-02", "vendor": "cisco",
            "version": "1.0", "serial": "",
            "config": "x" * (5 * 1024 * 1024 + 1),
        })
        self.assertEqual(r.status_code, 413, r.text)
        from services import inventory_manager
        self.assertNotIn("10.9.0.41", inventory_manager.get_detected_versions())

    def test_agent_backup_push_carries_model_and_serial(self):
        # push_backup used to hardcode serial "" and run_backup_and_triage
        # never returned model/serial at all, so the model-based classifier
        # never received its input for an agent-site device.
        sid, token = self._create_agent_site("Model-Serial-Push")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.46", "vendor": "cisco", "hostname": "switch-06"}]})

        r = self.client.post("/api/agent/backup", headers=ah, json={
            "ip": "10.9.0.46", "hostname": "switch-06", "vendor": "cisco",
            "version": "15.2(7)E2", "model": "WS-C2960X-24", "serial": "FDO12345678",
            "config": "hostname switch-06\n!\nend\n",
        })
        self.assertEqual(r.status_code, 200, r.text)

        from services import inventory_manager
        entry = inventory_manager.get_detected_versions()["10.9.0.46"]
        self.assertEqual(entry.get("model"), "WS-C2960X-24")
        self.assertEqual(entry.get("serial"), "FDO12345678")

    def test_backup_push_cannot_target_another_sites_device(self):
        sid_a, token_a = self._create_agent_site("Backup-A")
        sid_b, token_b = self._create_agent_site("Backup-B")
        self.client.post("/api/agent/inventory",
                         headers=self._agent_headers(sid_b, token_b),
                         json={"devices": [{"ip": "10.9.0.42", "vendor": "cisco"}]})

        r = self.client.post("/api/agent/backup",
                             headers=self._agent_headers(sid_a, token_a),
                             json={"ip": "10.9.0.42", "hostname": "switch-03",
                                   "vendor": "cisco", "version": "1.0",
                                   "serial": "", "config": "end\n"})
        self.assertEqual(r.status_code, 404, r.text)

    def test_the_job_queue_accepts_a_triage_kind(self):
        from services import site_manager
        sid, _token = self._create_agent_site("Triage-Kind")
        job = site_manager.enqueue_job(sid, "10.9.0.65", "", requested_by=ADMIN,
                                       kind="triage")
        self.assertEqual(job["kind"], "triage")
        with self.assertRaises(ValueError):
            site_manager.enqueue_job(sid, "10.9.0.65", "", kind="nonsense")

    def test_triage_on_an_agent_device_is_queued_not_refused(self):
        # b9ecd63 made the direct path refuse. The operator-visible answer is
        # now "queued": the agent runs it and pushes the result back.
        from services import site_manager
        sid, token = self._create_agent_site("Triage-Queue")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.70", "vendor": "cisco",
                         "hostname": "switch-01", "group": "Generale"}]})

        r = self.client.post("/api/run-triage", headers=self.admin_h,
                             json={"group": "Generale"})
        self.assertEqual(r.status_code, 200, r.text)

        jobs = site_manager.list_jobs(sid)
        self.assertTrue(any(j["device_ip"] == "10.9.0.70" and j["kind"] == "triage"
                            for j in jobs), jobs)


    def test_ping_check_does_not_overwrite_the_status_the_agent_just_pushed(self):
        # has_direct_path is False for an agent site, so ping_check's own
        # probe returns None (not measurable). Writing "unknown" over that
        # would erase the real online/offline the agent pushed moments ago.
        sid, token = self._create_agent_site("Ping-No-Overwrite")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.80", "vendor": "cisco",
                        "hostname": "switch-01", "group": "Generale"}]})
        self.client.post("/api/agent/status", headers=ah,
                         json={"devices": [{"ip": "10.9.0.80", "up": True}]})

        from services import inventory_manager
        self.assertEqual(
            inventory_manager.get_detected_versions()["10.9.0.80"]["status"], "online")

        r = self.client.post("/api/ping-check", headers=self.admin_h,
                             json={"group": "Generale"})
        self.assertEqual(r.status_code, 200, r.text)

        self.assertEqual(
            inventory_manager.get_detected_versions()["10.9.0.80"]["status"], "online")

    def test_ping_single_does_not_overwrite_the_status_the_agent_just_pushed(self):
        sid, token = self._create_agent_site("Ping-Single-No-Overwrite")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.81", "vendor": "cisco",
                        "hostname": "switch-02", "group": "Generale"}]})
        self.client.post("/api/agent/status", headers=ah,
                         json={"devices": [{"ip": "10.9.0.81", "up": True}]})

        from services import inventory_manager
        r = self.client.get("/api/ping/10.9.0.81", headers=self.admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(r.json()["reachable"])

        self.assertEqual(
            inventory_manager.get_detected_versions()["10.9.0.81"]["status"], "online")


    def test_run_triage_does_not_pile_up_duplicate_jobs(self):
        # With the agent offline the queue must not grow without bound: a
        # second run-triage while a triage job is still pending/running for
        # the same device must not enqueue a second copy.
        from services import site_manager
        sid, token = self._create_agent_site("Triage-Dedupe")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.71", "vendor": "cisco",
                        "hostname": "switch-01", "group": "Generale"}]})

        r1 = self.client.post("/api/run-triage", headers=self.admin_h,
                              json={"group": "Generale"})
        self.assertEqual(r1.status_code, 200, r1.text)
        r2 = self.client.post("/api/run-triage", headers=self.admin_h,
                              json={"group": "Generale"})
        self.assertEqual(r2.status_code, 200, r2.text)

        jobs = [j for j in site_manager.list_jobs(sid)
               if j["device_ip"] == "10.9.0.71" and j["kind"] == "triage"]
        self.assertEqual(len(jobs), 1, jobs)


class CentralDoesNotTouchAgentSiteDevices(unittest.TestCase):
    """Mode B promises the central needs no path to the site. It did anyway.

    The agent mirrors its inventory into the central so the dashboard can show
    it, and every central-side prober then read those rows as its own devices.
    On a routed lab that is denied ICMP and denied SSH from the central in the
    customer's firewall log; on a real NAT'd site it is a device permanently
    reported "offline" because the probe cannot arrive.
    """

    AGENT = {"id": "milan", "name": "Milan", "mode": "agent"}
    JUMP = {"id": "roma", "name": "Roma", "mode": "jump"}
    CENTRAL = {"id": "central", "name": "Central", "mode": "central"}

    def test_an_agent_site_has_no_direct_path(self):
        from unittest import mock
        from services import site_manager
        with mock.patch.object(site_manager, "get_site", return_value=self.AGENT):
            self.assertFalse(site_manager.has_direct_path("milan"))

    def test_a_central_site_still_has_one(self):
        from unittest import mock
        from services import site_manager
        with mock.patch.object(site_manager, "get_site", return_value=self.CENTRAL):
            self.assertTrue(site_manager.has_direct_path("central"))

    def test_a_site_the_central_does_not_know_keeps_its_direct_path(self):
        # This is what keeps the AGENT itself working: it runs the same code
        # over its local inventory, whose Site column names a site absent from
        # its own sites.json. Return False here and the agent would refuse to
        # reach the very devices it exists to manage.
        from unittest import mock
        from services import site_manager
        with mock.patch.object(site_manager, "get_site", return_value=None):
            self.assertTrue(site_manager.has_direct_path("milan"))
            self.assertFalse(site_manager.is_agent_site("milan"))

    def test_is_agent_site_separates_agent_from_jump(self):
        # Both lack a direct path, but only the jump site is still operated BY
        # the central (tunnelled through the bastion), so the two cannot share
        # one predicate.
        from unittest import mock
        from services import site_manager
        for site, expected in ((self.AGENT, True), (self.JUMP, False),
                               (self.CENTRAL, False)):
            with self.subTest(mode=site["mode"]):
                with mock.patch.object(site_manager, "get_site", return_value=site):
                    self.assertEqual(site_manager.is_agent_site(site["id"]), expected)
                    if not expected:
                        continue
                    self.assertFalse(site_manager.has_direct_path(site["id"]))

    def test_triage_refuses_instead_of_opening_ssh(self):
        from unittest import mock
        from core import core_engine
        from services import site_manager

        device = {"IP": "192.0.2.20", "Vendor": "cisco", "Group": "Generale",
                  "Site": "milan"}
        # is_reachable is the TCP/22 probe: reaching it at all is the failure.
        with mock.patch.object(site_manager, "get_site", return_value=self.AGENT), \
             mock.patch.object(core_engine, "is_reachable",
                               side_effect=AssertionError("probed the network")):
            out = core_engine.run_backup_and_triage(device)
        self.assertEqual(out["status"], "error")
        self.assertIn("agente", out["message"])

    def test_bulk_command_refuses_instead_of_opening_ssh(self):
        from unittest import mock
        from core import core_engine
        from services import site_manager

        device = {"IP": "192.0.2.20", "Vendor": "cisco", "Group": "Generale",
                  "Site": "milan"}
        with mock.patch.object(site_manager, "get_site", return_value=self.AGENT), \
             mock.patch.object(core_engine, "is_reachable",
                               side_effect=AssertionError("probed the network")):
            out = core_engine.run_bulk_command(device, ["show version"])
        self.assertEqual(out["status"], "error")
        self.assertIn("agente", out["message"])


class AgentConfigFileWins(unittest.TestCase):
    """An interval set from the dashboard must survive an agent restart.

    The dashboard's change is persisted into agent.json by the _agent_config
    job, but --interval carried an argparse default of 60 while being applied
    with "if args.interval" — a test of "did the operator pass this flag?"
    that was true on every start. So the file was read, then overwritten by a
    flag nobody had typed.
    """

    BASE = {"central_url": "http://192.0.2.10:8000", "site_id": "test-site",
            "token": "tok"}

    def _load(self, argv, cfg):
        import json as _json
        import sys
        import tempfile as _tf
        from unittest import mock
        from services import site_agent

        d = _tf.mkdtemp(prefix="sentinelnet_agentcfg_")
        path = os.path.join(d, "agent.json")
        with open(path, "w", encoding="utf-8") as f:
            _json.dump(cfg, f)
        with mock.patch.object(sys, "argv", ["site_agent.py", "--config", path] + argv):
            return site_agent.load_config()

    def test_the_interval_in_the_config_file_survives(self):
        out = self._load([], dict(self.BASE, interval=5))
        self.assertEqual(out["interval"], 5)

    def test_an_explicit_flag_still_overrides_the_file(self):
        out = self._load(["--interval", "120"], dict(self.BASE, interval=5))
        self.assertEqual(out["interval"], 120)

    def test_a_file_without_an_interval_gets_the_default(self):
        out = self._load([], dict(self.BASE))
        self.assertEqual(out["interval"], 60)


class AgentPushesItsOwnPingResults(unittest.TestCase):
    """The central does not reach an agent site's devices, so the agent's own
    ping is the only source of up/down for them."""

    def _agent(self):
        from unittest import mock
        from services import site_agent
        agent = site_agent.Agent.__new__(site_agent.Agent)
        agent.cfg = {"site_id": "milan", "interval": 60}
        agent._post = mock.MagicMock()
        agent._post.return_value.json.return_value = {"status": "success",
                                                      "updated": 2}
        return agent

    def test_every_device_is_reported_including_the_unreachable_one(self):
        # An unreachable device is pushed as down, never omitted: a skipped
        # device silently vanishes from the ping monitor, which is the
        # failure this change exists to remove.
        from unittest import mock

        agent = self._agent()
        devices = [{"IP": "10.9.0.50"}, {"IP": "10.9.0.51"}]
        with mock.patch("collectors.network_scanner._ping",
                        side_effect=lambda ip: ip == "10.9.0.50"):
            agent.push_status(devices)

        path, payload = agent._post.call_args[0]
        self.assertEqual(path, "/api/agent/status")
        self.assertEqual(payload["devices"],
                         [{"ip": "10.9.0.50", "up": True},
                          {"ip": "10.9.0.51", "up": False}])

    def test_no_devices_means_no_call(self):
        agent = self._agent()
        agent.push_status([])
        agent._post.assert_not_called()


class AgentScheduledBackup(unittest.TestCase):
    """The backup interval is deliberately not the polling interval: a 15s
    poll must not mean a config backup every 15 seconds."""

    def _agent(self, backup_interval=3600):
        from unittest import mock
        from services import site_agent
        agent = site_agent.Agent.__new__(site_agent.Agent)
        agent.cfg = {"site_id": "milan", "interval": 60,
                     "backup_interval": backup_interval}
        agent._last_backup = 0.0
        agent._post = mock.MagicMock()
        agent._post.return_value.json.return_value = {"status": "success",
                                                      "file": "/x"}
        return agent

    def test_a_successful_triage_is_pushed_with_its_config_text(self):
        import tempfile
        from unittest import mock
        from core import core_engine

        agent = self._agent()
        d = tempfile.mkdtemp(prefix="sentinelnet_bk_")
        path = os.path.join(d, "switch-01-10.9.0.60.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("hostname switch-01\nend\n")

        device = {"IP": "10.9.0.60", "Vendor": "cisco", "Group": "Generale"}
        with mock.patch.object(core_engine, "run_backup_and_triage",
                               return_value={"status": "success",
                                             "version": "15.2(7)E2",
                                             "hostname": "switch-01",
                                             "file": path}):
            agent.push_backup(device)

        call_path, payload = agent._post.call_args[0]
        self.assertEqual(call_path, "/api/agent/backup")
        self.assertEqual(payload["ip"], "10.9.0.60")
        self.assertEqual(payload["hostname"], "switch-01")
        self.assertIn("hostname switch-01", payload["config"])

    def test_push_backup_forwards_model_and_serial(self):
        # push_backup used to hardcode serial "" regardless of what
        # run_backup_and_triage returned, dropping the classifier's input.
        import tempfile
        from unittest import mock
        from core import core_engine

        agent = self._agent()
        d = tempfile.mkdtemp(prefix="sentinelnet_bk_")
        path = os.path.join(d, "switch-07-10.9.0.66.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("hostname switch-07\nend\n")

        device = {"IP": "10.9.0.66", "Vendor": "cisco", "Group": "Generale"}
        with mock.patch.object(core_engine, "run_backup_and_triage",
                               return_value={"status": "success",
                                             "version": "15.2(7)E2",
                                             "hostname": "switch-07",
                                             "model": "WS-C2960X-24",
                                             "serial": "FDO12345678",
                                             "file": path}):
            agent.push_backup(device)

        _call_path, payload = agent._post.call_args[0]
        self.assertEqual(payload["model"], "WS-C2960X-24")
        self.assertEqual(payload["serial"], "FDO12345678")

    def test_a_failed_triage_pushes_nothing(self):
        # A partial or empty push must never overwrite a good stored config.
        from unittest import mock
        from core import core_engine

        agent = self._agent()
        device = {"IP": "10.9.0.61", "Vendor": "cisco", "Group": "Generale"}
        with mock.patch.object(core_engine, "run_backup_and_triage",
                               return_value={"status": "error", "message": "boom"}):
            out = agent.push_backup(device)
        agent._post.assert_not_called()
        self.assertEqual(out["status"], "error")

    def test_interval_zero_disables_the_scheduled_phase(self):
        from unittest import mock
        agent = self._agent(backup_interval=0)
        with mock.patch.object(agent, "push_backup") as pb:
            n = agent.maybe_run_backups([{"IP": "10.9.0.62"}])
        pb.assert_not_called()
        self.assertEqual(n, 0)

    def test_the_phase_does_not_run_again_before_its_interval(self):
        from unittest import mock
        agent = self._agent(backup_interval=3600)
        with mock.patch.object(agent, "push_backup",
                               return_value={"status": "success"}) as pb:
            first = agent.maybe_run_backups([{"IP": "10.9.0.63"}])
            second = agent.maybe_run_backups([{"IP": "10.9.0.63"}])
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(pb.call_count, 1)
        self.assertGreater(agent._last_backup, 0.0)

    def test_a_triage_job_runs_the_local_backup_and_reports_a_short_result(self):
        # The job result column is rendered verbatim in the job-history panel,
        # so it carries a summary and never the config text.
        from unittest import mock
        agent = self._agent()
        agent._get = mock.MagicMock()
        agent._get.return_value.json.return_value = {"jobs": [
            {"id": "j1", "device_ip": "10.9.0.64", "command": "", "kind": "triage"},
        ]}
        posted = []

        def _capture(path, body):
            posted.append((path, body))
            return mock.MagicMock()

        agent._post = mock.MagicMock(side_effect=_capture)

        with mock.patch.object(agent, "push_backup",
                               return_value={"status": "success", "file": "/x"}) as pb:
            agent.run_jobs([{"IP": "10.9.0.64", "Vendor": "cisco"}])

        pb.assert_called_once()
        results = [body for path, body in posted if path.endswith("/result")]
        self.assertEqual(results[0]["status"], "done")
        self.assertNotIn("hostname", results[0]["result"])


if __name__ == "__main__":
    unittest.main()
