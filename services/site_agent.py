"""SentinelNet - Agente di sede (Mode B).

Processo leggero da eseguire nella sede remota. Si connette IN USCITA verso il
SentinelNet centrale (HTTPS su VPN) autenticandosi con il token per-sede, e
periodicamente:
  - invia un heartbeat;
  - spinge l'inventario locale dei dispositivi;
  - raccoglie e spinge le MAC-table dei dispositivi locali;
  - preleva i job di comando CLI in attesa, li esegue via SSH in locale e ne
    posta i risultati.

Riusa i moduli del repository (inventory_manager, core_engine, mac_collector)
per la raccolta locale. L'inventario locale dell'agente è il file
network_hosts.csv nella sua data dir (SENTINELNET_DATA_DIR), gestito con gli
stessi strumenti/CLI del centrale.

Uso:
    python site_agent.py --central-url https://central:8765 \
                         --site-id milano --token <TOKEN> [--interval 60]
oppure:
    python site_agent.py --config agent.json

agent.json:
    {"central_url": "...", "site_id": "...", "token": "...", "interval": 60,
     "verify_tls": true, "data_dir": "./agent-data"}
"""
import os
import sys
import json
import time
import socket
import threading
import collections
import argparse

import requests

# Ensure project root is in sys.path so 'services', 'core', 'collectors' modules import cleanly
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


class SyslogCollector:
    """Listener UDP leggero per raccogliere eventi syslog dai dispositivi locali."""
    def __init__(self, host="0.0.0.0", port=5514, maxlen=2000):
        self.host = host
        self.port = port
        self.queue = collections.deque(maxlen=maxlen)
        self.running = False
        self.sock = None
        self.thread = None

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.host, self.port))
            self.running = True
            self.thread = threading.Thread(target=self._listen_loop, daemon=True)
            self.thread.start()
            print(f"[syslog] collector avviato su UDP {self.host}:{self.port}")
        except Exception as e:
            print(f"[syslog] impossibile avviare listener UDP su porta {self.port}: {e}")

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(8192)
                if data:
                    raw_str = data.decode("utf-8", errors="replace")
                    self.queue.append({
                        "ts": int(time.time()),
                        "src_ip": addr[0],
                        "raw": raw_str
                    })
            except Exception:
                if not self.running:
                    break

    def drain(self, limit=500):
        items = []
        while self.queue and len(items) < limit:
            items.append(self.queue.popleft())
        return items


def load_config():
    p = argparse.ArgumentParser(description="SentinelNet - Agente di sede")
    p.add_argument("--config", help="File JSON di configurazione")
    p.add_argument("--central-url", help="URL base del SentinelNet centrale")
    p.add_argument("--site-id", help="Id della sede (X-Site-Id)")
    p.add_argument("--token", help="Token per-sede")
    p.add_argument("--interval", type=int, default=60, help="Secondi tra i cicli")
    p.add_argument("--data-dir", help="Directory dati locale (inventario)")
    p.add_argument("--no-verify-tls", action="store_true",
                   help="Non verificare il certificato TLS del centrale")
    p.add_argument("--syslog-port", type=int, help="Porta UDP listener syslog locale (default 5514)")
    p.add_argument("--no-syslog", action="store_true", help="Disattiva il listener syslog locale")
    args = p.parse_args()

    cfg = {}
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            cfg = json.load(f)
    if args.central_url:
        cfg["central_url"] = args.central_url
    if args.site_id:
        cfg["site_id"] = args.site_id
    if args.token:
        cfg["token"] = args.token
    if args.data_dir:
        cfg["data_dir"] = args.data_dir
    if args.interval:
        cfg["interval"] = args.interval
    if args.no_verify_tls:
        cfg["verify_tls"] = False
    if args.syslog_port:
        cfg["syslog_port"] = args.syslog_port
    if args.no_syslog:
        cfg["syslog_enabled"] = False

    for key in ("central_url", "site_id", "token"):
        if not cfg.get(key):
            p.error(f"Parametro obbligatorio mancante: {key}")

    cfg.setdefault("interval", 60)
    cfg.setdefault("verify_tls", True)
    cfg.setdefault("data_dir", "./agent-data")
    cfg.setdefault("syslog_enabled", True)
    cfg.setdefault("syslog_port", 5514)
    if cfg.get("data_dir"):
        os.environ["SENTINELNET_DATA_DIR"] = cfg["data_dir"]
    return cfg


class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg["central_url"].rstrip("/")
        self.verify = cfg.get("verify_tls", True)
        self.headers = {
            "X-Site-Id": cfg["site_id"],
            "X-Site-Token": cfg["token"],
            "Content-Type": "application/json",
        }
        self.syslog_collector = None
        self.syslog_worker_running = False
        if cfg.get("syslog_enabled", True):
            syslog_port = int(cfg.get("syslog_port", 5514))
            self.syslog_collector = SyslogCollector(port=syslog_port)
            self.syslog_collector.start()
            self._start_syslog_worker()
        # Import ritardato: dipende da SENTINELNET_DATA_DIR già impostata.
        global inventory_manager, core_engine, mac_collector
        from services import inventory_manager
        from core import core_engine
        from collectors import mac_collector

    def _start_syslog_worker(self):
        """Worker thread in background che trasmette in tempo reale (ogni 2s)
        gli eventi syslog al centrale, stile Checkmk / streaming."""
        self.syslog_worker_running = True
        t = threading.Thread(target=self._syslog_flush_loop, daemon=True)
        t.start()

    def _syslog_flush_loop(self):
        while self.syslog_worker_running:
            try:
                self.push_syslog()
            except Exception:
                pass
            time.sleep(2)

    # --- HTTP helper ---
    def _post(self, path, payload):
        return requests.post(self.base + path, headers=self.headers,
                             json=payload, verify=self.verify, timeout=30)

    def _get(self, path):
        return requests.get(self.base + path, headers=self.headers,
                            verify=self.verify, timeout=30)

    # --- Cicli di lavoro ---
    def heartbeat(self):
        r = self._post("/api/agent/heartbeat", {})
        r.raise_for_status()
        return r.json()

    def push_inventory(self, devices):
        payload = {"devices": [
            {"ip": d["IP"], "vendor": d.get("Vendor", "cisco"),
             "hostname": d.get("Hostname", ""),
             "group": d.get("Group") or d.get("Tenant", "")}
            for d in devices]}
        r = self._post("/api/agent/inventory", payload)
        r.raise_for_status()
        return r.json()

    def push_mac(self, devices):
        collections = []
        for d in devices:
            ip = d["IP"]
            vendor = (d.get("Vendor") or "cisco").lower()
            username, password, secret = core_engine.get_device_credentials(d)
            try:
                _, netmiko_type = core_engine.resolve_driver(vendor)
            except Exception:
                netmiko_type = "cisco_ios"
            try:
                res = mac_collector.collect_mac_table(
                    ip, username, password, secret, device_type=netmiko_type,
                    transports=inventory_manager.parse_transports(d))
            except Exception as e:
                print(f"[mac] {ip}: errore raccolta: {e}")
                continue
            if res.get("error"):
                print(f"[mac] {ip}: {res['error']}")
                continue
            collections.append({
                "switch_ip": ip,
                "switch_name": d.get("Hostname", ""),
                "rows": res.get("rows", []),
            })
        if not collections:
            return {"recorded": 0}
        r = self._post("/api/agent/mac", {"collections": collections})
        r.raise_for_status()
        return r.json()

    def run_jobs(self, devices):
        r = self._get("/api/agent/jobs")
        r.raise_for_status()
        jobs = r.json().get("jobs", [])
        by_ip = {d["IP"]: d for d in devices}
        for job in jobs:
            ip = job["device_ip"]
            cmd = job["command"]
            device = by_ip.get(ip)
            if not device:
                out = {"status": "error", "result": f"Dispositivo {ip} non in inventario locale."}
            else:
                res = core_engine.send_custom_command(device, cmd)
                if res.get("status") == "success":
                    out = {"status": "done", "result": res.get("output", "")}
                else:
                    out = {"status": "error", "result": res.get("message", "errore")}
            try:
                self._post(f"/api/agent/jobs/{job['id']}/result", out).raise_for_status()
                print(f"[job] {job['id']} su {ip}: {out['status']}")
            except Exception as e:
                print(f"[job] {job['id']}: invio risultato fallito: {e}")

    def push_syslog(self):
        if not self.syslog_collector:
            return {"ingested": 0}
        events = self.syslog_collector.drain()
        if not events:
            return {"ingested": 0}
        r = self._post("/api/agent/syslog", {"events": events})
        r.raise_for_status()
        res = r.json()
        print(f"[syslog] {res.get('ingested', 0)} eventi inviati al centrale")
        return res

    def cycle(self):
        devices = inventory_manager.get_all_devices()
        info = self.heartbeat()
        print(f"[heartbeat] sede '{info.get('site_id')}' ok, {len(devices)} dispositivi locali")
        try:
            self.push_inventory(devices)
        except Exception as e:
            print(f"[inventory] errore: {e}")
        try:
            self.push_mac(devices)
        except Exception as e:
            print(f"[mac] errore: {e}")
        try:
            self.push_syslog()
        except Exception as e:
            print(f"[syslog] errore: {e}")
        try:
            self.run_jobs(devices)
        except Exception as e:
            print(f"[jobs] errore: {e}")

    def run(self):
        interval = int(self.cfg.get("interval", 60))
        print(f"[agent] avviato: centrale={self.base} sede={self.cfg['site_id']} "
              f"intervallo={interval}s")
        while True:
            try:
                self.cycle()
            except Exception as e:
                print(f"[agent] ciclo fallito: {e}")
            time.sleep(interval)


def main():
    cfg = load_config()
    Agent(cfg).run()


if __name__ == "__main__":
    main()
