import threading
import webbrowser
import time
import json
import urllib.request
import gzip
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import inventory_manager
import core_engine

PORT = 8765
BASE_URL = "https://euvdservices.enisa.europa.eu"

class NetManagerAPIHandler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path

        # 1. Serve il file HTML statico della Dashboard
        if path == "/" or path == "/index.html" or path.startswith("/?"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._cors()
            self.end_headers()
            template_path = os.path.join("templates", "dashboard.html")
            if os.path.exists(template_path):
                with open(template_path, "rb") as f:
                    self.wfile.write(f.read())
            return

        # 2. API: Ottieni l'inventario dei dispositivi e le versioni scansionate
        if path == "/api/local-devices":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            devices = inventory_manager.get_all_devices()
            versions = inventory_manager.get_detected_versions()
            response_data = {"devices": devices, "detected_versions": versions}
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            return

        # Proxy verso il database europeo ENISA EUVD per Threat Intelligence
        if path.startswith("/api/"):
            target = BASE_URL + path
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "ThreatIntelDashboard/3.0"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    raw = r.read()
                    ct = r.headers.get("Content-Type", "application/json")
                    if "gzip" in r.headers.get("Content-Encoding", ""):
                        raw = gzip.decompress(raw)
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self._cors()
                self.end_headers()
                self.wfile.write(raw)
            except Exception as e:
                self.send_error(502, str(e))
            return

        self.send_error(404)

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        try:
            data = json.loads(post_data) if post_data else {}
        except:
            data = {}

        # 1. API: Inserimento nuovo dispositivo da form Web UI
        if self.path == "/api/add-device":
            inventory_manager.add_device_to_csv(
                data['ip'], data['vendor'], data['profile'],
                data.get('username', ''), data.get('password', ''), data.get('enable_secret', '')
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success"}).encode('utf-8'))
            return

        # 2. API: Avvio Scan Automazione e Backup globale
        if self.path == "/api/run-triage":
            devices = inventory_manager.get_all_devices()
            results = []
            for d in devices:
                res = core_engine.run_backup_and_triage(d)
                results.append({"ip": d['IP'], "result": res})
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "complete", "details": results}).encode('utf-8'))
            return

        # 3. API: Inoltro comando CLI arbitrario a singolo apparato
        if self.path == "/api/send-command":
            devices = inventory_manager.get_all_devices()
            target_device = next((d for d in devices if d['IP'] == data['ip']), None)
            
            if target_device:
                res = core_engine.send_custom_command(target_device, data['command'])
            else:
                res = {"status": "error", "message": "Dispositivo non presente in inventario"}
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._cors()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode('utf-8'))
            return

def open_browser():
    time.sleep(1.2)
    webbrowser.open(f"http://localhost:{PORT}/")

def main():
    # Creazione della cartella templates se non esiste per ospitare la dashboard
    if not os.path.exists("templates"):
        os.makedirs("templates")
        
    server = HTTPServer(("localhost", PORT), NetManagerAPIHandler)
    t = threading.Thread(target=open_browser, daemon=True)
    t.start()
    print(f"Net Manager Alfa in esecuzione su http://localhost:{PORT}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()

if __name__ == "__main__":
    main()
