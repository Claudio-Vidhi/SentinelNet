# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""SentinelNet - Agente di sonda (Mode B).

LINUX SOLTANTO. Un agente Windows non e' in roadmap: la sua gestione remota
dalla dashboard (lettura log, riavvio) e' costruita su systemd e journalctl,
che altrove non esistono. Il centrale, al contrario, gira anche su Windows.
Vedi docs/probes.md, sezione "Supported platforms".

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
    python probe_agent.py --central-url https://central:8000 \
                          --probe-id milano --token <TOKEN> [--interval 60]
oppure:
    python probe_agent.py --config agent.json

agent.json:
    {"central_url": "...", "probe_id": "...", "token": "...", "interval": 60,
     "verify_tls": true, "data_dir": "./agent-data"}
"""
import csv
import io
import os
import sys
import json
import time
import socket
import struct
import threading
import collections
import argparse

import requests

# Ensure project root is in sys.path so 'services', 'core', 'collectors' modules import cleanly
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services import agent_policy, inventory_manager
from core import core_engine, data_config, inventory_migration, probe_migration
from collectors import arp_collector, mac_collector


OT_SUPPORTED_PROBES = ("ethernet_ip", "modbus", "opc_ua", "bacnet")
OT_DEFAULT_PORTS = {
    "ethernet_ip": 44818,
    "modbus": 502,
    "opc_ua": 4840,
    "bacnet": 47808,
}
OT_MIN_INTERVAL_FLOOR_S = 10
OT_DEFAULT_MIN_INTERVAL_S = 300


def build_enip_list_identity() -> bytes:
    """Build a 24-byte read-only EtherNet/IP ListIdentity (0x0063) encapsulation header."""
    return struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"SENTINEL", 0)


def parse_enip_list_identity(data: bytes) -> dict:
    """Parse an EtherNet/IP ListIdentity reply into a device identity dict."""
    if len(data) < 24:
        return {"protocol": "ethernet_ip", "command": "ListIdentity", "raw_len": len(data)}
    cmd, length, _session, status, _ctx, _opts = struct.unpack("<HHII8sI", data[:24])
    out: dict[str, object] = {
        "protocol": "ethernet_ip",
        "command": "ListIdentity",
        "command_code": cmd,
        "status": status,
    }
    body = data[24:24 + length]
    if cmd != 0x0063 or len(body) < 6:
        return out
    item_count, item_type, item_len = struct.unpack("<HHH", body[:6])
    if item_count < 1 or item_type != 0x000C:
        return out
    item = body[6:6 + item_len]
    # CIP Identity Item: 2B encap_version + 16B socket_addr + 2B vendor + 2B dev_type
    # + 2B prod_code + 2B rev + 2B status + 4B serial + 1B name_len + name
    if len(item) < 33:
        return out
    vendor_id, dev_type, prod_code, rev_maj, rev_min, cip_status, serial = struct.unpack(
        "<HHHBBHI", item[18:32]
    )
    name_len = item[32]
    prod_name = item[33:33 + name_len].decode("utf-8", errors="replace").strip()
    out.update({
        "vendor_id": vendor_id,
        "device_type": dev_type,
        "product_code": prod_code,
        "revision": f"{rev_maj}.{rev_min}",
        "cip_status": cip_status,
        "serial": f"{serial:08x}",
        "product_name": prod_name,
    })
    return out


def build_modbus_read_device_id(
    unit_id: int = 1,
    read_code: int = 1,
    object_id: int = 0,
    transaction_id: int = 1,
) -> bytes:
    """Build a read-only Modbus TCP FC 43 / MEI 14 (Read Device Identification) ADU.

    Strictly restricted to Function Code 0x2B (43) and MEI Type 0x0E (14).
    """
    if read_code not in (1, 2, 3, 4):
        raise ValueError(f"Invalid Modbus Read Device ID code: {read_code}")
    if not (0 <= unit_id <= 255) or not (0 <= object_id <= 255):
        raise ValueError("unit_id and object_id must be in 0..255")
    # MBAP: Transaction ID (2B), Protocol ID = 0 (2B), Length = 5 (2B), Unit ID (1B)
    # PDU:  Function Code = 0x2B (1B), MEI Type = 0x0E (1B), ReadDevId (1B), ObjectId (1B)
    return struct.pack(
        ">HHHBBBBB",
        transaction_id & 0xFFFF,
        0,
        5,
        unit_id,
        0x2B,
        0x0E,
        read_code,
        object_id,
    )


_MODBUS_OBJECT_NAMES = {
    0x00: "vendor_name",
    0x01: "product_code",
    0x02: "revision",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "user_application_name",
}


def parse_modbus_read_device_id(data: bytes) -> dict:
    """Parse a Modbus TCP FC 43 / MEI 14 response into device identification fields."""
    if len(data) < 9:
        return {"protocol": "modbus", "command": "ReadDeviceIdentification", "raw_len": len(data)}
    tx_id, proto_id, _length, unit_id, func_code = struct.unpack(">HHHBB", data[:8])
    out: dict[str, object] = {
        "protocol": "modbus",
        "command": "ReadDeviceIdentification",
        "transaction_id": tx_id,
        "protocol_id": proto_id,
        "unit_id": unit_id,
        "function_code": func_code,
    }
    if func_code == 0xAB:
        out["exception_code"] = data[8]
        return out
    if func_code != 0x2B or len(data) < 14:
        return out
    mei_type, read_code, conformity, more_follows, next_obj, num_objs = struct.unpack(
        ">BBBBBB", data[8:14]
    )
    if mei_type != 0x0E:
        return out
    out["mei_type"] = mei_type
    out["read_code"] = read_code
    out["conformity_level"] = conformity
    objects: dict[str, str] = {}
    pos = 14
    for _ in range(num_objs):
        if pos + 2 > len(data):
            break
        obj_id, obj_len = data[pos], data[pos + 1]
        pos += 2
        if pos + obj_len > len(data):
            break
        val = data[pos:pos + obj_len].decode("utf-8", errors="replace").strip()
        pos += obj_len
        key = _MODBUS_OBJECT_NAMES.get(obj_id, f"object_{obj_id:02x}")
        objects[key] = val
        out[key] = val
    out["objects"] = objects
    return out


def build_opcua_hello(endpoint_url: str = "opc.tcp://localhost:4840") -> bytes:
    """Build a read-only OPC-UA Binary Protocol HEL (Hello) chunk."""
    url_bytes = endpoint_url.encode("utf-8")
    total_len = 8 + 20 + 4 + len(url_bytes)
    return (
        b"HELF"
        + struct.pack("<IIIIIII", total_len, 0, 65536, 65536, 0, 0, len(url_bytes))
        + url_bytes
    )


def build_opcua_get_endpoints_request(endpoint_url: str = "opc.tcp://localhost:4840") -> bytes:
    """Build a read-only OPC-UA GetEndpointsRequest (NodeId 428) message."""
    url_bytes = endpoint_url.encode("utf-8")
    # NodeId 428 in 4-byte numeric encoding: 0x01, namespace 0, 428 (0x01AC)
    node_id = b"\x01\x00\xac\x01"
    # RequestHeader minimal + EndpointUrl + LocaleIds (0) + ProfileUris (0)
    payload = node_id + struct.pack("<i", len(url_bytes)) + url_bytes + struct.pack("<ii", 0, 0)
    total_len = 8 + len(payload)
    return b"MSGF" + struct.pack("<I", total_len) + payload


def parse_opcua_response(data: bytes) -> dict:
    """Parse an OPC-UA ACK, ERR, or GetEndpoints response chunk."""
    if len(data) < 8:
        return {"protocol": "opc_ua", "command": "GetEndpoints", "raw_len": len(data)}
    msg_type = data[:3].decode("ascii", errors="replace")
    chunk_type = chr(data[3])
    msg_size = struct.unpack("<I", data[4:8])[0]
    out: dict[str, object] = {
        "protocol": "opc_ua",
        "command": "GetEndpoints",
        "message_type": msg_type,
        "chunk_type": chunk_type,
        "message_size": msg_size,
    }
    if msg_type == "ACK" and len(data) >= 28:
        ver, rcv_buf, snd_buf, max_msg, max_chunks = struct.unpack("<IIIII", data[8:28])
        out.update({
            "protocol_version": ver,
            "receive_buffer_size": rcv_buf,
            "send_buffer_size": snd_buf,
            "max_message_size": max_msg,
            "max_chunk_count": max_chunks,
        })
    elif msg_type == "ERR" and len(data) >= 16:
        err_code, reason_len = struct.unpack("<Ii", data[8:16])
        reason = ""
        if reason_len > 0 and len(data) >= 16 + reason_len:
            reason = data[16:16 + reason_len].decode("utf-8", errors="replace")
        out.update({"error_code": err_code, "reason": reason})
    return out


def build_bacnet_who_is() -> bytes:
    """Build an 8-byte read-only BACnet/IP Unconfirmed Who-Is frame."""
    # BVLC: Type 0x81 (BACnet/IP), Function 0x0A (Original-Unicast-NPDU), Length 0x0008
    # NPDU: Version 0x01, Control 0x00
    # APDU: PDU Type 0x10 (Unconfirmed-Request), Service Choice 0x08 (Who-Is)
    return bytes((0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08))


def parse_bacnet_i_am(data: bytes) -> dict:
    """Parse a BACnet/IP I-Am Unconfirmed-Request response."""
    out: dict[str, object] = {"protocol": "bacnet", "command": "Who-Is"}
    if len(data) < 12 or data[0] != 0x81:
        return out
    bvlc_func = data[1]
    bvlc_len = struct.unpack(">H", data[2:4])[0]
    out["bvlc_function"] = bvlc_func
    out["bvlc_length"] = bvlc_len
    if data[4] != 0x01:
        return out
    npdu_ctrl = data[5]
    pos = 6
    # Skip DNET/DLEN/DADR if destination specifier bit (0x20) is set
    if npdu_ctrl & 0x20:
        if pos + 3 > len(data):
            return out
        dlen = data[pos + 2]
        pos += 3 + dlen
    # Skip SNET/SLEN/SADR if source specifier bit (0x08) is set
    if npdu_ctrl & 0x08:
        if pos + 3 > len(data):
            return out
        slen = data[pos + 2]
        pos += 3 + slen
    if npdu_ctrl & 0x20:
        pos += 1  # hop count
    if pos + 2 > len(data):
        return out
    apdu_type = data[pos]
    service_choice = data[pos + 1]
    if apdu_type != 0x10 or service_choice != 0x00:
        return out
    out["service"] = "I-Am"
    pos += 2
    # Application tag 12 (Object Identifier): 0xC4 followed by 4-byte uint32
    if pos + 5 <= len(data) and data[pos] == 0xC4:
        obj_raw = struct.unpack(">I", data[pos + 1:pos + 5])[0]
        obj_type = (obj_raw >> 22) & 0x3FF
        device_instance = obj_raw & 0x3FFFFF
        out["object_type"] = obj_type
        out["device_instance"] = device_instance
        pos += 5
    # Skip Max APDU Length Accepted + Segmentation Supported application tags to read Vendor ID
    for _ in range(2):
        if pos >= len(data):
            break
        tag_len = data[pos] & 0x07
        pos += 1 + tag_len
    if pos < len(data) and (data[pos] & 0xF0) == 0x20:
        vlen = data[pos] & 0x07
        if 1 <= vlen <= 4 and pos + 1 + vlen <= len(data):
            vendor_id = int.from_bytes(data[pos + 1:pos + 1 + vlen], "big")
            out["vendor_id"] = vendor_id
    return out



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
        while self.running and self.sock is not None:
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


def _git_identity():
    """Commit, branch e stato del checkout dell'agente.

    Best-effort: un agente installato da zip non ha un repo e non deve
    fallire per questo. Serve a rispondere "quale codice sta girando qui",
    che senza SSH era una domanda senza risposta."""
    def _run(args):
        try:
            import subprocess
            out = subprocess.run(["git"] + args, cwd=_ROOT, capture_output=True,
                                 text=True, timeout=5)
            return out.stdout.strip() if out.returncode == 0 else ""
        except Exception:
            return ""
    return {
        "commit": _run(["rev-parse", "--short", "HEAD"]),
        "branch": _run(["rev-parse", "--abbrev-ref", "HEAD"]),
        "dirty": bool(_run(["status", "--porcelain"])),
    }


def load_config():
    p = argparse.ArgumentParser(description="SentinelNet - Agente di sede")
    p.add_argument("--config", help="File JSON di configurazione")
    p.add_argument("--central-url", help="URL base del SentinelNet centrale")
    p.add_argument("--probe-id", help="Id della sonda (X-Probe-Id)")
    p.add_argument("--token", help="Token per-sede")
    # default=None, like every other option here, and NOT 60: the flags below
    # are applied with "if args.X", which asks "did the user pass it?". With a
    # default of 60 that question was always true, so the flag overwrote the
    # interval read from --config on every start -- an interval changed from
    # the dashboard was persisted into agent.json correctly and then thrown
    # away at the next restart. The 60s default still applies, from the
    # cfg.setdefault below, which is where the other defaults live.
    p.add_argument("--interval", type=int, help="Secondi tra i cicli (default 60)")
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
        cfg["config_file"] = os.path.abspath(args.config)
    if args.central_url:
        cfg["central_url"] = args.central_url
    if args.probe_id:
        cfg["probe_id"] = args.probe_id
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

    for key in ("central_url", "probe_id", "token"):
        if not cfg.get(key):
            p.error(f"Parametro obbligatorio mancante: {key}")

    cfg.setdefault("interval", 60)
    cfg.setdefault("backup_interval", 3600)
    # Raccolta MAC/ARP: cadenza propria, perche' e' l'unica fase del ciclo che
    # apre una sessione SSH su OGNI apparato. Legata a 'interval' significava
    # sei sessioni al minuto per dispositivo con un polling a 10s: rumore
    # inutile su uno switch di produzione, e in dieci secondi una tabella
    # MAC/ARP non e' cambiata. 0 = ad ogni ciclo, per chi la vuole com'era.
    cfg.setdefault("l2_interval", 300)
    cfg.setdefault("verify_tls", True)
    cfg.setdefault("data_dir", "./agent-data")
    cfg.setdefault("syslog_enabled", True)
    cfg.setdefault("syslog_port", 5514)
    cfg.setdefault("ot_probes_enabled", False)
    cfg.setdefault("ot_probe_min_interval_s", OT_DEFAULT_MIN_INTERVAL_S)
    if cfg.get("data_dir"):
        os.environ["SENTINELNET_DATA_DIR"] = cfg["data_dir"]
        # The agent never runs the central's lifespan, so its own inventory
        # keeps the pre-rename header column after a self-update.
        probe_migration._hosts_header(cfg["data_dir"])
        for step in inventory_migration.migrate(cfg["data_dir"]):
            print(f"[inventory] migrazione: {step}")
    return cfg


# The only keys central may set through _agent_config, with their type: the
# fields of the dashboard's agent settings (routers/probes.AgentConfigUpdateSchema).
AGENT_CONFIG_KEYS = {"syslog_port": int, "interval": int, "backup_interval": int,
                     "l2_interval": int, "syslog_enabled": bool}


class Agent:
    def __init__(self, cfg):
        self._start_ts = time.time()
        # 0.0 = mai eseguito, quindi il primo ciclo fa subito un backup e poi
        # l'intervallo governa. Attendere un'ora prima del primo lascerebbe
        # mappa e versioni vuote per un'ora dopo il deploy.
        self._last_backup = 0.0
        # Stessa regola del backup: 0.0 = mai eseguito, quindi la prima
        # raccolta parte subito e solo dopo comanda l'intervallo.
        self._last_l2 = 0.0
        self._ot_probe_last_ts = {}
        self.cfg = cfg
        self.base = cfg["central_url"].rstrip("/")
        self.verify = cfg.get("verify_tls", True)
        self.headers = {
            "X-Probe-Id": cfg["probe_id"],
            "X-Probe-Token": cfg["token"],
            "Content-Type": "application/json",
        }
        self.syslog_collector = None
        self.syslog_worker_running = False
        if cfg.get("syslog_enabled", True):
            syslog_port = int(cfg.get("syslog_port", 5514))
            self.syslog_collector = SyslogCollector(port=syslog_port)
            self.syslog_collector.start()
            self._start_syslog_worker()

    def _stop_syslog_collector(self):
        """Ferma il listener UDP e libera la porta. Il worker di inoltro resta
        in piedi: senza collector si limita a non avere niente da spingere, e
        riaccendere il listener non deve far nascere un secondo thread."""
        col, self.syslog_collector = self.syslog_collector, None
        if not col:
            return
        col.running = False
        if col.sock:
            try:
                col.sock.close()
            except Exception:
                pass

    def _start_syslog_worker(self):
        """Worker thread in background che trasmette in tempo reale (ogni 2s)
        gli eventi syslog al centrale, stile Checkmk / streaming."""
        self.syslog_worker_running = True
        t = threading.Thread(target=self._syslog_flush_loop, daemon=True)
        t.start()

    def _syslog_flush_loop(self):
        # Un push che fallisce sempre svuota l'inoltro syslog senza che si veda:
        # si stampa il cambio di stato, non ogni giro (uno ogni 2s).
        failing = False
        while self.syslog_worker_running:
            try:
                self.push_syslog()
                if failing:
                    print("[agent] push syslog ripristinato.")
                    failing = False
            except Exception as e:
                if not failing:
                    print(f"[agent] push syslog fallito, inoltro fermo: {e}")
                    failing = True
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
        from core.version import __version__
        payload = {
            "version": __version__,
            **_git_identity(),
            "python_version": sys.version.split()[0],
            "syslog_enabled": bool(self.syslog_collector),
            "data_dir": os.path.abspath(self.cfg.get("data_dir") or "."),
            "syslog_port": int(self.cfg.get("syslog_port", 5514)),
            "interval": int(self.cfg.get("interval", 60)),
            "backup_interval": int(self.cfg.get("backup_interval") or 0),
            "l2_interval": int(self.cfg.get("l2_interval") or 0),
            "uptime_s": int(time.time() - self._start_ts) if hasattr(self, "_start_ts") else 0,
            # ADR-0009 §6: state and counts only, never the subnets themselves.
            "policy": agent_policy.summary(),
        }
        r = self._post("/api/agent/heartbeat", payload)
        r.raise_for_status()
        return r.json()

    def push_inventory(self, devices):
        payload = {"devices": [
            {"ip": d["IP"], "vendor": d.get("Vendor", "cisco"),
             "hostname": d.get("Hostname", ""),
             "group": d.get("Group") or d.get("Tenant", "")}
            for d in devices if isinstance(d, dict) and d.get("IP")]}
        r = self._post("/api/agent/inventory", payload)
        r.raise_for_status()
        return r.json()

    def push_mac(self, devices):
        collections = []
        self._wlc_arp = {}
        for d in devices:
            if not isinstance(d, dict) or not d.get("IP"):
                continue
            if inventory_manager.is_manual(d):
                continue  # no credentials by design: one would abort the whole push
            if mac_collector.is_wlc(d):
                res = mac_collector.collect_wlc(d)
                if res.get("error"):
                    print(f"[mac] {d['IP']}: {res['error']}")
                    continue
                collections.append({"switch_ip": d["IP"],
                                    "switch_name": d.get("Hostname", ""),
                                    "rows": res["rows"]})
                # Client MAC<->IP rides the ARP push: same table, same route.
                self._wlc_arp[d["IP"]] = res["arp"]
                continue
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

    def push_arp(self, devices):
        """Spinge i binding MAC<->IP letti dalle tabelle ARP dei gateway locali.

        Senza questo, un client di una sede remota ha una porta di switch ma
        NESSUN indirizzo IP: ``arp_entries`` e' l'unico posto dove vive il
        legame MAC<->IP, e tutto cio' che sta a valle (Client Map, flow path,
        diagnosi) parte dall'IP. La MAC table da sola non basta.

        Solo i gateway L3 hanno una tabella ARP utile: uno switch di accesso
        risponde 'vuoto' e la sua raccolta viene saltata dal chiamante.
        """
        collections = []
        for d in devices:
            if not isinstance(d, dict) or not d.get("IP"):
                continue
            ip = d["IP"]
            wlc_arp = getattr(self, "_wlc_arp", {}).get(ip)
            if wlc_arp:
                collections.append({"source_ip": ip,
                                    "source_name": d.get("Hostname", ""),
                                    "source_type": "wlc", "entries": wlc_arp})
            try:
                res = arp_collector.collect_from_device(d)
            except Exception as e:
                print(f"[arp] {ip}: errore raccolta: {e}")
                continue
            if res.get("status") != "success":
                print(f"[arp] {ip}: {res.get('message', 'errore')}")
                continue
            if not res.get("entries"):
                continue          # non ruota VLAN: non e' un errore
            collections.append({
                "source_ip": ip,
                "source_name": d.get("Hostname", ""),
                "source_type": res.get("source_type", ""),
                "entries": res["entries"],
            })
        if not collections:
            return {"recorded": 0}
        r = self._post("/api/agent/arp", {"collections": collections})
        r.raise_for_status()
        return r.json()

    def push_status(self, devices):
        """Ping locale dei propri dispositivi, spinto al centrale.

        Il centrale non ha (e non deve avere) un percorso diretto verso questi
        apparati: senza questo push la sede resta senza stato up/down."""
        from collectors.network_scanner import _ping as icmp_ping
        items = []
        for d in devices:
            ip = (d.get("IP") or "").strip()
            if not ip:
                continue
            try:
                up = bool(icmp_ping(ip))
            except Exception:
                up = False
            items.append({"ip": ip, "up": up})
        if not items:
            return {"updated": 0}
        r = self._post("/api/agent/status", {"devices": items})
        r.raise_for_status()
        return r.json()

    # Task 4: Scheduled backup phase
    def push_backup(self, device):
        """Triage+backup locale di un dispositivo, spinto al centrale.

        La copia locale in data/backup-config resta: e' quella che l'agente
        scrive comunque. Al centrale va il testo, perche' e' li' che vivono
        mappa, config drift e classificazione per modello."""
        res = core_engine.run_backup_and_triage(device)
        if res.get("status") != "success":
            return {"status": "error", "message": res.get("message", "errore")}
        try:
            with open(res["file"], encoding="utf-8") as f:
                config_out = f.read()
        except OSError as e:
            return {"status": "error", "message": f"backup illeggibile: {e}"}
        r = self._post("/api/agent/backup", {
            "ip": device["IP"],
            "hostname": res.get("hostname", ""),
            "vendor": device.get("Vendor", "cisco"),
            "version": res.get("version", "Non Rilevata"),
            "model": res.get("model", ""),
            "serial": res.get("serial", ""),
            "config": config_out,
        })
        r.raise_for_status()
        return {"status": "success", **r.json()}

    def apply_central_devices(self, items):
        """Applica l'inventario che il centrale gestisce per questa sede.

        Tre regole, e la terza e' quella che tiene in piedi tutto il resto:
        si AGGIUNGE e si AGGIORNA, non si CANCELLA mai. Un dispositivo assente
        dalla lista significa "il centrale non lo conosce", non "rimuovilo":
        l'agente puo' legittimamente averne di suoi, ed e' cosi' che funziona
        il push in salita, che resta la strada per farglieli sapere.

        Le credenziali arrivano in chiaro e add_or_update_device le cifra con
        la chiave LOCALE. Una stringa vuota su un dispositivo esistente vuol
        gia' dire "tieni quelle che ci sono", quindi un push senza segreti
        (centrale in HTTP) non azzera quelle che l'agente ha gia'.
        """
        applied = 0
        for it in items or []:
            ip = (it.get("ip") or "").strip()
            if not ip:
                continue
            group = (it.get("group") or "").strip()
            if not group:
                continue
            if group not in inventory_manager.get_all_groups():
                inventory_manager.add_group(group)
            try:
                inventory_manager.add_or_update_device(
                    ip, it.get("vendor") or "cisco", "custom",
                    it.get("username") or "", it.get("password") or "",
                    it.get("enable_secret") or "", group,
                    probe=self.cfg["probe_id"], ssh_port=it.get("ssh_port"),
                    require_location=False)
                if it.get("hostname"):
                    inventory_manager.update_device_hostname(ip, it["hostname"])
                applied += 1
            except ValueError as e:
                print(f"[devices] {ip} ignorato: {e}")
        if applied:
            print(f"[devices] {applied} dispositivi dal centrale")
        return applied

    def maybe_push_l2(self, devices):
        """Raccolta MAC e ARP, alla cadenza 'l2_interval'.

        Le due fasi restano indipendenti fra loro (una che fallisce non ferma
        l'altra), ma condividono l'orologio: aprono la stessa sessione SSH
        verso gli stessi apparati, quindi separarle raddoppierebbe le
        connessioni senza dare nulla in cambio.
        """
        every = int(self.cfg.get("l2_interval") or 0)
        now = time.time()
        if every > 0 and self._last_l2 and now - self._last_l2 < every:
            return False
        self._last_l2 = now
        try:
            self.push_mac(devices)
        except Exception as e:
            print(f"[mac] errore: {e}")
        try:
            self.push_arp(devices)
        except Exception as e:
            print(f"[arp] errore: {e}")
        return True

    def maybe_run_backups(self, devices):
        """Fase di backup schedulata. Ritorna quanti dispositivi sono passati."""
        every = int(self.cfg.get("backup_interval") or 0)
        if every <= 0:
            return 0
        now = time.time()
        if self._last_backup and now - self._last_backup < every:
            return 0
        self._last_backup = now
        n = 0
        for d in devices:
            try:
                if self.push_backup(d).get("status") == "success":
                    n += 1
            except Exception as e:
                print(f"[backup] {d.get('IP')}: {e}")
        return n

    @staticmethod
    def _deferred_exit():
        """Esce dal processo dopo un attimo, lasciando che systemd lo rialzi.

        L'attesa non e' cosmetica: il risultato del job viene postato al
        centrale dopo il ritorno di _execute_agent_rpc, e uscire subito lo
        farebbe sparire."""
        time.sleep(1.5)
        os._exit(0)

    def _execute_agent_rpc(self, cmd: str) -> dict:
        """Esegue comandi di gestione remota dell'agente (_agent_self_update,
        _agent_restart, _agent_logs, _agent_config).

        LINUX SOLTANTO, e un agente Windows non e' in roadmap: _agent_logs
        legge il journal con journalctl e _agent_restart esce dal processo
        contando su systemd per riavviarlo. Su un host senza systemd il primo
        darebbe errore e il secondo lascerebbe la sede senza agente. Vedi
        docs/probes.md, "Supported platforms"."""
        import subprocess
        parts = cmd.split(maxsplit=1)
        action = parts[0]
        arg = parts[1] if len(parts) > 1 else ""

        if action == "_agent_self_update":
            try:
                proc = subprocess.run(
                    ["git", "pull"], cwd=_ROOT, capture_output=True, text=True, timeout=60
                )
                output = proc.stdout + proc.stderr
                status = "done" if proc.returncode == 0 else "error"
                result = f"[git pull] code={proc.returncode}\n{output}"
                # Il pull scrive il codice nuovo sul disco; il processo continua
                # a girare con quello vecchio in memoria. Senza questo riavvio
                # il pannello flotta mostrava ancora la versione precedente e
                # l'unico rimedio era un systemctl restart a mano sull'host
                # della sede: proprio la shell che questa funzione evita.
                # Il riavvio e' differito, come in _agent_restart, cosi' il
                # risultato del job arriva al centrale prima che il processo
                # esca. Nessun riavvio se non e' cambiato nulla (interromperebbe
                # i job in corso per niente) o se il pull e' fallito.
                if status == "done" and "Already up to date" not in output:
                    # Le dipendenze PRIMA del riavvio: un aggiornamento che ne
                    # aggiunge una, riavviato senza installarla, manda l'agente
                    # in crash-loop (systemd lo rialza, l'import fallisce, la
                    # sede resta senza agente). Con l'interprete che sta
                    # girando, cosi' finisce nel venv giusto senza sapere come
                    # e' stato creato.
                    dep = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "-r",
                         os.path.join(_ROOT, "requirements.txt")],
                        cwd=_ROOT, capture_output=True, text=True, timeout=600)
                    if dep.returncode != 0:
                        # Niente riavvio: il codice vecchio in memoria funziona,
                        # quello nuovo sul disco no. Meglio una sede che gira
                        # indietro di una versione che una sede spenta.
                        return {"status": "error", "result": result +
                                "\n[pip] installazione delle dipendenze fallita "
                                f"(code={dep.returncode}), riavvio annullato:\n"
                                f"{(dep.stderr or dep.stdout or '').strip()[-2000:]}"}
                    result += f"\n[pip] dipendenze aggiornate (code={dep.returncode})."
                    threading.Thread(target=self._deferred_exit, daemon=True).start()
                    result += "\nRiavvio dell'agente programmato per applicare l'aggiornamento."
                return {"status": status, "result": result}
            except Exception as e:
                return {"status": "error", "result": f"Errore git pull: {e}"}

        elif action == "_agent_restart":
            threading.Thread(target=self._deferred_exit, daemon=True).start()
            return {"status": "done", "result": "Riavvio agente programmato tra 1.5 secondi (systemd auto-restart)."}

        elif action == "_agent_logs":
            try:
                proc = subprocess.run(
                    ["journalctl", "-u", "sentinelnet-agent", "-n", "200",
                     "--no-pager"],
                    capture_output=True, text=True, timeout=20)
                # Ultime 200 righe e basta: questa stringa finisce tale e quale
                # nel pannello storico job, dove un journal intero e' inservibile.
                tail = "\n".join((proc.stdout or proc.stderr).splitlines()[-200:])
                return {"status": "done", "result": tail}
            except Exception as e:
                return {"status": "error", "result": f"journalctl non disponibile: {e}"}

        elif action == "_agent_get_inventory":
            try:
                from services import inventory_manager
                buf = io.StringIO()
                w = csv.DictWriter(buf, fieldnames=inventory_manager._HOSTS_FIELDS,
                                   extrasaction="ignore", lineterminator="\n")
                w.writeheader()
                w.writerows(inventory_manager.get_all_devices())
                return {"status": "done", "result": buf.getvalue()}
            except Exception as e:
                return {"status": "error", "result": f"Errore lettura inventario locale: {e}"}

        elif action == "_agent_save_inventory":
            try:
                from services import inventory_manager
                # Scrivere `arg` verbatim significava accettare qualunque cosa:
                # una colonna 'Tenant' (che il parser chiama 'Group') mandava
                # ogni apparato nel gruppo sbagliato, un CSV con il punto e
                # virgola o il BOM di Excel faceva esplodere get_all_devices(),
                # e un comando senza argomento azzerava il file. Si passa dal
                # lettore tollerante e si riscrive nelle colonne canoniche.
                # ponytail: Password/Enable Secret/SNMP Community restano come
                # arrivano. Cifrarle richiederebbe la chiave Fernet dell'agente,
                # che la centrale non ha; un valore in chiaro viene ignorato da
                # get_device_credentials. Documentato in docs/probes.md.
                rows = [rec for _, rec in inventory_manager._read_inventory_csv(arg)]
                os.makedirs(os.path.dirname(inventory_manager.inventory_db_path()), exist_ok=True)
                inventory_manager.write_devices(rows)
                return {"status": "done",
                        "result": f"Inventario locale salvato con successo ({len(rows)} apparati)."}
            except ValueError as e:
                return {"status": "error", "result": f"CSV non valido: {e}"}
            except Exception as e:
                return {"status": "error", "result": f"Errore salvataggio inventario: {e}"}

        elif action == "_agent_config":
            try:
                new_cfg = json.loads(arg)
                # ADR-0009 §4: central may set what the dashboard offers and
                # nothing else. central_url, token, probe_id, data_dir and
                # ot_probes_enabled stay a decision of whoever runs this host.
                bad = [k for k, v in (new_cfg.items() if isinstance(new_cfg, dict) else [])
                       if k not in AGENT_CONFIG_KEYS or not isinstance(v, AGENT_CONFIG_KEYS[k])
                       or isinstance(v, bool) != (AGENT_CONFIG_KEYS[k] is bool)]
                if not isinstance(new_cfg, dict) or bad:
                    return {"status": "error",
                            "result": f"Configurazione rifiutata dall'agente: chiavi non "
                                      f"consentite o di tipo errato {bad}. Consentite: "
                                      f"{sorted(AGENT_CONFIG_KEYS)}."}
                self.cfg.update(new_cfg)

                # Persiste su disco solo se l'agente e' stato avviato con
                # --config (load_config imposta config_file solo in quel caso).
                # Se avviato da flag CLI, la modifica resta solo in memoria e
                # va persa al riavvio: il risultato del job deve dirlo
                # onestamente, non limitarsi a "done".
                persisted = False
                if self.cfg.get("config_file"):
                    with open(self.cfg["config_file"], "w", encoding="utf-8") as f:
                        json.dump(self.cfg, f, indent=2)
                    persisted = True

                # Accensione/spegnimento del listener. La porta era
                # configurabile e il listener no: l'unico modo di spegnerlo era
                # riavviare l'agente con --no-syslog, cioe' una sessione SSH
                # nella sede.
                if "syslog_enabled" in new_cfg:
                    if new_cfg["syslog_enabled"]:
                        if not self.syslog_collector:
                            self.syslog_collector = SyslogCollector(
                                port=int(self.cfg.get("syslog_port", 5514)))
                            self.syslog_collector.start()
                            if not self.syslog_worker_running:
                                self._start_syslog_worker()
                    else:
                        self._stop_syslog_collector()

                # Rebind syslog listener if port changed
                if "syslog_port" in new_cfg and self.syslog_collector:
                    new_port = int(new_cfg["syslog_port"])
                    if self.syslog_collector.port != new_port:
                        self._stop_syslog_collector()
                        self.syslog_collector = SyslogCollector(port=new_port)
                        self.syslog_collector.start()

                if persisted:
                    note = "applicata in memoria e salvata su disco (config_file)"
                else:
                    note = ("applicata SOLO in memoria: nessun config_file attivo "
                            "(agente avviato da flag CLI), verra' persa al riavvio")
                return {"status": "done", "result": f"Configurazione agent aggiornata ({note}): {new_cfg}"}
            except Exception as e:
                return {"status": "error", "result": f"Errore aggiornamento config: {e}"}

        return {"status": "error", "result": f"Comando RPC sconosciuto: {action}"}

    def _execute_rest_job(self, device, spec_json: str) -> dict:
        """Esegue una chiamata REST di sola lettura verso un apparato locale.

        Il centrale non raggiunge gli apparati di una sede agent, e le domande
        che contano per una diagnosi (quale policy matcherebbe, quale rotta,
        il tunnel è su?) non hanno un equivalente CLI affidabile.

        L'allowlist viene RIVERIFICATA qui, non solo dal centrale che ha
        accodato il job. Non è ridondanza: il modello della modalità agent è
        che le credenziali restino nella sede anche se il centrale viene
        compromesso, e accettare qualunque percorso arrivi dal centrale
        annullerebbe proprio quella garanzia.
        """
        from services import fortigate_service, probe_manager
        try:
            spec = json.loads(spec_json)
        except (TypeError, ValueError):
            return {"status": "error", "result": "Job REST malformato."}
        path = spec.get("path", "")
        if not probe_manager.rest_path_allowed(path):
            print(f"[job] percorso REST rifiutato dall'agente: {path!r}")
            return {"status": "error",
                    "result": f"Percorso REST non consentito: {path!r}"}
        try:
            data = fortigate_service.api_get(device["IP"], path,
                                             spec.get("params") or None)
            return {"status": "done", "result": json.dumps(data)}
        except Exception as e:
            return {"status": "error", "result": str(e)}

    @staticmethod
    def _normalize_ot_protocol(protocol: str) -> str:
        p = (protocol or "").strip().lower()
        if p in ("modbus_tcp", "modbus-tcp"):
            return "modbus"
        if p in ("enip", "ethernet/ip", "ethernet-ip"):
            return "ethernet_ip"
        if p in ("opcua", "opc-ua"):
            return "opc_ua"
        return p

    def _device_ot_protocols(self, device: dict) -> list:
        """Return the list of OT probe protocols explicitly enabled for a device."""
        raw = device.get("ot_probes") or device.get("OT Probes")
        if isinstance(raw, (list, tuple, set)):
            return [self._normalize_ot_protocol(str(x)) for x in raw if str(x).strip()]
        if isinstance(raw, str) and raw.strip():
            return [self._normalize_ot_protocol(x) for x in raw.split(",") if x.strip()]
        return []

    def _is_ot_probe_allowed(self, device: dict, protocol: str) -> bool:
        """Check that read-only OT probing is explicitly enabled for both the
        site (agent config) and the individual target device."""
        if not isinstance(device, dict) or not (device.get("IP") or "").strip():
            return False
        if not bool(self.cfg.get("ot_probes_enabled", False)):
            return False
        if inventory_manager.is_manual(device):
            return False
        proto = self._normalize_ot_protocol(protocol)
        if proto not in OT_SUPPORTED_PROBES:
            return False
        allowed_protos = self._device_ot_protocols(device)
        flag = device.get("ot_probe_enabled")
        if flag is None:
            flag_str = str(device.get("OT Probe") or "").strip().lower()
            flag = flag_str in ("1", "true", "yes", "on") if flag_str else False
        if flag is False and not allowed_protos:
            return False
        if allowed_protos and proto not in allowed_protos:
            return False
        return bool(flag) or (proto in allowed_protos)

    @staticmethod
    def _probe_ethernet_ip(ip: str, port: int, timeout: float) -> dict:
        req = build_enip_list_identity()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            resp = sock.recv(4096)
        return parse_enip_list_identity(resp)

    @staticmethod
    def _probe_modbus(ip: str, port: int, timeout: float, unit_id: int = 1) -> dict:
        req = build_modbus_read_device_id(unit_id=unit_id, read_code=1, object_id=0)
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            resp = sock.recv(4096)
        return parse_modbus_read_device_id(resp)

    @staticmethod
    def _probe_opc_ua(ip: str, port: int, timeout: float) -> dict:
        endpoint_url = f"opc.tcp://{ip}:{port}"
        req = build_opcua_hello(endpoint_url)
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(req)
            resp = sock.recv(4096)
        out = parse_opcua_response(resp)
        out["endpoint_url"] = endpoint_url
        return out

    @staticmethod
    def _probe_bacnet(ip: str, port: int, timeout: float) -> dict:
        req = build_bacnet_who_is()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(req, (ip, port))
            resp, _addr = sock.recvfrom(4096)
        finally:
            sock.close()
        return parse_bacnet_i_am(resp)

    def run_ot_probe(self, device: dict, protocol: str, timeout: float = 2.0) -> dict:
        """Execute a rate-limited, opt-in, read-only OT identity probe against device."""
        ip = (device.get("IP") or "").strip() if isinstance(device, dict) else ""
        proto = self._normalize_ot_protocol(protocol)
        if proto not in OT_SUPPORTED_PROBES:
            raise ValueError(f"Unsupported OT probe protocol: {protocol!r}")
        if not self._is_ot_probe_allowed(device, proto):
            return {
                "status": "blocked",
                "reason": "OT probe disabled for site or device",
                "ip": ip,
                "protocol": proto,
            }
        min_interval = max(
            OT_MIN_INTERVAL_FLOOR_S,
            int(self.cfg.get("ot_probe_min_interval_s", OT_DEFAULT_MIN_INTERVAL_S)),
        )
        now = time.time()
        key = (ip, proto)
        last_ts = getattr(self, "_ot_probe_last_ts", {}).get(key)
        if last_ts is not None and (now - last_ts) < min_interval:
            return {
                "status": "rate_limited",
                "retry_after_s": round(min_interval - (now - last_ts), 2),
                "ip": ip,
                "protocol": proto,
            }
        if not hasattr(self, "_ot_probe_last_ts"):
            self._ot_probe_last_ts = {}
        self._ot_probe_last_ts[key] = now
        port = int(device.get("ot_port") or OT_DEFAULT_PORTS[proto])
        try:
            if proto == "ethernet_ip":
                identity = self._probe_ethernet_ip(ip, port, timeout)
            elif proto == "modbus":
                unit_id = int(device.get("modbus_unit_id") or 1)
                identity = self._probe_modbus(ip, port, timeout, unit_id=unit_id)
            elif proto == "opc_ua":
                identity = self._probe_opc_ua(ip, port, timeout)
            else:
                identity = self._probe_bacnet(ip, port, timeout)
            return {
                "status": "ok",
                "ip": ip,
                "protocol": proto,
                "identity": identity,
            }
        except Exception as e:
            return {
                "status": "error",
                "ip": ip,
                "protocol": proto,
                "error": str(e),
            }

    def maybe_run_ot_probes(self, devices) -> list:
        """Run opt-in read-only OT probes for explicitly enabled devices."""
        if not bool(self.cfg.get("ot_probes_enabled", False)):
            return []
        results = []
        for d in devices or []:
            if not isinstance(d, dict) or not d.get("IP"):
                continue
            protos = self._device_ot_protocols(d) or list(OT_SUPPORTED_PROBES)
            for proto in protos:
                if not self._is_ot_probe_allowed(d, proto):
                    continue
                res = self.run_ot_probe(d, proto)
                if res.get("status") in ("ok", "error"):
                    results.append(res)
        return results

    def _execute_ot_probe_job(self, device: dict, spec_str: str) -> dict:
        protocol = spec_str.strip()
        timeout = 2.0
        if protocol.startswith("{"):
            try:
                spec = json.loads(protocol)
                protocol = spec.get("protocol", "")
                timeout = float(spec.get("timeout", 2.0))
            except (TypeError, ValueError):
                return {"status": "error", "result": "Job OT probe malformato."}
        try:
            res = self.run_ot_probe(device, protocol, timeout=timeout)
        except ValueError as e:
            return {"status": "error", "result": str(e)}
        status = "done" if res.get("status") == "ok" else "error"
        return {"status": status, "result": json.dumps(res)}

    @staticmethod
    def _log_job(job: dict, out: dict) -> None:
        """ADR-0009 §5: the site's own record of what central asked for, kept
        where central cannot edit it. The command, not its output."""
        # ponytail: one append-only file, no rotation; rotate when sites run
        # enough jobs for its size to matter.
        rec = {"ts": int(time.time()), "id": job.get("id"), "kind": job.get("kind") or "cli",
               "device_ip": job.get("device_ip"), "command": (job.get("command") or "")[:200],
               "requested_by": job.get("requested_by", ""),
               "bypass": bool(job.get("blacklist_bypass")), "status": out.get("status")}
        try:
            with open(data_config.get_path("agent_jobs.jsonl"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError as e:
            print(f"[job] log locale non scritto: {e}")

    def run_jobs(self, devices):
        r = self._get("/api/agent/jobs")
        r.raise_for_status()
        jobs = r.json().get("jobs", [])
        by_ip = {d["IP"]: d for d in devices if isinstance(d, dict) and d.get("IP")}
        for job in jobs:
            ip = job.get("device_ip")
            cmd = job.get("command", "")
            if job.get("kind") == "rest":
                device = by_ip.get(ip)
                out = ({"status": "error",
                        "result": f"Dispositivo {ip} non in inventario locale."}
                       if not device else self._execute_rest_job(device, cmd))
            elif job.get("kind") == "ot_probe":
                device = by_ip.get(ip)
                out = ({"status": "error",
                        "result": f"Dispositivo {ip} non in inventario locale."}
                       if not device else self._execute_ot_probe_job(device, cmd))
            elif job.get("kind") == "triage":
                device = by_ip.get(ip)
                if not device:
                    out = {"status": "error",
                           "result": f"Dispositivo {ip} non in inventario locale."}
                else:
                    res = self.push_backup(device)
                    # Un riassunto, mai la config: questa colonna viene resa
                    # tale e quale nel pannello storico job.
                    out = ({"status": "done", "result": "backup inviato al centrale"}
                           if res.get("status") == "success"
                           else {"status": "error",
                                 "result": res.get("message", "errore")})
            elif cmd.startswith("_agent_"):
                out = self._execute_agent_rpc(cmd)
            else:
                device = by_ip.get(ip)
                if not device:
                    out = {"status": "error", "result": f"Dispositivo {ip} non in inventario locale."}
                elif job.get("blacklist_bypass") and not agent_policy.allows_change(ip):
                    # ADR-0009 §2: the bypass is central's request, the grant is
                    # the local policy's. Refused outright, with the reason.
                    out = {"status": "error",
                           "result": f"Modifica non concessa dalla policy locale dell'agente "
                                     f"per {ip} ('change' in {agent_policy.POLICY_FILE})."}
                else:
                    # Il bypass della blacklist arriva dal centrale, che lo
                    # ha autorizzato e messo in audit (M-1). L'allowlist REST
                    # resta decisa qui, e nessun flag del centrale la allarga.
                    res = core_engine.send_custom_command(
                        device, cmd,
                        bypass_blacklist=bool(job.get("blacklist_bypass")))
                    if res.get("status") == "success":
                        out = {"status": "done", "result": res.get("output", "")}
                    else:
                        out = {"status": "error", "result": res.get("message", "errore")}
            self._log_job(job, out)
            try:
                self._post(f"/api/agent/jobs/{job['id']}/result", out).raise_for_status()
                print(f"[job] {job['id']} '{cmd}': {out['status']}")
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
        info = self.heartbeat()
        # Prima dell'inventario locale: un dispositivo appena spinto dal
        # centrale dev'essere gia' nella lista che le fasi qui sotto usano,
        # altrimenti resta invisibile per un giro intero.
        try:
            self.apply_central_devices(info.get("devices"))
        except Exception as e:
            print(f"[devices] errore: {e}")
        devices = inventory_manager.get_all_devices()
        print(f"[heartbeat] sonda '{info.get('probe_id')}' ok, {len(devices)} dispositivi locali")
        try:
            self.push_inventory(devices)
        except Exception as e:
            print(f"[inventory] errore: {e}")
        try:
            self.maybe_push_l2(devices)
        except Exception as e:
            print(f"[l2] errore: {e}")
        try:
            self.push_status(devices)
        except Exception as e:
            print(f"[status] errore: {e}")
        try:
            self.maybe_run_backups(devices)
        except Exception as e:
            print(f"[backup] errore: {e}")
        try:
            self.push_syslog()
        except Exception as e:
            print(f"[syslog] errore: {e}")
        try:
            self.run_jobs(devices)
        except Exception as e:
            print(f"[jobs] errore: {e}")

    def stop(self):
        self.syslog_worker_running = False
        if self.syslog_collector:
            self.syslog_collector.running = False
            if self.syslog_collector.sock:
                try:
                    self.syslog_collector.sock.close()
                except Exception:
                    pass
        print("[agent] arrestato con successo.")

    def run(self):
        print(f"[agent] avviato: centrale={self.base} sonda={self.cfg['probe_id']}")
        try:
            while True:
                try:
                    self.cycle()
                except Exception as e:
                    print(f"[agent] ciclo fallito: {e}")
                # L'intervallo va riletto DOPO cycle(): run_jobs() (chiamato da
                # cycle()) puo' applicare un _agent_config che aggiorna
                # self.cfg["interval"]. Leggendolo prima del ciclo, come in
                # precedenza, il nuovo valore veniva usato solo al giro
                # successivo, ritardando di un ciclo intero l'effetto della
                # modifica.
                interval = int(self.cfg.get("interval", 60))
                time.sleep(interval)
        except (KeyboardInterrupt, SystemExit):
            self.stop()


def main():
    cfg = load_config()
    # ADR-0009: the local device policy is loaded before anything dials. A
    # broken file stops the agent here rather than running without a boundary.
    from services import agent_policy
    policy = agent_policy.load_or_bootstrap(
        cfg["data_dir"], [d.get("IP") for d in inventory_manager.get_all_devices()])
    agent_policy.install(policy)
    print(f"[policy] {policy['path']}: {agent_policy.summary()}")
    if policy["state"] == "bootstrap":
        print("[policy] policy di bootstrap: rivedi allowed_subnets/change e togli "
              "\"bootstrap\" dal file (docs/probes.md, Device policy).")
    Agent(cfg).run()


if __name__ == "__main__":
    main()
