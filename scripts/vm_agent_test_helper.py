#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SentinelNet - VM Agent Test Helper

Script di supporto per testare e configurare l'agente di sede (site_agent.py)
in un ambiente di Virtual Machine (VM).

Caratteristiche:
  1. Generazione guidata di `agent.json` e della directory dati `agent-data`.
  2. Inizializzazione inventario locale `network_hosts.csv` con apparati della VM.
  3. Diagnostica di rete & autenticazione verso il SentinelNet centrale.

Uso:
  # Inizializza configurazione e inventario locale sulla VM:
  python scripts/vm_agent_test_helper.py setup --central-url http://192.168.1.100:8765 \
                                                --site-id vm-lab \
                                                --token <TOKEN_MOSTRATO_SU_CENTRALE>

  # Aggiungi un apparato di test all'inventario locale della VM:
  python scripts/vm_agent_test_helper.py add-device --ip 192.168.56.10 \
                                                     --hostname sw-milano-vm \
                                                     --vendor cisco \
                                                     --username admin \
                                                     --password secret

  # Diagnostica connessione verso il centrale:
  python scripts/vm_agent_test_helper.py check --config agent.json
"""
import os
import sys
import json
import argparse
import csv
import requests

# Assicura importazione corretta da root del progetto
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

CSV_HEADERS = [
    "IP", "Hostname", "Vendor", "Model", "Driver", "Transport", "Port",
    "AuthGroup", "Username", "Password", "Secret", "SNMP_Community",
    "SNMP_Version", "Tenant", "Group", "Site", "Category", "Status", "Notes"
]


def setup_agent(args):
    data_dir = os.path.abspath(args.data_dir)
    os.makedirs(data_dir, exist_ok=True)

    config_content = {
        "central_url": args.central_url.rstrip("/"),
        "site_id": args.site_id,
        "token": args.token,
        "interval": args.interval,
        "verify_tls": not args.no_verify_tls,
        "data_dir": data_dir,
    }

    config_path = os.path.abspath(args.config_output)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config_content, f, indent=2)

    csv_path = os.path.join(data_dir, "network_hosts.csv")
    if not os.path.exists(csv_path):
        with open(csv_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADERS)

    print(f"[OK] Configurazione creata: {config_path}")
    print(f"[OK] Directory dati pronta: {data_dir}")
    print(f"[OK] Inventario locale: {csv_path}")
    print("\nPer avviare l'agente:")
    print(f"  python services/site_agent.py --config {config_path}")


def add_device(args):
    data_dir = os.path.abspath(args.data_dir)
    os.makedirs(data_dir, exist_ok=True)
    csv_path = os.path.join(data_dir, "network_hosts.csv")

    existing_rows = []
    if os.path.exists(csv_path):
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader, None)
            for row in reader:
                if row and row[0] != args.ip:
                    existing_rows.append(row)

    new_row = [
        args.ip, args.hostname, args.vendor, "VM-TestModel", "cisco_ios",
        "ssh", "22", "", args.username, args.password, args.secret,
        "public", "2c", "VM-Tenant", args.site_id, args.site_id,
        "Switch", "active", "VM Lab Test Device"
    ]

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADERS)
        for r in existing_rows:
            writer.writerow(r)
        writer.writerow(new_row)

    print(f"[OK] Dispositivo {args.ip} ({args.hostname}) aggiunto a {csv_path}")


def check_agent(args):
    if not os.path.exists(args.config):
        print(f"[ERRORE] File di configurazione non trovato: {args.config}")
        sys.exit(1)

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    central_url = cfg.get("central_url", "").rstrip("/")
    site_id = cfg.get("site_id", "")
    token = cfg.get("token", "")
    verify_tls = cfg.get("verify_tls", True)

    print(f"--- DIAGNOSTICA AGENTE VM ---")
    print(f"Centrale URL : {central_url}")
    print(f"Site ID      : {site_id}")
    print(f"Verify TLS   : {verify_tls}")

    headers = {
        "X-Site-Id": site_id,
        "X-Site-Token": token,
        "Content-Type": "application/json",
    }

    try:
        url = f"{central_url}/api/agent/heartbeat"
        r = requests.post(url, headers=headers, json={}, verify=verify_tls, timeout=10)
        if r.status_code == 200:
            print(f"[OK] Heartbeat riuscito! Risposta: {r.json()}")
        elif r.status_code == 401:
            print(f"[ERRORE 401] Autenticazione fallita: Token o Site ID non validi per la sede '{site_id}'.")
        else:
            print(f"[ERRORE {r.status_code}] Risposta inattesa: {r.text}")
    except Exception as e:
        print(f"[ERRORE CONNESSIONE] Impossibile raggiungere il centrale: {e}")


def main():
    parser = argparse.ArgumentParser(description="SentinelNet VM Agent Test Helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: setup
    p_setup = subparsers.add_parser("setup", help="Crea agent.json e inizializza directory dati")
    p_setup.add_argument("--central-url", required=True, help="URL base del centrale (es. http://192.168.1.100:8765)")
    p_setup.add_argument("--site-id", required=True, help="ID della sede (es. milano-vm)")
    p_setup.add_argument("--token", required=True, help="Token per-sede ottenuto dal centrale")
    p_setup.add_argument("--interval", type=int, default=15, help="Intervallo polling in secondi")
    p_setup.add_argument("--data-dir", default="./agent-data", help="Directory per inventario locale")
    p_setup.add_argument("--config-output", default="agent.json", help="Percorso del file agent.json")
    p_setup.add_argument("--no-verify-tls", action="store_true", help="Disabilita verifica TLS")

    # Subcommand: add-device
    p_add = subparsers.add_parser("add-device", help="Aggiungi apparato all'inventario locale VM")
    p_add.add_argument("--ip", required=True, help="IP del dispositivo (es. 192.168.56.10)")
    p_add.add_argument("--hostname", default="sw-vm-01", help="Hostname del dispositivo")
    p_add.add_argument("--vendor", default="cisco", help="Vendor (cisco, fortinet, etc.)")
    p_add.add_argument("--username", default="admin", help="Username SSH")
    p_add.add_argument("--password", default="adminpw", help="Password SSH")
    p_add.add_argument("--secret", default="", help="Password enable/secret")
    p_add.add_argument("--site-id", default="milano-vm", help="ID della sede")
    p_add.add_argument("--data-dir", default="./agent-data", help="Directory per inventario locale")

    # Subcommand: check
    p_check = subparsers.add_parser("check", help="Verifica connessione e token verso il centrale")
    p_check.add_argument("--config", default="agent.json", help="File agent.json da verificare")

    args = parser.parse_args()
    if args.command == "setup":
        setup_agent(args)
    elif args.command == "add-device":
        add_device(args)
    elif args.command == "check":
        check_agent(args)


if __name__ == "__main__":
    main()
