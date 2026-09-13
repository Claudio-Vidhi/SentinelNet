#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sonda di trasporto per un host Windows raggiunto via SSH.

I comandi PowerShell del driver sono gia' stati provati su un Windows vero
(docs/windows-collection.md §6). Quello che questa sonda verifica e' l'unica
cosa che resta in dubbio: **il trasporto**, cioe' netmiko 'generic' contro il
prompt di cmd.exe su una sessione SSH.

Usa lo STESSO percorso del triage (``resolve_driver`` piu' il
``core.net_ssh.ConnectHandler`` con gli stessi parametri di ``core_engine``),
non una copia: una sonda che apre la sessione a modo suo proverebbe se stessa.

    uv run python scripts/dev/windows_probe.py --ip 192.0.2.50 --user admin

La password si chiede al terminale se non la si passa con --password, e non
viene scritta da nessuna parte. Con --save si salva l'artefatto su file per
riguardarlo: quel file contiene hostname, seriali e indirizzi dell'host, quindi
va tenuto fuori dal repository (``data/`` e' gia' ignorata).

Prima di lanciarla, sulla VM, come amministratore:

    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
    Start-Service sshd
    Set-Service -Name sshd -StartupType Automatic
"""

import argparse
import getpass
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from ai import config_analyzer, windows_analyzer          # noqa: E402
from core import core_engine                              # noqa: E402
from drivers.windows import TRIAGE_COMMANDS               # noqa: E402


def probe(ip: str, user: str, password: str, port: int, timeout: int):
    # Il ConnectHandler del PROGETTO, non quello di netmiko: e' lo stesso che
    # usa core_engine, e passa dal bastione quando l'host sta dietro un sito
    # jump. Importare netmiko direttamente proverebbe un trasporto diverso da
    # quello del triage -- e tests/test_jump_site.py lo vieta per questo.
    from core.net_ssh import ConnectHandler

    driver_cls, netmiko_type = core_engine.resolve_driver("windows")
    print(f"driver: {driver_cls.__name__} su netmiko '{netmiko_type}'")

    params = {
        "device_type": netmiko_type,
        "host": ip,
        "username": user,
        "password": password,
        "port": port,
        "timeout": timeout,
        "auth_timeout": 10,
        "banner_timeout": 10,
    }

    t0 = time.time()
    with ConnectHandler(**params) as conn:
        print(f"connesso in {time.time() - t0:.1f}s")

        # Il punto di rottura piu' probabile: netmiko costruisce il modello di
        # terminazione di ogni comando dal prompt, e quello di cmd.exe
        # ('C:\\Users\\admin>') non e' quello di un apparato di rete.
        prompt = conn.find_prompt()
        print(f"prompt letto: {prompt!r}")

        # Nessuna modalita' enable su questa piattaforma: se qualcuno la
        # reintroduce, il comando finisce nell'output come testo.
        core_engine.maybe_enable(conn, netmiko_type, "")

        driver = driver_cls(conn)
        print(f"versione: {driver.get_version()}")
        print(f"modello:  {driver.get_model()}")
        print(f"seriale:  {driver.get_serial() or '(nessuno, o segnaposto)'}")

        parts, slow, empty = [], [], []
        for cmd, tag in TRIAGE_COMMANDS:
            t = time.time()
            try:
                out = conn.send_command(cmd, read_timeout=45)
            except Exception as e:                # noqa: BLE001 — e' una sonda
                print(f"  FALLITO {tag}: {type(e).__name__}: {e}")
                out = ""
            took = time.time() - t
            out = out if isinstance(out, str) else str(out or "")
            rows = [l for l in out.splitlines() if l.strip()]
            if took > 10:
                slow.append((tag, took))
            if not rows:
                empty.append(tag)
            print(f"  {took:5.1f}s {len(rows):4} righe  {tag}")
            parts.append(f"{tag}\n{out}")

        artefact = "\n".join(parts)

    print()
    if slow:
        print("comandi lenti (>10s), da guardare se la sessione va in timeout:")
        for tag, took in slow:
            print(f"  {took:.1f}s {tag}")
    if empty:
        # Su questa piattaforma una sezione vuota di solito significa "account
        # non amministratore", non "comando rotto".
        print("sezioni vuote (spesso: account non amministratore):")
        for tag in empty:
            print(f"  {tag}")
    return artefact


def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ip", required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--password", default=None,
                   help="se assente, viene chiesta al terminale e non salvata")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--save", metavar="FILE",
                   help="scrive l'artefatto su FILE (contiene dati dell'host: "
                        "tenerlo fuori dal repository)")
    args = p.parse_args()

    password = args.password or getpass.getpass(
        f"Password di {args.user}@{args.ip}: ")

    try:
        artefact = probe(args.ip, args.user, password, args.port, args.timeout)
    except Exception as e:                        # noqa: BLE001 — e' una sonda
        print(f"\nconnessione fallita: {type(e).__name__}: {e}")
        print("\nDa controllare, nell'ordine:")
        print("  1. il servizio sshd gira?   Get-Service sshd")
        print("  2. la porta risponde?       Test-NetConnection <ip> -Port 22")
        print("  3. le credenziali entrano?  ssh utente@<ip> da un terminale")
        return 1

    print()
    kind = config_analyzer.detect_config_type(artefact)
    print(f"detect_config_type: {kind}",
          "OK" if kind == "windows" else "<-- ATTESO 'windows'")
    env = windows_analyzer.analyze(artefact)
    if env.get("error"):
        print("l'analizzatore e' andato in errore: vedi il log")
        return 1
    print(f"sezioni popolate: {len(env['sections'])}")
    for s in env["sections"]:
        print(f"  {s['id']:16} righe={len(s['rows']):4}")
    hostname = core_engine.extract_hostname_from_config(artefact)
    print(f"hostname estratto: {hostname or '(nessuno) <-- sarebbe un difetto'}")

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            f.write(artefact)
        print(f"\nartefatto scritto in {args.save}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
