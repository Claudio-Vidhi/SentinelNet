# -*- coding: utf-8 -*-
"""Verifica che l'albero tracciato non contenga dati di un cliente reale.

Serve perche' `master` e `Dev` hanno lo stesso contenuto: non esiste piu' uno
strip che, per caso, teneva fuori dal pubblico i file di sviluppo. Tutto cio'
che si committa e' pubblicato, quindi il confine della privacy e' `git add`,
non il branch.

Tre controlli, ognuno nato da un modo diverso di far uscire dati veri:

1. **File di stato tracciati.** Un nuovo `data/*.json` (o `.db`, o un
   `network_hosts.csv` nella radice) e' tracciato per default: basta un
   `git add -A` dopo che lo strumento ha girato una volta sulla rete del
   cliente e la fuga e' fatta.
2. **Indirizzi IP pubblici.** In un repo di rete un IP e' il dato piu' facile
   da copiare senza pensarci. Sono ammessi solo gli spazi che non
   appartengono a nessuno: privati (RFC 1918), documentazione (RFC 5737),
   benchmark (RFC 2544), loopback, link-local, multicast, CGNAT e i resolver
   pubblici notori.
3. **Segreti.** Chiavi private PEM e token dei vendor incollati in un file.

Uso:
    uv run python scripts/check_no_private_data.py            # 0 = pulito
    uv run python scripts/check_no_private_data.py --verbose  # conta i file

Una riga che deve contenere un indirizzo pubblico per forza (un esempio di
documentazione di un vendor, un resolver citato per nome) si marca con il
commento `check-private-data: ok`, che la esclude.

Regola di riferimento: AGENTS.md, sezione "Protect real data".
"""

import ipaddress
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Estensioni che si leggono come testo. Un .png o un .db non si scansionano:
# il primo non ha IP, e il secondo non deve proprio essere tracciato (lo dice
# il controllo 1).
TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".js", ".ts", ".mjs", ".html", ".css",
    ".yml", ".yaml", ".toml", ".cfg", ".ini", ".conf", ".sh", ".ps1", ".csv",
    ".spec", ".service", ".sudoers", "",
}

# File di stato che non devono MAI essere tracciati. Non e' un doppione del
# .gitignore: e' la rete di sicurezza per quando qualcuno usa `git add -f`, o
# per quando una regola del .gitignore sparisce senza che nessuno se ne
# accorga.
FORBIDDEN_TRACKED = re.compile(
    r"(^|/)(network_hosts\.csv|users\.json|sites\.json|identities\.json"
    r"|groups\.json|vendors\.json|fortigate_tokens\.json|app_settings\.json"
    r"|login_attempts\.json|tenant_snmp\.json|ap_inventory\.json"
    r"|config_baselines\.json|detected_versions\.json|device_models\.json"
    r"|device_categories\.json|agent\.json|ssh_known_hosts.*"
    r"|.*\.db|.*\.db-wal|.*\.db-shm|secret\.key|jwt_secret\.key)$"
)

# Il testo che segnala un segreto, non il segreto stesso.
SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
     "chiave privata PEM"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "access key AWS"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "token GitHub"),
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "chiave API stile OpenAI"),
)

# Quattro ottetti e non di piu': i lookaround escludono gli OID SNMP
# (1.3.6.1.2.1...), che altrimenti producevano una decina di finti indirizzi
# per riga e rendevano il controllo inservibile.
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

# Resolver pubblici: compaiono nei test e nella documentazione come esempio di
# "un indirizzo fuori dalla LAN", e non appartengono a nessun cliente.
PUBLIC_RESOLVERS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222",
}

# Spazi che non sono di nessuno: documentazione (RFC 5737), benchmark
# (RFC 2544), CGNAT (RFC 6598), IETF protocol assignments (RFC 6890) e 240/4.
NEUTRAL_NETS = tuple(ipaddress.IPv4Network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15",
    "100.64.0.0/10", "192.0.0.0/24", "240.0.0.0/4",
    # Relay anycast 6to4: un prefisso, non l'indirizzo di qualcuno.
    "192.88.99.0/24",
))

# Alberi in cui una quadrupla puntata NON e' un indirizzo. I controlli CIS si
# numerano 5.4.1.1 e le versioni firmware sono 3.2.0.84: indistinguibili da un  (check-private-data: ok)
# IP per una regex, e nessuno dei due file vede mai dati di un cliente.
# Restano soggetti al controllo sui segreti.
IP_EXEMPT_PREFIXES = ("services/netsec_audit/", "drivers/")

# Il path data di un'icona SVG e' pieno di numeri separati da punti.
_SVG_LINE = re.compile(r"<path|\sd=\"M")


def _is_allowed_ip(text: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        # Non e' un indirizzo: un numero di versione, una maschera malformata,
        # una tupla qualsiasi. Non e' compito di questo script lamentarsene.
        return True
    if text in PUBLIC_RESOLVERS:
        return True
    if (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved
            or ip.is_link_local or ip.is_unspecified):
        return True
    return any(ip in net for net in NEUTRAL_NETS)


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


def scan():
    """Ritorna [(percorso, riga, spiegazione)]; lista vuota = albero pulito."""
    problems = []
    for rel in tracked_files():
        if FORBIDDEN_TRACKED.search(rel):
            problems.append((rel, 0, "file di stato tracciato"))
            continue
        path = ROOT / rel
        if path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if "check-private-data: ok" in line:
                continue
            for pattern, what in SECRET_PATTERNS:
                if pattern.search(line):
                    problems.append((rel, n, what))
            if rel.startswith(IP_EXEMPT_PREFIXES) or _SVG_LINE.search(line):
                continue
            for candidate in _IP_RE.findall(line):
                if not _is_allowed_ip(candidate):
                    problems.append(
                        (rel, n, f"IP pubblico {candidate}: usare RFC 5737 "
                                 "(192.0.2.x) o un indirizzo privato"))
    return problems


def main():
    problems = scan()
    if "--verbose" in sys.argv:
        print(f"File tracciati esaminati: {len(tracked_files())}")
    if not problems:
        print("Nessun dato privato nell'albero tracciato.")
        return 0
    for rel, line, what in problems:
        print(f"{rel}:{line}: {what}" if line else f"{rel}: {what}")
    print(f"\n{len(problems)} problemi. Vedi AGENTS.md, \"Protect real data\".")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
