# -*- coding: utf-8 -*-
"""Valutazioni di audit su configurazione FortiOS parsata.

Ogni regola e' una funzione pura ``ParsedConfig -> RuleOutcome``. Le regole
NON inventano verdetti: quando il blocco necessario alla valutazione non
esiste restituiscono UNKNOWN, tranne dove l'assenza E' essa stessa la
violazione (assenza di logging remoto, admin senza trusthost) — in quei casi
il comportamento e' documentato sulla singola regola.
"""

from typing import List, Set

from .model import FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome
from .parser import ParsedConfig, section_entries, section_present, setting

# --- Hardening ---------------------------------------------------------------

_INSECURE_ACCESS = {"telnet", "http"}
_WEAK_TLS = {"sslv3", "tlsv1-0", "tlsv1-1", "tlsv1.0", "tlsv1.1"}
_MAX_ADMINTIMEOUT = 30


def _ctx(*parts: str) -> str:
    return " / ".join(p for p in parts if p)


def check_management_protocols(cfg: ParsedConfig) -> RuleOutcome:
    """Telnet/HTTP abilitati su un'interfaccia (allowaccess)."""
    ifaces = section_entries(cfg, "system interface")
    if not ifaces:
        return RuleOutcome(
            UNKNOWN,
            "Sezione 'config system interface' assente: impossibile valutare "
            "i protocolli di gestione.")
    ev: List[Evidence] = []
    for name in sorted(ifaces):
        for r in ifaces[name]:
            if r.key != "allowaccess":
                continue
            bad = sorted({v.lower() for v in r.values} & _INSECURE_ACCESS)
            if bad:
                ev.append(Evidence(r.line, r.raw.strip(),
                                   _ctx("system interface", name)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Protocolli di amministrazione non cifrati (Telnet/HTTP) abilitati "
            "su %d interfaccia/e." % len(ev),
            ev)
    return RuleOutcome(
        PASS, "Tutte le interfacce usano solo protocolli di gestione cifrati.")


def check_tls_version(cfg: ParsedConfig) -> RuleOutcome:
    """Versione minima SSL/TLS ammessa per l'accesso amministrativo."""
    rec = (setting(cfg, "system global", "ssl-min-proto-version")
           or setting(cfg, "system global", "admin-https-ssl-versions"))
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare la versione minima TLS.")
        return RuleOutcome(
            WARN,
            "Versione minima TLS non impostata esplicitamente: si applica il "
            "default della piattaforma, che varia con la versione di FortiOS.")
    weak = sorted({v.lower() for v in rec.values} & _WEAK_TLS)
    if weak:
        return RuleOutcome(
            FAIL,
            "Versione TLS deprecata ammessa: %s." % ", ".join(weak),
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    return RuleOutcome(PASS, "Versione minima SSL/TLS conforme (TLS 1.2+).")


def check_idle_timeout(cfg: ParsedConfig) -> RuleOutcome:
    """Timeout di inattivita' della sessione amministrativa."""
    rec = setting(cfg, "system global", "admintimeout")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare il timeout amministrativo.")
        return RuleOutcome(
            WARN, "'admintimeout' non configurato: si applica il default "
                  "della piattaforma.")
    try:
        val = int(rec.values[0])
    except (IndexError, ValueError):
        return RuleOutcome(
            WARN, "Valore di 'admintimeout' non interpretabile.",
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    if val == 0:
        return RuleOutcome(
            FAIL, "Timeout amministrativo disabilitato (0): le sessioni non "
                  "scadono mai.",
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    if val > _MAX_ADMINTIMEOUT:
        return RuleOutcome(
            FAIL, "Timeout amministrativo troppo alto (%d minuti, massimo "
                  "consigliato %d)." % (val, _MAX_ADMINTIMEOUT),
            [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
    return RuleOutcome(
        PASS, "Timeout di inattivita' amministrativa configurato a %d minuti."
              % val)


def check_strong_crypto(cfg: ParsedConfig) -> RuleOutcome:
    """'set strong-crypto enable' (cifrari deboli disabilitati)."""
    rec = setting(cfg, "system global", "strong-crypto")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare 'strong-crypto'.")
        return RuleOutcome(
            WARN, "'strong-crypto' non impostato: cifrari deboli "
                  "potenzialmente ammessi.")
    if rec.values and rec.values[0].lower() == "enable":
        return RuleOutcome(PASS, "'strong-crypto' abilitato.")
    return RuleOutcome(
        WARN, "'strong-crypto' disabilitato: cifrari deboli ammessi.",
        [Evidence(rec.line, rec.raw.strip(), _ctx("system global"))])
