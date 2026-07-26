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


# --- Regole di accesso -------------------------------------------------------

_ANY_ADDR = {"all", "any"}
_ANY_SERVICE = {"all", "any"}
_ADMIN_PORTS = (22, 3389)
_BUILTIN_ADMIN_SERVICES = {"ssh", "rdp"}


def _policy_values(recs):
    """Mappa chiave -> valori minuscoli per una singola voce di policy."""
    out = {}
    for r in recs:
        out.setdefault(r.key, []).extend(v.lower() for v in r.values)
    return out


def _policy_line(recs, prefer="action"):
    for r in recs:
        if r.key == prefer:
            return r.line, r.raw.strip()
    return (recs[0].line, recs[0].raw.strip()) if recs else (0, "")


def wan_interfaces(cfg: ParsedConfig) -> Set[str]:
    """Interfacce con ruolo WAN.

    Preferisce 'set role wan'. Se nessuna interfaccia dichiara un ruolo
    (comune sulle configurazioni piu' vecchie) ricade sui nomi convenzionali.
    """
    ifaces = section_entries(cfg, "system interface")
    named = set()
    for name, recs in ifaces.items():
        for r in recs:
            if r.key == "role" and r.values and r.values[0].lower() == "wan":
                named.add(name)
    if named:
        return named
    return {n for n in ifaces
            if n.lower().startswith("wan") or n.lower() == "port1"}


def check_any_any_policy(cfg: ParsedConfig) -> RuleOutcome:
    """Policy che accetta qualunque sorgente verso qualunque destinazione."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare le regole di accesso.")
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        vals = _policy_values(policies[pid])
        if "accept" not in vals.get("action", []):
            continue
        if (set(vals.get("srcaddr", [])) & _ANY_ADDR
                and set(vals.get("dstaddr", [])) & _ANY_ADDR
                and set(vals.get("service", [])) & _ANY_SERVICE):
            line, raw = _policy_line(policies[pid])
            ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Trovate %d policy che accettano traffico any-to-any su qualunque "
            "servizio." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna policy any-to-any: sorgente, destinazione e servizio "
              "sono sempre specificati.")


def check_boundary_protection(cfg: ParsedConfig) -> RuleOutcome:
    """Traffico in INGRESSO da un'interfaccia WAN verso qualunque destinazione."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare la protezione del perimetro.")
    wan = wan_interfaces(cfg)
    if not wan:
        return RuleOutcome(
            UNKNOWN, "Nessuna interfaccia WAN identificabile: impossibile "
                     "valutare il confine di rete.")
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        vals = _policy_values(policies[pid])
        if "accept" not in vals.get("action", []):
            continue
        srcintf = set(vals.get("srcintf", []))
        if not srcintf & {w.lower() for w in wan}:
            continue
        if set(vals.get("dstaddr", [])) & _ANY_ADDR:
            line, raw = _policy_line(policies[pid])
            ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Trovate %d policy in ingresso da WAN verso qualunque "
            "destinazione interna." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna policy in ingresso da WAN verso destinazioni generiche.")


def _range_hits_admin_port(token: str) -> bool:
    """True se un token 'tcp-portrange' copre la 22 o la 3389."""
    token = token.split(":")[0]           # scarta la parte source-port
    for part in token.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                lo_i, hi_i = int(lo), int(hi)
            else:
                lo_i = hi_i = int(part)
        except ValueError:
            continue
        if any(lo_i <= p <= hi_i for p in _ADMIN_PORTS):
            return True
    return False


def _admin_service_names(cfg: ParsedConfig) -> Set[str]:
    """Servizi che risolvono a TCP 22/3389, inclusi i custom."""
    names = set(_BUILTIN_ADMIN_SERVICES)
    for name, recs in section_entries(cfg, "firewall service custom").items():
        for r in recs:
            if r.key == "tcp-portrange" and any(
                    _range_hits_admin_port(v) for v in r.values):
                names.add(name.lower())
    return names


def check_inbound_admin_ports(cfg: ParsedConfig) -> RuleOutcome:
    """SSH/RDP esposti da WAN verso sorgenti generiche (PCI-DSS 1.2)."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare l'esposizione delle porte amministrative.")
    wan = {w.lower() for w in wan_interfaces(cfg)}
    if not wan:
        return RuleOutcome(
            UNKNOWN, "Nessuna interfaccia WAN identificabile: impossibile "
                     "valutare l'esposizione delle porte amministrative.")
    admin_services = _admin_service_names(cfg)
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        vals = _policy_values(policies[pid])
        if "accept" not in vals.get("action", []):
            continue
        if not set(vals.get("srcintf", [])) & wan:
            continue
        if not set(vals.get("srcaddr", [])) & _ANY_ADDR:
            continue
        if set(vals.get("service", [])) & admin_services:
            line, raw = _policy_line(policies[pid], prefer="service")
            ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Porte amministrative (SSH 22 / RDP 3389) raggiungibili da "
            "Internet in %d policy." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna esposizione diretta di SSH/RDP verso reti pubbliche.")
