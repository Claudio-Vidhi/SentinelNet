# -*- coding: utf-8 -*-
"""Valutazioni di audit su configurazione FortiOS parsata.

Ogni regola e' una funzione pura ``ParsedConfig -> RuleOutcome``. Le regole
NON inventano verdetti: quando il blocco necessario alla valutazione non
esiste restituiscono UNKNOWN, tranne dove l'assenza E' essa stessa la
violazione (assenza di logging remoto, admin senza trusthost) — in quei casi
il comportamento e' documentato sulla singola regola.
"""

from typing import List, Optional, Set, Tuple

from .model import FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome
from .parser import (ConfigRecord, ParsedConfig, section_entries,
                     section_present, setting)

# --- Hardening ---------------------------------------------------------------

_INSECURE_ACCESS = {"telnet", "http"}
_WEAK_TLS = {"sslv3", "tlsv1-0", "tlsv1-1", "tlsv1.0", "tlsv1.1"}
# CIS Fortinet FortiGate 7.4.x, raccomandazione 2.4.4: 15 minuti.
_MAX_ADMINTIMEOUT = 15


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


# --- Identita' e logging -----------------------------------------------------

_DEFAULT_COMMUNITIES = {"public", "private"}
# I valori di un trusthost sono confrontati come INSIEME, quindi
# 'set trusthost1 0.0.0.0 0.0.0.0' si riduce a {"0.0.0.0"}.
_UNRESTRICTED_TRUSTHOST = ({"0.0.0.0"}, {"0.0.0.0/0"})


def check_admin_trusthost(cfg: ParsedConfig) -> RuleOutcome:
    """Account amministrativi raggiungibili da qualunque IP (NIST AC-17).

    ASSENZA COME VIOLAZIONE: un account senza alcun 'trusthost' e' raggiungibile
    da ovunque per default FortiOS, quindi vale FAIL e non UNKNOWN. E' invece
    UNKNOWN l'assenza dell'intero blocco 'config system admin'.
    """
    admins = section_entries(cfg, "system admin")
    if not admins:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system admin' assente: impossibile "
                     "valutare le restrizioni di accesso amministrativo.")
    ev: List[Evidence] = []
    for name in sorted(admins):
        recs = admins[name]
        hosts = [r for r in recs if r.key.startswith("trusthost")]
        if not hosts:
            line = recs[0].line if recs else 0
            ev.append(Evidence(
                line, "nessun 'trusthost' definito per l'account",
                _ctx("system admin", name)))
            continue
        for r in hosts:
            vals = {v.lower() for v in r.values}
            if any(vals == unrestricted
                   for unrestricted in _UNRESTRICTED_TRUSTHOST):
                ev.append(Evidence(r.line, r.raw.strip(),
                                   _ctx("system admin", name)))
    if ev:
        return RuleOutcome(
            FAIL,
            "%d account amministrativi accessibili da qualunque IP sorgente."
            % len(ev), ev)
    return RuleOutcome(
        PASS, "Tutti gli account amministrativi sono ristretti a sottoreti "
              "di gestione fidate.")


def check_snmp_community(cfg: ParsedConfig) -> RuleOutcome:
    """Community string SNMP v1/v2c di default."""
    if not section_present(cfg, "system snmp community"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system snmp community' assente: "
                     "impossibile valutare le community SNMP.")
    communities = section_entries(cfg, "system snmp community")
    ev: List[Evidence] = []
    for name in sorted(communities):
        for r in communities[name]:
            if (r.key == "name" and r.values
                    and r.values[0].lower() in _DEFAULT_COMMUNITIES):
                ev.append(Evidence(r.line, r.raw.strip(),
                                   _ctx("system snmp community", name)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Community SNMP di default in chiaro ('public'/'private'): %d."
            % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessuna community SNMP di default configurata.")


def check_syslog(cfg: ParsedConfig) -> RuleOutcome:
    """Inoltro dei log verso un syslog remoto (NIST AU-2/AU-12, PCI 10.2).

    ASSENZA COME VIOLAZIONE: se il blocco non esiste non c'e' alcun logging
    remoto configurato, che e' esattamente il controllo che fallisce.
    """
    if not section_present(cfg, "log syslogd setting"):
        return RuleOutcome(
            FAIL,
            "Nessun inoltro syslog remoto configurato: la sezione "
            "'config log syslogd setting' non esiste.",
            [Evidence(0, "blocco 'config log syslogd setting' assente",
                      "log syslogd setting")])
    status = setting(cfg, "log syslogd setting", "status")
    server = setting(cfg, "log syslogd setting", "server")
    ev: List[Evidence] = []
    if (status is None or not status.values
            or status.values[0].lower() != "enable"):
        ev.append(Evidence(
            status.line if status else 0,
            status.raw.strip() if status else "'status' non impostato a enable",
            _ctx("log syslogd setting")))
    if server is None or not server.values:
        ev.append(Evidence(
            server.line if server else 0,
            server.raw.strip() if server else "nessun 'server' syslog definito",
            _ctx("log syslogd setting")))
    if ev:
        return RuleOutcome(
            FAIL, "Inoltro syslog remoto non attivo o privo di destinazione.",
            ev)
    return RuleOutcome(
        PASS, "Inoltro dei log verso syslog remoto attivo e configurato.")


def check_vendor_defaults(cfg: ParsedConfig) -> RuleOutcome:
    """Account di default e policy password (PCI-DSS 2.2)."""
    admins = section_entries(cfg, "system admin")
    has_policy_block = section_present(cfg, "system password-policy")
    if not admins and not has_policy_block:
        return RuleOutcome(
            UNKNOWN, "Ne' 'config system admin' ne' "
                     "'config system password-policy' presenti: impossibile "
                     "valutare i default di fabbrica.")
    ev: List[Evidence] = []
    for name in sorted(admins):
        if name.lower() == "admin":
            recs = admins[name]
            ev.append(Evidence(
                recs[0].line if recs else 0,
                "account amministrativo di default 'admin' presente",
                _ctx("system admin", name)))
    if has_policy_block:
        status = setting(cfg, "system password-policy", "status")
        if (status is None or not status.values
                or status.values[0].lower() != "enable"):
            ev.append(Evidence(
                status.line if status else 0,
                status.raw.strip() if status
                else "'status' della password-policy non abilitato",
                _ctx("system password-policy")))
    else:
        ev.append(Evidence(
            0, "nessuna 'config system password-policy' definita",
            _ctx("system password-policy")))
    if ev:
        return RuleOutcome(
            FAIL,
            "Rilevati default di fabbrica o policy password non applicata "
            "(%d riscontri)." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessun account di default e policy password attiva.")


# =============================================================================
# CIS Fortinet FortiGate 7.4.x — controlli aggiuntivi
#
# Le regole qui sotto seguono la stessa convenzione di quelle sopra: blocco
# assente -> UNKNOWN, salvo dove l'assenza E' la violazione (e in quel caso
# lo dice la docstring). Il numero di raccomandazione sta in ``benchmarks.py``,
# non qui: una funzione puo' servire piu' benchmark.
# =============================================================================

def _ev1(rec: ConfigRecord, *ctx: str) -> Evidence:
    return Evidence(rec.line, rec.raw.strip(), _ctx(*ctx))


def _records_under(cfg: ParsedConfig,
                   *path: str) -> List[ConfigRecord]:
    """Tutti i record il cui path inizia con ``path`` (blocchi annidati inclusi)."""
    return [r for r in cfg.records if r.path[:len(path)] == path]


def _flag(cfg: ParsedConfig, section: str, key: str, want: str,
          subject: str, why: str,
          missing: str = WARN) -> RuleOutcome:
    """Controllo di un interruttore enable/disable in un blocco singolo."""
    rec = setting(cfg, section, key)
    if rec is None:
        if not section_present(cfg, section):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config %s' assente: impossibile valutare "
                         "%s." % (section, subject))
        return RuleOutcome(
            missing,
            "'%s' non impostato: vale il default della piattaforma." % key,
            [Evidence(0, "nessun 'set %s %s'" % (key, want), _ctx(section))])
    if rec.values and rec.values[0].lower() == want:
        return RuleOutcome(PASS, "%s: conforme ('%s %s')."
                                 % (subject.capitalize(), key, want))
    return RuleOutcome(FAIL, why, [_ev1(rec, section)])


def _int_value(rec: ConfigRecord) -> Optional[int]:
    try:
        return int(rec.values[0])
    except (IndexError, ValueError):
        return None


# --- 1.x Rete ----------------------------------------------------------------

def check_dns_configured(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 1.1 — server DNS configurati.

    ASSENZA COME VIOLAZIONE: senza il blocco non c'e' alcun DNS impostato, che
    e' esattamente cio' che il controllo verifica.
    """
    if not section_present(cfg, "system dns"):
        return RuleOutcome(
            FAIL, "Nessun server DNS configurato: la sezione "
                  "'config system dns' non esiste.",
            [Evidence(0, "blocco 'config system dns' assente", "system dns")])
    servers = [setting(cfg, "system dns", k)
               for k in ("primary", "secondary")]
    present = [r for r in servers if r is not None and r.values]
    if not present:
        return RuleOutcome(
            FAIL, "Blocco DNS presente ma nessun server risolutore definito.",
            [Evidence(0, "nessun 'set primary' / 'set secondary'",
                      "system dns")])
    if len(present) < 2:
        return RuleOutcome(
            WARN, "Un solo server DNS configurato: la risoluzione si ferma se "
                  "quel server non risponde.",
            [_ev1(present[0], "system dns")])
    return RuleOutcome(PASS, "Due server DNS configurati.")


def check_intrazone_deny(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 1.2 — traffico intra-zona negato per default."""
    zones = section_entries(cfg, "system zone")
    if not zones:
        return RuleOutcome(
            UNKNOWN, "Nessuna zona definita: il traffico intra-zona non e' "
                     "applicabile.")
    ev: List[Evidence] = []
    for name in sorted(zones):
        rec = next((r for r in zones[name] if r.key == "intrazone"), None)
        if rec is None:
            ev.append(Evidence(
                zones[name][0].line if zones[name] else 0,
                "nessun 'set intrazone deny' (default: allow)",
                _ctx("system zone", name)))
        elif not rec.values or rec.values[0].lower() != "deny":
            ev.append(_ev1(rec, "system zone", name))
    if ev:
        return RuleOutcome(
            FAIL,
            "%d zone consentono il traffico fra le proprie interfacce senza "
            "passare da una policy." % len(ev), ev)
    return RuleOutcome(PASS, "Tutte le zone negano il traffico intra-zona.")


# --- 2.1 Impostazioni di sistema ---------------------------------------------

def check_login_banners(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.1 / 2.1.2 — banner pre-login e post-login."""
    if not section_present(cfg, "system global"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system global' assente: impossibile "
                     "valutare i banner di accesso.")
    ev: List[Evidence] = []
    for key in ("pre-login-banner", "post-login-banner"):
        rec = setting(cfg, "system global", key)
        if rec is None:
            ev.append(Evidence(0, "nessun 'set %s enable'" % key,
                               _ctx("system global")))
        elif not rec.values or rec.values[0].lower() != "enable":
            ev.append(_ev1(rec, "system global"))
    if ev:
        return RuleOutcome(
            FAIL, "Banner di accesso mancanti (%d su 2): nessuna avvertenza "
                  "legale prima o dopo l'autenticazione." % len(ev), ev)
    return RuleOutcome(PASS, "Banner pre-login e post-login entrambi attivi.")


def check_timezone(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.3 — fuso orario impostato esplicitamente."""
    rec = setting(cfg, "system global", "timezone")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare il fuso orario.")
        return RuleOutcome(
            WARN, "Fuso orario non impostato: i timestamp dei log usano il "
                  "default di fabbrica e non corrispondono all'ora locale.",
            [Evidence(0, "nessun 'set timezone'", _ctx("system global"))])
    return RuleOutcome(PASS, "Fuso orario impostato esplicitamente.")


def check_ntp(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.4 — sincronizzazione oraria attiva con server dichiarati."""
    if not section_present(cfg, "system ntp"):
        return RuleOutcome(
            FAIL, "Nessuna sincronizzazione oraria configurata: la sezione "
                  "'config system ntp' non esiste.",
            [Evidence(0, "blocco 'config system ntp' assente", "system ntp")])
    ev: List[Evidence] = []
    sync = setting(cfg, "system ntp", "ntpsync")
    if sync is None or not sync.values or sync.values[0].lower() != "enable":
        ev.append(_ev1(sync, "system ntp") if sync
                  else Evidence(0, "nessun 'set ntpsync enable'", "system ntp"))
    # I server custom stanno in 'config ntpserver', annidata dentro 'system ntp'.
    servers = {r.path[2] for r in _records_under(cfg, "system ntp", "ntpserver")
               if len(r.path) > 2}
    ntp_type = setting(cfg, "system ntp", "type")
    is_custom = (ntp_type is not None and ntp_type.values
                 and ntp_type.values[0].lower() == "custom")
    if is_custom and not servers:
        ev.append(Evidence(ntp_type.line if ntp_type else 0,
                           "'type custom' senza alcun server in "
                           "'config ntpserver'", "system ntp"))
    if ev:
        return RuleOutcome(
            FAIL, "Sincronizzazione oraria non attiva o priva di sorgente: "
                  "i log non sono correlabili fra apparati.", ev)
    return RuleOutcome(
        PASS, "Sincronizzazione NTP attiva%s."
              % (" con %d server dichiarati" % len(servers) if servers else ""))


def check_hostname(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.5 — hostname diverso da quello di fabbrica."""
    rec = setting(cfg, "system global", "hostname")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(
                UNKNOWN, "Sezione 'config system global' assente: impossibile "
                         "valutare l'hostname.")
        return RuleOutcome(
            WARN, "Hostname non impostato: l'apparato resta col nome di "
                  "fabbrica e i log non lo distinguono dagli altri.",
            [Evidence(0, "nessun 'set hostname'", _ctx("system global"))])
    name = (rec.values[0] if rec.values else "").strip()
    # Il default di fabbrica e' il modello, spesso col numero di serie: e' il
    # nome che l'apparato ha prima di essere messo in servizio.
    if not name or name.lower().startswith(("fortigate", "fgt")):
        return RuleOutcome(
            FAIL, "Hostname ancora quello di fabbrica.",
            [_ev1(rec, "system global")])
    return RuleOutcome(PASS, "Hostname personalizzato.")


def check_auto_install(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.7 — installazione automatica da USB disabilitata."""
    if not section_present(cfg, "system auto-install"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system auto-install' assente: vale il "
                     "default della piattaforma.")
    ev: List[Evidence] = []
    for key in ("auto-install-config", "auto-install-image"):
        rec = setting(cfg, "system auto-install", key)
        if rec is not None and rec.values and rec.values[0].lower() == "enable":
            ev.append(_ev1(rec, "system auto-install"))
    if ev:
        return RuleOutcome(
            FAIL,
            "Installazione automatica da chiavetta USB attiva: chi ha accesso "
            "fisico puo' sostituire configurazione o firmware al riavvio.", ev)
    return RuleOutcome(PASS, "Installazione automatica da USB disabilitata.")


def check_static_key_ciphers(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.8 — 'ssl-static-key-ciphers disable' (perfect forward secrecy)."""
    return _flag(
        cfg, "system global", "ssl-static-key-ciphers", "disable",
        "cifrari a chiave statica",
        "Cifrari a chiave statica ammessi: senza forward secrecy, chi "
        "compromette la chiave del server puo' decifrare il traffico "
        "registrato in passato.")


def check_admin_https_redirect(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.9 — redirect da HTTP a HTTPS sulla GUI."""
    return _flag(
        cfg, "system global", "admin-https-redirect", "enable",
        "redirect HTTPS della GUI",
        "Redirect HTTPS disabilitato: la GUI resta raggiungibile in chiaro "
        "sugli indirizzi dove HTTP e' ammesso.")


def check_cpu_log_threshold(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.12 — 'log-single-cpu-high enable'."""
    return _flag(
        cfg, "system global", "log-single-cpu-high", "enable",
        "allarme di saturazione CPU",
        "Saturazione di un singolo core non registrata: un processo che "
        "satura una CPU passa inosservato finche' il carico medio resta basso.")


def check_gui_hostname_display(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.13 — hostname mostrato nella GUI."""
    return _flag(
        cfg, "system global", "gui-display-hostname", "enable",
        "hostname nella GUI",
        "Hostname non mostrato nella GUI: chi amministra piu' apparati non "
        "distingue a colpo d'occhio su quale sta operando.")


# --- 2.2 Password e blocco account -------------------------------------------

_MIN_PASSWORD_LENGTH = 8            # CIS 2.2.1
_MAX_LOCKOUT_THRESHOLD = 3          # CIS 2.2.2
_MIN_LOCKOUT_DURATION = 900         # CIS 2.2.2, secondi


def check_password_policy_strength(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.2.1 — policy password con lunghezza e complessita' minime.

    Distinta da ``check_vendor_defaults``, che si limita a verificare che la
    policy sia ATTIVA: qui si guarda cosa impone.
    """
    if not section_present(cfg, "system password-policy"):
        return RuleOutcome(
            FAIL, "Nessuna policy password definita: la sezione "
                  "'config system password-policy' non esiste.",
            [Evidence(0, "blocco 'config system password-policy' assente",
                      "system password-policy")])
    sec = "system password-policy"
    ev: List[Evidence] = []
    length = setting(cfg, sec, "minimum-length")
    if length is None:
        ev.append(Evidence(0, "nessun 'set minimum-length'", _ctx(sec)))
    else:
        val = _int_value(length)
        if val is None or val < _MIN_PASSWORD_LENGTH:
            ev.append(_ev1(length, sec))
    # Le quattro classi di caratteri richieste dal benchmark.
    for key in ("min-lower-case-letter", "min-upper-case-letter",
                "min-non-alphanumeric", "min-number"):
        rec = setting(cfg, sec, key)
        val = _int_value(rec) if rec is not None else None
        if val is None or val < 1:
            ev.append(_ev1(rec, sec) if rec is not None
                      else Evidence(0, "nessun 'set %s 1'" % key, _ctx(sec)))
    if ev:
        return RuleOutcome(
            FAIL,
            "Policy password sotto i requisiti minimi (%d parametri non "
            "conformi): lunghezza minima %d caratteri e almeno un carattere "
            "per ciascuna delle quattro classi."
            % (len(ev), _MIN_PASSWORD_LENGTH), ev)
    return RuleOutcome(
        PASS, "Policy password conforme: almeno %d caratteri con tutte e "
              "quattro le classi richieste." % _MIN_PASSWORD_LENGTH)


def check_admin_lockout(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.2.2 — soglia e durata del blocco dopo tentativi falliti."""
    if not section_present(cfg, "system global"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system global' assente: impossibile "
                     "valutare il blocco degli account.")
    ev: List[Evidence] = []
    thr = setting(cfg, "system global", "admin-lockout-threshold")
    if thr is None:
        ev.append(Evidence(0, "nessun 'set admin-lockout-threshold %d'"
                           % _MAX_LOCKOUT_THRESHOLD, _ctx("system global")))
    else:
        val = _int_value(thr)
        if val is None or val > _MAX_LOCKOUT_THRESHOLD:
            ev.append(_ev1(thr, "system global"))
    dur = setting(cfg, "system global", "admin-lockout-duration")
    if dur is None:
        ev.append(Evidence(0, "nessun 'set admin-lockout-duration %d'"
                           % _MIN_LOCKOUT_DURATION, _ctx("system global")))
    else:
        val = _int_value(dur)
        if val is None or val < _MIN_LOCKOUT_DURATION:
            ev.append(_ev1(dur, "system global"))
    if ev:
        return RuleOutcome(
            FAIL,
            "Blocco degli account amministrativi troppo permissivo: servono "
            "al massimo %d tentativi e almeno %d secondi di blocco, altrimenti "
            "un attacco a forza bruta resta praticabile."
            % (_MAX_LOCKOUT_THRESHOLD, _MIN_LOCKOUT_DURATION), ev)
    return RuleOutcome(
        PASS, "Blocco account dopo %d tentativi per almeno %d secondi."
              % (_MAX_LOCKOUT_THRESHOLD, _MIN_LOCKOUT_DURATION))


# --- 2.3 SNMP -----------------------------------------------------------------

def check_snmp_v3_only(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.3.2 — solo SNMPv3; nessuna community v1/v2c.

    Complementare a ``check_snmp_community``, che guarda i NOMI di default:
    qui il problema e' il protocollo, che trasmette la community in chiaro
    qualunque nome le si dia.
    """
    has_community = section_present(cfg, "system snmp community")
    has_user = section_present(cfg, "system snmp user")
    if not has_community and not has_user:
        return RuleOutcome(
            UNKNOWN, "Nessuna configurazione SNMP presente: nulla da valutare.")
    communities = section_entries(cfg, "system snmp community")
    ev: List[Evidence] = []
    for name in sorted(communities):
        recs = communities[name]
        status = next((r for r in recs if r.key == "status"), None)
        if status is not None and status.values \
                and status.values[0].lower() == "disable":
            continue
        ev.append(Evidence(
            recs[0].line if recs else 0,
            "community SNMP v1/v2c attiva",
            _ctx("system snmp community", name)))
    if ev:
        return RuleOutcome(
            FAIL,
            "%d community SNMP v1/v2c attive: la community viaggia in chiaro "
            "e vale come credenziale." % len(ev), ev)
    if not has_user:
        return RuleOutcome(
            WARN, "Nessuna community v1/v2c attiva ma nemmeno un utente "
                  "SNMPv3: il monitoraggio SNMP non e' configurato.",
            [Evidence(0, "nessuna 'config system snmp user'",
                      "system snmp user")])
    return RuleOutcome(PASS, "Solo SNMPv3 in uso.")


# --- 2.4 Amministrazione ------------------------------------------------------

_DEFAULT_ADMIN_PORTS = {"admin-sport": 443, "admin-ssh-port": 22}


def check_admin_ports_changed(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.4.7 — porte amministrative spostate dai valori di default."""
    if not section_present(cfg, "system global"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system global' assente: impossibile "
                     "valutare le porte amministrative.")
    ev: List[Evidence] = []
    for key, default in sorted(_DEFAULT_ADMIN_PORTS.items()):
        rec = setting(cfg, "system global", key)
        if rec is None:
            ev.append(Evidence(0, "'%s' non impostato: vale il default %d"
                               % (key, default), _ctx("system global")))
        elif _int_value(rec) == default:
            ev.append(_ev1(rec, "system global"))
    if ev:
        return RuleOutcome(
            WARN,
            "Porte amministrative sui valori di default (%d su 2): non e' una "
            "vulnerabilita' di per se', ma le scansioni di massa le trovano "
            "per prime." % len(ev), ev)
    return RuleOutcome(PASS, "Porte amministrative spostate dai default.")


def check_local_in_policy(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.4.6 — policy local-in a protezione dei servizi dell'apparato."""
    if not section_present(cfg, "firewall local-in-policy"):
        return RuleOutcome(
            WARN,
            "Nessuna policy 'local-in': il traffico diretto all'apparato e' "
            "filtrato solo da 'allowaccess', che non distingue le sorgenti.",
            [Evidence(0, "blocco 'config firewall local-in-policy' assente",
                      "firewall local-in-policy")])
    entries = section_entries(cfg, "firewall local-in-policy")
    if not entries:
        return RuleOutcome(
            WARN, "Blocco 'local-in-policy' presente ma vuoto.",
            [Evidence(0, "nessuna voce definita", "firewall local-in-policy")])
    return RuleOutcome(
        PASS, "%d policy 'local-in' a protezione dei servizi dell'apparato."
              % len(entries))


# --- 2.5 Alta disponibilita' --------------------------------------------------

def check_ha_configured(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.5.1 / 2.5.2 — cluster HA con interfacce monitorate.

    UNKNOWN quando l'apparato non e' in cluster: un nodo singolo e' una scelta
    architetturale, non una violazione che questo motore possa giudicare.
    """
    if not section_present(cfg, "system ha"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config system ha' assente: apparato non in "
                     "configurazione di alta disponibilita'.")
    mode = setting(cfg, "system ha", "mode")
    if mode is None or not mode.values \
            or mode.values[0].lower() in ("standalone", ""):
        return RuleOutcome(
            UNKNOWN, "HA in modalita' standalone: nessun cluster da valutare.")
    monitor = setting(cfg, "system ha", "monitor")
    if monitor is None or not monitor.values:
        return RuleOutcome(
            FAIL,
            "Cluster HA senza interfacce monitorate: il failover non scatta "
            "se cade un collegamento dati, solo se cade il nodo.",
            [_ev1(mode, "system ha")])
    return RuleOutcome(
        PASS, "Cluster HA in modalita' '%s' con %d interfacce monitorate."
              % (mode.values[0], len(monitor.values)))


# --- 3.x / 4.x Igiene delle policy -------------------------------------------

_SECURITY_PROFILES = ("av-profile", "ips-sensor", "webfilter-profile",
                      "application-list", "dnsfilter-profile",
                      "ssl-ssh-profile", "file-filter-profile",
                      "emailfilter-profile")


def _accept_policies(cfg: ParsedConfig
                     ) -> List[Tuple[str, List[ConfigRecord]]]:
    policies = section_entries(cfg, "firewall policy")
    out = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        vals = _policy_values(policies[pid])
        if "accept" in vals.get("action", []):
            out.append((pid, policies[pid]))
    return out


def check_policy_logging(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 7.x — registrazione del traffico su ogni policy che accetta.

    ASSENZA COME VIOLAZIONE all'interno della singola policy: senza
    'set logtraffic' FortiOS registra solo le sessioni con security profile,
    quindi il traffico semplicemente consentito non lascia traccia.
    """
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare la registrazione del traffico.")
    ev: List[Evidence] = []
    for pid, recs in _accept_policies(cfg):
        rec = next((r for r in recs if r.key == "logtraffic"), None)
        if rec is None:
            ev.append(Evidence(
                recs[0].line if recs else 0,
                "nessun 'set logtraffic all'",
                _ctx("firewall policy", pid)))
        elif rec.values and rec.values[0].lower() == "disable":
            ev.append(_ev1(rec, "firewall policy", pid))
    if ev:
        return RuleOutcome(
            FAIL,
            "%d policy accettano traffico senza registrarlo: quel traffico "
            "non compare in nessuna indagine successiva." % len(ev), ev)
    return RuleOutcome(
        PASS, "Tutte le policy che accettano traffico lo registrano.")


def check_policy_security_profiles(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 4.x — profili di sicurezza applicati al traffico in uscita da WAN."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare i profili di sicurezza.")
    wan = {w.lower() for w in wan_interfaces(cfg)}
    if not wan:
        return RuleOutcome(
            UNKNOWN, "Nessuna interfaccia WAN identificabile: impossibile "
                     "stabilire quali policy attraversano il perimetro.")
    ev: List[Evidence] = []
    for pid, recs in _accept_policies(cfg):
        vals = _policy_values(recs)
        if not set(vals.get("dstintf", [])) & wan:
            continue
        if any(k in vals for k in _SECURITY_PROFILES):
            continue
        line, raw = _policy_line(recs)
        ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            WARN,
            "%d policy instradano traffico verso Internet senza alcun profilo "
            "di ispezione: l'apparato le tratta come semplice routing."
            % len(ev), ev)
    return RuleOutcome(
        PASS, "Ogni policy verso Internet applica almeno un profilo di "
              "ispezione.")


def check_policy_comments(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 3.x — ogni policy documentata da un commento."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(
            UNKNOWN, "Sezione 'config firewall policy' assente: impossibile "
                     "valutare la documentazione delle regole.")
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        recs = policies[pid]
        if any(r.key in ("comments", "comment") and r.values for r in recs):
            continue
        line, raw = _policy_line(recs)
        ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(
            WARN,
            "%d policy prive di commento: senza una motivazione registrata "
            "nessuno se la sente di rimuoverle, e restano per sempre."
            % len(ev), ev)
    return RuleOutcome(PASS, "Tutte le policy sono documentate.")


# --- 6.x VPN ------------------------------------------------------------------

def check_sslvpn_tls(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 6.1.2 — versione TLS minima del portale SSL-VPN."""
    if not section_present(cfg, "vpn ssl settings"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config vpn ssl settings' assente: SSL-VPN non "
                     "configurata.")
    rec = (setting(cfg, "vpn ssl settings", "ssl-min-proto-ver")
           or setting(cfg, "vpn ssl settings", "ssl-min-proto-version"))
    if rec is None:
        return RuleOutcome(
            WARN, "Versione TLS minima della SSL-VPN non impostata: vale il "
                  "default della piattaforma.",
            [Evidence(0, "nessun 'set ssl-min-proto-ver tls1-2'",
                      "vpn ssl settings")])
    val = (rec.values[0].lower() if rec.values else "")
    if val in ("tls1-2", "tls1-3", "tlsv1-2", "tlsv1-3"):
        return RuleOutcome(PASS, "SSL-VPN limitata a TLS 1.2 o superiore.")
    return RuleOutcome(
        FAIL, "SSL-VPN accetta TLS deprecato ('%s')." % val,
        [_ev1(rec, "vpn ssl settings")])


def check_sslvpn_source_restriction(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 6.1.x — portale SSL-VPN ristretto per indirizzo sorgente."""
    if not section_present(cfg, "vpn ssl settings"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config vpn ssl settings' assente: SSL-VPN non "
                     "configurata.")
    rec = setting(cfg, "vpn ssl settings", "source-address")
    if rec is None or not rec.values:
        return RuleOutcome(
            WARN,
            "Portale SSL-VPN raggiungibile da qualunque indirizzo: senza "
            "'source-address' l'unica barriera sono le credenziali.",
            [Evidence(0, "nessun 'set source-address'", "vpn ssl settings")])
    if {v.lower() for v in rec.values} & _ANY_ADDR:
        return RuleOutcome(
            FAIL, "Portale SSL-VPN esposto a 'all': restrizione sorgente "
                  "presente ma inefficace.",
            [_ev1(rec, "vpn ssl settings")])
    return RuleOutcome(
        PASS, "Accesso al portale SSL-VPN ristretto per indirizzo sorgente.")


# --- 7.x Logging --------------------------------------------------------------

def check_syslog_encrypted(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 7.x — inoltro syslog cifrato (TLS).

    Si applica solo se un syslog remoto e' configurato: la sua ASSENZA e' gia'
    la violazione segnalata da ``check_syslog``, e ripeterla qui conterebbe lo
    stesso problema due volte nel punteggio.
    """
    if not section_present(cfg, "log syslogd setting"):
        return RuleOutcome(
            UNKNOWN, "Nessun syslog remoto configurato: la cifratura del "
                     "trasporto non e' applicabile.")
    status = setting(cfg, "log syslogd setting", "status")
    if status is None or not status.values \
            or status.values[0].lower() != "enable":
        return RuleOutcome(
            UNKNOWN, "Inoltro syslog non attivo: la cifratura del trasporto "
                     "non e' applicabile.")
    rec = setting(cfg, "log syslogd setting", "enc-algorithm")
    if rec is not None and rec.values \
            and rec.values[0].lower() in ("high", "high-medium", "low"):
        return RuleOutcome(
            PASS, "Inoltro syslog cifrato ('enc-algorithm %s')."
                  % rec.values[0])
    return RuleOutcome(
        WARN,
        "Log inviati al syslog remoto in chiaro: chi intercetta il segmento "
        "legge indirizzi, utenti e destinazioni di ogni sessione.",
        [_ev1(rec, "log syslogd setting") if rec is not None
         else Evidence(0, "nessun 'set enc-algorithm high'",
                       "log syslogd setting")])


def check_event_logging(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 7.x — registrazione degli eventi di sistema abilitata."""
    return _flag(
        cfg, "log eventfilter", "event", "enable",
        "registrazione degli eventi di sistema",
        "Registrazione degli eventi di sistema disabilitata: login, modifiche "
        "di configurazione e failover HA non lasciano traccia.")


def check_log_local_disk(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 7.x — registrazione locale su disco attiva.

    UNKNOWN se il blocco non esiste: i modelli entry-level non hanno disco e
    non espongono affatto 'config log disk setting'.
    """
    if not section_present(cfg, "log disk setting"):
        return RuleOutcome(
            UNKNOWN, "Sezione 'config log disk setting' assente: l'apparato "
                     "potrebbe non avere un disco locale.")
    status = setting(cfg, "log disk setting", "status")
    if status is not None and status.values \
            and status.values[0].lower() == "enable":
        return RuleOutcome(PASS, "Registrazione locale su disco attiva.")
    return RuleOutcome(
        WARN,
        "Registrazione su disco locale disattivata: se il collector remoto e' "
        "irraggiungibile non resta alcuna traccia.",
        [_ev1(status, "log disk setting") if status is not None
         else Evidence(0, "nessun 'set status enable'", "log disk setting")])
