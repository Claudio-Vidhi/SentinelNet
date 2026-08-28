# -*- coding: utf-8 -*-
"""Valutazioni di audit su configurazione FortiOS parsata.

Ogni regola e' una funzione pura ``ParsedConfig -> RuleOutcome``. Le regole
NON inventano verdetti: quando il blocco necessario alla valutazione non
esiste restituiscono UNKNOWN, tranne dove l'assenza E' essa stessa la
violazione (assenza di logging remoto, admin senza trusthost) — in quei casi
il comportamento e' documentato sulla singola regola.

Le regole non scrivono frasi: dichiarano una CHIAVE di ``messages.py`` e i
parametri che la riempiono. Vedi la nota sulla lingua in ``model.py``.

I riferimenti CIS citati nei commenti sono al *CIS Fortinet FortiGate
Benchmark v1.0.1*; il numero di raccomandazione di ogni regola sta in
``benchmarks.py``, perche' una stessa funzione serve piu' benchmark.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from .model import (FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome, absent)
from .parser import (ConfigRecord, ParsedConfig, section_entries,
                     section_present, setting)

# --- Hardening ---------------------------------------------------------------

_INSECURE_ACCESS = {"telnet", "http"}
_WEAK_TLS = {"sslv3", "tlsv1-0", "tlsv1-1", "tlsv1.0", "tlsv1.1"}
# CIS Fortinet FortiGate 7.4.x, raccomandazione 2.4.4: 5 minuti, che e'
# anche il default di fabbrica.
_MAX_ADMINTIMEOUT = 5


def _ctx(*parts: str) -> str:
    return " / ".join(p for p in parts if p)


def _ev1(rec: ConfigRecord, *ctx: str) -> Evidence:
    return Evidence(rec.line, rec.raw.strip(), _ctx(*ctx))


def check_management_protocols(cfg: ParsedConfig) -> RuleOutcome:
    """Telnet/HTTP abilitati su un'interfaccia (allowaccess)."""
    ifaces = section_entries(cfg, "system interface")
    if not ifaces:
        return RuleOutcome(UNKNOWN, "fos.mgmt_proto.no_section")
    ev: List[Evidence] = []
    for name in sorted(ifaces):
        for r in ifaces[name]:
            if r.key != "allowaccess":
                continue
            bad = sorted({v.lower() for v in r.values} & _INSECURE_ACCESS)
            if bad:
                ev.append(_ev1(r, "system interface", name))
    if ev:
        return RuleOutcome(FAIL, "fos.mgmt_proto.insecure", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.mgmt_proto.ok")


def check_tls_version(cfg: ParsedConfig) -> RuleOutcome:
    """Versione minima SSL/TLS ammessa per l'accesso amministrativo."""
    rec = (setting(cfg, "system global", "ssl-min-proto-version")
           or setting(cfg, "system global", "admin-https-ssl-versions"))
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(UNKNOWN, "fos.tls.no_section")
        return RuleOutcome(WARN, "fos.tls.not_set",
                           [absent("ev.no_directive", _ctx("system global"),
                                   what="set ssl-min-proto-version TLSv1-2")])
    weak = sorted({v.lower() for v in rec.values} & _WEAK_TLS)
    if weak:
        return RuleOutcome(FAIL, "fos.tls.weak",
                           [_ev1(rec, "system global")],
                           {"versions": ", ".join(weak)})
    return RuleOutcome(PASS, "fos.tls.ok")


def check_idle_timeout(cfg: ParsedConfig) -> RuleOutcome:
    """Timeout di inattivita' della sessione amministrativa."""
    rec = setting(cfg, "system global", "admintimeout")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(UNKNOWN, "fos.idle.no_section")
        return RuleOutcome(WARN, "fos.idle.not_set",
                           [absent("ev.no_directive", _ctx("system global"),
                                   what="set admintimeout %d"
                                        % _MAX_ADMINTIMEOUT)])
    val = _int_value(rec)
    if val is None:
        return RuleOutcome(WARN, "fos.idle.unreadable",
                           [_ev1(rec, "system global")])
    if val == 0:
        return RuleOutcome(FAIL, "fos.idle.disabled",
                           [_ev1(rec, "system global")])
    if val > _MAX_ADMINTIMEOUT:
        return RuleOutcome(FAIL, "fos.idle.too_high",
                           [_ev1(rec, "system global")],
                           {"value": val, "max": _MAX_ADMINTIMEOUT})
    return RuleOutcome(PASS, "fos.idle.ok", (), {"value": val})


def check_strong_crypto(cfg: ParsedConfig) -> RuleOutcome:
    """'set strong-crypto enable' (cifrari deboli disabilitati)."""
    return _flag(cfg, "system global", "strong-crypto", "enable",
                 "fos.strong_crypto", missing=WARN, bad_status=WARN)


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
        return RuleOutcome(UNKNOWN, "fos.policy.no_section")
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
        return RuleOutcome(FAIL, "fos.any_any.found", ev, {"count": len(ev)})
    return RuleOutcome(PASS, "fos.any_any.ok")


def check_boundary_protection(cfg: ParsedConfig) -> RuleOutcome:
    """Traffico in INGRESSO da un'interfaccia WAN verso qualunque destinazione."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(UNKNOWN, "fos.policy.no_section")
    wan = wan_interfaces(cfg)
    if not wan:
        return RuleOutcome(UNKNOWN, "fos.policy.no_wan")
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
        return RuleOutcome(FAIL, "fos.boundary.found", ev, {"count": len(ev)})
    return RuleOutcome(PASS, "fos.boundary.ok")


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
        return RuleOutcome(UNKNOWN, "fos.policy.no_section")
    wan = {w.lower() for w in wan_interfaces(cfg)}
    if not wan:
        return RuleOutcome(UNKNOWN, "fos.policy.no_wan")
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
        return RuleOutcome(FAIL, "fos.admin_ports.exposed", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.admin_ports.ok")


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
        return RuleOutcome(UNKNOWN, "fos.trusthost.no_section")
    ev: List[Evidence] = []
    for name in sorted(admins):
        recs = admins[name]
        hosts = [r for r in recs if r.key.startswith("trusthost")]
        if not hosts:
            ev.append(absent("ev.no_trusthost", _ctx("system admin", name)))
            continue
        for r in hosts:
            vals = {v.lower() for v in r.values}
            if any(vals == unrestricted
                   for unrestricted in _UNRESTRICTED_TRUSTHOST):
                ev.append(_ev1(r, "system admin", name))
    if ev:
        return RuleOutcome(FAIL, "fos.trusthost.unrestricted", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.trusthost.ok")


def check_snmp_community(cfg: ParsedConfig) -> RuleOutcome:
    """Community string SNMP v1/v2c di default."""
    if not section_present(cfg, "system snmp community"):
        return RuleOutcome(UNKNOWN, "fos.snmp_default.no_section")
    communities = section_entries(cfg, "system snmp community")
    ev: List[Evidence] = []
    for name in sorted(communities):
        for r in communities[name]:
            if (r.key == "name" and r.values
                    and r.values[0].lower() in _DEFAULT_COMMUNITIES):
                ev.append(_ev1(r, "system snmp community", name))
    if ev:
        return RuleOutcome(FAIL, "fos.snmp_default.found", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.snmp_default.ok")


def check_syslog(cfg: ParsedConfig) -> RuleOutcome:
    """Inoltro dei log verso un syslog remoto (NIST AU-2/AU-12, PCI 10.2).

    ASSENZA COME VIOLAZIONE: se il blocco non esiste non c'e' alcun logging
    remoto configurato, che e' esattamente il controllo che fallisce.
    """
    if not section_present(cfg, "log syslogd setting"):
        return RuleOutcome(
            FAIL, "fos.syslog.no_section",
            [absent("ev.no_block", "log syslogd setting",
                    what="config log syslogd setting")])
    status = setting(cfg, "log syslogd setting", "status")
    server = setting(cfg, "log syslogd setting", "server")
    ev: List[Evidence] = []
    if (status is None or not status.values
            or status.values[0].lower() != "enable"):
        ev.append(_ev1(status, "log syslogd setting") if status is not None
                  else absent("ev.no_directive", _ctx("log syslogd setting"),
                              what="set status enable"))
    if server is None or not server.values:
        ev.append(_ev1(server, "log syslogd setting") if server is not None
                  else absent("ev.no_directive", _ctx("log syslogd setting"),
                              what="set server <ip>"))
    if ev:
        return RuleOutcome(FAIL, "fos.syslog.incomplete", ev)
    return RuleOutcome(PASS, "fos.syslog.ok")


def check_vendor_defaults(cfg: ParsedConfig) -> RuleOutcome:
    """Account di default e policy password (PCI-DSS 2.2)."""
    admins = section_entries(cfg, "system admin")
    has_policy_block = section_present(cfg, "system password-policy")
    if not admins and not has_policy_block:
        return RuleOutcome(UNKNOWN, "fos.defaults.no_section")
    ev: List[Evidence] = []
    for name in sorted(admins):
        if name.lower() == "admin":
            recs = admins[name]
            ev.append(Evidence(recs[0].line if recs else 0, "",
                               _ctx("system admin", name),
                               message="ev.default_admin_account"))
    if has_policy_block:
        status = setting(cfg, "system password-policy", "status")
        if (status is None or not status.values
                or status.values[0].lower() != "enable"):
            ev.append(_ev1(status, "system password-policy")
                      if status is not None
                      else absent("ev.no_directive",
                                  _ctx("system password-policy"),
                                  what="set status enable"))
    else:
        ev.append(absent("ev.no_block", _ctx("system password-policy"),
                         what="config system password-policy"))
    if ev:
        return RuleOutcome(FAIL, "fos.defaults.found", ev, {"count": len(ev)})
    return RuleOutcome(PASS, "fos.defaults.ok")


# =============================================================================
# CIS Fortinet FortiGate 7.4.x — controlli aggiuntivi
#
# Stessa convenzione: blocco assente -> UNKNOWN, salvo dove l'assenza E' la
# violazione (e in quel caso lo dice la docstring).
# =============================================================================

def _records_under(cfg: ParsedConfig, *path: str) -> List[ConfigRecord]:
    """Tutti i record il cui path inizia con ``path`` (blocchi annidati inclusi)."""
    return [r for r in cfg.records if r.path[:len(path)] == path]


def _flag(cfg: ParsedConfig, section: str, key: str, want: str,
          prefix: str, missing: str = WARN,
          bad_status: str = FAIL) -> RuleOutcome:
    """Controllo di un interruttore enable/disable in un blocco singolo.

    ``prefix`` e' il prefisso delle chiavi di catalogo: la regola espone
    ``<prefix>.no_section``, ``.not_set``, ``.bad`` e ``.ok``.
    """
    rec = setting(cfg, section, key)
    if rec is None:
        if not section_present(cfg, section):
            return RuleOutcome(UNKNOWN, prefix + ".no_section")
        return RuleOutcome(
            missing, prefix + ".not_set",
            [absent("ev.no_directive", _ctx(section),
                    what="set %s %s" % (key, want))])
    if rec.values and rec.values[0].lower() == want:
        return RuleOutcome(PASS, prefix + ".ok")
    return RuleOutcome(bad_status, prefix + ".bad", [_ev1(rec, section)])


def _int_value(rec: Optional[ConfigRecord]) -> Optional[int]:
    if rec is None:
        return None
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
        return RuleOutcome(FAIL, "fos.dns.no_section",
                           [absent("ev.no_block", "system dns",
                                   what="config system dns")])
    servers = [setting(cfg, "system dns", k)
               for k in ("primary", "secondary")]
    present = [r for r in servers if r is not None and r.values]
    if not present:
        return RuleOutcome(FAIL, "fos.dns.no_server",
                           [absent("ev.no_directive", "system dns",
                                   what="set primary <ip>")])
    if len(present) < 2:
        return RuleOutcome(WARN, "fos.dns.single",
                           [_ev1(present[0], "system dns")])
    return RuleOutcome(PASS, "fos.dns.ok")


def check_intrazone_deny(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 1.2 — traffico intra-zona negato per default."""
    zones = section_entries(cfg, "system zone")
    if not zones:
        return RuleOutcome(UNKNOWN, "fos.intrazone.no_zones")
    ev: List[Evidence] = []
    for name in sorted(zones):
        rec = next((r for r in zones[name] if r.key == "intrazone"), None)
        if rec is None:
            ev.append(absent("ev.no_directive", _ctx("system zone", name),
                             what="set intrazone deny"))
        elif not rec.values or rec.values[0].lower() != "deny":
            ev.append(_ev1(rec, "system zone", name))
    if ev:
        return RuleOutcome(FAIL, "fos.intrazone.allowed", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.intrazone.ok")


# --- 2.1 Impostazioni di sistema ---------------------------------------------

def check_login_banners(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.1 / 2.1.2 — banner pre-login e post-login."""
    if not section_present(cfg, "system global"):
        return RuleOutcome(UNKNOWN, "fos.banners.no_section")
    ev: List[Evidence] = []
    for key in ("pre-login-banner", "post-login-banner"):
        rec = setting(cfg, "system global", key)
        if rec is None:
            ev.append(absent("ev.no_directive", _ctx("system global"),
                             what="set %s enable" % key))
        elif not rec.values or rec.values[0].lower() != "enable":
            ev.append(_ev1(rec, "system global"))
    if ev:
        return RuleOutcome(FAIL, "fos.banners.missing", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.banners.ok")


def check_timezone(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.3 — fuso orario impostato esplicitamente."""
    rec = setting(cfg, "system global", "timezone")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(UNKNOWN, "fos.timezone.no_section")
        return RuleOutcome(WARN, "fos.timezone.not_set",
                           [absent("ev.no_directive", _ctx("system global"),
                                   what="set timezone <id>")])
    return RuleOutcome(PASS, "fos.timezone.ok")


def check_ntp(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.4 — sincronizzazione oraria attiva con server dichiarati."""
    if not section_present(cfg, "system ntp"):
        return RuleOutcome(FAIL, "fos.ntp.no_section",
                           [absent("ev.no_block", "system ntp",
                                   what="config system ntp")])
    ev: List[Evidence] = []
    sync = setting(cfg, "system ntp", "ntpsync")
    if sync is None or not sync.values or sync.values[0].lower() != "enable":
        ev.append(_ev1(sync, "system ntp") if sync is not None
                  else absent("ev.no_directive", "system ntp",
                              what="set ntpsync enable"))
    # I server custom stanno in 'config ntpserver', annidata dentro 'system ntp'.
    servers = {r.path[2] for r in _records_under(cfg, "system ntp", "ntpserver")
               if len(r.path) > 2}
    ntp_type = setting(cfg, "system ntp", "type")
    is_custom = (ntp_type is not None and ntp_type.values
                 and ntp_type.values[0].lower() == "custom")
    if is_custom and not servers:
        ev.append(absent("ev.ntp_custom_without_server", "system ntp"))
    if ev:
        return RuleOutcome(FAIL, "fos.ntp.not_syncing", ev)
    return RuleOutcome(PASS, "fos.ntp.ok", (), {"count": len(servers)})


def check_hostname(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.5 — hostname diverso da quello di fabbrica."""
    rec = setting(cfg, "system global", "hostname")
    if rec is None:
        if not section_present(cfg, "system global"):
            return RuleOutcome(UNKNOWN, "fos.hostname.no_section")
        return RuleOutcome(WARN, "fos.hostname.not_set",
                           [absent("ev.no_directive", _ctx("system global"),
                                   what="set hostname <nome>")])
    name = (rec.values[0] if rec.values else "").strip()
    # Il default di fabbrica e' il modello, spesso col numero di serie: e' il
    # nome che l'apparato ha prima di essere messo in servizio.
    if not name or name.lower().startswith(("fortigate", "fgt")):
        return RuleOutcome(FAIL, "fos.hostname.factory",
                           [_ev1(rec, "system global")])
    return RuleOutcome(PASS, "fos.hostname.ok")


def check_auto_install(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.7 — installazione automatica da USB disabilitata."""
    if not section_present(cfg, "system auto-install"):
        return RuleOutcome(UNKNOWN, "fos.auto_install.no_section")
    ev: List[Evidence] = []
    for key in ("auto-install-config", "auto-install-image"):
        rec = setting(cfg, "system auto-install", key)
        if rec is not None and rec.values and rec.values[0].lower() == "enable":
            ev.append(_ev1(rec, "system auto-install"))
    if ev:
        return RuleOutcome(FAIL, "fos.auto_install.enabled", ev)
    return RuleOutcome(PASS, "fos.auto_install.ok")


def check_static_key_ciphers(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.8 — 'ssl-static-key-ciphers disable' (perfect forward secrecy)."""
    return _flag(cfg, "system global", "ssl-static-key-ciphers", "disable",
                 "fos.static_ciphers")


def check_admin_https_redirect(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.9 — redirect da HTTP a HTTPS sulla GUI."""
    return _flag(cfg, "system global", "admin-https-redirect", "enable",
                 "fos.https_redirect")


def check_cpu_log_threshold(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.12 — 'log-single-cpu-high enable'."""
    return _flag(cfg, "system global", "log-single-cpu-high", "enable",
                 "fos.cpu_log")


def check_gui_hostname_display(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.1.13 — hostname NON mostrato nella pagina di login della GUI.

    Il verso non e' quello che suggerisce il nome dell'impostazione: il
    benchmark vuole ``disable``, perche' la pagina di login e' pre-autenticazione
    e l'hostname vi comparirebbe per chiunque la raggiunga.
    """
    return _flag(cfg, "system global", "gui-display-hostname", "disable",
                 "fos.gui_hostname")


# --- 2.2 Password e blocco account -------------------------------------------

_MIN_PASSWORD_LENGTH = 14           # CIS 2.2.1
_MAX_LOCKOUT_THRESHOLD = 3          # CIS 2.2.2
_MIN_LOCKOUT_DURATION = 900         # CIS 2.2.2, secondi


def check_password_policy_strength(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.2.1 — policy password con lunghezza e complessita' minime.

    Distinta da ``check_vendor_defaults``, che si limita a verificare che la
    policy sia ATTIVA: qui si guarda cosa impone.
    """
    sec = "system password-policy"
    if not section_present(cfg, sec):
        return RuleOutcome(FAIL, "fos.pwpolicy.no_section",
                           [absent("ev.no_block", sec,
                                   what="config system password-policy")])
    ev: List[Evidence] = []
    length = setting(cfg, sec, "minimum-length")
    if length is None:
        ev.append(absent("ev.no_directive", _ctx(sec),
                         what="set minimum-length %d" % _MIN_PASSWORD_LENGTH))
    elif (_int_value(length) or 0) < _MIN_PASSWORD_LENGTH:
        ev.append(_ev1(length, sec))
    # Le quattro classi di caratteri richieste dal benchmark.
    for key in ("min-lower-case-letter", "min-upper-case-letter",
                "min-non-alphanumeric", "min-number"):
        rec = setting(cfg, sec, key)
        val = _int_value(rec)
        if val is None or val < 1:
            ev.append(_ev1(rec, sec) if rec is not None
                      else absent("ev.no_directive", _ctx(sec),
                                  what="set %s 1" % key))
    if ev:
        return RuleOutcome(FAIL, "fos.pwpolicy.weak", ev,
                           {"count": len(ev),
                            "minlen": _MIN_PASSWORD_LENGTH})
    return RuleOutcome(PASS, "fos.pwpolicy.ok", (),
                       {"minlen": _MIN_PASSWORD_LENGTH})


def check_admin_lockout(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.2.2 — soglia e durata del blocco dopo tentativi falliti."""
    if not section_present(cfg, "system global"):
        return RuleOutcome(UNKNOWN, "fos.lockout.no_section")
    ev: List[Evidence] = []
    thr = setting(cfg, "system global", "admin-lockout-threshold")
    if thr is None:
        ev.append(absent("ev.no_directive", _ctx("system global"),
                         what="set admin-lockout-threshold %d"
                              % _MAX_LOCKOUT_THRESHOLD))
    elif (_int_value(thr) or 10 ** 6) > _MAX_LOCKOUT_THRESHOLD:
        ev.append(_ev1(thr, "system global"))
    dur = setting(cfg, "system global", "admin-lockout-duration")
    if dur is None:
        ev.append(absent("ev.no_directive", _ctx("system global"),
                         what="set admin-lockout-duration %d"
                              % _MIN_LOCKOUT_DURATION))
    elif (_int_value(dur) or 0) < _MIN_LOCKOUT_DURATION:
        ev.append(_ev1(dur, "system global"))
    params = {"threshold": _MAX_LOCKOUT_THRESHOLD,
              "duration": _MIN_LOCKOUT_DURATION}
    if ev:
        return RuleOutcome(FAIL, "fos.lockout.weak", ev, params)
    return RuleOutcome(PASS, "fos.lockout.ok", (), params)


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
        return RuleOutcome(UNKNOWN, "fos.snmpv3.no_snmp")
    communities = section_entries(cfg, "system snmp community")
    ev: List[Evidence] = []
    for name in sorted(communities):
        recs = communities[name]
        status = next((r for r in recs if r.key == "status"), None)
        if status is not None and status.values \
                and status.values[0].lower() == "disable":
            continue
        ev.append(Evidence(recs[0].line if recs else 0, "",
                           _ctx("system snmp community", name),
                           message="ev.snmp_v1v2c_active"))
    if ev:
        return RuleOutcome(FAIL, "fos.snmpv3.v1v2c", ev, {"count": len(ev)})
    if not has_user:
        return RuleOutcome(WARN, "fos.snmpv3.no_user",
                           [absent("ev.no_block", "system snmp user",
                                   what="config system snmp user")])
    return RuleOutcome(PASS, "fos.snmpv3.ok")


# --- 2.4 Amministrazione ------------------------------------------------------

_DEFAULT_ADMIN_PORTS = {"admin-sport": 443, "admin-ssh-port": 22}


def check_admin_ports_changed(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.4.7 — porte amministrative spostate dai valori di default."""
    if not section_present(cfg, "system global"):
        return RuleOutcome(UNKNOWN, "fos.admin_port.no_section")
    ev: List[Evidence] = []
    for key, default in sorted(_DEFAULT_ADMIN_PORTS.items()):
        rec = setting(cfg, "system global", key)
        if rec is None:
            ev.append(absent("ev.not_set_default_value", _ctx("system global"),
                             what=key, value=default))
        elif _int_value(rec) == default:
            ev.append(_ev1(rec, "system global"))
    if ev:
        return RuleOutcome(WARN, "fos.admin_port.default", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.admin_port.ok")


def check_local_in_policy(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.4.6 — policy local-in a protezione dei servizi dell'apparato."""
    if not section_present(cfg, "firewall local-in-policy"):
        return RuleOutcome(
            WARN, "fos.local_in.no_section",
            [absent("ev.no_block", "firewall local-in-policy",
                    what="config firewall local-in-policy")])
    entries = section_entries(cfg, "firewall local-in-policy")
    if not entries:
        return RuleOutcome(WARN, "fos.local_in.empty",
                           [absent("ev.block_empty",
                                   "firewall local-in-policy")])
    return RuleOutcome(PASS, "fos.local_in.ok", (), {"count": len(entries)})


# --- 2.5 Alta disponibilita' --------------------------------------------------

def check_ha_configured(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 2.5.1 / 2.5.2 — cluster HA con interfacce monitorate.

    UNKNOWN quando l'apparato non e' in cluster: un nodo singolo e' una scelta
    architetturale, non una violazione che questo motore possa giudicare.
    """
    if not section_present(cfg, "system ha"):
        return RuleOutcome(UNKNOWN, "fos.ha.no_section")
    mode = setting(cfg, "system ha", "mode")
    if mode is None or not mode.values \
            or mode.values[0].lower() in ("standalone", ""):
        return RuleOutcome(UNKNOWN, "fos.ha.standalone")
    monitor = setting(cfg, "system ha", "monitor")
    if monitor is None or not monitor.values:
        return RuleOutcome(FAIL, "fos.ha.no_monitor",
                           [_ev1(mode, "system ha")])
    return RuleOutcome(PASS, "fos.ha.ok", (),
                       {"mode": mode.values[0], "count": len(monitor.values)})


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
    if not section_entries(cfg, "firewall policy"):
        return RuleOutcome(UNKNOWN, "fos.policy.no_section")
    ev: List[Evidence] = []
    for pid, recs in _accept_policies(cfg):
        rec = next((r for r in recs if r.key == "logtraffic"), None)
        if rec is None:
            ev.append(absent("ev.no_directive", _ctx("firewall policy", pid),
                             what="set logtraffic all"))
        elif rec.values and rec.values[0].lower() == "disable":
            ev.append(_ev1(rec, "firewall policy", pid))
    if ev:
        return RuleOutcome(FAIL, "fos.policy_log.missing", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.policy_log.ok")


def check_policy_security_profiles(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 4.x — profili di sicurezza applicati al traffico in uscita da WAN."""
    if not section_entries(cfg, "firewall policy"):
        return RuleOutcome(UNKNOWN, "fos.policy.no_section")
    wan = {w.lower() for w in wan_interfaces(cfg)}
    if not wan:
        return RuleOutcome(UNKNOWN, "fos.policy.no_wan")
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
        return RuleOutcome(WARN, "fos.profiles.missing", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.profiles.ok")


def check_policy_comments(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 3.x — ogni policy documentata da un commento."""
    policies = section_entries(cfg, "firewall policy")
    if not policies:
        return RuleOutcome(UNKNOWN, "fos.policy.no_section")
    ev: List[Evidence] = []
    for pid in sorted(policies, key=lambda k: (len(k), k)):
        recs = policies[pid]
        if any(r.key in ("comments", "comment") and r.values for r in recs):
            continue
        line, raw = _policy_line(recs)
        ev.append(Evidence(line, raw, _ctx("firewall policy", pid)))
    if ev:
        return RuleOutcome(WARN, "fos.comments.missing", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "fos.comments.ok")


# --- 6.x VPN ------------------------------------------------------------------

def check_sslvpn_tls(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 6.1.2 — versione TLS minima del portale SSL-VPN."""
    if not section_present(cfg, "vpn ssl settings"):
        return RuleOutcome(UNKNOWN, "fos.sslvpn.no_section")
    rec = (setting(cfg, "vpn ssl settings", "ssl-min-proto-ver")
           or setting(cfg, "vpn ssl settings", "ssl-min-proto-version"))
    if rec is None:
        return RuleOutcome(WARN, "fos.sslvpn_tls.not_set",
                           [absent("ev.no_directive", "vpn ssl settings",
                                   what="set ssl-min-proto-ver tls1-2")])
    val = (rec.values[0].lower() if rec.values else "")
    if val in ("tls1-2", "tls1-3", "tlsv1-2", "tlsv1-3"):
        return RuleOutcome(PASS, "fos.sslvpn_tls.ok")
    return RuleOutcome(FAIL, "fos.sslvpn_tls.weak",
                       [_ev1(rec, "vpn ssl settings")], {"version": val})


def check_sslvpn_source_restriction(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 6.1.x — portale SSL-VPN ristretto per indirizzo sorgente."""
    if not section_present(cfg, "vpn ssl settings"):
        return RuleOutcome(UNKNOWN, "fos.sslvpn.no_section")
    rec = setting(cfg, "vpn ssl settings", "source-address")
    if rec is None or not rec.values:
        return RuleOutcome(WARN, "fos.sslvpn_src.unrestricted",
                           [absent("ev.no_directive", "vpn ssl settings",
                                   what="set source-address <gruppo>")])
    if {v.lower() for v in rec.values} & _ANY_ADDR:
        return RuleOutcome(FAIL, "fos.sslvpn_src.any",
                           [_ev1(rec, "vpn ssl settings")])
    return RuleOutcome(PASS, "fos.sslvpn_src.ok")


# --- 7.x Logging --------------------------------------------------------------

def check_syslog_encrypted(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 7.x — inoltro syslog cifrato (TLS).

    Si applica solo se un syslog remoto e' configurato: la sua ASSENZA e' gia'
    la violazione segnalata da ``check_syslog``, e ripeterla qui conterebbe lo
    stesso problema due volte nel punteggio.
    """
    if not section_present(cfg, "log syslogd setting"):
        return RuleOutcome(UNKNOWN, "fos.syslog_enc.no_syslog")
    status = setting(cfg, "log syslogd setting", "status")
    if status is None or not status.values \
            or status.values[0].lower() != "enable":
        return RuleOutcome(UNKNOWN, "fos.syslog_enc.disabled")
    rec = setting(cfg, "log syslogd setting", "enc-algorithm")
    if rec is not None and rec.values \
            and rec.values[0].lower() in ("high", "high-medium", "low"):
        return RuleOutcome(PASS, "fos.syslog_enc.ok", (),
                           {"algorithm": rec.values[0]})
    return RuleOutcome(
        WARN, "fos.syslog_enc.plaintext",
        [_ev1(rec, "log syslogd setting") if rec is not None
         else absent("ev.no_directive", "log syslogd setting",
                     what="set enc-algorithm high")])


def check_event_logging(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 7.x — registrazione degli eventi di sistema abilitata."""
    return _flag(cfg, "log eventfilter", "event", "enable", "fos.event_log")


def check_log_local_disk(cfg: ParsedConfig) -> RuleOutcome:
    """CIS 7.x — registrazione locale su disco attiva.

    UNKNOWN se il blocco non esiste: i modelli entry-level non hanno disco e
    non espongono affatto 'config log disk setting'.
    """
    if not section_present(cfg, "log disk setting"):
        return RuleOutcome(UNKNOWN, "fos.log_disk.no_section")
    status = setting(cfg, "log disk setting", "status")
    if status is not None and status.values \
            and status.values[0].lower() == "enable":
        return RuleOutcome(PASS, "fos.log_disk.ok")
    return RuleOutcome(
        WARN, "fos.log_disk.disabled",
        [_ev1(status, "log disk setting") if status is not None
         else absent("ev.no_directive", "log disk setting",
                     what="set status enable")])
