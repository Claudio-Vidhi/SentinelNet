# -*- coding: utf-8 -*-
"""Valutazioni di audit su configurazione Cisco IOS / IOS-XE parsata.

Distillate dal *CIS Cisco IOS XE 17.x Benchmark v2.2.1*. Il numero della
raccomandazione, il comando di audit e quello di rimedio vivono in
``benchmarks.py``; qui sta solo la valutazione, che e' una funzione pura
``IosConfig -> RuleOutcome``.

Come per FortiOS, le regole dichiarano una CHIAVE di ``messages.py``, non una
frase: vedi la nota sulla lingua in ``model.py``.

ASSENZA E VERDETTO — su IOS la distinzione e' diversa da FortiOS. Una
``running-config`` e' completa per costruzione: se ``aaa new-model`` non
compare, non e' "non valutabile", e' disabilitato. Quindi:

  - config vuota o non parsabile  -> UNKNOWN (non c'e' niente da valutare);
  - direttiva globale assente     -> FAIL/WARN, perche' l'assenza E' lo stato;
  - famiglia di blocchi assente   -> UNKNOWN quando la raccomandazione e'
    condizionata alla presenza del costrutto (nessuna ``line vty``, nessuna
    ``snmp-server community``, nessun ``router eigrp``...). Il benchmark stesso
    marca queste come "if protocol is used" / "when using SNMP".

Diverse raccomandazioni CIS non sono verificabili da una configurazione
salvata (``show ip ssh``, ``diag``, la versione firmware, il modulus RSA che
IOS non stampa): non hanno una regola qui, invece di averne una che indovina.
"""

from typing import List, Optional

from .ios_parser import (
    IosConfig, IosLine, blocks_matching, child, find, find_top, first_top,
    has_top, is_empty)
from .model import (FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome, absent)

# --- soglie dichiarate dal benchmark -----------------------------------------

_MAX_EXEC_TIMEOUT_MIN = 10      # 1.2.6 / 1.2.7 / 1.2.8
_MAX_SSH_TIMEOUT_S = 60         # 2.1.1.1.4
_MAX_SSH_RETRIES = 3            # 2.1.1.1.5
_MIN_LOG_BUFFER = 64000         # 2.2.2 ("Recommended size is 64000")
_MIN_SNMP_AES_BITS = 128        # 1.5.10


def _ev(l: IosLine, note: str = "") -> Evidence:
    return Evidence(l.line, l.text, " / ".join(p for p in l.path if p) or note)


def _guard(cfg: IosConfig) -> Optional[RuleOutcome]:
    return RuleOutcome(UNKNOWN, "ios.empty") if is_empty(cfg) else None


def _int_arg(l: IosLine, index: int) -> Optional[int]:
    try:
        return int(l.words[index])
    except (IndexError, ValueError):
        return None


# --- 1.1 AAA ------------------------------------------------------------------

def check_ios_aaa_new_model(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.1.1 — 'aaa new-model' abilitato."""
    g = _guard(cfg)
    if g:
        return g
    if has_top(cfg, "no aaa new-model"):
        return RuleOutcome(FAIL, "ios.aaa.disabled",
                           [_ev(find_top(cfg, "no aaa new-model")[0])])
    if has_top(cfg, "aaa new-model"):
        return RuleOutcome(PASS, "ios.aaa.ok")
    return RuleOutcome(FAIL, "ios.aaa.absent",
                       [absent("ev.no_directive", what="aaa new-model")])


def check_ios_aaa_authentication_login(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.1.2 — metodo 'aaa authentication login' definito."""
    g = _guard(cfg)
    if g:
        return g
    if not has_top(cfg, "aaa new-model"):
        return RuleOutcome(UNKNOWN, "ios.aaa.not_applicable_login")
    hits = find_top(cfg, "aaa authentication login")
    if not hits:
        return RuleOutcome(
            FAIL, "ios.aaa_login.absent",
            [absent("ev.no_directive", what="aaa authentication login")])
    # Un metodo 'none' vanifica il controllo: e' peggio dell'assenza, perche'
    # sembra configurato.
    weak = [l for l in hits if l.words[-1:] == ["none"]]
    if weak:
        return RuleOutcome(FAIL, "ios.aaa_login.none",
                           [_ev(l) for l in weak])
    return RuleOutcome(PASS, "ios.aaa_login.ok", (), {"count": len(hits)})


def check_ios_aaa_accounting_commands(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.1.6 — accounting dei comandi a privilegio 15."""
    g = _guard(cfg)
    if g:
        return g
    if not has_top(cfg, "aaa new-model"):
        return RuleOutcome(UNKNOWN, "ios.aaa.not_applicable_accounting")
    if find_top(cfg, "aaa accounting commands 15"):
        return RuleOutcome(PASS, "ios.accounting.ok")
    return RuleOutcome(
        FAIL, "ios.accounting.absent",
        [absent("ev.no_directive", what="aaa accounting commands 15")])


# --- 1.2 Accesso --------------------------------------------------------------

def _vty_blocks(cfg: IosConfig):
    return blocks_matching(cfg, "line vty")


def check_ios_vty_transport_ssh(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.2 — 'transport input ssh' su ogni 'line vty'."""
    g = _guard(cfg)
    if g:
        return g
    vtys = _vty_blocks(cfg)
    if not vtys:
        return RuleOutcome(UNKNOWN, "ios.vty.absent")
    ev: List[Evidence] = []
    for header, kids in vtys:
        t = child(kids, "transport input")
        if t is None:
            ev.append(absent("ev.no_transport_input", header))
            continue
        allowed = set(t.words[2:])
        if allowed - {"ssh", "none"}:
            ev.append(_ev(t, header))
    if ev:
        return RuleOutcome(FAIL, "ios.vty_transport.insecure", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "ios.vty_transport.ok")


def check_ios_vty_access_class(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.5 — 'access-class' applicata a ogni 'line vty'."""
    g = _guard(cfg)
    if g:
        return g
    vtys = _vty_blocks(cfg)
    if not vtys:
        return RuleOutcome(UNKNOWN, "ios.vty.absent")
    ev = [absent("ev.no_directive", header, what="access-class <ACL> in")
          for header, kids in vtys if child(kids, "access-class") is None]
    if ev:
        return RuleOutcome(FAIL, "ios.vty_acl.missing", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "ios.vty_acl.ok")


def _check_exec_timeout(cfg: IosConfig, prefix: str,
                        key: str) -> RuleOutcome:
    g = _guard(cfg)
    if g:
        return g
    found = blocks_matching(cfg, prefix)
    if not found:
        return RuleOutcome(UNKNOWN, key + ".absent")
    ev: List[Evidence] = []
    for header, kids in found:
        t = child(kids, "exec-timeout")
        if t is None:
            # Default IOS: 10 minuti sulle linee EXEC. Conforme, ma implicito:
            # una modifica al default della piattaforma lo cambia senza che la
            # configurazione lo dica.
            ev.append(absent("ev.not_set_default", header,
                             what="exec-timeout"))
            continue
        mins = _int_arg(t, 1)
        secs = _int_arg(t, 2) or 0
        if mins is None:
            ev.append(_ev(t, header))
        elif mins == 0 and secs == 0:
            ev.append(_ev(t, header))
        elif mins > _MAX_EXEC_TIMEOUT_MIN or (
                mins == _MAX_EXEC_TIMEOUT_MIN and secs > 0):
            ev.append(_ev(t, header))
    params = {"count": len(ev), "max": _MAX_EXEC_TIMEOUT_MIN}
    if ev:
        return RuleOutcome(FAIL, key + ".bad", ev, params)
    return RuleOutcome(PASS, key + ".ok", (), params)


def check_ios_vty_exec_timeout(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.8 — 'exec-timeout' <= 10 minuti su 'line vty'."""
    return _check_exec_timeout(cfg, "line vty", "ios.vty_timeout")


def check_ios_console_exec_timeout(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.7 — 'exec-timeout' <= 10 minuti su 'line con 0'."""
    return _check_exec_timeout(cfg, "line con", "ios.con_timeout")


def check_ios_aux_no_exec(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.3 — 'no exec' sulla porta ausiliaria.

    Il benchmark stesso nota che molti apparati non hanno una porta AUX: se il
    blocco non c'e', il controllo non si applica.
    """
    g = _guard(cfg)
    if g:
        return g
    aux = blocks_matching(cfg, "line aux")
    if not aux:
        return RuleOutcome(UNKNOWN, "ios.aux.absent")
    ev = [absent("ev.no_directive", header, what="no exec")
          for header, kids in aux if child(kids, "no exec") is None]
    if ev:
        return RuleOutcome(FAIL, "ios.aux.exec_active", ev)
    return RuleOutcome(PASS, "ios.aux.ok")


def check_ios_local_user_privilege(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.1 — utenti locali a 'privilege 1'."""
    g = _guard(cfg)
    if g:
        return g
    users = find_top(cfg, "username ")
    if not users:
        return RuleOutcome(UNKNOWN, "ios.users.absent")
    ev = [_ev(u) for u in users if "privilege 15" in u.lower]
    if ev:
        return RuleOutcome(WARN, "ios.user_priv.high", ev, {"count": len(ev)})
    return RuleOutcome(PASS, "ios.user_priv.ok")


# --- 1.3 Banner ---------------------------------------------------------------

def _check_banner(cfg: IosConfig, kind: str) -> RuleOutcome:
    g = _guard(cfg)
    if g:
        return g
    if find(cfg, "banner %s" % kind):
        return RuleOutcome(PASS, "ios.banner.ok", (), {"kind": kind})
    return RuleOutcome(FAIL, "ios.banner.absent",
                       [absent("ev.no_directive", what="banner %s" % kind)],
                       {"kind": kind})


def check_ios_banner_login(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.3.2 — 'banner login' configurato."""
    return _check_banner(cfg, "login")


def check_ios_banner_motd(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.3.3 — 'banner motd' configurato."""
    return _check_banner(cfg, "motd")


# --- 1.4 Password -------------------------------------------------------------

def check_ios_enable_secret(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.4.1 — 'enable secret' al posto di 'enable password'."""
    g = _guard(cfg)
    if g:
        return g
    weak = find_top(cfg, "enable password")
    secret = find_top(cfg, "enable secret")
    if weak:
        return RuleOutcome(FAIL, "ios.enable.password",
                           [_ev(l) for l in weak])
    if secret:
        return RuleOutcome(PASS, "ios.enable.ok")
    return RuleOutcome(FAIL, "ios.enable.absent",
                       [absent("ev.no_directive", what="enable secret")])


def check_ios_service_password_encryption(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.4.2 — 'service password-encryption' abilitato."""
    g = _guard(cfg)
    if g:
        return g
    if has_top(cfg, "no service password-encryption"):
        return RuleOutcome(
            FAIL, "ios.pw_encryption.disabled",
            [_ev(find_top(cfg, "no service password-encryption")[0])])
    if has_top(cfg, "service password-encryption"):
        return RuleOutcome(PASS, "ios.pw_encryption.ok")
    return RuleOutcome(
        FAIL, "ios.pw_encryption.absent",
        [absent("ev.no_directive", what="service password-encryption")])


def check_ios_username_secret(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.4.3 — ogni utente locale usa 'secret', non 'password'."""
    g = _guard(cfg)
    if g:
        return g
    users = find_top(cfg, "username ")
    if not users:
        return RuleOutcome(UNKNOWN, "ios.users.absent")
    ev = [_ev(u) for u in users if " secret " not in (u.lower + " ")]
    if ev:
        return RuleOutcome(FAIL, "ios.user_secret.password", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "ios.user_secret.ok")


# --- 1.5 SNMP -----------------------------------------------------------------

_DEFAULT_COMMUNITIES = {"public", "private"}


def _communities(cfg: IosConfig) -> List[IosLine]:
    return find_top(cfg, "snmp-server community")


def check_ios_snmp_default_community(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.5.2 / 1.5.3 — community 'public' o 'private'."""
    g = _guard(cfg)
    if g:
        return g
    comms = _communities(cfg)
    if not comms:
        return RuleOutcome(UNKNOWN, "ios.snmp.absent")
    ev = [_ev(c) for c in comms
          if len(c.words) > 2 and c.words[2] in _DEFAULT_COMMUNITIES]
    if ev:
        return RuleOutcome(FAIL, "ios.snmp_default.found", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "ios.snmp_default.ok")


def check_ios_snmp_readwrite(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.5.4 — nessuna community SNMP in scrittura (RW)."""
    g = _guard(cfg)
    if g:
        return g
    comms = _communities(cfg)
    if not comms:
        return RuleOutcome(UNKNOWN, "ios.snmp.absent")
    ev = [_ev(c) for c in comms if "rw" in c.words[3:]]
    if ev:
        return RuleOutcome(FAIL, "ios.snmp_rw.found", ev, {"count": len(ev)})
    return RuleOutcome(PASS, "ios.snmp_rw.ok")


def check_ios_snmp_community_acl(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.5.5 — ogni community SNMP ristretta da una access-list."""
    g = _guard(cfg)
    if g:
        return g
    comms = _communities(cfg)
    if not comms:
        return RuleOutcome(UNKNOWN, "ios.snmp.absent")
    ev = []
    for c in comms:
        # 'snmp-server community <str> [ro|rw] [ipv6 <acl>] [<acl>]'
        tail = [w for w in c.words[3:] if w not in ("ro", "rw", "view")]
        if not tail:
            ev.append(_ev(c))
    if ev:
        return RuleOutcome(FAIL, "ios.snmp_acl.missing", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "ios.snmp_acl.ok")


def check_ios_snmpv3_privacy(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.5.9 / 1.5.10 — SNMPv3 con autenticazione e cifratura AES 128+."""
    g = _guard(cfg)
    if g:
        return g
    groups = find_top(cfg, "snmp-server group")
    users = find_top(cfg, "snmp-server user")
    if not groups and not users:
        return RuleOutcome(UNKNOWN, "ios.snmpv3.absent")
    ev: List[Evidence] = []
    for grp in groups:
        if "v3" in grp.words and "priv" not in grp.words:
            ev.append(_ev(grp))
    for usr in users:
        if "v3" not in usr.words:
            continue
        if "priv" not in usr.words:
            ev.append(_ev(usr))
            continue
        if "aes" not in usr.words:
            ev.append(_ev(usr))
            continue
        bits = _int_arg(usr, usr.words.index("aes") + 1)
        if bits is None or bits < _MIN_SNMP_AES_BITS:
            ev.append(_ev(usr))
    params = {"count": len(ev), "bits": _MIN_SNMP_AES_BITS}
    if ev:
        return RuleOutcome(FAIL, "ios.snmpv3.weak", ev, params)
    return RuleOutcome(PASS, "ios.snmpv3.ok", (), params)


# --- 2.1 Servizi globali e SSH ------------------------------------------------

def check_ios_ssh_version(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.2 — 'ip ssh version 2'."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip ssh version")
    if rec is None:
        return RuleOutcome(WARN, "ios.ssh_version.not_set",
                           [absent("ev.no_directive",
                                   what="ip ssh version 2")])
    if rec.words[-1] == "2":
        return RuleOutcome(PASS, "ios.ssh_version.ok")
    return RuleOutcome(FAIL, "ios.ssh_version.v1", [_ev(rec)])


def check_ios_ssh_timeout(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.1.4 — 'ip ssh time-out' <= 60 secondi."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip ssh time-out", "ip ssh timeout")
    if rec is None:
        return RuleOutcome(WARN, "ios.ssh_timeout.not_set",
                           [absent("ev.no_directive",
                                   what="ip ssh time-out %d"
                                        % _MAX_SSH_TIMEOUT_S)])
    val = _int_arg(rec, -1)
    if val is None:
        return RuleOutcome(WARN, "ios.ssh_timeout.unreadable", [_ev(rec)])
    if val > _MAX_SSH_TIMEOUT_S:
        return RuleOutcome(FAIL, "ios.ssh_timeout.too_high", [_ev(rec)],
                           {"value": val, "max": _MAX_SSH_TIMEOUT_S})
    return RuleOutcome(PASS, "ios.ssh_timeout.ok", (), {"value": val})


def check_ios_ssh_auth_retries(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.1.5 — 'ip ssh authentication-retries' <= 3."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip ssh authentication-retries")
    if rec is None:
        return RuleOutcome(WARN, "ios.ssh_retries.not_set",
                           [absent("ev.no_directive",
                                   what="ip ssh authentication-retries %d"
                                        % _MAX_SSH_RETRIES)])
    val = _int_arg(rec, -1)
    if val is None:
        return RuleOutcome(WARN, "ios.ssh_retries.unreadable", [_ev(rec)])
    if val > _MAX_SSH_RETRIES:
        return RuleOutcome(FAIL, "ios.ssh_retries.too_high", [_ev(rec)],
                           {"value": val, "max": _MAX_SSH_RETRIES})
    return RuleOutcome(PASS, "ios.ssh_retries.ok", (), {"value": val})


def check_ios_domain_name(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.1.2 — 'ip domain-name' impostato (prerequisito di SSH)."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip domain-name", "ip domain name")
    if rec is None:
        return RuleOutcome(FAIL, "ios.domain.absent",
                           [absent("ev.no_directive", what="ip domain-name")])
    return RuleOutcome(PASS, "ios.domain.ok", (), {"domain": rec.words[-1]})


def _check_service_off(cfg: IosConfig, service: str,
                       key: str) -> RuleOutcome:
    """Servizio che deve risultare disattivato ('no <service>')."""
    g = _guard(cfg)
    if g:
        return g
    if has_top(cfg, "no %s" % service):
        return RuleOutcome(PASS, "ios.service.ok", (), {"service": service})
    enabled = find_top(cfg, service)
    if enabled:
        # Solo l'esito negativo ha una chiave per servizio: il rischio di un CDP
        # acceso non e' quello di un PAD acceso, e dirlo in modo generico
        # ("servizio attivo") toglierebbe al report la sola parte utile.
        return RuleOutcome(FAIL, key + ".enabled", [_ev(enabled[0])],
                           {"service": service})
    # IOS non stampa i default: l'assenza della riga 'no ...' significa che il
    # servizio e' attivo col default di fabbrica, ma la configurazione non lo
    # afferma. WARN, non FAIL: il verdetto certo richiede 'show running-config
    # all', che qui non c'e'.
    return RuleOutcome(
        WARN, "ios.service.not_disabled",
        [absent("ev.no_directive", what="no %s" % service)],
        {"service": service})


def check_ios_cdp(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.2 — 'no cdp run'."""
    return _check_service_off(cfg, "cdp run", "ios.cdp")


def check_ios_service_dhcp(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.4 — 'no service dhcp'."""
    return _check_service_off(cfg, "service dhcp", "ios.dhcp")


def check_ios_service_pad(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.7 — 'no service pad'."""
    return _check_service_off(cfg, "service pad", "ios.pad")


def check_ios_tcp_keepalives(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.5 / 2.1.6 — 'service tcp-keepalives-in' e '-out'."""
    g = _guard(cfg)
    if g:
        return g
    missing = [d for d in ("in", "out")
               if not has_top(cfg, "service tcp-keepalives-%s" % d)]
    if missing:
        return RuleOutcome(
            FAIL, "ios.keepalive.missing",
            [absent("ev.no_directive", what="service tcp-keepalives-%s" % d)
             for d in missing],
            {"directives": ", ".join("tcp-keepalives-%s" % d
                                     for d in missing)})
    return RuleOutcome(PASS, "ios.keepalive.ok")


# --- 2.2 Logging --------------------------------------------------------------

def check_ios_logging_host(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.4 — almeno un 'logging host' remoto."""
    g = _guard(cfg)
    if g:
        return g
    hosts = find_top(cfg, "logging host", "logging server")
    # 'logging <ip>' senza la parola chiave 'host' e' la forma storica, ancora
    # accettata da IOS e ancora presente in molte configurazioni.
    legacy = [l for l in find_top(cfg, "logging ")
              if len(l.words) == 2 and l.words[1][:1].isdigit()]
    if hosts or legacy:
        return RuleOutcome(PASS, "ios.log_host.ok", (),
                           {"count": len(set(hosts + legacy))})
    return RuleOutcome(FAIL, "ios.log_host.absent",
                       [absent("ev.no_directive", what="logging host")])


def check_ios_logging_buffered(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.2 — 'logging buffered' con dimensione adeguata."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "logging buffered")
    if rec is None:
        return RuleOutcome(FAIL, "ios.log_buffer.absent",
                           [absent("ev.no_directive",
                                   what="logging buffered %d"
                                        % _MIN_LOG_BUFFER)])
    size = next((v for v in (_int_arg(rec, i)
                             for i in range(2, len(rec.words)))
                 if v is not None), None)
    if size is None:
        return RuleOutcome(WARN, "ios.log_buffer.no_size", [_ev(rec)])
    if size < _MIN_LOG_BUFFER:
        return RuleOutcome(WARN, "ios.log_buffer.small", [_ev(rec)],
                           {"size": size, "min": _MIN_LOG_BUFFER})
    return RuleOutcome(PASS, "ios.log_buffer.ok", (), {"size": size})


def check_ios_logging_console(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.3 — 'logging console critical'."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "logging console")
    if rec is None:
        return RuleOutcome(WARN, "ios.log_console.not_set",
                           [absent("ev.no_directive",
                                   what="logging console critical")])
    if rec.words[-1] in ("critical", "2", "emergencies", "0", "alerts", "1"):
        return RuleOutcome(PASS, "ios.log_console.ok", (),
                           {"level": rec.words[-1]})
    return RuleOutcome(WARN, "ios.log_console.verbose", [_ev(rec)],
                       {"level": rec.words[-1]})


def check_ios_logging_trap(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.5 — 'logging trap informational' (o piu' dettagliato)."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "logging trap")
    if rec is None:
        return RuleOutcome(WARN, "ios.log_trap.not_set",
                           [absent("ev.no_directive",
                                   what="logging trap informational")])
    level = rec.words[-1]
    if level in ("informational", "6", "debugging", "7"):
        return RuleOutcome(PASS, "ios.log_trap.ok", (), {"level": level})
    return RuleOutcome(FAIL, "ios.log_trap.too_strict", [_ev(rec)],
                       {"level": level})


def check_ios_service_timestamps(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.6 — 'service timestamps ... datetime' su log e debug."""
    g = _guard(cfg)
    if g:
        return g
    stamps = find_top(cfg, "service timestamps")
    if not stamps:
        return RuleOutcome(FAIL, "ios.timestamps.absent",
                           [absent("ev.no_directive",
                                   what="service timestamps log datetime")])
    bad = [l for l in stamps if "datetime" not in l.words]
    if bad:
        return RuleOutcome(WARN, "ios.timestamps.uptime",
                           [_ev(l) for l in bad])
    return RuleOutcome(PASS, "ios.timestamps.ok")


def check_ios_logging_source_interface(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.7 — 'logging source-interface' fissata."""
    g = _guard(cfg)
    if g:
        return g
    if has_top(cfg, "logging source-interface"):
        return RuleOutcome(PASS, "ios.log_source.ok")
    return RuleOutcome(WARN, "ios.log_source.absent",
                       [absent("ev.no_directive",
                               what="logging source-interface")])


def check_ios_login_logging(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.8 — 'login on-failure log' e 'login on-success log'."""
    g = _guard(cfg)
    if g:
        return g
    missing = [d for d in ("on-failure", "on-success")
               if not has_top(cfg, "login %s log" % d)]
    if missing:
        return RuleOutcome(
            FAIL, "ios.login_log.missing",
            [absent("ev.no_directive", what="login %s log" % d)
             for d in missing],
            {"directives": ", ".join("login %s log" % d for d in missing)})
    return RuleOutcome(PASS, "ios.login_log.ok")


# --- 2.3 NTP ------------------------------------------------------------------

def check_ios_ntp_servers(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.3.2 — almeno un 'ntp server' configurato."""
    g = _guard(cfg)
    if g:
        return g
    servers = find_top(cfg, "ntp server")
    if not servers:
        return RuleOutcome(FAIL, "ios.ntp.absent",
                           [absent("ev.no_directive", what="ntp server")])
    if len(servers) < 2:
        return RuleOutcome(WARN, "ios.ntp.single", [_ev(servers[0])])
    return RuleOutcome(PASS, "ios.ntp.ok", (), {"count": len(servers)})


def check_ios_ntp_authentication(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.3.1.1 / 2.3.1.3 — NTP autenticato con chiave fidata."""
    g = _guard(cfg)
    if g:
        return g
    if not find_top(cfg, "ntp server"):
        return RuleOutcome(UNKNOWN, "ios.ntp_auth.not_applicable")
    ev: List[Evidence] = []
    if not has_top(cfg, "ntp authenticate"):
        ev.append(absent("ev.no_directive", what="ntp authenticate"))
    if not has_top(cfg, "ntp trusted-key"):
        ev.append(absent("ev.no_directive", what="ntp trusted-key"))
    if ev:
        return RuleOutcome(FAIL, "ios.ntp_auth.missing", ev)
    return RuleOutcome(PASS, "ios.ntp_auth.ok")


# --- 3.1 Piano dati -----------------------------------------------------------

def check_ios_source_route(cfg: IosConfig) -> RuleOutcome:
    """CIS 3.1.1 — 'no ip source-route'."""
    return _check_service_off(cfg, "ip source-route", "ios.source_route")


def check_ios_proxy_arp(cfg: IosConfig) -> RuleOutcome:
    """CIS 3.1.2 — 'no ip proxy-arp' sulle interfacce con indirizzamento IP."""
    g = _guard(cfg)
    if g:
        return g
    ifaces = [(h, k) for h, k in blocks_matching(cfg, "interface")
              if child(k, "ip address") is not None]
    if not ifaces:
        return RuleOutcome(UNKNOWN, "ios.proxy_arp.no_ip_iface")
    ev = [absent("ev.not_set_default_on", header, what="no ip proxy-arp")
          for header, kids in ifaces if child(kids, "no ip proxy-arp") is None]
    if ev:
        return RuleOutcome(WARN, "ios.proxy_arp.enabled", ev,
                           {"count": len(ev)})
    return RuleOutcome(PASS, "ios.proxy_arp.ok")


def check_ios_tunnel_interfaces(cfg: IosConfig) -> RuleOutcome:
    """CIS 3.1.3 — nessuna interfaccia 'tunnel' non prevista."""
    g = _guard(cfg)
    if g:
        return g
    tunnels = blocks_matching(cfg, "interface tunnel")
    if not tunnels:
        return RuleOutcome(PASS, "ios.tunnel.none")
    return RuleOutcome(
        WARN, "ios.tunnel.present",
        [Evidence(0, header, "interface") for header, _ in tunnels],
        {"count": len(tunnels)})
