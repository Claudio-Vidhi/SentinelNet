# -*- coding: utf-8 -*-
"""Valutazioni di audit sull'artefatto di backup di un host Linux.

Distillate dal *CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0*. Il numero della
raccomandazione, il comando di audit e quello di rimedio vivono in
``benchmarks.py``; qui sta solo la valutazione, che e' una funzione pura
``LinuxConfig -> RuleOutcome``.

Come per le altre due piattaforme, le regole dichiarano una CHIAVE di
``messages.py``, non una frase: vedi la nota sulla lingua in ``model.py``.

ASSENZA E VERDETTO — su Linux la risposta cambia da file a file, e sbagliarla
significa emettere verdetti inventati:

  - **sshd** — un'opzione assente NON e' "non valutabile": vale il default
    compilato, che qui e' scritto accanto a ogni regola. C'e' pero' un caso in
    cui l'assenza non dice nulla: se ``sshd_config`` contiene una direttiva
    ``Include`` (il default di Ubuntu 24.04), l'impostazione puo' vivere in
    ``sshd_config.d/`` che l'artefatto non contiene → UNKNOWN. Il triage
    privilegiato appende ``sshd -T``, la configurazione EFFETTIVA: quando c'e',
    vince su tutto e il dubbio non si pone.
  - **login.defs** — il file c'e' sempre e dichiara la politica: una direttiva
    assente significa nessuna politica dichiarata, quindi FAIL.
  - **sysctl.conf** — un parametro assente NON e' un verdetto: puo' essere
    impostato in ``/etc/sysctl.d/`` o a runtime, che l'artefatto non vede.
    UNKNOWN. Impostato al valore sbagliato e' invece una violazione piena.
  - **fstab** — nessuna riga per un punto di mount puo' voler dire che non e'
    una partizione separata (su ``/tmp`` il benchmark ammette anche tmpfs
    montato da systemd): UNKNOWN. Riga presente senza l'opzione: FAIL.

Se una sezione manca del tutto dall'artefatto, la regola che la legge e'
UNKNOWN: e' un backup parziale, non un host non conforme.
"""

from typing import List, Optional, Tuple

from .linux_parser import (
    SSHD_EFFECTIVE, LinuxConfig, LinuxLine, directives, first_directive,
    fstab_entry, fstab_options, has_file, is_empty, last_directive,
    sysctl_value)
from .model import FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome, absent

SSHD_CONFIG = "/etc/ssh/sshd_config"
LOGIN_DEFS = "/etc/login.defs"
SYSCTL_CONF = "/etc/sysctl.conf"
FSTAB = "/etc/fstab"

# --- soglie dichiarate dal benchmark -----------------------------------------

_MAX_AUTH_TRIES = 4             # 5.1.16
_MAX_LOGIN_GRACE_S = 60         # 5.1.13
_MAX_PASS_MAX_DAYS = 365        # 5.4.1.1
_MIN_PASS_MIN_DAYS = 1          # 5.4.1.2
_MIN_PASS_WARN_AGE = 7          # 5.4.1.3
_LOG_LEVELS = ("info", "verbose")               # 5.1.14
_STRONG_HASHES = ("sha512", "yescrypt")         # 5.4.1.4


def _ev(l: LinuxLine, note: str = "") -> Evidence:
    return Evidence(l.line, l.text, note)


def _guard(cfg: LinuxConfig) -> Optional[RuleOutcome]:
    return RuleOutcome(UNKNOWN, "lnx.empty") if is_empty(cfg) else None


def _int_of(l: LinuxLine, index: int = 1) -> Optional[int]:
    try:
        return int(l.words[index])
    except (IndexError, ValueError):
        return None


# --- sshd ---------------------------------------------------------------------

def _sshd_directive(cfg: LinuxConfig,
                    keyword: str) -> Tuple[Optional[LinuxLine], str]:
    """(riga, stato) dell'opzione sshd. Stato: ``set``, ``default``, ``unknown``.

    ``sshd -T`` stampa la configurazione effettiva e ha la precedenza: e' l'unico
    modo di sapere cosa applica davvero un host che usa ``Include``.
    """
    effective = cfg.files.get(SSHD_EFFECTIVE) or []
    hit = first_directive(effective, keyword)
    if hit is not None:
        return hit, "set"

    if not has_file(cfg, SSHD_CONFIG):
        return None, "unknown"
    lines = cfg.files[SSHD_CONFIG]
    # sshd applica la PRIMA occorrenza, non l'ultima.
    hit = first_directive(lines, keyword)
    if hit is not None:
        return hit, "set"
    if directives(lines, "include"):
        return None, "unknown"
    return None, "default"


def _sshd_flag(cfg: LinuxConfig, keyword: str, wanted: str, ok_key: str,
               bad_key: str, default_value: str) -> RuleOutcome:
    """Opzione sshd binaria: confronto col valore atteso, default compreso."""
    g = _guard(cfg)
    if g:
        return g
    line, state = _sshd_directive(cfg, keyword)
    if state == "unknown":
        return RuleOutcome(UNKNOWN, "lnx.sshd.not_assessable",
                           (), {"what": keyword})
    if state == "default":
        if default_value == wanted:
            return RuleOutcome(PASS, ok_key, (), {"value": default_value})
        return RuleOutcome(FAIL, bad_key,
                           [absent("ev.not_set_default_value", SSHD_CONFIG,
                                   what=keyword, value=default_value)],
                           {"value": default_value})
    assert line is not None
    value = line.words[1] if len(line.words) > 1 else ""
    if value == wanted:
        return RuleOutcome(PASS, ok_key, (), {"value": value})
    return RuleOutcome(FAIL, bad_key, [_ev(line, SSHD_CONFIG)],
                       {"value": value or "-"})


def check_linux_sshd_permit_root_login(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.20 — login diretto di root via SSH disabilitato."""
    return _sshd_flag(cfg, "permitrootlogin", "no", "lnx.sshd_root.ok",
                      "lnx.sshd_root.allowed", "prohibit-password")


def check_linux_sshd_permit_empty_passwords(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.19 — nessun accesso con password vuota."""
    return _sshd_flag(cfg, "permitemptypasswords", "no", "lnx.sshd_empty.ok",
                      "lnx.sshd_empty.allowed", "no")


def check_linux_sshd_hostbased_auth(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.10 — autenticazione basata sull'host disabilitata."""
    return _sshd_flag(cfg, "hostbasedauthentication", "no",
                      "lnx.sshd_hostbased.ok", "lnx.sshd_hostbased.enabled",
                      "no")


def check_linux_sshd_ignore_rhosts(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.11 — i file .rhosts/.shosts non partecipano all'autenticazione."""
    return _sshd_flag(cfg, "ignorerhosts", "yes", "lnx.sshd_rhosts.ok",
                      "lnx.sshd_rhosts.honored", "yes")


def check_linux_sshd_disable_forwarding(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.8 — inoltro TCP/X11 attraverso la sessione SSH disattivato."""
    return _sshd_flag(cfg, "disableforwarding", "yes",
                      "lnx.sshd_forwarding.ok", "lnx.sshd_forwarding.allowed",
                      "no")


def check_linux_sshd_max_auth_tries(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.16 — tentativi di autenticazione per connessione limitati."""
    g = _guard(cfg)
    if g:
        return g
    line, state = _sshd_directive(cfg, "maxauthtries")
    if state == "unknown":
        return RuleOutcome(UNKNOWN, "lnx.sshd.not_assessable", (),
                           {"what": "MaxAuthTries"})
    if state == "default":
        # Il default compilato di OpenSSH e' 6: sopra la soglia del benchmark.
        return RuleOutcome(FAIL, "lnx.sshd_authtries.high",
                           [absent("ev.not_set_default_value", SSHD_CONFIG,
                                   what="MaxAuthTries", value=6)],
                           {"value": 6, "max": _MAX_AUTH_TRIES})
    assert line is not None
    value = _int_of(line)
    if value is None:
        return RuleOutcome(WARN, "lnx.sshd_authtries.unreadable", [_ev(line)])
    if value <= _MAX_AUTH_TRIES:
        return RuleOutcome(PASS, "lnx.sshd_authtries.ok", (), {"value": value})
    return RuleOutcome(FAIL, "lnx.sshd_authtries.high", [_ev(line)],
                       {"value": value, "max": _MAX_AUTH_TRIES})


def check_linux_sshd_login_grace_time(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.13 — finestra per completare l'autenticazione limitata."""
    g = _guard(cfg)
    if g:
        return g
    line, state = _sshd_directive(cfg, "logingracetime")
    if state == "unknown":
        return RuleOutcome(UNKNOWN, "lnx.sshd.not_assessable", (),
                           {"what": "LoginGraceTime"})
    if state == "default":
        return RuleOutcome(FAIL, "lnx.sshd_grace.high",
                           [absent("ev.not_set_default_value", SSHD_CONFIG,
                                   what="LoginGraceTime", value=120)],
                           {"value": 120, "max": _MAX_LOGIN_GRACE_S})
    assert line is not None
    value = _int_of(line)
    if value is None:
        return RuleOutcome(WARN, "lnx.sshd_grace.unreadable", [_ev(line)])
    # Zero disattiva il limite: e' il caso peggiore, non il migliore.
    if 1 <= value <= _MAX_LOGIN_GRACE_S:
        return RuleOutcome(PASS, "lnx.sshd_grace.ok", (), {"value": value})
    return RuleOutcome(FAIL, "lnx.sshd_grace.high", [_ev(line)],
                       {"value": value, "max": _MAX_LOGIN_GRACE_S})


def check_linux_sshd_client_alive(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.7 — sessione inattiva chiusa dal server."""
    g = _guard(cfg)
    if g:
        return g
    values = {}
    for keyword, fallback in (("clientaliveinterval", 0),
                              ("clientalivecountmax", 3)):
        line, state = _sshd_directive(cfg, keyword)
        if state == "unknown":
            return RuleOutcome(UNKNOWN, "lnx.sshd.not_assessable", (),
                               {"what": "ClientAlive*"})
        values[keyword] = (fallback if line is None else _int_of(line), line)
    interval, interval_line = values["clientaliveinterval"]
    count, count_line = values["clientalivecountmax"]
    bad = [l for v, l in (values["clientaliveinterval"],
                          values["clientalivecountmax"])
           if not v]
    if bad:
        evidence: List[Evidence] = [_ev(l) for l in bad if l is not None]
        if not evidence:
            evidence = [absent("ev.not_set_default_value", SSHD_CONFIG,
                               what="ClientAliveInterval", value=0)]
        return RuleOutcome(FAIL, "lnx.sshd_alive.disabled", evidence,
                           {"interval": interval or 0, "count": count or 0})
    return RuleOutcome(PASS, "lnx.sshd_alive.ok", (),
                       {"interval": interval, "count": count})


def check_linux_sshd_log_level(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.14 — livello di log sufficiente a ricostruire gli accessi."""
    g = _guard(cfg)
    if g:
        return g
    line, state = _sshd_directive(cfg, "loglevel")
    if state == "unknown":
        return RuleOutcome(UNKNOWN, "lnx.sshd.not_assessable", (),
                           {"what": "LogLevel"})
    if state == "default":
        return RuleOutcome(PASS, "lnx.sshd_loglevel.ok", (), {"value": "INFO"})
    assert line is not None
    value = line.words[1] if len(line.words) > 1 else ""
    if value in _LOG_LEVELS:
        return RuleOutcome(PASS, "lnx.sshd_loglevel.ok", (), {"value": value})
    return RuleOutcome(FAIL, "lnx.sshd_loglevel.weak", [_ev(line)],
                       {"value": value or "-"})


def check_linux_sshd_banner(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.1.5 — avviso legale mostrato prima dell'autenticazione."""
    g = _guard(cfg)
    if g:
        return g
    line, state = _sshd_directive(cfg, "banner")
    if state == "unknown":
        return RuleOutcome(UNKNOWN, "lnx.sshd.not_assessable", (),
                           {"what": "Banner"})
    if state == "default":
        return RuleOutcome(FAIL, "lnx.sshd_banner.absent",
                           [absent("ev.no_directive", SSHD_CONFIG,
                                   what="Banner")])
    assert line is not None
    value = line.words[1] if len(line.words) > 1 else ""
    if not value or value == "none":
        return RuleOutcome(FAIL, "lnx.sshd_banner.absent", [_ev(line)])
    return RuleOutcome(PASS, "lnx.sshd_banner.ok", (), {"value": value})


# --- login.defs ---------------------------------------------------------------

def _login_defs_int(cfg: LinuxConfig, keyword: str):
    """(valore, riga, stato) da login.defs. Stato: ``set``, ``absent``, ``no_file``."""
    if not has_file(cfg, LOGIN_DEFS):
        return None, None, "no_file"
    # login.defs applica l'ULTIMA assegnazione della stessa chiave.
    line = last_directive(cfg.files[LOGIN_DEFS], keyword)
    if line is None:
        return None, None, "absent"
    return _int_of(line), line, "set"


def _pass_policy(cfg: LinuxConfig, keyword: str, ok_key: str, bad_key: str,
                 limit: int, at_most: bool) -> RuleOutcome:
    g = _guard(cfg)
    if g:
        return g
    value, line, state = _login_defs_int(cfg, keyword)
    if state == "no_file":
        return RuleOutcome(UNKNOWN, "lnx.login_defs.absent")
    if state == "absent":
        return RuleOutcome(FAIL, "lnx.pass_policy.undeclared",
                           [absent("ev.no_directive", LOGIN_DEFS,
                                   what=keyword)], {"what": keyword})
    assert line is not None
    if value is None:
        return RuleOutcome(WARN, "lnx.pass_policy.unreadable", [_ev(line)],
                           {"what": keyword})
    ok = (0 < value <= limit) if at_most else (value >= limit)
    if ok:
        return RuleOutcome(PASS, ok_key, (), {"value": value})
    return RuleOutcome(FAIL, bad_key, [_ev(line, LOGIN_DEFS)],
                       {"value": value, "limit": limit})


def check_linux_pass_max_days(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.4.1.1 — scadenza massima della password dichiarata."""
    return _pass_policy(cfg, "pass_max_days", "lnx.pass_max.ok",
                        "lnx.pass_max.too_long", _MAX_PASS_MAX_DAYS, True)


def check_linux_pass_min_days(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.4.1.2 — intervallo minimo fra due cambi password."""
    return _pass_policy(cfg, "pass_min_days", "lnx.pass_min.ok",
                        "lnx.pass_min.too_short", _MIN_PASS_MIN_DAYS, False)


def check_linux_pass_warn_age(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.4.1.3 — preavviso prima della scadenza della password."""
    return _pass_policy(cfg, "pass_warn_age", "lnx.pass_warn.ok",
                        "lnx.pass_warn.too_short", _MIN_PASS_WARN_AGE, False)


def check_linux_encrypt_method(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 5.4.1.4 — algoritmo di hashing delle password robusto."""
    g = _guard(cfg)
    if g:
        return g
    if not has_file(cfg, LOGIN_DEFS):
        return RuleOutcome(UNKNOWN, "lnx.login_defs.absent")
    line = last_directive(cfg.files[LOGIN_DEFS], "encrypt_method")
    if line is None:
        return RuleOutcome(FAIL, "lnx.encrypt.undeclared",
                           [absent("ev.no_directive", LOGIN_DEFS,
                                   what="ENCRYPT_METHOD")])
    value = line.words[1] if len(line.words) > 1 else ""
    if value in _STRONG_HASHES:
        return RuleOutcome(PASS, "lnx.encrypt.ok", (), {"value": value.upper()})
    return RuleOutcome(FAIL, "lnx.encrypt.weak", [_ev(line, LOGIN_DEFS)],
                       {"value": value.upper() or "-"})


# --- fstab --------------------------------------------------------------------

def _mount_options(cfg: LinuxConfig, mount_point: str, wanted: tuple,
                   ok_key: str, bad_key: str) -> RuleOutcome:
    g = _guard(cfg)
    if g:
        return g
    if not has_file(cfg, FSTAB):
        return RuleOutcome(UNKNOWN, "lnx.fstab.absent")
    entry = fstab_entry(cfg.files[FSTAB], mount_point)
    if entry is None:
        # Nessuna riga: puo' non essere una partizione separata (su /tmp il
        # benchmark ammette anche un tmpfs montato da systemd). Da fstab non si
        # vedono le opzioni effettive, quindi non si conclude.
        return RuleOutcome(UNKNOWN, "lnx.mount.not_separate", (),
                           {"mount": mount_point})
    options = fstab_options(entry)
    missing = [o for o in wanted if o not in options]
    if missing:
        return RuleOutcome(FAIL, bad_key, [_ev(entry, FSTAB)],
                           {"mount": mount_point, "missing": ", ".join(missing)})
    return RuleOutcome(PASS, ok_key, (), {"mount": mount_point})


def check_linux_tmp_mount_options(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 1.1.2.1.2 / 1.1.2.1.3 / 1.1.2.1.4 — /tmp senza device, setuid, exec."""
    return _mount_options(cfg, "/tmp", ("nodev", "nosuid", "noexec"),
                          "lnx.mount.ok", "lnx.mount.missing_options")


def check_linux_var_mount_options(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 1.1.2.4.2 / 1.1.2.4.3 — /var senza device e senza setuid."""
    return _mount_options(cfg, "/var", ("nodev", "nosuid"),
                          "lnx.mount.ok", "lnx.mount.missing_options")


# --- sysctl -------------------------------------------------------------------

def _sysctl_rule(cfg: LinuxConfig, keys: tuple, wanted: str, ok_key: str,
                 bad_key: str) -> RuleOutcome:
    """Parametri di rete che devono valere ``wanted``.

    Assente da ``sysctl.conf`` non e' un verdetto: il valore puo' arrivare da
    ``/etc/sysctl.d/`` o essere stato impostato a runtime, e l'artefatto non li
    contiene. Impostato al valore sbagliato e' invece una violazione piena,
    qualunque cosa faccia il resto del sistema.
    """
    g = _guard(cfg)
    if g:
        return g
    if not has_file(cfg, SYSCTL_CONF):
        return RuleOutcome(UNKNOWN, "lnx.sysctl.absent")
    lines = cfg.files[SYSCTL_CONF]
    found, wrong = [], []
    for key in keys:
        line = sysctl_value(lines, key)
        if line is None:
            continue
        found.append(line)
        if line.lower.split("=", 1)[-1].strip() != wanted:
            wrong.append(line)
    if wrong:
        return RuleOutcome(FAIL, bad_key, [_ev(l, SYSCTL_CONF) for l in wrong],
                           {"count": len(wrong), "value": wanted})
    if not found:
        return RuleOutcome(UNKNOWN, "lnx.sysctl.not_declared", (),
                           {"what": keys[0]})
    return RuleOutcome(PASS, ok_key, (), {"count": len(found)})


def check_linux_ip_forward(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 3.3.1.1 — inoltro di pacchetti IP disattivato su un host non router."""
    return _sysctl_rule(cfg, ("net.ipv4.ip_forward",), "0",
                        "lnx.sysctl_forward.ok", "lnx.sysctl_forward.enabled")


def check_linux_accept_redirects(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 3.3.1.8 / 3.3.1.9 — ICMP redirect in ingresso ignorati."""
    return _sysctl_rule(cfg, ("net.ipv4.conf.all.accept_redirects",
                              "net.ipv4.conf.default.accept_redirects"), "0",
                        "lnx.sysctl_accept_redirects.ok",
                        "lnx.sysctl_accept_redirects.enabled")


def check_linux_send_redirects(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 3.3.1.4 / 3.3.1.5 — ICMP redirect non emessi."""
    return _sysctl_rule(cfg, ("net.ipv4.conf.all.send_redirects",
                              "net.ipv4.conf.default.send_redirects"), "0",
                        "lnx.sysctl_send_redirects.ok",
                        "lnx.sysctl_send_redirects.enabled")


def check_linux_source_route(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 3.3.1.14 / 3.3.1.15 — pacchetti con source routing scartati."""
    return _sysctl_rule(cfg, ("net.ipv4.conf.all.accept_source_route",
                              "net.ipv4.conf.default.accept_source_route"), "0",
                        "lnx.sysctl_source_route.ok",
                        "lnx.sysctl_source_route.enabled")


def check_linux_tcp_syncookies(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 3.3.1.18 — protezione contro il SYN flood attiva."""
    return _sysctl_rule(cfg, ("net.ipv4.tcp_syncookies",), "1",
                        "lnx.sysctl_syncookies.ok",
                        "lnx.sysctl_syncookies.disabled")


def check_linux_log_martians(cfg: LinuxConfig) -> RuleOutcome:
    """CIS 3.3.1.16 / 3.3.1.17 — pacchetti con indirizzo impossibile registrati."""
    return _sysctl_rule(cfg, ("net.ipv4.conf.all.log_martians",
                              "net.ipv4.conf.default.log_martians"), "1",
                        "lnx.sysctl_martians.ok",
                        "lnx.sysctl_martians.disabled")
