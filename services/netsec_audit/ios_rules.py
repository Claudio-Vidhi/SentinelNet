# -*- coding: utf-8 -*-
"""Valutazioni di audit su configurazione Cisco IOS / IOS-XE parsata.

Distillate dal *CIS Cisco IOS XE 17.x Benchmark v2.2.1*. Il numero della
raccomandazione, il comando di audit e quello di rimedio vivono in
``benchmarks.py``; qui sta solo la valutazione, che e' una funzione pura
``IosConfig -> RuleOutcome``.

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
from .model import FAIL, PASS, UNKNOWN, WARN, Evidence, RuleOutcome

# --- soglie dichiarate dal benchmark -----------------------------------------

_MAX_EXEC_TIMEOUT_MIN = 10      # 1.2.6 / 1.2.7 / 1.2.8
_MAX_SSH_TIMEOUT_S = 60         # 2.1.1.1.4
_MAX_SSH_RETRIES = 3            # 2.1.1.1.5
_MIN_LOG_BUFFER = 64000         # 2.2.2 ("Recommended size is 64000")
_MIN_SNMP_AES_BITS = 128        # 1.5.10

_EMPTY = "Configurazione vuota o non riconosciuta come Cisco IOS."


def _ev(l: IosLine, note: str = "") -> Evidence:
    return Evidence(l.line, l.text, " / ".join(p for p in l.path if p) or note)


def _absent(what: str, ctx: str = "running-config") -> Evidence:
    return Evidence(0, what, ctx)


def _guard(cfg: IosConfig) -> Optional[RuleOutcome]:
    return RuleOutcome(UNKNOWN, _EMPTY) if is_empty(cfg) else None


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
        return RuleOutcome(
            FAIL, "'aaa new-model' esplicitamente disabilitato: nessun "
                  "controllo accessi centralizzato.",
            [_ev(find_top(cfg, "no aaa new-model")[0])])
    if has_top(cfg, "aaa new-model"):
        return RuleOutcome(PASS, "'aaa new-model' abilitato.")
    return RuleOutcome(
        FAIL, "'aaa new-model' assente: l'apparato usa l'autenticazione "
              "legacy di linea.",
        [_absent("nessun 'aaa new-model' nella configurazione")])


def check_ios_aaa_authentication_login(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.1.2 — metodo 'aaa authentication login' definito."""
    g = _guard(cfg)
    if g:
        return g
    if not has_top(cfg, "aaa new-model"):
        return RuleOutcome(
            UNKNOWN, "'aaa new-model' non attivo: i metodi AAA di login non "
                     "sono applicabili.")
    hits = find_top(cfg, "aaa authentication login")
    if not hits:
        return RuleOutcome(
            FAIL, "Nessun 'aaa authentication login' definito.",
            [_absent("nessun 'aaa authentication login'")])
    # Un metodo 'none' vanifica il controllo: e' peggio dell'assenza, perche'
    # sembra configurato.
    weak = [l for l in hits if l.words[-1:] == ["none"]]
    if weak:
        return RuleOutcome(
            FAIL, "Metodo di login con fallback 'none': accesso senza "
                  "credenziali.",
            [_ev(l) for l in weak])
    return RuleOutcome(
        PASS, "Autenticazione di login AAA definita (%d liste)." % len(hits))


def check_ios_aaa_accounting_commands(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.1.6 — accounting dei comandi a privilegio 15."""
    g = _guard(cfg)
    if g:
        return g
    if not has_top(cfg, "aaa new-model"):
        return RuleOutcome(
            UNKNOWN, "'aaa new-model' non attivo: l'accounting AAA non e' "
                     "applicabile.")
    if find_top(cfg, "aaa accounting commands 15"):
        return RuleOutcome(
            PASS, "Accounting dei comandi privilegiati (livello 15) attivo.")
    return RuleOutcome(
        FAIL, "Nessun 'aaa accounting commands 15': i comandi privilegiati "
              "non lasciano traccia di chi li ha eseguiti.",
        [_absent("nessun 'aaa accounting commands 15'")])


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
        return RuleOutcome(
            UNKNOWN, "Nessuna 'line vty' configurata: accesso remoto non "
                     "valutabile.")
    ev: List[Evidence] = []
    for header, kids in vtys:
        t = child(kids, "transport input")
        if t is None:
            ev.append(_absent("nessun 'transport input' (default: tutti i "
                              "protocolli, telnet compreso)", header))
            continue
        allowed = set(t.words[2:])
        if allowed - {"ssh", "none"}:
            ev.append(_ev(t, header))
    if ev:
        return RuleOutcome(
            FAIL, "Protocolli non cifrati ammessi su %d linea/e vty." % len(ev),
            ev)
    return RuleOutcome(PASS, "Tutte le 'line vty' accettano solo SSH.")


def check_ios_vty_access_class(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.5 — 'access-class' applicata a ogni 'line vty'."""
    g = _guard(cfg)
    if g:
        return g
    vtys = _vty_blocks(cfg)
    if not vtys:
        return RuleOutcome(
            UNKNOWN, "Nessuna 'line vty' configurata: nessun accesso remoto "
                     "da restringere.")
    ev = [_absent("nessuna 'access-class ... in' sulla linea", header)
          for header, kids in vtys
          if child(kids, "access-class") is None]
    if ev:
        return RuleOutcome(
            FAIL, "%d linea/e vty raggiungibili da qualunque indirizzo "
                  "sorgente." % len(ev), ev)
    return RuleOutcome(
        PASS, "Ogni 'line vty' e' ristretta da una access-class.")


def _check_exec_timeout(cfg: IosConfig, prefix: str,
                        what: str) -> RuleOutcome:
    g = _guard(cfg)
    if g:
        return g
    found = blocks_matching(cfg, prefix)
    if not found:
        return RuleOutcome(
            UNKNOWN, "Nessuna linea '%s' configurata." % prefix)
    ev: List[Evidence] = []
    for header, kids in found:
        t = child(kids, "exec-timeout")
        if t is None:
            # Default IOS: 10 minuti sulle linee EXEC. Conforme, ma implicito:
            # una modifica al default della piattaforma lo cambia senza che la
            # configurazione lo dica.
            ev.append(_absent("'exec-timeout' non impostato: vale il default "
                              "di piattaforma", header))
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
    if ev:
        return RuleOutcome(
            FAIL,
            "Timeout di inattivita' assente, disabilitato o superiore a %d "
            "minuti su %d %s." % (_MAX_EXEC_TIMEOUT_MIN, len(ev), what), ev)
    return RuleOutcome(
        PASS, "Timeout di inattivita' entro %d minuti su tutte le %s."
              % (_MAX_EXEC_TIMEOUT_MIN, what))


def check_ios_vty_exec_timeout(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.8 — 'exec-timeout' <= 10 minuti su 'line vty'."""
    return _check_exec_timeout(cfg, "line vty", "linee vty")


def check_ios_console_exec_timeout(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.7 — 'exec-timeout' <= 10 minuti su 'line con 0'."""
    return _check_exec_timeout(cfg, "line con", "linee console")


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
        return RuleOutcome(
            UNKNOWN, "Nessuna 'line aux' presente: l'apparato non espone una "
                     "porta ausiliaria.")
    ev = [_absent("nessun 'no exec' sulla porta ausiliaria", header)
          for header, kids in aux if child(kids, "no exec") is None]
    if ev:
        return RuleOutcome(
            FAIL, "Processo EXEC attivo sulla porta ausiliaria.", ev)
    return RuleOutcome(PASS, "Processo EXEC disabilitato sulla porta ausiliaria.")


def check_ios_local_user_privilege(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.2.1 — utenti locali a 'privilege 1'."""
    g = _guard(cfg)
    if g:
        return g
    users = find_top(cfg, "username ")
    if not users:
        return RuleOutcome(
            UNKNOWN, "Nessun utente locale definito: privilegi non valutabili.")
    ev = [_ev(u) for u in users if "privilege 15" in u.lower]
    if ev:
        return RuleOutcome(
            WARN,
            "%d utenti locali con 'privilege 15': ottengono EXEC privilegiato "
            "senza passare da 'enable'." % len(ev), ev)
    return RuleOutcome(
        PASS, "Nessun utente locale con privilegio 15 diretto.")


# --- 1.3 Banner ---------------------------------------------------------------

def _check_banner(cfg: IosConfig, kind: str) -> RuleOutcome:
    g = _guard(cfg)
    if g:
        return g
    if find(cfg, "banner %s" % kind):
        return RuleOutcome(PASS, "Banner '%s' configurato." % kind)
    return RuleOutcome(
        FAIL,
        "Banner '%s' assente: nessuna avvertenza legale all'accesso." % kind,
        [_absent("nessun 'banner %s'" % kind)])


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
        return RuleOutcome(
            FAIL, "'enable password' in uso: cifratura reversibile di tipo 7.",
            [_ev(l) for l in weak])
    if secret:
        return RuleOutcome(PASS, "'enable secret' configurato.")
    return RuleOutcome(
        FAIL, "Nessun 'enable secret': l'accesso privilegiato non e' protetto "
              "da password.",
        [_absent("nessun 'enable secret'")])


def check_ios_service_password_encryption(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.4.2 — 'service password-encryption' abilitato."""
    g = _guard(cfg)
    if g:
        return g
    if has_top(cfg, "no service password-encryption"):
        return RuleOutcome(
            FAIL, "'service password-encryption' esplicitamente disabilitato: "
                  "password in chiaro nella configurazione.",
            [_ev(find_top(cfg, "no service password-encryption")[0])])
    if has_top(cfg, "service password-encryption"):
        return RuleOutcome(PASS, "'service password-encryption' abilitato.")
    return RuleOutcome(
        FAIL, "'service password-encryption' assente: le password di linea "
              "restano in chiaro.",
        [_absent("nessun 'service password-encryption'")])


def check_ios_username_secret(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.4.3 — ogni utente locale usa 'secret', non 'password'."""
    g = _guard(cfg)
    if g:
        return g
    users = find_top(cfg, "username ")
    if not users:
        return RuleOutcome(
            UNKNOWN, "Nessun utente locale definito.")
    ev = [_ev(u) for u in users if " secret " not in (u.lower + " ")]
    if ev:
        return RuleOutcome(
            FAIL,
            "%d utenti locali con 'password' invece di 'secret': hash "
            "reversibile o debole." % len(ev), ev)
    return RuleOutcome(PASS, "Tutti gli utenti locali usano 'secret'.")


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
        return RuleOutcome(
            UNKNOWN, "Nessuna community SNMP configurata: nulla da valutare.")
    ev = [_ev(c) for c in comms
          if len(c.words) > 2 and c.words[2] in _DEFAULT_COMMUNITIES]
    if ev:
        return RuleOutcome(
            FAIL, "Community SNMP di default ('public'/'private') in uso: %d."
                  % len(ev), ev)
    return RuleOutcome(PASS, "Nessuna community SNMP di default.")


def check_ios_snmp_readwrite(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.5.4 — nessuna community SNMP in scrittura (RW)."""
    g = _guard(cfg)
    if g:
        return g
    comms = _communities(cfg)
    if not comms:
        return RuleOutcome(
            UNKNOWN, "Nessuna community SNMP configurata: nulla da valutare.")
    ev = [_ev(c) for c in comms if "rw" in c.words[3:]]
    if ev:
        return RuleOutcome(
            FAIL, "Community SNMP in scrittura: consentono di riconfigurare "
                  "l'apparato via SNMP (%d)." % len(ev), ev)
    return RuleOutcome(PASS, "Nessuna community SNMP in scrittura.")


def check_ios_snmp_community_acl(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.5.5 — ogni community SNMP ristretta da una access-list."""
    g = _guard(cfg)
    if g:
        return g
    comms = _communities(cfg)
    if not comms:
        return RuleOutcome(
            UNKNOWN, "Nessuna community SNMP configurata: nulla da valutare.")
    ev = []
    for c in comms:
        # 'snmp-server community <str> [ro|rw] [ipv6 <acl>] [<acl>]'
        tail = [w for w in c.words[3:] if w not in ("ro", "rw", "view")]
        if not tail:
            ev.append(_ev(c))
    if ev:
        return RuleOutcome(
            FAIL, "%d community SNMP interrogabili da qualunque host: manca "
                  "la access-list." % len(ev), ev)
    return RuleOutcome(
        PASS, "Ogni community SNMP e' ristretta da una access-list.")


def check_ios_snmpv3_privacy(cfg: IosConfig) -> RuleOutcome:
    """CIS 1.5.9 / 1.5.10 — SNMPv3 con autenticazione e cifratura AES 128+."""
    g = _guard(cfg)
    if g:
        return g
    groups = find_top(cfg, "snmp-server group")
    users = find_top(cfg, "snmp-server user")
    if not groups and not users:
        return RuleOutcome(
            UNKNOWN, "Nessun gruppo o utente SNMPv3 configurato.")
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
    if ev:
        return RuleOutcome(
            FAIL, "SNMPv3 senza cifratura o con cifratura sotto AES-%d (%d "
                  "riscontri)." % (_MIN_SNMP_AES_BITS, len(ev)), ev)
    return RuleOutcome(
        PASS, "SNMPv3 configurato con autenticazione e cifratura AES-%d o "
              "superiore." % _MIN_SNMP_AES_BITS)


# --- 2.1 Servizi globali e SSH ------------------------------------------------

def check_ios_ssh_version(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.2 — 'ip ssh version 2'."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip ssh version")
    if rec is None:
        return RuleOutcome(
            WARN, "'ip ssh version' non impostato: SSH opera in modalita' "
                  "compatibile e accetta anche la versione 1.",
            [_absent("nessun 'ip ssh version 2'")])
    if rec.words[-1] == "2":
        return RuleOutcome(PASS, "SSH forzato alla versione 2.")
    return RuleOutcome(
        FAIL, "SSH versione 1 ammessa: protocollo con vulnerabilita' note.",
        [_ev(rec)])


def check_ios_ssh_timeout(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.1.4 — 'ip ssh time-out' <= 60 secondi."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip ssh time-out", "ip ssh timeout")
    if rec is None:
        return RuleOutcome(
            WARN, "'ip ssh time-out' non impostato: vale il default di "
                  "piattaforma (120 s).",
            [_absent("nessun 'ip ssh time-out'")])
    val = _int_arg(rec, -1)
    if val is None:
        return RuleOutcome(WARN, "Valore di 'ip ssh time-out' non "
                                 "interpretabile.", [_ev(rec)])
    if val > _MAX_SSH_TIMEOUT_S:
        return RuleOutcome(
            FAIL, "Timeout di login SSH troppo alto (%d s, massimo consigliato "
                  "%d)." % (val, _MAX_SSH_TIMEOUT_S), [_ev(rec)])
    return RuleOutcome(PASS, "Timeout di login SSH a %d secondi." % val)


def check_ios_ssh_auth_retries(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.1.5 — 'ip ssh authentication-retries' <= 3."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip ssh authentication-retries")
    if rec is None:
        return RuleOutcome(
            WARN, "'ip ssh authentication-retries' non impostato: vale il "
                  "default di piattaforma (3).",
            [_absent("nessun 'ip ssh authentication-retries'")])
    val = _int_arg(rec, -1)
    if val is None:
        return RuleOutcome(WARN, "Valore di 'ip ssh authentication-retries' "
                                 "non interpretabile.", [_ev(rec)])
    if val > _MAX_SSH_RETRIES:
        return RuleOutcome(
            FAIL, "Troppi tentativi di autenticazione per sessione SSH (%d, "
                  "massimo consigliato %d)." % (val, _MAX_SSH_RETRIES),
            [_ev(rec)])
    return RuleOutcome(
        PASS, "Tentativi di autenticazione SSH limitati a %d." % val)


def check_ios_domain_name(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.1.1.2 — 'ip domain-name' impostato (prerequisito di SSH)."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "ip domain-name", "ip domain name")
    if rec is None:
        return RuleOutcome(
            FAIL, "'ip domain-name' assente: senza dominio non e' possibile "
                  "generare la coppia di chiavi RSA per SSH.",
            [_absent("nessun 'ip domain-name'")])
    return RuleOutcome(PASS, "Dominio configurato: %s." % rec.words[-1])


def _check_service_off(cfg: IosConfig, service: str, why: str) -> RuleOutcome:
    """Servizio che deve risultare disattivato ('no <service>')."""
    g = _guard(cfg)
    if g:
        return g
    if has_top(cfg, "no %s" % service):
        return RuleOutcome(PASS, "'%s' disabilitato." % service)
    enabled = find_top(cfg, service)
    if enabled:
        return RuleOutcome(FAIL, why, [_ev(enabled[0])])
    # IOS non stampa i default: l'assenza della riga 'no ...' significa che il
    # servizio e' attivo col default di fabbrica, ma la configurazione non lo
    # afferma. WARN, non FAIL: il verdetto certo richiede 'show running-config
    # all', che qui non c'e'.
    return RuleOutcome(
        WARN,
        "Nessun 'no %s' in configurazione: il servizio resta al default di "
        "fabbrica (attivo) e non e' disattivato esplicitamente." % service,
        [_absent("nessun 'no %s'" % service)])


def check_ios_cdp(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.2 — 'no cdp run'."""
    return _check_service_off(
        cfg, "cdp run",
        "CDP attivo: annuncia modello, versione IOS e identita' dell'apparato "
        "a chiunque sia sul segmento.")


def check_ios_service_dhcp(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.4 — 'no service dhcp'."""
    return _check_service_off(
        cfg, "service dhcp",
        "Servizio DHCP attivo sull'apparato di rete: superficie di attacco "
        "inutile se l'indirizzamento e' erogato altrove.")


def check_ios_service_pad(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.7 — 'no service pad'."""
    return _check_service_off(
        cfg, "service pad",
        "Servizio PAD (X.25) attivo: espone il set di comandi PAD.")


def check_ios_tcp_keepalives(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.1.5 / 2.1.6 — 'service tcp-keepalives-in' e '-out'."""
    g = _guard(cfg)
    if g:
        return g
    missing = [d for d in ("in", "out")
               if not has_top(cfg, "service tcp-keepalives-%s" % d)]
    if missing:
        return RuleOutcome(
            FAIL,
            "Keepalive TCP mancanti (%s): le sessioni interrotte restano "
            "aperte e sono dirottabili."
            % ", ".join("tcp-keepalives-%s" % d for d in missing),
            [_absent("nessun 'service tcp-keepalives-%s'" % d)
             for d in missing])
    return RuleOutcome(
        PASS, "Keepalive TCP attivi in ingresso e in uscita.")


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
        return RuleOutcome(
            PASS, "Inoltro dei log verso %d collector remoto/i."
                  % len(set(hosts + legacy)))
    return RuleOutcome(
        FAIL, "Nessun 'logging host': i log restano solo sull'apparato e si "
              "perdono al riavvio.",
        [_absent("nessun 'logging host'")])


def check_ios_logging_buffered(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.2 — 'logging buffered' con dimensione adeguata."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "logging buffered")
    if rec is None:
        return RuleOutcome(
            FAIL, "Nessun 'logging buffered': senza buffer locale non resta "
                  "traccia consultabile dall'apparato.",
            [_absent("nessun 'logging buffered'")])
    size = next((v for v in (_int_arg(rec, i)
                             for i in range(2, len(rec.words)))
                 if v is not None), None)
    if size is None:
        return RuleOutcome(
            WARN, "'logging buffered' senza dimensione esplicita: vale il "
                  "default di piattaforma.", [_ev(rec)])
    if size < _MIN_LOG_BUFFER:
        return RuleOutcome(
            WARN, "Buffer di log piccolo (%d byte, consigliato %d): gli eventi "
                  "piu' vecchi vengono sovrascritti in fretta."
                  % (size, _MIN_LOG_BUFFER), [_ev(rec)])
    return RuleOutcome(PASS, "Buffer di log di %d byte." % size)


def check_ios_logging_console(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.3 — 'logging console critical'."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "logging console")
    if rec is None:
        return RuleOutcome(
            WARN, "'logging console' non limitato: il default invia OGNI "
                  "messaggio alla console, che e' lenta e li perde in caso "
                  "di picco.",
            [_absent("nessun 'logging console critical'")])
    if rec.words[-1] in ("critical", "2", "emergencies", "0", "alerts", "1"):
        return RuleOutcome(
            PASS, "Log su console limitati a '%s'." % rec.words[-1])
    return RuleOutcome(
        WARN, "Livello di log su console troppo verboso ('%s'): in caso di "
              "picco la coda si riempie e i messaggi vengono scartati."
              % rec.words[-1], [_ev(rec)])


def check_ios_logging_trap(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.5 — 'logging trap informational' (o piu' dettagliato)."""
    g = _guard(cfg)
    if g:
        return g
    rec = first_top(cfg, "logging trap")
    if rec is None:
        return RuleOutcome(
            WARN, "'logging trap' non impostato: la severita' inviata al "
                  "syslog remoto resta quella di default.",
            [_absent("nessun 'logging trap informational'")])
    level = rec.words[-1]
    ok = {"informational", "6", "debugging", "7"}
    if level in ok:
        return RuleOutcome(
            PASS, "Severita' verso syslog remoto a '%s'." % level)
    return RuleOutcome(
        FAIL, "Severita' verso syslog remoto troppo restrittiva ('%s'): gli "
              "eventi informativi non vengono inoltrati." % level, [_ev(rec)])


def check_ios_service_timestamps(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.6 — 'service timestamps ... datetime' su log e debug."""
    g = _guard(cfg)
    if g:
        return g
    stamps = find_top(cfg, "service timestamps")
    if not stamps:
        return RuleOutcome(
            FAIL, "Nessun 'service timestamps': i messaggi non sono "
                  "correlabili con quelli degli altri apparati.",
            [_absent("nessun 'service timestamps'")])
    bad = [l for l in stamps if "datetime" not in l.words]
    if bad:
        return RuleOutcome(
            WARN, "Timestamp basati sull'uptime invece che sulla data: "
                  "inutilizzabili per correlare tra apparati.",
            [_ev(l) for l in bad])
    return RuleOutcome(PASS, "Timestamp con data e ora su log e debug.")


def check_ios_logging_source_interface(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.7 — 'logging source-interface' fissata."""
    g = _guard(cfg)
    if g:
        return g
    if has_top(cfg, "logging source-interface"):
        return RuleOutcome(
            PASS, "Interfaccia sorgente dei log fissata.")
    return RuleOutcome(
        WARN, "Nessuna 'logging source-interface': l'IP sorgente dei messaggi "
              "cambia con la rotta e complica filtri e correlazione.",
        [_absent("nessun 'logging source-interface'")])


def check_ios_login_logging(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.2.8 — 'login on-failure log' e 'login on-success log'."""
    g = _guard(cfg)
    if g:
        return g
    missing = [d for d in ("on-failure", "on-success")
               if not has_top(cfg, "login %s log" % d)]
    if missing:
        return RuleOutcome(
            FAIL,
            "Accessi non registrati (%s): impossibile ricostruire chi e' "
            "entrato e quando." % ", ".join("login %s log" % d for d in missing),
            [_absent("nessun 'login %s log'" % d) for d in missing])
    return RuleOutcome(
        PASS, "Accessi riusciti e falliti registrati entrambi.")


# --- 2.3 NTP ------------------------------------------------------------------

def check_ios_ntp_servers(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.3.2 — almeno un 'ntp server' configurato."""
    g = _guard(cfg)
    if g:
        return g
    servers = find_top(cfg, "ntp server")
    if not servers:
        return RuleOutcome(
            FAIL, "Nessun 'ntp server': senza orologio sincronizzato i log e "
                  "la validita' dei certificati non sono affidabili.",
            [_absent("nessun 'ntp server'")])
    if len(servers) < 2:
        return RuleOutcome(
            WARN, "Un solo server NTP configurato: nessuna ridondanza in caso "
                  "di guasto della sorgente oraria.",
            [_ev(servers[0])])
    return RuleOutcome(PASS, "%d server NTP configurati." % len(servers))


def check_ios_ntp_authentication(cfg: IosConfig) -> RuleOutcome:
    """CIS 2.3.1.1 / 2.3.1.3 — NTP autenticato con chiave fidata."""
    g = _guard(cfg)
    if g:
        return g
    if not find_top(cfg, "ntp server"):
        return RuleOutcome(
            UNKNOWN, "Nessun server NTP configurato: autenticazione NTP non "
                     "applicabile.")
    ev: List[Evidence] = []
    if not has_top(cfg, "ntp authenticate"):
        ev.append(_absent("nessun 'ntp authenticate'"))
    if not has_top(cfg, "ntp trusted-key"):
        ev.append(_absent("nessuna 'ntp trusted-key'"))
    if ev:
        return RuleOutcome(
            FAIL, "NTP non autenticato: l'apparato accetta l'ora da qualunque "
                  "sorgente che si dichiari server.", ev)
    return RuleOutcome(PASS, "NTP autenticato con chiave fidata.")


# --- 3.1 Piano dati -----------------------------------------------------------

def check_ios_source_route(cfg: IosConfig) -> RuleOutcome:
    """CIS 3.1.1 — 'no ip source-route'."""
    return _check_service_off(
        cfg, "ip source-route",
        "Source routing attivo: consente al mittente di imporre il percorso "
        "dei pacchetti, tecnica usata per aggirare i controlli di rotta.")


def check_ios_proxy_arp(cfg: IosConfig) -> RuleOutcome:
    """CIS 3.1.2 — 'no ip proxy-arp' sulle interfacce con indirizzamento IP."""
    g = _guard(cfg)
    if g:
        return g
    ifaces = [(h, k) for h, k in blocks_matching(cfg, "interface")
              if child(k, "ip address") is not None]
    if not ifaces:
        return RuleOutcome(
            UNKNOWN, "Nessuna interfaccia con indirizzo IP: proxy ARP non "
                     "valutabile.")
    ev = [_absent("nessun 'no ip proxy-arp' (default: attivo)", header)
          for header, kids in ifaces if child(kids, "no ip proxy-arp") is None]
    if ev:
        return RuleOutcome(
            WARN,
            "Proxy ARP non disabilitato su %d interfaccia/e: estende il "
            "dominio di broadcast oltre il segmento e indebolisce la "
            "segmentazione." % len(ev), ev)
    return RuleOutcome(
        PASS, "Proxy ARP disabilitato su tutte le interfacce indirizzate.")


def check_ios_tunnel_interfaces(cfg: IosConfig) -> RuleOutcome:
    """CIS 3.1.3 — nessuna interfaccia 'tunnel' non prevista."""
    g = _guard(cfg)
    if g:
        return g
    tunnels = [(h, k) for h, k in blocks_matching(cfg, "interface tunnel")]
    if not tunnels:
        return RuleOutcome(PASS, "Nessuna interfaccia tunnel configurata.")
    return RuleOutcome(
        WARN,
        "%d interfacce tunnel presenti: da confermare come previste, sono un "
        "canale di uscita che aggira i controlli perimetrali." % len(tunnels),
        [Evidence(0, header, "interface") for header, _ in tunnels])
