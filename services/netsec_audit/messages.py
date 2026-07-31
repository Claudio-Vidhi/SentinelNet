# -*- coding: utf-8 -*-
"""Catalogo dei messaggi di verdetto del motore di audit, italiano e inglese.

Le regole dichiarano una chiave e i parametri; qui c'e' la frase. Motivo in
``model.py``: un report di audit e' un documento che si consegna, e deve poter
uscire in una lingua diversa da quella con cui l'operatore sta lavorando.

Regole di scrittura di una voce:

- La frase dice COSA E' STATO TROVATO e PERCHE' conta, in una riga. Il "perche'
  dovrebbe essere impostato cosi'" per esteso sta in ``guidance.py``: qui
  sarebbe illeggibile in una cella di tabella.
- I segnaposto sono nominati (``{count}``, ``{max}``) e devono comparire in
  entrambe le lingue: il test di parita' lo verifica.
- I comandi CLI non si traducono e non entrano nel catalogo: viaggiano come
  parametro ``what``, perche' devono restare confrontabili con la
  configurazione analizzata.
"""

from typing import Any, Dict

LANGS = ("it", "en")
DEFAULT_LANG = "it"

MESSAGES: Dict[str, Dict[str, str]] = {

    # --- evidenze: assenze -----------------------------------------------
    "ev.no_directive": {
        "it": "nessun «{what}» in configurazione",
        "en": "no «{what}» in the configuration",
    },
    "ev.no_block": {
        "it": "blocco «{what}» assente",
        "en": "«{what}» block absent",
    },
    "ev.block_empty": {
        "it": "blocco presente ma privo di voci",
        "en": "block present but with no entries",
    },
    "ev.not_set_default": {
        "it": "«{what}» non impostato: vale il default di piattaforma",
        "en": "«{what}» not set: the platform default applies",
    },
    "ev.not_set_default_value": {
        "it": "«{what}» non impostato: vale il default {value}",
        "en": "«{what}» not set: the default {value} applies",
    },
    "ev.not_set_default_on": {
        "it": "nessun «{what}»: la funzione resta attiva per default",
        "en": "no «{what}»: the feature stays on by default",
    },
    "ev.no_trusthost": {
        "it": "nessun «trusthost» definito per l'account",
        "en": "no «trusthost» defined for this account",
    },
    "ev.default_admin_account": {
        "it": "account amministrativo di default «admin» presente",
        "en": "default «admin» administrative account present",
    },
    "ev.snmp_v1v2c_active": {
        "it": "community SNMP v1/v2c attiva",
        "en": "SNMP v1/v2c community active",
    },
    "ev.ntp_custom_without_server": {
        "it": "«type custom» senza alcun server in «config ntpserver»",
        "en": "«type custom» with no server under «config ntpserver»",
    },
    "ev.no_transport_input": {
        "it": "nessun «transport input»: il default ammette ogni protocollo, "
              "telnet compreso",
        "en": "no «transport input»: the default allows every protocol, "
              "telnet included",
    },

    # --- FortiOS: hardening ----------------------------------------------
    "fos.mgmt_proto.no_section": {
        "it": "Sezione «config system interface» assente: impossibile "
              "valutare i protocolli di gestione.",
        "en": "«config system interface» section absent: management protocols "
              "cannot be assessed.",
    },
    "fos.mgmt_proto.insecure": {
        "it": "Protocolli di amministrazione non cifrati (Telnet/HTTP) "
              "abilitati su {count} interfaccia/e.",
        "en": "Unencrypted management protocols (Telnet/HTTP) enabled on "
              "{count} interface(s).",
    },
    "fos.mgmt_proto.ok": {
        "it": "Tutte le interfacce usano solo protocolli di gestione cifrati.",
        "en": "Every interface allows encrypted management protocols only.",
    },
    "fos.tls.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "la versione minima TLS.",
        "en": "«config system global» section absent: the minimum TLS version "
              "cannot be assessed.",
    },
    "fos.tls.not_set": {
        "it": "Versione minima TLS non impostata esplicitamente: si applica "
              "il default della piattaforma, che varia con la versione di "
              "FortiOS.",
        "en": "Minimum TLS version not set explicitly: the platform default "
              "applies, and it changes between FortiOS releases.",
    },
    "fos.tls.weak": {
        "it": "Versione TLS deprecata ammessa: {versions}.",
        "en": "Deprecated TLS version allowed: {versions}.",
    },
    "fos.tls.ok": {
        "it": "Versione minima SSL/TLS conforme (TLS 1.2+).",
        "en": "Minimum SSL/TLS version compliant (TLS 1.2+).",
    },
    "fos.idle.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "il timeout amministrativo.",
        "en": "«config system global» section absent: the administrative "
              "timeout cannot be assessed.",
    },
    "fos.idle.not_set": {
        "it": "«admintimeout» non configurato: si applica il default della "
              "piattaforma.",
        "en": "«admintimeout» not configured: the platform default applies.",
    },
    "fos.idle.unreadable": {
        "it": "Valore di «admintimeout» non interpretabile.",
        "en": "«admintimeout» value cannot be read as a number.",
    },
    "fos.idle.disabled": {
        "it": "Timeout amministrativo disabilitato (0): le sessioni non "
              "scadono mai.",
        "en": "Administrative timeout disabled (0): sessions never expire.",
    },
    "fos.idle.too_high": {
        "it": "Timeout amministrativo troppo alto ({value} minuti, massimo "
              "consigliato {max}).",
        "en": "Administrative timeout too high ({value} minutes, recommended "
              "maximum {max}).",
    },
    "fos.idle.ok": {
        "it": "Timeout di inattivita' amministrativa configurato a {value} "
              "minuti.",
        "en": "Administrative idle timeout set to {value} minutes.",
    },
    "fos.strong_crypto.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "«strong-crypto».",
        "en": "«config system global» section absent: «strong-crypto» cannot "
              "be assessed.",
    },
    "fos.strong_crypto.not_set": {
        "it": "«strong-crypto» non impostato: cifrari deboli potenzialmente "
              "ammessi.",
        "en": "«strong-crypto» not set: weak ciphers may be accepted.",
    },
    "fos.strong_crypto.bad": {
        "it": "«strong-crypto» disabilitato: cifrari deboli ammessi.",
        "en": "«strong-crypto» disabled: weak ciphers accepted.",
    },
    "fos.strong_crypto.ok": {
        "it": "«strong-crypto» abilitato.",
        "en": "«strong-crypto» enabled.",
    },

    # --- FortiOS: regole di accesso --------------------------------------
    "fos.policy.no_section": {
        "it": "Sezione «config firewall policy» assente: impossibile valutare "
              "le regole di accesso.",
        "en": "«config firewall policy» section absent: access rules cannot "
              "be assessed.",
    },
    "fos.policy.no_wan": {
        "it": "Nessuna interfaccia WAN identificabile: impossibile stabilire "
              "quali policy attraversano il perimetro.",
        "en": "No WAN interface identifiable: there is no way to tell which "
              "policies cross the perimeter.",
    },
    "fos.any_any.found": {
        "it": "Trovate {count} policy che accettano traffico any-to-any su "
              "qualunque servizio.",
        "en": "Found {count} policies accepting any-to-any traffic on any "
              "service.",
    },
    "fos.any_any.ok": {
        "it": "Nessuna policy any-to-any: sorgente, destinazione e servizio "
              "sono sempre specificati.",
        "en": "No any-to-any policy: source, destination and service are "
              "always specified.",
    },
    "fos.boundary.found": {
        "it": "Trovate {count} policy in ingresso da WAN verso qualunque "
              "destinazione interna.",
        "en": "Found {count} inbound policies from WAN towards any internal "
              "destination.",
    },
    "fos.boundary.ok": {
        "it": "Nessuna policy in ingresso da WAN verso destinazioni generiche.",
        "en": "No inbound policy from WAN towards a catch-all destination.",
    },
    "fos.admin_ports.exposed": {
        "it": "Porte amministrative (SSH 22 / RDP 3389) raggiungibili da "
              "Internet in {count} policy.",
        "en": "Administrative ports (SSH 22 / RDP 3389) reachable from the "
              "Internet in {count} policies.",
    },
    "fos.admin_ports.ok": {
        "it": "Nessuna esposizione diretta di SSH/RDP verso reti pubbliche.",
        "en": "No direct exposure of SSH/RDP towards public networks.",
    },

    # --- FortiOS: identita' e logging ------------------------------------
    "fos.trusthost.no_section": {
        "it": "Sezione «config system admin» assente: impossibile valutare le "
              "restrizioni di accesso amministrativo.",
        "en": "«config system admin» section absent: administrative access "
              "restrictions cannot be assessed.",
    },
    "fos.trusthost.unrestricted": {
        "it": "{count} account amministrativi accessibili da qualunque IP "
              "sorgente.",
        "en": "{count} administrative accounts reachable from any source IP.",
    },
    "fos.trusthost.ok": {
        "it": "Tutti gli account amministrativi sono ristretti a sottoreti di "
              "gestione fidate.",
        "en": "Every administrative account is restricted to trusted "
              "management subnets.",
    },
    "fos.snmp_default.no_section": {
        "it": "Sezione «config system snmp community» assente: impossibile "
              "valutare le community SNMP.",
        "en": "«config system snmp community» section absent: SNMP "
              "communities cannot be assessed.",
    },
    "fos.snmp_default.found": {
        "it": "Community SNMP di default in chiaro («public»/«private»): "
              "{count}.",
        "en": "Default cleartext SNMP communities («public»/«private»): "
              "{count}.",
    },
    "fos.snmp_default.ok": {
        "it": "Nessuna community SNMP di default configurata.",
        "en": "No default SNMP community configured.",
    },
    "fos.syslog.no_section": {
        "it": "Nessun inoltro syslog remoto configurato: la sezione «config "
              "log syslogd setting» non esiste.",
        "en": "No remote syslog forwarding configured: the «config log "
              "syslogd setting» section does not exist.",
    },
    "fos.syslog.incomplete": {
        "it": "Inoltro syslog remoto non attivo o privo di destinazione.",
        "en": "Remote syslog forwarding not enabled, or with no destination.",
    },
    "fos.syslog.ok": {
        "it": "Inoltro dei log verso syslog remoto attivo e configurato.",
        "en": "Log forwarding to a remote syslog collector enabled and "
              "configured.",
    },
    "fos.defaults.no_section": {
        "it": "Ne' «config system admin» ne' «config system password-policy» "
              "presenti: impossibile valutare i default di fabbrica.",
        "en": "Neither «config system admin» nor «config system "
              "password-policy» present: factory defaults cannot be assessed.",
    },
    "fos.defaults.found": {
        "it": "Rilevati default di fabbrica o policy password non applicata "
              "({count} riscontri).",
        "en": "Factory defaults or an unenforced password policy detected "
              "({count} findings).",
    },
    "fos.defaults.ok": {
        "it": "Nessun account di default e policy password attiva.",
        "en": "No default account, and the password policy is enforced.",
    },

    # --- FortiOS: rete ----------------------------------------------------
    "fos.dns.no_section": {
        "it": "Nessun server DNS configurato: la sezione «config system dns» "
              "non esiste.",
        "en": "No DNS server configured: the «config system dns» section does "
              "not exist.",
    },
    "fos.dns.no_server": {
        "it": "Blocco DNS presente ma nessun server risolutore definito.",
        "en": "DNS block present but no resolver defined.",
    },
    "fos.dns.single": {
        "it": "Un solo server DNS configurato: la risoluzione si ferma se "
              "quel server non risponde.",
        "en": "Only one DNS server configured: resolution stops if that "
              "server goes silent.",
    },
    "fos.dns.ok": {
        "it": "Due server DNS configurati.",
        "en": "Two DNS servers configured.",
    },
    "fos.intrazone.no_zones": {
        "it": "Nessuna zona definita: il traffico intra-zona non e' "
              "applicabile.",
        "en": "No zone defined: intra-zone traffic does not apply.",
    },
    "fos.intrazone.allowed": {
        "it": "{count} zone consentono il traffico fra le proprie interfacce "
              "senza passare da una policy.",
        "en": "{count} zones allow traffic between their own interfaces "
              "without going through a policy.",
    },
    "fos.intrazone.ok": {
        "it": "Tutte le zone negano il traffico intra-zona.",
        "en": "Every zone denies intra-zone traffic.",
    },

    # --- FortiOS: impostazioni di sistema --------------------------------
    "fos.banners.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare i "
              "banner di accesso.",
        "en": "«config system global» section absent: login banners cannot be "
              "assessed.",
    },
    "fos.banners.missing": {
        "it": "Banner di accesso mancanti ({count} su 2): nessuna avvertenza "
              "legale prima o dopo l'autenticazione.",
        "en": "Login banners missing ({count} of 2): no legal notice before "
              "or after authentication.",
    },
    "fos.banners.ok": {
        "it": "Banner pre-login e post-login entrambi attivi.",
        "en": "Pre-login and post-login banners both enabled.",
    },
    "fos.timezone.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "il fuso orario.",
        "en": "«config system global» section absent: the time zone cannot be "
              "assessed.",
    },
    "fos.timezone.not_set": {
        "it": "Fuso orario non impostato: i timestamp dei log usano il "
              "default di fabbrica e non corrispondono all'ora locale.",
        "en": "Time zone not set: log timestamps use the factory default and "
              "do not match local time.",
    },
    "fos.timezone.ok": {
        "it": "Fuso orario impostato esplicitamente.",
        "en": "Time zone set explicitly.",
    },
    "fos.ntp.no_section": {
        "it": "Nessuna sincronizzazione oraria configurata: la sezione "
              "«config system ntp» non esiste.",
        "en": "No time synchronisation configured: the «config system ntp» "
              "section does not exist.",
    },
    "fos.ntp.not_syncing": {
        "it": "Sincronizzazione oraria non attiva o priva di sorgente: i log "
              "non sono correlabili fra apparati.",
        "en": "Time synchronisation not enabled, or with no source: logs "
              "cannot be correlated across devices.",
    },
    "fos.ntp.ok": {
        "it": "Sincronizzazione NTP attiva ({count} server dichiarati).",
        "en": "NTP synchronisation enabled ({count} servers declared).",
    },
    "fos.hostname.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "l'hostname.",
        "en": "«config system global» section absent: the hostname cannot be "
              "assessed.",
    },
    "fos.hostname.not_set": {
        "it": "Hostname non impostato: l'apparato resta col nome di fabbrica "
              "e i log non lo distinguono dagli altri.",
        "en": "Hostname not set: the device keeps its factory name and logs "
              "do not tell it apart from the others.",
    },
    "fos.hostname.factory": {
        "it": "Hostname ancora quello di fabbrica.",
        "en": "Hostname still the factory one.",
    },
    "fos.hostname.ok": {
        "it": "Hostname personalizzato.",
        "en": "Hostname customised.",
    },
    "fos.auto_install.no_section": {
        "it": "Sezione «config system auto-install» assente: vale il default "
              "della piattaforma.",
        "en": "«config system auto-install» section absent: the platform "
              "default applies.",
    },
    "fos.auto_install.enabled": {
        "it": "Installazione automatica da chiavetta USB attiva: chi ha "
              "accesso fisico puo' sostituire configurazione o firmware al "
              "riavvio.",
        "en": "Automatic install from USB enabled: anyone with physical "
              "access can replace the configuration or the firmware at boot.",
    },
    "fos.auto_install.ok": {
        "it": "Installazione automatica da USB disabilitata.",
        "en": "Automatic install from USB disabled.",
    },
    "fos.static_ciphers.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare i "
              "cifrari a chiave statica.",
        "en": "«config system global» section absent: static-key ciphers "
              "cannot be assessed.",
    },
    "fos.static_ciphers.not_set": {
        "it": "«ssl-static-key-ciphers» non impostato: vale il default della "
              "piattaforma.",
        "en": "«ssl-static-key-ciphers» not set: the platform default applies.",
    },
    "fos.static_ciphers.bad": {
        "it": "Cifrari a chiave statica ammessi: senza forward secrecy, chi "
              "compromette la chiave del server puo' decifrare il traffico "
              "registrato in passato.",
        "en": "Static-key ciphers accepted: without forward secrecy, anyone "
              "who obtains the server key can decrypt traffic captured in the "
              "past.",
    },
    "fos.static_ciphers.ok": {
        "it": "Cifrari a chiave statica disabilitati.",
        "en": "Static-key ciphers disabled.",
    },
    "fos.https_redirect.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "il redirect HTTPS.",
        "en": "«config system global» section absent: the HTTPS redirect "
              "cannot be assessed.",
    },
    "fos.https_redirect.not_set": {
        "it": "«admin-https-redirect» non impostato: vale il default della "
              "piattaforma.",
        "en": "«admin-https-redirect» not set: the platform default applies.",
    },
    "fos.https_redirect.bad": {
        "it": "Redirect HTTPS disabilitato: la GUI resta raggiungibile in "
              "chiaro sugli indirizzi dove HTTP e' ammesso.",
        "en": "HTTPS redirect disabled: the GUI stays reachable in cleartext "
              "wherever HTTP is allowed.",
    },
    "fos.https_redirect.ok": {
        "it": "Redirect da HTTP a HTTPS attivo sulla GUI.",
        "en": "HTTP-to-HTTPS redirect enabled on the GUI.",
    },
    "fos.cpu_log.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "l'allarme di saturazione CPU.",
        "en": "«config system global» section absent: the CPU saturation "
              "alarm cannot be assessed.",
    },
    "fos.cpu_log.not_set": {
        "it": "«log-single-cpu-high» non impostato: vale il default della "
              "piattaforma.",
        "en": "«log-single-cpu-high» not set: the platform default applies.",
    },
    "fos.cpu_log.bad": {
        "it": "Saturazione di un singolo core non registrata: un processo che "
              "satura una CPU passa inosservato finche' il carico medio resta "
              "basso.",
        "en": "Single-core saturation not logged: a process pinning one CPU "
              "goes unnoticed while the average load stays low.",
    },
    "fos.cpu_log.ok": {
        "it": "Allarme di saturazione di una singola CPU attivo.",
        "en": "Single-CPU saturation alarm enabled.",
    },
    "fos.gui_hostname.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "la visualizzazione dell'hostname.",
        "en": "«config system global» section absent: hostname display cannot "
              "be assessed.",
    },
    "fos.gui_hostname.not_set": {
        "it": "«gui-display-hostname» non impostato: vale il default della "
              "piattaforma.",
        "en": "«gui-display-hostname» not set: the platform default applies.",
    },
    "fos.gui_hostname.bad": {
        "it": "Hostname mostrato nella pagina di login: chiunque raggiunga la "
              "GUI legge il nome dell'apparato prima di autenticarsi.",
        "en": "Hostname shown on the login page: anyone who reaches the GUI "
              "reads the device name before authenticating.",
    },
    "fos.gui_hostname.ok": {
        "it": "Hostname non mostrato nella pagina di login.",
        "en": "Hostname not shown on the login page.",
    },

    # --- FortiOS: password e blocco account ------------------------------
    "fos.pwpolicy.no_section": {
        "it": "Nessuna policy password definita: la sezione «config system "
              "password-policy» non esiste.",
        "en": "No password policy defined: the «config system "
              "password-policy» section does not exist.",
    },
    "fos.pwpolicy.weak": {
        "it": "Policy password sotto i requisiti minimi ({count} parametri "
              "non conformi): lunghezza minima {minlen} caratteri e almeno un "
              "carattere per ciascuna delle quattro classi.",
        "en": "Password policy below the minimum requirements ({count} "
              "parameters non-compliant): at least {minlen} characters and at "
              "least one character from each of the four classes.",
    },
    "fos.pwpolicy.ok": {
        "it": "Policy password conforme: almeno {minlen} caratteri con tutte "
              "e quattro le classi richieste.",
        "en": "Password policy compliant: at least {minlen} characters with "
              "all four required classes.",
    },
    "fos.lockout.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "il blocco degli account.",
        "en": "«config system global» section absent: account lockout cannot "
              "be assessed.",
    },
    "fos.lockout.weak": {
        "it": "Blocco degli account amministrativi troppo permissivo: servono "
              "al massimo {threshold} tentativi e almeno {duration} secondi "
              "di blocco, altrimenti un attacco a forza bruta resta "
              "praticabile.",
        "en": "Administrative account lockout too permissive: it needs at "
              "most {threshold} attempts and at least {duration} seconds of "
              "lockout, otherwise brute forcing stays practical.",
    },
    "fos.lockout.ok": {
        "it": "Blocco account dopo {threshold} tentativi per almeno "
              "{duration} secondi.",
        "en": "Account locked after {threshold} attempts for at least "
              "{duration} seconds.",
    },

    # --- FortiOS: SNMP ----------------------------------------------------
    "fos.snmpv3.no_snmp": {
        "it": "Nessuna configurazione SNMP presente: nulla da valutare.",
        "en": "No SNMP configuration present: nothing to assess.",
    },
    "fos.snmpv3.v1v2c": {
        "it": "{count} community SNMP v1/v2c attive: la community viaggia in "
              "chiaro e vale come credenziale.",
        "en": "{count} SNMP v1/v2c communities active: the community travels "
              "in cleartext and counts as a credential.",
    },
    "fos.snmpv3.no_user": {
        "it": "Nessuna community v1/v2c attiva ma nemmeno un utente SNMPv3: "
              "il monitoraggio SNMP non e' configurato.",
        "en": "No active v1/v2c community, but no SNMPv3 user either: SNMP "
              "monitoring is not configured.",
    },
    "fos.snmpv3.ok": {
        "it": "Solo SNMPv3 in uso.",
        "en": "SNMPv3 only.",
    },

    # --- FortiOS: amministrazione ----------------------------------------
    "fos.admin_port.no_section": {
        "it": "Sezione «config system global» assente: impossibile valutare "
              "le porte amministrative.",
        "en": "«config system global» section absent: administrative ports "
              "cannot be assessed.",
    },
    "fos.admin_port.default": {
        "it": "Porte amministrative sui valori di default ({count} su 2): non "
              "e' una vulnerabilita' di per se', ma le scansioni di massa le "
              "trovano per prime.",
        "en": "Administrative ports left on their defaults ({count} of 2): "
              "not a vulnerability in itself, but mass scans find these "
              "first.",
    },
    "fos.admin_port.ok": {
        "it": "Porte amministrative spostate dai default.",
        "en": "Administrative ports moved off the defaults.",
    },
    "fos.local_in.no_section": {
        "it": "Nessuna policy «local-in»: il traffico diretto all'apparato e' "
              "filtrato solo da «allowaccess», che non distingue le sorgenti.",
        "en": "No «local-in» policy: traffic aimed at the device itself is "
              "filtered only by «allowaccess», which does not discriminate by "
              "source.",
    },
    "fos.local_in.empty": {
        "it": "Blocco «local-in-policy» presente ma vuoto.",
        "en": "«local-in-policy» block present but empty.",
    },
    "fos.local_in.ok": {
        "it": "{count} policy «local-in» a protezione dei servizi "
              "dell'apparato.",
        "en": "{count} «local-in» policies protecting the device's own "
              "services.",
    },

    # --- FortiOS: alta disponibilita' ------------------------------------
    "fos.ha.no_section": {
        "it": "Sezione «config system ha» assente: apparato non in "
              "configurazione di alta disponibilita'.",
        "en": "«config system ha» section absent: the device is not in a "
              "high-availability configuration.",
    },
    "fos.ha.standalone": {
        "it": "HA in modalita' standalone: nessun cluster da valutare.",
        "en": "HA in standalone mode: no cluster to assess.",
    },
    "fos.ha.no_monitor": {
        "it": "Cluster HA senza interfacce monitorate: il failover non scatta "
              "se cade un collegamento dati, solo se cade il nodo.",
        "en": "HA cluster with no monitored interfaces: failover does not "
              "trigger when a data link drops, only when the node itself "
              "goes down.",
    },
    "fos.ha.ok": {
        "it": "Cluster HA in modalita' «{mode}» con {count} interfacce "
              "monitorate.",
        "en": "HA cluster in «{mode}» mode with {count} monitored interfaces.",
    },

    # --- FortiOS: igiene delle policy ------------------------------------
    "fos.policy_log.missing": {
        "it": "{count} policy accettano traffico senza registrarlo: quel "
              "traffico non compare in nessuna indagine successiva.",
        "en": "{count} policies accept traffic without logging it: that "
              "traffic appears in no later investigation.",
    },
    "fos.policy_log.ok": {
        "it": "Tutte le policy che accettano traffico lo registrano.",
        "en": "Every policy that accepts traffic also logs it.",
    },
    "fos.profiles.missing": {
        "it": "{count} policy instradano traffico verso Internet senza alcun "
              "profilo di ispezione: l'apparato le tratta come semplice "
              "routing.",
        "en": "{count} policies route traffic to the Internet with no "
              "inspection profile: the device treats them as plain routing.",
    },
    "fos.profiles.ok": {
        "it": "Ogni policy verso Internet applica almeno un profilo di "
              "ispezione.",
        "en": "Every Internet-bound policy applies at least one inspection "
              "profile.",
    },
    "fos.comments.missing": {
        "it": "{count} policy prive di commento: senza una motivazione "
              "registrata nessuno se la sente di rimuoverle, e restano per "
              "sempre.",
        "en": "{count} policies with no comment: with no recorded reason "
              "nobody dares remove them, so they stay forever.",
    },
    "fos.comments.ok": {
        "it": "Tutte le policy sono documentate.",
        "en": "Every policy is documented.",
    },

    # --- FortiOS: VPN -----------------------------------------------------
    "fos.sslvpn.no_section": {
        "it": "Sezione «config vpn ssl settings» assente: SSL-VPN non "
              "configurata.",
        "en": "«config vpn ssl settings» section absent: SSL-VPN not "
              "configured.",
    },
    "fos.sslvpn_tls.not_set": {
        "it": "Versione TLS minima della SSL-VPN non impostata: vale il "
              "default della piattaforma.",
        "en": "Minimum TLS version for the SSL-VPN not set: the platform "
              "default applies.",
    },
    "fos.sslvpn_tls.weak": {
        "it": "SSL-VPN accetta TLS deprecato («{version}»).",
        "en": "The SSL-VPN accepts deprecated TLS («{version}»).",
    },
    "fos.sslvpn_tls.ok": {
        "it": "SSL-VPN limitata a TLS 1.2 o superiore.",
        "en": "SSL-VPN restricted to TLS 1.2 or above.",
    },
    "fos.sslvpn_src.unrestricted": {
        "it": "Portale SSL-VPN raggiungibile da qualunque indirizzo: senza "
              "«source-address» l'unica barriera sono le credenziali.",
        "en": "SSL-VPN portal reachable from any address: without "
              "«source-address» the only barrier is the credentials.",
    },
    "fos.sslvpn_src.any": {
        "it": "Portale SSL-VPN esposto a «all»: restrizione sorgente presente "
              "ma inefficace.",
        "en": "SSL-VPN portal exposed to «all»: the source restriction exists "
              "but does nothing.",
    },
    "fos.sslvpn_src.ok": {
        "it": "Accesso al portale SSL-VPN ristretto per indirizzo sorgente.",
        "en": "SSL-VPN portal access restricted by source address.",
    },

    # --- FortiOS: logging -------------------------------------------------
    "fos.syslog_enc.no_syslog": {
        "it": "Nessun syslog remoto configurato: la cifratura del trasporto "
              "non e' applicabile.",
        "en": "No remote syslog configured: transport encryption does not "
              "apply.",
    },
    "fos.syslog_enc.disabled": {
        "it": "Inoltro syslog non attivo: la cifratura del trasporto non e' "
              "applicabile.",
        "en": "Syslog forwarding not enabled: transport encryption does not "
              "apply.",
    },
    "fos.syslog_enc.plaintext": {
        "it": "Log inviati al syslog remoto in chiaro: chi intercetta il "
              "segmento legge indirizzi, utenti e destinazioni di ogni "
              "sessione.",
        "en": "Logs sent to the remote syslog in cleartext: anyone tapping "
              "the segment reads the addresses, users and destinations of "
              "every session.",
    },
    "fos.syslog_enc.ok": {
        "it": "Inoltro syslog cifrato («enc-algorithm {algorithm}»).",
        "en": "Syslog forwarding encrypted («enc-algorithm {algorithm}»).",
    },
    "fos.event_log.no_section": {
        "it": "Sezione «config log eventfilter» assente: impossibile valutare "
              "la registrazione degli eventi.",
        "en": "«config log eventfilter» section absent: event logging cannot "
              "be assessed.",
    },
    "fos.event_log.not_set": {
        "it": "«event» non impostato: vale il default della piattaforma.",
        "en": "«event» not set: the platform default applies.",
    },
    "fos.event_log.bad": {
        "it": "Registrazione degli eventi di sistema disabilitata: login, "
              "modifiche di configurazione e failover HA non lasciano traccia.",
        "en": "System event logging disabled: logins, configuration changes "
              "and HA failovers leave no trace.",
    },
    "fos.event_log.ok": {
        "it": "Registrazione degli eventi di sistema attiva.",
        "en": "System event logging enabled.",
    },
    "fos.log_disk.no_section": {
        "it": "Sezione «config log disk setting» assente: l'apparato potrebbe "
              "non avere un disco locale.",
        "en": "«config log disk setting» section absent: the device may have "
              "no local disk.",
    },
    "fos.log_disk.disabled": {
        "it": "Registrazione su disco locale disattivata: se il collector "
              "remoto e' irraggiungibile non resta alcuna traccia.",
        "en": "Local disk logging disabled: if the remote collector is "
              "unreachable, nothing is retained.",
    },
    "fos.log_disk.ok": {
        "it": "Registrazione locale su disco attiva.",
        "en": "Local disk logging enabled.",
    },

    # --- Cisco IOS: base --------------------------------------------------
    "ios.empty": {
        "it": "Configurazione vuota o non riconosciuta come Cisco IOS.",
        "en": "Configuration empty, or not recognised as Cisco IOS.",
    },
    "ios.aaa.disabled": {
        "it": "«aaa new-model» esplicitamente disabilitato: nessun controllo "
              "accessi centralizzato.",
        "en": "«aaa new-model» explicitly disabled: no centralised access "
              "control.",
    },
    "ios.aaa.absent": {
        "it": "«aaa new-model» assente: l'apparato usa l'autenticazione "
              "legacy di linea.",
        "en": "«aaa new-model» absent: the device falls back to legacy "
              "line authentication.",
    },
    "ios.aaa.ok": {
        "it": "«aaa new-model» abilitato.",
        "en": "«aaa new-model» enabled.",
    },
    "ios.aaa.not_applicable_login": {
        "it": "«aaa new-model» non attivo: i metodi AAA di login non sono "
              "applicabili.",
        "en": "«aaa new-model» not enabled: AAA login methods do not apply.",
    },
    "ios.aaa.not_applicable_accounting": {
        "it": "«aaa new-model» non attivo: l'accounting AAA non e' "
              "applicabile.",
        "en": "«aaa new-model» not enabled: AAA accounting does not apply.",
    },
    "ios.aaa_login.absent": {
        "it": "Nessun «aaa authentication login» definito.",
        "en": "No «aaa authentication login» defined.",
    },
    "ios.aaa_login.none": {
        "it": "Metodo di login con fallback «none»: accesso senza credenziali.",
        "en": "Login method with a «none» fallback: access with no "
              "credentials.",
    },
    "ios.aaa_login.ok": {
        "it": "Autenticazione di login AAA definita ({count} liste).",
        "en": "AAA login authentication defined ({count} lists).",
    },
    "ios.accounting.absent": {
        "it": "Nessun «aaa accounting commands 15»: i comandi privilegiati "
              "non lasciano traccia di chi li ha eseguiti.",
        "en": "No «aaa accounting commands 15»: privileged commands leave no "
              "record of who ran them.",
    },
    "ios.accounting.ok": {
        "it": "Accounting dei comandi privilegiati (livello 15) attivo.",
        "en": "Accounting of privileged (level 15) commands enabled.",
    },

    # --- Cisco IOS: accesso ----------------------------------------------
    "ios.vty.absent": {
        "it": "Nessuna «line vty» configurata: accesso remoto non valutabile.",
        "en": "No «line vty» configured: remote access cannot be assessed.",
    },
    "ios.vty_transport.insecure": {
        "it": "Protocolli non cifrati ammessi su {count} linea/e vty.",
        "en": "Unencrypted protocols allowed on {count} vty line(s).",
    },
    "ios.vty_transport.ok": {
        "it": "Tutte le «line vty» accettano solo SSH.",
        "en": "Every «line vty» accepts SSH only.",
    },
    "ios.vty_acl.missing": {
        "it": "{count} linea/e vty raggiungibili da qualunque indirizzo "
              "sorgente.",
        "en": "{count} vty line(s) reachable from any source address.",
    },
    "ios.vty_acl.ok": {
        "it": "Ogni «line vty» e' ristretta da una access-class.",
        "en": "Every «line vty» is restricted by an access-class.",
    },
    "ios.vty_timeout.absent": {
        "it": "Nessuna «line vty» configurata.",
        "en": "No «line vty» configured.",
    },
    "ios.vty_timeout.bad": {
        "it": "Timeout di inattivita' assente, disabilitato o superiore a "
              "{max} minuti su {count} linee vty.",
        "en": "Idle timeout missing, disabled or above {max} minutes on "
              "{count} vty lines.",
    },
    "ios.vty_timeout.ok": {
        "it": "Timeout di inattivita' entro {max} minuti su tutte le linee "
              "vty.",
        "en": "Idle timeout within {max} minutes on every vty line.",
    },
    "ios.con_timeout.absent": {
        "it": "Nessuna «line con» configurata.",
        "en": "No «line con» configured.",
    },
    "ios.con_timeout.bad": {
        "it": "Timeout di inattivita' assente, disabilitato o superiore a "
              "{max} minuti su {count} linee console.",
        "en": "Idle timeout missing, disabled or above {max} minutes on "
              "{count} console lines.",
    },
    "ios.con_timeout.ok": {
        "it": "Timeout di inattivita' entro {max} minuti su tutte le linee "
              "console.",
        "en": "Idle timeout within {max} minutes on every console line.",
    },
    "ios.aux.absent": {
        "it": "Nessuna «line aux» presente: l'apparato non espone una porta "
              "ausiliaria.",
        "en": "No «line aux» present: the device exposes no auxiliary port.",
    },
    "ios.aux.exec_active": {
        "it": "Processo EXEC attivo sulla porta ausiliaria.",
        "en": "EXEC process active on the auxiliary port.",
    },
    "ios.aux.ok": {
        "it": "Processo EXEC disabilitato sulla porta ausiliaria.",
        "en": "EXEC process disabled on the auxiliary port.",
    },
    "ios.users.absent": {
        "it": "Nessun utente locale definito.",
        "en": "No local user defined.",
    },
    "ios.user_priv.high": {
        "it": "{count} utenti locali con «privilege 15»: ottengono EXEC "
              "privilegiato senza passare da «enable».",
        "en": "{count} local users with «privilege 15»: they get privileged "
              "EXEC without going through «enable».",
    },
    "ios.user_priv.ok": {
        "it": "Nessun utente locale con privilegio 15 diretto.",
        "en": "No local user with direct privilege 15.",
    },

    # --- Cisco IOS: banner e password ------------------------------------
    "ios.banner.absent": {
        "it": "Banner «{kind}» assente: nessuna avvertenza legale all'accesso.",
        "en": "«{kind}» banner absent: no legal notice on access.",
    },
    "ios.banner.ok": {
        "it": "Banner «{kind}» configurato.",
        "en": "«{kind}» banner configured.",
    },
    "ios.enable.password": {
        "it": "«enable password» in uso: cifratura reversibile di tipo 7.",
        "en": "«enable password» in use: reversible type-7 encoding.",
    },
    "ios.enable.absent": {
        "it": "Nessun «enable secret»: l'accesso privilegiato non e' protetto "
              "da password.",
        "en": "No «enable secret»: privileged access is not password "
              "protected.",
    },
    "ios.enable.ok": {
        "it": "«enable secret» configurato.",
        "en": "«enable secret» configured.",
    },
    "ios.pw_encryption.disabled": {
        "it": "«service password-encryption» esplicitamente disabilitato: "
              "password in chiaro nella configurazione.",
        "en": "«service password-encryption» explicitly disabled: cleartext "
              "passwords in the configuration.",
    },
    "ios.pw_encryption.absent": {
        "it": "«service password-encryption» assente: le password di linea "
              "restano in chiaro.",
        "en": "«service password-encryption» absent: line passwords stay in "
              "cleartext.",
    },
    "ios.pw_encryption.ok": {
        "it": "«service password-encryption» abilitato.",
        "en": "«service password-encryption» enabled.",
    },
    "ios.user_secret.password": {
        "it": "{count} utenti locali con «password» invece di «secret»: hash "
              "reversibile o debole.",
        "en": "{count} local users using «password» instead of «secret»: "
              "reversible or weak hash.",
    },
    "ios.user_secret.ok": {
        "it": "Tutti gli utenti locali usano «secret».",
        "en": "Every local user uses «secret».",
    },

    # --- Cisco IOS: SNMP --------------------------------------------------
    "ios.snmp.absent": {
        "it": "Nessuna community SNMP configurata: nulla da valutare.",
        "en": "No SNMP community configured: nothing to assess.",
    },
    "ios.snmp_default.found": {
        "it": "Community SNMP di default («public»/«private») in uso: {count}.",
        "en": "Default SNMP communities («public»/«private») in use: {count}.",
    },
    "ios.snmp_default.ok": {
        "it": "Nessuna community SNMP di default.",
        "en": "No default SNMP community.",
    },
    "ios.snmp_rw.found": {
        "it": "Community SNMP in scrittura: consentono di riconfigurare "
              "l'apparato via SNMP ({count}).",
        "en": "Read-write SNMP communities: they allow reconfiguring the "
              "device over SNMP ({count}).",
    },
    "ios.snmp_rw.ok": {
        "it": "Nessuna community SNMP in scrittura.",
        "en": "No read-write SNMP community.",
    },
    "ios.snmp_acl.missing": {
        "it": "{count} community SNMP interrogabili da qualunque host: manca "
              "la access-list.",
        "en": "{count} SNMP communities queryable from any host: the "
              "access-list is missing.",
    },
    "ios.snmp_acl.ok": {
        "it": "Ogni community SNMP e' ristretta da una access-list.",
        "en": "Every SNMP community is restricted by an access-list.",
    },
    "ios.snmpv3.absent": {
        "it": "Nessun gruppo o utente SNMPv3 configurato.",
        "en": "No SNMPv3 group or user configured.",
    },
    "ios.snmpv3.weak": {
        "it": "SNMPv3 senza cifratura o con cifratura sotto AES-{bits} "
              "({count} riscontri).",
        "en": "SNMPv3 without encryption, or below AES-{bits} ({count} "
              "findings).",
    },
    "ios.snmpv3.ok": {
        "it": "SNMPv3 configurato con autenticazione e cifratura AES-{bits} o "
              "superiore.",
        "en": "SNMPv3 configured with authentication and AES-{bits} "
              "encryption or better.",
    },

    # --- Cisco IOS: SSH e servizi ----------------------------------------
    "ios.ssh_version.not_set": {
        "it": "«ip ssh version» non impostato: SSH opera in modalita' "
              "compatibile e accetta anche la versione 1.",
        "en": "«ip ssh version» not set: SSH runs in compatibility mode and "
              "accepts version 1 as well.",
    },
    "ios.ssh_version.v1": {
        "it": "SSH versione 1 ammessa: protocollo con vulnerabilita' note.",
        "en": "SSH version 1 allowed: a protocol with known vulnerabilities.",
    },
    "ios.ssh_version.ok": {
        "it": "SSH forzato alla versione 2.",
        "en": "SSH forced to version 2.",
    },
    "ios.ssh_timeout.not_set": {
        "it": "«ip ssh time-out» non impostato: vale il default di "
              "piattaforma (120 s).",
        "en": "«ip ssh time-out» not set: the platform default applies "
              "(120 s).",
    },
    "ios.ssh_timeout.unreadable": {
        "it": "Valore di «ip ssh time-out» non interpretabile.",
        "en": "«ip ssh time-out» value cannot be read as a number.",
    },
    "ios.ssh_timeout.too_high": {
        "it": "Timeout di login SSH troppo alto ({value} s, massimo "
              "consigliato {max}).",
        "en": "SSH login timeout too high ({value} s, recommended maximum "
              "{max}).",
    },
    "ios.ssh_timeout.ok": {
        "it": "Timeout di login SSH a {value} secondi.",
        "en": "SSH login timeout at {value} seconds.",
    },
    "ios.ssh_retries.not_set": {
        "it": "«ip ssh authentication-retries» non impostato: vale il default "
              "di piattaforma (3).",
        "en": "«ip ssh authentication-retries» not set: the platform default "
              "applies (3).",
    },
    "ios.ssh_retries.unreadable": {
        "it": "Valore di «ip ssh authentication-retries» non interpretabile.",
        "en": "«ip ssh authentication-retries» value cannot be read as a "
              "number.",
    },
    "ios.ssh_retries.too_high": {
        "it": "Troppi tentativi di autenticazione per sessione SSH ({value}, "
              "massimo consigliato {max}).",
        "en": "Too many authentication attempts per SSH session ({value}, "
              "recommended maximum {max}).",
    },
    "ios.ssh_retries.ok": {
        "it": "Tentativi di autenticazione SSH limitati a {value}.",
        "en": "SSH authentication attempts limited to {value}.",
    },
    "ios.domain.absent": {
        "it": "«ip domain-name» assente: senza dominio non e' possibile "
              "generare la coppia di chiavi RSA per SSH.",
        "en": "«ip domain-name» absent: without a domain the RSA key pair for "
              "SSH cannot be generated.",
    },
    "ios.domain.ok": {
        "it": "Dominio configurato: {domain}.",
        "en": "Domain configured: {domain}.",
    },
    "ios.service.ok": {
        "it": "«{service}» disabilitato.",
        "en": "«{service}» disabled.",
    },
    "ios.service.not_disabled": {
        "it": "Nessun «no {service}» in configurazione: il servizio resta al "
              "default di fabbrica (attivo) e non e' disattivato "
              "esplicitamente.",
        "en": "No «no {service}» in the configuration: the service stays at "
              "its factory default (on) and is not explicitly disabled.",
    },
    "ios.cdp.enabled": {
        "it": "CDP attivo: annuncia modello, versione IOS e identita' "
              "dell'apparato a chiunque sia sul segmento.",
        "en": "CDP enabled: it announces the model, IOS version and identity "
              "of the device to anyone on the segment.",
    },
    "ios.dhcp.enabled": {
        "it": "Servizio DHCP attivo sull'apparato di rete: superficie di "
              "attacco inutile se l'indirizzamento e' erogato altrove.",
        "en": "DHCP service running on the network device: pointless attack "
              "surface when addressing is served elsewhere.",
    },
    "ios.pad.enabled": {
        "it": "Servizio PAD (X.25) attivo: espone il set di comandi PAD.",
        "en": "PAD (X.25) service running: it exposes the PAD command set.",
    },
    "ios.source_route.enabled": {
        "it": "Source routing attivo: consente al mittente di imporre il "
              "percorso dei pacchetti, tecnica usata per aggirare i controlli "
              "di rotta.",
        "en": "Source routing enabled: it lets the sender dictate the packet "
              "path, a technique used to bypass routing controls.",
    },
    "ios.keepalive.missing": {
        "it": "Keepalive TCP mancanti ({directives}): le sessioni interrotte "
              "restano aperte e sono dirottabili.",
        "en": "TCP keepalives missing ({directives}): dropped sessions stay "
              "open and can be hijacked.",
    },
    "ios.keepalive.ok": {
        "it": "Keepalive TCP attivi in ingresso e in uscita.",
        "en": "TCP keepalives enabled inbound and outbound.",
    },

    # --- Cisco IOS: logging -----------------------------------------------
    "ios.log_host.absent": {
        "it": "Nessun «logging host»: i log restano solo sull'apparato e si "
              "perdono al riavvio.",
        "en": "No «logging host»: logs stay on the device only and are lost "
              "at reboot.",
    },
    "ios.log_host.ok": {
        "it": "Inoltro dei log verso {count} collector remoto/i.",
        "en": "Log forwarding to {count} remote collector(s).",
    },
    "ios.log_buffer.absent": {
        "it": "Nessun «logging buffered»: senza buffer locale non resta "
              "traccia consultabile dall'apparato.",
        "en": "No «logging buffered»: with no local buffer the device keeps "
              "nothing you can read back.",
    },
    "ios.log_buffer.no_size": {
        "it": "«logging buffered» senza dimensione esplicita: vale il default "
              "di piattaforma.",
        "en": "«logging buffered» with no explicit size: the platform default "
              "applies.",
    },
    "ios.log_buffer.small": {
        "it": "Buffer di log piccolo ({size} byte, consigliato {min}): gli "
              "eventi piu' vecchi vengono sovrascritti in fretta.",
        "en": "Log buffer small ({size} bytes, recommended {min}): older "
              "events get overwritten quickly.",
    },
    "ios.log_buffer.ok": {
        "it": "Buffer di log di {size} byte.",
        "en": "Log buffer of {size} bytes.",
    },
    "ios.log_console.not_set": {
        "it": "«logging console» non limitato: il default invia OGNI "
              "messaggio alla console, che e' lenta e li perde in caso di "
              "picco.",
        "en": "«logging console» not limited: the default sends EVERY message "
              "to the console, which is slow and drops them under load.",
    },
    "ios.log_console.verbose": {
        "it": "Livello di log su console troppo verboso («{level}»): in caso "
              "di picco la coda si riempie e i messaggi vengono scartati.",
        "en": "Console log level too verbose («{level}»): under load the "
              "queue fills and messages are discarded.",
    },
    "ios.log_console.ok": {
        "it": "Log su console limitati a «{level}».",
        "en": "Console logging limited to «{level}».",
    },
    "ios.log_trap.not_set": {
        "it": "«logging trap» non impostato: la severita' inviata al syslog "
              "remoto resta quella di default.",
        "en": "«logging trap» not set: the severity sent to the remote syslog "
              "stays at its default.",
    },
    "ios.log_trap.too_strict": {
        "it": "Severita' verso syslog remoto troppo restrittiva («{level}»): "
              "gli eventi informativi non vengono inoltrati.",
        "en": "Severity towards the remote syslog too restrictive "
              "(«{level}»): informational events are not forwarded.",
    },
    "ios.log_trap.ok": {
        "it": "Severita' verso syslog remoto a «{level}».",
        "en": "Severity towards the remote syslog at «{level}».",
    },
    "ios.timestamps.absent": {
        "it": "Nessun «service timestamps»: i messaggi non sono correlabili "
              "con quelli degli altri apparati.",
        "en": "No «service timestamps»: messages cannot be correlated with "
              "those from other devices.",
    },
    "ios.timestamps.uptime": {
        "it": "Timestamp basati sull'uptime invece che sulla data: "
              "inutilizzabili per correlare tra apparati.",
        "en": "Timestamps based on uptime rather than wall-clock time: "
              "useless for correlating across devices.",
    },
    "ios.timestamps.ok": {
        "it": "Timestamp con data e ora su log e debug.",
        "en": "Date and time stamps on logs and debugs.",
    },
    "ios.log_source.absent": {
        "it": "Nessuna «logging source-interface»: l'IP sorgente dei messaggi "
              "cambia con la rotta e complica filtri e correlazione.",
        "en": "No «logging source-interface»: the source IP of the messages "
              "changes with the route, complicating filters and correlation.",
    },
    "ios.log_source.ok": {
        "it": "Interfaccia sorgente dei log fissata.",
        "en": "Log source interface pinned.",
    },
    "ios.login_log.missing": {
        "it": "Accessi non registrati ({directives}): impossibile "
              "ricostruire chi e' entrato e quando.",
        "en": "Logins not recorded ({directives}): there is no way to "
              "reconstruct who logged in and when.",
    },
    "ios.login_log.ok": {
        "it": "Accessi riusciti e falliti registrati entrambi.",
        "en": "Both successful and failed logins recorded.",
    },

    # --- Cisco IOS: NTP e piano dati -------------------------------------
    "ios.ntp.absent": {
        "it": "Nessun «ntp server»: senza orologio sincronizzato i log e la "
              "validita' dei certificati non sono affidabili.",
        "en": "No «ntp server»: without a synchronised clock, logs and "
              "certificate validity cannot be trusted.",
    },
    "ios.ntp.single": {
        "it": "Un solo server NTP configurato: nessuna ridondanza in caso di "
              "guasto della sorgente oraria.",
        "en": "Only one NTP server configured: no redundancy if the time "
              "source fails.",
    },
    "ios.ntp.ok": {
        "it": "{count} server NTP configurati.",
        "en": "{count} NTP servers configured.",
    },
    "ios.ntp_auth.not_applicable": {
        "it": "Nessun server NTP configurato: autenticazione NTP non "
              "applicabile.",
        "en": "No NTP server configured: NTP authentication does not apply.",
    },
    "ios.ntp_auth.missing": {
        "it": "NTP non autenticato: l'apparato accetta l'ora da qualunque "
              "sorgente che si dichiari server.",
        "en": "NTP not authenticated: the device takes the time from any "
              "source claiming to be a server.",
    },
    "ios.ntp_auth.ok": {
        "it": "NTP autenticato con chiave fidata.",
        "en": "NTP authenticated with a trusted key.",
    },
    "ios.proxy_arp.no_ip_iface": {
        "it": "Nessuna interfaccia con indirizzo IP: proxy ARP non valutabile.",
        "en": "No interface with an IP address: proxy ARP cannot be assessed.",
    },
    "ios.proxy_arp.enabled": {
        "it": "Proxy ARP non disabilitato su {count} interfaccia/e: estende "
              "il dominio di broadcast oltre il segmento e indebolisce la "
              "segmentazione.",
        "en": "Proxy ARP not disabled on {count} interface(s): it extends the "
              "broadcast domain past the segment and weakens segmentation.",
    },
    "ios.proxy_arp.ok": {
        "it": "Proxy ARP disabilitato su tutte le interfacce indirizzate.",
        "en": "Proxy ARP disabled on every addressed interface.",
    },
    "ios.tunnel.none": {
        "it": "Nessuna interfaccia tunnel configurata.",
        "en": "No tunnel interface configured.",
    },
    "ios.tunnel.present": {
        "it": "{count} interfacce tunnel presenti: da confermare come "
              "previste, sono un canale di uscita che aggira i controlli "
              "perimetrali.",
        "en": "{count} tunnel interfaces present: confirm they are intended — "
              "they are an egress path that bypasses perimeter controls.",
    },

    # --- Linux: non valutabile --------------------------------------------
    "lnx.empty": {
        "it": "Artefatto vuoto o illeggibile: non c'e' nulla da valutare.",
        "en": "Empty or unreadable artifact: there is nothing to assess.",
    },
    "lnx.sshd.not_assessable": {
        "it": "«{what}» non compare in sshd_config, che pero' include "
              "«sshd_config.d/»: l'impostazione effettiva non e' nel backup. "
              "Serve un triage con password sudo, che raccoglie «sshd -T».",
        "en": "«{what}» does not appear in sshd_config, which however includes "
              "«sshd_config.d/»: the effective setting is not in the backup. "
              "A triage with the sudo password collects «sshd -T».",
    },
    "lnx.login_defs.absent": {
        "it": "«/etc/login.defs» assente dal backup: politica delle password "
              "non valutabile.",
        "en": "«/etc/login.defs» missing from the backup: the password policy "
              "cannot be assessed.",
    },
    "lnx.fstab.absent": {
        "it": "«/etc/fstab» assente dal backup: opzioni di mount non valutabili.",
        "en": "«/etc/fstab» missing from the backup: mount options cannot be "
              "assessed.",
    },
    "lnx.sysctl.absent": {
        "it": "«/etc/sysctl.conf» assente dal backup: parametri di rete non "
              "valutabili.",
        "en": "«/etc/sysctl.conf» missing from the backup: network parameters "
              "cannot be assessed.",
    },
    "lnx.sysctl.not_declared": {
        "it": "«{what}» non e' dichiarato in sysctl.conf: puo' essere "
              "impostato in «/etc/sysctl.d/» o a runtime, che il backup non "
              "contiene.",
        "en": "«{what}» is not declared in sysctl.conf: it may be set under "
              "«/etc/sysctl.d/» or at runtime, which the backup does not cover.",
    },
    "lnx.mount.not_separate": {
        "it": "Nessuna riga in fstab per «{mount}»: non e' una partizione "
              "separata, oppure e' montata altrove (es. tmpfs da systemd). "
              "Le opzioni effettive non si vedono da fstab.",
        "en": "No fstab entry for «{mount}»: it is not a separate partition, "
              "or it is mounted elsewhere (e.g. a systemd tmpfs). The "
              "effective options are not visible from fstab.",
    },

    # --- Linux: SSH -------------------------------------------------------
    "lnx.sshd_root.ok": {
        "it": "Login diretto di root via SSH disabilitato.",
        "en": "Direct root login over SSH is disabled.",
    },
    "lnx.sshd_root.allowed": {
        "it": "Login di root via SSH ammesso («{value}»): un attaccante che "
              "indovina una sola password ottiene subito il massimo privilegio.",
        "en": "Root login over SSH allowed («{value}»): guessing a single "
              "password hands over full privilege immediately.",
    },
    "lnx.sshd_empty.ok": {
        "it": "Nessun accesso SSH con password vuota.",
        "en": "No SSH access with an empty password.",
    },
    "lnx.sshd_empty.allowed": {
        "it": "Accesso SSH con password vuota ammesso («{value}»).",
        "en": "SSH access with an empty password is allowed («{value}»).",
    },
    "lnx.sshd_hostbased.ok": {
        "it": "Autenticazione basata sull'host disabilitata.",
        "en": "Host-based authentication is disabled.",
    },
    "lnx.sshd_hostbased.enabled": {
        "it": "Autenticazione basata sull'host attiva («{value}»): la fiducia "
              "si sposta dal singolo account alla macchina di origine.",
        "en": "Host-based authentication enabled («{value}»): trust moves from "
              "the individual account to the originating machine.",
    },
    "lnx.sshd_rhosts.ok": {
        "it": "I file «.rhosts» non partecipano all'autenticazione.",
        "en": "«.rhosts» files play no part in authentication.",
    },
    "lnx.sshd_rhosts.honored": {
        "it": "I file «.rhosts» sono onorati («{value}»): un utente puo' "
              "dichiarare da solo di quali host fidarsi.",
        "en": "«.rhosts» files are honoured («{value}»): a user can declare "
              "on their own which hosts to trust.",
    },
    "lnx.sshd_forwarding.ok": {
        "it": "Inoltro TCP/X11 attraverso la sessione SSH disattivato.",
        "en": "TCP/X11 forwarding through the SSH session is disabled.",
    },
    "lnx.sshd_forwarding.allowed": {
        "it": "Inoltro TCP/X11 consentito («{value}»): la sessione puo' essere "
              "usata come tunnel verso reti che l'host raggiunge e il client no.",
        "en": "TCP/X11 forwarding allowed («{value}»): the session can be used "
              "as a tunnel into networks the host reaches and the client does not.",
    },
    "lnx.sshd_authtries.ok": {
        "it": "Tentativi di autenticazione per connessione limitati a {value}.",
        "en": "Authentication attempts per connection limited to {value}.",
    },
    "lnx.sshd_authtries.high": {
        "it": "{value} tentativi di autenticazione per connessione (massimo "
              "raccomandato {max}).",
        "en": "{value} authentication attempts per connection (recommended "
              "maximum {max}).",
    },
    "lnx.sshd_authtries.unreadable": {
        "it": "«MaxAuthTries» presente ma con un valore non numerico.",
        "en": "«MaxAuthTries» present but with a non-numeric value.",
    },
    "lnx.sshd_grace.ok": {
        "it": "Finestra di autenticazione di {value} secondi.",
        "en": "Authentication window of {value} seconds.",
    },
    "lnx.sshd_grace.high": {
        "it": "Finestra di autenticazione di {value} secondi (massimo "
              "raccomandato {max}; 0 significa nessun limite).",
        "en": "Authentication window of {value} seconds (recommended maximum "
              "{max}; 0 means no limit at all).",
    },
    "lnx.sshd_grace.unreadable": {
        "it": "«LoginGraceTime» presente ma con un valore non numerico.",
        "en": "«LoginGraceTime» present but with a non-numeric value.",
    },
    "lnx.sshd_alive.ok": {
        "it": "Sessione inattiva chiusa dal server (intervallo {interval}s, "
              "{count} tentativi).",
        "en": "Idle sessions are closed by the server (interval {interval}s, "
              "{count} probes).",
    },
    "lnx.sshd_alive.disabled": {
        "it": "Il server non chiude le sessioni inattive (intervallo "
              "{interval}, conteggio {count}): una sessione abbandonata resta "
              "aperta finche' non cade la rete.",
        "en": "The server never closes idle sessions (interval {interval}, "
              "count {count}): an abandoned session stays open until the "
              "network drops it.",
    },
    "lnx.sshd_loglevel.ok": {
        "it": "Livello di log SSH adeguato («{value}»).",
        "en": "SSH log level is adequate («{value}»).",
    },
    "lnx.sshd_loglevel.weak": {
        "it": "Livello di log SSH «{value}»: sotto INFO gli accessi non "
              "lasciano traccia utilizzabile.",
        "en": "SSH log level «{value}»: below INFO logins leave no usable "
              "trace.",
    },
    "lnx.sshd_banner.ok": {
        "it": "Avviso pre-autenticazione configurato («{value}»).",
        "en": "Pre-authentication banner configured («{value}»).",
    },
    "lnx.sshd_banner.absent": {
        "it": "Nessun avviso pre-autenticazione: manca la dichiarazione che "
              "l'accesso e' riservato e monitorato.",
        "en": "No pre-authentication banner: the notice that access is "
              "restricted and monitored is missing.",
    },

    # --- Linux: politica delle password -----------------------------------
    "lnx.pass_policy.undeclared": {
        "it": "«{what}» non dichiarato in login.defs: nessuna politica per "
              "questo parametro.",
        "en": "«{what}» not declared in login.defs: no policy for this "
              "parameter.",
    },
    "lnx.pass_policy.unreadable": {
        "it": "«{what}» presente ma con un valore non numerico.",
        "en": "«{what}» present but with a non-numeric value.",
    },
    "lnx.pass_max.ok": {
        "it": "Scadenza della password a {value} giorni.",
        "en": "Password expires after {value} days.",
    },
    "lnx.pass_max.too_long": {
        "it": "Scadenza della password a {value} giorni (massimo raccomandato "
              "{limit}; 0 o assente significa nessuna scadenza).",
        "en": "Password expires after {value} days (recommended maximum "
              "{limit}; 0 or missing means it never expires).",
    },
    "lnx.pass_min.ok": {
        "it": "Intervallo minimo fra due cambi password: {value} giorni.",
        "en": "Minimum interval between password changes: {value} days.",
    },
    "lnx.pass_min.too_short": {
        "it": "Intervallo minimo fra due cambi password di {value} giorni "
              "(minimo raccomandato {limit}): senza attesa, un utente puo' "
              "aggirare lo storico ricambiando la password piu' volte di fila.",
        "en": "Minimum interval between password changes of {value} days "
              "(recommended minimum {limit}): with no wait a user can cycle "
              "through the history and return to the old password.",
    },
    "lnx.pass_warn.ok": {
        "it": "Preavviso di scadenza: {value} giorni.",
        "en": "Expiry warning: {value} days.",
    },
    "lnx.pass_warn.too_short": {
        "it": "Preavviso di scadenza di {value} giorni (minimo raccomandato "
              "{limit}).",
        "en": "Expiry warning of {value} days (recommended minimum {limit}).",
    },
    "lnx.encrypt.ok": {
        "it": "Hashing delle password con «{value}».",
        "en": "Password hashing uses «{value}».",
    },
    "lnx.encrypt.weak": {
        "it": "Hashing delle password con «{value}»: un algoritmo veloce rende "
              "praticabile la ricerca esaustiva su uno «/etc/shadow» rubato.",
        "en": "Password hashing uses «{value}»: a fast algorithm makes brute "
              "force practical against a stolen «/etc/shadow».",
    },
    "lnx.encrypt.undeclared": {
        "it": "«ENCRYPT_METHOD» non dichiarato in login.defs: vale il default "
              "della distribuzione, che non e' garantito nel tempo.",
        "en": "«ENCRYPT_METHOD» not declared in login.defs: the distribution "
              "default applies, and that is not guaranteed to stay the same.",
    },

    # --- Linux: mount -----------------------------------------------------
    "lnx.mount.ok": {
        "it": "«{mount}» montato con le opzioni di restrizione raccomandate.",
        "en": "«{mount}» is mounted with the recommended restriction options.",
    },
    "lnx.mount.missing_options": {
        "it": "«{mount}» montato senza «{missing}»: una directory scrivibile da "
              "tutti puo' ospitare eseguibili o file setuid.",
        "en": "«{mount}» mounted without «{missing}»: a world-writable "
              "directory can then host executables or setuid files.",
    },

    # --- Linux: parametri di rete ------------------------------------------
    "lnx.sysctl_forward.ok": {
        "it": "Inoltro di pacchetti IP disattivato.",
        "en": "IP packet forwarding is disabled.",
    },
    "lnx.sysctl_forward.enabled": {
        "it": "Inoltro di pacchetti IP attivo: l'host puo' fare da ponte fra "
              "due reti che il perimetro tiene separate.",
        "en": "IP packet forwarding is enabled: the host can bridge two "
              "networks the perimeter keeps apart.",
    },
    "lnx.sysctl_accept_redirects.ok": {
        "it": "Gli ICMP redirect in ingresso vengono ignorati.",
        "en": "Incoming ICMP redirects are ignored.",
    },
    "lnx.sysctl_accept_redirects.enabled": {
        "it": "Gli ICMP redirect in ingresso vengono accettati ({count} "
              "parametro/i): chiunque sul segmento puo' riscrivere la tabella "
              "di routing dell'host.",
        "en": "Incoming ICMP redirects are accepted ({count} parameter(s)): "
              "anyone on the segment can rewrite the host routing table.",
    },
    "lnx.sysctl_send_redirects.ok": {
        "it": "L'host non emette ICMP redirect.",
        "en": "The host does not emit ICMP redirects.",
    },
    "lnx.sysctl_send_redirects.enabled": {
        "it": "L'host emette ICMP redirect ({count} parametro/i): rivela la "
              "topologia di routing a chiunque lo interroghi.",
        "en": "The host emits ICMP redirects ({count} parameter(s)): it "
              "discloses the routing topology to anyone who probes it.",
    },
    "lnx.sysctl_source_route.ok": {
        "it": "I pacchetti con source routing vengono scartati.",
        "en": "Source-routed packets are dropped.",
    },
    "lnx.sysctl_source_route.enabled": {
        "it": "I pacchetti con source routing vengono accettati ({count} "
              "parametro/i): il mittente sceglie il percorso e puo' aggirare i "
              "controlli di rete.",
        "en": "Source-routed packets are accepted ({count} parameter(s)): the "
              "sender picks the path and can bypass network controls.",
    },
    "lnx.sysctl_syncookies.ok": {
        "it": "Protezione contro il SYN flood attiva.",
        "en": "SYN flood protection is active.",
    },
    "lnx.sysctl_syncookies.disabled": {
        "it": "Protezione contro il SYN flood disattivata: la coda delle "
              "connessioni mezze aperte si riempie con poco traffico.",
        "en": "SYN flood protection is disabled: the half-open connection "
              "queue fills up with very little traffic.",
    },
    "lnx.sysctl_martians.ok": {
        "it": "I pacchetti con indirizzo di origine impossibile vengono "
              "registrati.",
        "en": "Packets with an impossible source address are logged.",
    },
    "lnx.sysctl_martians.disabled": {
        "it": "I pacchetti con indirizzo di origine impossibile non vengono "
              "registrati ({count} parametro/i): uno spoofing in corso non "
              "lascia traccia.",
        "en": "Packets with an impossible source address are not logged "
              "({count} parameter(s)): spoofing in progress leaves no trace.",
    },

    # --- motore -----------------------------------------------------------
    "engine.nothing_to_assess": {
        "it": "Nessuna configurazione da valutare: il testo fornito e' vuoto "
              "o non riconosciuto come configurazione di rete.",
        "en": "Nothing to assess: the supplied text is empty, or not "
              "recognised as a network configuration.",
    },
}


def normalize_lang(lang: Any) -> str:
    """Lingua supportata piu' vicina a ``lang``, con fallback sul default."""
    code = str(lang or "").strip().lower()[:2]
    return code if code in LANGS else DEFAULT_LANG


def render(key: str, lang: str = DEFAULT_LANG,
           params: Any = None) -> str:
    """Frase per ``key``, con i parametri interpolati.

    Chiave sconosciuta o segnaposto mancante NON sollevano: un audit deve
    poter uscire anche se una traduzione manca. Il testo degradato e' la
    chiave stessa, che e' riconoscibile a colpo d'occhio e viene intercettata
    dai test di copertura (``tests/test_netsec_audit_messages.py``), non
    dall'utente in produzione.
    """
    entry = MESSAGES.get(key)
    if not entry:
        return key
    text = entry.get(normalize_lang(lang)) or entry.get(DEFAULT_LANG) or key
    if not params:
        return text
    try:
        return text.format(**params)
    except (KeyError, IndexError, ValueError):
        return text
