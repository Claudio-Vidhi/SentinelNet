# -*- coding: utf-8 -*-
"""Motivazione, impatto e valore di default di ogni controllo di audit.

Il verdetto di una regola (``messages.py``) dice COSA e' stato trovato. Qui c'e'
il resto, che in una cella di tabella non ci starebbe e che e' quanto serve a
decidere se applicare davvero il rimedio:

  ``why``      perche' l'impostazione dovrebbe essere in quel modo — cosa
               diventa possibile per un attaccante quando non lo e';
  ``impact``   cosa succede applicando il rimedio. E' il campo che manca quasi
               sempre negli strumenti di compliance, ed e' l'unico che l'operatore
               non puo' dedurre: "disabilita CDP" e' ovvio, "disabilitando CDP i
               telefoni IP potrebbero non ricevere piu' la VLAN voce" no;
  ``default``  valore di fabbrica, quando esiste ed e' rilevante. Diverse regole
               avvisano che "vale il default della piattaforma": senza sapere
               QUALE, l'avviso non e' azionabile.

FONTE E LICENZA — i testi sono scritti qui, non copiati dai benchmark. I
documenti CIS sono materiale protetto con restrizioni di ridistribuzione e
questo repository e' pubblico: si cita il numero di raccomandazione
(``ref`` in ``benchmarks.py``), non il suo contenuto. Le voci sono indicizzate
per NOME DELLA FUNZIONE di controllo, non per id di benchmark, perche' la
ragione di un'impostazione e' la stessa quale che sia lo standard che la cita:
CIS 2.1.10 e NIST SC-13 guardano la stessa versione di TLS per lo stesso motivo.
"""

from typing import Dict, Optional

from .messages import DEFAULT_LANG, normalize_lang

_FIELDS = ("why", "impact", "default")

GUIDANCE: Dict[str, Dict[str, Dict[str, str]]] = {

    # =========================================================================
    # FortiOS
    # =========================================================================
    "check_management_protocols": {
        "why": {
            "it": "Telnet e HTTP trasmettono credenziali e sessione in chiaro: "
                  "chi e' sullo stesso segmento, o su un qualunque tratto "
                  "attraversato, legge la password dell'amministratore cosi' "
                  "com'e'. Su un'interfaccia esposta verso l'esterno equivale a "
                  "pubblicarla.",
            "en": "Telnet and HTTP carry credentials and session data in "
                  "cleartext: anyone on the same segment, or on any hop in "
                  "between, reads the administrator password as typed. On an "
                  "externally facing interface that amounts to publishing it.",
        },
        "impact": {
            "it": "Chi amministra ancora via Telnet o HTTP perde l'accesso "
                  "finche' non passa a SSH/HTTPS. Verificare prima che gli "
                  "script di automazione non usino quei protocolli.",
            "en": "Anyone still administering over Telnet or HTTP loses access "
                  "until they switch to SSH/HTTPS. Check first that no "
                  "automation scripts rely on those protocols.",
        },
        "default": {
            "it": "Su un'interfaccia nuova «allowaccess» e' vuoto; i profili "
                  "preconfezionati aggiungono spesso ping e https.",
            "en": "On a fresh interface «allowaccess» is empty; canned profiles "
                  "often add ping and https.",
        },
    },
    "check_tls_version": {
        "why": {
            "it": "TLS 1.0 e 1.1 usano costruzioni (CBC con MAC-then-encrypt, "
                  "SHA-1 nelle firme) per cui esistono attacchi pratici, e sono "
                  "ritirati da PCI-DSS e dalle principali normative. Ammetterli "
                  "significa che un attaccante puo' forzare la negoziazione "
                  "verso la versione piu' debole accettata.",
            "en": "TLS 1.0 and 1.1 rely on constructions (CBC with "
                  "MAC-then-encrypt, SHA-1 in signatures) with practical "
                  "attacks against them, and are retired by PCI-DSS and the "
                  "main regulations. Allowing them means an attacker can force "
                  "the negotiation down to the weakest accepted version.",
        },
        "impact": {
            "it": "Browser e client molto vecchi non riescono piu' a "
                  "collegarsi alla GUI. In pratica riguarda solo postazioni "
                  "fuori supporto.",
            "en": "Very old browsers and clients can no longer reach the GUI. "
                  "In practice this only affects out-of-support machines.",
        },
        "default": {
            "it": "Varia con la versione di FortiOS: le release recenti "
                  "partono da TLS 1.2, le piu' vecchie accettano ancora 1.0.",
            "en": "Varies with the FortiOS release: recent versions start at "
                  "TLS 1.2, older ones still accept 1.0.",
        },
    },
    "check_idle_timeout": {
        "why": {
            "it": "Una sessione amministrativa lasciata aperta e' una sessione "
                  "gia' autenticata a disposizione di chiunque arrivi a quella "
                  "postazione, e resta valida anche se nel frattempo la "
                  "password e' stata cambiata o l'account revocato.",
            "en": "An administrative session left open is an already "
                  "authenticated session available to whoever reaches that "
                  "workstation, and it stays valid even if the password was "
                  "changed or the account revoked in the meantime.",
        },
        "impact": {
            "it": "Chi lavora a lungo sulla GUI viene disconnesso a meta' di "
                  "un'operazione. Fastidioso, mai distruttivo: FortiOS non "
                  "applica una configurazione a meta'.",
            "en": "Anyone working long sessions in the GUI gets logged out "
                  "mid-task. Annoying, never destructive: FortiOS does not "
                  "apply a half-written configuration.",
        },
        "default": {"it": "5 minuti.", "en": "5 minutes."},
    },
    "check_strong_crypto": {
        "why": {
            "it": "Senza «strong-crypto» l'apparato continua a offrire cifrari "
                  "e hash legacy (3DES, RC4, MD5, SHA-1) nelle proprie "
                  "sessioni SSL/SSH: la sicurezza effettiva e' quella del "
                  "cifrario piu' debole che il client riesce a negoziare, non "
                  "del piu' forte disponibile.",
            "en": "Without «strong-crypto» the device keeps offering legacy "
                  "ciphers and hashes (3DES, RC4, MD5, SHA-1) on its own "
                  "SSL/SSH sessions: effective security is that of the weakest "
                  "cipher a client can negotiate, not the strongest available.",
        },
        "impact": {
            "it": "Client SSH e tool di monitoraggio molto datati possono non "
                  "negoziare piu'. Da verificare su collector e sistemi di "
                  "backup prima di applicarlo in produzione.",
            "en": "Very old SSH clients and monitoring tools may fail to "
                  "negotiate. Check collectors and backup systems before "
                  "applying it in production.",
        },
        "default": {"it": "enable — ma su apparati aggiornati da versioni "
                          "molto vecchie puo' risultare disabilitato.",
                    "en": "enable — but on devices upgraded from very old "
                          "releases it can end up disabled."},
    },
    "check_any_any_policy": {
        "why": {
            "it": "Una regola con sorgente, destinazione e servizio a «all» non "
                  "e' un controllo di accesso: e' un instradamento con il "
                  "logging di un firewall. Annulla la segmentazione e rende "
                  "impossibile dire, dopo un incidente, cosa sarebbe dovuto "
                  "passare e cosa no.",
            "en": "A rule with source, destination and service all set to "
                  "«all» is not access control: it is routing with a "
                  "firewall's logging. It voids segmentation and makes it "
                  "impossible to say, after an incident, what should have been "
                  "allowed through and what should not.",
        },
        "impact": {
            "it": "Restringerla e' l'intervento piu' rischioso di tutta la "
                  "lista: quasi sempre quella regola copre traffico che nessuno "
                  "ha piu' censito. Attivare prima il logging, ricavare i flussi "
                  "reali, poi sostituirla con regole specifiche.",
            "en": "Tightening it is the riskiest change on this whole list: "
                  "that rule almost always covers traffic nobody has inventoried "
                  "any more. Turn logging on first, derive the real flows, then "
                  "replace it with specific rules.",
        },
    },
    "check_boundary_protection": {
        "why": {
            "it": "Una policy in ingresso da WAN con destinazione «all» rende "
                  "raggiungibile dall'esterno qualunque host interno che abbia "
                  "una rotta, comprese le reti che nessuno considera esposte. "
                  "L'esposizione cresce da sola ogni volta che si aggiunge una "
                  "VLAN.",
            "en": "An inbound policy from WAN with destination «all» makes "
                  "every internal host with a route reachable from outside, "
                  "including the networks nobody thinks of as exposed. The "
                  "exposure grows on its own every time a VLAN is added.",
        },
        "impact": {
            "it": "Specificare le destinazioni puo' interrompere pubblicazioni "
                  "di servizi non documentate. Ricavarle dai log della policy "
                  "prima di restringerla.",
            "en": "Naming the destinations can break undocumented service "
                  "publications. Derive them from the policy's own logs before "
                  "tightening it.",
        },
    },
    "check_inbound_admin_ports": {
        "why": {
            "it": "SSH e RDP raggiungibili da Internet vengono trovati dalle "
                  "scansioni di massa nel giro di ore e sottoposti a forza "
                  "bruta in continuo. Anche con credenziali robuste restano la "
                  "porta d'ingresso preferita del ransomware.",
            "en": "SSH and RDP reachable from the Internet are found by mass "
                  "scans within hours and brute forced continuously. Even with "
                  "strong credentials they remain ransomware's favourite way in.",
        },
        "impact": {
            "it": "Chi amministra da remoto senza VPN perde l'accesso: "
                  "predisporre prima VPN o bastion, altrimenti si rischia di "
                  "chiudersi fuori.",
            "en": "Anyone administering remotely without a VPN loses access: "
                  "set up the VPN or bastion first, or you risk locking "
                  "yourself out.",
        },
    },
    "check_admin_trusthost": {
        "why": {
            "it": "Senza «trusthost» l'unica barriera davanti alla console di "
                  "amministrazione e' la password. Con «trusthost» un attaccante "
                  "che possiede credenziali valide, rubate o riusate, non riesce "
                  "comunque a presentarle: deve prima entrare nella rete di "
                  "gestione.",
            "en": "Without «trusthost» the only barrier in front of the "
                  "administration console is the password. With it, an attacker "
                  "holding valid credentials — stolen or reused — still cannot "
                  "present them: they have to get into the management network "
                  "first.",
        },
        "impact": {
            "it": "Sbagliare la sottorete chiude fuori tutti gli amministratori "
                  "e lascia solo l'accesso da console fisica. Applicarlo "
                  "verificando l'IP sorgente della propria sessione in corso.",
            "en": "Getting the subnet wrong locks out every administrator and "
                  "leaves only physical console access. Apply it while checking "
                  "the source IP of your own live session.",
        },
        "default": {
            "it": "0.0.0.0/0 — nessuna restrizione.",
            "en": "0.0.0.0/0 — no restriction.",
        },
    },
    "check_snmp_community": {
        "why": {
            "it": "«public» e «private» sono i primi due valori che qualunque "
                  "strumento di scansione prova. Una community di default e' "
                  "una credenziale nota che espone l'intera tabella di "
                  "configurazione, di routing e di interfacce dell'apparato.",
            "en": "«public» and «private» are the first two values any scanning "
                  "tool tries. A default community is a known credential that "
                  "exposes the device's whole configuration, routing and "
                  "interface tables.",
        },
        "impact": {
            "it": "Ogni sistema di monitoraggio che interroga l'apparato va "
                  "riconfigurato con la nuova community, altrimenti i grafici "
                  "si fermano senza un errore evidente.",
            "en": "Every monitoring system polling the device has to be "
                  "reconfigured with the new community, otherwise the graphs "
                  "stop with no obvious error.",
        },
    },
    "check_syslog": {
        "why": {
            "it": "I log che restano solo sull'apparato sono esattamente quelli "
                  "che un attaccante cancella per primo, e spariscono comunque "
                  "al riavvio o alla rotazione. Senza copia remota non c'e' "
                  "indagine possibile, e nemmeno prova di conformita'.",
            "en": "Logs that stay on the device alone are exactly the ones an "
                  "attacker wipes first, and they vanish anyway at reboot or "
                  "rotation. With no remote copy there is no investigation "
                  "possible, and no evidence of compliance either.",
        },
        "impact": {
            "it": "Volume: un firewall carico genera facilmente decine di GB al "
                  "giorno. Dimensionare il collector e la ritenzione prima di "
                  "attivare l'inoltro.",
            "en": "Volume: a busy firewall easily produces tens of GB per day. "
                  "Size the collector and the retention before turning "
                  "forwarding on.",
        },
    },
    "check_vendor_defaults": {
        "why": {
            "it": "L'account «admin» di fabbrica e' il primo nome che viene "
                  "provato, e non essendo mai stato creato da nessuno spesso "
                  "non compare nelle revisioni periodiche degli accessi. Senza "
                  "password policy attiva, nulla impedisce di assegnargli una "
                  "password banale.",
            "en": "The factory «admin» account is the first name anyone tries, "
                  "and since nobody ever created it, it often escapes periodic "
                  "access reviews. With no password policy enforced, nothing "
                  "stops it from getting a trivial password.",
        },
        "impact": {
            "it": "Creare il nuovo account amministrativo e verificarne "
                  "l'accesso PRIMA di rimuovere «admin»: e' l'ordine che evita "
                  "di restare senza alcun amministratore.",
            "en": "Create the replacement administrative account and verify it "
                  "works BEFORE removing «admin»: that order is what stops you "
                  "ending up with no administrator at all.",
        },
    },
    "check_dns_configured": {
        "why": {
            "it": "L'apparato risolve nomi per proprio conto: aggiornamenti, "
                  "verifica dei certificati, feed di threat intelligence, "
                  "oggetti FQDN nelle policy. Senza risolutori affidabili "
                  "quelle funzioni degradano in silenzio, e un DNS non "
                  "controllato puo' dirottare gli oggetti FQDN.",
            "en": "The device resolves names on its own behalf: updates, "
                  "certificate validation, threat-intelligence feeds, FQDN "
                  "objects in policies. Without reliable resolvers those "
                  "functions degrade silently, and an uncontrolled DNS can "
                  "hijack the FQDN objects.",
        },
        "impact": {
            "it": "Nessuno: cambiare i risolutori non tocca il traffico degli "
                  "utenti, che usa i propri.",
            "en": "None: changing the resolvers does not touch user traffic, "
                  "which uses its own.",
        },
        "default": {"it": "risolutori pubblici di FortiGuard: il controllo "
                          "passa anche senza che nessuno abbia scelto un DNS.",
                    "en": "FortiGuard public resolvers: the check passes even "
                          "though nobody chose a DNS."},
    },
    "check_intrazone_deny": {
        "why": {
            "it": "Con «intrazone allow» il traffico fra due interfacce della "
                  "stessa zona non attraversa alcuna policy: non e' filtrato e "
                  "non e' registrato. E' una scorciatoia che rimane invisibile, "
                  "perche' nell'elenco delle regole non compare nulla.",
            "en": "With «intrazone allow», traffic between two interfaces of "
                  "the same zone crosses no policy at all: it is neither "
                  "filtered nor logged. It is a shortcut that stays invisible, "
                  "because nothing about it shows up in the rule list.",
        },
        "impact": {
            "it": "Alto: il traffico fra le interfacce della zona si ferma "
                  "finche' non si scrivono le policy corrispondenti. Da fare in "
                  "finestra di manutenzione.",
            "en": "High: traffic between the zone's interfaces stops until the "
                  "matching policies are written. Do it in a maintenance window.",
        },
        "default": {"it": "deny — il traffico intra-zona e' bloccato di "
                          "fabbrica; se e' permesso, qualcuno l'ha aperto.",
                    "en": "deny — intra-zone traffic is blocked out of the "
                          "box; if it is allowed, someone opened it."},
    },
    "check_login_banners": {
        "why": {
            "it": "Il banner non impedisce nulla sul piano tecnico: serve sul "
                  "piano legale. In molte giurisdizioni l'assenza di "
                  "un'avvertenza esplicita indebolisce l'azione contro chi "
                  "accede senza titolo, che puo' sostenere di non essere stato "
                  "avvisato.",
            "en": "The banner prevents nothing technically: its purpose is "
                  "legal. In many jurisdictions the absence of an explicit "
                  "notice weakens action against unauthorised access, since the "
                  "intruder can claim they were never warned.",
        },
        "impact": {
            "it": "Nessuno sul traffico. Far approvare il testo dall'ufficio "
                  "legale invece di improvvisarlo.",
            "en": "None on traffic. Have the wording approved by legal rather "
                  "than improvising it.",
        },
        "default": {"it": "disable.", "en": "disable."},
    },
    "check_timezone": {
        "why": {
            "it": "Se il fuso e' sbagliato ogni evento e' registrato con un'ora "
                  "che non corrisponde a quella reale: la correlazione con gli "
                  "altri apparati salta, e in un'indagine la sequenza dei fatti "
                  "risulta alterata proprio quando conta.",
            "en": "With the wrong time zone every event is recorded at a time "
                  "that does not match reality: correlation with the other "
                  "devices breaks, and in an investigation the sequence of "
                  "events comes out distorted exactly when it matters.",
        },
        "impact": {
            "it": "I log gia' registrati mantengono il vecchio riferimento: "
                  "annotare il momento del cambio, altrimenti l'archivio "
                  "contiene una discontinuita' inspiegata.",
            "en": "Logs already recorded keep the old reference: note when the "
                  "change happened, otherwise the archive holds an unexplained "
                  "discontinuity.",
        },
        "default": {"it": "(GMT-8:00) Pacific Time.",
                    "en": "(GMT-8:00) Pacific Time."},
    },
    "check_ntp": {
        "why": {
            "it": "Un orologio alla deriva invalida la verifica dei "
                  "certificati, i token a tempo e la correlazione fra apparati. "
                  "In un'indagine, timestamp non sincronizzati rendono "
                  "impossibile stabilire cosa e' successo prima.",
            "en": "A drifting clock invalidates certificate validation, "
                  "time-based tokens and cross-device correlation. In an "
                  "investigation, unsynchronised timestamps make it impossible "
                  "to establish what happened first.",
        },
        "impact": {
            "it": "Il primo allineamento puo' spostare l'orologio di parecchio "
                  "e produrre un salto nei log. Meglio in finestra di "
                  "manutenzione se l'apparato termina sessioni VPN.",
            "en": "The first sync can move the clock a long way and produce a "
                  "jump in the logs. Better in a maintenance window if the "
                  "device terminates VPN sessions.",
        },
        "default": {"it": "sincronizzazione attiva verso i server NTP di "
                          "FortiGuard.",
                    "en": "synchronisation enabled towards the FortiGuard NTP "
                          "servers."},
    },
    "check_hostname": {
        "why": {
            "it": "Il nome di fabbrica contiene il modello, e spesso il numero "
                  "di serie: e' la prima informazione utile a chi cerca un "
                  "exploit mirato. Ed e' anche il motivo per cui, con piu' "
                  "apparati identici, il log non dice quale ha generato "
                  "l'evento.",
            "en": "The factory name carries the model, and often the serial "
                  "number: it is the first useful piece of information for "
                  "anyone hunting a targeted exploit. It is also why, with "
                  "several identical devices, the log does not say which one "
                  "produced the event.",
        },
        "impact": {
            "it": "Nessuno sul traffico. Cambia il prompt CLI e il campo "
                  "«devname» nei log: aggiornare i filtri del SIEM.",
            "en": "None on traffic. It changes the CLI prompt and the "
                  "«devname» field in the logs: update the SIEM filters.",
        },
    },
    "check_auto_install": {
        "why": {
            "it": "Con l'auto-install attivo, una chiavetta USB inserita al "
                  "riavvio sostituisce configurazione o firmware senza "
                  "autenticarsi. Trasforma un accesso fisico di trenta secondi "
                  "nel controllo completo dell'apparato.",
            "en": "With auto-install on, a USB stick inserted at boot replaces "
                  "the configuration or the firmware with no authentication. It "
                  "turns thirty seconds of physical access into full control of "
                  "the device.",
        },
        "impact": {
            "it": "Si perde il ripristino rapido da USB in caso di guasto: "
                  "verificare di avere una procedura di recupero alternativa.",
            "en": "You lose fast USB recovery after a failure: make sure an "
                  "alternative recovery procedure exists.",
        },
        "default": {"it": "enable.", "en": "enable."},
    },
    "check_static_key_ciphers": {
        "why": {
            "it": "I cifrari a chiave statica non danno forward secrecy: chi "
                  "registra oggi il traffico cifrato e ottiene domani la chiave "
                  "privata del server puo' decifrare retroattivamente tutto "
                  "l'archivio. Con lo scambio effimero, la compromissione della "
                  "chiave non apre il passato.",
            "en": "Static-key ciphers give no forward secrecy: whoever records "
                  "encrypted traffic today and obtains the server's private key "
                  "tomorrow can retroactively decrypt the whole archive. With "
                  "ephemeral exchange, compromising the key does not unlock the "
                  "past.",
        },
        "impact": {
            "it": "Trascurabile: ogni client moderno supporta lo scambio "
                  "effimero.",
            "en": "Negligible: every modern client supports ephemeral exchange.",
        },
        "default": {"it": "enable — i cifrari a chiave statica sono ammessi "
                          "di fabbrica.",
                    "en": "enable — static-key ciphers are allowed out of the "
                          "box."},
    },
    "check_admin_https_redirect": {
        "why": {
            "it": "Se HTTP resta raggiungibile senza redirect, l'amministratore "
                  "che digita l'indirizzo senza «https://» invia la prima "
                  "richiesta in chiaro — e con essa, a seconda del client, il "
                  "cookie di sessione.",
            "en": "If HTTP stays reachable with no redirect, an administrator "
                  "typing the address without «https://» sends the first "
                  "request in cleartext — and with it, depending on the client, "
                  "the session cookie.",
        },
        "impact": {
            "it": "Nessuno. Il redirect non apre nulla che non fosse gia' "
                  "raggiungibile.",
            "en": "None. The redirect opens nothing that was not already "
                  "reachable.",
        },
        "default": {"it": "enable.", "en": "enable."},
    },
    "check_cpu_log_threshold": {
        "why": {
            "it": "Il carico medio nasconde la saturazione di un singolo core, "
                  "che su un firewall e' il sintomo tipico di un processo in "
                  "loop o di un attacco mirato a una funzione specifica. Senza "
                  "questo allarme il problema si manifesta come lentezza "
                  "inspiegabile.",
            "en": "Average load hides the saturation of a single core, which on "
                  "a firewall is the classic symptom of a looping process or an "
                  "attack aimed at one specific function. Without this alarm the "
                  "problem shows up only as unexplained slowness.",
        },
        "impact": {
            "it": "Solo qualche riga di log in piu'.",
            "en": "Only a few extra log lines.",
        },
        "default": {"it": "disable.", "en": "disable."},
    },
    "check_gui_hostname_display": {
        "why": {
            "it": "La pagina di login e' pre-autenticazione: e' raggiungibile "
                  "da chiunque arrivi all'indirizzo, non solo da chi ha "
                  "credenziali. Mostrarvi l'hostname regala il nome "
                  "dell'apparato — e con esso ruolo e sede, visto come si "
                  "nominano gli apparati — a chi sta solo sondando.",
            "en": "The login page is pre-authentication: it is reachable by "
                  "anyone who gets to the address, not only by those holding "
                  "credentials. Showing the hostname there hands the device "
                  "name — and with it the role and site, given how devices get "
                  "named — to whoever is merely probing.",
        },
        "impact": {
            "it": "Chi amministra piu' apparati identici perde il riferimento "
                  "visivo sulla pagina di login e deve fidarsi dell'URL. Dopo "
                  "l'autenticazione l'hostname resta visibile.",
            "en": "Anyone administering several identical devices loses the "
                  "visual cue on the login page and has to trust the URL. "
                  "After authentication the hostname is still visible.",
        },
        "default": {"it": "disable.", "en": "disable."},
    },
    "check_password_policy_strength": {
        "why": {
            "it": "Le credenziali di un firewall valgono l'intera rete che "
                  "protegge. Una policy che impone lunghezza e varieta' non "
                  "rende una password buona, ma esclude quelle che un attacco a "
                  "dizionario risolve in pochi minuti.",
            "en": "Firewall credentials are worth the entire network behind "
                  "them. A policy enforcing length and variety does not make a "
                  "password good, but it rules out the ones a dictionary attack "
                  "solves in minutes.",
        },
        "impact": {
            "it": "La policy si applica al cambio successivo, non "
                  "retroattivamente: le password deboli gia' impostate restano "
                  "valide finche' non scadono. Attivare anche «expire-status».",
            "en": "The policy applies at the next change, not retroactively: "
                  "weak passwords already set stay valid until they expire. "
                  "Turn «expire-status» on as well.",
        },
        "default": {"it": "status disable.", "en": "status disable."},
    },
    "check_admin_lockout": {
        "why": {
            "it": "Senza blocco, un attaccante puo' provare password "
                  "indefinitamente al ritmo che la rete consente: e' l'unica "
                  "differenza fra una password indovinata in giorni e una mai "
                  "indovinata.",
            "en": "With no lockout an attacker can try passwords indefinitely "
                  "at whatever rate the network allows: that is the whole "
                  "difference between a password guessed in days and one never "
                  "guessed.",
        },
        "impact": {
            "it": "Un blocco aggressivo si presta a un denial of service: chi "
                  "conosce il nome di un amministratore puo' bloccarlo di "
                  "proposito. Ha senso solo insieme a «trusthost», che limita "
                  "chi puo' tentare.",
            "en": "Aggressive lockout enables a denial of service: anyone who "
                  "knows an administrator's username can lock them out on "
                  "purpose. It only makes sense together with «trusthost», "
                  "which limits who can even try.",
        },
        "default": {
            "it": "3 tentativi, 60 secondi di blocco.",
            "en": "3 attempts, 60 seconds of lockout.",
        },
    },
    "check_snmp_v3_only": {
        "why": {
            "it": "SNMP v1 e v2c non hanno autenticazione: la community e' una "
                  "password in chiaro dentro ogni pacchetto, ripetuta a ogni "
                  "polling. Chi la intercetta una volta legge da quel momento "
                  "l'intero stato dell'apparato. SNMPv3 autentica e cifra.",
            "en": "SNMP v1 and v2c have no authentication: the community is a "
                  "cleartext password inside every packet, repeated at every "
                  "poll. Capture it once and you can read the device's entire "
                  "state from then on. SNMPv3 authenticates and encrypts.",
        },
        "impact": {
            "it": "Ogni sistema di monitoraggio va migrato a SNMPv3 con utente, "
                  "chiave di autenticazione e chiave di cifratura. Non tutti gli "
                  "strumenti datati lo supportano: verificarlo prima.",
            "en": "Every monitoring system has to move to SNMPv3 with a user, "
                  "an authentication key and a privacy key. Not every legacy "
                  "tool supports it: check first.",
        },
    },
    "check_admin_ports_changed": {
        "why": {
            "it": "Spostare la porta non e' sicurezza: chi fa una scansione "
                  "completa la trova comunque. Toglie pero' l'apparato dalle "
                  "scansioni di massa, che cercano solo le porte note, e questo "
                  "riduce di molto il rumore di forza bruta nei log — rendendo "
                  "visibili i tentativi mirati.",
            "en": "Moving the port is not security: a full scan finds it "
                  "anyway. It does take the device out of mass scans, which "
                  "only look at well-known ports, and that cuts brute-force "
                  "noise in the logs enough to make targeted attempts visible.",
        },
        "impact": {
            "it": "Ogni collegamento amministrativo deve indicare la nuova "
                  "porta, script e segnalibri compresi. Da coordinare, o meta' "
                  "del gruppo si trova fuori.",
            "en": "Every administrative connection has to name the new port, "
                  "scripts and bookmarks included. Coordinate it, or half the "
                  "team finds itself locked out.",
        },
        "default": {
            "it": "HTTPS 443, SSH 22.",
            "en": "HTTPS 443, SSH 22.",
        },
    },
    "check_local_in_policy": {
        "why": {
            "it": "«allowaccess» decide QUALI servizi l'apparato espone su "
                  "un'interfaccia, non A CHI. Le policy «local-in» sono l'unico "
                  "modo di filtrare per sorgente il traffico diretto "
                  "all'apparato stesso — la GUI, SSH, il portale VPN.",
            "en": "«allowaccess» decides WHICH services the device exposes on "
                  "an interface, not TO WHOM. «local-in» policies are the only "
                  "way to filter, by source, traffic aimed at the device "
                  "itself — the GUI, SSH, the VPN portal.",
        },
        "impact": {
            "it": "Una local-in scritta male chiude fuori l'amministratore e "
                  "non e' modificabile da GUI su tutte le versioni. Prepararsi "
                  "l'accesso da console prima di applicarla.",
            "en": "A badly written local-in policy locks the administrator out, "
                  "and it is not editable from the GUI on every version. Have "
                  "console access ready before applying it.",
        },
        "default": {"it": "nessuna policy local-in.",
                    "en": "no local-in policy."},
    },
    "check_ha_configured": {
        "why": {
            "it": "Un cluster che sorveglia solo lo stato del nodo non commuta "
                  "quando cade un collegamento dati: il nodo attivo resta "
                  "«sano» e continua a tenere il traffico su una porta che non "
                  "passa piu' nulla. Il monitoraggio delle interfacce e' cio' "
                  "che rende reale il failover.",
            "en": "A cluster watching only node health does not fail over when "
                  "a data link drops: the active node still looks healthy and "
                  "keeps holding traffic on a port that no longer forwards "
                  "anything. Interface monitoring is what makes failover real.",
        },
        "impact": {
            "it": "Monitorare un'interfaccia instabile produce commutazioni "
                  "continue, peggio del guasto che si voleva coprire. "
                  "Monitorare solo i collegamenti stabili e ridondati.",
            "en": "Monitoring a flapping interface produces constant "
                  "failovers, worse than the failure it was meant to cover. "
                  "Monitor only stable, redundant links.",
        },
    },
    "check_policy_logging": {
        "why": {
            "it": "Senza «logtraffic all» FortiOS registra solo le sessioni "
                  "toccate da un security profile: il traffico semplicemente "
                  "consentito non lascia traccia. E' proprio quello che serve "
                  "guardare dopo un incidente, per stabilire cosa e' uscito.",
            "en": "Without «logtraffic all», FortiOS logs only the sessions "
                  "touched by a security profile: plainly permitted traffic "
                  "leaves no trace. That is exactly what you need to look at "
                  "after an incident, to establish what left the network.",
        },
        "impact": {
            "it": "Aumenta molto il volume dei log e il carico su disco e "
                  "collector. Su regole ad altissimo traffico valutare "
                  "«logtraffic utm» come compromesso.",
            "en": "It increases log volume, and disk and collector load, "
                  "considerably. On very high-traffic rules consider "
                  "«logtraffic utm» as a compromise.",
        },
        "default": {"it": "disabilitato: una policy nuova non registra nulla, "
                          "e nemmeno il deny implicito finale lo fa.",
                    "en": "disabled: a new policy logs nothing, and neither "
                          "does the final implicit deny."},
    },
    "check_policy_security_profiles": {
        "why": {
            "it": "Una regola verso Internet senza profili di ispezione lascia "
                  "passare malware, comando e controllo ed esfiltrazione senza "
                  "guardarli: l'apparato si comporta come un router con NAT. La "
                  "licenza per ispezionare c'e' gia', semplicemente non e' "
                  "applicata a quella regola.",
            "en": "An Internet-bound rule with no inspection profiles lets "
                  "malware, command-and-control and exfiltration through "
                  "unexamined: the device behaves like a NAT router. The "
                  "licence to inspect is already there, it is simply not "
                  "applied to that rule.",
        },
        "impact": {
            "it": "L'ispezione consuma CPU e puo' ridurre il throughput; "
                  "l'ispezione SSL in particolare rompe le applicazioni che "
                  "usano certificate pinning. Introdurla per gradi.",
            "en": "Inspection costs CPU and can reduce throughput; SSL "
                  "inspection in particular breaks applications that use "
                  "certificate pinning. Introduce it gradually.",
        },
    },
    "check_policy_comments": {
        "why": {
            "it": "Non e' un controllo di sicurezza ma la condizione perche' "
                  "gli altri restino applicabili: una regola senza motivazione "
                  "registrata non viene mai rimossa, perche' nessuno sa cosa "
                  "romperebbe. Le regole si accumulano e il criterio di accesso "
                  "diventa illeggibile.",
            "en": "Not a security control but the condition for the others to "
                  "stay workable: a rule with no recorded reason never gets "
                  "removed, because nobody knows what it would break. Rules pile "
                  "up and the access policy becomes unreadable.",
        },
        "impact": {"it": "Nessuno.", "en": "None."},
    },
    "check_sslvpn_tls": {
        "why": {
            "it": "Il portale SSL-VPN e' per definizione esposto su Internet e "
                  "vi transitano le credenziali degli utenti remoti. E' il "
                  "punto della configurazione dove una versione di TLS "
                  "deprecata pesa di piu'.",
            "en": "The SSL-VPN portal is by definition exposed to the Internet, "
                  "and remote users' credentials travel across it. It is the "
                  "place in the configuration where a deprecated TLS version "
                  "costs the most.",
        },
        "impact": {
            "it": "Client VPN datati possono non connettersi piu'. Verificare "
                  "la versione di FortiClient in uso prima di applicarlo.",
            "en": "Older VPN clients may fail to connect. Check the FortiClient "
                  "version in use before applying it.",
        },
        "default": {"it": "tls1-2 come minimo su FortiOS 7.4: il controllo e' "
                          "gia' soddisfatto salvo che qualcuno l'abbia "
                          "abbassato.",
                    "en": "tls1-2 as the minimum on FortiOS 7.4: the check is "
                          "already satisfied unless someone lowered it."},
    },
    "check_sslvpn_source_restriction": {
        "why": {
            "it": "Un portale VPN raggiungibile dal mondo intero e' sottoposto "
                  "a credential stuffing continuo, e alcune delle "
                  "vulnerabilita' piu' gravi di FortiOS si sfruttano prima "
                  "dell'autenticazione. Restringere le sorgenti riduce la "
                  "superficie anche contro un exploit non ancora corretto.",
            "en": "A VPN portal reachable from the whole world faces constant "
                  "credential stuffing, and some of the most serious FortiOS "
                  "vulnerabilities are exploitable pre-authentication. "
                  "Restricting sources shrinks the surface even against an "
                  "unpatched exploit.",
        },
        "impact": {
            "it": "Applicabile solo se gli utenti remoti hanno indirizzi "
                  "prevedibili, o per paese. Con utenti in mobilita' e' spesso "
                  "impraticabile: in quel caso la misura equivalente e' "
                  "l'autenticazione a piu' fattori.",
            "en": "Only workable if remote users have predictable addresses, or "
                  "by country. With travelling users it is often impractical: "
                  "there, the equivalent control is multi-factor "
                  "authentication.",
        },
    },
    "check_syslog_encrypted": {
        "why": {
            "it": "Il flusso syslog contiene indirizzi, nomi utente, "
                  "destinazioni e azioni di ogni sessione: e' una mappa della "
                  "rete e di chi ci lavora. In chiaro, chiunque si trovi sul "
                  "percorso verso il collector la legge.",
            "en": "The syslog stream carries addresses, usernames, "
                  "destinations and actions for every session: it is a map of "
                  "the network and of who works on it. In cleartext, anyone on "
                  "the path to the collector reads it.",
        },
        "impact": {
            "it": "Il collector deve accettare syslog su TLS e presentare un "
                  "certificato valido. Non tutti i server syslog lo fanno.",
            "en": "The collector has to accept syslog over TLS and present a "
                  "valid certificate. Not every syslog server does.",
        },
        "default": {"it": "disabilitato.", "en": "disabled."},
    },
    "check_event_logging": {
        "why": {
            "it": "Gli event log sono la traccia di chi ha fatto cosa "
                  "sull'apparato: accessi, modifiche di configurazione, "
                  "commutazioni HA. Il log del traffico dice cosa e' passato, "
                  "questo dice chi ha cambiato le regole — ed e' la meta' che "
                  "serve dopo un accesso non autorizzato.",
            "en": "Event logs are the record of who did what on the device: "
                  "logins, configuration changes, HA failovers. Traffic logs "
                  "say what passed through; these say who changed the rules — "
                  "and that is the half you need after unauthorised access.",
        },
        "impact": {
            "it": "Volume trascurabile rispetto al log di traffico.",
            "en": "Volume is negligible next to traffic logging.",
        },
        "default": {"it": "enable.", "en": "enable."},
    },
    "check_log_local_disk": {
        "why": {
            "it": "Il disco locale e' la rete di sicurezza quando il collector "
                  "remoto e' irraggiungibile — cioe' proprio durante un guasto "
                  "di rete o un attacco, che sono i momenti in cui i log "
                  "servono. Senza, quella finestra resta vuota per sempre.",
            "en": "The local disk is the safety net for when the remote "
                  "collector is unreachable — which is precisely during a "
                  "network failure or an attack, the moments when logs matter. "
                  "Without it, that window stays empty forever.",
        },
        "impact": {
            "it": "Su modelli entry-level la scrittura continua consuma la "
                  "memoria flash. Valutare la ritenzione invece di disattivare.",
            "en": "On entry-level models continuous writing wears the flash. "
                  "Tune retention rather than turning it off.",
        },
    },

    # =========================================================================
    # Cisco IOS / IOS-XE
    # =========================================================================
    "check_ios_aaa_new_model": {
        "why": {
            "it": "Senza «aaa new-model» l'apparato si autentica con le "
                  "password di linea e gli utenti locali: credenziali che "
                  "vivono nella configurazione di ogni singolo apparato, non "
                  "revocabili centralmente e non tracciabili a una persona. E' "
                  "il presupposto di quasi tutti gli altri controlli di "
                  "accesso.",
            "en": "Without «aaa new-model» the device authenticates with line "
                  "passwords and local users: credentials living in each "
                  "device's own configuration, not centrally revocable and not "
                  "traceable to a person. It is the precondition for nearly "
                  "every other access control.",
        },
        "impact": {
            "it": "Attivarlo cambia immediatamente il modo in cui vengono "
                  "valutati gli accessi e puo' chiudere fuori chi usava le "
                  "password di linea. Definire prima i metodi con fallback "
                  "«local», tenendo aperta una sessione.",
            "en": "Enabling it changes how logins are evaluated immediately, "
                  "and can lock out anyone using line passwords. Define the "
                  "methods with a «local» fallback first, keeping a session "
                  "open.",
        },
    },
    "check_ios_aaa_authentication_login": {
        "why": {
            "it": "Il metodo di login determina da dove vengono verificate le "
                  "credenziali. Un metodo con fallback «none» e' peggio "
                  "dell'assenza di AAA: sembra configurato, ma in caso di "
                  "server irraggiungibile lascia entrare senza chiedere nulla.",
            "en": "The login method decides where credentials get verified. A "
                  "method with a «none» fallback is worse than no AAA at all: "
                  "it looks configured, but when the server is unreachable it "
                  "lets anyone in without asking.",
        },
        "impact": {
            "it": "Il fallback corretto e' «local», che richiede almeno un "
                  "utente locale definito: crearlo prima, o un guasto del "
                  "server TACACS+ rende l'apparato inaccessibile.",
            "en": "The right fallback is «local», which needs at least one "
                  "local user defined: create it first, or a TACACS+ outage "
                  "makes the device unreachable.",
        },
    },
    "check_ios_aaa_accounting_commands": {
        "why": {
            "it": "L'accounting dei comandi a livello 15 e' l'unica traccia di "
                  "chi ha eseguito cosa. Senza, il log dice che qualcuno e' "
                  "entrato ma non cosa ha cambiato: dopo un'interruzione non e' "
                  "possibile risalire al comando che l'ha causata.",
            "en": "Accounting of level-15 commands is the only record of who "
                  "ran what. Without it the log says someone logged in but not "
                  "what they changed: after an outage there is no way back to "
                  "the command that caused it.",
        },
        "impact": {
            "it": "Genera traffico verso il server TACACS+ a ogni comando. Se "
                  "il server non risponde, con «start-stop» la sessione puo' "
                  "rallentare sensibilmente.",
            "en": "It generates traffic to the TACACS+ server on every command. "
                  "If the server stops answering, «start-stop» can slow the "
                  "session noticeably.",
        },
    },
    "check_ios_vty_transport_ssh": {
        "why": {
            "it": "Telnet trasmette la password dell'amministratore in chiaro, "
                  "carattere per carattere. Su una linea vty senza «transport "
                  "input» vale il default, che su molte versioni ammette ogni "
                  "protocollo disponibile: l'assenza della direttiva e' quindi "
                  "essa stessa il problema.",
            "en": "Telnet sends the administrator's password in cleartext, one "
                  "character at a time. On a vty line with no «transport "
                  "input» the default applies, and on many releases that allows "
                  "every available protocol: the missing directive is itself the "
                  "problem.",
        },
        "impact": {
            "it": "Richiede che SSH sia gia' funzionante — dominio impostato e "
                  "chiavi RSA generate — altrimenti la linea diventa "
                  "inutilizzabile. Verificarlo prima di chiudere Telnet.",
            "en": "It requires SSH to be working already — domain set and RSA "
                  "keys generated — otherwise the line becomes unusable. Verify "
                  "that before closing Telnet.",
        },
        "default": {
            "it": "«transport input all» sulle versioni piu' vecchie, «none» su "
                  "quelle recenti.",
            "en": "«transport input all» on older releases, «none» on recent "
                  "ones.",
        },
    },
    "check_ios_vty_access_class": {
        "why": {
            "it": "Senza access-class la porta SSH dell'apparato risponde a "
                  "chiunque riesca a raggiungerla, e ogni tentativo di accesso "
                  "consuma una delle poche linee vty disponibili: bastano "
                  "connessioni ripetute per lasciare fuori gli amministratori "
                  "senza indovinare alcuna password.",
            "en": "Without an access-class the device's SSH port answers "
                  "anyone who can reach it, and every login attempt consumes "
                  "one of the few vty lines available: repeated connections "
                  "alone can lock administrators out without guessing any "
                  "password.",
        },
        "impact": {
            "it": "Una ACL sbagliata chiude fuori tutti e lascia solo la "
                  "console fisica. Applicarla verificando che il proprio "
                  "indirizzo sorgente sia incluso, e con «reload in 10» attivo "
                  "come rete di sicurezza.",
            "en": "A wrong ACL locks everyone out and leaves only the physical "
                  "console. Apply it after checking your own source address is "
                  "included, with «reload in 10» armed as a safety net.",
        },
    },
    "check_ios_vty_exec_timeout": {
        "why": {
            "it": "Una sessione vty abbandonata resta autenticata e occupa una "
                  "linea. Con «exec-timeout 0 0» non scade mai: chi trova quel "
                  "terminale ottiene i privilegi di chi l'ha lasciato aperto.",
            "en": "An abandoned vty session stays authenticated and holds a "
                  "line. With «exec-timeout 0 0» it never expires: whoever "
                  "finds that terminal inherits the privileges of the person "
                  "who left it open.",
        },
        "impact": {
            "it": "Disconnessioni durante operazioni lunghe. Nessun rischio per "
                  "la configurazione, che su IOS e' applicata comando per "
                  "comando.",
            "en": "Disconnections during long operations. No risk to the "
                  "configuration, which on IOS is applied command by command.",
        },
        "default": {"it": "10 minuti.", "en": "10 minutes."},
    },
    "check_ios_console_exec_timeout": {
        "why": {
            "it": "La console e' spesso collegata in permanenza a un server "
                  "seriale raggiungibile in rete: una sessione lasciata aperta "
                  "li' e' accessibile a chiunque arrivi a quel server, senza "
                  "passare da alcuna autenticazione dell'apparato.",
            "en": "The console is often permanently wired to a network-reachable "
                  "terminal server: a session left open there is available to "
                  "anyone who reaches that server, bypassing the device's "
                  "authentication entirely.",
        },
        "impact": {
            "it": "Nessuno, salvo dover riautenticarsi durante interventi "
                  "lunghi da console.",
            "en": "None, beyond having to re-authenticate during long console "
                  "sessions.",
        },
        "default": {"it": "10 minuti.", "en": "10 minutes."},
    },
    "check_ios_aux_no_exec": {
        "why": {
            "it": "La porta ausiliaria e' spesso collegata a un modem o a un "
                  "server di console e poi dimenticata. Con il processo EXEC "
                  "attivo offre un accesso amministrativo completo che non "
                  "compare in nessuna revisione degli accessi in rete.",
            "en": "The auxiliary port is often wired to a modem or a console "
                  "server and then forgotten. With the EXEC process active it "
                  "offers full administrative access that appears in no review "
                  "of network access paths.",
        },
        "impact": {
            "it": "Si perde l'accesso di emergenza via AUX. Rilevante solo se "
                  "esiste davvero una procedura che lo usa.",
            "en": "You lose emergency access over AUX. Only relevant if a "
                  "procedure actually uses it.",
        },
    },
    "check_ios_local_user_privilege": {
        "why": {
            "it": "Un utente a «privilege 15» entra direttamente in EXEC "
                  "privilegiato: la password di enable non viene mai chiesta e "
                  "il secondo fattore di controllo sparisce. Ogni compromissione "
                  "di quell'account e' immediatamente totale.",
            "en": "A «privilege 15» user lands straight in privileged EXEC: the "
                  "enable password is never asked and the second control step "
                  "disappears. Any compromise of that account is immediately "
                  "total.",
        },
        "impact": {
            "it": "Riportare gli utenti a «privilege 1» impone di conoscere la "
                  "enable secret: verificare che sia nota e documentata prima, "
                  "o gli amministratori restano con soli privilegi di lettura.",
            "en": "Dropping users to «privilege 1» means they must know the "
                  "enable secret: make sure it is known and documented first, or "
                  "administrators are left with read-only privileges.",
        },
    },
    "check_ios_banner_login": {
        "why": {
            "it": "Il banner di login compare prima dell'autenticazione ed e' "
                  "l'avvertenza che qualifica come non autorizzato ogni accesso "
                  "successivo. Non deve rivelare modello, versione o "
                  "proprietario: sarebbero informazioni offerte a chi sta "
                  "sondando l'apparato.",
            "en": "The login banner appears before authentication and is the "
                  "notice that makes any subsequent access unauthorised. It must "
                  "not reveal model, version or owner: that would be handing "
                  "information to whoever is probing the device.",
        },
        "impact": {"it": "Nessuno.", "en": "None."},
    },
    "check_ios_banner_motd": {
        "why": {
            "it": "Il MOTD e' il messaggio mostrato a ogni connessione. Ha lo "
                  "stesso valore legale del banner di login e, essendo "
                  "modificabile senza toccare l'autenticazione, e' il posto "
                  "dove annunciare finestre di manutenzione.",
            "en": "The MOTD is shown on every connection. It carries the same "
                  "legal weight as the login banner and, being editable without "
                  "touching authentication, is where maintenance windows get "
                  "announced.",
        },
        "impact": {"it": "Nessuno.", "en": "None."},
    },
    "check_ios_enable_secret": {
        "why": {
            "it": "«enable password» e' memorizzata con la cifratura di tipo 7, "
                  "reversibile: esistono decodificatori online da vent'anni. "
                  "Chiunque legga la configurazione — un backup, un ticket, un "
                  "collega — ottiene la password privilegiata in chiaro. "
                  "«enable secret» usa un hash non invertibile.",
            "en": "«enable password» is stored with type-7 encoding, which is "
                  "reversible: online decoders have existed for twenty years. "
                  "Anyone who reads the configuration — a backup, a ticket, a "
                  "colleague — recovers the privileged password in cleartext. "
                  "«enable secret» uses a non-invertible hash.",
        },
        "impact": {
            "it": "Se sono presenti entrambe, IOS usa «secret» e ignora "
                  "«password»: impostare la secret e verificare l'accesso prima "
                  "di rimuovere la vecchia riga.",
            "en": "If both are present IOS uses «secret» and ignores "
                  "«password»: set the secret and verify access before removing "
                  "the old line.",
        },
    },
    "check_ios_service_password_encryption": {
        "why": {
            "it": "Senza questa direttiva le password di linea e alcune "
                  "credenziali di protocollo restano leggibili in chiaro nella "
                  "configurazione, che circola in backup, ticket e repository. "
                  "La cifratura di tipo 7 e' debole, ma toglie la lettura "
                  "accidentale a chi si limita a guardare.",
            "en": "Without this directive line passwords and some protocol "
                  "credentials stay readable in cleartext in the configuration, "
                  "which travels through backups, tickets and repositories. "
                  "Type-7 encoding is weak, but it stops casual reading by "
                  "anyone merely looking.",
        },
        "impact": {
            "it": "Nessuno. Da non confondere con una protezione reale: e' "
                  "reversibile, e serve «secret» dove possibile.",
            "en": "None. Not to be mistaken for real protection: it is "
                  "reversible, and «secret» is what you want wherever possible.",
        },
        "default": {"it": "disabilitato.", "en": "disabled."},
    },
    "check_ios_username_secret": {
        "why": {
            "it": "«username ... password» conserva la credenziale in chiaro o "
                  "in tipo 7, entrambi recuperabili da chi legge la "
                  "configurazione. «secret» applica un hash: chi ottiene il "
                  "backup non ottiene le password.",
            "en": "«username ... password» keeps the credential in cleartext or "
                  "type 7, both recoverable by anyone who reads the "
                  "configuration. «secret» applies a hash: whoever gets the "
                  "backup does not get the passwords.",
        },
        "impact": {
            "it": "Le password vanno reimpostate: l'hash non si ricava da "
                  "quelle esistenti. Usare «algorithm-type sha256» dove la "
                  "versione lo supporta.",
            "en": "Passwords must be re-entered: the hash cannot be derived "
                  "from the existing ones. Use «algorithm-type sha256» where "
                  "the release supports it.",
        },
    },
    "check_ios_snmp_default_community": {
        "why": {
            "it": "«public» e «private» sono i primi valori provati da "
                  "qualunque scanner. Su IOS una community di lettura espone "
                  "tabella ARP, interfacce, rotte e vicini CDP: la mappa "
                  "completa della rete, offerta senza autenticazione.",
            "en": "«public» and «private» are the first values any scanner "
                  "tries. On IOS a read community exposes the ARP table, "
                  "interfaces, routes and CDP neighbours: a complete map of the "
                  "network, handed over with no authentication.",
        },
        "impact": {
            "it": "Ogni sistema di monitoraggio va aggiornato con la nuova "
                  "community, altrimenti smette di raccogliere senza segnalarlo.",
            "en": "Every monitoring system needs the new community, otherwise "
                  "it silently stops collecting.",
        },
    },
    "check_ios_snmp_readwrite": {
        "why": {
            "it": "Una community RW non e' monitoraggio: consente di "
                  "modificare la configurazione via SNMP e, storicamente, di "
                  "scaricarla o sostituirla via TFTP. Con SNMPv2c quella "
                  "community viaggia in chiaro a ogni polling.",
            "en": "An RW community is not monitoring: it allows changing the "
                  "configuration over SNMP and, historically, downloading or "
                  "replacing it over TFTP. Under SNMPv2c that community travels "
                  "in cleartext at every poll.",
        },
        "impact": {
            "it": "Alcuni strumenti di provisioning usano SNMP RW per scrivere "
                  "la configurazione: verificare prima di rimuoverla, o quei "
                  "flussi si fermano.",
            "en": "Some provisioning tools use SNMP RW to write configuration: "
                  "check before removing it, or those workflows stop.",
        },
    },
    "check_ios_snmp_community_acl": {
        "why": {
            "it": "Una community senza access-list risponde a chiunque possa "
                  "inviare un pacchetto UDP all'apparato — e UDP si falsifica "
                  "facilmente come sorgente. L'ACL e' quello che limita "
                  "l'interrogazione ai soli sistemi di monitoraggio.",
            "en": "A community with no access-list answers anyone able to send "
                  "the device a UDP packet — and UDP source addresses are easy "
                  "to forge. The ACL is what confines querying to the "
                  "monitoring systems.",
        },
        "impact": {
            "it": "Dimenticare un collector nella lista lo lascia senza dati, "
                  "in silenzio. Enumerarli tutti prima.",
            "en": "Leaving a collector out of the list silently starves it of "
                  "data. Enumerate them all first.",
        },
    },
    "check_ios_snmpv3_privacy": {
        "why": {
            "it": "SNMPv3 senza «priv» autentica ma non cifra: i dati "
                  "viaggiano leggibili. Con AES a 128 bit o piu' sia "
                  "l'autenticazione sia il contenuto sono protetti, e SNMP "
                  "smette di essere un canale di ricognizione.",
            "en": "SNMPv3 without «priv» authenticates but does not encrypt: "
                  "the data travels readable. With AES at 128 bits or above "
                  "both the authentication and the payload are protected, and "
                  "SNMP stops being a reconnaissance channel.",
        },
        "impact": {
            "it": "Cifratura e autenticazione costano CPU a ogni polling: su "
                  "apparati datati con intervalli brevi l'effetto e' "
                  "misurabile.",
            "en": "Encryption and authentication cost CPU at every poll: on "
                  "older devices with short intervals the effect is "
                  "measurable.",
        },
    },
    "check_ios_ssh_version": {
        "why": {
            "it": "SSH versione 1 ha debolezze strutturali nel controllo di "
                  "integrita' che permettono l'inserimento di comandi in una "
                  "sessione cifrata. Non e' una questione di chiavi piu' lunghe: "
                  "il protocollo e' rotto e va escluso.",
            "en": "SSH version 1 has structural weaknesses in its integrity "
                  "checking that allow injecting commands into an encrypted "
                  "session. This is not about longer keys: the protocol is "
                  "broken and has to be excluded.",
        },
        "impact": {
            "it": "Client SSH molto vecchi non si collegano piu'. In pratica "
                  "nessuno strumento ancora supportato usa SSHv1.",
            "en": "Very old SSH clients stop connecting. In practice no "
                  "supported tool still uses SSHv1.",
        },
        "default": {
            "it": "modalita' compatibile: accetta 1 e 2.",
            "en": "compatibility mode: accepts both 1 and 2.",
        },
    },
    "check_ios_ssh_timeout": {
        "why": {
            "it": "Il timeout limita quanto a lungo una connessione puo' "
                  "restare aperta senza completare l'autenticazione. Con il "
                  "default di 120 secondi, poche connessioni parallele tengono "
                  "occupate tutte le linee vty e lasciano fuori gli "
                  "amministratori.",
            "en": "The timeout bounds how long a connection can stay open "
                  "without completing authentication. At the 120-second "
                  "default, a handful of parallel connections hold every vty "
                  "line and lock administrators out.",
        },
        "impact": {
            "it": "Su collegamenti molto lenti o con autenticazione a piu' "
                  "fattori 60 secondi possono essere stretti: verificare col "
                  "proprio flusso di login.",
            "en": "On very slow links or with multi-factor authentication 60 "
                  "seconds can be tight: check against your own login flow.",
        },
        "default": {"it": "120 secondi.", "en": "120 seconds."},
    },
    "check_ios_ssh_auth_retries": {
        "why": {
            "it": "Ogni tentativo consentito nella stessa sessione moltiplica "
                  "le password provabili senza il costo di riaprire la "
                  "connessione. Limitarli non ferma la forza bruta ma la "
                  "rallenta e la rende visibile nei log.",
            "en": "Every attempt allowed within the same session multiplies the "
                  "passwords testable without the cost of reopening the "
                  "connection. Limiting them does not stop brute force but "
                  "slows it and makes it visible in the logs.",
        },
        "impact": {
            "it": "Trascurabile: chi sbaglia la password riapre la sessione.",
            "en": "Negligible: anyone mistyping simply reconnects.",
        },
        "default": {"it": "3.", "en": "3."},
    },
    "check_ios_domain_name": {
        "why": {
            "it": "IOS deriva il nome della coppia di chiavi RSA da hostname e "
                  "dominio: senza dominio le chiavi non si generano e SSH non "
                  "puo' partire. Non e' un controllo di sicurezza in se', e' il "
                  "prerequisito che rende applicabile tutto il resto.",
            "en": "IOS derives the RSA key pair name from the hostname and the "
                  "domain: with no domain the keys cannot be generated and SSH "
                  "cannot start. Not a security control in itself, but the "
                  "precondition that makes the rest applicable.",
        },
        "impact": {
            "it": "Cambiare il dominio dopo aver generato le chiavi le "
                  "invalida: SSH va riabilitato rigenerandole.",
            "en": "Changing the domain after generating the keys invalidates "
                  "them: SSH has to be re-enabled by regenerating them.",
        },
    },
    "check_ios_cdp": {
        "why": {
            "it": "CDP annuncia in chiaro modello, versione di IOS, nome "
                  "dell'apparato, indirizzo di gestione e porta: e' esattamente "
                  "l'elenco che serve per scegliere un exploit. Chiunque si "
                  "colleghi a una presa lo riceve senza autenticarsi.",
            "en": "CDP announces, in cleartext, the model, IOS version, device "
                  "name, management address and port: precisely the list needed "
                  "to pick an exploit. Anyone plugging into a socket receives it "
                  "without authenticating.",
        },
        "impact": {
            "it": "Telefoni IP e access point Cisco usano CDP per ricevere la "
                  "VLAN voce e negoziare il PoE: disabilitarlo globalmente puo' "
                  "lasciarli senza servizio. Disabilitarlo per interfaccia sulle "
                  "porte utente e' il compromesso usuale.",
            "en": "Cisco IP phones and access points use CDP to learn the voice "
                  "VLAN and negotiate PoE: disabling it globally can leave them "
                  "without service. Disabling it per interface on user ports is "
                  "the usual compromise.",
        },
        "default": {"it": "attivo.", "en": "enabled."},
    },
    "check_ios_service_dhcp": {
        "why": {
            "it": "Se l'indirizzamento e' erogato altrove, il servizio DHCP "
                  "attivo e' solo superficie di attacco: risponde a richieste "
                  "sulla rete e ha un proprio storico di vulnerabilita'. Puo' "
                  "anche entrare in conflitto col server legittimo.",
            "en": "If addressing is served elsewhere, a running DHCP service is "
                  "pure attack surface: it answers requests on the network and "
                  "has a vulnerability history of its own. It can also conflict "
                  "with the legitimate server.",
        },
        "impact": {
            "it": "Alto se l'apparato eroga davvero indirizzi, anche solo a una "
                  "VLAN di gestione o a un pool di test. Verificare la presenza "
                  "di «ip dhcp pool» prima di disabilitare.",
            "en": "High if the device really hands out addresses, even to a "
                  "single management VLAN or a test pool. Check for «ip dhcp "
                  "pool» before disabling.",
        },
        "default": {"it": "attivo.", "en": "enabled."},
    },
    "check_ios_service_pad": {
        "why": {
            "it": "PAD serve per X.25, protocollo che non esiste piu' in alcuna "
                  "rete in produzione. Resta attivo per compatibilita' storica "
                  "ed e' codice raggiungibile che nessuno usa, verifica o "
                  "aggiorna: la definizione di superficie di attacco inutile.",
            "en": "PAD exists for X.25, a protocol absent from any production "
                  "network today. It stays on for historical compatibility, "
                  "reachable code that nobody uses, reviews or patches: the "
                  "definition of pointless attack surface.",
        },
        "impact": {"it": "Nessuno.", "en": "None."},
        "default": {"it": "attivo.", "en": "enabled."},
    },
    "check_ios_tcp_keepalives": {
        "why": {
            "it": "Senza keepalive, una sessione amministrativa interrotta "
                  "male — cavo staccato, portatile chiuso — resta aperta e "
                  "autenticata lato apparato. Occupa una linea vty e, in casi "
                  "sfortunati, e' dirottabile.",
            "en": "Without keepalives an administrative session that ended "
                  "badly — cable pulled, laptop closed — stays open and "
                  "authenticated on the device side. It holds a vty line and, in "
                  "unlucky cases, can be hijacked.",
        },
        "impact": {"it": "Nessuno.", "en": "None."},
        "default": {"it": "disabilitati.", "en": "disabled."},
    },
    "check_ios_logging_host": {
        "why": {
            "it": "Il buffer di un apparato IOS e' piccolo e volatile: si "
                  "svuota a ogni riavvio e si sovrascrive da solo in poche ore "
                  "su un apparato attivo. Senza collector remoto, la traccia "
                  "dell'evento che ha causato il riavvio sparisce con il "
                  "riavvio stesso.",
            "en": "An IOS device's buffer is small and volatile: it empties at "
                  "every reboot and overwrites itself within hours on a busy "
                  "device. With no remote collector, the record of the event "
                  "that caused the reboot disappears along with the reboot.",
        },
        "impact": {
            "it": "Aggiunge traffico UDP costante verso il collector. Su "
                  "collegamenti geografici lenti valutare il livello di "
                  "severita' inviato.",
            "en": "It adds steady UDP traffic towards the collector. On slow "
                  "WAN links, tune the severity level sent.",
        },
    },
    "check_ios_logging_buffered": {
        "why": {
            "it": "Il buffer locale e' cio' che si legge quando il collector "
                  "remoto e' irraggiungibile, che e' spesso il momento in cui "
                  "serve. Un buffer troppo piccolo si sovrascrive prima che "
                  "qualcuno arrivi a guardarlo.",
            "en": "The local buffer is what you read when the remote collector "
                  "is unreachable, which is often exactly when you need it. Too "
                  "small a buffer overwrites itself before anyone gets to look.",
        },
        "impact": {
            "it": "Occupa RAM. Su apparati con poca memoria un buffer molto "
                  "grande sottrae risorse alle funzioni di rete.",
            "en": "It consumes RAM. On memory-constrained devices a very large "
                  "buffer takes resources away from networking functions.",
        },
        "default": {
            "it": "4096 byte su molte piattaforme.",
            "en": "4096 bytes on many platforms.",
        },
    },
    "check_ios_logging_console": {
        "why": {
            "it": "La console e' un'interfaccia seriale lenta, e IOS attende "
                  "che ogni messaggio sia stato scritto. Con un livello "
                  "verboso, durante un evento di rete l'apparato passa tempo a "
                  "scrivere sulla console invece che a instradare: e' un modo "
                  "documentato di far cadere un router sotto carico.",
            "en": "The console is a slow serial interface, and IOS waits for "
                  "each message to be written. At a verbose level, during a "
                  "network event the device spends its time writing to the "
                  "console instead of routing: a documented way to take a "
                  "router down under load.",
        },
        "impact": {
            "it": "Chi lavora da console vede meno messaggi in tempo reale. "
                  "Restano tutti nel buffer e sul syslog.",
            "en": "Anyone working from the console sees fewer live messages. "
                  "They all remain in the buffer and on syslog.",
        },
        "default": {"it": "debugging — tutto.", "en": "debugging — everything."},
    },
    "check_ios_logging_trap": {
        "why": {
            "it": "«logging trap» decide quanto viene inoltrato al syslog "
                  "remoto. Impostato troppo in alto — «emergencies», "
                  "«alerts» — non arrivano ne' i login, ne' le modifiche di "
                  "configurazione, ne' i cambi di stato delle interfacce: "
                  "esattamente cio' che serve correlare.",
            "en": "«logging trap» decides how much is forwarded to the remote "
                  "syslog. Set too high — «emergencies», «alerts» — neither "
                  "logins, nor configuration changes, nor interface state "
                  "changes arrive: precisely what you need to correlate.",
        },
        "impact": {
            "it": "«informational» aumenta sensibilmente il volume: "
                  "dimensionare la ritenzione del collector.",
            "en": "«informational» increases volume considerably: size the "
                  "collector's retention accordingly.",
        },
        "default": {"it": "informational.", "en": "informational."},
    },
    "check_ios_service_timestamps": {
        "why": {
            "it": "Con i timestamp basati sull'uptime, un messaggio riporta "
                  "«2w3d» invece di una data: per sapere quando e' accaduto "
                  "servono l'ora del riavvio e un calcolo a mano. Correlare "
                  "eventi fra piu' apparati diventa impraticabile.",
            "en": "With uptime-based timestamps a message reads «2w3d» instead "
                  "of a date: working out when it happened needs the boot time "
                  "and hand arithmetic. Correlating events across devices "
                  "becomes impractical.",
        },
        "impact": {
            "it": "Nessuno. Aggiungere «show-timezone» se gli apparati sono su "
                  "fusi diversi, altrimenti la data e' ambigua.",
            "en": "None. Add «show-timezone» if devices sit in different time "
                  "zones, otherwise the date is ambiguous.",
        },
        "default": {"it": "uptime.", "en": "uptime."},
    },
    "check_ios_logging_source_interface": {
        "why": {
            "it": "Senza interfaccia sorgente fissa, l'IP da cui arrivano i log "
                  "cambia con la rotta scelta al momento. Il collector vede lo "
                  "stesso apparato sotto identita' diverse, i filtri per "
                  "sorgente saltano e le correlazioni si spezzano.",
            "en": "Without a pinned source interface, the IP the logs come from "
                  "changes with whatever route is chosen at the time. The "
                  "collector sees one device under several identities, "
                  "source-based filters break and correlations fall apart.",
        },
        "impact": {
            "it": "L'interfaccia scelta — tipicamente una loopback — deve "
                  "essere raggiungibile dal collector, altrimenti i log "
                  "smettono di arrivare.",
            "en": "The chosen interface — typically a loopback — has to be "
                  "reachable from the collector, otherwise the logs stop "
                  "arriving.",
        },
    },
    "check_ios_login_logging": {
        "why": {
            "it": "Senza «login on-failure log» un attacco a forza bruta non "
                  "lascia alcuna traccia: non c'e' modo di accorgersene ne' "
                  "durante ne' dopo. Senza «on-success» non si sa quale "
                  "tentativo, alla fine, e' andato a buon fine.",
            "en": "Without «login on-failure log» a brute-force attack leaves "
                  "no trace at all: there is no way to notice it, during or "
                  "after. Without «on-success» there is no telling which attempt "
                  "eventually worked.",
        },
        "impact": {
            "it": "Volume trascurabile, salvo su apparati gia' sotto attacco — "
                  "dove pero' e' precisamente il punto.",
            "en": "Negligible volume, except on devices already under attack — "
                  "where that is precisely the point.",
        },
    },
    "check_ios_ntp_servers": {
        "why": {
            "it": "Un orologio non sincronizzato rende i log di quell'apparato "
                  "incollocabili nel tempo rispetto a tutti gli altri: la "
                  "sequenza degli eventi, che e' cio' che si ricostruisce dopo "
                  "un incidente, diventa inattendibile. Due sorgenti servono "
                  "perche' una sola non e' verificabile.",
            "en": "An unsynchronised clock makes that device's logs impossible "
                  "to place in time against every other device: the sequence of "
                  "events, which is what you reconstruct after an incident, "
                  "becomes unreliable. Two sources matter because a single one "
                  "cannot be cross-checked.",
        },
        "impact": {
            "it": "La prima sincronizzazione puo' spostare l'orologio "
                  "bruscamente. Su apparati che terminano tunnel IPsec un salto "
                  "puo' rinegoziare le associazioni.",
            "en": "The first sync can move the clock abruptly. On devices "
                  "terminating IPsec tunnels a jump can force renegotiation.",
        },
    },
    "check_ios_ntp_authentication": {
        "why": {
            "it": "NTP non autenticato accetta l'ora da qualunque sorgente che "
                  "si dichiari server. Spostare l'orologio serve a far scadere "
                  "certificati validi, riabilitarne di revocati e rendere "
                  "incoerenti i log proprio durante un'intrusione.",
            "en": "Unauthenticated NTP takes the time from any source claiming "
                  "to be a server. Shifting the clock is a way to expire valid "
                  "certificates, resurrect revoked ones and make the logs "
                  "incoherent precisely during an intrusion.",
        },
        "impact": {
            "it": "Le chiavi vanno configurate identiche su server e client: "
                  "se non corrispondono la sincronizzazione si ferma in "
                  "silenzio, e la deriva riparte.",
            "en": "The keys must match exactly on server and client: if they do "
                  "not, synchronisation stops silently and drift resumes.",
        },
    },
    "check_ios_source_route": {
        "why": {
            "it": "Il source routing lascia al mittente la scelta del percorso "
                  "dei propri pacchetti: e' cosi' che si raggiungono reti che "
                  "l'instradamento normale non esporrebbe e si aggirano i "
                  "controlli basati sul percorso. Non ha usi legittimi nelle "
                  "reti moderne.",
            "en": "Source routing lets the sender choose the path of their own "
                  "packets: that is how you reach networks normal routing would "
                  "not expose, and how path-based controls get bypassed. It has "
                  "no legitimate use in modern networks.",
        },
        "impact": {
            "it": "Nessuno in pratica. Qualche strumento diagnostico molto "
                  "vecchio lo usava.",
            "en": "None in practice. Some very old diagnostic tools relied on "
                  "it.",
        },
        "default": {"it": "attivo.", "en": "enabled."},
    },
    "check_ios_proxy_arp": {
        "why": {
            "it": "Con proxy ARP il router risponde alle richieste ARP per "
                  "indirizzi che non gli appartengono, facendo apparire host di "
                  "altre reti come se fossero sul segmento locale. Estende il "
                  "dominio di broadcast oltre il confine progettato e vanifica "
                  "in parte la segmentazione.",
            "en": "With proxy ARP the router answers ARP requests for addresses "
                  "that are not its own, making hosts on other networks look "
                  "local to the segment. It stretches the broadcast domain past "
                  "its designed boundary and partly defeats segmentation.",
        },
        "impact": {
            "it": "Host configurati con una maschera sbagliata smettono di "
                  "raggiungere le altre reti, perche' si appoggiavano al proxy "
                  "ARP senza saperlo. Sono guasti latenti che emergono tutti "
                  "insieme.",
            "en": "Hosts configured with the wrong netmask stop reaching other "
                  "networks, because they were leaning on proxy ARP without "
                  "knowing. These are latent faults that surface all at once.",
        },
        "default": {"it": "attivo su ogni interfaccia.", "en": "on, per interface."},
    },
    "check_ios_tunnel_interfaces": {
        "why": {
            "it": "Un tunnel incapsula traffico e lo porta fuori dal percorso "
                  "sorvegliato: le policy perimetrali vedono un solo flusso "
                  "verso l'endpoint, non cio' che contiene. Un tunnel legittimo "
                  "va documentato; uno non previsto e' una via d'uscita che "
                  "aggira ogni controllo.",
            "en": "A tunnel encapsulates traffic and carries it off the "
                  "monitored path: perimeter policies see a single flow to the "
                  "endpoint, not what it contains. A legitimate tunnel needs "
                  "documenting; an unexpected one is an exit that bypasses every "
                  "control.",
        },
        "impact": {
            "it": "Rimuovere un tunnel in uso interrompe la connettivita' che "
                  "trasporta, spesso verso una sede o un fornitore. Da "
                  "verificare, non da eliminare d'ufficio.",
            "en": "Removing a tunnel in use breaks whatever connectivity it "
                  "carries, often to a branch or a supplier. Something to "
                  "verify, not to delete on sight.",
        },
    },
}


def guidance_for(check_name: str, lang: str = DEFAULT_LANG
                 ) -> Dict[str, str]:
    """Motivazione, impatto e default di un controllo, nella lingua richiesta.

    Dizionario vuoto se il controllo non ha ancora una voce: la UI nasconde la
    sezione invece di mostrare un riquadro vuoto, e nessuna regola smette di
    funzionare per una guida mancante.
    """
    entry = GUIDANCE.get(check_name)
    if not entry:
        return {}
    code = normalize_lang(lang)
    out: Dict[str, str] = {}
    for field in _FIELDS:
        texts = entry.get(field)
        if not texts:
            continue
        value: Optional[str] = texts.get(code) or texts.get(DEFAULT_LANG)
        if value:
            out[field] = value
    return out
