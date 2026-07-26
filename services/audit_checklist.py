# -*- coding: utf-8 -*-
"""Servizio gestione Audit Checklist Manutenzione Firewall.

Gestisce:
- Seeding e versionamento dei template di audit (audit_templates, audit_template_items)
- Ciclo di vita degli audit engagement per cliente (audit_engagements)
- Valutazione singoli item con storia modifiche (audit_engagement_items, audit_engagement_history)
- Allegati ed evidenze (audit_evidence)
- Generazione relazione finale HTML con blocco di avvertimento prerequisiti
- Integrazione AI assist per suggerimento valutazioni
"""

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from core import db

logger = logging.getLogger("sentinelnet.audit_checklist")

# Item con prerequisiti vincolanti per la relazione finale
PREREQUISITE_REFS = {"1.3", "1.6", "1.7"}

# Vocabolario stati e gravita'
VALID_STATUSES = {
    "non_valutato",
    "conforme",
    "parziale",
    "non_conforme",
    "non_applicabile",
    "da_verificare",
}

VALID_SEVERITIES = {
    "critica",
    "alta",
    "media",
    "bassa",
    "osservazione",
}

DEFAULT_CHECKLIST_ITEMS = [
    # Sezione 1
    {
        "ref": "1.1",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Procurarsi e leggere i report relativi ai precedenti audit",
        "guidance_why": "Fornisce il quadro storico di vulnerabilità ed evoluzioni della rete cliente.",
        "guidance_good": "Report precedenti archiviati e analizzati prima dell'intervento.",
        "guidance_how": "Richiedere al cliente i report degli audit passati.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "osservazione",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 10,
    },
    {
        "ref": "1.2",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Procurarsi le copie delle procedure di sicurezza aziendali relative alla rete",
        "guidance_why": "La configurazione deve rispecchiare le policy formali del cliente.",
        "guidance_good": "Procedure di sicurezza documentate e aggiornate disponibili.",
        "guidance_how": "Verificare con il responsabile IT o Security Manager.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "bassa",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 20,
    },
    {
        "ref": "1.3",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Procurarsi lo schema logico di rete e le connessioni fisiche del firewall",
        "guidance_why": "Prerequisito fondamentale per l'audit; senza di esso la valutazione è parziale.",
        "guidance_good": "Schema di rete logico e fisico completo, aggiornato e coerente.",
        "guidance_how": "Ottenere diagrammi di rete o disegni tecnici del perimetro.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "alta",
        "is_prerequisite": 1,
        "requires_evidence": 1,
        "sort_order": 30,
    },
    {
        "ref": "1.4",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Identificare le connettività agli ISP e le VPN configurate sul firewall",
        "guidance_why": "Evita di interrompere servizi critici e garantisce mappatura completa delle rotte/tunnel.",
        "guidance_good": "Lista completa di linee WAN, backup e tunnel VPN attivi.",
        "guidance_how": "Controllare configurazione interfacce e rotte statiche/BGP/OSPF.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 40,
    },
    {
        "ref": "1.5",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Ottenere informazioni hardware/firmware, contratti e date End-Of-Life",
        "guidance_why": "Apparati EOL o senza supporto espongono la rete a vulnerabilità unpatched.",
        "guidance_good": "Versione firmware supportata, contratto di manutenzione attivo e hardware non EOL.",
        "guidance_how": "Verificare lo stato della licenza e versione OS su portale vendor.",
        "thresholds_json": json.dumps({"firmware_status": "supported", "eol_reached": False}),
        "check_kind": "semi",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 50,
    },
    {
        "ref": "1.6",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Verificare l'accesso ai LOG (Syslog / FortiAnalyzer / Cloud)",
        "guidance_why": "Senza log centralizzati e consultabili non è possibile tracciare incidenti o auditare accessi.",
        "guidance_good": "Log inviati a server sicuro con retention adeguata e accessibili.",
        "guidance_how": "Verificare la presenza di invio Syslog o FortiAnalyzer funzionante.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "alta",
        "is_prerequisite": 1,
        "requires_evidence": 1,
        "sort_order": 60,
    },
    {
        "ref": "1.7",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Controllare accesso ai backup di configurazione, frequenza e consistenza",
        "guidance_why": "Prerequisito critico per garantire il ripristino in caso di guasto o disastro.",
        "guidance_good": "Backup automatici periodici cifrati su storage esterno verificati.",
        "guidance_how": "Verificare data e dimensione dell'ultimo backup disponibile.",
        "thresholds_json": json.dumps({"max_backup_age_days": 7}),
        "check_kind": "manual",
        "severity_default": "critica",
        "is_prerequisite": 1,
        "requires_evidence": 1,
        "sort_order": 70,
    },
    {
        "ref": "1.8",
        "section_no": 1,
        "section_title": "Pre-Audit raccolta informazioni",
        "title": "Verificare data ed esito dell'ultimo test di Disaster Recovery / Business Continuity",
        "guidance_why": "Il test reale richiede il cutover degli apparati principali.",
        "guidance_good": "Test di DR eseguito negli ultimi 12 mesi con esito positivo documentato.",
        "guidance_how": "Intervistare il referente IT e richiedere il verbale di test DR.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 80,
    },
    # Sezione 2
    {
        "ref": "2.1",
        "section_no": 2,
        "section_title": "Sicurezza fisica e ambiente operativo",
        "title": "Adeguatezza e sicurezza dei locali che ospitano i firewall",
        "guidance_why": "Condizioni ambientali avverse causano guasti hardware prematuri.",
        "guidance_good": "Locale CED dedicato, condizionato (18-25°C), controllo accessi e antincendio.",
        "guidance_how": "Ispezione visiva o intervista in loco.",
        "thresholds_json": json.dumps({"temp_min_c": 18, "temp_max_c": 25}),
        "check_kind": "manual",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 90,
    },
    {
        "ref": "2.2",
        "section_no": 2,
        "section_title": "Sicurezza fisica e ambiente operativo",
        "title": "Procedura di restringimento accesso ai locali fisici al solo personale autorizzato",
        "guidance_why": "Accessi fisici incontrollati permettono manomissioni o furto di apparati.",
        "guidance_good": "Registro accessi o badge nominali attivi 24/7.",
        "guidance_how": "Verificare modalità di accesso alla sala server.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 100,
    },
    {
        "ref": "2.3",
        "section_no": 2,
        "section_title": "Sicurezza fisica e ambiente operativo",
        "title": "Adeguatezza cablaggio hardware e architettura ad alta affidabilità (HA)",
        "guidance_why": "Grovigli di cavi sui moduli o mancanza di HA allungano i tempi di ripristino.",
        "guidance_good": "Apparati in HA cluster, cavi Cat6 etichettati e passati ordinatamente.",
        "guidance_how": "Verificare stato del cluster e cablaggio rack.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 110,
    },
    {
        "ref": "2.4",
        "section_no": 2,
        "section_title": "Sicurezza fisica e ambiente operativo",
        "title": "Adeguatezza alimentazione elettrica e continuità (UPS)",
        "guidance_why": "Sbalzi o blackout senza UPS ridondato provocano corruzione dati o spegnimenti improvvisi.",
        "guidance_good": "Doppio alimentatore collegato a due linee UPS distinte e monitorate.",
        "guidance_how": "Ispezionare le prese di alimentazione degli apparati.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 120,
    },
    {
        "ref": "2.5",
        "section_no": 2,
        "section_title": "Sicurezza fisica e ambiente operativo",
        "title": "Hardening del sistema operativo dell'apparato di sicurezza",
        "guidance_why": "Servizi di gestione superflui attivi aumentano la superficie d'attacco.",
        "guidance_good": "Servizi inutilizzati disabilitati (es. Telnet, HTTP, USB auto-install).",
        "guidance_how": "Verificare le opzioni di gestione e porte aperte sul firewall.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 130,
    },
    # Sezione 3
    {
        "ref": "3.1",
        "section_no": 3,
        "section_title": "Accessi amministrativi e log",
        "title": "Identificare utenti amministratori e reti sorgente permesse (Trusthosts)",
        "guidance_why": "L'accesso amministrativo aperto a qualsiasi IP espone a tentativi di brute force.",
        "guidance_good": "Utenti nominali con trusthost limitati a subnet di gestione sicure.",
        "guidance_how": "Esaminare `config system admin` e i relativi trusthost.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "critica",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 140,
    },
    {
        "ref": "3.2",
        "section_no": 3,
        "section_title": "Accessi amministrativi e log",
        "title": "Revisione profili di accesso e privilegi degli amministratori",
        "guidance_why": "Applicare il principio del minimo privilegio agli utenti gestionali.",
        "guidance_good": "Profili personalizzati con permessi di sola lettura dove opportuno.",
        "guidance_how": "Analizzare `config system accprofile` e le associazioni agli utenti.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 150,
    },
    {
        "ref": "3.3",
        "section_no": 3,
        "section_title": "Accessi amministrativi e log",
        "title": "Rimuovere utenti generici o limitarli ad uso Disaster Recovery con password in cassaforte",
        "guidance_why": "Account generici condivisi impediscono l'imputabilità delle modifiche.",
        "guidance_good": "Account 'admin' di default disabilitato o protetto in cassaforte credenziali.",
        "guidance_how": "Controllare la presenza dell'utente admin di default attivo.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 160,
    },
    {
        "ref": "3.4",
        "section_no": 3,
        "section_title": "Accessi amministrativi e log",
        "title": "Identificare chi può consultare i log di navigazione oltre la retention di 7 giorni",
        "guidance_why": "Normativa privacy e Statuto dei Lavoratori richiedono protezione da controllo a distanza.",
        "guidance_good": "Accesso ai log di navigazione tracciato, cifrato e limitato al DPO / soggetti autorizzati.",
        "guidance_how": "Intervistare la direzione IT sui ruoli abilitati alla visione dei log web.",
        "thresholds_json": json.dumps({"max_unrestricted_days": 7}),
        "check_kind": "manual",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 170,
    },
    {
        "ref": "3.5",
        "section_no": 3,
        "section_title": "Accessi amministrativi e log",
        "title": "Verificare che l'archivio dei log sia cifrato e protetto in transito e a riposo",
        "guidance_why": "Log in chiaro inviati in rete possono essere intercettati o alterati.",
        "guidance_good": "Inoltro log via TLS/HTTPS cifrato verso FortiAnalyzer o Syslog-ng.",
        "guidance_how": "Verificare la cifratura dell'inoltro log nella configurazione.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 180,
    },
    # Sezione 4
    {
        "ref": "4.1",
        "section_no": 4,
        "section_title": "Processi di gestione firewall",
        "title": "Esistenza di una catena di autorizzazione formale per le modifiche di configurazione",
        "guidance_why": "Modifiche estemporanee prive di Change Approval provocano buchi di sicurezza e disservizi.",
        "guidance_good": "Procedura di Change Management con approvazione scritta prima di ogni modifica.",
        "guidance_how": "Richiedere la procedura aziendale di Change Management.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 190,
    },
    {
        "ref": "4.2",
        "section_no": 4,
        "section_title": "Processi di gestione firewall",
        "title": "Verifica a campione sull'approvazione formale delle ultime modifiche effettuate",
        "guidance_why": "Accerta che la procedura di change sia effettivamente applicata nella pratica.",
        "guidance_good": "Tutte le ultime 5 modifiche a campione corrispondono a ticket approvati.",
        "guidance_how": "Confrontare il log delle modifiche sul firewall con il sistema di ticketing.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "bassa",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 200,
    },
    {
        "ref": "4.3",
        "section_no": 4,
        "section_title": "Processi di gestione firewall",
        "title": "Verifica della tracciabilità delle utenze amministrative e dei ruoli operativi",
        "guidance_why": "Ogni operatore deve accedere con la propria utenza nominale.",
        "guidance_good": "Nessun account generico o condiviso tra tecnici o fornitori terzi.",
        "guidance_how": "Verificare l'elenco utenti e i ruoli sul firewall.",
        "thresholds_json": None,
        "check_kind": "manual",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 210,
    },
    # Sezione 5
    {
        "ref": "5.1",
        "section_no": 5,
        "section_title": "Sistema operativo firewall",
        "title": "Verifica data/ora di sistema e sincronizzazione con server NTP affidabile",
        "guidance_why": "Ora non sincronizzata rende i log inutilizzabili per la correlazione di eventi ed indagini.",
        "guidance_good": "Data/ora corretta sincronizzata con almento 2 server NTP di fiducia.",
        "guidance_how": "Verificare la configurazione `config system ntp` e lo stato di sincronizzazione.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 220,
    },
    {
        "ref": "5.2",
        "section_no": 5,
        "section_title": "Sistema operativo firewall",
        "title": "Verifica aggiornamento firmware e patch di sicurezza applicate",
        "guidance_why": "Firmware non aggiornati contengono vulnerabilità note pubblicamente e facilmente sfruttabili.",
        "guidance_good": "Versione firmware allineata alla patch release raccomandata dal produttore.",
        "guidance_how": "Verificare versione OS corrente e confrontare con matrice firmware vendor.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "critica",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 230,
    },
    {
        "ref": "5.3",
        "section_no": 5,
        "section_title": "Sistema operativo firewall",
        "title": "Verifica vulnerabilità note e bollettini di sicurezza pubblicati per la versione in uso",
        "guidance_why": "Identifica exploit specifici non ancora mitigati dall'organizzazione.",
        "guidance_good": "Nessuna vulnerabilità critica (CVSS >= 8.0) priva di mitigazione o patch.",
        "guidance_how": "Consultare i PSIRT advisory Fortinet per la versione specifica.",
        "thresholds_json": json.dumps({"cvss_threshold": 8.0}),
        "check_kind": "manual",
        "severity_default": "critica",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 240,
    },
    {
        "ref": "5.4",
        "section_no": 5,
        "section_title": "Sistema operativo firewall",
        "title": "Verifica licenze attive ed effettiva usabilità delle funzionalità gestite",
        "guidance_why": "Licenze scadute disabilitano gli aggiornamenti dei pattern IPS/Antivirus/WebFilter.",
        "guidance_good": "Tutte le licenze UTM/FortiGuard attive con scadenza superiore a 30 giorni.",
        "guidance_how": "Verificare lo stato delle licenze nella dashboard o via CLI.",
        "thresholds_json": json.dumps({"min_days_remaining": 30}),
        "check_kind": "semi",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 250,
    },
    {
        "ref": "5.5",
        "section_no": 5,
        "section_title": "Sistema operativo firewall",
        "title": "Verifica utilizzo CPU, RAM ed interfacce di rete nelle ore di picco",
        "guidance_why": "Saturazione di risorse causa drop di pacchetti, latenza o reboot d'emergenza.",
        "guidance_good": "RAM < 70% e CPU < 55% nelle ore lavorative per garantire margine operativo.",
        "guidance_how": "Verificare i grafici di prestazione o il comando `get system performance status`.",
        "thresholds_json": json.dumps({"ram_max_pct": 70, "cpu_max_pct": 55}),
        "check_kind": "semi",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 260,
    },
    {
        "ref": "5.6",
        "section_no": 5,
        "section_title": "Sistema operativo firewall",
        "title": "Analisi log di sistema per identificare anomalie o malfunzionamenti hardware/software",
        "guidance_why": "Evidenzia guasti imminenti (es. flappato di link, errori di memoria o dischi).",
        "guidance_good": "Assenza di messaggi d'errore critici o warning ricorrenti negli ultimi 7 giorni.",
        "guidance_how": "Consultare il log eventi di sistema del firewall.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 270,
    },
    # Sezione 6
    {
        "ref": "6.1",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Valutare la collocazione dell'apparato nella topologia e la segmentazione di rete",
        "guidance_why": "Verificare che la rete sia suddivisa in zone di sicurezza omogenee (LAN, DMZ, IoT, Guest).",
        "guidance_good": "Segmentazione efficace con regole di isolamento tra le zone.",
        "guidance_how": "Analizzare interfacce, VLAN e policy di routing.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 280,
    },
    {
        "ref": "6.2",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Verificare punto unico d'ingresso/uscita per isolare la rete da internet",
        "guidance_why": "Connessioni sconosciute o punti d'uscita bypassano i controlli di sicurezza perimetrici.",
        "guidance_good": "Tutto il traffico verso internet passa dal firewall unico o dal cluster in HA.",
        "guidance_how": "Verificare le rotte di default e le interfacce attestate su WAN.",
        "thresholds_json": None,
        "check_kind": "semi",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 290,
    },
    {
        "ref": "6.3",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Revisione policy con oggetti troppo generici (ANY) in sorgente o destinazione",
        "guidance_why": "Regole permissive consentono movimento laterale e traffico indesiderato.",
        "guidance_good": "Tutte le policy definiscono indirizzi e porte specifici (eccezione egress internet).",
        "guidance_how": "Ricercare policy con `srcaddr all` o `dstaddr all` oltre al traffico outbound web.",
        "thresholds_json": None,
        "check_kind": "auto",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 300,
    },
    {
        "ref": "6.4",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Servizi esposti pubblicamente utilizzano protocolli cifrati",
        "guidance_why": "Servizi in chiaro (HTTP, FTP, Telnet) su internet permettono l'intercettazione delle credenziali.",
        "guidance_good": "Solo protocolli cifrati (HTTPS, SSH, IPsec/SSL VPN) esposti su IP pubblici.",
        "guidance_how": "Controllare VIP e policy inbound con destinazione server interni.",
        "thresholds_json": None,
        "check_kind": "auto",
        "severity_default": "critica",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 310,
    },
    {
        "ref": "6.5",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Rimozione o disabilitazione di policy, oggetti e tunnel VPN inutilizzati",
        "guidance_why": "Riduce l'ingombro della configurazione ed evita riattivazioni accidentali di falle sfortunate.",
        "guidance_good": "Nessuna policy con hit-count 0 negli ultimi 90 giorni.",
        "guidance_how": "Verificare gli oggetti inutilizzati e l'hit-count delle regole.",
        "thresholds_json": json.dumps({"max_unused_days": 90}),
        "check_kind": "auto",
        "severity_default": "bassa",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 320,
    },
    {
        "ref": "6.7",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Policy verso internet bloccano categorie pericolose, botnet e contenuto rischioso",
        "guidance_why": "Protegge gli endpoint aziendali da malware, phishing e C2 botnet.",
        "guidance_good": "WebFilter e Application Control attivi su tutte le policy LAN->WAN con botnet block abilitato.",
        "guidance_how": "Controllare la configurazione dei profili UTM applicati al traffico outbound.",
        "thresholds_json": None,
        "check_kind": "auto",
        "severity_default": "alta",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 330,
    },
    {
        "ref": "6.9",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Policy che espongono server verso l'esterno hanno profilo IPS configurato correttamente",
        "guidance_why": "Server pubblici sono costantemente sotto attacco exploit automatizzati.",
        "guidance_good": "Profilo IPS attivo con blocco automatico e quarantena IP >= 60 giorni su firme critiche.",
        "guidance_how": "Esaminare il profilo IPS associato ai Virtual IP.",
        "thresholds_json": json.dumps({"quarantine_days_min": 60}),
        "check_kind": "auto",
        "severity_default": "critica",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 340,
    },
    {
        "ref": "6.11",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Solo server autorizzati possono effettuare chiamate DNS ed NTP esterne",
        "guidance_why": "Previene il tunneling DNS, l'esfiltrazione dati ed il malware che usa server DNS arbitrari.",
        "guidance_good": "Policy outbound DNS/NTP limitate ai soli resolver/NTP aziendali ufficiali.",
        "guidance_how": "Verificare le regole di uscite verso le porte 53/UDP e 123/UDP.",
        "thresholds_json": None,
        "check_kind": "auto",
        "severity_default": "media",
        "is_prerequisite": 0,
        "requires_evidence": 0,
        "sort_order": 350,
    },
    {
        "ref": "6.15",
        "section_no": 6,
        "section_title": "Configurazione base e policy di sicurezza",
        "title": "Accesso VPN Client (SSL/IPsec) protetto da autenticazione forte / 2FA",
        "guidance_why": "Le sole credenziali statiche compromesse sono la causa primaria di intrusioni via VPN.",
        "guidance_good": "Autenticazione a Due Fattori (2FA / OTP / SAML MFA) obbligatoria per tutti gli utenti VPN.",
        "guidance_how": "Verificare `config vpn ssl settings` e l'impostazione two-factor sui gruppi utenti.",
        "thresholds_json": None,
        "check_kind": "auto",
        "severity_default": "critica",
        "is_prerequisite": 0,
        "requires_evidence": 1,
        "sort_order": 360,
    },
]


def seed_default_template() -> int:
    """Verifica e crea il template v1 di default se non esiste. Ritorna template_id."""
    conn = db.get_observability_connection()
    try:
        row = conn.execute(
            "SELECT id FROM audit_templates WHERE version = 1"
        ).fetchone()
        if row:
            return int(row["id"])

        now = int(time.time())
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO audit_templates (version, name, status, created_ts, created_by, notes)
               VALUES (1, 'Checklist Audit Manutenzione Firewall v1.0', 'published', ?, 'system',
                       'Template standard derivato da checklist_x_c.docx con note e soglie guida')""",
            (now,),
        )
        template_id = cursor.lastrowid
        if template_id is None:
            raise RuntimeError("Impossibile inserire il template audit v1")
        for item in DEFAULT_CHECKLIST_ITEMS:
            cursor.execute(
                """INSERT INTO audit_template_items
                   (template_id, ref, section_no, section_title, title, guidance_why, guidance_good,
                    guidance_how, thresholds_json, check_kind, severity_default, is_prerequisite,
                    requires_evidence, sort_order)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    template_id,
                    item["ref"],
                    item["section_no"],
                    item["section_title"],
                    item["title"],
                    item["guidance_why"],
                    item["guidance_good"],
                    item["guidance_how"],
                    item["thresholds_json"],
                    item["check_kind"],
                    item["severity_default"],
                    item["is_prerequisite"],
                    item["requires_evidence"],
                    item["sort_order"],
                ),
            )
        conn.commit()
        logger.info("Seeded default audit template v1 with %d items", len(DEFAULT_CHECKLIST_ITEMS))
        return template_id
    finally:
        conn.close()


# --- CRUD TEMPLATES ---------------------------------------------------------

def list_templates() -> List[Dict[str, Any]]:
    """Ritorna la lista dei template di audit."""
    conn = db.get_observability_connection()
    try:
        rows = conn.execute(
            """SELECT t.id, t.version, t.name, t.status, t.created_ts, t.created_by, t.notes,
                      COUNT(i.id) AS item_count
               FROM audit_templates t
               LEFT JOIN audit_template_items i ON i.template_id = t.id
               GROUP BY t.id
               ORDER BY t.version DESC"""
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_template(template_id: int) -> Optional[Dict[str, Any]]:
    """Ritorna i dettagli di un template e i relativi item."""
    conn = db.get_observability_connection()
    try:
        row = conn.execute(
            "SELECT * FROM audit_templates WHERE id = ?", (template_id,)
        ).fetchone()
        if not row:
            return None
        tpl = dict(row)
        items = conn.execute(
            """SELECT * FROM audit_template_items
               WHERE template_id = ?
               ORDER BY section_no ASC, sort_order ASC, ref ASC""",
            (template_id,),
        ).fetchall()
        tpl["items"] = [dict(i) for i in items]
        return tpl
    finally:
        conn.close()


# --- CRUD ENGAGEMENTS -------------------------------------------------------

def create_engagement(
    customer_name: str,
    tenant: Optional[str] = None,
    site_id: Optional[str] = None,
    template_id: Optional[int] = None,
    assigned_to: Optional[str] = None,
    scope_notes: Optional[str] = None,
    onsite_or_remote: str = "remote",
    interviewee: Optional[str] = None,
    created_by: str = "system",
) -> Dict[str, Any]:
    """Crea un nuovo engagement di audit bloccando il template_id specificato (o il v1 di default)."""
    if not template_id:
        template_id = seed_default_template()

    tpl = get_template(template_id)
    if not tpl:
        raise ValueError(f"Template audit {template_id} non trovato")

    now = int(time.time())
    conn = db.get_observability_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO audit_engagements
               (customer_name, tenant, site_id, template_id, status, created_ts, updated_ts,
                created_by, assigned_to, scope_notes, onsite_or_remote, interviewee)
               VALUES (?, ?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?, ?)""",
            (
                customer_name,
                tenant,
                site_id,
                template_id,
                now,
                now,
                created_by,
                assigned_to,
                scope_notes,
                onsite_or_remote,
                interviewee,
            ),
        )
        eng_id = cursor.lastrowid

        # Inizializza gli engagement_items dal template
        for item in tpl["items"]:
            cursor.execute(
                """INSERT INTO audit_engagement_items
                   (engagement_id, item_ref, status, severity, finding_text, recommendation_text, assessed_by, assessed_ts, ai_assisted)
                   VALUES (?, ?, 'non_valutato', ?, NULL, NULL, NULL, NULL, 0)""",
                (eng_id, item["ref"], item["severity_default"]),
            )

        # Log storico
        cursor.execute(
            """INSERT INTO audit_engagement_history (engagement_id, item_ref, action, details_json, actor, ts)
               VALUES (?, NULL, 'created', ?, ?, ?)""",
            (
                eng_id,
                json.dumps({"customer_name": customer_name, "template_version": tpl["version"]}),
                created_by,
                now,
            ),
        )
        conn.commit()
        return get_engagement(eng_id)  # type: ignore
    finally:
        conn.close()


def list_engagements(
    status: Optional[str] = None, tenant: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Elenca gli audit engagement con aggregazione dello stato avanzamento."""
    conn = db.get_observability_connection()
    try:
        query = """
            SELECT e.*, t.version AS template_version, t.name AS template_name,
                   COUNT(i.id) AS total_items,
                   SUM(CASE WHEN i.status != 'non_valutato' THEN 1 ELSE 0 END) AS evaluated_items,
                   SUM(CASE WHEN i.status = 'conforme' THEN 1 ELSE 0 END) AS conforme_count,
                   SUM(CASE WHEN i.status = 'non_conforme' THEN 1 ELSE 0 END) AS non_conforme_count,
                   SUM(CASE WHEN i.status = 'da_verificare' THEN 1 ELSE 0 END) AS da_verificare_count
            FROM audit_engagements e
            JOIN audit_templates t ON t.id = e.template_id
            LEFT JOIN audit_engagement_items i ON i.engagement_id = e.id
        """
        where = []
        params = []
        if status:
            where.append("e.status = ?")
            params.append(status)
        if tenant:
            where.append("e.tenant = ?")
            params.append(tenant)

        if where:
            query += " WHERE " + " AND ".join(where)

        query += " GROUP BY e.id ORDER BY e.updated_ts DESC"

        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_engagement(engagement_id: int) -> Optional[Dict[str, Any]]:
    """Ritorna l'engagement completo con tutti gli item e il relativo template."""
    conn = db.get_observability_connection()
    try:
        row = conn.execute(
            """SELECT e.*, t.version AS template_version, t.name AS template_name
               FROM audit_engagements e
               JOIN audit_templates t ON t.id = e.template_id
               WHERE e.id = ?""",
            (engagement_id,),
        ).fetchone()
        if not row:
            return None
        eng = dict(row)

        items = conn.execute(
            """SELECT i.*, ti.section_no, ti.section_title, ti.title, ti.guidance_why,
                      ti.guidance_good, ti.guidance_how, ti.thresholds_json, ti.check_kind,
                      ti.is_prerequisite, ti.requires_evidence, ti.sort_order
               FROM audit_engagement_items i
               JOIN audit_template_items ti ON ti.template_id = ? AND ti.ref = i.item_ref
               WHERE i.engagement_id = ?
               ORDER BY ti.section_no ASC, ti.sort_order ASC, ti.ref ASC""",
            (eng["template_id"], engagement_id),
        ).fetchall()
        eng["items"] = [dict(i) for i in items]

        evidences = conn.execute(
            "SELECT * FROM audit_evidence WHERE engagement_id = ? ORDER BY uploaded_ts DESC",
            (engagement_id,),
        ).fetchall()
        eng["evidence"] = [dict(ev) for ev in evidences]

        return eng
    finally:
        conn.close()


def update_engagement_metadata(
    engagement_id: int,
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    scope_notes: Optional[str] = None,
    onsite_or_remote: Optional[str] = None,
    interviewee: Optional[str] = None,
    actor: str = "system",
) -> Dict[str, Any]:
    """Aggiorna le informazioni di intestazione/stato dell'engagement."""
    conn = db.get_observability_connection()
    try:
        eng = conn.execute(
            "SELECT * FROM audit_engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        if not eng:
            raise ValueError(f"Engagement {engagement_id} non trovato")

        updates = []
        params: List[Any] = []

        if status and status in {"draft", "in_progress", "completed"}:
            updates.append("status = ?")
            params.append(status)
        if assigned_to is not None:
            updates.append("assigned_to = ?")
            params.append(assigned_to)
        if scope_notes is not None:
            updates.append("scope_notes = ?")
            params.append(scope_notes)
        if onsite_or_remote is not None:
            updates.append("onsite_or_remote = ?")
            params.append(onsite_or_remote)
        if interviewee is not None:
            updates.append("interviewee = ?")
            params.append(interviewee)

        if updates:
            now = int(time.time())
            updates.append("updated_ts = ?")
            params.append(now)
            params.append(engagement_id)

            sql = f"UPDATE audit_engagements SET {', '.join(updates)} WHERE id = ?"
            conn.execute(sql, tuple(params))
            conn.execute(
                """INSERT INTO audit_engagement_history (engagement_id, item_ref, action, details_json, actor, ts)
                   VALUES (?, NULL, 'metadata_update', ?, ?, ?)""",
                (engagement_id, json.dumps({"updates": updates}), actor, now),
            )
            conn.commit()

        return get_engagement(engagement_id)  # type: ignore
    finally:
        conn.close()


def update_item_assessment(
    engagement_id: int,
    item_ref: str,
    status: str,
    severity: Optional[str] = None,
    finding_text: Optional[str] = None,
    recommendation_text: Optional[str] = None,
    actor: str = "system",
    ai_assisted: bool = False,
) -> Dict[str, Any]:
    """Aggiorna la valutazione di un singolo rigo di audit."""
    if status not in VALID_STATUSES:
        raise ValueError(f"Stato non valido: {status}")
    if severity and severity not in VALID_SEVERITIES:
        raise ValueError(f"Gravita non valida: {severity}")

    conn = db.get_observability_connection()
    try:
        row = conn.execute(
            "SELECT * FROM audit_engagement_items WHERE engagement_id = ? AND item_ref = ?",
            (engagement_id, item_ref),
        ).fetchone()
        if not row:
            raise ValueError(f"Item {item_ref} non trovato nell'engagement {engagement_id}")

        now = int(time.time())
        conn.execute(
            """UPDATE audit_engagement_items
               SET status = ?, severity = ?, finding_text = ?, recommendation_text = ?,
                   assessed_by = ?, assessed_ts = ?, ai_assisted = ?
               WHERE engagement_id = ? AND item_ref = ?""",
            (
                status,
                severity or row["severity"],
                finding_text,
                recommendation_text,
                actor,
                now,
                1 if ai_assisted else 0,
                engagement_id,
                item_ref,
            ),
        )

        # Aggiorna updated_ts dell'engagement e imposta status 'in_progress' se era 'draft'
        conn.execute(
            """UPDATE audit_engagements
               SET updated_ts = ?,
                   status = CASE WHEN status = 'draft' THEN 'in_progress' ELSE status END
               WHERE id = ?""",
            (now, engagement_id),
        )

        # Registra cronologia
        history_details = {
            "old_status": row["status"],
            "new_status": status,
            "severity": severity or row["severity"],
            "has_finding": bool(finding_text),
        }
        conn.execute(
            """INSERT INTO audit_engagement_history (engagement_id, item_ref, action, details_json, actor, ts)
               VALUES (?, ?, 'item_assess', ?, ?, ?)""",
            (engagement_id, item_ref, json.dumps(history_details), actor, now),
        )
        conn.commit()
        return get_engagement(engagement_id)  # type: ignore
    finally:
        conn.close()


# --- EVIDENZE ED ALLEGATI ---------------------------------------------------

def add_evidence(
    engagement_id: int,
    item_ref: str,
    kind: str,
    filename: Optional[str] = None,
    path: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    confidential: bool = True,
) -> Dict[str, Any]:
    """Aggiunge una nuova evidenza ad un item di audit."""
    if kind not in {"file", "config_ref", "note", "scan_finding"}:
        raise ValueError(f"Tipo evidenza non valido: {kind}")

    now = int(time.time())
    payload_json = json.dumps(payload) if payload else None

    conn = db.get_observability_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO audit_evidence
               (engagement_id, item_ref, kind, payload_json, filename, path, uploaded_ts, confidential)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                engagement_id,
                item_ref,
                kind,
                payload_json,
                filename,
                path,
                now,
                1 if confidential else 0,
            ),
        )
        ev_id = cursor.lastrowid
        conn.commit()
        return {"id": ev_id, "engagement_id": engagement_id, "item_ref": item_ref, "kind": kind}
    finally:
        conn.close()


# --- GENERAZIONE RELAZIONE HTML ---------------------------------------------

def generate_audit_relazione(engagement_id: int) -> str:
    """Genera la relazione HTML completa per l'audit specificato."""
    eng = get_engagement(engagement_id)
    if not eng:
        raise ValueError(f"Engagement {engagement_id} non trovato")

    # Controlla se i prerequisiti (1.3, 1.6, 1.7) sono non conformi o da verificare
    unmet_prerequisites = []
    for item in eng["items"]:
        if item["item_ref"] in PREREQUISITE_REFS:
            if item["status"] in {"non_conforme", "da_verificare"}:
                unmet_prerequisites.append(item)

    # Conteggi per sintesi esecutiva
    status_counts: Dict[str, int] = {}
    severity_counts: Dict[str, int] = {}
    for item in eng["items"]:
        st = item["status"]
        status_counts[st] = status_counts.get(st, 0) + 1
        if st in {"non_conforme", "parziale"}:
            sev = item["severity"] or "media"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Costruzione HTML
    prereq_html = ""
    if unmet_prerequisites:
        prereq_items_list = "".join(
            f"<li><strong>Item {p['item_ref']} — {p['title']}</strong>: Stato <em>{p['status'].upper()}</em></li>"
            for p in unmet_prerequisites
        )
        prereq_html = f"""
        <div style="background-color: #fff3cd; border: 2px solid #ffeeba; border-left: 6px solid #ffc107; color: #856404; padding: 15px; margin-bottom: 25px; border-radius: 4px;">
            <h3 style="margin-top:0; color:#856404;">⚠️ AVVERTIMENTO PREREQUISITI NON SODDISFATTI</h3>
            <p>I seguenti prerequisiti fondamentali per l'audit non sono stati soddisfatti o risultano da verificare:</p>
            <ul>{prereq_items_list}</ul>
            <p><strong>Impatto sulla relazione:</strong> In assenza di tali prerequisiti, il presente audit risponde ad una valutazione <em>parziale e superficiale</em> della sicurezza perimetrale. Le valutazioni contenute devono essere considerate valide con riserva fino al completamento delle verifiche mancanti.</p>
        </div>
        """

    # Tabella sintesi esecutiva
    exec_summary_html = f"""
    <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%; margin-bottom: 25px;">
        <tr style="background-color: #f8f9fa;">
            <th>Stato Valutazione</th>
            <th>Numero Item</th>
            <th>Gravità Anomalie (Non Conformi/Parziali)</th>
            <th>Conteggio</th>
        </tr>
        <tr>
            <td><strong>Conforme</strong></td><td>{status_counts.get('conforme', 0)}</td>
            <td>Critica</td><td><span style="color:red; font-weight:bold;">{severity_counts.get('critica', 0)}</span></td>
        </tr>
        <tr>
            <td><strong>Parziale</strong></td><td>{status_counts.get('parziale', 0)}</td>
            <td>Alta</td><td><span style="color:orange; font-weight:bold;">{severity_counts.get('alta', 0)}</span></td>
        </tr>
        <tr>
            <td><strong>Non Conforme</strong></td><td><span style="color:red; font-weight:bold;">{status_counts.get('non_conforme', 0)}</span></td>
            <td>Media</td><td>{severity_counts.get('media', 0)}</td>
        </tr>
        <tr>
            <td><strong>Da Verificare</strong></td><td><span style="color:blue;">{status_counts.get('da_verificare', 0)}</span></td>
            <td>Bassa / Osservazione</td><td>{severity_counts.get('bassa', 0) + severity_counts.get('osservazione', 0)}</td>
        </tr>
        <tr>
            <td><strong>Non Applicabile / Non Valutato</strong></td><td>{status_counts.get('non_applicabile', 0) + status_counts.get('non_valutato', 0)}</td>
            <td><strong>Totale Item</strong></td><td>{len(eng['items'])}</td>
        </tr>
    </table>
    """

    # Risultati dettaglio per sezione
    current_sec = None
    findings_html = ""
    for item in eng["items"]:
        if item["section_no"] != current_sec:
            current_sec = item["section_no"]
            findings_html += f"<h2 style='color:#0d6efd; border-bottom: 2px solid #0d6efd; padding-bottom:5px; margin-top:30px;'>Sezione {current_sec} — {item['section_title']}</h2>"

        st_color = "#6c757d"
        if item["status"] == "conforme":
            st_color = "#198754"
        elif item["status"] in {"non_conforme", "parziale"}:
            st_color = "#dc3545"
        elif item["status"] == "da_verificare":
            st_color = "#0d6efd"

        finding_txt = item["finding_text"] or "<em>Nessun rilievo segnalato.</em>"
        recom_txt = item["recommendation_text"] or "<em>Nessuna raccomandazione specifica.</em>"

        findings_html += f"""
        <div style="margin-bottom: 20px; padding: 12px; border: 1px solid #dee2e6; border-radius: 5px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h4 style="margin:0;">Item {item['item_ref']}: {item['title']}</h4>
                <span style="background-color:{st_color}; color:white; padding:3px 8px; border-radius:3px; font-weight:bold; font-size:12px;">{item['status'].upper()}</span>
            </div>
            <p style="font-size:13px; color:#6c757d; margin: 5px 0;"><strong>Guida audit:</strong> {item['guidance_why']}</p>
            <p style="margin: 5px 0;"><strong>Rilievo / Riscontro:</strong> {finding_txt}</p>
            <p style="margin: 5px 0;"><strong>Raccomandazione:</strong> {recom_txt}</p>
        </div>
        """

    # Open points / Da verificare
    open_points = [i for i in eng["items"] if i["status"] == "da_verificare"]
    open_points_html = ""
    if open_points:
        items_op = "".join(f"<li><strong>Item {i['item_ref']} - {i['title']}</strong>: {i['finding_text'] or 'In attesa di riscontro dal cliente'}</li>" for i in open_points)
        open_points_html = f"""
        <h2 style="color:#0d6efd; border-bottom: 2px solid #0d6efd; padding-bottom:5px; margin-top:30px;">Punti Aperti da Chiarire con il Cliente</h2>
        <ul>{items_op}</ul>
        """

    html_report = f"""<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <title>Relazione Audit Manutenzione Firewall - {eng['customer_name']}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 40px; }}
        h1 {{ color: #1a252f; border-bottom: 3px solid #1a252f; padding-bottom: 10px; }}
        .meta-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 25px; border: 1px solid #e9ecef; }}
        .footer {{ margin-top: 50px; font-size: 11px; color: #6c757d; text-align: center; border-top: 1px solid #dee2e6; padding-top: 15px; }}
        @media print {{
            body {{ margin: 15mm 15mm; font-size: 11pt; }}
            h1 {{ font-size: 18pt; }}
            .no-print {{ display: none !important; }}
            div {{ page-break-inside: avoid; }}
        }}
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <script>
        async function downloadPdf() {{
            const btn = document.getElementById('btnPdf');
            if (btn) btn.textContent = 'Generazione PDF...';
            const noPrints = document.querySelectorAll('.no-print');
            noPrints.forEach(el => el.style.display = 'none');
            const opt = {{
                margin: [10, 10, 10, 10],
                filename: 'Relazione_Audit_{eng["customer_name"].replace(" ", "_")}.pdf',
                image: {{ type: 'jpeg', quality: 0.98 }},
                html2canvas: {{ scale: 2, useCORS: true, logging: false }},
                jsPDF: {{ unit: 'mm', format: 'a4', orientation: 'portrait' }}
            }};
            try {{
                if (typeof html2pdf !== 'undefined') {{
                    await html2pdf().set(opt).from(document.body).save();
                }} else {{
                    window.print();
                }}
            }} catch (e) {{
                console.error('PDF error:', e);
                window.print();
            }} finally {{
                noPrints.forEach(el => el.style.display = '');
                if (btn) btn.textContent = 'Scarica PDF';
            }}
        }}
        function downloadHtml() {{
            const clone = document.body.cloneNode(true);
            const noPrints = clone.querySelectorAll('.no-print');
            noPrints.forEach(el => el.remove());
            const blob = new Blob(['<!DOCTYPE html><html>' + clone.outerHTML + '</html>'], {{ type: 'text/html;charset=utf-8' }});
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'Relazione_Audit_{eng["customer_name"].replace(" ", "_")}.html';
            a.click();
        }}
    </script>
</head>
<body>
    <div class="no-print" style="margin-bottom: 20px; padding: 12px 16px; background: #1e293b; color: white; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; font-family: system-ui, sans-serif;">
        <span style="font-size: 14px; font-weight: bold;">SentinelNet — Anteprima Relazione Audit</span>
        <div style="display: flex; gap: 10px;">
            <button id="btnPdf" onclick="downloadPdf()" style="padding: 8px 16px; background: #10b981; color: white; border: none; border-radius: 6px; font-size: 13px; font-weight: bold; cursor: pointer;">Scarica PDF</button>
            <button onclick="window.print()" style="padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 6px; font-size: 13px; font-weight: bold; cursor: pointer;">Stampa</button>
            <button onclick="downloadHtml()" style="padding: 8px 16px; background: #64748b; color: white; border: none; border-radius: 6px; font-size: 13px; font-weight: bold; cursor: pointer;">Scarica HTML</button>
        </div>
    </div>
    <h1>Relazione Audit Manutenzione Firewall</h1>
    <div class="meta-box">
        <p><strong>Cliente:</strong> {eng['customer_name']} | <strong>Stato Audit:</strong> {eng['status'].upper()}</p>
        <p><strong>Modalità:</strong> {eng['onsite_or_remote'].upper()} | <strong>Intervistato:</strong> {eng['interviewee'] or 'N/D'}</p>
        <p><strong>Auditor / Ingegnere:</strong> {eng['assigned_to'] or eng['created_by']} | <strong>Template:</strong> v{eng['template_version']} ({eng['template_name']})</p>
        <p><strong>Data Generazione:</strong> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}</p>
    </div>

    {prereq_html}

    <h2>Sintesi Esecutiva</h2>
    {exec_summary_html}

    {findings_html}

    {open_points_html}

    <div class="footer">
        <p><strong>DOCUMENTO CONFIDENZIALE</strong> - Generato da SentinelNet Audit Engine. Destinato esclusivamente al cliente {eng['customer_name']}. Vietata la diffusione non autorizzata.</p>
    </div>
</body>
</html>
"""
    return html_report
