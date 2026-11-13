# Business model: dal canvas al prodotto

Data: 2026-11-13 · Versione di riferimento: 0.65.0

Analisi del Business Model Canvas di SentinelNet (Lean Canvas + BMC) messo a
confronto con quello che il codice fa davvero. L'obiettivo non sono funzioni
nuove: si tratta di chiudere le lacune che il canvas stesso dichiara, partendo
da quello che c'è già.

Segmenti, prezzi e curva del valore restano ipotesi da validare con le
interviste, non dati di mercato.

## 1. Correzioni al canvas (fatte)

- Versione portata a 0.65.0 (prima diceva 0.64.2).
- Report di stato rete per l'auditor: era "in progettazione", la fase A è
  rilasciata nella 0.65.0 (docx con evidenze mappate su NIS2/ISO 27001). Ora
  compare anche tra le "prove" nella tabella per l'investitore.
- Perimetro della proposta di valore: SentinelNet affianca l'NMS del cliente e
  non lo sostituisce. È la conseguenza della rimozione del motore Incidenti
  nella 0.65.0.

## 2. Lacune dichiarate e cosa le chiude

| Blocco del BMC | Lacuna | Base già presente |
|---|---|---|
| Ricavi: canone MSP per tenant | Nessun contatore di tenant e apparati attivi | Multi-tenant con limiti applicati lato server |
| Ricavi: report rivenduto dall'MSP | Report solo su richiesta, con il marchio SentinelNet | `services/status_report/` (fase A); la fase B è già pianificata |
| Metriche chiave | Definite "non misurabili" | `/api/settings/update/check` e le release GitHub: i download si contano senza telemetria |
| Partner: "si integra con Zabbix/PRTG/LibreNMS" | Nessuna integrazione nel codice: oggi è solo una promessa | Eventi e risultati CVE/drift già nel DB |
| Validare: primo backup in meno di un'ora | Nessuno lo misura | `static/js/ui-wizard.js`, `add-devices.js`, `tutorials.js`, log di audit |
| Segmento OT | I bypass tra zone si calcolano solo nella mappa (JS), quindi nel report la segmentazione resta "parziale" | Rilevamento zone IT/OT già presente nella mappa |
| Canali: Docker | Poco visibile | `Dockerfile` e `docker-compose.yml` esistono già |

## 3. Priorità

Le tre funzioni che trasformano le ipotesi di ricavo in un pilota da proporre
agli MSP:

1. **Contatore di tenant e apparati attivi.** Una vista in amministrazione con
   i conteggi per tenant e un export. È la base per qualsiasi canone per tenant
   o per fascia di apparati: senza, il prezzo non si può né calcolare né
   verificare.
2. **Report di stato rete, fase B, con il marchio dell'MSP.** Salvataggio,
   invio programmato e confronto con il report precedente (già pianificati),
   più logo e nome dell'MSP nel docx. Diventa il report periodico che l'MSP
   rivende al cliente finale.
3. **Percorso guidato "primo backup".** Riusa il wizard esistente e scrive nel
   log di audit l'ora di inizio e quella del primo backup riuscito. Rende
   misurabile l'ipotesi "primo backup in meno di un'ora" nei 3 piloti.

Dopo queste tre: bypass tra zone nel report (segmento OT), esportazione verso
gli NMS (per mantenere la promessa "si integra"), Docker in evidenza nel README.

## 4. Fuori dal codice

- **Listino indicativo** per la licenza commerciale e per il canone MSP: senza
  un prezzo l'ipotesi "pagherebbero per tenant" non si può testare.
- **Marchio EUIPO**: compare tre volte come "da fare", costa poco, va fatto
  prima del Demo Day.
- **Socio commerciale**: l'unica cosa indicata in "Cosa manca" che non dipende
  dal prodotto.
