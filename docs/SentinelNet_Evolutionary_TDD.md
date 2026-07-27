# SentinelNet - Evolutionary Technical Design Document (TDD)

Version: Draft 0.1

## 1. Scopo

Questo documento non descrive un progetto da iniziare, ma l'evoluzione
di SentinelNet, un sistema già in sviluppo.

Il suo obiettivo è preservare la coerenza architetturale mentre il
progetto cresce.

------------------------------------------------------------------------

# 2. Principi architetturali

## 2.1 Separazione delle responsabilità

SentinelNet deve essere composto da livelli indipendenti.

    Data Plane
        │
    Normalization
        │
    Correlation Engine
        │
    Knowledge Base
        │
    Reasoning Engine
        │
    Service Layer
        ├── REST API
        ├── MCP Server
        ├── Dashboard
        └── Future Integrations

Nessuna logica di business deve risiedere nella dashboard.

------------------------------------------------------------------------

## 2.2 Dashboard come client

La dashboard non è il prodotto.

È uno dei client del Service Layer.

Domani lo stesso motore dovrà poter essere interrogato da:

-   Dashboard Web
-   REST API
-   MCP Server
-   CLI
-   Automazioni
-   AI Agent

------------------------------------------------------------------------

# 3. Stato attuale

Il progetto possiede già basi solide:

-   pipeline di ingest asincrona
-   collector NetFlow/IPFIX/sFlow
-   raccolta Syslog
-   correlazione Flow/SIEM
-   modello multi-tenant
-   API
-   integrazione MCP iniziale

L'obiettivo NON è riscrivere questi componenti.

L'obiettivo è costruire livelli di intelligenza sopra di essi.

------------------------------------------------------------------------

# 4. Roadmap evolutiva

## Fase 1 - Data Plane

Stabilizzare:

-   collector
-   parser
-   storage
-   normalizzazione
-   metriche

Contratto:

I dati raccolti devono essere indipendenti dalla modalità di
visualizzazione.

------------------------------------------------------------------------

## Fase 2 - Correlation Engine

Correlare:

-   NetFlow
-   SNMP
-   Syslog
-   Routing
-   Topologia
-   Configurazioni

Output:

Eventi arricchiti.

------------------------------------------------------------------------

## Fase 3 - Knowledge Base

Creare una base di conoscenza dei problemi.

Ogni problema descrive:

-   sintomi
-   indicatori
-   possibili cause
-   livello di confidenza
-   verifiche consigliate

Esempi:

-   congestione
-   loop Layer2
-   broadcast storm
-   routing instability
-   backup fuori finestra
-   failover SD-WAN

------------------------------------------------------------------------

## Fase 4 - Reasoning Engine

Riceve eventi correlati.

Produce:

-   causa probabile
-   motivazione
-   evidenze
-   livello di confidenza

Ogni conclusione deve essere spiegabile.

Mai "black box".

------------------------------------------------------------------------

## Fase 5 - Incident Intelligence

Costruzione automatica della timeline.

Esempio

09:31 Backup

↓

09:32 Congestione

↓

09:33 CPU elevata

↓

09:35 Ticket utenti

↓

Probabile causa: Backup fuori finestra.

------------------------------------------------------------------------

# 5. Service Layer

Espone funzioni di dominio.

Esempi:

-   findRootCause()
-   tracePath()
-   analyzeBroadcastStorm()
-   explainInterface()
-   summarizeIncident()
-   compareBaseline()

Il Service Layer è l'unico punto di accesso alla logica.

------------------------------------------------------------------------

# 6. REST e MCP

REST e MCP devono condividere gli stessi servizi.

Non devono implementare logica diversa.

REST è pensato per:

-   frontend
-   integrazioni software

MCP è pensato per:

-   AI Agent
-   Copilot
-   ChatGPT
-   automazioni intelligenti

------------------------------------------------------------------------

# 7. Regole architetturali

-   Nessuna logica nella UI.
-   Nessuna duplicazione fra REST e MCP.
-   Tutte le conclusioni devono essere spiegabili.
-   Nessun dato sintetico presentato come reale.
-   Ogni correlazione deve essere verificabile.
-   Le fonti restano indipendenti.

------------------------------------------------------------------------

# 8. Visione

SentinelNet non deve essere ricordato come una dashboard NetFlow.

L'obiettivo è diventare una piattaforma di Network Observability con
capacità di Incident Intelligence.

Il valore non sarà mostrare più grafici.

Il valore sarà trasformare telemetria grezza in spiegazioni operative.

La dashboard rappresenta semplicemente una delle modalità con cui un
operatore, uno script o un agente AI possono interrogare il motore di
osservabilità.
