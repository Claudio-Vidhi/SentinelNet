# Traffico — un solo tab, quattro viste

Data: 2026-08-11. Base: `HEAD = e14c0c1`, ramo `Dev`.
Origine: `docs/ui_tab_overlap_analysis.md` §A3 + decisione dell'utente in `docs/Improvements`
("reimaging the structure to be more useful with data provided and more control for user,
less clutter").

> Indirizzi di esempio RFC 5737 (`192.0.2.x`, `198.51.100.x`), come impone
> `CLAUDE.md` §"Protect real data".

## Perché

`#tab-flows` e `#tab-flow-siem` non sono due domini: sono due letture della stessa
pipeline di osservabilità. Oggi la divisione costa clutter e controlli che si
contraddicono.

### Tre finestre temporali nello stesso tab

| Controllo | Dove | Cosa governa |
| :--- | :--- | :--- |
| `#flowsWindow` | pannello filtri di `#tab-flows` | top talker, tabella flussi, syslog |
| `#obsChartWindow` | dentro la card protocolli, `#obsProtocolCard` | solo il grafico protocolli |
| `#flowSiemWindow` | hero di `#tab-flow-siem` | eventi, istogramma, faccette |

Tre selettori, quattro opzioni identiche (`15m/1h/24h/7d`), nessuna sincronia:
l'operatore può leggere un top talker su 15 minuti accanto a un grafico su 24 ore
e credere che raccontino la stessa finestra.

A questi si aggiunge un quarto comportamento **non configurabile**:
`loadAnomalies()` (`static/js/observability.js:806`) chiama
`/api/observability/anomalies?...&window=7d` con la finestra **cablata a 7 giorni**,
ignorando qualunque selettore. Il pannello anomalie non ha mai seguito il tab.

### Due filtri tenant

`#flowsTenantBtn` (dropdown multi-checkbox con `#flowsTenantAll` / `#flowsTenantList`)
in Flussi, `#flowSiemTenant` (select singola) in Flow SIEM. Due modelli di
selezione diversi per la stessa domanda.

### Tre ripartizioni per protocollo

1. `#flowDetailInline` — "Dettaglio Flussi / Ripartizione della telemetria per protocollo".
2. `#obsProtocolCard` — donut / barre / trend su `#obsProtocolCanvas`, con `Dettagli` che apre
   `openObsInspectModal()`.
3. `#fgProtoTableBody` — tabella Protocollo / Porta / Rate nella hero a due colonne.

Tre pannelli, un solo dato.

### Le "anomalie" e gli "incidenti" sono la stessa coda

Questa è la scoperta che cambia il disegno. `GET /api/observability/anomalies`
(`routers/observability.py:340`) legge **la tabella `incidents`**:

```sql
SELECT i.id, i.opened_ts AS created_ts, i.tenant, i.cause_kind AS kind,
       i.title, i.severity, i.status, i.confidence, i.event_count, ...
FROM incidents i
```

Il docstring lo dice: *"Dalla v7 la riga è un INCIDENTE, non più un singolo evento
correlato"*. Il campo `id` restituito **è l'id dell'incidente**. E
`POST /api/observability/anomalies/{event_id}/status`
(`routers/observability.py:385`) è un alias legacy di
`POST /api/incidents/{incident_id}/status` (`routers/incidents.py:321`): stessa
tabella, stessa `_ALLOWED_TRANSITIONS`, stessa concorrenza ottimistica.

Conseguenza: il pannello "Correlated anomalies" di Flussi, la lista `#homeAnomBody`
in Home e il tab `#tab-incidents` **non sono tre granularità diverse — sono tre
rendering della stessa query**. L'utente ha scelto "anomalie come pill di Traffico
+ deep link"; questa scoperta la rende più facile di quanto sembrasse, non meno:
il link anomalia → incidente non va costruito, l'id è già lì.

### Inventario pannelli (stato attuale)

`#tab-flows`: subtab bar, hero titolo, `#flowsObsBanner`, KPI strip `#fgKpiStrip`,
`#flowDetailInline`, `#obsProtocolCard`, hero `#fgTenantSummary` + `#fgProtoTableBody`,
top talker `#fgTalkersTableBody`, pannello filtri + `#flowsTableBody` +
`#flowsSyslogAllSection`, pannello anomalie `#anomTableBody`, drawer laterale
`#flowDetailPanel`. **Undici blocchi impilati in verticale.**

`#tab-flow-siem`: subtab bar, hero con stream badge/tenant/window, istogramma
`#flowSiemHistCanvas`, ricerca `#flowSiemQueryInput`, griglia faccette
`#flowSiemFacets` + registro `#flowSiemTableBody`.

## Decisioni prese con l'utente

- **Aggregate-first.** Il tab apre su una **Panoramica**: KPI, top talker,
  ripartizione protocolli. La ricerca SIEM (query, faccette, istogramma, live tail)
  diventa una vista, non un tab gemello. Motivo: si entra in Traffico per "chi sta
  consumando banda", e la ricerca è il drill-down di quegli stessi eventi.
- **Le anomalie restano in Traffico**, come vista propria, con deep link verso
  l'incidente. Home rimanda qui invece di tenere la sua lista. `#tab-incidents` resta
  dov'è (vista correlata, con reasoning/timeline/AI).
- **Un solo selettore tenant + una sola finestra per tutto il tab.** La card
  protocolli perde la finestra privata. Nessun selettore globale d'app in questa
  fase: la migrazione a B3 (`docs/ui_tab_overlap_analysis.md`) resta possibile ma
  fuori scope.
- **Fuori scope da `docs/Improvements`**: pulsante Shun IP, iniezione ACL/Flowspec,
  analisi JA3/SNI. Nessuna delle tre entra in questo lavoro.

## Struttura target

Un solo `tab-content`: **si tiene l'id `#tab-flows`** e si elimina
`#tab-flow-siem`. La voce di nav e `switchTab('tab-flows')` restano invariate, così
nessun deep link esistente si rompe.

```
TRAFFICO
┌──────────────────────────────────────────────────────────────┐
│ Tenant [Tutti ▾]  Finestra [1h ▾]  ⟳  ☑auto  ☐no telemetria │  header unico
└──────────────────────────────────────────────────────────────┘
[ Panoramica ]  Flussi   Ricerca   Anomalie                       pill bar
```

Riuso dei pattern che esistono già, niente CSS nuovo: la pill bar è la stessa
`ca-pill` + `fgt-pane` del tab FortiGate (`fgtSwitchView`/`fgtPickView`).
Convenzione id coerente: pill `#trafPill-<vista>`, contenitori `#trafPane-<vista>`.

| Vista | Contenuto | Route |
| :--- | :--- | :--- |
| **Panoramica** (default) | `#flowsObsBanner`, KPI strip, top talker, un solo pannello protocolli (donut/barre/trend + tabella proto/porta/rate), riepilogo tenant | `/api/observability/top`, `/api/observability/protocol-distribution`, `/api/observability/flowgraph` |
| **Flussi** | tabella flussi con chips sorgente, selettore colonne, drawer dettaglio, sezione syslog | `/api/observability/top`, `/api/observability/syslog` |
| **Ricerca** | query libera o `campo:valore`, faccette, istogramma event-rate, live tail, suppress | `/api/flow-siem/events`, `/histogram`, `/facets`, `/alerts/suppress` |
| **Anomalie** | coda incidenti in forma flow-scoped, filtro stato, chip filtro IP, link all'incidente | `/api/observability/anomalies` (+ `/status`) |

## Mappatura elemento per elemento

| Oggi | Domani |
| :--- | :--- |
| `#flowsWindow` | header unico del tab |
| `#obsChartWindow` | **eliminato** — la card segue la finestra del tab |
| `#flowSiemWindow` | **eliminato** — idem |
| `#flowsTenantBtn` + `#flowsTenantDropdown` + `#flowsTenantAll` + `#flowsTenantList` | header unico (si tiene il multi-checkbox: è il più espressivo dei due) |
| `#flowSiemTenant` | **eliminato**, la vista Ricerca legge il tenant dell'header |
| `#flowsAutoRefresh`, `#flowsHideTelemetry`, `#flowsLastUpdate` | header unico, valgono per tutte le viste |
| due `.subtab-bar` (2 copie) | una pill bar (−2 delle 13 copie censite in §B4) |
| `#flowDetailInline` | **eliminato**, assorbito dal pannello protocolli unico |
| `#fgProtoTableBody` | tabella di dettaglio *dentro* il pannello protocolli |
| `#obsProtocolCanvas` + `#btnChartType{Donut,Bar,Trend}` + `openObsInspectModal()` | invariati, dentro Panoramica |
| `#fgKpiStrip`, `#fgTalkersTableBody`, `#fgTenantSummary` | invariati, Panoramica |
| `#flowsTableHead/Body`, `#flowsSourceChips`, `#flowsColsBtn/Dropdown`, `#flowsSyslogAll*`, `#flowDetailPanel` | invariati, vista Flussi |
| `#flowSiemQueryInput`, `#flowSiemFacets`, `#flowSiemHistCanvas`, `#flowSiemTableBody`, `#btnFlowSiemStream`, `#flowSiemStreamBadge` | invariati, vista Ricerca |
| `#anomStatus`, `#anomTableBody`, `#anomIpFilterChip`, `#anomSectionTitle` | invariati, vista Anomalie |
| `analyzeFlowsWithAi()` | resta, spostato nell'header (agisce sulla finestra corrente) |
| `#homeAnomBody` in Home | diventa un deep link "N anomalie nuove" → Traffico/Anomalie |

### Comportamenti da correggere durante lo spostamento

1. **`loadAnomalies()` deve usare la finestra dell'header**, non `window=7d` cablato.
   Il default resta `7d` **solo** come valore iniziale del selettore se si decide che
   le anomalie hanno bisogno di più storia dei flussi — ma allora la scelta è
   visibile, non nascosta nel codice.
2. **Riga anomalia → incidente**: `id` è già l'id dell'incidente. Il link apre
   `#tab-incidents` sul dettaglio. Nessuna modifica di API.
3. **Cambio pill = ricarica solo la vista che si apre.** Oggi `flowsTabShown()`
   carica tutto in blocco; le viste non aperte non devono chiamare le loro route.

## Cosa non cambia

- **Nessuna route nuova, nessuna route modificata.** Il lavoro è interamente
  `templates/dashboard.html` + `static/js/observability.js` +
  `static/js/flow-analytics.js` + chiavi i18n.
- Nessun cambiamento a `ai/mcp_server.py`: `get_top_talkers` e `get_anomalies`
  restano quello che sono (e restano disabilitati di default).
- Nessun cambiamento allo schema del DB di osservabilità.

## Punti aperti

- **L'alias legacy `POST /api/observability/anomalies/{id}/status`** duplica
  `POST /api/incidents/{id}/status` sulla stessa tabella. Va deprecato, ma **non in
  questo lavoro**: qui l'unica regola è che la vista Anomalie continui a chiamare
  quello che chiama oggi. La rimozione è un ticket separato, dopo aver verificato che
  nessun consumatore esterno lo usi.
- **Finestra iniziale del tab**: oggi `#flowsWindow` parte da `15m`,
  `#obsChartWindow` e `#flowSiemWindow` da `24h`. Serve un default unico; proposta
  `1h`, da confermare all'implementazione guardando cosa è più utile all'apertura.
- **Larghezza della vista Ricerca**: la griglia `240px 1fr` di Flow SIEM assume la
  pagina intera. Dentro un tab con pill bar l'altezza cambia di ~40px, il
  `min-height:450px` del registro va rivisto.

## Test

Il criterio è: nessuna route persa, nessun controllo perso.

- `tests/test_router_parity.py` — deve restare verde senza modifiche (è la prova che
  non abbiamo toccato le route).
- Nuovo `tests/test_traffico_tab.py`, sullo stampo di `tests/test_wlc_tab.py`:
  ogni id nella tabella "Mappatura" marcato *invariato* esiste ancora in
  `dashboard.html`; ogni id marcato *eliminato* non esiste più; `#tab-flow-siem` non
  esiste; esistono le 4 pill e i 4 pane.
- Nuovo caso JS sullo stampo di `tests/js/test_wlc_quality.mjs`: cambiando la
  finestra nell'header, tutte le viste caricate rileggono la stessa finestra —
  in particolare la chiamata anomalie non contiene più `window=7d` cablato.
- Verifica a browser delle 4 viste dopo il merge (il piano di
  `2026-08-10-subnet-scan-discovery.md` ha lasciato lo stesso tipo di coda: le
  verifiche a browser vanno fatte, non dichiarate).

## Fasi

1. **Header + pill bar + 4 pane vuoti**, `#tab-flow-siem` ancora vivo. Nessun
   contenuto spostato: si verifica solo che la struttura regga.
2. **Sposta Panoramica e Flussi** dentro i loro pane; elimina `#flowDetailInline` e
   `#obsChartWindow`; un solo pannello protocolli.
3. **Sposta Ricerca** da `#tab-flow-siem`, che viene eliminato insieme alle due
   `.subtab-bar`; `#flowSiemTenant`/`#flowSiemWindow` cadono.
4. **Sposta Anomalie**, correggi la finestra cablata, aggiungi il link all'incidente.
5. **Home**: `#homeAnomBody` diventa deep link.
6. Test, verifica a browser, `graphify update .`, aggiornamento di
   `docs/netsec_troubleshooting_qa_v3.md` §4 e `docs/ui_tab_overlap_analysis.md` §A3
   **nello stesso commit** — gli id citati là diventano falsi nel momento in cui
   questa fase chiude.

Ogni fase è un commit che lascia il tab funzionante.
