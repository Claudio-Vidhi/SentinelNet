# Flussi Live (Top Talker) + Flow SIEM — report tecnico

Documento di orientamento al codice per chi deve mettere mano ai due tab.
Copre: pipeline di ingest, schema dati, endpoint, frontend, decisioni prese e
loro motivazione, limiti noti.

Riferimenti incrociati: `docs/MASTER-IMPLEMENTATION-PLAN.md` (fasi 1–5, §9),
`CONTRIBUTING.md` §3 (regola async-DB) e §4 (regola di scope multi-tenant).

---

## 1. In una riga

| | Flussi Live | Flow SIEM |
|---|---|---|
| Tab | `tab-flows` | `tab-flow-siem` |
| Domanda a cui risponde | *quanto traffico, fra chi, su che protocollo* | *quel traffico è stato permesso o bloccato, e perché* |
| Tabella sorgente | `flow_aggregates` (+ `syslog_events`, `correlated_events`) | `syslog_events` (+ `siem_suppressions`) |
| Router | [routers/observability.py](routers/observability.py) | [routers/flow_siem.py](routers/flow_siem.py) |
| JS | [static/js/observability.js](static/js/observability.js) | [static/js/flow-analytics.js](static/js/flow-analytics.js) |
| Visibilità | sempre presente | dietro flag preview admin |

La separazione non è estetica: `flow_aggregates` **non ha nessuna nozione di
ALLOW/DENY** (sono contatori NetFlow/IPFIX/sFlow), mentre `syslog_events` è
l'unica tabella che contiene verdetti reali degli apparati. Vedi §7.1 per
com'è andata quando questa distinzione è stata ignorata.

---

## 2. Pipeline di ingest (comune a entrambi)

```
apparati di rete
   │ UDP (IPFIX 4739 / NetFlow 2055 / sFlow 6343 / syslog 5514)
   ▼
_IngestProtocol.datagram_received   ← observability/ingesters/udp_server.py
   │ put_nowait su asyncio.Queue (maxsize 20_000)
   ▼
_consumer (1 task per listener)
   │ parser(data, src_ip)           ← ipfix.py / sflow.py / syslog.py
   │ _resolve_tenant(exporter_ip)   ← inventory_manager.get_device_by_ip
   ▼
db.enqueue_flow() / db.enqueue_write()   ← coda bounded 10_000
   ▼
thread "obs-db-writer" (unica connessione in scrittura, commit batch da 500)
   ▼
observability.db  (SQLite WAL)
```

### 2.1 Decisioni strutturali dell'ingest

**Loop di ingest separato.** I listener UDP non girano sull'event loop
principale di FastAPI ma su un loop asyncio dedicato in un thread proprio
(`_get_ingest_loop()`, [udp_server.py:141](observability/ingesters/udp_server.py#L141)).
Un burst di decine di migliaia di datagrammi non deve rendere non reattivi il
terminale WebSocket e le API. È la correzione del "difetto #1" della guida
originale, dove il parsing avveniva inline nel loop principale.

**`datagram_received` non fa nulla oltre ad accodare.** Nessun task per
pacchetto, nessun parsing, nessun DB nell'handler. Coda piena → scarto +
metrica `dropped_queue_full`. Perdere pacchetti in modo misurato è preferibile
a bloccare il loop.

**Switch interval del GIL abbassato a 1ms**
([udp_server.py:152](observability/ingesters/udp_server.py#L152)). Il thread di
parsing è CPU-bound a burst; col default di 5ms il loop principale attendeva
decine di ms sotto carico.

**Yield periodico nel consumer** (`await asyncio.sleep(0)` ogni 20 record). Con
la coda piena `queue.get()` ritorna senza sospendere: senza lo yield il
consumer affamerebbe il loop di ingest.

**Attribuzione tenant rigida.** L'IP sorgente del datagramma viene risolto in
un device dell'inventario. Exporter sconosciuto (o collisione: due device con
lo stesso IP) → **record scartati**, upsert in `quarantined_exporters`, una
voce di audit rate-limited a 1/ora per exporter, metrica
`dropped_unknown_exporter`. *Nessun record viene mai scritto con tenant
`default`*: un dato senza sede attendibile è peggio di nessun dato, perché
inquina lo scoping multi-tenant.

### 2.2 Strato DB ([core/db.py](core/db.py))

Regole non negoziabili:

- **Una sola connessione in scrittura**, posseduta dal thread writer.
- Le scritture si accodano con `enqueue_write()` — coda bounded, mai bloccante.
- Le letture dagli endpoint async passano da `await db.read()`, che fa
  `asyncio.to_thread` con connessione read-only per chiamata (WAL permette
  letture concorrenti).
- `get_observability_connection()` è **solo** per migrazioni e test: vietata nei
  percorsi async (gate CI via grep). Unica eccezione consapevole:
  `obs_anomaly_status()` la usa dentro `asyncio.to_thread` perché serve una
  transazione read-then-write atomica.

**Resilienza del writer.** Commit batch (fino a 500 payload). Se un payload del
batch fallisce → rollback e riesecuzione item-per-item, scartando solo i payload
difettosi (`writes_dropped_error`). Crash del writer → riavvio con backoff
esponenziale, max 5 tentativi; oltre il limite le scritture vengono scartate ma
**l'app resta viva** (§2.7 del piano).

**Clock skew.** `flow_window_start()` usa il timestamp dell'exporter solo se
entro ±300s dalla ricezione, altrimenti ricade sul tempo di ricezione e
incrementa `clock_skew_fallback`. Un apparato con l'orologio sbagliato non deve
poter scrivere bucket nel futuro o nel passato remoto.

### 2.3 Aggregazione dei flussi

`FLOW_UPSERT_SQL` fa UPSERT su
`UNIQUE(window_start, tenant, src_ip, dst_ip, protocol, dst_port)` con
`window_start` troncato al minuto. Quindi `flow_aggregates` **non è un log di
flussi**, è un rollup al minuto: `flow_count` conta quanti record di flusso
sono confluiti nel bucket.

---

## 3. Schema dati ([observability/storage/schema.sql](observability/storage/schema.sql))

Migrazioni forward-only e idempotenti (`IF NOT EXISTS` ovunque).
`SCHEMA_VERSION = 4`. Guardia di **downgrade**: se il DB dichiara una versione
più nuova del codice, `migrate()` solleva `SchemaTooNewError` e l'osservabilità
rifiuta di partire (contratto di rollback §6.3).

| Tabella | Chi la scrive | Chi la legge | Note |
|---|---|---|---|
| `flow_aggregates` | ingester flow (upsert al minuto) | `/top`, `/flowgraph`, `/protocol-distribution`, correlatore, `summary.py` | colonna `source` aggiunta in v3 via ALTER idempotente; NULL = righe legacy |
| `syslog_events` | ingester syslog | `/syslog`, **tutto Flow SIEM**, correlatore | `action` = verdetto reale dell'apparato |
| `correlated_events` | correlatore | `/anomalies`, KPI "spikes" | `dedup_key UNIQUE` + `INSERT OR IGNORE` |
| `siem_suppressions` | `POST /alerts/suppress` | esclusione in `/events` e `/facets` | PK = `syslog_events.id` |
| `quarantined_exporters` | ingest | diagnostica | exporter non in inventario |
| `api_observations` | api_poller REST | `/api-context` | snapshot FortiGate, non flussi |

### 3.1 Retention ([observability/rollup.py](observability/rollup.py))

Job orario, misura tecnica GDPR (§6.7). DELETE batchati a 5000 righe per
transazione via `rowid`, per non tenere lock lunghi. Gli eventi correlati
**non risolti** (`new`/`ack`) non vengono mai eliminati automaticamente —
solo quelli `resolved`.

> Nota: `siem_suppressions` non è nella tabella di retention. Le soppressioni
> sopravvivono alla cancellazione dell'evento syslog a cui puntano (righe
> orfane innocue, ma è un dettaglio da sapere).

---

## 4. Flussi Live (`tab-flows`)

### 4.1 Endpoint

Tutti in [routers/observability.py](routers/observability.py), tutti scoped da
`_tenant_filter()`.

| Endpoint | Auth | Cosa fa |
|---|---|---|
| `GET /api/observability/top` | utente | top talker aggregati; `window`, `metric` (bytes\|packets), `source`, `limit≤500` |
| `GET /api/observability/flowgraph` | utente | nodi/archi top-50, KPI, riepilogo tenant, breakdown protocolli |
| `GET /api/observability/protocol-distribution` | utente | totali + trend temporale + breakdown per drill-down |
| `GET /api/observability/syslog` | utente | ultimi eventi syslog normalizzati |
| `GET /api/observability/anomalies` | utente | eventi correlati, paginati, filtrati per stato |
| `POST /api/observability/anomalies/{id}/status` | operator | transizione di stato |
| `GET/POST /api/observability/config` | **admin** | config listener, applicata a caldo |
| `GET /api/observability/health` | **admin** | listener attivi, metriche, dimensione DB |
| `POST /api/observability/api-poll` | operator | polling REST one-shot |

### 4.2 Regola di scope (§4 di CONTRIBUTING.md)

```python
def _tenant_filter(current_user):
    scope = user_group_scope(current_user)
    if scope is None:
        return "", ()                      # admin o utente non limitato
    groups = sorted(scope)
    placeholders = ",".join("?" * len(groups))
    return f" AND tenant IN ({placeholders})", tuple(groups)
```

Sempre `WHERE tenant IN (…placeholders…)` con parametri bound. **Mai**
interpolazione di stringhe, **mai** un gruppo scalare (un utente può
appartenere a più sedi). `user_group_scope` ritorna `None` per admin e per
utenti senza gruppi assegnati.

### 4.3 Validazione finestra

`_parse_window()` accetta `^(\d{1,4})([mhd])$` con tetto a 7 giorni
(`MAX_WINDOW_S`). Fuori formato o fuori range → 400. È l'unico punto di
ingresso della finestra per tutti gli endpoint del router.

### 4.4 `/flowgraph` — le decisioni interessanti

**Bytes del nodo = src + dst.**
```python
node_bytes[src] = node_bytes.get(src, 0) + nbytes
node_bytes[dst] = node_bytes.get(dst, 0) + nbytes
```
Un host solo-destinazione (un server interno mai visto come sorgente) altrimenti
resterebbe a 0 e verrebbe scartato ingiustamente dal cap top-50.

**Cap a 50 nodi, poi archi filtrati sui nodi sopravvissuti, poi top-50 archi.**
L'ordine conta: filtrare gli archi prima dei nodi produrrebbe archi pendenti.

**VLAN: reale se nota, sintetica se no, e la differenza è dichiarata.**
Se esiste un binding ARP per l'IP (tabella `arp_entries` di Client Map,
popolata dai gateway L3) si usa la VLAN 802.1Q reale. Altrimenti si ricade su
`_synthetic_vlan(tenant)` e **il nodo/arco viene marcato `vlan_real: false`**.
Il frontend alza il flag `vlan_disclosure` e mostra un asterisco con tooltip
([observability.js:872](static/js/observability.js#L872)). Principio: mai
spacciare un valore inventato per un tag reale.

`_synthetic_vlan()` usa **sha1 troncato**, non `hash()`: il builtin è salato per
processo (`PYTHONHASHSEED` random), quindi la stessa sede avrebbe avuto VLAN
diverse fra restart e fra worker.

**Il grafo force-directed non esiste più.** Il canvas è stato rimosso; restano
KPI, riepilogo tenant e le due tabelle. `_fgVisibleEdges()` ritorna l'intera
finestra proprio perché non c'è più un grafo su cui fare click-to-filter.

### 4.5 Correlatore ([observability/correlator.py](observability/correlator.py))

Task periodico ogni 300s, lookback 900s, max 500 eventi/ciclo.

Politica **precision-over-recall** (Decisione #9): si parte dagli eventi syslog
con `action` in `_SECURITY_ACTIONS`, si estraggono src/dst/porta dal messaggio,
e **serve evidenza di flusso corroborante** — un bucket in `flow_aggregates`
stesso tenant, stessi endpoint, entro ±120s. Senza flusso non si emette nulla.

Unica eccezione: severità ≤ 3 (emerg…error) emerge comunque come evento
standalone, anche senza flusso e senza endpoint estraibili. Un `critical` non
può sparire perché il NetFlow non è arrivato.

Dedup: `sha256(tenant|kind|syslog_id|src|dst|flow_tuple)` su colonna `UNIQUE`
con `INSERT OR IGNORE`. Le ri-esecuzioni non duplicano.

Arricchimento switch/porta best-effort via `mac_history.client_map` (uplink già
esclusi), stesso tenant. Assente → `switch_port` NULL, non un placeholder.

Mai correlazione cross-tenant: tutte le query filtrano per tenant.

### 4.6 Frontend ([static/js/observability.js](static/js/observability.js))

- **Auto-refresh 30s**, in pausa se il tab non è attivo o la pagina non è
  visibile; refresh immediato al ritorno (`visibilitychange`).
- **Anti-sovrapposizione**: `flowsFetchInFlight` e `_fgFetchInFlight` evitano
  fetch concorrenti.
- **Selezione per tupla, non per indice riga.** `flowKey(f)` =
  `tenant|src|dst|proto|port|source`. La selezione sopravvive al filtro tenant e
  al refresh periodico; con l'indice si sarebbe spostata sotto le dita
  dell'utente.
- **Chip per origine** (`all`/`netflow`/`ipfix`/`sflow`/`syslog`). In modo
  `syslog` lo schema colonne è diverso: tabella dedicata, non un adattamento
  della tabella flussi. In modo `all` il syslog compare in una sezione separata
  sotto.
- **Colonne nascondibili** persistite in `localStorage`
  (`sentinelnet_flows_hidden_cols`).
- **Banner di stato**: se `/health` dice observability spenta o nessun listener
  attivo, lo si dichiara. Prima l'assenza di dati era silenziosa e
  indistinguibile da "rete tranquilla". `/health` è admin-only: 403 → banner
  nascosto, non errore.
- **Pannello dettaglio flusso** (slide-in): riusa
  `/api/arp/client-map` per MAC/switch/porta della sorgente — nessun endpoint
  nuovo.
- **Ponte verso la topologia**: `highlightInTopology(ip)` cambia tab e fa
  `networkInstance.focus(ip)` con retry (20 tentativi × 250ms) perché il grafo
  Vis.js potrebbe non essere ancora caricato.
- **Ponte verso le anomalie**: `jumpToAnomaliesForFlow()` imposta un filtro
  client-side su src/dst e scrolla su un'ancora esplicita
  (`#anomSectionTitle`) — il vecchio selettore `#tab-flows h4` si rompeva a ogni
  modifica della gerarchia.

### 4.7 Transizioni di stato delle anomalie

`_ALLOWED_TRANSITIONS = {(new,ack), (new,resolved), (ack,resolved)}`.
Concorrenza ottimistica: il client manda `from_status` e l'UPDATE ha
`AND status = ?`; `rowcount == 0` → **409** con messaggio "ricarica la lista".
Evento fuori scope o inesistente → **404 identico**, per non confermare
l'esistenza di eventi di altre sedi.

### 4.8 Integrazione AI

Due percorsi, entrambi con assemblaggio del contesto **lato server**:

- nessuna riga selezionata → `attach_top_flows: true` → riassunto top-N;
- righe selezionate → `attach_flow_keys: [{src_ip,dst_ip,protocol,dst_port}]`,
  max 20.

Il browser invia **solo tuple identificative**: mai byte o pacchetti. I totali
vengono ri-derivati dal DB in `top_flows_context()`
([observability/summary.py](observability/summary.py)), e lo scope tenant resta
applicato in AND — le key fornite dal client non possono estrarre righe di altri
tenant. Il contesto passa comunque dal choke-point di redazione in
`ai_assistant.chat()`. L'UI dichiara esplicitamente cosa sta per essere inviato
e a quale provider.

### 4.9 Esposizione MCP

`get_top_talkers` e `get_anomalies` sono definiti in
[ai/mcp_server.py:414](ai/mcp_server.py#L414) ma sono in
`_MCP_DEFAULT_DISABLED` ([routers/mcp.py:15](routers/mcp.py#L15)): vanno
abilitati esplicitamente.

---

## 5. Flow SIEM (`tab-flow-siem`)

### 5.1 Gating

Tab dietro flag preview admin: `GET/POST /api/settings/flow-siem-preview`
([routers/settings.py:111](routers/settings.py#L111)), persistito in
`app_settings.json` come `flow_siem_preview_enabled`, con voce di audit a ogni
cambio. Il pulsante di nav è `display:none` finché il flag è off.

### 5.2 Endpoint

Prefix `/api/flow-siem`, tutti scoped.

| Endpoint | Cosa fa |
|---|---|
| `GET /events` | registro eventi, `q`, `window`, `action`, `limit≤500`, `offset` |
| `GET /histogram` | conteggi + deny per bucket temporale (10–100 bucket) |
| `GET /facets` | top src/dst IP, threat flag, azioni |
| `POST /alerts/suppress` | soppressione persistita |

### 5.3 Da riga syslog a evento SIEM

`_to_event()` ([flow_siem.py:129](routers/flow_siem.py#L129)):

| Campo | Origine |
|---|---|
| `id` | `syslog_events.id` — **chiave primaria, stabile** |
| `src_ip`/`dst_ip` | kv FortiGate `srcip`/`dstip`, fallback prime due IP nel messaggio |
| `src_port`/`dst_port` | kv `srcport`/`dstport` |
| `proto` | kv `proto`\|`service`, numerico mappato (6→TCP, 17→UDP, 1→ICMP) |
| `bytes` | `sentbyte + rcvdbyte`, `None` se assenti |
| `action` | colonna `action` oppure kv `action` |
| `is_deny` | `action` ∈ `_SECURITY_ACTIONS` (importato dal correlatore) |
| `threat_flag` | derivato: vedi sotto |

`_threat_flag()` deriva **solo da dati reali**, in ordine di priorità:
`BLOCKED_TRAFFIC` (deny) → `HIGH_SEVERITY` (sev ≤ 3) → `HIGH_VOLUME_TRANSFER`
(> 1 MB) → `EXTERNAL_DNS` (dst 8.8.8.8 / 1.1.1.1) → `NORMAL`.

**Ciò che il messaggio non contiene resta `None`** e la UI mostra un trattino.
Nessun campo sintetizzato.

### 5.4 Deep scan a lotti

`src_ip`, `dst_ip`, `proto`, `threat_flag` non sono colonne: nascono da
`_to_event()` sul corpo del messaggio. Il filtro **non è esprimibile in SQL** e
resta in Python. Quindi `/events` legge a lotti finché non ha abbastanza
corrispondenze:

```python
wanted = offset + limit
batch  = min(max(limit * 4, 500), MAX_LIMIT * 4)
while len(events) < wanted and scanned < MAX_SCAN:   # MAX_SCAN = 20_000
    ...
```

Con un blocco unico di righe recenti, un IP raro presente nelle faccette (che
scandiscono 2000 righe) non compariva mai in tabella. Il tetto a 20.000 righe
grezze per richiesta limita il costo.

**Costo noto:** filtro non selettivo su finestra ampia = fino a 20.000 righe
lette e parsate in Python per richiesta, con lo streaming che ripete la query
ogni 5s. È il compromesso accettato per non aggiungere colonne derivate allo
schema.

### 5.5 Sintassi `campo:valore`

`_FILTER_FIELDS = (src_ip, dst_ip, action, threat_flag, proto, device_ip, tenant)`.

La ricerca libera guarda **tutti** i campi: cliccare un IP fra le sorgenti
restituiva anche le righe in cui quell'IP è la destinazione, e con quelle più
numerose le righe volute finivano fuori dalla prima pagina. Da qui il filtro
esatto per campo.

Un prefisso non riconosciuto **non** viene interpretato come campo: resta
ricerca libera, così `8.8.8.8:53` continua a funzionare.

`_field_value()` normalizza `action`: le faccette etichettano ogni verdetto di
blocco come `DENY` (l'apparato può scrivere `blocked`, `drop`, …); senza la
normalizzazione, cliccare la faccetta `DENY` non avrebbe trovato quelle righe.

### 5.6 Soppressione

`POST /alerts/suppress` verifica che l'evento sia **nello scope dell'utente**
(altrimenti si potrebbe sopprimere un'allerta di un'altra sede → 404), poi
accoda un `INSERT OR REPLACE` in `siem_suppressions` con `reason` e
`suppressed_by`.

Sia `/events` sia `/facets` applicano
`AND NOT EXISTS (SELECT 1 FROM siem_suppressions x WHERE x.event_id = s.id)`:
senza l'esclusione anche in `/facets`, una faccetta contava eventi che la
tabella non mostrava più.

### 5.7 Frontend ([static/js/flow-analytics.js](static/js/flow-analytics.js))

- **Live tail** ogni 5s, pausabile. Non gira se il tab non è attivo.
- **Congelamento con dettaglio aperto**: se `_selectedEventId` è impostato, lo
  streaming non aggiorna la tabella — il refresh la ricostruisce e sposterebbe
  la riga che l'utente sta leggendo.
- **Deduplica per id**: il polling chiede sempre gli ultimi 20 eventi; senza la
  deduplica gli stessi eventi venivano riaccodati ogni 5s (duplicati in tabella,
  e un id selezionato apriva più dettagli identici). Buffer client capped a 150.
- **Scroll preservato**: la tabella viene ricostruita interamente, quindi si
  salva e ripristina `scrollTop` del contenitore.
- **Istogramma su canvas 2D**, barre rosse dove `deny_count > 0`. Nessun dato →
  lo si scrive. (Vedi §7.2.)
- **Faccette cliccabili**, ognuna sul proprio campo, che scrivono
  `campo:valore` nella casella di ricerca — stessa sintassi digitabile a mano,
  quindi il filtro resta visibile e modificabile.
- **Escaping**: convenzione di progetto `escapeHtml(...)` per il contenuto e
  `jsStr(...)` dentro gli handler inline.
- **Nota DENY nel dettaglio**: quando l'azione è di blocco, il drawer chiarisce
  che SentinelNet è una piattaforma di osservabilità **passiva** — il blocco
  l'ha fatto l'apparato, non SentinelNet.

---

## 6. Configurazione e ciclo di vita

### 6.1 Default sicuri ([core/data_config.py:65](core/data_config.py#L65))

Tutto spento, bind su `127.0.0.1`, porte alte non privilegiate
(IPFIX 4739, NetFlow 2055, sFlow 6343, syslog **5514** — mai 514 in-process; il
mapping privilegiato si fa solo via Docker). `0.0.0.0` richiede opt-in
esplicito.

Precedenza: **variabili d'ambiente > `app_settings.json` > default**.

### 6.2 Applicazione a caldo ([observability/listener_manager.py](observability/listener_manager.py))

`apply_obs_config()` è idempotente e viene chiamata sia dal lifespan sia da
`POST /api/observability/config`: **nessun riavvio del processo richiesto**.

Diff fra handle attivi e config desiderata; **stop-before-start** per lo stesso
nome, obbligatorio su Windows che non permette il doppio bind della stessa
porta. Bind fallito → metrica `listener_bind_failed`, stato registrato in
`listener_status`, log di errore, **listener saltato e app viva**.

Lo stato è a livello di modulo, non su `app.state`, così l'endpoint può
richiamare `apply_obs_config` senza un riferimento a `FastAPI`.

Task di background (retention, correlazione, poller API): partono alla prima
attivazione del master switch e restano attivi (sono no-op se non c'è nulla da
fare); il poller API viene riavviato se cambia l'intervallo.

### 6.3 Lifespan ([app_server.py:25](app_server.py#L25))

```
db.start_writer()        → migrate() + thread writer
apply_obs_config(cfg)    → listener + task
   yield
listener_manager.shutdown()
db.stop_writer()         → drena la coda, best-effort 10s
```

`SchemaTooNewError` all'avvio è fatale e stampata su stderr: meglio non partire
che scrivere su un DB di una versione futura.

---

## 7. Errori storici corretti (utili per non reintrodurli)

### 7.1 Flow SIEM costruito su `flow_aggregates`

La prima versione del router leggeva `flow_aggregates` e **sintetizzava i campi
mancanti**: azione da `idx % 5`, porta sorgente da `1024 + idx*37`, timestamp da
`now - idx*45`, VLAN fissa a 10. L'id era posizionale (`siem-fl-<indice>`),
derivato dal rango per byte: **non identificava un evento ma una posizione in
classifica**, quindi al refresh successivo lo stesso id puntava a un'altra
connessione e il dettaglio aperto cambiava contenuto sotto gli occhi
dell'utente.

Correzione: fonte = `syslog_events`, id = chiave primaria.

### 7.2 Istogramma sinusoidale

`/histogram` non interrogava il database: i valori erano
`abs(sin(i * 0.4)) * 45` e i deny il 15% di quelli. Le barre disegnate erano una
sinusoide. Anche il fallback lato client disegnava una rampa finta
(`count: 20+i`) a DB vuoto: un database senza dati sembrava traffico reale.

### 7.3 Soppressione no-op

`POST /alerts/suppress` rispondeva `{"suppressed": true}` senza scrivere nulla.
L'allerta ricompariva al refresh successivo. Da qui la tabella
`siem_suppressions`.

### 7.4 Flow SIEM senza scope tenant

Il router non applicava `_tenant_filter` affatto: un utente limitato a una sede
vedeva gli eventi di tutte le sedi.

### 7.5 `hash()` per la VLAN sintetica

Salato per processo: VLAN diverse fra restart e fra worker. Sostituito con sha1
troncato.

---

## 8. Test

| File | Copre |
|---|---|
| `tests/test_flow_siem.py` | `TestFlowSiem`, `TestFlowSiemDeepScan` |
| `tests/test_observability_api.py` | endpoint del router observability |
| `tests/test_observability_flowgraph.py` | `TestFlowGraph`, `TestFlowGraphRealVlan`, `TestFlowGraphVlanTenantScope` |
| `tests/test_observability_ingest.py` | parser e pipeline di ingest |
| `tests/test_observability_ui.py` | markup e wiring dei tab |

Esecuzione: `unittest` (i test del progetto girano anche come script).

---

## 9. Limiti noti / punti di attenzione

1. **Costo del deep scan** (§5.4): fino a 20.000 righe parsate in Python per
   richiesta, ripetute ogni 5s dal live tail. Se diventa un problema, la strada
   è materializzare `src_ip`/`dst_ip`/`action` come colonne in `syslog_events` al
   momento dell'ingest — non ottimizzare il loop Python.
2. **`total` in `/events` è il conteggio dei match trovati finora**, non il
   totale reale nella finestra: il deep scan si ferma appena ha abbastanza
   risultati. Non usarlo per una paginazione con numero di pagine.
3. **RFC 3164 senza anno né timezone**: si assume anno corrente e fuso locale
   del server. Limite del formato BSD, non del parser.
4. **`siem_suppressions` fuori dalla retention** (§3.1).
5. **VLAN sintetica** quando manca il binding ARP: sempre marcata, mai
   silenziosa — ma è comunque un valore non reale.
6. **Precision-over-recall del correlatore**: un evento di sicurezza senza
   NetFlow corroborante e con severità > 3 non genera anomalia. È voluto
   (Decisione #9), ma va saputo quando si indaga un "perché non è comparso".

---

## 10. Percorso di indagine tipico (cosa il codice supporta)

1. **Flussi Live** → KPI (throughput, top path %, talker, spikes) e tabella top
   talker. Filtri: finestra, metrica, origine, tenant.
2. Riga sospetta → click apre il **pannello dettaglio**: MAC/switch/porta della
   sorgente via client-map, link alla topologia, salto alle anomalie di quel
   flusso.
3. **Anomalie correlate** → transizioni `new` → `ack` → `resolved`.
4. **Flow SIEM** → filtro `src_ip:<ip>` o `dst_ip:<ip>` per il verdetto reale
   ALLOW/DENY dell'apparato, con faccette e istogramma.
5. Falso positivo confermato → **sopprimi** (persistito, escluso da eventi e
   faccette).
6. Opzionale: selezione righe in Flussi Live → **analisi AI** con contesto
   assemblato e redatto lato server.
