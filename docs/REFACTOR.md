# Refactor `app_server.py` → router modulari

> Registro della fase 2 del [MASTER-IMPLEMENTATION-PLAN](MASTER-IMPLEMENTATION-PLAN.md).

## Decisioni e rilievi

- **Layout (Decisione #1):** confermato **layout flat** (moduli alla radice,
  nuovi sotto-pacchetti `observability/` e `routers/`). Nessun prefisso
  `sentinelnet.` negli import; la guida originale è stata riscritta di
  conseguenza.
- **Meccanismo di startup (rilievo 2.4):** il codice pre-refactor **non usava
  `@app.on_event`** — nessun hook di startup esisteva. Il `lifespan` è quindi
  un'aggiunta netta: (1) `db.migrate()` con guardia di versione, (2) avvio
  writer observability; in chiusura drain del writer.
- **Auth/scope (2.1):** `get_current_user`, `require_*`, `user_group_scope`,
  `assert_group_allowed`, `assert_device_allowed` vivono in
  `routers/deps.py`; `app_server.py` li reimporta (compatibilità con test e
  monolite residuo). Lo scope resta un **set multi-gruppo** (mai scalare).
- **Snapshot golden:** `tests_data/openapi_golden.json` catturato PRIMA
  dell'estrazione (120 route). `test_router_parity.py` confronta percorsi,
  metodi, parametri e schemi; unica differenza ammessa i `tags`.

## Tabella di migrazione (2.2 / 2.3)

| Endpoint (invariato) | Router | Note |
|---|---|---|
| `GET /api/fortigate/tokens` | `routers/fortigate.py` | admin |
| `POST /api/fortigate/token` | `routers/fortigate.py` | admin |
| `GET /api/fortigate/{ip}/status` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/interfaces` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/arp` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/dhcp-leases` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/device-inventory` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/policies` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/policy-stats` | `routers/fortigate.py` | |
| `POST /api/fortigate/{ip}/policy-lookup` | `routers/fortigate.py` | |
| `POST /api/fortigate/{ip}/sessions` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/routes` | `routers/fortigate.py` | |
| `POST /api/fortigate/{ip}/logs` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/wifi/clients` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/wifi/aps` | `routers/fortigate.py` | |
| `GET /api/fortigate/{ip}/full-config` | `routers/fortigate.py` | operator+, audit |
| `POST /api/fortigate/{ip}/diagnose-client` | `routers/fortigate.py` | audit |
| `GET /api/wlc/{ip}/status` | `routers/wlc.py` | |
| `GET /api/wlc/{ip}/ap-summary` | `routers/wlc.py` | |
| `GET /api/wlc/{ip}/client-summary` | `routers/wlc.py` | |
| `GET /api/wlc/{ip}/client/{mac}` | `routers/wlc.py` | |
| `GET /api/wlc/{ip}/wlan-summary` | `routers/wlc.py` | |
| `GET /api/wlc/{ip}/rogue-aps` | `routers/wlc.py` | |
| `GET /api/wlc/{ip}/interfaces` | `routers/wlc.py` | |
| `GET /api/wlc/{ip}/diagnose-client/{mac}` | `routers/wlc.py` | audit |

Gli schemi `Fgt*` sono stati spostati in `routers/fortigate.py` (usati solo lì).
`_fortigate_live_context` (contesto AI) importa `_fgt_device` dal router.

## Performance query observability (4.3)

Validato su dataset seedato da **1.000.000 righe** in `flow_aggregates`
(`test_observability_api.py::TestQueryPerf`):

- `/api/observability/top` (1h, limit 50): piano `SEARCH flow_aggregates
  USING INDEX idx_flow_window_tenant` — nessun full scan; latenza **< 500 ms**
  (gate in test).
- Correlatore: lookup flussi per (tenant, src, dst, window BETWEEN) coperto
  dallo stesso indice; ciclo completo bounded (< 30 s gate, tipicamente ms).
- Nessun indice aggiuntivo necessario oltre a quelli dello schema v1.

## Prossime estrazioni (6.6)

`mac`, `ai`, `sites`, `backup`, `provisioner`: stesso pattern — aggiungere il
prefisso a `MIGRATED_PREFIXES` in `test_router_parity.py` e le route a
`test_rbac_scope.py`.
