# Refactor `app_server.py` → router modulari (Fase Destructure)

> Registro della fase 6.6 e del [2026-07-15-app-server-destructuring.md](./plans/2026-07-15-app-server-destructuring.md).

## Decisioni e rilievi

- **Layout:** Mantenuto il layout flat. I router vivono in `routers/`.
- **`app_server.py`:** Sfoltito radicalmente a 234 righe. Il file ora contiene esclusivamente:
  - Il blocco `lifespan` per l'avvio e spegnimento di moduli (observability).
  - L'istanza principale `FastAPI`.
  - Gli `include_router` per 21 router complessivi.
  - I re-export per compatibilità (es. `routers.deps`, `routers.ai`).
  - Il serving dei contenuti statici (`GET /`, templates).
  - `main()` e avvio uvicorn.
- **WebSocket:** La route WebSocket `/api/triage/jobs/{job_id}/stream` è stata estratta in `routers/triage.py`. Questo ha aggirato i limiti dell'OpenAPI snapshotting, ed è stato verificato manualmente e testato via `test_triage.py`.

## Tabella di migrazione (fase 6.6)

La lista completa dei router e i loro scopi principali:

| Router | Note |
|---|---|
| `routers/app_settings.py` | Configurazione interna app_settings |
| `routers/auth.py` | JWT, login, logout, me |
| `routers/inventory.py` | Gestione inventory (DeviceSchema) |
| `routers/catalog.py` | Vendor parser e plugin statici |
| `routers/settings.py` | Applicazione impostazioni generali |
| `routers/topology.py` | View per vis-network (edges, nodes) |
| `routers/triage.py` | Background jobs e WebSocket |
| `routers/commands.py` | Liste e command allowed |
| `routers/backup.py` | Backup file zip |
| `routers/mac.py` | Ricerca MAC, ARP |
| `routers/arp.py` | ARP collector e tabelle |
| `routers/analyzer.py` | Config analysis diff e controlli |
| `routers/ai.py` | AI assistant, mock e profili |
| `routers/provisioner.py` | Switch/FortiGate ZTP provisioning |
| `routers/mcp.py` | Model Context Protocol config |
| `routers/scan.py` | Network subnet scanner in background |
| `routers/sites.py` | Gestione multi-sede (RemoteSites) |
| `routers/agent.py` | Endpoint autenticati per agenti periferici |

## Patch nei test

I test richiedevano aggiornamenti mirati nei punti di mocking (patch) per via dello spostamento di nomi di variabili e metodi al di fuori di `app_server`:
- `test_observability_ui.py`: Aggiornato il mocking di `app_server._get_active_ai_profile` verso `routers.ai._get_active_ai_profile`.
- `test_transports.py`: Verificati eventuali refactor point di `core_engine`.
- `test_remote_site.py`: Sistemate le dipendenze import (`re`, `status`, `log_audit`, `is_command_safe`) necessarie ai router modulari.

## Code Dead / Da non toccare

Il processo di estrazione si è focalizzato sullo snellimento di `app_server.py`. Le funzioni migrate mantengono la firma identica e non sono state ritoccate per ipotetiche pulizie. Gli hook di avvio e alcuni re-export di `ai` vivono in `app_server.py` per non invalidare l'architettura di altri test finché l'esecuzione è confermata stabile.
