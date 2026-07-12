# Contribuire a SentinelNet

Regole vincolanti per ogni modifica (umana o via agente AI). Derivano dal
piano in [docs/MASTER-IMPLEMENTATION-PLAN.md](docs/MASTER-IMPLEMENTATION-PLAN.md).

## 1. Lingua

- **Stringhe utente, log, messaggi d'errore, commenti e docstring: italiano.**
- **Identificatori (funzioni, variabili, moduli, endpoint): inglese.**

```python
# ✅ corretto
def resolve_tls_config():
    raise TlsConfigError("Configurazione TLS incompleta: ...")

# ❌ sbagliato
def risolvi_config_tls():
    raise TlsConfigError("Incomplete TLS configuration: ...")
```

## 2. Doppio artefatto (exe + Docker)

Ogni PR deve lasciare buildabili **entrambi** gli artefatti:

```sh
uv run pyinstaller SentinelNet.spec   # exe Windows
docker compose build                  # immagine Docker
```

Nuovi file dati (es. `schema.sql`) vanno aggiunti a `datas` in
`SentinelNet.spec` e verificati in tutte e tre le modalità (sorgente, exe,
Docker). I percorsi bundled si risolvono via `sys._MEIPASS`.

## 3. Regola async-DB (non negoziabile)

- **Mai `sqlite3` diretto nei percorsi async** (endpoint FastAPI, handler UDP).
- Letture: `await db.read(sql, params)` (off-load su thread).
- Scritture: `db.enqueue_write(...)` / `db.enqueue_flow(...)` (coda bounded,
  writer dedicato, commit batch).
- `db.get_observability_connection()` è consentita SOLO in migrazioni e test.

```python
# ✅ corretto (endpoint async)
rows = await db.read("SELECT ... WHERE tenant IN (...)", scoped)

# ❌ sbagliato: blocca l'event loop (terminale WS, API, tutto)
conn = db.get_observability_connection()
rows = conn.execute("SELECT ...").fetchall()
```

## 4. Regola di scope multi-gruppo

Un utente può avere **più** gruppi (`user_group_scope`). Mai usare uno scalare
`user.group` nelle query o nei check di autorizzazione:

```python
# ✅ corretto
placeholders = ",".join("?" * len(groups))
await db.read(f"SELECT ... WHERE tenant IN ({placeholders})", tuple(groups))

# ❌ sbagliato: nasconde o espone dati con utenti multi-gruppo
await db.read("SELECT ... WHERE tenant = ?", (user.group,))
```

Per i device: `assert_group_allowed` / `assert_device_allowed`.

## 5. Assunzione single-process

Il writer SQLite è single-process. Non avviare l'app con `--workers > 1` a
osservabilità attiva; la scalabilità orizzontale non è supportata per il
modulo observability.

## 6. Gate di sicurezza permanenti (grep in review/CI)

| Gate | Comando | Atteso |
|---|---|---|
| Token in sessionStorage (L-1) | `grep -c "sessionStorage" templates/dashboard.html` | 0 usi per token |
| sqlite3 nei path async | `grep -n "get_observability_connection" app_server.py routers/ observability/ingesters/` | solo migrazioni/test |
| Segreti in chiaro nel provisioner (I-2) | test `test_provisioning_secrets.py` | verde |
| Redazione LLM (I-1) | test `test_redaction.py` | verde |
| TLS fail-closed (H-1) | test `test_tls_config.py` | verde |

## 7. Test

I test sono `unittest` eseguibili come script: `uv run python test_<nome>.py`.
Ogni nuovo modulo porta il proprio `test_<modulo>.py`; i test usano
`SENTINELNET_DATA_DIR` temporanea, mai lo stato reale.
