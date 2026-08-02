# FortiGate Management Tab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the hidden "FortiGate LIVE" preview tab into a normal admin-only "Fortigate Management" tab exposing most of the FortiGate read-only API surface, with a refinished UI.

**Architecture:** Twelve new read-only service functions over the existing `api_get`/`api_get_cmdb` transport, thirteen new routes, and a rebuilt tab whose seven sub-tabs are driven by one declarative `FGT_DATASETS` registry plus a single generic loader/renderer. No writes to FortiOS anywhere.

**Tech Stack:** Python 3.14 + FastAPI + Pydantic (backend), vanilla JS + Font Awesome (frontend), `unittest` (tests), `uv` (runner), `pyrefly` (type check).

## Global Constraints

- **Read-only.** No PUT/POST/DELETE against FortiOS cmdb. No policy edits, no session clearing, no object CRUD.
- **No customer data in tracked files.** Use RFC 5737 addresses only — `192.0.2.x`, `198.51.100.x`, `203.0.113.x` — and placeholder names like `switch-01`, `<hostname>`, `AA:BB:CC:DD:EE:FF`. Never a real device model, version, hostname, serial or management IP, not even as an illustration.
- **Italian codebase.** Docstrings and comments in Italian, matching the surrounding files. User-facing strings go through `i18n` with both `it` and `en` entries.
- **Escaping.** Every FortiGate-derived string reaching the DOM goes through `escapeHtml(jsStr(x))`.
- **No backwards-compatibility shims.** Delete the preview flag outright; do not leave a stub endpoint returning `true`.
- **No JS test runner exists.** Frontend assertions are grep-style over `frontend_source()` from `tests/test_helpers_frontend.py`. Logic that needs a real test belongs in Python.
- Gate before every commit, per `CLAUDE.md`:
  ```sh
  uv run pyrefly check                          # 0 errors
  uv run python -m unittest discover -s tests   # all green
  ```
- Run tests for a single file with: `uv run python -m unittest tests.test_name -v`

## File Structure

| File | Responsibility | Tasks |
|---|---|---|
| `services/fortigate_service.py` | All FortiOS calls. Gains 13 functions (12 new + 1 join). | 2, 3, 4, 5 |
| `routers/fortigate.py` | Routing, auth, per-site scoping. Gains 14 routes and 3 schema fields. | 1, 2, 3, 4, 5 |
| `routers/settings.py` | Loses both `/api/settings/fortigate-preview` handlers. | 7 |
| `tests/test_fortigate_service.py` | Unit tests for the new service functions. | 2, 3, 4, 5 |
| `tests/test_fortigate_management.py` | **New.** Route auth, admin projection, dataset registry integrity. | 3, 8 |
| `tests/test_router_parity.py` | Allowlist edits for new/removed paths and the changed schema. | 1, 3, 4, 7 |
| `tests/test_ui_revamp.py` | Stale `fortigate-preview.js` comments. | 7 |
| `static/js/fortigate-management.js` | **Renamed** from `fortigate-preview.js`. Registry, loader, renderer, sub-tab switching, existing token/target UI. | 7, 8, 10 |
| `static/js/core.js` | `switchTab` dispatch; drop the gating call. | 7 |
| `static/js/i18n.js` | New label keys in both `it` and `en`. | 9 |
| `templates/dashboard.html` | Tab markup: 7 sub-tab panes. | 7, 9, 10 |
| `static/css/dashboard.css` | Re-scope `.ca-pill` off `#tab-config`. | 9 |
| `docs/fortigate-management-plan.md` | The spec. Already committed. | — |

---

# Phase 1 — Close the two carried-in gaps

### Task 1: Expose the log category over HTTP

`get_traffic_logs` accepts `log_type`/`log_subtype`/`cli_category` (`services/fortigate_service.py:510-511`) but `FgtLogQuerySchema` never sends them, so they are unreachable from any client.

**Files:**
- Modify: `routers/fortigate.py:60-65` (schema), `routers/fortigate.py:208-214` (route)
- Modify: `tests/test_router_parity.py:101`, `tests/test_router_parity.py:162`
- Test: `tests/test_fortigate_service.py`

**Interfaces:**
- Consumes: `fortigate_service.get_traffic_logs(device, src_ip, dst_ip, action, count, log_device, log_type, log_subtype, cli_category)` — already exists.
- Produces: `POST /api/fortigate/{ip}/logs` accepting three extra optional body fields.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fortigate_service.py`:

```python
class TrafficLogCategoryTest(unittest.TestCase):
    """Il router deve poter scegliere la categoria di log: i parametri
    esistevano nel service ma nessuno schema li trasportava."""

    @mock.patch("services.fortigate_service.api_get")
    def test_log_type_and_subtype_reach_the_api_path(self, mock_api_get):
        mock_api_get.return_value = {"results": []}
        fgs.get_traffic_logs(DEVICE, log_device="memory",
                             log_type="utm", log_subtype="virus",
                             cli_category="virus")
        path = mock_api_get.call_args[0][1]
        self.assertEqual(path, "log/memory/utm/virus")

    @mock.patch("services.fortigate_service.api_get")
    def test_defaults_are_the_historic_traffic_forward(self, mock_api_get):
        mock_api_get.return_value = {"results": []}
        fgs.get_traffic_logs(DEVICE)
        self.assertEqual(mock_api_get.call_args[0][1], "log/disk/traffic/forward")
```

- [ ] **Step 2: Run test to verify current behaviour**

Run: `uv run python -m unittest tests.test_fortigate_service.TrafficLogCategoryTest -v`

Expected: PASS. These pin the *service*, which already works — they exist so the router change below cannot silently break the path construction. If either fails, the path-building assumption in this task is wrong; stop and re-read `get_traffic_logs` before continuing.

- [ ] **Step 3: Add the three fields to the schema**

In `routers/fortigate.py`, replace the `FgtLogQuerySchema` class body:

```python
class FgtLogQuerySchema(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    action: Optional[str] = None   # accept | deny | ...
    count: int = 100
    log_device: str = "disk"       # disk | memory
    # Categoria del log. Il service costruisce log/{device}/{type}/{subtype}
    # e usa cli_category per il fallback CLI; i default riproducono il
    # traffico forward, cioè il comportamento storico di questo endpoint.
    log_type: str = "traffic"      # traffic | event | utm
    log_subtype: str = "forward"   # forward | local | virus | webfilter | ips | ...
    cli_category: str = "traffic"
```

- [ ] **Step 4: Pass them through in the route**

In `routers/fortigate.py`, replace the body of `fgt_logs`:

```python
    return _fgt_call(fortigate_service.get_traffic_logs, _fgt_device(ip, current_user),
                     src_ip=payload.src_ip, dst_ip=payload.dst_ip,
                     action=payload.action, count=payload.count,
                     log_device=payload.log_device, log_type=payload.log_type,
                     log_subtype=payload.log_subtype,
                     cli_category=payload.cli_category)
```

- [ ] **Step 5: Run the parity tests and watch them fail**

Run: `uv run python -m unittest tests.test_router_parity -v`

Expected: FAIL — `test_migrated_schemas_identical` and `test_every_schema_identical` both report `schema FgtLogQuerySchema cambiato`. This is the expected, sanctioned break: the schema gained optional fields with defaults.

- [ ] **Step 6: Record the sanctioned schema change**

In `tests/test_router_parity.py:101`, extend `TestRouterParity.ALLOWED_CHANGED_SCHEMAS`:

```python
    # FgtLogQuerySchema ha guadagnato log_type/log_subtype/cli_category: i
    # parametri esistevano già in get_traffic_logs ma nessuno schema li
    # trasportava, quindi la categoria di log era irraggiungibile via HTTP.
    # Aggiunta puramente additiva (campi opzionali con i default storici):
    # nessun client esistente cambia comportamento.
    ALLOWED_CHANGED_SCHEMAS = ("FgtTokenSchema", "AgentDeviceSchema", "DeviceSchema",
                               "FgtLogQuerySchema")
```

In `tests/test_router_parity.py:162`, extend `TestFullParity.ALLOWED_CHANGED_SCHEMAS`:

```python
    # FgtLogQuerySchema: vedi TestRouterParity.ALLOWED_CHANGED_SCHEMAS.
    ALLOWED_CHANGED_SCHEMAS = ("AgentDeviceSchema", "DeviceSchema", "FgtLogQuerySchema")
```

- [ ] **Step 7: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

Expected: 0 pyrefly errors, all tests green.

- [ ] **Step 8: Commit**

```bash
git add routers/fortigate.py tests/test_fortigate_service.py tests/test_router_parity.py
git commit -m "feat(fortigate): expose log category over HTTP

get_traffic_logs took log_type/log_subtype/cli_category but
FgtLogQuerySchema carried only log_device, so every caller was pinned to
traffic/forward. Additive: the defaults reproduce today's behaviour.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Policy hit counters

`get_policy_stats` has a route and an MCP tool but nothing renders it. Join it to the config rows server-side, where it can carry a test.

**Files:**
- Modify: `services/fortigate_service.py` (after `get_firewall_policy_objects`, ~line 390)
- Modify: `routers/fortigate.py` (new route near the other `/firewall/` routes, ~line 188)
- Test: `tests/test_fortigate_service.py`

**Interfaces:**
- Consumes: `get_firewall_policy_objects(device) -> {"source": str, "data": list}`, `get_policy_stats(device) -> {"source": str, "data": list, "api_error": str|None}`.
- Produces: `get_policies_with_stats(device) -> {"source": "api", "data": list[dict], "stats_error": str|None}` where each row is a config row plus keys `hit_count: int`, `bytes: int`, `active_sessions: int`, `last_used: str|None`, `never_hit: bool`. Route `GET /api/fortigate/{ip}/firewall/policies-with-stats`. The dataset registry (Task 8) consumes this under the key `policies`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fortigate_service.py`:

```python
class PoliciesWithStatsTest(unittest.TestCase):
    """Le policy mai colpite sono un rilievo d'audit: il join deve
    distinguere 'zero hit' da 'contatore assente'."""

    CONFIG = [
        {"policyid": 1, "name": "allow-web", "action": "accept", "status": "enable"},
        {"policyid": 2, "name": "dead-rule", "action": "accept", "status": "enable"},
        {"policyid": 3, "name": "no-counter", "action": "deny", "status": "enable"},
    ]
    STATS = [
        {"policyid": 1, "hit_count": 42, "bytes": 1024,
         "active_sessions": 3, "last_used": "2026-08-01 10:00:00"},
        {"policyid": 2, "hit_count": 0, "bytes": 0, "active_sessions": 0},
    ]

    def _run(self, stats_side_effect=None):
        with mock.patch.object(fgs, "get_firewall_policy_objects",
                               return_value={"source": "api", "data": self.CONFIG}), \
             mock.patch.object(fgs, "get_policy_stats",
                               side_effect=stats_side_effect,
                               return_value={"source": "api", "data": self.STATS}):
            return fgs.get_policies_with_stats(DEVICE)

    def test_counters_are_joined_on_policyid(self):
        rows = {r["policyid"]: r for r in self._run()["data"]}
        self.assertEqual(rows[1]["hit_count"], 42)
        self.assertEqual(rows[1]["active_sessions"], 3)
        self.assertFalse(rows[1]["never_hit"])

    def test_zero_hit_policy_is_flagged(self):
        rows = {r["policyid"]: r for r in self._run()["data"]}
        self.assertEqual(rows[2]["hit_count"], 0)
        self.assertTrue(rows[2]["never_hit"], "una policy con hit_count 0 è morta")

    def test_policy_absent_from_stats_is_not_flagged_as_dead(self):
        # Nessun contatore != contatore a zero: senza dato non si può dire
        # che la regola sia morta, e marcarla sarebbe un falso positivo.
        rows = {r["policyid"]: r for r in self._run()["data"]}
        self.assertEqual(rows[3]["hit_count"], 0)
        self.assertFalse(rows[3]["never_hit"])

    def test_config_survives_a_stats_failure(self):
        res = self._run(stats_side_effect=fgs.FortiGateError("monitor down"))
        self.assertEqual(len(res["data"]), 3)
        self.assertIn("monitor down", res["stats_error"])
        self.assertFalse(any(r["never_hit"] for r in res["data"]))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_fortigate_service.PoliciesWithStatsTest -v`

Expected: FAIL — `AttributeError: module 'services.fortigate_service' has no attribute 'get_policies_with_stats'`

- [ ] **Step 3: Implement the join**

In `services/fortigate_service.py`, after `get_firewall_policy_objects` (~line 390):

```python
def get_policies_with_stats(device):
    """Policy (cmdb, slim) unite ai contatori runtime, join su ``policyid``.

    ``never_hit`` è vero solo per le policy che HANNO un contatore e vale
    zero: senza contatore non si può dire che la regola sia morta, e
    marcarla produrrebbe un falso positivo in audit. Se i contatori non
    arrivano la configurazione viene restituita comunque, con l'errore in
    ``stats_error``: metà risposta è meglio di un 502."""
    policies = get_firewall_policy_objects(device)
    rows = policies.get("data") or []
    stats_error = None
    by_id = {}
    try:
        stats = get_policy_stats(device)
        data = stats.get("data")
        if isinstance(data, list):
            by_id = {s.get("policyid"): s for s in data if isinstance(s, dict)}
    except FortiGateError as e:
        stats_error = str(e)

    merged = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        s = by_id.get(row.get("policyid"))
        merged.append({**row,
                       "hit_count": (s or {}).get("hit_count", 0),
                       "bytes": (s or {}).get("bytes", 0),
                       "active_sessions": (s or {}).get("active_sessions", 0),
                       "last_used": (s or {}).get("last_used"),
                       "never_hit": bool(s) and not (s or {}).get("hit_count")})
    return {"source": policies.get("source", "api"), "data": merged,
            "stats_error": stats_error}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_fortigate_service.PoliciesWithStatsTest -v`

Expected: PASS, 4 tests.

- [ ] **Step 5: Add the route**

In `routers/fortigate.py`, after `fgt_firewall_services` (~line 188):

```python
@router.get("/api/fortigate/{ip}/firewall/policies-with-stats")
def fgt_firewall_policies_with_stats(ip: str, current_user = Depends(get_current_user)):
    """Policy firewall unite ai contatori runtime (hit, byte, sessioni):
    una sola richiesta invece di due, e le regole mai colpite sono già
    marcate."""
    return _fgt_call(fortigate_service.get_policies_with_stats,
                     _fgt_device(ip, current_user))
```

No parity edit needed: the path is under `/api/fortigate/{ip}/firewall`, already in both allowlists.

- [ ] **Step 6: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

Expected: 0 pyrefly errors, all green — including `test_router_parity`, which must NOT complain about the new path.

- [ ] **Step 7: Commit**

```bash
git add services/fortigate_service.py routers/fortigate.py tests/test_fortigate_service.py
git commit -m "feat(fortigate): join policy hit counters to the policy list

get_policy_stats had a route and an MCP tool but nothing rendered it.
Joining server-side keeps the zero-hit logic testable (no JS test runner
here) and halves the browser's requests. never_hit distinguishes a
counter reading zero from no counter at all.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

# Phase 2 — New read-only service functions and routes

### Task 3: System group

**Files:**
- Modify: `services/fortigate_service.py` (after `get_system_status`, ~line 322)
- Modify: `routers/fortigate.py`
- Modify: `tests/test_router_parity.py:58`, `tests/test_router_parity.py:130`
- Create: `tests/test_fortigate_management.py`
- Test: `tests/test_fortigate_service.py`

**Interfaces:**
- Consumes: `api_get(ip, path)`, `api_get_cmdb(ip, path, fmt=None)`, `FortiGateError`, `get_ha_status(device)`, `get_ha_checksums(device)` — all existing.
- Produces:
  - `get_system_resources(device) -> {"source": "api", "data": {"usage": ..., "time": ...}}`
  - `get_ha(device) -> {"source": "api", "data": {"status": ..., "checksums": ...}}`
  - `get_admins(device) -> {"source": "api", "data": list}`
  - `get_banned_users(device) -> {"source": "api", "data": list}`
  - `get_config_revisions(device) -> {"source": "api", "data": list}`
  - `get_certificates(device) -> {"source": "api", "data": list}`
  - `ADMIN_FIELDS: str` — the projection passed to `api_get_cmdb(fmt=...)`.
  - Routes `GET /api/fortigate/{ip}/system/{resources,ha,admins,banned-users,config-revisions,certificates}`.

- [ ] **Step 1: Write the failing service test**

Append to `tests/test_fortigate_service.py`:

```python
class SystemGroupTest(unittest.TestCase):
    @mock.patch("services.fortigate_service.api_get")
    def test_resources_merges_usage_and_time(self, mock_api_get):
        mock_api_get.side_effect = [{"results": {"cpu": 7}}, {"results": {"time": 1}}]
        res = fgs.get_system_resources(DEVICE)
        self.assertEqual([c[0][1] for c in mock_api_get.call_args_list],
                         ["monitor/system/resource/usage", "monitor/system/time"])
        self.assertEqual(res["data"]["usage"], {"cpu": 7})
        self.assertEqual(res["data"]["time"], {"time": 1})

    @mock.patch("services.fortigate_service.api_get")
    def test_ha_merges_status_and_checksums(self, mock_api_get):
        mock_api_get.side_effect = [{"results": {"mode": "a-p"}}, {"results": {"cs": "x"}}]
        res = fgs.get_ha(DEVICE)
        self.assertEqual(res["data"]["status"], {"mode": "a-p"})
        self.assertEqual(res["data"]["checksums"], {"cs": "x"})

    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_admins_are_projected(self, mock_cmdb):
        mock_cmdb.return_value = {"results": [{"name": "admin"}]}
        fgs.get_admins(DEVICE)
        self.assertEqual(mock_cmdb.call_args[0][1], "cmdb/system/admin")
        self.assertEqual(mock_cmdb.call_args[1]["fmt"], fgs.ADMIN_FIELDS)

    def test_admin_projection_carries_no_secret(self):
        # La proiezione è l'unica barriera fra gli account admin del
        # FortiGate e il browser: nessun campo che possa contenere una
        # credenziale deve comparirci.
        for banned in ("password", "passwd", "secret", "key", "hash"):
            self.assertNotIn(banned, fgs.ADMIN_FIELDS.lower())

    @mock.patch("services.fortigate_service.api_get")
    def test_simple_monitor_getters_hit_the_right_paths(self, mock_api_get):
        mock_api_get.return_value = {"results": []}
        for fn, path in ((fgs.get_banned_users, "monitor/user/banned"),
                         (fgs.get_config_revisions, "monitor/system/config-revision"),
                         (fgs.get_certificates, "monitor/system/available-certificates")):
            fn(DEVICE)
            self.assertEqual(mock_api_get.call_args[0][1], path)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_fortigate_service.SystemGroupTest -v`

Expected: FAIL — `AttributeError: ... has no attribute 'get_system_resources'`

- [ ] **Step 3: Implement the six functions**

In `services/fortigate_service.py`, after `get_system_status` (~line 322):

```python
# --- Sistema: risorse, HA, account, revisioni, certificati -------------------
# Sola REST: nessuno di questi ha un equivalente CLI 1:1 affidabile, quindi
# niente fallback SSH (stessa scelta di policy_lookup e dell'inventario cmdb).

# Proiezione degli account amministrativi. È l'unica barriera fra gli account
# del FortiGate e il browser: elencare i campi voluti, mai filtrare quelli
# indesiderati dalla risposta, perché una versione futura di FortiOS potrebbe
# aggiungerne uno nuovo che nessuno ha pensato di escludere.
ADMIN_FIELDS = "name|accprofile|trusthost1|trusthost2|two-factor|comments"


def get_system_resources(device):
    """Uso CPU/memoria/disco/sessioni più l'ora di sistema, in una risposta
    sola: la Overview ne fa una card, non quattro richieste."""
    ip = device["IP"]
    return {"source": "api",
            "data": {"usage": api_get(ip, "monitor/system/resource/usage").get("results"),
                     "time": api_get(ip, "monitor/system/time").get("results")}}


def get_ha(device):
    """Stato HA e checksum di sincronizzazione insieme: due cluster allineati
    ma con checksum diversi sono il caso che conta, e serve vederli vicini."""
    return {"source": "api",
            "data": {"status": get_ha_status(device).get("results"),
                     "checksums": get_ha_checksums(device).get("results")}}


def get_admins(device):
    """Account amministrativi (cmdb/system/admin), proiettati su ADMIN_FIELDS:
    nessuna credenziale lascia questa funzione."""
    data = api_get_cmdb(device["IP"], "cmdb/system/admin", fmt=ADMIN_FIELDS)
    return {"source": "api", "data": data.get("results", data)}


def get_banned_users(device):
    """Utenti/IP bannati dalle azioni di quarantena FortiOS."""
    data = api_get(device["IP"], "monitor/user/banned")
    return {"source": "api", "data": data.get("results", data)}


def get_config_revisions(device):
    """Revisioni di configurazione salvate a bordo (config-revision)."""
    data = api_get(device["IP"], "monitor/system/config-revision")
    return {"source": "api", "data": data.get("results", data)}


def get_certificates(device):
    """Certificati disponibili con scadenza. Endpoint monitor: metadati e
    scadenza, mai il materiale della chiave privata."""
    data = api_get(device["IP"], "monitor/system/available-certificates")
    return {"source": "api", "data": data.get("results", data)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_fortigate_service.SystemGroupTest -v`

Expected: PASS, 5 tests.

- [ ] **Step 5: Add the six routes**

In `routers/fortigate.py`, after `fgt_status` (~line 148):

```python
@router.get("/api/fortigate/{ip}/system/resources")
def fgt_system_resources(ip: str, current_user = Depends(get_current_user)):
    """Uso CPU/memoria/disco/sessioni e ora di sistema."""
    return _fgt_call(fortigate_service.get_system_resources, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/system/ha")
def fgt_system_ha(ip: str, current_user = Depends(get_current_user)):
    """Stato HA e checksum di sincronizzazione del cluster."""
    return _fgt_call(fortigate_service.get_ha, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/system/admins")
def fgt_system_admins(ip: str, current_user = Depends(require_admin)):
    """Account amministrativi del FortiGate (proiettati: nessuna credenziale).
    Admin-only: è l'elenco di chi può amministrare il firewall."""
    log_audit(f"Elenco admin FortiGate richiesto per '{ip}' da '{current_user.get('sub')}'.")
    return _fgt_call(fortigate_service.get_admins, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/system/banned-users")
def fgt_system_banned_users(ip: str, current_user = Depends(get_current_user)):
    """Utenti/IP in quarantena."""
    return _fgt_call(fortigate_service.get_banned_users, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/system/config-revisions")
def fgt_system_config_revisions(ip: str, current_user = Depends(get_current_user)):
    """Revisioni di configurazione salvate a bordo."""
    return _fgt_call(fortigate_service.get_config_revisions, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/system/certificates")
def fgt_system_certificates(ip: str, current_user = Depends(get_current_user)):
    """Certificati disponibili con data di scadenza."""
    return _fgt_call(fortigate_service.get_certificates, _fgt_device(ip, current_user))
```

- [ ] **Step 6: Run parity and watch it fail**

Run: `uv run python -m unittest tests.test_router_parity -v`

Expected: FAIL — `test_no_unexpected_new_paths` lists the six `/api/fortigate/{ip}/system/...` paths.

- [ ] **Step 7: Allowlist the new prefix**

In `tests/test_router_parity.py:58`, append `"/api/fortigate/{ip}/system"` to `TestRouterParity.ALLOWED_NEW_PREFIXES`.

In `tests/test_router_parity.py:130`, append `"/api/fortigate/{ip}/system"` to `TestFullParity.NEW_PREFIXES`.

- [ ] **Step 8: Write the route-auth test**

Create `tests/test_fortigate_management.py`:

```python
# -*- coding: utf-8 -*-
"""Guardie della tab Fortigate Management: chi può chiamare cosa, e cosa
non deve mai uscire dal service."""
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_fgtmgmt_"))

import app_server  # noqa: E402
from routers import deps  # noqa: E402


def _dependency_names(path: str, method: str = "get"):
    for route in app_server.app.routes:
        if getattr(route, "path", None) == path and method.upper() in getattr(route, "methods", ()):
            return {d.call.__name__ for d in route.dependant.dependencies if d.call}
    raise AssertionError(f"rotta non trovata: {method.upper()} {path}")


class AdminOnlyRoutesTest(unittest.TestCase):
    def test_admin_list_is_admin_only(self):
        # L'elenco di chi amministra il firewall non è dato da operatore.
        self.assertIn(deps.require_admin.__name__,
                      _dependency_names("/api/fortigate/{ip}/system/admins"))

    def test_full_config_stays_operator(self):
        self.assertIn(deps.require_operator.__name__,
                      _dependency_names("/api/fortigate/{ip}/full-config"))

    def test_read_only_views_are_open_to_authenticated_users(self):
        for path in ("/api/fortigate/{ip}/system/resources",
                     "/api/fortigate/{ip}/system/ha",
                     "/api/fortigate/{ip}/system/certificates"):
            names = _dependency_names(path)
            self.assertNotIn(deps.require_admin.__name__, names, path)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 9: Run the new test**

Run: `uv run python -m unittest tests.test_fortigate_management -v`

Expected: PASS, 3 tests. If `_dependency_names` returns an empty set for a route, the auth dependency is declared as a default argument rather than a `Depends` in the signature — re-read how `require_admin` is wired in the neighbouring routes before adjusting the helper.

- [ ] **Step 10: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

- [ ] **Step 11: Commit**

```bash
git add services/fortigate_service.py routers/fortigate.py tests/test_fortigate_service.py tests/test_fortigate_management.py tests/test_router_parity.py
git commit -m "feat(fortigate): system reads (resources, HA, admins, certs, revisions)

Six read-only getters over the existing REST transport. get_admins
projects on ADMIN_FIELDS and its route is admin-only: the projection is
the only barrier between the firewall's admin accounts and the browser,
so it allowlists fields instead of filtering them out.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: VPN tunnels and SD-WAN health

`get_vpn_tunnels` exists (`services/fortigate_service.py:449`) but has never had a route.

**Files:**
- Modify: `services/fortigate_service.py` (after `get_vpn_tunnels`, ~line 457)
- Modify: `routers/fortigate.py`
- Modify: `tests/test_router_parity.py:58`, `tests/test_router_parity.py:130`
- Test: `tests/test_fortigate_service.py`

**Interfaces:**
- Consumes: `get_vpn_tunnels(device)` (existing), `_api_or_ssh(device, api_path, api_params, ssh_cmd)`.
- Produces: `get_sdwan_health(device) -> {"source": "api", "data": ...}`; routes `GET /api/fortigate/{ip}/vpn/tunnels` and `GET /api/fortigate/{ip}/sdwan/health`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fortigate_service.py`:

```python
class SdwanHealthTest(unittest.TestCase):
    @mock.patch("services.fortigate_service.api_get")
    def test_hits_the_documented_health_check_path(self, mock_api_get):
        # Percorso confermato da docs/reference/fortios/rest-api.md.
        mock_api_get.return_value = {"results": {}}
        fgs.get_sdwan_health(DEVICE)
        self.assertEqual(mock_api_get.call_args[0][1], "monitor/virtual-wan/health-check")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_fortigate_service.SdwanHealthTest -v`

Expected: FAIL — no attribute `get_sdwan_health`.

- [ ] **Step 3: Implement**

In `services/fortigate_service.py`, after `get_vpn_tunnels` (~line 457):

```python
def get_sdwan_health(device):
    """Qualità dei link SD-WAN (latenza, jitter, packet loss per SLA).

    Un FortiGate senza SD-WAN configurata risponde 404 e questa solleva
    FortiGateError: è corretto, la tab lo rende come pannello vuoto invece
    che come errore."""
    data = api_get(device["IP"], "monitor/virtual-wan/health-check")
    return {"source": "api", "data": data.get("results", data)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_fortigate_service.SdwanHealthTest -v`

Expected: PASS.

- [ ] **Step 5: Add both routes**

In `routers/fortigate.py`, after `fgt_routes` (~line 207):

```python
@router.get("/api/fortigate/{ip}/vpn/tunnels")
def fgt_vpn_tunnels(ip: str, current_user = Depends(get_current_user)):
    """Stato vivo dei tunnel IPsec: quali stanno in piedi adesso, non quali
    sono configurati."""
    return _fgt_call(fortigate_service.get_vpn_tunnels, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/sdwan/health")
def fgt_sdwan_health(ip: str, current_user = Depends(get_current_user)):
    """Qualità dei link SD-WAN (latenza, jitter, perdita per SLA)."""
    return _fgt_call(fortigate_service.get_sdwan_health, _fgt_device(ip, current_user))
```

- [ ] **Step 6: Allowlist both prefixes**

In `tests/test_router_parity.py:58`, append `"/api/fortigate/{ip}/vpn"` and `"/api/fortigate/{ip}/sdwan"` to `TestRouterParity.ALLOWED_NEW_PREFIXES`.

In `tests/test_router_parity.py:130`, append the same two to `TestFullParity.NEW_PREFIXES`.

- [ ] **Step 7: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

- [ ] **Step 8: Commit**

```bash
git add services/fortigate_service.py routers/fortigate.py tests/test_fortigate_service.py tests/test_router_parity.py
git commit -m "feat(fortigate): route VPN tunnel state, add SD-WAN health

get_vpn_tunnels had existed since the diagnosis work with no route at
all. SD-WAN health-check path is the one documented in
docs/reference/fortios/rest-api.md.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: Firewall object groups, VIPs, pools, security profiles

**Files:**
- Modify: `services/fortigate_service.py` (after `get_firewall_custom_services`, ~line 402)
- Modify: `routers/fortigate.py`
- Test: `tests/test_fortigate_service.py`

**Interfaces:**
- Consumes: `api_get_cmdb(ip, path, fmt=None)`, `FortiGateError`.
- Produces: `get_address_groups`, `get_service_groups`, `get_vips`, `get_ip_pools`, `get_security_profiles` — each `(device) -> {"source": "api", "data": ...}`. Routes under `GET /api/fortigate/{ip}/firewall/{address-groups,service-groups,vips,ip-pools,security-profiles}`. No parity edit: the prefix is already allowlisted.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_fortigate_service.py`:

```python
class FirewallObjectsTest(unittest.TestCase):
    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_each_getter_hits_its_cmdb_path(self, mock_cmdb):
        mock_cmdb.return_value = {"results": []}
        for fn, path in ((fgs.get_address_groups, "cmdb/firewall/addrgrp"),
                         (fgs.get_service_groups, "cmdb/firewall.service/group"),
                         (fgs.get_vips, "cmdb/firewall/vip"),
                         (fgs.get_ip_pools, "cmdb/firewall/ippool")):
            fn(DEVICE)
            self.assertEqual(mock_cmdb.call_args[0][1], path)

    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_security_profiles_aggregate_four_families(self, mock_cmdb):
        mock_cmdb.return_value = {"results": [{"name": "default"}]}
        res = fgs.get_security_profiles(DEVICE)
        self.assertEqual(set(res["data"]), {"antivirus", "ips", "webfilter", "application"})
        self.assertEqual(res["data"]["antivirus"], [{"name": "default"}])

    @mock.patch("services.fortigate_service.api_get_cmdb")
    def test_a_missing_profile_family_does_not_sink_the_others(self, mock_cmdb):
        # Una licenza senza IPS non deve svuotare antivirus e webfilter.
        mock_cmdb.side_effect = [{"results": [{"name": "av"}]},
                                 fgs.FortiGateError("404 ips"),
                                 {"results": []}, {"results": []}]
        res = fgs.get_security_profiles(DEVICE)
        self.assertEqual(res["data"]["antivirus"], [{"name": "av"}])
        self.assertEqual(res["data"]["ips"], [])
        self.assertIn("ips", res["errors"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_fortigate_service.FirewallObjectsTest -v`

Expected: FAIL — no attribute `get_address_groups`.

- [ ] **Step 3: Implement**

In `services/fortigate_service.py`, after `get_firewall_custom_services` (~line 402):

```python
def get_address_groups(device):
    """Gruppi di indirizzi: nome, membri, commento."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall/addrgrp",
                        fmt="name|member|comment")
    return {"source": "api", "data": data.get("results", data)}


def get_service_groups(device):
    """Gruppi di servizi."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall.service/group",
                        fmt="name|member|comment")
    return {"source": "api", "data": data.get("results", data)}


def get_vips(device):
    """Virtual IP (DNAT): da quale indirizzo esterno a quale interno."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall/vip",
                        fmt="name|extip|extintf|mappedip|portforward|"
                            "extport|mappedport|protocol|comment")
    return {"source": "api", "data": data.get("results", data)}


def get_ip_pools(device):
    """IP pool (SNAT)."""
    data = api_get_cmdb(device["IP"], "cmdb/firewall/ippool",
                        fmt="name|type|startip|endip|comments")
    return {"source": "api", "data": data.get("results", data)}


# Famiglie di profili di sicurezza: chiave usata dalla UI -> percorso cmdb.
_SECURITY_PROFILES = {
    "antivirus": "cmdb/antivirus/profile",
    "ips": "cmdb/ips/sensor",
    "webfilter": "cmdb/webfilter/profile",
    "application": "cmdb/application/list",
}


def get_security_profiles(device):
    """Profili di sicurezza per famiglia.

    Una famiglia che manca (licenza senza IPS, feature non abilitata)
    risponde 404: si registra in ``errors`` e le altre passano comunque.
    Fallire tutto perché una sola manca renderebbe il pannello inutile
    sulla metà dei FortiGate."""
    out, errors = {}, {}
    for key, path in _SECURITY_PROFILES.items():
        try:
            data = api_get_cmdb(device["IP"], path, fmt="name|comment")
            out[key] = data.get("results", data)
        except FortiGateError as e:
            out[key] = []
            errors[key] = str(e)
    return {"source": "api", "data": out, "errors": errors}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_fortigate_service.FirewallObjectsTest -v`

Expected: PASS, 3 tests.

- [ ] **Step 5: Add the five routes**

In `routers/fortigate.py`, after `fgt_firewall_policies_with_stats` (added in Task 2):

```python
@router.get("/api/fortigate/{ip}/firewall/address-groups")
def fgt_firewall_address_groups(ip: str, current_user = Depends(get_current_user)):
    """Gruppi di indirizzi, sola lettura."""
    return _fgt_call(fortigate_service.get_address_groups, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/firewall/service-groups")
def fgt_firewall_service_groups(ip: str, current_user = Depends(get_current_user)):
    """Gruppi di servizi, sola lettura."""
    return _fgt_call(fortigate_service.get_service_groups, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/firewall/vips")
def fgt_firewall_vips(ip: str, current_user = Depends(get_current_user)):
    """Virtual IP (DNAT), sola lettura."""
    return _fgt_call(fortigate_service.get_vips, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/firewall/ip-pools")
def fgt_firewall_ip_pools(ip: str, current_user = Depends(get_current_user)):
    """IP pool (SNAT), sola lettura."""
    return _fgt_call(fortigate_service.get_ip_pools, _fgt_device(ip, current_user))

@router.get("/api/fortigate/{ip}/firewall/security-profiles")
def fgt_firewall_security_profiles(ip: str, current_user = Depends(get_current_user)):
    """Profili di sicurezza (antivirus, IPS, webfilter, application control)."""
    return _fgt_call(fortigate_service.get_security_profiles, _fgt_device(ip, current_user))
```

- [ ] **Step 6: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

Expected: all green, including parity — these paths need no allowlist edit.

- [ ] **Step 7: Commit**

```bash
git add services/fortigate_service.py routers/fortigate.py tests/test_fortigate_service.py
git commit -m "feat(fortigate): address/service groups, VIPs, IP pools, profiles

Completes the firewall object view: you could already see addresses but
not the groups referencing them. Security profiles degrade per family so
a licence without IPS still shows antivirus and webfilter.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

# Phase 3 — Tab rebuild

### Task 6: Smoke-check the new endpoints against a real FortiGate

Only `monitor/virtual-wan/health-check` is confirmed by `docs/reference/fortios/rest-api.md:29`. The other paths are standard FortiOS 7.x but unverified here, and a wrong path silently becomes an empty panel.

**Files:** none — this is a verification gate before UI work.

- [ ] **Step 1: Call each new route against a configured target**

With the app running and a FortiGate target configured, for each of the eleven new paths, record HTTP status and whether `data` is non-empty. `404` from FortiOS surfaces as HTTP 502.

- [ ] **Step 2: Classify every non-200**

For each failure decide: **wrong path** (fix the service function and its test) or **feature absent on this box** (expected — the UI renders an empty panel, see Task 10 Step 3). Write the verdict per endpoint into the task notes.

- [ ] **Step 3: Fix any wrong paths and re-run their unit tests**

If a path was wrong, correct the service function, update the asserted path in `tests/test_fortigate_service.py`, and re-run that test class.

- [ ] **Step 4: Commit only if something changed**

```bash
git add services/fortigate_service.py tests/test_fortigate_service.py
git commit -m "fix(fortigate): correct API paths found by smoke check

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

If nothing changed, skip the commit and note that all eleven paths verified clean.

---

### Task 7: Rename and de-gate

**Files:**
- Rename: `static/js/fortigate-preview.js` → `static/js/fortigate-management.js`
- Modify: `templates/dashboard.html:188-191` (nav), `:2113-2116` (toggle), `:2160-2164` (tab open), `:3097` (script tag)
- Modify: `static/js/core.js:462-463`, `:584`
- Modify: `routers/settings.py:85-96`
- Modify: `tests/test_router_parity.py:58`, `:130`
- Modify: `tests/test_ui_revamp.py:963`, `:986`, `:1085`, `:1101`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: tab id `tab-fortigate`, nav id `navFortigate`, entry point `loadFgtTab()` (renamed from `loadFgtPreviewTab()`). Tasks 9 and 10 build inside `#tab-fortigate`.

- [ ] **Step 1: Rename the file and its script tag**

```bash
git mv static/js/fortigate-preview.js static/js/fortigate-management.js
```

In `templates/dashboard.html:3097`: `<script src="/static/js/fortigate-management.js"></script>`

- [ ] **Step 2: Delete the gating code**

In `static/js/fortigate-management.js`, delete `applyFgtPreviewGating()` (lines 30-39) and `setFgtPreview()` (lines 41-56) entirely, along with the `--- Gating ---` and `--- Toggle preview ---` comment banners.

Rename `loadFgtPreviewTab()` → `loadFgtTab()`.

Update the file's header comment: it currently says the tab is admin-gated behind a preview flag, which stops being true.

- [ ] **Step 3: Delete the call sites**

In `static/js/core.js`, delete lines 462-463:

```js
    if (currentRole === 'admin' && typeof applyFgtPreviewGating === 'function') {
        try { await applyFgtPreviewGating(); } catch (e) { /* non bloccante */ }
    }
```

In `static/js/core.js:584`, replace:

```js
    else if(tabId === 'tab-fortigate') loadFgtTab();
```

- [ ] **Step 4: Delete the settings endpoints**

In `routers/settings.py`, delete both handlers at lines 85-96 (`get_fortigate_preview_settings`, `set_fortigate_preview_settings`) and the now-unused `FortigatePreviewSchema` class. Search the file for `fortigate_preview_enabled` and remove any remaining reference.

- [ ] **Step 5: Rename tab and nav in the markup**

In `templates/dashboard.html:188-191`, replace the nav button:

```html
        <button id="navFortigate" class="nav-item requires-admin" onclick="switchTab('tab-fortigate', this)">
          <span class="nav-left" data-i18n="tabFgtManagement"><i class="fa-solid fa-shield-halved"></i> Fortigate Management</span>
        </button>
```

(The `style="display:none;"` and the `preview-badge` span are both gone.)

At `:2160`, `<div id="tab-fortigate-preview"` becomes `<div id="tab-fortigate"`.

At `:2163-2164`, drop the `<span class="preview-badge">preview</span>` from the eyebrow and point the heading at the new i18n keys `fgtEyebrow` / `titleFgtTab` / `descFgtTab` (defined in Task 9).

Delete the toggle block at `:2113-2116` from the MCP settings tab.

- [ ] **Step 6: Run parity and watch it fail**

Run: `uv run python -m unittest tests.test_router_parity -v`

Expected: FAIL — `TestFullParity.test_path_set_identical` reports that `/api/settings/fortigate-preview` is in the snapshot but not in the current app.

- [ ] **Step 7: Record the removal**

In `tests/test_router_parity.py:58`, **delete** `"/api/settings/fortigate-preview"` from `TestRouterParity.ALLOWED_NEW_PREFIXES` — it no longer exists, so permitting it is stale.

In `tests/test_router_parity.py:130`, **add** `"/api/settings/fortigate-preview"` to `TestFullParity.NEW_PREFIXES` with this comment above the tuple:

```python
    # NEW_PREFIXES filtra entrambi i lati del confronto, quindi copre anche
    # i percorsi RIMOSSI: /api/settings/fortigate-preview era il flag della
    # tab FortiGate in anteprima, sparito quando la tab è diventata normale.
```

- [ ] **Step 8: Fix the stale UI comments**

In `tests/test_ui_revamp.py`, update the four comments at lines 963, 986, 1085 and 1101 to say `static/js/fortigate-management.js` and "Fortigate Management tab" instead of "FortiGate LIVE (preview)". These are comments only — the two live assertions (`apiFetch('/api/fortigate/tokens')`, `apiFetch('/api/fortigate/token'`) still hold because the token panel survives.

- [ ] **Step 9: Verify nothing references the old names**

```sh
git grep -n "fortigate-preview\|fgtPreview\|FgtPreview\|fortigate_preview\|tab-fortigate-preview"
```

Expected: no hits outside `docs/`. Any hit in `static/`, `routers/`, `templates/` or `tests/` is a miss — fix it before committing.

- [ ] **Step 10: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "refactor(fortigate): promote the preview tab to Fortigate Management

Deletes the fortigate_preview_enabled flag, its two settings endpoints
and the MCP-tab toggle rather than leaving a stub. The nav item keeps
requires-admin. TestFullParity.NEW_PREFIXES filters both sides of the
comparison, so it covers the removed settings path too.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: Dataset registry, loader and renderer

Replaces the three-view `FGT_OBJ_COLUMNS` machinery with one registry covering every read view.

**Files:**
- Modify: `static/js/fortigate-management.js` (replace lines 8-28 and 212-290 of the original file)
- Modify: `tests/test_fortigate_management.py`

**Interfaces:**
- Consumes: routes from Tasks 2-5; `apiFetch`, `escapeHtml`, `jsStr`, `showToast`, `i18n`, `currentLang` from `core.js` / `mcp-client.js`.
- Produces:
  - `FGT_DATASETS` — object keyed by dataset name; each value `{url: (ip) => string, method?: 'POST', body?: () => object, cols: [key, i18nKey][], pick?: (data) => any}`.
  - `loadFgtDataset(key)` — fetches into `fgtDatasetRows[key]`, then renders.
  - `renderFgtDataset(key)` — renders into `#fgtView-<key>`.
  - Task 10 calls `loadFgtDataset` from the sub-tab switchers.

- [ ] **Step 1: Write the failing registry test**

Append to `tests/test_fortigate_management.py`:

```python
import re  # noqa: E402  (in cima al file, accanto agli altri import)


def _js() -> str:
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(base, "static", "js", "fortigate-management.js"),
              encoding="utf-8") as f:
        return f.read()


class DatasetRegistryTest(unittest.TestCase):
    """Il registro è l'unica cosa che sa quale URL serve una vista: un
    percorso sbagliato lì diventa un pannello vuoto in produzione, non un
    errore. Si verifica qui, contro l'OpenAPI vera."""

    @classmethod
    def setUpClass(cls):
        src = _js()
        # Solo il blocco del registro: il resto del file contiene la PUT
        # legittima che aggiorna un target FortiGate (saveFgtMgrTarget), che
        # non è una vista e non deve far scattare il controllo di sola lettura.
        start = src.index("const FGT_DATASETS = {")
        cls.registry = src[start:src.index("\n};", start)]
        cls.paths = set(app_server.app.openapi()["paths"])

    def test_every_dataset_url_exists_in_the_openapi(self):
        # url: ip => `/api/fortigate/${ip}/qualcosa`  ->  /api/fortigate/{ip}/qualcosa
        urls = re.findall(r"url:\s*ip\s*=>\s*`([^`]+)`", self.registry)
        self.assertGreaterEqual(len(urls), 15, "registro troppo piccolo: parsing rotto?")
        for u in urls:
            path = u.replace("${ip}", "{ip}")
            self.assertIn(path, self.paths, f"dataset punta a una rotta inesistente: {path}")

    def test_no_dataset_declares_a_write_method(self):
        # La tab è di sola lettura: POST è ammesso solo per le query
        # (sessions, logs, policy-lookup), mai PUT/DELETE/PATCH.
        for verb in ("'PUT'", "'DELETE'", "'PATCH'"):
            self.assertNotIn(verb, self.registry, f"metodo di scrittura nel registro: {verb}")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_fortigate_management.DatasetRegistryTest -v`

Expected: FAIL on `test_every_dataset_url_exists_in_the_openapi` — the registry does not exist, so `len(urls)` is 0.

- [ ] **Step 3: Write the registry**

In `static/js/fortigate-management.js`, replace the `FGT_OBJ_COLUMNS` / `FGT_OBJ_ENDPOINT` block (original lines 8-28) with:

```js
// Registro delle viste di sola lettura. Ogni voce dice DOVE prendere i dati
// e QUALI colonne mostrarne: un solo loader e un solo renderer li servono
// tutte, aggiungerne una costa tre righe. `pick` estrae il ramo giusto per
// le risposte annidate (risorse, HA, profili).
const FGT_DATASETS = {
    // --- Network ---
    interfaces:   { url: ip => `/api/fortigate/${ip}/interfaces`,
                    cols: [['name','colFgtIfName'], ['ip','colFgtIfIp'], ['status','colFgtIfStatus'],
                           ['speed','colFgtIfSpeed'], ['duplex','colFgtIfDuplex'], ['alias','colFgtIfAlias']] },
    arp:          { url: ip => `/api/fortigate/${ip}/arp`,
                    cols: [['ip','colFgtArpIp'], ['mac','colFgtArpMac'], ['interface','colFgtArpIntf'], ['age','colFgtArpAge']] },
    dhcp:         { url: ip => `/api/fortigate/${ip}/dhcp-leases`,
                    cols: [['ip','colFgtDhcpIp'], ['mac','colFgtDhcpMac'], ['hostname','colFgtDhcpHost'],
                           ['expire_time','colFgtDhcpExpire'], ['interface','colFgtDhcpIntf']] },
    routes:       { url: ip => `/api/fortigate/${ip}/routes`,
                    cols: [['ip_mask','colFgtRouteDest'], ['gateway','colFgtRouteGw'], ['interface','colFgtRouteIntf'],
                           ['type','colFgtRouteType'], ['distance','colFgtRouteDist'], ['metric','colFgtRouteMetric']] },
    vpn:          { url: ip => `/api/fortigate/${ip}/vpn/tunnels`,
                    cols: [['name','colFgtVpnName'], ['rgwy','colFgtVpnPeer'], ['status','colFgtVpnStatus'],
                           ['incoming_bytes','colFgtVpnIn'], ['outgoing_bytes','colFgtVpnOut']] },
    sdwan:        { url: ip => `/api/fortigate/${ip}/sdwan/health`,
                    cols: [['name','colFgtSdwanName'], ['status','colFgtSdwanStatus'], ['latency','colFgtSdwanLatency'],
                           ['jitter','colFgtSdwanJitter'], ['packet_loss','colFgtSdwanLoss']] },
    // --- Firewall ---
    addresses:    { url: ip => `/api/fortigate/${ip}/firewall/addresses`,
                    cols: [['name','colFgtAddrName'], ['type','colFgtAddrType'], ['subnet','colFgtAddrSubnet'],
                           ['fqdn','colFgtAddrFqdn'], ['comment','colFgtAddrComment']] },
    addressGroups:{ url: ip => `/api/fortigate/${ip}/firewall/address-groups`,
                    cols: [['name','colFgtGrpName'], ['member','colFgtGrpMembers'], ['comment','colFgtGrpComment']] },
    services:     { url: ip => `/api/fortigate/${ip}/firewall/services`,
                    cols: [['name','colFgtSvcName'], ['tcp-portrange','colFgtSvcTcp'],
                           ['udp-portrange','colFgtSvcUdp'], ['comment','colFgtSvcComment']] },
    serviceGroups:{ url: ip => `/api/fortigate/${ip}/firewall/service-groups`,
                    cols: [['name','colFgtGrpName'], ['member','colFgtGrpMembers'], ['comment','colFgtGrpComment']] },
    vips:         { url: ip => `/api/fortigate/${ip}/firewall/vips`,
                    cols: [['name','colFgtVipName'], ['extip','colFgtVipExt'], ['mappedip','colFgtVipMapped'],
                           ['extintf','colFgtVipIntf'], ['portforward','colFgtVipPf'], ['comment','colFgtVipComment']] },
    ipPools:      { url: ip => `/api/fortigate/${ip}/firewall/ip-pools`,
                    cols: [['name','colFgtPoolName'], ['type','colFgtPoolType'],
                           ['startip','colFgtPoolStart'], ['endip','colFgtPoolEnd']] },
    policies:     { url: ip => `/api/fortigate/${ip}/firewall/policies-with-stats`,
                    cols: [['policyid','colFgtPolId'], ['name','colFgtPolName'],
                           ['srcintf','colFgtPolSrcIntf'], ['dstintf','colFgtPolDstIntf'],
                           ['srcaddr','colFgtPolSrcAddr'], ['dstaddr','colFgtPolDstAddr'],
                           ['service','colFgtPolService'], ['action','colFgtPolAction'],
                           ['status','colFgtPolStatus'], ['hit_count','colFgtPolHits'],
                           ['active_sessions','colFgtPolSessions'], ['last_used','colFgtPolLastUsed']] },
    // Quale policy matcherebbe un flusso: risposta a oggetto singolo, resa
    // come tabella chiave/valore (cols vuoto -> ramo isKv del renderer).
    policyLookup: { url: ip => `/api/fortigate/${ip}/policy-lookup`, method: 'POST',
                    body: () => ({ src_ip: _fgtVal('fgtLookupSrc'), dest: _fgtVal('fgtLookupDst'),
                                   protocol: _fgtVal('fgtLookupProto') || 'TCP',
                                   dest_port: parseInt(_fgtVal('fgtLookupPort')) || 443,
                                   srcintf: _fgtVal('fgtLookupIntf') || null }),
                    cols: [] },
    securityProfiles: { url: ip => `/api/fortigate/${ip}/firewall/security-profiles`, cols: [] },
    // --- Traffic ---
    deviceInventory:{ url: ip => `/api/fortigate/${ip}/device-inventory`,
                    cols: [['hostname','colFgtDevHost'], ['mac','colFgtDevMac'], ['ipv4_address','colFgtDevIp'],
                           ['os_name','colFgtDevOs'], ['detected_interface','colFgtDevIntf'], ['is_online','colFgtDevOnline']] },
    sessions:     { url: ip => `/api/fortigate/${ip}/sessions`, method: 'POST',
                    body: () => ({ src_ip: _fgtVal('fgtSessSrc') || null, dst_ip: _fgtVal('fgtSessDst') || null,
                                   dst_port: parseInt(_fgtVal('fgtSessPort')) || null, count: 100 }),
                    cols: [['protocol','colFgtSessProto'], ['source','colFgtSessSrc'], ['source_port','colFgtSessSport'],
                           ['destination','colFgtSessDst'], ['destination_port','colFgtSessDport'],
                           ['policy_id','colFgtSessPolicy'], ['duration','colFgtSessDuration']] },
    logs:         { url: ip => `/api/fortigate/${ip}/logs`, method: 'POST',
                    body: () => ({ src_ip: _fgtVal('fgtLogSrc') || null, dst_ip: _fgtVal('fgtLogDst') || null,
                                   action: _fgtVal('fgtLogAction') || null, count: 100,
                                   log_device: _fgtVal('fgtLogDevice') || 'disk',
                                   log_type: _fgtVal('fgtLogType') || 'traffic',
                                   log_subtype: _fgtVal('fgtLogSubtype') || 'forward',
                                   cli_category: _fgtVal('fgtLogType') || 'traffic' }),
                    cols: [['date','colFgtLogDate'], ['time','colFgtLogTime'], ['srcip','colFgtLogSrc'],
                           ['dstip','colFgtLogDst'], ['dstport','colFgtLogDport'], ['action','colFgtLogAction'],
                           ['policyid','colFgtLogPolicy'], ['service','colFgtLogService']] },
    // --- Security ---
    admins:       { url: ip => `/api/fortigate/${ip}/system/admins`,
                    cols: [['name','colFgtAdminName'], ['accprofile','colFgtAdminProfile'],
                           ['trusthost1','colFgtAdminTrust'], ['two-factor','colFgtAdmin2fa'], ['comments','colFgtAdminComment']] },
    bannedUsers:  { url: ip => `/api/fortigate/${ip}/system/banned-users`,
                    cols: [['ip_address','colFgtBanIp'], ['cause','colFgtBanCause'], ['expires','colFgtBanExpires']] },
    certificates: { url: ip => `/api/fortigate/${ip}/system/certificates`,
                    cols: [['name','colFgtCertName'], ['type','colFgtCertType'], ['status','colFgtCertStatus'],
                           ['valid_to','colFgtCertExpiry'], ['issuer','colFgtCertIssuer']] },
    configRevisions:{ url: ip => `/api/fortigate/${ip}/system/config-revisions`,
                    cols: [['id','colFgtRevId'], ['date','colFgtRevDate'], ['admin','colFgtRevAdmin'], ['comment','colFgtRevComment']] },
    // --- WiFi ---
    wifiAps:      { url: ip => `/api/fortigate/${ip}/wifi/aps`,
                    cols: [['name','colFgtApName'], ['status','colFgtApStatus'], ['ip','colFgtApIp'],
                           ['os_version','colFgtApVersion'], ['clients','colFgtApClients']] },
    wifiClients:  { url: ip => `/api/fortigate/${ip}/wifi/clients`,
                    cols: [['hostname','colFgtWcHost'], ['mac','colFgtWcMac'], ['ip','colFgtWcIp'],
                           ['ssid','colFgtWcSsid'], ['signal','colFgtWcSignal'], ['channel','colFgtWcChannel']] },
    // --- Settings ---
    // Contiene segreti (operator+ lato rotta): mai caricata di default, solo
    // dietro al pulsante esplicito in Impostazioni.
    fullConfig:   { url: ip => `/api/fortigate/${ip}/full-config`, cols: [] },
};

// Valore di un input, stringa vuota se l'elemento non c'è ancora.
function _fgtVal(id) {
    const el = document.getElementById(id);
    return el ? String(el.value || '').trim() : '';
}

let fgtDatasetRows = {};   // key -> { rows, source, apiError, error }
```

- [ ] **Step 4: Write the loader**

Append to `static/js/fortigate-management.js`:

```js
// Un solo loader per tutte le viste. Un dataset che fallisce non è un
// errore della tab: su un FortiGate senza SD-WAN o senza controller WiFi
// il 502 è la risposta giusta, e la vista si rende vuota con il motivo nel
// title invece di sparare un toast rosso.
async function loadFgtDataset(key) {
    const spec = FGT_DATASETS[key];
    const ip = fgtCurrentTarget();
    if (!spec || !ip) return;
    const opts = spec.method === 'POST'
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(spec.body ? spec.body() : {}) }
        : undefined;
    try {
        const res = await apiFetch(spec.url(encodeURIComponent(ip)), opts);
        if (res && res.ok) {
            const body = await res.json();
            const data = spec.pick ? spec.pick(body.data) : body.data;
            fgtDatasetRows[key] = {
                rows: Array.isArray(data) ? data : (data == null ? [] : [data]),
                raw: data, source: body.source, apiError: body.api_error || null, error: null,
            };
        } else {
            const err = res ? await res.json().catch(() => ({})) : {};
            fgtDatasetRows[key] = { rows: [], raw: null, source: null, apiError: null,
                                    error: err.detail || 'HTTP ' + (res ? res.status : '?') };
        }
    } catch (e) {
        fgtDatasetRows[key] = { rows: [], raw: null, source: null, apiError: null, error: String(e) };
    }
    renderFgtDataset(key);
}
```

- [ ] **Step 5: Write the renderer**

Append to `static/js/fortigate-management.js` (this replaces the old `renderFgtPrevObjTable`, which assumed a list and hid the SSH fallback):

```js
// Le risposte del service sono {source, data, api_error?} e `data` può
// essere lista, dict o testo CLI grezzo quando è scattato il fallback SSH.
// Il vecchio renderer conosceva solo il primo caso.
function renderFgtDataset(key) {
    const host = document.getElementById('fgtView-' + key);
    if (!host) return;
    const spec = FGT_DATASETS[key];
    const st = fgtDatasetRows[key];
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    const en = currentLang === 'en';

    if (!st) { host.innerHTML = _fgtEmpty(L.msgFgtNotLoaded || (en ? 'Not loaded.' : 'Non caricato.')); return; }
    if (st.error) {
        host.innerHTML = _fgtEmpty(en ? 'Not available on this device.' : 'Non disponibile su questo dispositivo.', st.error);
        return;
    }

    // Fallback SSH: dirlo. "REST non ha risposto e stiamo leggendo la CLI"
    // non è la stessa cosa di "il firewall ha risposto", e finora la UI lo
    // nascondeva.
    const badge = st.source === 'ssh'
        ? `<div style="margin-bottom:8px;"><span class="status warn" title="${escapeHtml(jsStr(st.apiError || ''))}">
             <i class="fa-solid fa-terminal"></i> ${escapeHtml(L.badgeFgtSshFallback || (en ? 'CLI fallback — REST failed' : 'Fallback CLI — REST fallita'))}</span></div>`
        : '';

    if (typeof st.raw === 'string') {
        host.innerHTML = badge + `<pre style="font-family:var(--font-code); font-size:12px; background:var(--surface);
            border:1px solid var(--border); border-radius:8px; padding:12px; margin:0;
            white-space:pre-wrap; max-height:420px; overflow:auto;">${escapeHtml(jsStr(st.raw))}</pre>`;
        return;
    }
    if (!st.rows.length) { host.innerHTML = badge + _fgtEmpty(L.msgFgtObjEmpty || (en ? 'No data.' : 'Nessun dato.')); return; }

    // Un dict singolo (risorse, HA) diventa una tabella chiave/valore.
    const isKv = st.rows.length === 1 && !spec.cols.some(([k]) => k in (st.rows[0] || {}));
    const filter = (_fgtVal('fgtFilter-' + key) || '').toLowerCase();
    const html = isKv ? _fgtKvTable(st.rows[0]) : _fgtColTable(spec.cols, st.rows, filter, L);
    host.innerHTML = badge + html;
}

function _fgtEmpty(msg, title) {
    return `<div style="text-align:center; padding:20px; color:var(--text-muted); font-size:13px;"
        ${title ? `title="${escapeHtml(jsStr(title))}"` : ''}>${escapeHtml(msg)}</div>`;
}

function _fgtCell(v) {
    if (Array.isArray(v)) v = v.map(x => (x && x.name) || x).join(', ');
    if (v === null || v === undefined || v === '') return '—';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
}

function _fgtKvTable(obj) {
    const rows = Object.entries(obj || {}).map(([k, v]) =>
        `<tr style="border-bottom:1px solid var(--border);">
           <td style="padding:8px 12px; font-weight:600; width:32%;">${escapeHtml(jsStr(k))}</td>
           <td style="padding:8px 12px; font-family:var(--font-code); font-size:12px;">${escapeHtml(jsStr(_fgtCell(v)))}</td>
         </tr>`).join('');
    return `<div class="table-wrap" style="margin-top:0;"><table style="width:100%; font-size:13px; border-collapse:collapse;"><tbody>${rows}</tbody></table></div>`;
}

function _fgtColTable(cols, rows, filter, L) {
    const text = r => cols.map(([k]) => _fgtCell(r ? r[k] : undefined)).join(' ').toLowerCase();
    const shown = filter ? rows.filter(r => text(r).includes(filter)) : rows;
    const head = cols.map(([, lk]) => `<th style="padding:8px 12px; text-align:left;">${escapeHtml(L[lk] || lk)}</th>`).join('');
    const body = shown.map(r => {
        // Una policy con contatore a zero è un rilievo d'audit, non una riga
        // qualunque: si evidenzia.
        const dead = r && r.never_hit ? ' style="color:var(--warning);"' : '';
        const tds = cols.map(([k]) =>
            `<td style="padding:8px 12px; font-family:var(--font-code); font-size:12px;"${dead}>${escapeHtml(jsStr(_fgtCell(r ? r[k] : undefined)))}</td>`).join('');
        return `<tr style="border-bottom:1px solid var(--border);">${tds}</tr>`;
    }).join('');
    return `<div class="table-wrap" style="margin-top:0;">
        <table style="width:100%; font-size:13px; border-collapse:collapse;">
          <thead><tr style="border-bottom:1px solid var(--border); background:var(--surface-3);">${head}</tr></thead>
          <tbody>${body}</tbody>
        </table></div>`;
}
```

- [ ] **Step 6: Delete the superseded renderer**

Delete `switchFgtPrevObjView`, `loadFgtPrevObjects`, `renderFgtPrevObjTable` and the module-level `fgtPrevObjView` / `fgtPrevObjRows` (original lines 212-290). Their three views are now registry entries.

Add `fgtCurrentTarget()` near the top of the target-management section:

```js
// L'IP su cui operano tutte le viste: il target attivo scelto in testa alla tab.
function fgtCurrentTarget() {
    return _fgtVal('fgtTargetSelect');
}
```

- [ ] **Step 7: Run the registry test**

Run: `uv run python -m unittest tests.test_fortigate_management -v`

Expected: PASS. If `test_every_dataset_url_exists_in_the_openapi` names a path, that dataset URL is wrong — fix the registry, not the test.

- [ ] **Step 8: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

- [ ] **Step 9: Commit**

```bash
git add static/js/fortigate-management.js tests/test_fortigate_management.py
git commit -m "feat(fortigate): dataset registry driving every read view

Generalises FGT_OBJ_COLUMNS from three views to twenty-two: one loader,
one renderer, three lines per view. The renderer now handles list, dict
and raw-CLI responses, and shows a badge when the SSH fallback fired --
the old one assumed a list and hid the fallback entirely.

A test walks the registry against the real OpenAPI, so a typo'd endpoint
fails in CI instead of becoming a blank panel.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: Sub-tab markup, CSS and i18n

**Files:**
- Modify: `templates/dashboard.html` (`#tab-fortigate` body)
- Modify: `static/css/dashboard.css:834-836`
- Modify: `static/js/i18n.js` (both `it` ~line 118 and `en` ~line 1281 blocks)

**Interfaces:**
- Consumes: `FGT_DATASETS` keys from Task 8 — each dataset `k` needs a container `<div id="fgtView-k">`.
- Produces: seven panes `#fgtPane-{overview,network,firewall,traffic,security,wifi,settings}` and `fgtSwitchView(name)` (implemented in Task 10).

- [ ] **Step 1: Re-scope the pill CSS**

In `static/css/dashboard.css:834-836`, change the three selectors so the Fortigate tab gets them too — the pills are currently unstyled there because the rules are `#tab-config`-only:

```css
        #tab-config .ca-pill, #tab-fortigate .ca-pill { padding:6px 14px; border-radius:20px; border:1px solid var(--border); background:var(--surface-2); color:var(--text-muted); font-size:12px; cursor:pointer; transition:var(--transition); }
        #tab-config .ca-pill.active, #tab-fortigate .ca-pill.active { background:var(--primary); color:#fff; border-color:var(--primary); }
        #tab-config .ca-pill:hover:not(.active), #tab-fortigate .ca-pill:hover:not(.active) { background:var(--surface-3); }
```

- [ ] **Step 2: Add the i18n keys**

In `static/js/i18n.js`, in the `it` block replace `tabFgtPreview` / `fgtPreviewEyebrow` / `titleFgtPreviewTab` / `descFgtPreviewTab` (lines 118-124) with:

```js
        tabFgtManagement: '<i class="fa-solid fa-shield-halved"></i> Fortigate Management',
        fgtEyebrow: '<i class="fa-solid fa-shield-halved"></i> Integrazioni',
        titleFgtTab: 'Fortigate Management',
        descFgtTab: 'Stato, rete, policy, traffico e WiFi dei FortiGate in tempo reale. Sola lettura: nessuna modifica viene scritta sul firewall, e i token non vengono mai restituiti al browser.',
        fgtSubOverview: 'Panoramica', fgtSubNetwork: 'Rete', fgtSubFirewall: 'Firewall',
        fgtSubTraffic: 'Traffico', fgtSubSecurity: 'Sicurezza', fgtSubWifi: 'WiFi',
        fgtSubSettings: 'Impostazioni',
        badgeFgtSshFallback: 'Fallback CLI — REST fallita',
        msgFgtNotLoaded: 'Non caricato.',
```

Mirror in the `en` block (lines 1281-1287):

```js
        tabFgtManagement: '<i class="fa-solid fa-shield-halved"></i> Fortigate Management',
        fgtEyebrow: '<i class="fa-solid fa-shield-halved"></i> Integrations',
        titleFgtTab: 'Fortigate Management',
        descFgtTab: 'FortiGate status, network, policies, traffic and WiFi in real time. Read-only: nothing is written back to the firewall, and tokens are never returned to the browser.',
        fgtSubOverview: 'Overview', fgtSubNetwork: 'Network', fgtSubFirewall: 'Firewall',
        fgtSubTraffic: 'Traffic', fgtSubSecurity: 'Security', fgtSubWifi: 'WiFi',
        fgtSubSettings: 'Settings',
        badgeFgtSshFallback: 'CLI fallback — REST failed',
        msgFgtNotLoaded: 'Not loaded.',
```

- [ ] **Step 3: Add every column label key**

Add to **both** blocks one entry per `i18nKey` used in `FGT_DATASETS` (Task 8, Step 3) that does not already exist. The pre-existing ones are `colFgtAddr*`, `colFgtPol*` (id/name/srcintf/dstintf/srcaddr/dstaddr/service/action/status) and `colFgtSvc*` — reuse those, do not duplicate them.

New keys needed, Italian then English:

```
colFgtIfName Nome / Name          colFgtIfIp IP / IP              colFgtIfStatus Stato / Status
colFgtIfSpeed Velocità / Speed    colFgtIfDuplex Duplex / Duplex  colFgtIfAlias Alias / Alias
colFgtArpIp IP / IP               colFgtArpMac MAC / MAC          colFgtArpIntf Interfaccia / Interface
colFgtArpAge Età / Age            colFgtDhcpIp IP / IP            colFgtDhcpMac MAC / MAC
colFgtDhcpHost Hostname / Hostname                                colFgtDhcpExpire Scadenza / Expires
colFgtDhcpIntf Interfaccia / Interface                            colFgtRouteDest Destinazione / Destination
colFgtRouteGw Gateway / Gateway   colFgtRouteIntf Interfaccia / Interface
colFgtRouteType Tipo / Type       colFgtRouteDist Distanza / Distance
colFgtRouteMetric Metrica / Metric                                colFgtVpnName Tunnel / Tunnel
colFgtVpnPeer Peer / Peer         colFgtVpnStatus Stato / Status  colFgtVpnIn Byte in / Bytes in
colFgtVpnOut Byte out / Bytes out colFgtSdwanName Link / Link     colFgtSdwanStatus Stato / Status
colFgtSdwanLatency Latenza / Latency                              colFgtSdwanJitter Jitter / Jitter
colFgtSdwanLoss Perdita / Loss    colFgtGrpName Nome / Name       colFgtGrpMembers Membri / Members
colFgtGrpComment Commento / Comment                               colFgtVipName Nome / Name
colFgtVipExt IP esterno / External IP                             colFgtVipMapped IP interno / Mapped IP
colFgtVipIntf Interfaccia / Interface                             colFgtVipPf Port forward / Port forward
colFgtVipComment Commento / Comment                               colFgtPoolName Nome / Name
colFgtPoolType Tipo / Type        colFgtPoolStart IP iniziale / Start IP
colFgtPoolEnd IP finale / End IP  colFgtPolHits Hit / Hits
colFgtPolSessions Sessioni / Sessions                             colFgtPolLastUsed Ultimo uso / Last used
colFgtDevHost Hostname / Hostname colFgtDevMac MAC / MAC          colFgtDevIp IP / IP
colFgtDevOs OS / OS               colFgtDevIntf Interfaccia / Interface
colFgtDevOnline Online / Online   colFgtSessProto Proto / Proto   colFgtSessSrc Sorgente / Source
colFgtSessSport Porta sorg. / Src port                            colFgtSessDst Destinazione / Destination
colFgtSessDport Porta dest. / Dst port                            colFgtSessPolicy Policy / Policy
colFgtSessDuration Durata / Duration                              colFgtLogDate Data / Date
colFgtLogTime Ora / Time          colFgtLogSrc Sorgente / Source  colFgtLogDst Destinazione / Destination
colFgtLogDport Porta / Port       colFgtLogAction Azione / Action colFgtLogPolicy Policy / Policy
colFgtLogService Servizio / Service                               colFgtAdminName Nome / Name
colFgtAdminProfile Profilo / Profile                              colFgtAdminTrust Trusted host / Trusted host
colFgtAdmin2fa 2FA / 2FA          colFgtAdminComment Commento / Comment
colFgtBanIp IP / IP               colFgtBanCause Causa / Cause    colFgtBanExpires Scadenza / Expires
colFgtCertName Nome / Name        colFgtCertType Tipo / Type      colFgtCertStatus Stato / Status
colFgtCertExpiry Scadenza / Expiry                                colFgtCertIssuer Emittente / Issuer
colFgtRevId ID / ID               colFgtRevDate Data / Date       colFgtRevAdmin Admin / Admin
colFgtRevComment Commento / Comment                               colFgtApName AP / AP
colFgtApStatus Stato / Status     colFgtApIp IP / IP              colFgtApVersion Versione / Version
colFgtApClients Client / Clients  colFgtWcHost Hostname / Hostname
colFgtWcMac MAC / MAC             colFgtWcIp IP / IP              colFgtWcSsid SSID / SSID
colFgtWcSignal Segnale / Signal   colFgtWcChannel Canale / Channel
```

- [ ] **Step 4: Replace the tab body with seven panes**

In `templates/dashboard.html`, inside `<div id="tab-fortigate" class="tab-content">`, keep the hero (now pointing at `fgtEyebrow` / `titleFgtTab` / `descFgtTab`) and the target-selector panel at `:2172-2184`. After the target panel, insert the sub-tab bar:

```html
      <div class="subtab-bar" style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:16px;">
        <button class="btn btn-secondary ti-subtab active" id="fgtSub-overview" onclick="fgtSwitchView('overview')" data-i18n="fgtSubOverview">Panoramica</button>
        <button class="btn btn-secondary ti-subtab" id="fgtSub-network" onclick="fgtSwitchView('network')" data-i18n="fgtSubNetwork">Rete</button>
        <button class="btn btn-secondary ti-subtab" id="fgtSub-firewall" onclick="fgtSwitchView('firewall')" data-i18n="fgtSubFirewall">Firewall</button>
        <button class="btn btn-secondary ti-subtab" id="fgtSub-traffic" onclick="fgtSwitchView('traffic')" data-i18n="fgtSubTraffic">Traffico</button>
        <button class="btn btn-secondary ti-subtab" id="fgtSub-security" onclick="fgtSwitchView('security')" data-i18n="fgtSubSecurity">Sicurezza</button>
        <button class="btn btn-secondary ti-subtab" id="fgtSub-wifi" onclick="fgtSwitchView('wifi')" data-i18n="fgtSubWifi">WiFi</button>
        <button class="btn btn-secondary ti-subtab requires-admin" id="fgtSub-settings" onclick="fgtSwitchView('settings')" data-i18n="fgtSubSettings">Impostazioni</button>
      </div>
```

Then seven pane divs. Every pane except `overview` is `style="display:none;"`. Each dataset gets a panel with a filter input and a `#fgtView-<key>` container. Pattern for one pane, repeated per the sub-tab table in the spec:

```html
      <div id="fgtPane-network" class="fgt-pane" style="display:none;">
        <div class="panel" style="margin-bottom:18px;">
          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px;">
            <button type="button" class="ca-pill active" id="fgtPill-interfaces" onclick="fgtPickView('network','interfaces')" data-i18n="colFgtIfName">Interfacce</button>
            <button type="button" class="ca-pill" id="fgtPill-arp" onclick="fgtPickView('network','arp')">ARP</button>
            <button type="button" class="ca-pill" id="fgtPill-dhcp" onclick="fgtPickView('network','dhcp')">DHCP</button>
            <button type="button" class="ca-pill" id="fgtPill-routes" onclick="fgtPickView('network','routes')">Routing</button>
            <button type="button" class="ca-pill" id="fgtPill-vpn" onclick="fgtPickView('network','vpn')">VPN</button>
            <button type="button" class="ca-pill" id="fgtPill-sdwan" onclick="fgtPickView('network','sdwan')">SD-WAN</button>
          </div>
          <input id="fgtFilter-interfaces" type="text" oninput="renderFgtDataset('interfaces')" data-i18n-placeholder="phFgtObjFilter" placeholder="Filtra..." style="width:100%; margin-bottom:10px; padding:6px 12px; border-radius:8px; border:1px solid var(--border); background:var(--surface); color:var(--text); font-size:13px;">
          <div id="fgtView-interfaces"></div>
          <div id="fgtView-arp" style="display:none;"></div>
          <div id="fgtView-dhcp" style="display:none;"></div>
          <div id="fgtView-routes" style="display:none;"></div>
          <div id="fgtView-vpn" style="display:none;"></div>
          <div id="fgtView-sdwan" style="display:none;"></div>
        </div>
      </div>
```

Build the remaining panes on the same pattern. Every dataset key listed here needs both a `#fgtPill-<key>` button and a `#fgtView-<key>` container inside its pane, plus a `#fgtFilter-<key>` input calling `renderFgtDataset('<key>')` for the table views:

| Pane | Pill + view keys | Extra controls |
|---|---|---|
| `fgtPane-firewall` | `addresses`, `addressGroups`, `services`, `serviceGroups`, `vips`, `ipPools`, `policies`, `policyLookup` | Policy-lookup form inputs `fgtLookupSrc`, `fgtLookupDst`, `fgtLookupProto` (select TCP/UDP/ICMP), `fgtLookupPort`, `fgtLookupIntf`, and a button calling `loadFgtDataset('policyLookup')` |
| `fgtPane-traffic` | `sessions`, `logs`, `deviceInventory` | Session inputs `fgtSessSrc`, `fgtSessDst`, `fgtSessPort`; log inputs `fgtLogSrc`, `fgtLogDst`, `fgtLogAction`, `fgtLogDevice`, `fgtLogType`, `fgtLogSubtype`; a button per view calling `loadFgtDataset('sessions')` / `loadFgtDataset('logs')` |
| `fgtPane-security` | `admins`, `bannedUsers`, `certificates`, `configRevisions`, `securityProfiles` | — |
| `fgtPane-wifi` | `wifiAps`, `wifiClients` | — |

`fgtPane-overview` holds `<div id="fgtOverviewTiles"></div>` plus `#fgtView-resources` and `#fgtView-ha`. These three have **no pills** — Task 10's `renderFgtOverview()` drives them directly.

`fgtPane-settings` receives the **existing, unchanged** token panel (`:2186-2242`) and target-management markup — move them, do not rewrite them. Keep `class="requires-admin"` on the token panel. Delete the old objects panel at `:2244-2273`, superseded by the registry. Add a full-config section: a `#fgtView-fullConfig` container and a button calling `loadFgtDataset('fullConfig')`, never auto-loaded — the response contains secrets and the route is operator-only.

The `fgtLogType` / `fgtLogSubtype` selects are what makes Task 1's work reachable from the UI. Give `fgtLogType` the options `traffic` / `event` / `utm` and `fgtLogSubtype` the options `forward` / `local` / `virus` / `webfilter` / `ips`.

- [ ] **Step 5: Verify no orphan containers**

```sh
uv run python - <<'PY'
import re
html = open("templates/dashboard.html", encoding="utf-8").read()
js = open("static/js/fortigate-management.js", encoding="utf-8").read()
keys = set(re.findall(r"^\s{4}(\w+):\s*\{ url:", js, re.M))
have = set(re.findall(r'id="fgtView-(\w+)"', html))
# resources/ha entrano nel registro solo al Task 10: qui hanno gia' il
# contenitore ma non ancora la voce.
print("dataset senza contenitore:", sorted(keys - have))
print("contenitori senza dataset:", sorted(have - keys - {"resources", "ha"}))
PY
```

Expected: both lists empty.

- [ ] **Step 6: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

- [ ] **Step 7: Commit**

```bash
git add templates/dashboard.html static/css/dashboard.css static/js/i18n.js
git commit -m "feat(fortigate): seven sub-tabs, pill CSS fix, i18n labels

The .ca-pill rules were scoped #tab-config only, so this tab's view pills
had been rendering unstyled since they were added. Re-scoped rather than
duplicated.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 10: Wire the sub-tabs

**Files:**
- Modify: `static/js/fortigate-management.js`

**Interfaces:**
- Consumes: `FGT_DATASETS`, `loadFgtDataset`, `renderFgtDataset`, `fgtCurrentTarget` (Task 8); pane and pill ids (Task 9).
- Produces: `fgtSwitchView(pane)`, `fgtPickView(pane, key)`, `loadFgtTab()`, `renderFgtOverview()`.

- [ ] **Step 1: Write the sub-tab switcher**

Append to `static/js/fortigate-management.js`:

```js
// --- Sotto-tab -------------------------------------------------------------
// Panes locali, non tab-content separate: condividono un solo target e un
// solo contesto di dispositivo, quindi switchTab() non c'entra.
const FGT_PANES = ['overview', 'network', 'firewall', 'traffic', 'security', 'wifi', 'settings'];
// Prima vista di ogni pane: si carica da sola quando il pane si apre.
const FGT_PANE_DEFAULT = {
    network: 'interfaces', firewall: 'addresses', traffic: 'sessions',
    security: 'admins', wifi: 'wifiAps',
};
let fgtPane = 'overview';

function fgtSwitchView(pane) {
    fgtPane = pane;
    FGT_PANES.forEach(p => {
        const el = document.getElementById('fgtPane-' + p);
        if (el) el.style.display = p === pane ? '' : 'none';
        const btn = document.getElementById('fgtSub-' + p);
        if (btn) btn.classList.toggle('active', p === pane);
    });
    if (pane === 'overview') { renderFgtOverview(); return; }
    if (pane === 'settings') { loadFgtPrevTokens(); loadFgtTargets(); return; }
    const key = FGT_PANE_DEFAULT[pane];
    if (key) fgtPickView(pane, key);
}

// Sceglie la vista dentro un pane. Carica solo alla prima apertura: i dati
// restano finché non si preme Aggiorna, altrimenti ogni click rifà una
// chiamata REST al firewall.
function fgtPickView(pane, key) {
    Object.keys(FGT_DATASETS).forEach(k => {
        const view = document.getElementById('fgtView-' + k);
        const pill = document.getElementById('fgtPill-' + k);
        if (view && pill) {  // solo le viste del pane corrente hanno una pill
            if (k === key) { view.style.display = ''; pill.classList.add('active'); }
            else if (pill.closest('#fgtPane-' + pane)) { view.style.display = 'none'; pill.classList.remove('active'); }
        }
    });
    if (!fgtDatasetRows[key]) loadFgtDataset(key); else renderFgtDataset(key);
}

// Ricarica esplicita della vista aperta nel pane corrente.
function refreshFgtView() {
    const open = Object.keys(FGT_DATASETS).find(k => {
        const v = document.getElementById('fgtView-' + k);
        return v && v.style.display !== 'none' && v.closest('#fgtPane-' + fgtPane);
    });
    if (open) loadFgtDataset(open);
}
```

- [ ] **Step 2: Write the Overview renderer**

Append to `static/js/fortigate-management.js`:

```js
// --- Panoramica ------------------------------------------------------------
// Bespoke: quattro numeri in evidenza, non una tabella. Il resto della tab
// passa dal registro.
async function renderFgtOverview() {
    const ip = fgtCurrentTarget();
    const host = document.getElementById('fgtOverviewTiles');
    const en = currentLang === 'en';
    if (!host) return;
    if (!ip) { host.innerHTML = _fgtEmpty(en ? 'No target selected.' : 'Nessun target selezionato.'); return; }

    const [status, resources] = await Promise.all([
        apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/status`).then(r => r && r.ok ? r.json() : null).catch(() => null),
        apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/system/resources`).then(r => r && r.ok ? r.json() : null).catch(() => null),
    ]);

    const s = (status && status.data) || {};
    const u = (resources && resources.data && resources.data.usage) || {};
    const num = v => (Array.isArray(v) ? (v[0] || {}).current : v);
    const tile = (label, value, suffix) => `<div class="panel" style="margin:0; text-align:center; padding:14px;">
        <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:.04em;">${escapeHtml(label)}</div>
        <div style="font-family:var(--font-display); font-size:24px; margin-top:6px;">${escapeHtml(jsStr(value == null || value === '' ? '—' : String(value) + (suffix || '')))}</div>
      </div>`;

    host.style.display = 'grid';
    host.style.gridTemplateColumns = 'repeat(auto-fit, minmax(160px, 1fr))';
    host.style.gap = '12px';
    host.innerHTML =
        tile(en ? 'Hostname' : 'Hostname', s.hostname) +
        tile(en ? 'FortiOS' : 'FortiOS', s.version) +
        tile('CPU', num(u.cpu), '%') +
        tile(en ? 'Memory' : 'Memoria', num(u.mem), '%') +
        tile(en ? 'Sessions' : 'Sessioni', num(u.session)) +
        tile(en ? 'Disk' : 'Disco', num(u.disk), '%');

    loadFgtDataset('ha');
}
```

Add the `ha` and `resources` entries to `FGT_DATASETS` so the Overview's detail tables go through the same machinery — `pick` selects the nested branch:

```js
    ha:        { url: ip => `/api/fortigate/${ip}/system/ha`, pick: d => (d || {}).status, cols: [] },
    resources: { url: ip => `/api/fortigate/${ip}/system/resources`, pick: d => (d || {}).usage, cols: [] },
```

An empty `cols` is deliberate: these render as key/value tables via the `isKv` branch.

- [ ] **Step 3: Rewrite the tab entry point**

Replace `loadFgtTab()` (renamed in Task 7) with:

```js
function loadFgtTab() {
    populateFgtPrevDeviceSelects();
    loadFgtTargets().then(() => {
        fgtDatasetRows = {};   // target può essere cambiato: niente dati stantii
        fgtSwitchView(fgtPane);
    });
}
```

Update `onFgtTargetSelectChange()` to drop its old `loadFgtPrevObjects()` call and instead clear the cache and re-render the current pane:

```js
        fgtDatasetRows = {};
        fgtSwitchView(fgtPane);
```

- [ ] **Step 4: Verify every referenced function exists**

```sh
uv run python - <<'PY'
import re
js = open("static/js/fortigate-management.js", encoding="utf-8").read()
html = open("templates/dashboard.html", encoding="utf-8").read()
start = html.index('<div id="tab-fortigate"')
tab = html[start:html.index('<div id="tab-audit-checklist"')]
called = set(re.findall(r'onclick="(\w+)\(', tab)) | set(re.findall(r'oninput="(\w+)\(', tab)) | set(re.findall(r'onchange="(\w+)\(', tab))
defined = set(re.findall(r"function (\w+)", js))
missing = sorted(c for c in called if c not in defined)
print("handler non definiti:", missing)
PY
```

Expected: empty list, or only names defined in `core.js` / `mcp-client.js`. Any other name is a broken button — fix before committing.

- [ ] **Step 5: Run the app and click through all seven sub-tabs**

Start the app, open Fortigate Management as an admin, select a target, and visit each sub-tab and each pill. Confirm: no console errors, tables populate or show the empty state, the SSH-fallback badge appears where REST fails, and zero-hit policies render in the warning colour.

- [ ] **Step 6: Run the full gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

- [ ] **Step 7: Commit**

```bash
git add static/js/fortigate-management.js
git commit -m "feat(fortigate): wire the seven sub-tabs

Panes are local to the tab rather than separate tab-content divs: they
share one target and one device context. Views load once and cache;
Refresh is explicit so a stray click never re-hits the firewall.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 11: Docs, graph, build

**Files:**
- Modify: `docs/fortigate-management-plan.md`, `docs/operations.md`
- Regenerate: `graphify-out/`, `dist/SentinelNet.exe`

- [ ] **Step 1: Mark the spec's phases done**

Add a short "Status" line at the top of `docs/fortigate-management-plan.md` recording that all three phases shipped, with the date. Note any endpoint the Task 6 smoke check found unavailable on the test hardware.

- [ ] **Step 2: Check whether operations.md mentions the preview flag**

```sh
git grep -n "fortigate_preview\|FortiGate LIVE" docs/
```

Update any hit to describe the Fortigate Management tab instead. `docs/operations.md` already has uncommitted changes on this branch — do not revert them.

- [ ] **Step 3: Update the knowledge graph**

```sh
graphify update .
```

- [ ] **Step 4: Rebuild the executable**

```sh
uv run pyinstaller SentinelNet.spec
```

Expected: `dist/SentinelNet.exe` rebuilt. This is required — the shipped exe is what gets tested, and a stale one is exactly what made the client-diagnosis work look missing.

- [ ] **Step 5: Final gate**

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
```

- [ ] **Step 6: Commit**

```bash
git add docs graphify-out
git commit -m "docs(fortigate): record the shipped Fortigate Management tab

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Out of scope

Named here so nobody adds them mid-plan:

- **Any write to FortiOS.** Policy enable/disable, session clear, object CRUD.
- **Auto-refresh timers.** Refresh is a button.
- **Caching of cmdb reads** beyond the in-memory `fgtDatasetRows` for the current target.
- **Merging `Dev` into `master`.** Separate decision, separate session.
