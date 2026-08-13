# NetSec Audit History Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator choose to keep the result of a NetSec Audit run, and consult the history of scores and findings afterwards.

**Architecture:** One new table `netsec_audit_runs` in the existing SQLite database (`observability.db`), written by the scan route only when the caller asks for it. Three read routes and one delete, all tenant-scoped. A `Storico` panel in the NetSec Audit UI lists runs and reopens a stored result unchanged.

**Tech Stack:** FastAPI (`routers/analyzer.py`), SQLite via `core/db.py` + `observability/storage/schema.sql`, vanilla JS (`static/js/netsec-audit.js`), `unittest`.

## Design decisions, and why

**The client never sends the score back.** The obvious "Save" button would POST the
displayed result to the server — which makes the score a client-supplied value, so
anyone could store a fabricated 100%/GRADE A against a device they never audited.
Instead the request that *runs* the audit carries a `save: true` flag, and the server
persists the result **it** computed. That is why this is a checkbox on the scan form
rather than a button under the results. The UI still reads as "save this run"; the
trust boundary is what changes.

**Saving is opt-in.** Most scans are exploratory — re-run after a config tweak, try a
different benchmark. Auto-saving every one buries the runs worth keeping. The
checkbox defaults to off.

**Tenant scoping.** A run against a device inherits that device's tenant. A run against
a pasted config has no device, so `tenant` is `NULL`; those rows are visible only to
users with unrestricted scope (admins), because there is nothing to scope them by.
Out-of-scope and non-existent both answer 404 — the rule in `CONTRIBUTING.md` §4.

**Retention.** History grows without a ceiling otherwise. Same shape as the MAC-table
retention already in the app: a day count in settings, applied after each insert.

**What is stored.** The whole result document (`rules[]` included), not just the score.
A score with no findings behind it cannot be acted on months later, and re-running
against a config that has since changed answers a different question.

**The score is nullable, and there is no grade column.** Two facts checked against
`services/netsec_audit/model.py::score_rules` before writing this plan:

- `score` is `None` when every rule came back UNKNOWN — the function excludes UNKNOWN
  from the denominator and returns `None` rather than inventing a number, and the UI
  shows a dash. Storing that as `0` would turn "not determinable" into "everything
  failed", the exact falsification the function's docstring exists to prevent. The
  column is nullable and `None` is stored as `NULL`.
- `summary` has **no** `grade` key. The grade is computed in the browser
  (`static/js/netsec-audit.js:166`: `>= 80` A, `>= 60` B, else C) as a pure function
  of the score. Storing it would duplicate that rule, and a later threshold change
  would silently disagree with history. The history renders the grade from the stored
  score with the same helper the live result uses.

## Global Constraints

- Example data only: `192.0.2.x` / `198.51.100.x` (RFC 5737), `aa:bb:cc:...` (RFC 7042), `switch-01`. Never a real hostname, model, version, serial or management IP — this repo is public and `data/` holds real customer state.
- Code comments in English. User-facing strings in `static/js/i18n.js`, in BOTH `it` and `en`.
- No feature flags, no backwards-compatibility shims.
- Scope rule (`CONTRIBUTING.md` §4): every query filters tenant with bound parameters — never string interpolation, never a scalar group. Scope `None` (admin) means no tenant filter.
- Escaping: HTML text uses `escapeHtml(x)` alone; only a value inside an `on*="fn('…')"` JS string uses `escapeHtml(jsStr(x))`.
- Async routes read via `await db.read(...)`; `db.get_observability_connection()` is for migrations, tests, and the one atomic read-then-write case. Do not open it on an async path.
- Before every commit: `uv run pyrefly check` (0 errors), `uv run python -m unittest discover -s tests` (all green), `graphify update .`.
- Commit message body in Italian, repo style (`git log -5`). End with:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`

---

### Task 1: The table

**Files:**
- Modify: `observability/storage/schema.sql`
- Test: `tests/test_netsec_audit_history.py` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: table `netsec_audit_runs` with columns
  `id INTEGER PK`, `ts INTEGER`, `tenant TEXT NULL`, `device_name TEXT NULL`,
  `device_ip TEXT NULL`, `benchmark TEXT`, `benchmark_title TEXT`, `vendor TEXT`,
  `lang TEXT`, `score INTEGER NULL`, `summary_json TEXT`, `result_json TEXT`,
  `actor TEXT`. No `grade` column — it is derived from `score` in the UI.

- [ ] **Step 1: Write the failing test**

Create `tests/test_netsec_audit_history.py`:

```python
# -*- coding: utf-8 -*-
"""Storico degli audit: un punteggio senza i rilievi che lo hanno prodotto non
si puo' usare mesi dopo, quindi si conserva il documento intero.

Scoping: una run su un dispositivo eredita il tenant del dispositivo; una run su
una configurazione incollata non ne ha, e resta visibile solo a chi non e'
limitato per tenant.
"""

import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR",
                      tempfile.mkdtemp(prefix="sentinelnet_audithist_"))

from core import db  # noqa: E402

EXPECTED_COLUMNS = {
    "id", "ts", "tenant", "device_name", "device_ip", "benchmark",
    "benchmark_title", "vendor", "lang", "score",
    "summary_json", "result_json", "actor",
}


class TestSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.migrate()

    def test_the_table_exists_with_its_columns(self):
        conn = db.get_observability_connection()
        try:
            rows = conn.execute("PRAGMA table_info(netsec_audit_runs)").fetchall()
        finally:
            conn.close()
        self.assertTrue(rows, "netsec_audit_runs missing")
        self.assertEqual(EXPECTED_COLUMNS, {r["name"] for r in rows})

    def test_history_is_queried_newest_first_by_tenant(self):
        # The listing index must cover the two columns every query filters and
        # orders by, or the list page degrades into a scan as history grows.
        conn = db.get_observability_connection()
        try:
            idx = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='netsec_audit_runs'").fetchall()
        finally:
            conn.close()
        self.assertTrue([i for i in idx if "tenant" in i["name"] or "ts" in i["name"]],
                        "no index supporting (tenant, ts) lookups")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_history -v`
Expected: FAIL — `netsec_audit_runs missing`.

- [ ] **Step 3: Add the DDL**

Append to `observability/storage/schema.sql`, following the style of the
`audit_engagements` block already there:

```sql
-- Saved NetSec Audit runs. Opt-in: the scan route writes here only when the
-- caller asked to keep the run. The whole result document is kept, because a
-- score without the findings behind it cannot be acted on later, and re-running
-- against a config that has since changed answers a different question.
CREATE TABLE IF NOT EXISTS netsec_audit_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              INTEGER NOT NULL,
    -- NULL for a pasted config: nothing to scope it by, so only unrestricted
    -- users see it.
    tenant          TEXT,
    device_name     TEXT,
    device_ip       TEXT,
    benchmark       TEXT NOT NULL,
    benchmark_title TEXT NOT NULL,
    vendor          TEXT NOT NULL,
    lang            TEXT NOT NULL,
    -- NULL when every rule came back UNKNOWN: score_rules() returns None
    -- rather than inventing a number, and 0 would read as "everything failed".
    score           INTEGER,
    summary_json    TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    actor           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_netsec_audit_runs_tenant_ts
    ON netsec_audit_runs (tenant, ts DESC);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m unittest tests.test_netsec_audit_history -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add observability/storage/schema.sql tests/test_netsec_audit_history.py
git commit -m "feat(audit): la tabella dello storico, ancora senza chi la scrive"
```

---

### Task 2: Saving a run

**Files:**
- Modify: `routers/analyzer.py` (`NetSecAuditSchema`, `netsec_audit_scan`)
- Create: `services/netsec_audit/history.py`
- Test: `tests/test_netsec_audit_history.py` (extend)

**Interfaces:**
- Consumes: the table from Task 1; the result dict from `netsec_audit.run_netsec_audit()`, whose keys are `benchmark`, `benchmark_title`, `lang`, `vendor`, `score`, `summary`, `rules`.
- Produces: `history.save(result, *, tenant, device_name, device_ip, actor) -> int` (the new row id) and `history.prune(days: int) -> int` (rows deleted).

**The one rule that matters here:** the score written to the table is the one the
server just computed. The request carries `save: true` and nothing else about the
result — never a score, grade or rule list from the client.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_netsec_audit_history.py`:

```python
import json

from fastapi.testclient import TestClient

CSRF = {"X-Requested-With": "SentinelNet"}

CONFIG = "hostname switch-01\nno ip http server\n"


class TestSaving(unittest.TestCase):
    """The client asks to keep a run; it never supplies the result."""

    @classmethod
    def setUpClass(cls):
        db.migrate()
        import app_server
        cls.client = TestClient(app_server.app)
        # Log in with the same helper the other router tests use — see
        # tests/test_observability_ui.py. Do not invent a new one.

    def test_a_scan_without_the_flag_stores_nothing(self):
        before = self._count()
        r = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                             json={"config_text": CONFIG, "benchmark": "cis"})
        self.assertEqual(200, r.status_code)
        self.assertEqual(before, self._count())

    def test_a_scan_with_the_flag_stores_the_servers_own_result(self):
        r = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                             json={"config_text": CONFIG, "benchmark": "cis",
                                   "save": True})
        self.assertEqual(200, r.status_code)
        row = self._latest()
        self.assertEqual(r.json()["score"], row["score"])
        self.assertEqual(r.json()["rules"], json.loads(row["result_json"])["rules"])

    def test_a_forged_score_in_the_request_is_ignored(self):
        # The score is computed server-side. A client that sends one must not
        # be able to store it — otherwise the history is worthless as evidence.
        r = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                             json={"config_text": CONFIG, "benchmark": "cis",
                                   "save": True, "score": 100, "grade": "A"})
        self.assertEqual(200, r.status_code)
        self.assertEqual(r.json()["score"], self._latest()["score"])
        self.assertNotEqual(100, self._latest()["score"])

    def _count(self):
        conn = db.get_observability_connection()
        try:
            return conn.execute("SELECT COUNT(*) c FROM netsec_audit_runs").fetchone()["c"]
        finally:
            conn.close()

    def _latest(self):
        conn = db.get_observability_connection()
        try:
            return conn.execute("SELECT * FROM netsec_audit_runs "
                                "ORDER BY id DESC LIMIT 1").fetchone()
        finally:
            conn.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_history.TestSaving -v`
Expected: FAIL — nothing is stored.

- [ ] **Step 3: Write the store**

Create `services/netsec_audit/history.py`:

```python
# -*- coding: utf-8 -*-
"""Persistence for saved NetSec Audit runs.

Only the scan route writes here, and only with the result it just computed:
the client asks to keep a run, it does not supply one. A stored score is meant
to be usable as evidence later, which it is not if the browser can dictate it.
"""

import json
import time
from typing import Optional

from core import db


def save(result: dict, *, tenant: Optional[str], device_name: Optional[str],
         device_ip: Optional[str], actor: str) -> int:
    summary = result.get("summary") or {}
    # None means "not determinable" (every rule UNKNOWN). It stays None: coercing
    # it to 0 would record a perfect failure where the engine recorded no verdict.
    raw = result.get("score")
    score = int(raw) if isinstance(raw, (int, float)) else None
    conn = db.get_observability_connection()
    try:
        cur = conn.execute(
            "INSERT INTO netsec_audit_runs (ts, tenant, device_name, device_ip, "
            "benchmark, benchmark_title, vendor, lang, score, "
            "summary_json, result_json, actor) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (int(time.time()), tenant, device_name, device_ip,
             result.get("benchmark", ""), result.get("benchmark_title", ""),
             result.get("vendor", ""), result.get("lang", ""),
             score,
             json.dumps(summary), json.dumps(result), actor))
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def prune(days: int) -> int:
    """Drop runs older than ``days``. Returns how many rows went."""
    if days <= 0:
        return 0
    cutoff = int(time.time()) - days * 86400
    conn = db.get_observability_connection()
    try:
        cur = conn.execute("DELETE FROM netsec_audit_runs WHERE ts < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
```

`score_rules` returns `(score, summary)` where `summary` has `total`, `passed`,
`failed`, `warned`, `unknown` — and no grade. Both facts were checked against the
source when this plan was written; re-check before deviating.

- [ ] **Step 4: Wire the route**

In `routers/analyzer.py`, add to `NetSecAuditSchema`:

```python
    # Keep this run in the history. The result stored is the one computed here;
    # nothing about the outcome is ever read from the request.
    save: bool = False
```

At the end of `netsec_audit_scan`, replace the bare `return` with:

```python
    result = netsec_audit.run_netsec_audit(
        config_text=text,
        device_name=dev_name,
        benchmark=payload.benchmark,
        lang=payload.lang,
    )
    if payload.save:
        from services.netsec_audit import history
        from core.app_settings import get_app_settings

        tenant = None
        if payload.device_ip and payload.device_ip != "all":
            device = assert_device_allowed(current_user, payload.device_ip)
            tenant = (device or {}).get("Group") or None
        run_id = history.save(result, tenant=tenant, device_name=dev_name,
                              device_ip=payload.device_ip, actor=current_user.get("sub"))
        history.prune(int(get_app_settings().get("audit_history_days") or 365))
        log_audit(f"Audit '{payload.benchmark}' salvato nello storico (#{run_id}) "
                  f"da '{current_user.get('sub')}'.")
        result["saved_id"] = run_id
    return result
```

Import `assert_device_allowed` and `log_audit` at the top of the module if they
are not already there.

- [ ] **Step 5: Run tests**

Run: `uv run python -m unittest tests.test_netsec_audit_history -v`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add routers/analyzer.py services/netsec_audit/history.py tests/test_netsec_audit_history.py
git commit -m "feat(audit): una run si puo' conservare, col punteggio calcolato qui"
```

---

### Task 3: Reading the history back

**Files:**
- Modify: `routers/analyzer.py`
- Test: `tests/test_netsec_audit_history.py` (extend)

**Interfaces:**
- Consumes: the table and `history.save` from Tasks 1-2.
- Produces:
  - `GET /api/netsec-audit/history` → `{"runs": [...], "count": n}`, newest first, optional `tenant`, `device_ip`, `benchmark`, `limit` (default 100, cap 500). Rows carry the summary fields only — **not** `result_json`.
  - `GET /api/netsec-audit/history/{run_id}` → the stored result document.
  - `DELETE /api/netsec-audit/history/{run_id}` → admin only.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_netsec_audit_history.py`:

```python
class TestReading(unittest.TestCase):
    def test_the_list_does_not_ship_every_result_document(self):
        # The listing is a table of scores; sending each full rules[] with it
        # turns a page load into megabytes.
        r = self.client.get("/api/netsec-audit/history", headers=CSRF)
        self.assertEqual(200, r.status_code)
        for row in r.json()["runs"]:
            self.assertNotIn("result_json", row)
            self.assertIn("score", row)

    def test_the_detail_returns_the_stored_document_unchanged(self):
        saved = self.client.post("/api/netsec-audit/scan", headers=CSRF,
                                 json={"config_text": CONFIG, "benchmark": "cis",
                                       "save": True}).json()
        r = self.client.get(f"/api/netsec-audit/history/{saved['saved_id']}",
                            headers=CSRF)
        self.assertEqual(200, r.status_code)
        self.assertEqual(saved["rules"], r.json()["rules"])

    def test_out_of_scope_and_missing_answer_the_same_404(self):
        # Confirming existence to someone who may not see it leaks the fact
        # that another tenant was audited. Same rule as CONTRIBUTING.md §4.
        r = self.client.get("/api/netsec-audit/history/999999", headers=CSRF)
        self.assertEqual(404, r.status_code)

    def test_delete_is_admin_only(self):
        # Deleting evidence is not an operator action.
        import inspect
        from routers import analyzer
        from routers.deps import require_admin
        dep = inspect.signature(
            analyzer.netsec_audit_history_delete).parameters["current_user"].default
        self.assertIs(dep.dependency, require_admin)
```

Add a scoped-user case following `tests/test_rbac_scope.py`: a user limited to
tenant `sede-a` must not see a run stored under `sede-b`, and must get 404 — not
403 — when asking for it by id.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_history.TestReading -v`
Expected: FAIL — routes do not exist.

- [ ] **Step 3: Add the routes**

In `routers/analyzer.py`, following the tenant-filter style used in
`routers/observability.py` (bound placeholders, never interpolation):

```python
@router.get("/api/netsec-audit/history")
async def netsec_audit_history(tenant: Optional[str] = None,
                               device_ip: Optional[str] = None,
                               benchmark: Optional[str] = None,
                               limit: int = 100,
                               current_user = Depends(get_current_user)):
    """Saved runs, newest first. Summary columns only — the stored document is
    fetched one run at a time."""
    scope = user_group_scope(current_user)
    if tenant:
        if scope is not None and tenant not in scope:
            raise HTTPException(status_code=403, detail=f"Tenant '{tenant}' non consentito.")
        tenants = [tenant]
    else:
        tenants = scope

    sql = ("SELECT id, ts, tenant, device_name, device_ip, benchmark, "
           "benchmark_title, vendor, lang, score, summary_json, actor "
           "FROM netsec_audit_runs WHERE 1=1")
    params: list = []
    if tenants is not None:
        # A run on a pasted config has no tenant; only unrestricted users see it.
        sql += " AND tenant IN (%s)" % ",".join("?" for _ in tenants)
        params.extend(tenants)
    if device_ip:
        sql += " AND device_ip = ?"
        params.append(device_ip)
    if benchmark:
        sql += " AND benchmark = ?"
        params.append(benchmark)
    sql += " ORDER BY ts DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))

    rows = await db.read(sql, tuple(params))
    return {"runs": [dict(r) for r in rows], "count": len(rows)}
```

Write `netsec_audit_history_detail` and `netsec_audit_history_delete` the same
way: fetch by id, apply the identical tenant test, and answer **404 for both
out-of-scope and missing**. `netsec_audit_history_delete` takes
`Depends(require_admin)` and writes a `log_audit` line naming the run id and the
actor.

- [ ] **Step 4: Run tests**

Run: `uv run python -m unittest tests.test_netsec_audit_history -v`
Expected: all pass.
Also run `uv run python -m unittest tests.test_router_parity` — new paths under
`/api/netsec-audit` need adding to that test's allowed-new-prefix list if it
rejects them.

- [ ] **Step 5: Commit**

```bash
git add routers/analyzer.py tests/test_netsec_audit_history.py
git commit -m "feat(audit): lo storico si legge, con lo stesso 404 per assente e fuori scope"
```

---

### Task 4: The UI — a checkbox and a Storico panel

**Files:**
- Modify: `templates/dashboard.html` (NetSec Audit area), `static/js/netsec-audit.js`, `static/js/i18n.js`
- Test: `tests/test_netsec_audit_history.py` (extend with a structure class)

**Interfaces:**
- Consumes: the three routes from Task 3, and `save` on the scan request.
- Produces: `#auditSaveRun` (checkbox), `#auditHistoryPanel`, `#auditHistoryBody`, and functions `loadAuditHistory()`, `openAuditRun(id)`, `deleteAuditRun(id)`.

- [ ] **Step 1: Write the failing test**

```python
class TestHistoryUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "templates", "dashboard.html"), encoding="utf-8") as f:
            cls.html = f.read()
        with open(os.path.join(root, "static", "js", "netsec-audit.js"), encoding="utf-8") as f:
            cls.js = f.read()

    def test_the_save_checkbox_exists_and_defaults_off(self):
        self.assertIn('id="auditSaveRun"', self.html)
        idx = self.html.index('id="auditSaveRun"')
        tag = self.html[self.html.rindex("<input", 0, idx):self.html.index(">", idx)]
        self.assertNotIn("checked", tag)

    def test_the_scan_request_carries_the_flag_and_no_result_fields(self):
        body = self.js[self.js.index("/api/netsec-audit/scan"):]
        body = body[:body.index("});") + 3]
        self.assertIn("save:", body)
        for forged in ("score:", "grade:", "rules:"):
            self.assertNotIn(forged, body)

    def test_the_history_panel_is_wired(self):
        self.assertIn('id="auditHistoryBody"', self.html)
        self.assertIn("function loadAuditHistory", self.js)
        self.assertIn("/api/netsec-audit/history", self.js)

    def test_delete_asks_first(self):
        body = self.js[self.js.index("function deleteAuditRun"):]
        body = body[:body.index("\n}") + 2]
        self.assertIn("confirm(", body)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m unittest tests.test_netsec_audit_history.TestHistoryUi -v`
Expected: 4 failures.

- [ ] **Step 3: Build the UI**

Next to the benchmark select (`#auditBenchmarkSelect`, `templates/dashboard.html`),
add the checkbox:

```html
<label style="display:flex; align-items:center; gap:6px; font-size:12px; margin-top:8px;">
  <input type="checkbox" id="auditSaveRun">
  <span data-i18n="auditSaveRunLabel">Conserva questa esecuzione nello storico</span>
</label>
```

Add a collapsible history panel below the results area, with a table whose columns
are date, device, benchmark, vendor, score, grade (derived from the score by the
same helper the live result uses), actor, plus a row action to open
the stored run and (admin only, `class="requires-admin"`) delete it.

In `static/js/netsec-audit.js`: include `save: document.getElementById('auditSaveRun').checked`
in the scan request body; add `loadAuditHistory()`, `openAuditRun(id)` (fetch the
detail and render it through the SAME renderer the live scan uses, so a stored run
and a fresh one look identical), and `deleteAuditRun(id)` behind a `confirm()`.

New i18n keys in both `it` and `en`: `auditSaveRunLabel`, `auditHistoryTitle`,
`auditHistoryEmpty`, `auditHistoryOpen`, `auditHistoryDelete`, `auditHistoryConfirmDelete`.

- [ ] **Step 4: Run tests and check the browser**

Run: `uv run python -m unittest discover -s tests 2>&1 | grep -E "^(OK|FAILED|Ran )"`
Expected: `OK`.
Run: `node --check static/js/netsec-audit.js`

Browser check on a throwaway instance (fresh `SENTINELNET_DATA_DIR`, throwaway
admin, plain HTTP — never the real data dir):
1. Scan with the box unticked → nothing appears in the history.
2. Scan with it ticked → the run appears, with the score the results panel shows.
3. Opening a stored run renders identically to the live result.
4. A non-admin does not see the delete action.
Load the page in a fresh isolated browser context — Chrome caches these scripts hard.

- [ ] **Step 5: Commit**

```bash
git add templates/dashboard.html static/js/netsec-audit.js static/js/i18n.js tests/test_netsec_audit_history.py
git commit -m "feat(audit): la spunta per conservare e il pannello dello storico"
```

---

### Task 5: Retention setting and docs

**Files:**
- Modify: `core/app_settings.py` (default `audit_history_days`), the Settings UI where other retention values live, `docs/architecture.md`, `docs/netsec_troubleshooting_qa_v3.md`

- [ ] **Step 1: Add the setting**

Default `audit_history_days = 365`. Surface it beside the existing retention
controls in Settings; `0` means keep forever, and the UI must say so — an
unbounded table is a decision, not an accident.

- [ ] **Step 2: Test the boundary**

```python
def test_zero_days_keeps_everything(self):
    from services.netsec_audit import history
    self.assertEqual(0, history.prune(0))
```

- [ ] **Step 3: Document it**

`docs/architecture.md`: one line in the audit section saying runs can be kept and
where they live. `docs/netsec_troubleshooting_qa_v3.md`: add the three routes to
the NetSec Audit route list, and note that saving is opt-in and admin-deletable.

- [ ] **Step 4: Full check and commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
git add -A
git commit -m "feat(audit): retention dello storico, e le guide lo dicono"
```

---

## Self-Review

**Coverage:** the checkbox (Task 4) and the store behind it (Task 2); the history
that can be consulted (Tasks 3-4); the table (Task 1); growth control and docs
(Task 5). Nothing in the request is unaddressed.

**Type consistency:** `history.save(result, *, tenant, device_name, device_ip, actor) -> int`
and `history.prune(days) -> int` are spelled identically in Tasks 2, 3 and 5.
Route names `netsec_audit_history`, `netsec_audit_history_detail`,
`netsec_audit_history_delete` match between Task 3's code and Task 3's test.

**Open questions for the implementer to raise rather than guess:**
1. A run whose every rule is UNKNOWN stores `score = NULL`. The listing and the
   detail must both render a dash for it, never 0 — mirror what the live result
   panel already does.
2. `tests/test_router_parity.py` may reject the three new paths; add them to its
   allowed-new-prefix list rather than loosening the test.
3. If `core/app_settings.py` validates its keys against a fixed list, add
   `audit_history_days` there too or the setting will not persist.
