# GUI Management, Phase 1 + 1b — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator can see what version every part of the fleet is running, read an agent's log, and restart the central — without opening a shell.

**Architecture:** Phase 1 is read-only: the agent reports its real identity on the heartbeat it already sends, the central stores it on the site record and renders a fleet panel, and a new agent RPC verb tails the journal. Phase 1b adds the one write action that unlocks the existing advanced-settings panel — a restart performed by a separate systemd unit, never by the app killing itself — plus a self-signed certificate generator.

**Tech Stack:** Python 3.11+, FastAPI, classic no-bundler JavaScript, systemd, `git` and `openssl` via `subprocess`.

**Spec:** `docs/superpowers/specs/2026-09-01-gui-management-design.md`

## Global Constraints

- `uv run pyrefly check` (0 errors) and `uv run pytest tests -n 4` (all green) before every commit. For any commit touching `static/js`, also `uv run python scripts/check_frontend.py`, `uv run python scripts/check_a11y.py --strict` and `uv run python scripts/check_i18n_coverage.py --strict`. Never claim a check passed without running it.
- `graphify update .` after code changes.
- User-facing strings go through `tr('key')` with entries in **both** the `it` and `en` dictionaries of `static/js/i18n.js`. An inline `currentLang === 'en' ? …` ternary is a defect.
- Every new form control needs a `<label for>` matching its id, or `aria-label` + `data-i18n-aria-label`.
- Never edit `tests_data/openapi_pre_destructure.json` or `tests_data/openapi_golden.json`. New routes and schemas go in the `NEW_PREFIXES` / `NEW_SCHEMAS` allow-lists in `tests/test_router_parity.py`, purely additively, with a short Italian comment.
- Never write a real customer IP, hostname, model or serial into a tracked file. Use RFC 5737 (`192.0.2.x`) or the `10.9.0.x` range the agent tests use.
- Comments in the touched files are Italian; match the file. Comments explain *why*.
- **No shell-command passthrough.** Every new endpoint runs a fixed command with fixed arguments. Nothing accepts a command, a path or a unit name from the request body.

---

### Task 1: The agent reports its real identity

**Files:**
- Modify: `services/site_agent.py` (`Agent.heartbeat`, plus a new module-level helper)
- Modify: `routers/agent.py` (`agent_heartbeat`)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Produces: heartbeat payload gains `version`, `commit`, `branch`, `dirty`; the site record gains `agent_version`, `agent_commit`, `agent_branch`, `agent_dirty`. Tasks 2 and 3 read them.

**Context the implementer needs:** `Agent.heartbeat` currently sends a hardcoded `"version": "2.6.0"` string that matches nothing in the tree (the app is at 0.26.0) and that the central discards. This task **replaces** that literal — do not leave it beside the new fields.

- [ ] **Step 1: Write the failing test**

In `tests/test_remote_site.py`, inside `class RemoteSiteE2E`:

```python
    def test_the_agent_identity_is_stored_on_the_site(self):
        from core.version import __version__
        from services import site_manager
        sid, token = self._create_agent_site("Identity")
        ah = self._agent_headers(sid, token)
        r = self.client.post("/api/agent/heartbeat", headers=ah, json={
            "version": __version__, "commit": "abc1234",
            "branch": "Dev", "dirty": False,
        })
        self.assertEqual(r.status_code, 200, r.text)
        site = site_manager.get_site(sid)
        self.assertEqual(site["agent_version"], __version__)
        self.assertEqual(site["agent_commit"], "abc1234")
        self.assertEqual(site["agent_branch"], "Dev")
        self.assertFalse(site["agent_dirty"])
```

And a new class at module level, at the end of the file:

```python
class AgentReportsItsRealVersion(unittest.TestCase):
    def test_the_hardcoded_version_literal_is_gone(self):
        # The heartbeat used to send "2.6.0", a literal matching nothing, which
        # the central then discarded. A wrong answer is worse than none: it is
        # what made "did my update apply?" unanswerable from the dashboard.
        import pathlib
        src = (pathlib.Path(__file__).resolve().parents[1]
               / "services" / "site_agent.py").read_text(encoding="utf-8")
        self.assertNotIn('"2.6.0"', src)

    def test_the_payload_carries_the_real_version_and_git_identity(self):
        from unittest import mock
        from core.version import __version__
        from services import site_agent
        agent = site_agent.Agent.__new__(site_agent.Agent)
        agent.cfg = {"site_id": "milan", "interval": 60, "syslog_port": 5514}
        agent._start_ts = 0
        agent._post = mock.MagicMock()
        agent._post.return_value.json.return_value = {"ok": True}
        agent.heartbeat()
        _path, payload = agent._post.call_args[0]
        self.assertEqual(payload["version"], __version__)
        for key in ("commit", "branch", "dirty"):
            self.assertIn(key, payload)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_remote_site.py -k "agent_identity or AgentReportsItsRealVersion" -v`
Expected: FAIL — the literal is present and the site record has no `agent_version`.

- [ ] **Step 3: Implement**

In `services/site_agent.py`, add a helper beside `load_config`:

```python
def _git_identity():
    """Commit, branch e stato del checkout dell'agente.

    Best-effort: un agente installato da zip non ha un repo e non deve
    fallire per questo. Serve a rispondere "quale codice sta girando qui",
    che senza SSH era una domanda senza risposta."""
    def _run(args):
        try:
            import subprocess
            out = subprocess.run(["git"] + args, cwd=_ROOT, capture_output=True,
                                 text=True, timeout=5)
            return out.stdout.strip() if out.returncode == 0 else ""
        except Exception:
            return ""
    return {
        "commit": _run(["rev-parse", "--short", "HEAD"]),
        "branch": _run(["rev-parse", "--abbrev-ref", "HEAD"]),
        "dirty": bool(_run(["status", "--porcelain"])),
    }
```

In `Agent.heartbeat`, replace the hardcoded version line and merge the identity in:

```python
        from core.version import __version__
        payload = {
            "version": __version__,
            **_git_identity(),
            "python_version": sys.version.split()[0],
            ...
        }
```

In `routers/agent.py`, `agent_heartbeat`, beside the existing interval handling:

```python
        for key in ("version", "commit", "branch", "dirty"):
            if key in payload:
                updates[f"agent_{key}"] = payload[key]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_remote_site.py -k "agent_identity or AgentReportsItsRealVersion" -v`
Expected: PASS

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add services/site_agent.py routers/agent.py tests/test_remote_site.py
git commit -m "feat(agent): the agent reports the version and commit it actually runs"
```

---

### Task 2: Fleet version panel

**Files:**
- Modify: `routers/settings.py` (new endpoint)
- Modify: `static/js/settings.js`, `static/js/i18n.js`
- Modify: `tests/test_router_parity.py` (allow-list the new path)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: `agent_version` / `agent_commit` / `agent_branch` / `agent_dirty` from Task 1.
- Produces: `GET /api/fleet/versions` → `{"central": {...}, "agents": [...], "install_kind": "git"|"exe"|"source"}`.

- [ ] **Step 1: Write the failing test**

In `class RemoteSiteE2E`:

```python
    def test_the_fleet_panel_lists_the_central_and_every_agent(self):
        from core.version import __version__
        sid, token = self._create_agent_site("Fleet")
        self.client.post("/api/agent/heartbeat",
                         headers=self._agent_headers(sid, token),
                         json={"version": "0.25.0", "commit": "dead123",
                               "branch": "Dev", "dirty": False})
        r = self.client.get("/api/fleet/versions", headers=self.admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["central"]["version"], __version__)
        self.assertIn(body["install_kind"], ("git", "exe", "source"))
        agent = next(a for a in body["agents"] if a["site_id"] == sid)
        self.assertEqual(agent["version"], "0.25.0")
        # The point of the panel: an agent behind the central is marked.
        self.assertTrue(agent["behind"])

    def test_the_fleet_panel_is_admin_only(self):
        r = self.client.get("/api/fleet/versions")
        self.assertIn(r.status_code, (401, 403))
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_remote_site.py -k fleet -v`
Expected: FAIL — 404, the route does not exist.

- [ ] **Step 3: Implement**

In `routers/settings.py`:

```python
def _install_kind() -> str:
    """Come gira questa istanza: da repo git, da exe PyInstaller, o da una
    copia dei sorgenti senza repo. La terza non e' un dettaglio: chi ha
    scaricato uno zip non puo' aggiornare con git piu' di quanto possa un exe."""
    if getattr(sys, "frozen", False):
        return "exe"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return "git" if os.path.isdir(os.path.join(root, ".git")) else "source"


@router.get("/api/fleet/versions")
def get_fleet_versions(current_user = Depends(require_admin)):
    from core.version import __version__
    from services import site_manager
    kind = _install_kind()
    agents = []
    for s in site_manager.list_sites():
        if s.get("mode") != "agent":
            continue
        v = s.get("agent_version") or ""
        agents.append({
            "site_id": s["id"], "name": s.get("name", ""),
            "version": v, "commit": s.get("agent_commit", ""),
            "branch": s.get("agent_branch", ""),
            "dirty": bool(s.get("agent_dirty")),
            "last_seen": s.get("last_seen"),
            # Confronto grezzo di stringhe: una versione diversa da quella del
            # centrale e' esattamente cio' che l'operatore deve vedere, e non
            # serve un parser SemVer per dirlo.
            "behind": bool(v) and v != __version__,
        })
    return {"central": {"version": __version__, "install_kind": kind},
            "install_kind": kind, "agents": agents}
```

Add `"/api/fleet"` to `TestFullParity.NEW_PREFIXES` in `tests/test_router_parity.py`, purely additively, with the comment `# Pannello versioni della flotta (centrale + agenti).`

In `static/js/settings.js` render a table in the Settings tab: the central row first, then one row per agent with version, commit, branch, last seen, and a visible marker when `behind` or `dirty`. Every label through `tr()`, with keys added to both dictionaries in `static/js/i18n.js`.

- [ ] **Step 4: Verify**

```bash
uv run pytest tests/test_remote_site.py -k fleet -v
uv run python scripts/check_frontend.py
uv run python scripts/check_a11y.py --strict
uv run python scripts/check_i18n_coverage.py --strict
```

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add routers/settings.py static/js/settings.js static/js/i18n.js tests/test_router_parity.py tests/test_remote_site.py
git commit -m "feat(settings): a fleet panel showing what every part is running"
```

---

### Task 3: Agent log tail

**Files:**
- Modify: `services/site_agent.py` (`_execute_agent_rpc`)
- Modify: `routers/sites.py` (endpoint that enqueues it), `static/js/site-agent.js`, `static/js/i18n.js`
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Produces: the `_agent_logs` RPC command, returning the last 200 journal lines in the job result.

**Context:** follow `_agent_get_inventory` exactly — same enqueue path in `routers/sites.py`, same result-in-the-job-column shape. `VALID_JOB_KINDS` is **not** touched: this is an `_agent_*` command on the existing `cli` kind, not a new kind. Cap the output at 200 lines: that column is rendered verbatim in the job-history panel, where a whole journal is unusable.

- [ ] **Step 1: Write the failing test**

At module level in `tests/test_remote_site.py`:

```python
class AgentLogTail(unittest.TestCase):
    def test_the_log_tail_rpc_returns_bounded_output(self):
        from unittest import mock
        from services import site_agent
        agent = site_agent.Agent.__new__(site_agent.Agent)
        agent.cfg = {"site_id": "milan"}
        fake = "\n".join(f"line {i}" for i in range(1000))
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.MagicMock(returncode=0, stdout=fake, stderr="")
            out = agent._execute_agent_rpc("_agent_logs")
        self.assertEqual(out["status"], "done")
        self.assertLessEqual(len(out["result"].splitlines()), 200)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_remote_site.py -k AgentLogTail -v`
Expected: FAIL — the verb does not exist, so the unknown-command branch answers.

- [ ] **Step 3: Implement** — a branch in `_execute_agent_rpc`:

```python
        elif action == "_agent_logs":
            try:
                proc = subprocess.run(
                    ["journalctl", "-u", "sentinelnet-agent", "-n", "200",
                     "--no-pager"],
                    capture_output=True, text=True, timeout=20)
                # Ultime 200 righe e basta: questa stringa finisce tale e quale
                # nel pannello storico job, dove un journal intero e' inservibile.
                tail = "\n".join((proc.stdout or proc.stderr).splitlines()[-200:])
                return {"status": "done", "result": tail}
            except Exception as e:
                return {"status": "error", "result": f"journalctl non disponibile: {e}"}
```

Add the enqueueing endpoint in `routers/sites.py` following `agent_self_update_ep`, and a **Leggi log** button in the agent panel beside the existing actions, its label through `tr()`.

- [ ] **Step 4: Verify** — the test passes, frontend checks clean.

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add services/site_agent.py routers/sites.py static/js/site-agent.js static/js/i18n.js tests/test_remote_site.py
git commit -m "feat(agent): read the agent's log from the dashboard"
```

---

### Task 4: Restart the central from the GUI

**Files:**
- Create: `docs/deploy/sentinelnet-restart.service`, `docs/deploy/sentinelnet-restart.sudoers`
- Modify: `routers/settings.py`, `static/js/settings.js`, `static/js/i18n.js`, `docs/hardening.md`, `tests/test_router_parity.py`
- Test: `tests/test_settings_restart.py` (new)

**Interfaces:**
- Produces: `POST /api/settings/restart` → `{"status": "scheduled"}`, or 409 with a reason.

**This is the security-sensitive task of the plan.** Three rules, all covered by the tests below:

1. The endpoint runs **one fixed argv**: `["sudo", "-n", "systemctl", "start", "--no-block", "sentinelnet-restart.service"]`. Nothing from the request body reaches it; there is no unit-name parameter.
2. The sudoers file grants exactly that one command to the service account with `NOPASSWD` — never `systemctl` with a wildcard, never `ALL`.
3. **The app never calls `os._exit`.** A separate oneshot unit restarts the main service, so a failed restart leaves the old process running. That is the entire reason this task has this shape rather than the agent's.

- [ ] **Step 1: Write the failing tests** in a new `tests/test_settings_restart.py`, isolating `SENTINELNET_DATA_DIR` before imports exactly as `tests/test_remote_site.py` does, and creating its own admin user in `setUpClass`

```python
    def test_the_restart_endpoint_runs_one_fixed_command(self):
        from unittest import mock
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")
            r = self.client.post("/api/settings/restart", headers=self.admin_h)
        self.assertEqual(r.status_code, 200, r.text)
        argv = run.call_args[0][0]
        self.assertEqual(argv, ["sudo", "-n", "systemctl", "start", "--no-block",
                                "sentinelnet-restart.service"])

    def test_a_unit_name_in_the_body_is_ignored(self):
        # The body must never reach the command line. If this ever fails, the
        # endpoint has become a remote shell on the box that holds every
        # site's credentials.
        from unittest import mock
        with mock.patch("subprocess.run") as run:
            run.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")
            self.client.post("/api/settings/restart", headers=self.admin_h,
                             json={"unit": "evil.service; rm -rf /"})
        argv = run.call_args[0][0]
        self.assertNotIn("evil.service; rm -rf /", " ".join(argv))

    def test_it_is_admin_only(self):
        r = self.client.post("/api/settings/restart")
        self.assertIn(r.status_code, (401, 403))

    def test_it_refuses_when_the_app_is_not_supervised(self):
        # Without a supervisor, "restart" is just "kill". Say so instead.
        from unittest import mock
        from routers import settings as settings_router
        with mock.patch.object(settings_router, "_is_supervised", return_value=False):
            r = self.client.post("/api/settings/restart", headers=self.admin_h)
        self.assertEqual(r.status_code, 409, r.text)
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_settings_restart.py -v`
Expected: FAIL — 404, the route does not exist.

- [ ] **Step 3: Implement**

`_is_supervised()` returns False when `sys.frozen` is set, or when `INVOCATION_ID` is absent from the environment — systemd sets that variable for every unit it starts, so its absence means nothing will bring the process back. The endpoint checks it first, then runs the fixed argv, and answers 409 with the reason when the check fails or `sudo -n` is refused.

Write both deployment files in full: the oneshot unit that runs `systemctl restart sentinelnet.service`, and the sudoers fragment granting exactly the one command. Document them in `docs/hardening.md`, including the exact sudoers line and why it names one command rather than a wildcard.

Add `"/api/settings/restart"` to `NEW_PREFIXES` with a short Italian comment.

- [ ] **Step 4: Verify** — four tests pass; frontend checks clean for the button.

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add routers/settings.py static/js/settings.js static/js/i18n.js docs/deploy docs/hardening.md tests/
git commit -m "feat(settings): restart the application from the dashboard"
```

---

### Task 5: Generate a self-signed certificate

**Files:**
- Modify: `routers/settings.py`, `static/js/settings.js`, `static/js/i18n.js`, `tests/test_router_parity.py`
- Test: `tests/test_settings_restart.py`

**Interfaces:**
- Produces: `POST /api/settings/tls/self-signed` with `{"host": "192.0.2.10"}` → writes `certs/server.crt` and `certs/server.key` under the data directory, returns their paths and the expiry.

**Context:** the `subjectAltName` must carry the address clients will actually use, or every modern client rejects the certificate regardless of its CN. That is the detail this task exists to stop people getting wrong.

- [ ] **Step 1: Write the failing tests**

```python
    def test_the_generated_certificate_carries_the_host_in_its_san(self):
        r = self.client.post("/api/settings/tls/self-signed",
                             headers=self.admin_h, json={"host": "192.0.2.10"})
        self.assertEqual(r.status_code, 200, r.text)
        import subprocess
        text = subprocess.run(["openssl", "x509", "-in", r.json()["certfile"],
                               "-noout", "-text"],
                              capture_output=True, text=True).stdout
        self.assertIn("192.0.2.10", text)
        self.assertIn("Subject Alternative Name", text)

    def test_it_refuses_to_overwrite_an_existing_certificate(self):
        # Overwriting the running certificate without asking would drop every
        # agent that verifies it, and there is no undo.
        self.client.post("/api/settings/tls/self-signed",
                         headers=self.admin_h, json={"host": "192.0.2.10"})
        r = self.client.post("/api/settings/tls/self-signed",
                             headers=self.admin_h, json={"host": "192.0.2.10"})
        self.assertEqual(r.status_code, 409, r.text)

    def test_the_host_is_validated_not_interpolated(self):
        r = self.client.post("/api/settings/tls/self-signed", headers=self.admin_h,
                             json={"host": "192.0.2.4/CN=x\nDNS:evil"})
        self.assertEqual(r.status_code, 400, r.text)
```

- [ ] **Step 2: Run to verify failure** — 404.

- [ ] **Step 3: Implement** — a fixed `openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes` argv with `-subj "/CN=<host>"` and `-addext "subjectAltName=IP:<host>"` (or `DNS:` for a hostname), a strict validator accepting only an IPv4 literal or a DNS label, the key written `chmod 600`, and a refusal when the files already exist.

The UI must state that the application has to be restarted for a new certificate to take effect — which Task 4 has just made possible from the same screen.

- [ ] **Step 4: Verify** — three tests pass; frontend checks clean.

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add routers/settings.py static/js/settings.js static/js/i18n.js tests/
git commit -m "feat(settings): generate a self-signed certificate for this host"
```

---

## Verification (after all tasks)

```bash
uv run pyrefly check                          # 0 errors
uv run python scripts/check_frontend.py       # clean
uv run python scripts/check_a11y.py --strict  # zero
uv run python scripts/check_i18n_coverage.py --strict
uv run pytest tests -n 4
graphify update .
```

Then end to end on the lab: the fleet panel shows the central and the Ubuntu
agent with real commits; deliberately leave the agent a version behind and
confirm it is marked; read the agent's log from the panel; change the HTTP port
in advanced settings and apply it with the restart button, without a shell.

Note the suite currently has an order-dependent failure predating this work
(`test_shared_paths_are_pinned`, subtest `collectors.mac_history.DB_PATH`),
reproduced on `Dev` before any of it. It is not caused by these tasks; do not
chase it here.
