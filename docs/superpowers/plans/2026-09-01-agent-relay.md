# Agent Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a site agent do for the central what a bastion does for a jump site — report device status and run triage/backup locally — so an agent site stops being a blind spot without the central ever dialling its devices.

**Architecture:** Two directions on the connection the agent already holds open. Agent → central: a status push every cycle and a triage/backup push on its own `backup_interval`, landing in the same `backup_store.save_backup()` / `update_version_inventory()` writes a central-poll triage uses. Central → agent: one new job kind, `triage`, enqueued by `/api/run-triage` when the device belongs to an agent site.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, `requests` (agent side), `unittest` run via `uv run pytest`, SQLite for the job queue.

**Spec:** `docs/superpowers/specs/2026-09-01-agent-relay-design.md`

## Global Constraints

- Run `uv run pyrefly check` (0 errors) and `uv run pytest tests -n 4` (all green) before every commit. Never claim a check passed without running it.
- Run `graphify update .` after code changes.
- New and rewritten comments in English. Existing Italian comments are left alone — do not "fix" them as a drive-by. The agent/router files are Italian-commented; new comments there may follow the local language for consistency, which is what the code samples below do.
- Comments explain *why*. No comment that restates the line below it.
- Never write a real customer IP, hostname, model or serial into a tracked file. Use RFC 5737 ranges or `switch-01`. The existing agent tests use `10.9.0.x` — match that inside `tests/test_remote_site.py`.
- Config payload cap: **5 MB**, rejected with HTTP 413, never truncated.
- `backup_interval` default: **3600** seconds; `0` disables the scheduled phase.
- Both new endpoints authenticate with the existing `get_agent_site` dependency and reject an IP not tagged to the calling site.
- Frontend rules (Task 7 only): no inline `onclick`; user-facing strings go through `tr('key')` with entries in **both** the `it` and `en` dictionaries of `static/js/i18n.js`; a new form control needs a `<label for>` or `aria-label` + `data-i18n-aria-label`.

---

### Task 1: Central accepts a device-status push

**Files:**
- Modify: `routers/agent.py` (schema beside the other `Agent*Schema`, endpoint after `agent_push_arp`)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: `get_agent_site` (existing dependency in `routers/agent.py`); `inventory_manager.update_version_inventory(ip, vendor, version, status="online", model=None, serial=None)`; `inventory_manager.get_all_devices()`; `inventory_manager.get_detected_versions()`.
- Produces: `POST /api/agent/status` accepting `{"devices": [{"ip": str, "up": bool}]}`, returning `{"status": "success", "updated": int}`. Task 3 calls it.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_remote_site.py`, inside `class RemoteSiteE2E`:

```python
    def test_agent_status_push_updates_the_central_state(self):
        sid, token = self._create_agent_site("Status-Push")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={"devices": [
            {"ip": "10.9.0.20", "vendor": "cisco", "hostname": "switch-01"},
            {"ip": "10.9.0.21", "vendor": "cisco", "hostname": "switch-02"},
        ]})

        r = self.client.post("/api/agent/status", headers=ah, json={"devices": [
            {"ip": "10.9.0.20", "up": True},
            {"ip": "10.9.0.21", "up": False},
        ]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["updated"], 2)

        from services import inventory_manager
        versions = inventory_manager.get_detected_versions()
        self.assertEqual(versions["10.9.0.20"]["status"], "online")
        self.assertEqual(versions["10.9.0.21"]["status"], "offline")

    def test_agent_status_push_cannot_touch_another_sites_device(self):
        # One site's token must never write another site's state: the agent
        # job feed is already over-broad (docs/remote-sites.md), and the
        # write path must not inherit that.
        sid_a, token_a = self._create_agent_site("Status-A")
        sid_b, token_b = self._create_agent_site("Status-B")
        self.client.post("/api/agent/inventory",
                         headers=self._agent_headers(sid_b, token_b),
                         json={"devices": [{"ip": "10.9.0.30", "vendor": "cisco"}]})

        r = self.client.post("/api/agent/status",
                             headers=self._agent_headers(sid_a, token_a),
                             json={"devices": [{"ip": "10.9.0.30", "up": True}]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["updated"], 0)

        from services import inventory_manager
        self.assertNotIn("10.9.0.30", inventory_manager.get_detected_versions())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_remote_site.py -k "agent_status_push" -v`
Expected: FAIL — 404, the route does not exist.

- [ ] **Step 3: Write minimal implementation**

In `routers/agent.py`, add the schema next to the other `Agent*Schema` classes:

```python
class AgentStatusItemSchema(BaseModel):
    ip: str
    up: bool

class AgentStatusSchema(BaseModel):
    devices: List[AgentStatusItemSchema] = []
```

And the endpoint after `agent_push_arp`:

```python
@router.post("/api/agent/status")
def agent_push_status(payload: AgentStatusSchema, site = Depends(get_agent_site)):
    """Esiti del ping che l'agente esegue sui PROPRI dispositivi.

    Il centrale non raggiunge i dispositivi di una sede con agente (vedi
    site_manager.has_direct_path): questo push e' l'unica fonte di stato
    up/down per quella sede."""
    site_id = site["id"]
    own = {d.get("IP") for d in inventory_manager.get_all_devices()
           if d.get("Site") == site_id}
    known = inventory_manager.get_detected_versions()
    n = 0
    for d in payload.devices:
        # Il token di una sede non deve poter alterare lo stato di un'altra.
        if d.ip not in own:
            continue
        prev = known.get(d.ip, {})
        inventory_manager.update_version_inventory(
            d.ip, prev.get("vendor", "cisco"),
            prev.get("version", "Non Rilevata"),
            "online" if d.up else "offline")
        n += 1
    return {"status": "success", "updated": n}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_remote_site.py -k "agent_status_push" -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add routers/agent.py tests/test_remote_site.py
git commit -m "feat(agent): central accepts a device-status push from the agent"
```

---

### Task 2: Central accepts a config/triage push

**Files:**
- Modify: `routers/agent.py`
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: `get_agent_site`; `core.backup_store.save_backup(device, sys_name, config_out) -> str`, where `device` is the central inventory dict and must carry `IP`, `Group`, `Vendor`; `inventory_manager.update_version_inventory(...)` with `serial=`; `inventory_manager.update_device_hostname(ip, hostname)`.
- Produces: `POST /api/agent/backup` accepting `{"ip", "hostname", "vendor", "version", "serial", "config"}`, returning `{"status": "success", "file": str}`; HTTP 413 over 5 MB; HTTP 404 for an IP not in the calling site. Tasks 4 and 5 call it.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_remote_site.py`, inside `class RemoteSiteE2E`:

```python
    def test_agent_backup_push_lands_in_backup_config_and_versions(self):
        sid, token = self._create_agent_site("Backup-Push")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={"devices": [
            {"ip": "10.9.0.40", "vendor": "cisco", "hostname": "switch-01"},
        ]})

        r = self.client.post("/api/agent/backup", headers=ah, json={
            "ip": "10.9.0.40", "hostname": "switch-01", "vendor": "cisco",
            "version": "15.2(7)E2", "serial": "ABC1234DEFG",
            "config": "hostname switch-01\n!\nend\n",
        })
        self.assertEqual(r.status_code, 200, r.text)

        saved = r.json()["file"]
        self.assertTrue(os.path.exists(saved))
        with open(saved, encoding="utf-8") as f:
            self.assertIn("hostname switch-01", f.read())

        from services import inventory_manager
        entry = inventory_manager.get_detected_versions()["10.9.0.40"]
        self.assertEqual(entry["status"], "online")
        self.assertEqual(entry["version"], "15.2(7)E2")

    def test_an_oversized_config_is_refused_without_writing(self):
        # Truncating is worse than refusing: config drift would report a
        # spurious change and the model classifier would read half a file.
        sid, token = self._create_agent_site("Backup-Huge")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.41", "vendor": "cisco"}]})

        r = self.client.post("/api/agent/backup", headers=ah, json={
            "ip": "10.9.0.41", "hostname": "switch-02", "vendor": "cisco",
            "version": "1.0", "serial": "",
            "config": "x" * (5 * 1024 * 1024 + 1),
        })
        self.assertEqual(r.status_code, 413, r.text)
        from services import inventory_manager
        self.assertNotIn("10.9.0.41", inventory_manager.get_detected_versions())

    def test_backup_push_cannot_target_another_sites_device(self):
        sid_a, token_a = self._create_agent_site("Backup-A")
        sid_b, token_b = self._create_agent_site("Backup-B")
        self.client.post("/api/agent/inventory",
                         headers=self._agent_headers(sid_b, token_b),
                         json={"devices": [{"ip": "10.9.0.42", "vendor": "cisco"}]})

        r = self.client.post("/api/agent/backup",
                             headers=self._agent_headers(sid_a, token_a),
                             json={"ip": "10.9.0.42", "hostname": "switch-03",
                                   "vendor": "cisco", "version": "1.0",
                                   "serial": "", "config": "end\n"})
        self.assertEqual(r.status_code, 404, r.text)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_remote_site.py -k "backup_push or oversized_config" -v`
Expected: FAIL — the route does not exist. (The cross-site test returns 404 for the wrong reason at this point; it becomes meaningful in Step 4.)

- [ ] **Step 3: Write minimal implementation**

In `routers/agent.py`, add to the imports at the top:

```python
from core import backup_store
```

Add the cap and the schema:

```python
MAX_CONFIG_BYTES = 5 * 1024 * 1024

class AgentBackupSchema(BaseModel):
    ip: str
    hostname: str = ""
    vendor: str = "cisco"
    version: str = "Non Rilevata"
    serial: str = ""
    config: str
```

And the endpoint:

```python
@router.post("/api/agent/backup")
def agent_push_backup(payload: AgentBackupSchema, site = Depends(get_agent_site)):
    """Config e versione raccolte dall'agente sui propri dispositivi.

    Passa dalle STESSE funzioni del triage centrale (backup_store.save_backup e
    update_version_inventory), cosi' mappa, config drift e classificazione per
    modello si popolano senza nuovi lettori."""
    site_id = site["id"]
    device = next((d for d in inventory_manager.get_all_devices()
                   if d.get("IP") == payload.ip and d.get("Site") == site_id), None)
    if device is None:
        raise HTTPException(
            status_code=404,
            detail=f"Dispositivo {payload.ip} non appartiene alla sede '{site_id}'.")
    if len(payload.config.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Config oltre il limite di 5 MB: rifiutata, non troncata.")
    sys_name = payload.hostname or payload.ip
    file_path = backup_store.save_backup(device, sys_name, payload.config)
    inventory_manager.update_version_inventory(
        payload.ip, payload.vendor, payload.version, "online",
        serial=payload.serial or None)
    if payload.hostname:
        inventory_manager.update_device_hostname(payload.ip, payload.hostname)
    log_audit(f"Agente sede '{site_id}': backup ricevuto per {payload.ip} "
              f"({len(payload.config)} caratteri).")
    return {"status": "success", "file": file_path}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_remote_site.py -k "backup_push or oversized_config" -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add routers/agent.py tests/test_remote_site.py
git commit -m "feat(agent): central accepts a config push from the agent"
```

---

### Task 3: The agent pings its own devices each cycle

**Files:**
- Modify: `services/site_agent.py` (add `push_status`, call it from `cycle()`)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: `POST /api/agent/status` (Task 1); `collectors.network_scanner._ping(ip) -> bool`; the existing `self._post(path, payload)` helper.
- Produces: `Agent.push_status(devices) -> dict`.

- [ ] **Step 1: Write the failing test**

Add a new class at the end of `tests/test_remote_site.py`:

```python
class AgentPushesItsOwnPingResults(unittest.TestCase):
    """The central does not reach an agent site's devices, so the agent's own
    ping is the only source of up/down for them."""

    def _agent(self):
        from unittest import mock
        from services import site_agent
        agent = site_agent.Agent.__new__(site_agent.Agent)
        agent.cfg = {"site_id": "milan", "interval": 60}
        agent._post = mock.MagicMock()
        agent._post.return_value.json.return_value = {"status": "success",
                                                      "updated": 2}
        return agent

    def test_every_device_is_reported_including_the_unreachable_one(self):
        # An unreachable device is pushed as down, never omitted: a skipped
        # device silently vanishes from the ping monitor, which is the
        # failure this change exists to remove.
        from unittest import mock

        agent = self._agent()
        devices = [{"IP": "10.9.0.50"}, {"IP": "10.9.0.51"}]
        with mock.patch("collectors.network_scanner._ping",
                        side_effect=lambda ip: ip == "10.9.0.50"):
            agent.push_status(devices)

        path, payload = agent._post.call_args[0]
        self.assertEqual(path, "/api/agent/status")
        self.assertEqual(payload["devices"],
                         [{"ip": "10.9.0.50", "up": True},
                          {"ip": "10.9.0.51", "up": False}])

    def test_no_devices_means_no_call(self):
        agent = self._agent()
        agent.push_status([])
        agent._post.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_remote_site.py -k AgentPushesItsOwn -v`
Expected: FAIL — `AttributeError: 'Agent' object has no attribute 'push_status'`

- [ ] **Step 3: Write minimal implementation**

In `services/site_agent.py`, add the method after `push_arp`:

```python
    def push_status(self, devices):
        """Ping locale dei propri dispositivi, spinto al centrale.

        Il centrale non ha (e non deve avere) un percorso diretto verso questi
        apparati: senza questo push la sede resta senza stato up/down."""
        from collectors.network_scanner import _ping as icmp_ping
        items = []
        for d in devices:
            ip = (d.get("IP") or "").strip()
            if not ip:
                continue
            try:
                up = bool(icmp_ping(ip))
            except Exception:
                up = False
            items.append({"ip": ip, "up": up})
        if not items:
            return {"updated": 0}
        r = self._post("/api/agent/status", {"devices": items})
        r.raise_for_status()
        return r.json()
```

And call it in `cycle()`, right after the `push_arp` block:

```python
        try:
            self.push_status(devices)
        except Exception as e:
            print(f"[status] errore: {e}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_remote_site.py -k AgentPushesItsOwn -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add services/site_agent.py tests/test_remote_site.py
git commit -m "feat(agent): the agent pings its own devices and pushes the result"
```

---

### Task 4: The agent runs triage/backup on its own interval

**Files:**
- Modify: `services/site_agent.py` (`load_config` default, `Agent.__init__` clock, `push_backup`, `maybe_run_backups`, `cycle()`)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: `POST /api/agent/backup` (Task 2); `core_engine.run_backup_and_triage(device)`, which returns `{"status": "success", "version": str, "hostname": str, "file": str}` or `{"status": "error", "message": str}`.
- Produces: `Agent.push_backup(device) -> dict` and `Agent.maybe_run_backups(devices) -> int`. Task 5 calls `push_backup`.

- [ ] **Step 1: Write the failing test**

Add a new class at the end of `tests/test_remote_site.py`:

```python
class AgentScheduledBackup(unittest.TestCase):
    """The backup interval is deliberately not the polling interval: a 15s
    poll must not mean a config backup every 15 seconds."""

    def _agent(self, backup_interval=3600):
        from unittest import mock
        from services import site_agent
        agent = site_agent.Agent.__new__(site_agent.Agent)
        agent.cfg = {"site_id": "milan", "interval": 60,
                     "backup_interval": backup_interval}
        agent._last_backup = 0.0
        agent._post = mock.MagicMock()
        agent._post.return_value.json.return_value = {"status": "success",
                                                      "file": "/x"}
        return agent

    def test_a_successful_triage_is_pushed_with_its_config_text(self):
        import tempfile
        from unittest import mock
        from core import core_engine

        agent = self._agent()
        d = tempfile.mkdtemp(prefix="sentinelnet_bk_")
        path = os.path.join(d, "switch-01-10.9.0.60.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("hostname switch-01\nend\n")

        device = {"IP": "10.9.0.60", "Vendor": "cisco", "Group": "Generale"}
        with mock.patch.object(core_engine, "run_backup_and_triage",
                               return_value={"status": "success",
                                             "version": "15.2(7)E2",
                                             "hostname": "switch-01",
                                             "file": path}):
            agent.push_backup(device)

        call_path, payload = agent._post.call_args[0]
        self.assertEqual(call_path, "/api/agent/backup")
        self.assertEqual(payload["ip"], "10.9.0.60")
        self.assertEqual(payload["hostname"], "switch-01")
        self.assertIn("hostname switch-01", payload["config"])

    def test_a_failed_triage_pushes_nothing(self):
        # A partial or empty push must never overwrite a good stored config.
        from unittest import mock
        from core import core_engine

        agent = self._agent()
        device = {"IP": "10.9.0.61", "Vendor": "cisco", "Group": "Generale"}
        with mock.patch.object(core_engine, "run_backup_and_triage",
                               return_value={"status": "error", "message": "boom"}):
            out = agent.push_backup(device)
        agent._post.assert_not_called()
        self.assertEqual(out["status"], "error")

    def test_interval_zero_disables_the_scheduled_phase(self):
        from unittest import mock
        agent = self._agent(backup_interval=0)
        with mock.patch.object(agent, "push_backup") as pb:
            n = agent.maybe_run_backups([{"IP": "10.9.0.62"}])
        pb.assert_not_called()
        self.assertEqual(n, 0)

    def test_the_phase_does_not_run_again_before_its_interval(self):
        from unittest import mock
        agent = self._agent(backup_interval=3600)
        with mock.patch.object(agent, "push_backup",
                               return_value={"status": "success"}) as pb:
            first = agent.maybe_run_backups([{"IP": "10.9.0.63"}])
            second = agent.maybe_run_backups([{"IP": "10.9.0.63"}])
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(pb.call_count, 1)
        self.assertGreater(agent._last_backup, 0.0)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_remote_site.py -k AgentScheduledBackup -v`
Expected: FAIL — `AttributeError: 'Agent' object has no attribute 'push_backup'`

- [ ] **Step 3: Write minimal implementation**

In `load_config`, beside the other `setdefault` calls:

```python
    cfg.setdefault("backup_interval", 3600)
```

In `Agent.__init__`, beside `self._start_ts`:

```python
        # 0.0 = mai eseguito, quindi il primo ciclo fa subito un backup e poi
        # l'intervallo governa. Attendere un'ora prima del primo lascerebbe
        # mappa e versioni vuote per un'ora dopo il deploy.
        self._last_backup = 0.0
```

After `push_status`:

```python
    def push_backup(self, device):
        """Triage+backup locale di un dispositivo, spinto al centrale.

        La copia locale in data/backup-config resta: e' quella che l'agente
        scrive comunque. Al centrale va il testo, perche' e' li' che vivono
        mappa, config drift e classificazione per modello."""
        res = core_engine.run_backup_and_triage(device)
        if res.get("status") != "success":
            return {"status": "error", "message": res.get("message", "errore")}
        try:
            with open(res["file"], encoding="utf-8") as f:
                config_out = f.read()
        except OSError as e:
            return {"status": "error", "message": f"backup illeggibile: {e}"}
        r = self._post("/api/agent/backup", {
            "ip": device["IP"],
            "hostname": res.get("hostname", ""),
            "vendor": device.get("Vendor", "cisco"),
            "version": res.get("version", "Non Rilevata"),
            "serial": "",
            "config": config_out,
        })
        r.raise_for_status()
        return {"status": "success", **r.json()}

    def maybe_run_backups(self, devices):
        """Fase di backup schedulata. Ritorna quanti dispositivi sono passati."""
        every = int(self.cfg.get("backup_interval") or 0)
        if every <= 0:
            return 0
        now = time.time()
        if self._last_backup and now - self._last_backup < every:
            return 0
        self._last_backup = now
        n = 0
        for d in devices:
            try:
                if self.push_backup(d).get("status") == "success":
                    n += 1
            except Exception as e:
                print(f"[backup] {d.get('IP')}: {e}")
        return n
```

In `cycle()`, after the `push_status` block:

```python
        try:
            self.maybe_run_backups(devices)
        except Exception as e:
            print(f"[backup] errore: {e}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_remote_site.py -k AgentScheduledBackup -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add services/site_agent.py tests/test_remote_site.py
git commit -m "feat(agent): the agent runs triage and backup on its own interval"
```

---

### Task 5: A `triage` job the central can enqueue

**Files:**
- Modify: `services/site_manager.py:340` (`VALID_JOB_KINDS`)
- Modify: `services/site_agent.py` (`run_jobs` dispatch)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: `Agent.push_backup(device)` (Task 4); `site_manager.enqueue_job(site_id, device_ip, command, requested_by="", kind="cli") -> dict`.
- Produces: `kind="triage"` accepted by `enqueue_job` and handled by `run_jobs`. Task 6 enqueues it.

- [ ] **Step 1: Write the failing test**

Add to `class AgentScheduledBackup` in `tests/test_remote_site.py`:

```python
    def test_a_triage_job_runs_the_local_backup_and_reports_a_short_result(self):
        # The job result column is rendered verbatim in the job-history panel,
        # so it carries a summary and never the config text.
        from unittest import mock
        agent = self._agent()
        agent._get = mock.MagicMock()
        agent._get.return_value.json.return_value = {"jobs": [
            {"id": "j1", "device_ip": "10.9.0.64", "command": "", "kind": "triage"},
        ]}
        posted = []

        def _capture(path, body):
            posted.append((path, body))
            return mock.MagicMock()

        agent._post = mock.MagicMock(side_effect=_capture)

        with mock.patch.object(agent, "push_backup",
                               return_value={"status": "success", "file": "/x"}) as pb:
            agent.run_jobs([{"IP": "10.9.0.64", "Vendor": "cisco"}])

        pb.assert_called_once()
        results = [body for path, body in posted if path.endswith("/result")]
        self.assertEqual(results[0]["status"], "done")
        self.assertNotIn("hostname", results[0]["result"])
```

And to `class RemoteSiteE2E`:

```python
    def test_the_job_queue_accepts_a_triage_kind(self):
        from services import site_manager
        sid, _token = self._create_agent_site("Triage-Kind")
        job = site_manager.enqueue_job(sid, "10.9.0.65", "", requested_by=ADMIN,
                                       kind="triage")
        self.assertEqual(job["kind"], "triage")
        with self.assertRaises(ValueError):
            site_manager.enqueue_job(sid, "10.9.0.65", "", kind="nonsense")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_remote_site.py -k "triage_kind or triage_job" -v`
Expected: FAIL — `ValueError: Tipo di job non valido: triage`

- [ ] **Step 3: Write minimal implementation**

In `services/site_manager.py` line 340:

```python
VALID_JOB_KINDS = ("cli", "rest", "triage")
```

In `services/site_agent.py`, inside `run_jobs`, add a branch before the `cmd.startswith("_agent_")` check:

```python
            elif job.get("kind") == "triage":
                device = by_ip.get(ip)
                if not device:
                    out = {"status": "error",
                           "result": f"Dispositivo {ip} non in inventario locale."}
                else:
                    res = self.push_backup(device)
                    # Un riassunto, mai la config: questa colonna viene resa
                    # tale e quale nel pannello storico job.
                    out = ({"status": "done", "result": "backup inviato al centrale"}
                           if res.get("status") == "success"
                           else {"status": "error",
                                 "result": res.get("message", "errore")})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_remote_site.py -k "triage_kind or triage_job" -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add services/site_manager.py services/site_agent.py tests/test_remote_site.py
git commit -m "feat(sites): a triage job kind the central can enqueue for an agent"
```

---

### Task 6: `/api/run-triage` queues instead of refusing

**Files:**
- Modify: `routers/triage.py` (`run_triage`, from line 83)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: `site_manager.is_agent_site(site_id) -> bool`; `site_manager.enqueue_job(..., kind="triage")` (Task 5).
- Produces: the triage response gains a `queued` count.

- [ ] **Step 1: Read the current implementation first**

Read `routers/triage.py:83-133` in full before editing. The loop's exact shape — whether it runs in a background thread, how results accumulate into `triage_job` — decides where the branch goes, and this plan deliberately does not guess it. The test below uses `site_manager.list_jobs(site_id, limit=100)`, verified to exist at `services/site_manager.py:530`.

- [ ] **Step 2: Write the failing test**

Add to `class RemoteSiteE2E`:

```python
    def test_triage_on_an_agent_device_is_queued_not_refused(self):
        # b9ecd63 made the direct path refuse. The operator-visible answer is
        # now "queued": the agent runs it and pushes the result back.
        from services import site_manager
        sid, token = self._create_agent_site("Triage-Queue")
        ah = self._agent_headers(sid, token)
        self.client.post("/api/agent/inventory", headers=ah, json={
            "devices": [{"ip": "10.9.0.70", "vendor": "cisco",
                         "hostname": "switch-01", "group": "Generale"}]})

        r = self.client.post("/api/run-triage", headers=self.admin_h,
                             json={"group": "Generale"})
        self.assertEqual(r.status_code, 200, r.text)

        jobs = site_manager.list_jobs(sid)
        self.assertTrue(any(j["device_ip"] == "10.9.0.70" and j["kind"] == "triage"
                            for j in jobs), jobs)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `uv run pytest tests/test_remote_site.py -k triage_on_an_agent_device -v`
Expected: FAIL — no job is enqueued; the device is refused by `run_backup_and_triage`.

- [ ] **Step 4: Write minimal implementation**

Initialise `queued = 0` before the device loop, and in the loop, before calling `core_engine.run_backup_and_triage(d)`:

```python
        if site_manager.is_agent_site(d.get('Site')):
            # Il centrale non apre SSH verso una sede con agente: la richiesta
            # diventa un job che l'agente ritira al prossimo polling.
            site_manager.enqueue_job(d['Site'], d['IP'], "",
                                     requested_by=current_user.get('sub', ''),
                                     kind="triage")
            queued += 1
            continue
```

Include `queued` in the response payload the route returns.

- [ ] **Step 5: Run test to verify it passes**

Run: `uv run pytest tests/test_remote_site.py -k triage_on_an_agent_device -v`
Expected: PASS

- [ ] **Step 6: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add routers/triage.py tests/test_remote_site.py
git commit -m "feat(triage): an agent-site device is queued for its agent, not refused"
```

---

### Task 7: `backup_interval` in the agent config panel

**Files:**
- Modify: `routers/agent.py` (`agent_heartbeat`)
- Modify: `services/site_agent.py` (`heartbeat` payload)
- Modify: `routers/sites.py` (`AgentConfigUpdateSchema`, `agent_config_update_ep`)
- Modify: `static/js/site-agent.js` (config form + save handler)
- Modify: `static/js/i18n.js` (both dictionaries)
- Test: `tests/test_remote_site.py`

**Interfaces:**
- Consumes: the existing `_agent_config` job path, which already carries `syslog_port` and `interval`.
- Produces: `backup_interval` round-tripping dashboard → job → agent → heartbeat → `sites.json`.

- [ ] **Step 1: Write the failing test**

Add to `class RemoteSiteE2E`:

```python
    def test_backup_interval_round_trips_through_the_heartbeat(self):
        from services import site_manager
        sid, token = self._create_agent_site("Backup-Interval")
        ah = self._agent_headers(sid, token)
        r = self.client.post("/api/agent/heartbeat", headers=ah,
                             json={"backup_interval": 900})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(site_manager.get_site(sid)["backup_interval"], 900)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_remote_site.py -k backup_interval_round_trips -v`
Expected: FAIL — `KeyError: 'backup_interval'`

- [ ] **Step 3: Write minimal implementation**

In `routers/agent.py`, inside `agent_heartbeat`, beside the existing `syslog_port` / `interval` handling:

```python
        if "backup_interval" in payload:
            updates["backup_interval"] = payload["backup_interval"]
```

In `services/site_agent.py`, `heartbeat()`, add `backup_interval` to the payload it already sends with `syslog_port` and `interval`.

In `routers/sites.py`, add `backup_interval: Optional[int] = None` to `AgentConfigUpdateSchema` and include it in the JSON the endpoint puts into the `_agent_config` command, following exactly how `syslog_port` is handled there.

In `static/js/site-agent.js`, beside `curPort` / `curInterval`:

```javascript
        let curBackupInterval = (site && site.backup_interval) || 3600;
```

and a third control in the config grid (note the `<label for>`: `scripts/check_a11y.py --strict` is at zero and must stay there):

```html
                <div>
                    <label for="agentCfgBackupInterval" style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">${tr('agentBackupInterval')}</label>
                    <input id="agentCfgBackupInterval" type="number" value="${curBackupInterval}" style="width:100%; padding:6px 10px; font-size:12px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); color:var(--text);">
                </div>
```

Include its value in the save handler's request body next to the syslog port and interval.

In `static/js/i18n.js`, add to the `it` dictionary:

```javascript
        agentBackupInterval: "Intervallo Backup Config (sec, 0 = spento)",
```

and to the `en` dictionary:

```javascript
        agentBackupInterval: "Config Backup Interval (sec, 0 = off)",
```

- [ ] **Step 4: Run the test and the frontend gates**

```bash
uv run pytest tests/test_remote_site.py -k backup_interval_round_trips -v
uv run python scripts/check_frontend.py
uv run python scripts/check_a11y.py --strict
uv run python scripts/check_i18n_coverage.py --strict
```
Expected: test PASS, all three checks clean.

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4
graphify update .
git add static/js/site-agent.js static/js/i18n.js routers/sites.py routers/agent.py services/site_agent.py tests/test_remote_site.py
git commit -m "feat(agent): the config backup interval is settable from the dashboard"
```

---

### Task 8: Documentation

**Files:**
- Modify: `docs/remote-sites.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update `docs/remote-sites.md`**

Principle 5 currently says the central never dials the devices and their status comes from what the agent pushes. Extend it to name what is now pushed — ping results every cycle, config and version on `backup_interval`, and a `triage` job an operator can enqueue — and add `/api/agent/status` and `/api/agent/backup` wherever the document lists the agent protocol endpoints.

- [ ] **Step 2: Update `CHANGELOG.md`**

Under `## [Unreleased]`, add an `### Added` section before the existing `### Security`, describing what an agent site could not do before and what now travels over the agent's outbound connection. Say what the reader gains, not which files changed.

- [ ] **Step 3: Commit**

```bash
git add docs/remote-sites.md CHANGELOG.md
git commit -m "docs(remote-sites): the agent relay for status and triage"
```

---

## Verification (after all tasks)

```bash
uv run pyrefly check                          # 0 errors
uv run python scripts/check_frontend.py       # clean
uv run pytest tests -n 4                      # all green
graphify update .
```

Then end to end against the lab: with the agent running, confirm its devices leave "non misurabile" in the ping monitor, that a config appears under `data/backup-config/<group>/` on the **central**, and that the firewall log shows **no** ICMP or SSH from the central to those devices for the whole exercise. That last one is the point of the feature.
