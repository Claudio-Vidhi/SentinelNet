# Subnet Scan Discovery-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the subnet scan into pure discovery (ping + configurable TCP ports, zero credentials), and move SSH login into an optional, explicitly-triggered verify step that uses a user-chosen identity on user-selected rows only.

**Architecture:** `scan_subnet()` loses its credential/triage phase and becomes a single-phase port sweep. A new `POST /api/scan-verify` endpoint reuses the existing `_scan_jobs` background-job machinery to run `probe_device()` against selected IPs with credentials pulled from an identity. The scan modal grows a port field, a row-selection table, and two independent bottom actions (Verify / Add).

**Tech Stack:** Python 3, FastAPI, Pydantic v2, `concurrent.futures.ThreadPoolExecutor`, netmiko (via `probe_device`), vanilla JS + Jinja template (`templates/dashboard.html`), `unittest` + `fastapi.testclient.TestClient`.

**Spec:** `docs/superpowers/specs/2026-08-10-subnet-scan-discovery-design.md`

## Global Constraints

- Code comments in English (`CLAUDE.md` §Coding Style). Docs and user-facing strings follow the file they live in (Italian prose in `docs/`, IT+EN pairs in `static/js/i18n.js`).
- Never write real device models, versions, hostnames, serials or management IPs into tracked files. Examples use RFC 5737 (`192.0.2.x`, `198.51.100.x`), `switch-01`, `AA:BB:CC:DD:EE:FF` (`CLAUDE.md` §Protect real data).
- Before **each** commit, run and read the output of:
  - `uv run pyrefly check` — must be 0 errors
  - `uv run python -m unittest discover -s tests` — all green
  - `graphify update .` — after code changes
- Single test file run form (files end with `unittest.main()`): `uv run python tests/test_scan_and_hostkeys.py`
- Single test run form: `uv run python tests/test_scan_and_hostkeys.py TestClassName.test_method_name -v`
- Do not add feature flags or backwards-compat shims; delete the old code paths outright (`CLAUDE.md` §Coding Style).
- All values interpolated into HTML from JS use `escapeHtml(jsStr(x))`.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `collectors/network_scanner.py` | Enumerate hosts, ping + TCP port sweep. No credentials, ever. | Modify |
| `routers/scan.py` | Scan job lifecycle, port validation, verify job + tenant gate | Modify |
| `security/identity_manager.py` | Owns tenant-visibility semantics for identities | Modify (+1 function) |
| `templates/dashboard.html` | `subnetScanModal` markup | Modify |
| `static/js/i18n.js` | IT/EN strings for the modal | Modify |
| `static/js/devices.js` | Scan start, polling, result table, selection, verify, add | Modify |
| `tests/test_scan_and_hostkeys.py` | Scanner behaviour (2 existing classes need rewriting) | Modify |
| `tests/test_scan_verify.py` | `/api/scan-verify` endpoint + tenant gate | Create |

---

### Task 1: `scan_subnet()` becomes discovery-only

**Files:**
- Modify: `collectors/network_scanner.py:1-7` (imports), `:57-147` (whole function)
- Test: `tests/test_scan_and_hostkeys.py:50-108` (rewrite both existing scan classes)

**Interfaces:**
- Consumes: `parse_network(address) -> list[str]`, `_ping(ip) -> bool`, `core.core_engine.is_reachable(ip, port, timeout) -> bool` (all already present)
- Produces: `scan_subnet(address: str, ports: list[int], max_workers: int = 50, progress_cb=None) -> list[dict]` where each dict is `{"ip": str, "alive": bool, "open_ports": list[int]}`, sorted by IP ascending, containing only hosts where `alive or open_ports`

The two existing test classes (`TestScanProgress`, `TestScanIsDiscoveryOnly`) call `scan_subnet` with `vendor_hint=` / `credentials=` and will fail to even call the new signature. They are rewritten here, in the same task, because they are the test cycle for this deliverable.

- [x] **Step 1: Write the failing tests**

Replace `tests/test_scan_and_hostkeys.py` lines 50-108 (both classes `TestScanProgress` and `TestScanIsDiscoveryOnly`, keeping `TestKnownHostsBootstrap` above and the `unittest.main()` footer below) with:

```python
class TestScanIsDiscoveryOnly(unittest.TestCase):
    """Discovery must never authenticate. A subnet sweep that logs in produces
    an auth-failure burst on every host that does not use those credentials."""

    def test_scan_never_opens_an_ssh_session(self):
        from core import core_engine
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable", return_value=False), \
             mock.patch.object(core_engine, "probe_device") as probe, \
             mock.patch.object(core_engine, "run_backup_and_triage") as backup:
            ns.scan_subnet(address="192.0.2.0/29", ports=[22])
        probe.assert_not_called()
        backup.assert_not_called()

    def test_host_found_by_port_with_ping_failing(self):
        # ICMP is dropped by most firewalls: a ping pre-filter hides real devices.
        with mock.patch.object(ns, "_ping", return_value=False), \
             mock.patch.object(ns, "is_reachable",
                               side_effect=lambda ip, port, timeout=1: ip.endswith(".1") and port == 443):
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[22, 443])
        by_ip = {r["ip"]: r for r in rows}
        self.assertEqual(list(by_ip), ["192.0.2.1"])
        self.assertFalse(by_ip["192.0.2.1"]["alive"])
        self.assertEqual(by_ip["192.0.2.1"]["open_ports"], [443])

    def test_host_found_by_ping_with_no_open_ports(self):
        with mock.patch.object(ns, "_ping", side_effect=lambda ip: ip.endswith(".2")), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[22])
        self.assertEqual([r["ip"] for r in rows], ["192.0.2.2"])
        self.assertTrue(rows[0]["alive"])
        self.assertEqual(rows[0]["open_ports"], [])

    def test_silent_host_is_absent(self):
        with mock.patch.object(ns, "_ping", return_value=False), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[22])
        self.assertEqual(rows, [])

    def test_empty_port_list_is_ping_only(self):
        with mock.patch.object(ns, "_ping", side_effect=lambda ip: ip.endswith(".1")), \
             mock.patch.object(ns, "is_reachable") as reach:
            rows = ns.scan_subnet(address="192.0.2.0/29", ports=[])
        reach.assert_not_called()
        self.assertEqual([r["ip"] for r in rows], ["192.0.2.1"])

    def test_port_connect_timeout_is_one_second(self):
        # is_reachable defaults to 2s (core_engine.py:210). On a silent /24 with
        # 3 ports that is 1524 seconds of connect budget across the pool.
        seen = []
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable",
                               side_effect=lambda ip, port, timeout: seen.append(timeout) or False):
            ns.scan_subnet(address="192.0.2.0/30", ports=[22])
        self.assertEqual(set(seen), {1})

    def test_results_are_sorted_by_ip(self):
        # as_completed yields in completion order; the UI table must be stable.
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            rows = ns.scan_subnet(address="192.0.2.0/28", ports=[])
        self.assertEqual([r["ip"] for r in rows], sorted(
            (r["ip"] for r in rows), key=lambda s: tuple(int(o) for o in s.split("."))))


class TestScanProgress(unittest.TestCase):
    """One phase now: no triage, so the total no longer grows mid-run."""

    def test_progress_is_single_phase(self):
        calls = []
        with mock.patch.object(ns, "_ping", return_value=True), \
             mock.patch.object(ns, "is_reachable", return_value=False):
            ns.scan_subnet(address="192.0.2.0/29", ports=[22],
                           progress_cb=lambda done, total: calls.append((done, total)))
        # 6 usable hosts in a /29, one unit of work each.
        self.assertEqual(calls[-1], (6, 6))
        self.assertEqual({t for _, t in calls}, {6})
```

- [x] **Step 2: Run the tests to verify they fail**

Run: `uv run python tests/test_scan_and_hostkeys.py -v`
Expected: FAIL — `TypeError: scan_subnet() got an unexpected keyword argument 'ports'` (and `missing ... 'vendor_hint'`).

- [x] **Step 3: Rewrite the scanner**

In `collectors/network_scanner.py`, delete these two import lines:

```python
from security import crypto_vault
from core.core_engine import is_reachable, probe_device
```

and replace them with:

```python
from core.core_engine import is_reachable
```

Then replace the entire `scan_subnet` function (lines 57-147, everything from `def scan_subnet(` to the end of the file) with:

```python
def scan_subnet(
    address: str,
    ports: list[int],
    max_workers: int = 50,
    progress_cb=None,
) -> list[dict]:
    """Discovery only: no credentials, no login, no vendor guessing.

    1. parse_network() to enumerate host IPs.
    2. For every host concurrently: ping, then a TCP connect per requested port.
    3. Return the hosts that answered anything, sorted by IP:
         {"ip": str, "alive": bool, "open_ports": list[int]}

    A host that drops ICMP but has a port open still counts as found: firewalls
    that discard ping are the norm, so a ping pre-filter would hide real devices.

    ports is already validated by the caller (routers/scan.py); an empty list is
    a legitimate ping-only sweep.

    progress_cb, if given, is called as cb(done, len(hosts)) once per host.
    """
    hosts = parse_network(address)
    ports = list(ports)

    def _probe_host(ip: str) -> dict:
        alive = _ping(ip)
        # timeout=1 explicitly: is_reachable defaults to 2s, and this runs
        # len(hosts) * len(ports) times.
        open_ports = [p for p in ports if is_reachable(ip, p, timeout=1)]
        return {"ip": ip, "alive": alive, "open_ports": open_ports}

    found: list[dict] = []
    done = 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_probe_host, ip) for ip in hosts]
        for fut in as_completed(futures):
            row = fut.result()
            done += 1
            if progress_cb:
                progress_cb(done, len(hosts))
            if row["alive"] or row["open_ports"]:
                found.append(row)

    # as_completed yields in completion order; the table must not reshuffle.
    found.sort(key=lambda r: ipaddress.IPv4Address(r["ip"]))
    return found
```

- [x] **Step 4: Run the tests to verify they pass**

Run: `uv run python tests/test_scan_and_hostkeys.py -v`
Expected: PASS, all classes including `TestKnownHostsBootstrap`.

- [x] **Step 5: Verify nothing else calls the old signature**

Run: `uv run pyrefly check`
Expected: errors in `routers/scan.py` only (it still passes `vendor_hint=`/`credentials=`). That file is Task 2. If any *other* file appears, stop and report it — the spec assumed `routers/scan.py` is the sole caller.

- [x] **Step 6: Commit**

Note: this commit leaves `routers/scan.py` calling the old signature. That is intentional — Task 2 is the other half and lands immediately after. Do not run the full suite as a gate here; run it at the end of Task 2.

```bash
git add collectors/network_scanner.py tests/test_scan_and_hostkeys.py
git commit -m "refactor(scan): scan_subnet fa solo scoperta, niente credenziali

Ping + porte TCP configurabili. Spariscono vendor_hint, credentials e
la fase di triage SSH: la scansione non tenta piu' il login su ogni
host con la 22 aperta."
```

---

### Task 2: Port validation, and the router stops handing out credentials

**Files:**
- Modify: `routers/scan.py:8` (imports), `:21-26` (`SubnetScanRequest`), `:32-81` (`_run_scan_job`), `:83-119` (`start_subnet_scan`)
- Test: `tests/test_scan_verify.py` (create — port validation tests land here, the endpoint tests join in Task 4)

**Interfaces:**
- Consumes: `scan_subnet(address, ports, max_workers=50, progress_cb=None)` from Task 1
- Produces: `POST /api/scan-subnet` accepting `{"network": str, "ports": list[int]}`; `_scan_jobs[job_id]` dict shape `{"status", "results", "progress", "total", "started_at"}` (unchanged) — Task 4 reuses it

- [x] **Step 1: Write the failing test**

Create `tests/test_scan_verify.py`:

```python
# -*- coding: utf-8 -*-
"""Subnet scan is discovery-only; the login step is a separate, explicit
endpoint gated on an identity the caller is allowed to use."""

import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

_TMP_DATA_DIR = tempfile.mkdtemp(prefix="sentinelnet_test_scanverify_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP_DATA_DIR

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from security import user_manager  # noqa: E402

ADMIN, ADMIN_PASS = "scanadmin", "PasswordSicura1!"


class ScanApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        user_manager.create_user(ADMIN, ADMIN_PASS, role="admin")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DATA_DIR, ignore_errors=True)

    def _client(self):
        client = TestClient(app_server.app)
        r = client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        self.assertEqual(r.status_code, 200)
        token = r.json()["access_token"]
        client.headers.update({"Authorization": f"Bearer {token}"})
        return client


class TestScanPortValidation(ScanApiTestCase):
    """Ports are user input: 254 hosts x 65535 ports is one POST away."""

    def _post(self, body):
        with mock.patch("routers.scan.threading.Thread"):
            return self._client().post("/api/scan-subnet", json=body)

    def test_default_is_port_22(self):
        with mock.patch("routers.scan.threading.Thread") as thread:
            r = self._client().post("/api/scan-subnet", json={"network": "192.0.2.0/29"})
        self.assertEqual(r.status_code, 200)
        payload = thread.call_args.kwargs["args"][1]
        self.assertEqual(payload.ports, [22])

    def test_empty_port_list_is_accepted(self):
        r = self._post({"network": "192.0.2.0/29", "ports": []})
        self.assertEqual(r.status_code, 200)

    def test_port_out_of_range_is_rejected(self):
        self.assertEqual(self._post({"network": "192.0.2.0/29", "ports": [0]}).status_code, 422)
        self.assertEqual(self._post({"network": "192.0.2.0/29", "ports": [65536]}).status_code, 422)

    def test_too_many_ports_is_rejected(self):
        r = self._post({"network": "192.0.2.0/29", "ports": list(range(1, 20))})
        self.assertEqual(r.status_code, 422)

    def test_invalid_network_is_400(self):
        r = self._post({"network": "not-a-network", "ports": [22]})
        self.assertEqual(r.status_code, 400)

    def test_vendor_and_auto_add_are_gone(self):
        # Extra keys must not resurrect the old behaviour by accident.
        import inspect
        from routers import scan
        source = inspect.getsource(scan)
        self.assertNotIn("auto_add", source)
        self.assertNotIn("use_default_creds", source)
        self.assertNotIn("DEFAULT_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
```

- [x] **Step 2: Run the test to verify it fails**

Run: `uv run python tests/test_scan_verify.py -v`
Expected: FAIL — `test_default_is_port_22` errors with `AttributeError: 'SubnetScanRequest' object has no attribute 'ports'`, and `test_vendor_and_auto_add_are_gone` fails on `auto_add`.

- [x] **Step 3: Rewrite the request model and the job**

In `routers/scan.py`, change the typing import on line 8 to:

```python
from typing import Annotated, Optional, List, Dict, Any
```

and add `Field` to the pydantic import:

```python
from pydantic import BaseModel, Field
```

Replace `SubnetScanRequest` (lines 21-26) with:

```python
class SubnetScanRequest(BaseModel):
    network: str
    # Ports are user input and each one costs len(hosts) TCP connects: cap the
    # list, or 254 x 65535 connects are one POST away. Empty = ping-only sweep.
    ports: List[Annotated[int, Field(ge=1, le=65535)]] = Field(
        default_factory=lambda: [22], max_length=16
    )
```

Replace `_run_scan_job` (lines 32-81) with:

```python
def _run_scan_job(job_id: str, req: SubnetScanRequest):
    def _progress(done: int, total: int):
        with _scan_jobs_lock:
            if job_id in _scan_jobs:
                _scan_jobs[job_id]["progress"] = done

    try:
        results = scan_subnet(
            address=req.network,
            ports=req.ports,
            progress_cb=_progress,
        )
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"]   = "done"
            _scan_jobs[job_id]["results"]  = results
            _scan_jobs[job_id]["progress"] = _scan_jobs[job_id]["total"]
    except Exception as exc:
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"] = "error"
            _scan_jobs[job_id]["error"]  = str(exc)
```

In `start_subnet_scan` (lines 83-119), delete the `assert_group_allowed(current_user, payload.group)` call and its three-line comment: nothing is written to the inventory any more, and the group check lives on `/api/add-device` (`routers/inventory.py:164`), now the only way in. Keep the `parse_network` validation, the job creation, the dedicated thread and the `log_audit` line, but change the audit message to mention ports:

```python
    log_audit(
        f"Scansione subnet '{payload.network}' (porte: {payload.ports}) avviata "
        f"dall'utente '{current_user.get('sub')}' (job_id: {job_id}, host totali: {len(hosts)})."
    )
```

Finally fix the imports at the top: `inventory_manager` (line 17), `assert_group_allowed` (line 14) and `from core import core_engine` (line 16) are all unused by this module now — remove them. Task 4 imports `probe_device` explicitly rather than going through `core_engine`.

- [x] **Step 4: Run the tests to verify they pass**

Run: `uv run python tests/test_scan_verify.py -v`
Expected: PASS, 6 tests.

- [x] **Step 5: Run the full gate**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
```
Expected: pyrefly 0 errors; suite green. `tests/test_scan_and_hostkeys.py` from Task 1 must still pass here.

- [x] **Step 6: Commit**

```bash
graphify update .
git add routers/scan.py tests/test_scan_verify.py
git commit -m "feat(scan): porte configurabili, via auto_add e credenziali globali

SubnetScanRequest si riduce a network + ports (validate, max 16). Cadono
vendor, group, auto_add e use_default_creds (quest'ultimo dichiarato e mai
letto). Il controllo di sede resta su /api/add-device, unica via d'ingresso
all'inventario."
```

---

### Task 3: Identity visibility helper

**Files:**
- Modify: `security/identity_manager.py` (add one function after `get_identity_credentials`, around line 107)
- Test: `tests/test_scan_verify.py` (add one class)

**Interfaces:**
- Consumes: `_load()`, `_matches_tenant(r_tenant, target_tenant)`, `_lock` — all already in `identity_manager`
- Produces: `identity_visible_to(identity_id: str, tenants) -> bool` where `tenants` is a set of site names or `None` for unrestricted. Task 4 calls this before decrypting anything.

**Why this lives here:** `routers/deps.py` has no per-user tenant field — a caller's tenants are their *site scope*, `user_group_scope(current_user)` (`routers/deps.py:91`), which returns `None` for admin. Tenant and site are the same namespace in this codebase (`routers/ai.py:695` validates a tenant against `inventory_manager.get_all_groups()`; `routers/arp.py:58` assigns `tenants = user_group_scope(current_user)`). The matching rule itself already exists as `_matches_tenant`; this function is the public, set-aware wrapper so the router never imports a private.

- [x] **Step 1: Write the failing test**

Add to `tests/test_scan_verify.py`, above the `if __name__` footer:

```python
class TestIdentityVisibility(unittest.TestCase):
    """A caller restricted to some sites must not borrow another site's
    credentials by guessing an identity id."""

    def setUp(self):
        from security import identity_manager
        self.im = identity_manager
        self.global_id = self.im.add_identity("globale", "all", "u", "p", "s")["id"]
        self.site_a_id = self.im.add_identity("sede-a", "SiteA", "u", "p", "s")["id"]
        self.multi_id = self.im.add_identity("multi", ["SiteA", "SiteB"], "u", "p", "s")["id"]

    def tearDown(self):
        for ident in (self.global_id, self.site_a_id, self.multi_id):
            self.im.delete_identity(ident)

    def test_none_scope_sees_everything(self):
        for ident in (self.global_id, self.site_a_id, self.multi_id):
            self.assertTrue(self.im.identity_visible_to(ident, None))

    def test_global_identity_is_visible_to_any_scope(self):
        self.assertTrue(self.im.identity_visible_to(self.global_id, {"SiteC"}))

    def test_scoped_identity_hidden_from_other_site(self):
        self.assertFalse(self.im.identity_visible_to(self.site_a_id, {"SiteC"}))

    def test_scoped_identity_visible_to_its_own_site(self):
        self.assertTrue(self.im.identity_visible_to(self.site_a_id, {"SiteA"}))

    def test_multi_tenant_identity_matches_any_of_its_sites(self):
        self.assertTrue(self.im.identity_visible_to(self.multi_id, {"SiteB"}))
        self.assertFalse(self.im.identity_visible_to(self.multi_id, {"SiteC"}))

    def test_unknown_id_is_not_visible(self):
        self.assertFalse(self.im.identity_visible_to("deadbeef", None))
```

- [x] **Step 2: Run the test to verify it fails**

Run: `uv run python tests/test_scan_verify.py TestIdentityVisibility -v`
Expected: FAIL — `AttributeError: module 'security.identity_manager' has no attribute 'identity_visible_to'`.

- [x] **Step 3: Add the function**

In `security/identity_manager.py`, insert after `get_identity_credentials` (after line 106):

```python
def identity_visible_to(identity_id: str, tenants) -> bool:
    """True if a caller whose allowed sites are ``tenants`` may use this
    identity. ``tenants`` is a set of site names, or None for an unrestricted
    caller (admin) — the same shape routers/deps.py:user_group_scope returns.
    Global identities ('all') are visible to everyone. Unknown id -> False."""
    with _lock:
        row = next((r for r in _load() if r["id"] == identity_id), None)
    if row is None:
        return False
    if tenants is None:
        return True
    return any(_matches_tenant(row.get("tenant"), t) for t in tenants)
```

- [x] **Step 4: Run the test to verify it passes**

Run: `uv run python tests/test_scan_verify.py TestIdentityVisibility -v`
Expected: PASS, 6 tests.

- [x] **Step 5: Commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
git add security/identity_manager.py tests/test_scan_verify.py
git commit -m "feat(identities): identity_visible_to(id, tenants)

Regola di visibilita' per tenant in un solo posto, per i chiamanti che
devono decidere se un utente puo' usare un'identita' prima di decifrarne
le credenziali."
```

---

### Task 4: `POST /api/scan-verify`

**Files:**
- Modify: `routers/scan.py` (imports at top; new schema + job function + route appended after `start_subnet_scan`)
- Test: `tests/test_scan_verify.py` (add one class)

**Interfaces:**
- Consumes: `identity_manager.identity_visible_to(identity_id, tenants)` (Task 3), `identity_manager.get_identity_credentials(identity_id) -> tuple[str, str, str] | None`, `core_engine.probe_device(device) -> {"status": str, "hostname": str|None} | {"status": "error", "message": str}`, `deps.user_group_scope(current_user) -> set[str] | None`, `_scan_jobs` / `_scan_jobs_lock` (Task 2)
- Produces: `POST /api/scan-verify` returning `{"job_id": str, "status": "started", "total_hosts": int}`; polled through the **existing** `GET /api/scan-subnet/{job_id}`, whose `results` for a verify job are rows `{"ip": str, "ok": bool, "hostname": str|None, "error": str|None}`

- [x] **Step 1: Write the failing test**

Add to `tests/test_scan_verify.py`, above the `if __name__` footer:

```python
class TestScanVerify(ScanApiTestCase):
    """The only step that authenticates. It runs on the rows a human ticked,
    with an identity that human chose."""

    def setUp(self):
        from security import identity_manager
        self.im = identity_manager
        self.ident_id = self.im.add_identity("scan-test", "all", "u", "p", "s")["id"]

    def tearDown(self):
        self.im.delete_identity(self.ident_id)

    def _verify(self, body, probe_result=None):
        from core import core_engine
        probe_result = probe_result or {"status": "success", "hostname": "switch-01"}
        with mock.patch.object(core_engine, "probe_device", return_value=probe_result) as probe:
            r = self._client().post("/api/scan-verify", json=body)
            if r.status_code == 200:
                job_id = r.json()["job_id"]
                # The job runs on a real thread; poll until it settles.
                for _ in range(100):
                    poll = self._client().get(f"/api/scan-subnet/{job_id}")
                    if poll.json()["status"] != "running":
                        return r, probe, poll.json()
                    time.sleep(0.05)
                self.fail("verify job never finished")
        return r, probe, None

    def test_successful_verify_returns_hostname(self):
        _, probe, job = self._verify({
            "ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": self.ident_id,
        })
        probe.assert_called_once()
        self.assertEqual(job["results"], [
            {"ip": "192.0.2.10", "ok": True, "hostname": "switch-01", "error": None},
        ])

    def test_failed_login_reports_the_reason(self):
        _, _, job = self._verify(
            {"ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": self.ident_id},
            probe_result={"status": "error", "message": "Authentication failed"},
        )
        row = job["results"][0]
        self.assertFalse(row["ok"])
        self.assertIsNone(row["hostname"])
        self.assertEqual(row["error"], "Authentication failed")

    def test_probe_receives_the_chosen_vendor_and_encrypted_credentials(self):
        _, probe, _ = self._verify({
            "ips": ["192.0.2.10"], "vendor": "linux", "identity_id": self.ident_id,
        })
        device = probe.call_args.args[0]
        self.assertEqual(device["Vendor"], "linux")
        self.assertEqual(device["IP"], "192.0.2.10")
        # probe_device -> get_device_credentials decrypts, so it must get ciphertext.
        self.assertNotEqual(device["Password"], "p")

    def test_identity_outside_scope_is_404_and_never_decrypts(self):
        from routers import scan
        scoped = self.im.add_identity("altra-sede", "SiteZ", "u", "p", "s")["id"]
        try:
            with mock.patch.object(scan, "user_group_scope", return_value={"SiteA"}), \
                 mock.patch.object(self.im, "get_identity_credentials") as creds:
                r = self._client().post("/api/scan-verify", json={
                    "ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": scoped,
                })
            self.assertEqual(r.status_code, 404)
            creds.assert_not_called()
        finally:
            self.im.delete_identity(scoped)

    def test_unknown_identity_is_404(self):
        r, _, _ = self._verify({
            "ips": ["192.0.2.10"], "vendor": "cisco", "identity_id": "deadbeef",
        })
        self.assertEqual(r.status_code, 404)

    def test_malformed_ip_is_rejected(self):
        r, _, _ = self._verify({
            "ips": ["not-an-ip"], "vendor": "cisco", "identity_id": self.ident_id,
        })
        self.assertEqual(r.status_code, 422)

    def test_empty_ip_list_is_rejected(self):
        r, _, _ = self._verify({"ips": [], "vendor": "cisco", "identity_id": self.ident_id})
        self.assertEqual(r.status_code, 422)
```

- [x] **Step 2: Run the test to verify it fails**

Run: `uv run python tests/test_scan_verify.py TestScanVerify -v`
Expected: FAIL — all requests return 404 (`/api/scan-verify` does not exist), so `test_successful_verify_returns_hostname` fails on `KeyError: 'job_id'`.

- [x] **Step 3: Implement the endpoint**

In `routers/scan.py`, extend the imports at the top:

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

from routers.deps import get_current_user, require_operator, user_group_scope
from collectors.network_scanner import parse_network, scan_subnet
from core.core_engine import probe_device
from security import crypto_vault, identity_manager
```

Append after `start_subnet_scan` (and before `get_subnet_scan_status`):

```python
class ScanVerifyRequest(BaseModel):
    # Same IP shape as DeviceSchema (routers/inventory.py:23): these strings are
    # handed to netmiko, they do not get to be arbitrary.
    ips: List[Annotated[str, Field(pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")]] = Field(
        min_length=1, max_length=512
    )
    vendor: str
    identity_id: str


def _run_verify_job(job_id: str, req: ScanVerifyRequest, credentials: tuple):
    username, password, secret = credentials
    # probe_device -> get_device_credentials decrypts, so encrypt once here
    # instead of per host.
    enc_password = crypto_vault.encrypt_password(password)
    enc_secret   = crypto_vault.encrypt_password(secret)

    def _verify_one(ip: str) -> dict:
        device = {
            'IP':            ip,
            'Vendor':        req.vendor,
            'Profile':       'custom',
            'Username':      username,
            'Password':      enc_password,
            'Enable Secret': enc_secret,
            'Group':         'Discovered',
        }
        res = probe_device(device)
        if res.get('status') != 'success':
            return {"ip": ip, "ok": False, "hostname": None,
                    "error": res.get('message')}
        return {"ip": ip, "ok": True, "hostname": res.get('hostname'), "error": None}

    try:
        rows: list[dict] = []
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = [pool.submit(_verify_one, ip) for ip in req.ips]
            for fut in as_completed(futures):
                rows.append(fut.result())
                with _scan_jobs_lock:
                    if job_id in _scan_jobs:
                        _scan_jobs[job_id]["progress"] = len(rows)
        order = {ip: i for i, ip in enumerate(req.ips)}
        rows.sort(key=lambda r: order[r["ip"]])
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"]   = "done"
            _scan_jobs[job_id]["results"]  = rows
            _scan_jobs[job_id]["progress"] = _scan_jobs[job_id]["total"]
    except Exception as exc:
        with _scan_jobs_lock:
            _scan_jobs[job_id]["status"] = "error"
            _scan_jobs[job_id]["error"]  = str(exc)


@router.post("/api/scan-verify")
def start_scan_verify(
    payload: ScanVerifyRequest,
    current_user = Depends(require_operator),
):
    """The only part of a scan that authenticates, and only on the IPs the user
    selected with the identity the user picked."""
    # Visibility BEFORE decryption: without it an operator reads another site's
    # password by guessing an identity id. 404, not 403 — a 403 would confirm
    # that the identity exists.
    if not identity_manager.identity_visible_to(payload.identity_id,
                                                user_group_scope(current_user)):
        raise HTTPException(status_code=404, detail="Identita' non trovata.")

    credentials = identity_manager.get_identity_credentials(payload.identity_id)
    if credentials is None:
        raise HTTPException(status_code=404, detail="Identita' non trovata.")

    job_id = str(uuid.uuid4())
    with _scan_jobs_lock:
        _scan_jobs[job_id] = {
            "status":     "running",
            "results":    [],
            "progress":   0,
            "total":      len(payload.ips),
            "started_at": time.time(),
        }

    threading.Thread(target=_run_verify_job,
                     args=(job_id, payload, credentials), daemon=True).start()

    # This is the operation that generates authentication attempts on the
    # customer network: it gets an audit line.
    log_audit(
        f"Verifica credenziali su {len(payload.ips)} host avviata dall'utente "
        f"'{current_user.get('sub')}' (identita': {payload.identity_id}, "
        f"vendor: '{payload.vendor}', job_id: {job_id})."
    )
    return {"job_id": job_id, "status": "started", "total_hosts": len(payload.ips)}
```

- [x] **Step 4: Run the tests to verify they pass**

Run: `uv run python tests/test_scan_verify.py -v`
Expected: PASS, all classes (`TestScanPortValidation`, `TestIdentityVisibility`, `TestScanVerify`).

- [x] **Step 5: Run the full gate**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
```
Expected: 0 errors, suite green.

- [x] **Step 6: Commit**

```bash
graphify update .
git add routers/scan.py tests/test_scan_verify.py
git commit -m "feat(scan): POST /api/scan-verify, login solo su richiesta

Verifica opzionale con identita' scelta dall'utente sulle sole righe
selezionate. Job a se' sul meccanismo esistente. L'identita' dev'essere
visibile allo scope di sede del chiamante PRIMA di decifrare qualunque
credenziale: altrimenti si legge la password di un'altra sede indovinando
un id. 404 e non 403, per non confermarne l'esistenza."
```

---

### Task 5: Scan modal markup and strings

**Files:**
- Modify: `templates/dashboard.html:3358-3430` (the `subnetScanModal` block)
- Modify: `static/js/i18n.js:928-932` (IT) and `:2291-2295` (EN)

**Interfaces:**
- Produces: element ids consumed by Task 6 and 7 — `scanNetworkInput`, `scanPortsInput`, `scanGroupSelect`, `btnAvviaScan`, `subnetScanStatus`, `subnetScanProgressBar`, `subnetScanResults`, `subnetScanResultsTable`, `scanSelectAll`, `scanIdentitySelect`, `scanVerifyVendorSelect`, `btnScanVerify`, `btnScanAddSelected`, `scanActionsBar`

- [ ] **Step 1: Replace the modal body**

In `templates/dashboard.html`, inside `<div class="modal-overlay" id="subnetScanModal">`, widen the modal to `width: 720px` and replace everything from the `<div class="form-group">` holding `scanNetworkInput` down to (and including) the `btnAvviaScan` button with:

```html
      <div class="form-group">
        <label data-i18n="lblNetworkAddr">Indirizzo di Rete</label>
        <input id="scanNetworkInput" type="text"
               placeholder="es. 192.0.2.0/24 oppure 192.0.2.0 255.255.255.0"
               data-i18n-placeholder="placeholderNetworkInput"
               style="font-family: var(--font-data); font-size: 13px;
                      padding: 10px 12px; border-radius: 0;
                      background: var(--surface-2); border: 1px solid var(--border);
                      color: var(--text); width: 100%; box-sizing: border-box;
                      outline: none; transition: var(--transition);">
      </div>

      <div class="form-group">
        <label data-i18n="lblScanPorts">Porte TCP da verificare</label>
        <input id="scanPortsInput" type="text" value="22"
               placeholder="22,443"
               style="font-family: var(--font-data); font-size: 13px;
                      padding: 10px 12px; border-radius: 0;
                      background: var(--surface-2); border: 1px solid var(--border);
                      color: var(--text); width: 100%; box-sizing: border-box;
                      outline: none; transition: var(--transition);">
        <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px;">
          <button type="button" class="btn btn-small" onclick="addScanPort(22)"
                  style="margin:0; width:auto; padding:3px 8px;">SSH 22</button>
          <button type="button" class="btn btn-small" onclick="addScanPort(23)"
                  style="margin:0; width:auto; padding:3px 8px;">Telnet 23</button>
          <button type="button" class="btn btn-small" onclick="addScanPort(443)"
                  style="margin:0; width:auto; padding:3px 8px;">HTTPS 443</button>
          <button type="button" class="btn btn-small" onclick="addScanPort(8443)"
                  style="margin:0; width:auto; padding:3px 8px;">8443</button>
        </div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;"
             data-i18n="hintScanPorts">Vuoto = solo ping. Massimo 16 porte.</div>
      </div>

      <div class="form-group">
        <label data-i18n="lblGroup">Gruppo / Sede</label>
        <select id="scanGroupSelect"
                style="padding: 10px 12px; border-radius: 0;
                       background: var(--surface-2); border: 1px solid var(--border);
                       color: var(--text); font-family: inherit; font-size: 13px;
                       cursor: pointer; outline: none; width: 100%; transition: var(--transition);">
          <option value="Generale">Generale</option>
        </select>
      </div>

      <button class="btn btn-primary" id="btnAvviaScan"
              onclick="startSubnetScan()"
              style="width: 100%; margin: 0;"
              data-i18n="btnStartScan">
        <i class="fa-solid fa-satellite-dish"></i> Avvia Scansione
      </button>
```

Then, still inside `#subnetScanResults` and immediately after the `subnetScanResultsTable` container's closing `</div>`, add the actions bar:

```html
        <div id="scanActionsBar" style="display: none; align-items: center; gap: 8px;
                    flex-wrap: wrap; margin-top: 12px; padding-top: 12px;
                    border-top: 1px solid var(--border);">
          <label style="font-size: 12px; color: var(--text-muted);"
                 data-i18n="lblScanIdentity">Identità</label>
          <select id="scanIdentitySelect"
                  style="padding: 6px 8px; border-radius: 0; background: var(--surface-2);
                         border: 1px solid var(--border); color: var(--text);
                         font-size: 12px; cursor: pointer; outline: none;"></select>
          <label style="font-size: 12px; color: var(--text-muted);"
                 data-i18n="lblVendor">Vendor</label>
          <select id="scanVerifyVendorSelect"
                  style="padding: 6px 8px; border-radius: 0; background: var(--surface-2);
                         border: 1px solid var(--border); color: var(--text);
                         font-size: 12px; cursor: pointer; outline: none;"></select>
          <button class="btn btn-small" id="btnScanVerify" onclick="verifySelectedScanRows()"
                  style="margin:0; width:auto; padding:5px 10px;" disabled></button>
          <button class="btn btn-primary btn-small" id="btnScanAddSelected"
                  onclick="addSelectedScanRows()"
                  style="margin:0; width:auto; padding:5px 10px;" disabled></button>
        </div>
```

Delete the old `scanVendorSelect` form-group and the whole `scanAutoAdd` checkbox block.

- [ ] **Step 2: Add the strings**

In `static/js/i18n.js`, in the IT block near line 928, delete the `lblScanAutoAdd` line and add alongside `titleSubnetScan`:

```javascript
        lblScanPorts: 'Porte TCP da verificare',
        hintScanPorts: 'Vuoto = solo ping. Massimo 16 porte.',
        lblScanIdentity: 'Identità',
        optScanNoIdentity: '— nessuna (solo scoperta) —',
        btnScanVerify: 'Verifica selezionati ({n})',
        btnScanAddSelected: 'Aggiungi selezionati ({n})',
        scanFoundCount: 'Trovati {n} host',
        scanNoHosts: 'Nessun host ha risposto.',
        scanColPing: 'Ping',
        scanColPorts: 'Porte aperte',
        scanColVerify: 'Verifica',
        scanVerifyRunning: 'Verifica in corso — {done}/{total}...',
```

and in the EN block near line 2291, likewise deleting its `lblScanAutoAdd`:

```javascript
        lblScanPorts: 'TCP ports to check',
        hintScanPorts: 'Empty = ping only. Maximum 16 ports.',
        lblScanIdentity: 'Identity',
        optScanNoIdentity: '— none (discovery only) —',
        btnScanVerify: 'Verify selected ({n})',
        btnScanAddSelected: 'Add selected ({n})',
        scanFoundCount: '{n} hosts found',
        scanNoHosts: 'No host responded.',
        scanColPing: 'Ping',
        scanColPorts: 'Open ports',
        scanColVerify: 'Verify',
        scanVerifyRunning: 'Verifying — {done}/{total}...',
```

- [ ] **Step 3: Verify the template still renders**

```bash
uv run python -c "import app_server"
```
Expected: no exception. Then start the app and open the Devices tab → Subnet Scan: the modal shows Network, Ports with four chips, Group, and the Start button. The actions bar is hidden (no results yet).

- [ ] **Step 4: Commit**

```bash
git add templates/dashboard.html static/js/i18n.js
git commit -m "feat(ui): modale scansione con porte configurabili e barra azioni

Campo porte + chip preimpostati, barra identita'/vendor/verifica/aggiungi
sotto i risultati. Via il selettore vendor a monte e la checkbox auto-add."
```

---

### Task 6: Discovery results — render, select, add

**Files:**
- Modify: `static/js/devices.js:697-850` (the whole `--- SUBNET SCANNER ---` section)

**Interfaces:**
- Consumes: element ids from Task 5; `POST /api/scan-subnet` and `GET /api/scan-subnet/{job_id}` from Task 2; existing helpers `apiFetch`, `escapeHtml`, `jsStr`, `appInit`, `buildVendorOptions`, `globalGroups`, `currentLang`, `i18n`
- Produces: module-scope `_scanRows` (array of `{ip, alive, open_ports, verify}` where `verify` is `null` until Task 7 fills it); functions `addScanPort(port)`, `selectedScanIps()`, `refreshScanActionButtons()`, `renderScanResults(rows)` — Task 7 calls all four

- [ ] **Step 1: Replace the scanner section**

In `static/js/devices.js`, replace everything from `// --- SUBNET SCANNER ---` (line 697) through the end of `addDiscoveredDevice` (line 850) with:

```javascript
    // --- SUBNET SCANNER ---

    // Discovery rows currently on screen. verify is null until the user runs
    // the optional verify step (see verifySelectedScanRows).
    let _scanRows = [];

    function addScanPort(port) {
        const input = document.getElementById('scanPortsInput');
        const ports = input.value.split(',').map(s => s.trim()).filter(Boolean);
        if (!ports.includes(String(port))) ports.push(String(port));
        input.value = ports.join(',');
    }

    function openSubnetScanModal() {
        const sel = document.getElementById('scanGroupSelect');
        sel.innerHTML = '';
        Object.keys(globalGroups).forEach(g => {
            const opt = document.createElement('option');
            opt.value = g;
            opt.textContent = g;
            if (g === 'Generale') opt.selected = true;
            sel.appendChild(opt);
        });

        _scanRows = [];
        document.getElementById('subnetScanResults').style.display = 'none';
        document.getElementById('scanActionsBar').style.display = 'none';
        document.getElementById('subnetScanResultsTable').innerHTML = '';
        document.getElementById('subnetScanStatus').textContent = '';
        document.getElementById('scanNetworkInput').value = '';
        document.getElementById('scanPortsInput').value = '22';
        document.getElementById('btnAvviaScan').disabled = false;
        document.getElementById('subnetScanModal').style.display = 'flex';
    }

    function closeSubnetScanModal() {
        if (_scanJobInterval) { clearInterval(_scanJobInterval); _scanJobInterval = null; }
        document.getElementById('subnetScanModal').style.display = 'none';
    }

    function scanStartButtonIdle() {
        const b = document.getElementById('btnAvviaScan');
        b.disabled = false;
        b.innerHTML = currentLang === 'en'
            ? '<i class="fa-solid fa-satellite-dish"></i> Start Scan'
            : '<i class="fa-solid fa-satellite-dish"></i> Avvia Scansione';
    }

    async function startSubnetScan() {
        if (_scanJobInterval) { clearInterval(_scanJobInterval); _scanJobInterval = null; }

        const network = document.getElementById('scanNetworkInput').value.trim();
        if (!network) { document.getElementById('scanNetworkInput').focus(); return; }
        const ports = document.getElementById('scanPortsInput').value
            .split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));

        const btn = document.getElementById('btnAvviaScan');
        btn.disabled = true;
        btn.innerHTML = currentLang === 'en'
            ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Starting...'
            : '<i class="fa-solid fa-circle-notch fa-spin"></i> Avvio...';
        _scanRows = [];
        document.getElementById('subnetScanResults').style.display = 'block';
        document.getElementById('scanActionsBar').style.display = 'none';
        document.getElementById('subnetScanResultsTable').innerHTML = '';
        document.getElementById('subnetScanProgressBar').style.transform = 'scaleX(0)';
        document.getElementById('subnetScanStatus').textContent =
            currentLang === 'en' ? 'Starting scan...' : 'Avvio scansione...';

        const res = await apiFetch('/api/scan-subnet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ network, ports }),
        });
        if (!res || !res.ok) {
            const err = res ? await res.json() : { detail: currentLang === 'en' ? 'Network error' : 'Errore di rete' };
            document.getElementById('subnetScanStatus').textContent =
                (currentLang === 'en' ? 'Error: ' : 'Errore: ') +
                (err.detail || (currentLang === 'en' ? 'unable to start scan.' : 'impossibile avviare la scansione.'));
            scanStartButtonIdle();
            return;
        }
        const { job_id, total_hosts } = await res.json();
        document.getElementById('subnetScanStatus').textContent = currentLang === 'en'
            ? `Scan started — ${total_hosts} hosts to check...`
            : `Scansione avviata — ${total_hosts} host da verificare...`;
        btn.innerHTML = currentLang === 'en'
            ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...'
            : '<i class="fa-solid fa-circle-notch fa-spin"></i> Scansione in corso...';
        pollScanJob(job_id, total_hosts);
    }

    function pollScanJob(jobId, totalHosts) {
        _scanJobInterval = setInterval(async () => {
            const res = await apiFetch(`/api/scan-subnet/${jobId}`);
            if (!res || !res.ok) {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                document.getElementById('subnetScanStatus').textContent =
                    currentLang === 'en' ? 'Error during polling.' : 'Errore durante il polling.';
                scanStartButtonIdle();
                return;
            }
            const data = await res.json();
            const total = data.total || totalHosts;
            const pct = total > 0 ? Math.round((data.progress / total) * 100) : 0;
            document.getElementById('subnetScanProgressBar').style.transform = `scaleX(${pct / 100})`;
            document.getElementById('subnetScanStatus').textContent = currentLang === 'en'
                ? `Scanning — ${data.progress}/${total} hosts processed...`
                : `Scansione in corso — ${data.progress}/${total} host elaborati...`;

            if (data.status !== 'running') {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                scanStartButtonIdle();
                document.getElementById('subnetScanProgressBar').style.transform = 'scaleX(1)';
                if (data.status === 'error') {
                    document.getElementById('subnetScanStatus').textContent =
                        currentLang === 'en' ? 'Scan finished with error.' : 'Scansione terminata con errore.';
                    return;
                }
                _scanRows = (data.results || []).map(r => ({ ...r, verify: null }));
                renderScanResults(_scanRows);
            }
        }, 2000);
    }

    function selectedScanIps() {
        return Array.from(document.querySelectorAll('.scan-row-cb:checked'))
            .map(cb => cb.dataset.ip);
    }

    function refreshScanActionButtons() {
        const n = selectedScanIps().length;
        const L = i18n[currentLang];
        const identity = document.getElementById('scanIdentitySelect').value;
        const verifyBtn = document.getElementById('btnScanVerify');
        const addBtn = document.getElementById('btnScanAddSelected');
        verifyBtn.textContent = (L.btnScanVerify || 'Verifica selezionati ({n})').replace('{n}', n);
        addBtn.textContent = (L.btnScanAddSelected || 'Aggiungi selezionati ({n})').replace('{n}', n);
        // Verify authenticates: it needs both a selection and a chosen identity.
        verifyBtn.disabled = n === 0 || !identity;
        addBtn.disabled = n === 0;
    }

    function renderScanResults(rows) {
        const L = i18n[currentLang];
        document.getElementById('subnetScanStatus').textContent =
            (L.scanFoundCount || 'Trovati {n} host').replace('{n}', rows.length);

        if (rows.length === 0) {
            document.getElementById('subnetScanResultsTable').innerHTML =
                `<div style="padding:14px; color:var(--text-muted); font-size:13px;">${
                    escapeHtml(L.scanNoHosts || 'Nessun host ha risposto.')}</div>`;
            document.getElementById('scanActionsBar').style.display = 'none';
            return;
        }

        const header = `<div style="display:grid; grid-template-columns:28px 130px 48px 1fr 1fr;
                    align-items:center; gap:8px; padding:8px 12px; position:sticky; top:0;
                    background:var(--surface-3); border-bottom:1px solid var(--border);
                    font-size:11px; text-transform:uppercase; color:var(--text-muted);">
            <input type="checkbox" id="scanSelectAll" onchange="toggleAllScanRows(this)"
                   style="width:14px; height:14px; accent-color:var(--primary); cursor:pointer;">
            <span>IP</span>
            <span>${escapeHtml(L.scanColPing || 'Ping')}</span>
            <span>${escapeHtml(L.scanColPorts || 'Porte aperte')}</span>
            <span>${escapeHtml(L.scanColVerify || 'Verifica')}</span>
          </div>`;

        const body = rows.map(r => {
            const ports = r.open_ports.length
                ? escapeHtml(r.open_ports.join(', '))
                : '<span style="color:var(--text-muted)">—</span>';
            let verifyCell = '<span style="color:var(--text-muted)">—</span>';
            if (r.verify && r.verify.ok) {
                verifyCell = `<span style="color:var(--primary)">✓ ${
                    escapeHtml(jsStr(r.verify.hostname || ''))}</span>`;
            } else if (r.verify) {
                verifyCell = `<span style="color:var(--danger)" title="${
                    escapeHtml(jsStr(r.verify.error || ''))}">✗ ${
                    escapeHtml(jsStr((r.verify.error || '').slice(0, 40)))}</span>`;
            }
            return `<div style="display:grid; grid-template-columns:28px 130px 48px 1fr 1fr;
                        align-items:center; gap:8px; padding:8px 12px;
                        border-bottom:1px solid var(--border); font-size:12px;">
                <input type="checkbox" class="scan-row-cb" data-ip="${escapeHtml(jsStr(r.ip))}"
                       onchange="refreshScanActionButtons()"
                       style="width:14px; height:14px; accent-color:var(--primary); cursor:pointer;">
                <span style="font-family:var(--font-code); color:var(--primary);">${escapeHtml(jsStr(r.ip))}</span>
                <span style="color:${r.alive ? 'var(--primary)' : 'var(--text-muted)'};">${r.alive ? '✓' : '✗'}</span>
                <span style="font-family:var(--font-code);">${ports}</span>
                <span>${verifyCell}</span>
              </div>`;
        }).join('');

        document.getElementById('subnetScanResultsTable').innerHTML = header + body;
        document.getElementById('scanActionsBar').style.display = 'flex';
        populateScanIdentitySelect();
        const vendorSel = document.getElementById('scanVerifyVendorSelect');
        vendorSel.innerHTML = buildVendorOptions(vendorSel.value || 'cisco');
        refreshScanActionButtons();
    }

    function toggleAllScanRows(master) {
        document.querySelectorAll('.scan-row-cb').forEach(cb => { cb.checked = master.checked; });
        refreshScanActionButtons();
    }

    // Replaced in the verify task.
    function populateScanIdentitySelect() {}
    function verifySelectedScanRows() {}

    async function addSelectedScanRows() {
        const group = document.getElementById('scanGroupSelect').value;
        const vendorSel = document.getElementById('scanVerifyVendorSelect').value;
        const identityId = document.getElementById('scanIdentitySelect').value;
        const ips = selectedScanIps();

        for (const ip of ips) {
            const row = _scanRows.find(r => r.ip === ip);
            // A verified row knows its vendor and which identity opened it, so
            // it lands managed. An unverified one is IP only: guessing a vendor
            // is exactly what this screen stopped doing.
            const verified = row && row.verify && row.verify.ok;
            const body = verified
                ? { ip, vendor: vendorSel, profile: `identity:${identityId}`,
                    username: '', password: '', enable_secret: '', group }
                : { ip, vendor: '', profile: 'default',
                    username: '', password: '', enable_secret: '', group };
            await apiFetch('/api/add-device', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
        }
        appInit();
        closeSubnetScanModal();
    }
```

- [ ] **Step 2: Update the exports**

The `onclick` handlers need module functions on `window`. Find the export block at the bottom of `static/js/devices.js` (where `openSubnetScanModal`, `startSubnetScan`, `addDiscoveredDevice` etc. are assigned) and update it: remove `addDiscoveredDevice`, add `addScanPort`, `toggleAllScanRows`, `refreshScanActionButtons`, `addSelectedScanRows`, `verifySelectedScanRows`. `populateScanIdentitySelect` is only called from within the module and does not need exporting.

- [ ] **Step 3: Manual check**

Start the app, open Devices → Subnet Scan. Enter a small network you own (e.g. a /29 on your lab), ports `22,443`. Confirm:
- progress bar advances once, no jump backwards mid-run
- results table lists hosts with a ping column and an open-ports column
- the header checkbox selects/deselects all rows
- both bottom buttons show a live count; Add is enabled with a selection, Verify stays disabled (the identity select is an empty stub until Task 7)
- Add on an unverified row creates a device with an empty vendor in the Devices table

- [ ] **Step 4: Commit**

```bash
git add static/js/devices.js
git commit -m "feat(ui): tabella scoperta con selezione righe e aggiunta

Le righe sono selezionabili, Aggiungi scrive solo l'IP quando la riga non
e' stata verificata. Via addDiscoveredDevice e il filtro su ssh_ok, che
non esiste piu'."
```

---

### Task 7: The optional verify step

**Files:**
- Modify: `static/js/devices.js` (replace the two stubs from Task 6)

**Interfaces:**
- Consumes: `_scanRows`, `selectedScanIps()`, `refreshScanActionButtons()`, `renderScanResults(rows)` from Task 6; `POST /api/scan-verify` + `GET /api/scan-subnet/{job_id}` from Task 4; `GET /api/identities` (existing, `routers/provisioner.py:310`)
- Produces: nothing downstream — this is the last behavioural task

- [ ] **Step 1: Replace the stubs**

In `static/js/devices.js`, replace the two placeholder functions:

```javascript
    // Replaced in the verify task.
    function populateScanIdentitySelect() {}
    function verifySelectedScanRows() {}
```

with:

```javascript
    async function populateScanIdentitySelect() {
        const sel = document.getElementById('scanIdentitySelect');
        const L = i18n[currentLang];
        const res = await apiFetch('/api/identities');
        const identities = (res && res.ok) ? (await res.json()).identities || [] : [];
        // Empty value = no identity chosen: verify stays disabled, add still works.
        sel.innerHTML = `<option value="">${
            escapeHtml(L.optScanNoIdentity || '— nessuna (solo scoperta) —')}</option>` +
            identities.map(i => `<option value="${escapeHtml(jsStr(i.id))}">${
                escapeHtml(jsStr(i.name))} (${escapeHtml(jsStr(i.username))})</option>`).join('');
        sel.onchange = refreshScanActionButtons;
    }

    async function verifySelectedScanRows() {
        const ips = selectedScanIps();
        const identityId = document.getElementById('scanIdentitySelect').value;
        const vendor = document.getElementById('scanVerifyVendorSelect').value;
        if (!ips.length || !identityId) return;

        const L = i18n[currentLang];
        document.getElementById('btnScanVerify').disabled = true;

        const res = await apiFetch('/api/scan-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips, vendor, identity_id: identityId }),
        });
        if (!res || !res.ok) {
            const err = res ? await res.json() : { detail: currentLang === 'en' ? 'Network error' : 'Errore di rete' };
            document.getElementById('subnetScanStatus').textContent =
                (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (err.detail || '');
            refreshScanActionButtons();
            return;
        }
        const { job_id } = await res.json();

        // Same job machinery and same polling endpoint as the scan, but a job
        // of its own: the discovery job may already have been collected.
        const interval = setInterval(async () => {
            const poll = await apiFetch(`/api/scan-subnet/${job_id}`);
            if (!poll || !poll.ok) {
                clearInterval(interval);
                document.getElementById('subnetScanStatus').textContent =
                    currentLang === 'en' ? 'Error during polling.' : 'Errore durante il polling.';
                refreshScanActionButtons();
                return;
            }
            const data = await poll.json();
            document.getElementById('subnetScanStatus').textContent =
                (L.scanVerifyRunning || 'Verifica in corso — {done}/{total}...')
                    .replace('{done}', data.progress).replace('{total}', data.total);

            if (data.status !== 'running') {
                clearInterval(interval);
                if (data.status === 'error') {
                    document.getElementById('subnetScanStatus').textContent =
                        currentLang === 'en' ? 'Verify finished with error.' : 'Verifica terminata con errore.';
                    refreshScanActionButtons();
                    return;
                }
                // Merge by IP into the rows already on screen.
                const selected = new Set(ips);
                (data.results || []).forEach(v => {
                    const row = _scanRows.find(r => r.ip === v.ip);
                    if (row) row.verify = v;
                });
                renderScanResults(_scanRows);
                // renderScanResults rebuilds the table, so restore the selection.
                document.querySelectorAll('.scan-row-cb').forEach(cb => {
                    cb.checked = selected.has(cb.dataset.ip);
                });
                refreshScanActionButtons();
            }
        }, 2000);
    }
```

- [ ] **Step 2: Manual check**

Start the app. Create an identity under Provisioning with credentials valid for one lab device. Then Devices → Subnet Scan on a small network you own:
- the identity dropdown lists it, defaulting to "— nessuna —" with Verify disabled
- picking an identity enables Verify; the count matches the ticked rows
- Verify on a device with correct credentials shows `✓ <hostname>`
- Verify on a device with wrong credentials shows `✗ <reason>` and the row selection survives the re-render
- Add on a verified row creates a device with the chosen vendor and profile `identity:<id>`
- confirm in the audit log that the verify produced one line naming the identity and host count, and that the discovery phase produced **no** authentication attempt

- [ ] **Step 3: Full gate and commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
git add static/js/devices.js
git commit -m "feat(ui): verifica opzionale con identita' sulle righe scelte

Il selettore identita' parte vuoto: senza identita' la verifica resta
disabilitata e l'aggiunta funziona lo stesso. Job a se' con lo stesso
endpoint di polling della scansione, risultati fusi per IP."
```

---

### Task 8: Vendor-less devices are visible as such

**Files:**
- Modify: `static/js/devices.js:113-145` (the device table row builder)

**Interfaces:**
- Consumes: the device list entry `d` with `d.Vendor` possibly `""` after Task 6
- Produces: nothing downstream

Adding a device without verifying now writes an empty vendor. `DeviceSchema.vendor` is a required `str` but accepts `""`, and `add_or_update_device` does not validate it, so the row saves fine and then fails on the first backup with `resolve_driver`'s `ValueError`. Without this task those rows look normal until they break.

- [ ] **Step 1: Mark the rows**

In the device table row builder in `static/js/devices.js`, find where `d.Vendor` is rendered into its cell and replace that expression with:

```javascript
                    ${d.Vendor
                        ? escapeHtml(jsStr(d.Vendor))
                        : `<span style="color:var(--warning); font-style:italic;" title="${
                            escapeHtml(currentLang === 'en'
                                ? 'No vendor set: backup and triage will fail until you edit this device.'
                                : "Vendor non impostato: backup e triage falliranno finche' non modifichi il dispositivo.")
                          }">${escapeHtml(currentLang === 'en' ? 'not set' : 'non impostato')}</span>`}
```

- [ ] **Step 2: Manual check**

Add a discovered host without verifying it, then look at the Devices table: the vendor cell reads "non impostato" in the warning colour with a tooltip explaining what will fail. Edit the device, set a vendor, and confirm the cell goes back to normal.

- [ ] **Step 3: Commit**

```bash
git add static/js/devices.js
git commit -m "fix(devices): vendor vuoto visibile in tabella

Un dispositivo aggiunto dalla scansione senza verifica non ha vendor: il
primo backup fallisce su resolve_driver. Meglio dirlo nella riga che
lasciarlo sembrare normale finche' non si rompe."
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| Fase 1 — `scan_subnet` discovery-only, `timeout=1`, sorted rows, single-phase progress | 1 |
| Fase 2 — `SubnetScanRequest` ports, drop vendor/group/auto_add/use_default_creds, drop `assert_group_allowed` | 2 |
| Fase 3 — `POST /api/scan-verify`, separate job, tenant gate before decryption, audit line | 3 + 4 |
| Fase 4 — modal layout, chips, identity/vendor bar, two independent buttons, i18n, escaping | 5 + 6 + 7 |
| Conseguenze note — vendor-less rows visible | 8 |
| Test list items 1-7 | 1 (items 2,3,4,5), 2 (item 1), 4 (items 6,7) |

**Deviation from the spec, resolved here:** the spec's Fase 3 says the tenant check follows `get_identities(tenant)` because it "già filtra così". It does not — `tenant` there is a client-supplied query parameter, and `routers/deps.py` has no per-user tenant at all. The caller's tenants are their site scope, `user_group_scope(current_user)`, and tenant/site are one namespace (`routers/ai.py:695`, `routers/arp.py:58`). Task 3 introduces `identity_visible_to(identity_id, tenants)` to express this, and Task 4 calls it before any decryption. The security property the spec asked for is met; the mechanism it named was wrong.

**Type consistency:** `scan_subnet(address, ports, max_workers, progress_cb)` — Task 1 defines, Task 2 calls with `address=`/`ports=`/`progress_cb=`. Discovery row keys `ip`/`alive`/`open_ports` — Task 1 produces, Task 6 reads. Verify row keys `ip`/`ok`/`hostname`/`error` — Task 4 produces, Task 7 reads. `identity_visible_to(identity_id, tenants)` — Task 3 defines, Task 4 calls. Element ids declared in Task 5 match every `getElementById` in Tasks 6 and 7. `populateScanIdentitySelect` / `verifySelectedScanRows` are stubbed in Task 6 and replaced in Task 7, so every task leaves the module loadable.
