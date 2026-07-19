# semgrep.md — SentinelNet Semgrep Triage & Remediation Plan

Scan of commit `245d31a3` on `refs/heads/master`. All findings verified against source. Verdicts: **TP** (true positive), **FP** (false positive), **AM** (already mitigated in code, tool cannot see it), **WF** (won't fix, accepted).

---

## 1. Summary Table

| Finding ID | Location | Rule | Verdict | Real Severity | Fix Effort |
|---|---|---|---|---|---|
| 894563751 | `routers/sites.py:75` (`site_command_ep`) | ai.detection.authz | **TP** | High | Low |
| 894563752 | `routers/sites.py:100` (`get_command_job_ep`) | ai.detection.authz | **TP** | High | Low |
| 894563753 | `routers/sites.py:107` (`list_site_command_jobs_ep`) | ai.detection.authz | **TP** | High | Low |
| 894563748 | `routers/catalog.py:220` (`assign_device_category`) | ai.detection.idor | **TP** | Medium-High | Low |
| 894563750 | `routers/mac.py:336` (`mac_list_overrides`) | ai.detection.idor | **TP** | Medium | Low |
| 894563749 | `routers/commands.py:235` (`get_bulk_command_status`) | ai.detection.idor | **TP** (partially mitigated by UUIDv4 job ids) | Medium | Low |
| 894562874 | `routers/wlc.py:33` (`_wlc_query`) | generic-sql-fastapi | **FP** (no SQL — SSH/CLI service call) | — | — |
| 894562873 | `routers/ai.py:155` (`_device_running_config_context`) | tainted-path-traversal | **AM** (`assert_device_allowed` constrains `ip` to inventory) | Low | Trivial (hardening) |
| 894562872 | `routers/analyzer.py:35` (`_load_backup_text`) | tainted-path-traversal | **AM** (same pattern as above) | Low | Trivial (hardening) |
| 894562871 | `mac_history.py:408` | sqlalchemy-execute-raw-query | **FP** (placeholder-only interpolation, values bound) | — | — |
| 894562870 | `mac_history.py:455` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562869 | `mac_history.py:456` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562868 | `mac_history.py:457` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562867 | `mac_history.py:541` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562866 | `mac_history.py:542` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562865 | `mac_history.py:543` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562864 | `observability/correlator.py:98` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562863 | `observability/summary.py:51` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562862 | `observability/summary.py:58` | sqlalchemy-execute-raw-query | **FP** | — | — |
| 894562861 | `Dockerfile:36` (missing `USER`) | missing-user | **TP** | Medium | Low |
| 894562860 | `routers/commands.py:313` (`ws_terminal` connect) | tainted-paramiko / SSRF | **AM** (IP must resolve to inventory device + OTP + group scoping) | Low | — |
| 894562859 | `routers/commands.py:337` (`ws_terminal` retry connect) | tainted-paramiko / SSRF | **AM** (same guard path) | Low | — |
| 894562858 | `test_router_smoke.py:48` | non-literal-import | **WF** (test-only, input from local `pkgutil`) | — | — |
| 894562857 | `templates/dashboard.html:9` | missing-integrity | **TP** | Low | Low |
| 894562856 | `templates/dashboard.html:17` | missing-integrity | **TP** | Low | Low |
| 894562855 | `templates/dashboard.html:20` | missing-integrity | **TP** | Low | Low |
| 894562854 | `templates/dashboard.html:23` | missing-integrity | **TP** | Low | Low |
| 894562853 | `templates/dashboard.html:24` | missing-integrity | **TP** | Low | Low |
| 894562852 | `static/js/core.js:137` | unsafe-formatstring | **WF** (browser console log only) | — | — |

---

## 2. Fix Plan (by priority)

### Priority 1 — AuthZ / IDOR (agent-relay command execution & data exposure)

These are the only findings that allow a scoped operator/viewer to act on or read data outside their group scope. The codebase already has all needed helpers in `routers/deps.py` (`assert_device_allowed`, `assert_group_allowed`, `user_group_scope`) — every fix below is a reuse, no new abstractions.

#### 894563751 — `routers/sites.py` · `site_command_ep` (POST `/api/sites/{site_id}/command`)

A group-scoped operator can execute arbitrary CLI on any device of any agent site. Compare with `send_command` in `routers/commands.py`, which correctly calls `assert_group_allowed` on the target device's group — this endpoint skips it entirely.

**Fix:** after the IP regex check, resolve the target through `assert_device_allowed` (it both resolves the device from inventory and enforces group scope, exactly as used in `routers/wlc.py:_wlc_device`):

```python
from routers.deps import require_admin, require_operator, assert_device_allowed  # extend import

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", payload.ip):
        raise HTTPException(status_code=400, detail="IP non valido.")
    device = assert_device_allowed(current_user, payload.ip)   # 403 fuori scope
    if device is None:
        raise HTTPException(status_code=404, detail="Dispositivo non presente in inventario.")
    if (device.get("Site") or "central") != site_id:
        raise HTTPException(status_code=400, detail="Il dispositivo non appartiene a questa sede.")
```

The `Site` consistency check also closes the gap where an operator relays a command to an IP that belongs to a different site than the one addressed in the URL.

#### 894563752 — `routers/sites.py` · `get_command_job_ep` (GET `/api/command-jobs/{job_id}`)

Any operator can read any job's result (command, target IP, device output). Jobs carry the target `ip` (set in `enqueue_job(site_id, payload.ip, ...)`).

**Fix:** scope-check the job's device before returning:

```python
@router.get("/api/command-jobs/{job_id}")
def get_command_job_ep(job_id: str, current_user = Depends(require_operator)):
    job = site_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job non trovato.")
    assert_device_allowed(current_user, job.get("ip"))   # 403 se fuori scope
    return job
```

(If `assert_device_allowed` returns `None` for a device no longer in inventory, additionally return 404 to avoid leaking output for deleted devices.)

#### 894563753 — `routers/sites.py` · `list_site_command_jobs_ep` (GET `/api/sites/{site_id}/command-jobs`)

Any operator can enumerate all jobs of any site.

**Fix:** filter the returned jobs to devices whose group is in the caller's scope (same filtering idiom already used in `mac_scan` in `routers/mac.py`):

```python
from routers.deps import user_group_scope  # extend import
import inventory_manager

@router.get("/api/sites/{site_id}/command-jobs")
def list_site_command_jobs_ep(site_id: str, current_user = Depends(require_operator)):
    jobs = site_manager.list_jobs(site_id)
    scope = user_group_scope(current_user)
    if scope is not None:
        ip_group = {d["IP"]: d.get("Group", "Generale")
                    for d in inventory_manager.get_all_devices()}
        jobs = [j for j in jobs if ip_group.get(j.get("ip"), "Generale") in scope]
    return {"jobs": jobs}
```

#### 894563748 — `routers/catalog.py` · `assign_device_category` (POST `/api/device-categories/assign`)

Scoped operator can rewrite metadata (category, vendor, HA group, name, version) of any device. `node_id` is either an inventory IP or a `discovered_<hostname>` synthetic id.

**Fix:** add a scope check before `set_device_meta`, mirroring the check pattern of `rename_group`/`send_command`:

```python
    scope = user_group_scope(current_user)
    if scope is not None:
        device = next((d for d in inventory_manager.get_all_devices()
                       if d.get("IP") == payload.node_id), None)
        if device is not None:
            assert_group_allowed(current_user, device.get("Group", "Generale"))
        else:
            # Nodo scoperto (CDP/LLDP): consentito solo se visibile nella mappa scopata
            data = filter_map_to_scope(core_engine.generate_network_map(group_filter="all"), scope)
            if payload.node_id not in {n["id"] for n in data["nodes"]}:
                raise HTTPException(status_code=403, detail="Dispositivo non consentito per il tuo profilo.")
```

(`filter_map_to_scope` and `user_group_scope` are already imported in this file.)

#### 894563750 — `routers/mac.py` · `mac_list_overrides` (GET `/api/mac/overrides`)

Write/delete override endpoints call `assert_device_allowed`; the list endpoint returns everything (switch IPs + custom CLI commands) to any authenticated user including viewers.

**Fix:** filter to devices in scope, consistent with the write path:

```python
@router.get("/api/mac/overrides")
def mac_list_overrides(current_user = Depends(get_current_user)):
    overrides = mac_history.list_overrides()
    scope = user_group_scope(current_user)
    if scope is not None:
        allowed_ips = {d["IP"] for d in inventory_manager.get_all_devices()
                       if d.get("Group", "Generale") in scope}
        overrides = [o for o in overrides if o["switch_ip"] in allowed_ips]
    return {"overrides": overrides}
```

#### 894563749 — `routers/commands.py` · `get_bulk_command_status` (GET `/api/bulk-command/{job_id}`)

No ownership check; any authenticated user (viewer included) can read bulk command output given a job_id. Risk is reduced because job ids are `uuid.uuid4()` (unguessable) and jobs expire after 10 minutes — but ids leak into audit logs and browser history, and viewers should never see command output.

**Fix (two lines each):**
1. In `start_bulk_command`, record the owner when creating the job:
   ```python
   _bulk_jobs[job_id] = {
       "status": "running", "results": [], "progress": 0,
       "total": len(payload.ips), "started_at": time.time(),
       "owner": current_user.get("sub"),
   }
   ```
2. In `get_bulk_command_status`, change the dependency to `require_operator` and enforce ownership (admin bypass consistent with the rest of the app):
   ```python
   def get_bulk_command_status(job_id: str, current_user = Depends(require_operator)):
       ...
       if not job:
           raise HTTPException(status_code=404, detail=f"Job '{job_id}' non trovato.")
       if current_user.get("role") != "admin" and job.get("owner") != current_user.get("sub"):
           raise HTTPException(status_code=404, detail=f"Job '{job_id}' non trovato.")  # 404, non 403: non confermare l'esistenza
   ```

### Priority 2 — SQL injection findings

**All 10 findings (894562865–871, 894562864, 894562863, 894562862) are false positives.** In every flagged location, string interpolation (`%` or f-string) is used **only to generate `?` placeholder lists**, never to inject values:

- `mac_history.py:408, 455–457, 541–543` — e.g. `q.append("AND tenant IN (%s)" % ",".join("?" * len(tenants)))`, `args.extend(list(tenants))`. All user values (`mac`, `ip`, `vlan`, `interface`, `tenants`, `frm`, `to`, `limit`) are bound parameters. MAC fragments are additionally stripped to hex via `_HEXONLY`, and `limit` is clamped `int()`.
- `observability/correlator.py:98` — `IN ({placeholders})` where `placeholders = ",".join("?" * len(_SECURITY_ACTIONS))`, values bound; `_SECURITY_ACTIONS` is a module constant.
- `observability/summary.py:51, 58` — `clause`/`flow_clause` are composed exclusively of literal SQL and `?`; tenant names and flow-key values go through `params`/`flow_params` tuples.

**Action:** triage as **False Positive** in Semgrep with the comment "placeholder-list generation only; all values bound via sqlite3 parameters". Optionally add `# nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query` on these lines to prevent re-flagging. No code change required.

### Priority 3 — Path traversal (894562873, 894562872)

`routers/ai.py:_device_running_config_context` and `routers/analyzer.py:_load_backup_text` both call `assert_device_allowed(current_user, ip)` **before** `config_analyzer._find_freshest_backup(ip)` and raise 404 when the device is not in inventory. Therefore `ip` can only ever be an existing inventory IP — not attacker-arbitrary — and cannot contain `../` unless the inventory itself is poisoned by an operator. **Verdict: already mitigated.**

**Cheap hardening (recommended, one line each):** add the same IP regex already used in `sites.py`/`commands.py` at the top of both helpers, as defense in depth against a poisoned inventory:

```python
if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
    raise HTTPException(status_code=400, detail="IP non valido.")
```

Then mark both findings **risk-accepted / mitigated** in Semgrep.

### Priority 4 — SSRF / paramiko (894562860, 894562859)

`ws_terminal` connects via SSH to `ip` from the URL path, but only after: (a) a valid 30-second single-use OTP issued to an authenticated operator, (b) resolving `ip` against inventory (`device = next(...)`, close if not found), (c) group-scope enforcement for non-admins. The connect target is therefore always an inventory-registered device. **Verdict: already mitigated** — triage as such.

Optional hardening (not required for closure): replace `paramiko.AutoAddPolicy()` with a persisted known-hosts policy; this is a MITM concern, not SSRF, and is out of scope for these findings.

### Priority 5 — Dockerfile missing USER (894562861)

**True positive.** The container runs `app_server.py` as root.

**Fix** — add before `CMD`, after `COPY . .`:

```dockerfile
RUN useradd --create-home --uid 10001 sentinelnet && \
    mkdir -p /app/data && chown -R sentinelnet:sentinelnet /app/data
USER sentinelnet
```

Note: `iputils-ping` may need `setcap cap_net_raw+ep /usr/bin/ping` (or install `ping` with the setuid bit, which the Debian package provides) so `ping3` keeps working unprivileged. Verify the triage/ping feature in a non-root container before merging. Port 8765 is unprivileged, so no other change needed.

### Priority 6 — Subresource Integrity (894562853–894562857)

**True positives.** Five CDN `<script>`/`<link>` tags in `templates/dashboard.html` (lines 9, 17, 20, 23, 24) lack `integrity`.

**Fix:** for each tag, pin the exact version and add SRI + crossorigin, e.g.:

```html
<script src="https://cdn.example/lib@X.Y.Z/lib.min.js"
        integrity="sha384-<hash>" crossorigin="anonymous"></script>
```

Generate hashes with `curl -s <url> | openssl dgst -sha384 -binary | openssl base64 -A` or https://www.srihash.org. **Preferred alternative** (given this is a network-management tool often deployed in restricted/offline environments): vendor the five assets into `static/vendor/` and serve them locally — removes both the SRI issue and the CDN availability/privacy dependency in one move.

---

## 3. Won't-Fix (accepted with justification)

| Finding | Justification |
|---|---|
| 894562858 (`test_router_smoke.py:48`, non-literal import) | `importlib.import_module()` input comes from `pkgutil.iter_modules(routers.__path__)` — local package enumeration, not user input. Test-only file, never deployed. Mark **ignored (test code)**. |
| 894562852 (`static/js/core.js:137`, unsafe format string) | `console.error(\`[ApiFetch Error] ${url}:\`, err)` — client-side browser console logging only; worst case is a forged log line in the user's own devtools. No server log injection, no security boundary crossed. Mark **won't fix (informational)**. |
| 894562874 (`routers/wlc.py:33`, "SQL injection") | False positive: `wlc_service.query(device, service, mac=mac)` is an SSH/CLI query to a wireless controller, not a database call; `service` is a server-side literal. Mark **false positive**. (Optional hardening, separate ticket: validate the `mac` path parameter with `mac_history.normalize_mac` in `wlc_client_detail`/`wlc_diagnose_client` before it is interpolated into a CLI show command.) |
| 894562865–871, 894562864, 894562863, 894562862 (raw SQL) | False positives — see Priority 2. Placeholder-only interpolation, fully parameterized. |
| 894562860 / 894562859 (paramiko SSRF) | Already mitigated — OTP auth + inventory resolution + group scoping constrain the connect target. See Priority 4. |
| 894562873 / 894562872 (path traversal) | Already mitigated via `assert_device_allowed` inventory gate; apply the one-line IP regex hardening from Priority 3 and close. |

---

## Suggested execution order

1. **PR 1 (same day):** `sites.py` three fixes + `catalog.py` + `mac.py` + `commands.py` bulk-job ownership (Priority 1). Small, mechanical, all reuse `deps.py` helpers. Add regression tests: scoped-operator token vs. out-of-scope site/device → expect 403/404.
2. **PR 2:** Dockerfile non-root user (verify ping capability).
3. **PR 3:** SRI attributes or vendor CDN assets locally.
4. **Triage in Semgrep UI:** mark the 11 FP SQL findings, 2 path-traversal, 2 SSRF as FP/mitigated with the comments above; mark 894562858 and 894562852 as won't-fix.