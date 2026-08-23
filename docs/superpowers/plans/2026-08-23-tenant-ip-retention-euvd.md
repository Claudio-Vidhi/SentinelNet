# Tenant IP Identity, Retention Cap, EUVD Removal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make two tenants owning the same IP an ordinary, supported situation; let the operator choose how many config versions to keep; delete the EUVD leftovers now that the vulnerability API is NIST NVD.

**Architecture:** Three independent parts in one file. Part A changes device identity from "IP" to "(tenant, IP)" on the write path and resolves reads within the caller's tenant scope, without rewriting the 53 IP-keyed route paths. Part B adds one setting and one prune call. Part C is a deletion.

**Spec:** none — Parts A and B were scoped directly with the user; Part C's investigation is recorded in its preamble below.

## Global Constraints

- **Version:** single source of truth is `core/version.py`, currently `0.10.0`; `pyproject.toml` must match. Part A is a MINOR bump (identity behaviour change). Bump once, at the end.
- **No CI.** GitHub Actions was removed deliberately. The gates are local: `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py`, `uv run python -m unittest discover -s tests`, then `graphify update .`.
- **Tests must be `unittest.TestCase` classes.** Bare `test_*` functions are NOT collected by `unittest discover` — `tests/test_switch_provisioner.py` is an existing example of that trap.
- **No real customer data in tracked files.** `data/` is gitignored and this repo is public. Use RFC 5737 (`192.0.2.x`, `198.51.100.x`), `switch-01`, `ACME`, `<hostname>`.
- **New comments in English.** Existing Italian comments stay; do not translate them.
- **i18n:** every user-visible string needs a key in BOTH the `it` and `en` blocks of `static/js/i18n.js`, or `tests/test_i18n_parity.py` fails.
- **Never regenerate** `tests_data/openapi_golden.json` or `openapi_pre_destructure.json`. New paths and schemas go in the allow-lists in `tests/test_router_parity.py`, with a comment saying why.
- **`tests.test_observability_ingest.TestUdpEndToEnd.test_load_5kpps_loop_latency` is timing-sensitive** and can fail on a loaded machine. If only that fails, re-run it alone and say so.
- Commit after every task.

---

# Part A — Two tenants may own the same IP

## Why this is not merely a lookup nicety

Overlapping RFC 1918 space across customers is normal: two tenants each running `192.168.1.0/24` is the default state of the world, not an anomaly. The code treats an IP as globally unique, and the consequences are worse than ambiguity.

**The write path silently destroys data.** `add_or_update_device` in `services/inventory_manager.py` (around lines 444 and 464) rebuilds the device list with:

```python
devices = [d for d in devices if d['IP'] != ip]
```

Adding tenant B's `192.0.2.10` therefore **deletes tenant A's `192.0.2.10` row** — credentials, site, group and all. No warning, no audit line. This is the finding that makes Part A urgent rather than tidy.

**The read path picks whichever comes first.** `assert_device_allowed` (`routers/deps.py:111`) resolves with `next((d for d in ... if d['IP'] == ip), None)`. First match in CSV order wins, so a scoped user can be handed another tenant's device — or refused their own — depending on row order.

**`get_device_by_ip` refuses to answer at all.** It caches a `{"collision": True}` sentinel when it sees a duplicate (`services/inventory_manager.py:344-368`). Only two call sites check for it (`observability/ingesters/udp_server.py:73`; `core/net_ssh.py:jump_site_for` documents it). Of 23 callers, the rest get a dict missing every key they expect.

**The backup tree crosses tenants — and the config-drift work amplified it.** `remove_stale_backups(ip, new_dir, keep)` in `core/core_engine.py` walks the *entire* backup tree matching `-{ip}.txt`, so with two tenants sharing an IP, saving tenant A's backup may move tenant B's current backup into tenant A's folder — and since config drift shipped, `_move_history` may carry tenant B's whole `.history` archive with it. Verify this before designing around it; it is the highest-severity item in Part A.

## The approach, and why not the alternatives

**Chosen: identity is `(tenant, IP)` on the write path; reads resolve within the caller's scope.**

Users are already tenant-scoped (`user_group_scope` returns `None` for an admin, else a set of allowed groups). Within one tenant an IP *is* unique, so a scoped operator's existing IP-keyed URLs stay unambiguous with no change at all. Only an unscoped admin can hit a genuine ambiguity, and only then is a disambiguator needed.

Rejected: **a composite key in the URL** (`/api/{tenant}/{ip}/...`) — 53 route paths, every frontend call site, and the OpenAPI golden. Enormous, and it makes the common case pay for the rare one.

Rejected: **a synthetic device id** replacing IP everywhere — cleaner in the abstract, but it touches every route, every JS caller, the CSV format and every stored reference. A migration of that size is its own project, not a task in this plan.

---

### Task A1: Make the inventory write path tenant-aware

The data-loss bug. Do this first; nothing else in Part A matters if adding a device still deletes another tenant's row.

**Files:**
- Modify: `services/inventory_manager.py` — `add_or_update_device` and the list-rebuild sites (around lines 390, 444, 464)
- Test: `tests/test_tenant_ip_overlap.py` (create)

**Interfaces:**
- Consumes: nothing new.
- Produces: `add_or_update_device(...)` keyed on `(Group, IP)`. Same signature; the `group` argument now participates in identity.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""Two tenants may own the same IP.

Overlapping RFC 1918 space across customers is the normal state of the world,
not an anomaly. Adding tenant B's device used to delete tenant A's row with the
same address — credentials, site and all, with no warning.
"""
import unittest

from services import inventory_manager


class SameIpInTwoTenantsCoexist(unittest.TestCase):
    def setUp(self):
        raise NotImplementedError("see the Step 1 note below")

    def test_adding_the_second_tenant_keeps_the_first(self):
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", group="ACME", hostname="switch-01")
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", group="BETA", hostname="switch-99")

        rows = [d for d in inventory_manager.get_all_devices() if d["IP"] == "192.0.2.10"]
        self.assertEqual(2, len(rows))
        self.assertEqual({"ACME", "BETA"}, {r["Group"] for r in rows})

    def test_updating_one_tenant_does_not_touch_the_other(self):
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", group="ACME", hostname="switch-01")
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", group="BETA", hostname="switch-99")
        inventory_manager.add_or_update_device(
            ip="192.0.2.10", vendor="cisco", group="ACME", hostname="switch-01-renamed")

        rows = {r["Group"]: r for r in inventory_manager.get_all_devices()
                if r["IP"] == "192.0.2.10"}
        self.assertEqual("switch-01-renamed", rows["ACME"]["Hostname"])
        self.assertEqual("switch-99", rows["BETA"]["Hostname"])


if __name__ == "__main__":
    unittest.main()
```

**Step 1 note:** `add_or_update_device`'s real signature and the data-dir isolation pattern must be read from the code and from a neighbouring test. `tests/test_sites.py` and `tests/test_rbac_scope.py` both set `SENTINELNET_DATA_DIR` to a temp dir *before* importing the module — that ordering matters. Replace the `setUp` above with that pattern and correct the call signature to match reality. Do not guess it.

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_tenant_ip_overlap -v`
Expected: FAIL — the second add removes the first row, so only one comes back.

- [ ] **Step 3: Make identity composite**

In `services/inventory_manager.py`, change every place that rebuilds the device list by IP alone so it also compares the group. Grep for `['IP'] != ip` and `['IP'] == ip` in that file and fix each, reading its surrounding function first — one is a delete path where IP-only may be intended.

Add a helper rather than repeating the comparison:

```python
def _same_device(row: dict, ip: str, group: str) -> bool:
    """Identity is (tenant, IP), not IP.

    Two customers each running 192.168.1.0/24 is ordinary. Keying on IP alone
    meant adding the second tenant's device deleted the first tenant's row.
    """
    return row.get("IP") == ip and (row.get("Group") or "Generale") == (group or "Generale")
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run the new module, then the full suite. Other inventory tests assume IP-only identity; read each failure before changing it, and report any test you modify with the reason.

- [ ] **Step 5: Commit**

```bash
git add services/inventory_manager.py tests/test_tenant_ip_overlap.py
git commit -m "fix(inventory): identity is (tenant, IP), so adding a device stops deleting another tenant's"
```

---

### Task A2: Resolve reads inside the caller's tenant scope

**Files:**
- Modify: `routers/deps.py` — `assert_device_allowed`
- Test: `tests/test_tenant_ip_overlap.py` (extend)

**Interfaces:**
- Consumes: `user_group_scope(current_user)` — `None` for an admin, else a set of allowed group names.
- Produces: `assert_device_allowed(current_user, ip, tenant=None)` — `tenant` is optional and consulted only when the IP is ambiguous for this caller. Existing call sites keep working unchanged.

- [ ] **Step 1: Write the failing test**

Extend `tests/test_tenant_ip_overlap.py` with a class that seeds the same IP in two tenants and asserts:

- a user scoped to `ACME` resolves `192.0.2.10` to the ACME row, never BETA's
- a user scoped to `BETA` resolves the same IP to the BETA row
- an admin (unscoped) with an ambiguous IP and no `tenant` gets a clear failure rather than a silent first-match — assert the specific exception you settle on in Step 3
- an admin passing `tenant="BETA"` resolves to BETA's row

Follow `tests/test_rbac_scope.py` for constructing scoped users.

- [ ] **Step 2: Run it to make sure it fails**

Expected: the scoped cases return whichever row is first in CSV order, so at least one assertion fails.

- [ ] **Step 3: Implement scope-aware resolution**

```python
def assert_device_allowed(current_user, ip, tenant=None):
    """Resolve an IP to a device the caller may see.

    Identity is (tenant, IP): two customers may each own 192.0.2.10. A scoped
    user has exactly one candidate, because an IP is unique inside a tenant, so
    their existing IP-keyed URLs stay unambiguous. Only an unscoped admin can
    see more than one, and only then is `tenant` needed.
    """
    scope = user_group_scope(current_user)
    matches = [d for d in inventory_manager.get_all_devices() if d["IP"] == ip]
    if scope is not None:
        matches = [d for d in matches if (d.get("Group") or "Generale") in scope]
    if tenant:
        matches = [d for d in matches if (d.get("Group") or "Generale") == tenant]

    if not matches:
        return None
    if len(matches) > 1:
        tenants = ", ".join(sorted(m.get("Group", "Generale") for m in matches))
        raise HTTPException(
            status_code=409,
            detail=f"{ip} esiste in piu' tenant ({tenants}). Specificare il tenant.")
    device = matches[0]
    assert_group_allowed(current_user, device.get("Group", "Generale"))
    return device
```

Decide deliberately whether 409 is right and whether the detail should name the tenants — only an unscoped admin can reach that branch, and an admin already sees every tenant, so it leaks nothing. Record the reasoning in your report.

- [ ] **Step 4: Run the tests, then the full suite**

53 routes call this. Read every failure before touching it.

- [ ] **Step 5: Commit**

---

### Task A3: Stop the backup tree crossing tenants

**Verify the premise before writing code.** Reproduce the cross-tenant move in a test first. If it does not reproduce, say so and stop — do not "fix" something you could not make fail.

**Files:**
- Modify: `core/core_engine.py` — `remove_stale_backups`, `_move_history`, `save_backup`
- Test: `tests/test_tenant_ip_overlap.py` (extend)

- [ ] **Step 1: Write the failing test**

Seed a current backup plus two archived history versions for `192.0.2.10` under tenant `BETA`. Then call `save_backup` for a different device with the same IP under tenant `ACME`. Assert BETA's current backup and both archived versions are still under BETA, and ACME has only its own.

- [ ] **Step 2: Run it and confirm it fails**

- [ ] **Step 3: Scope the walk to the device's own tenant**

The function exists to clean up after a device that changed *group or vendor* — a move within one owner's tree. It should never touch a directory belonging to a different tenant. The tree is `backup-config/<tenant>/<vendor>/`, so the tenant is the first path component under `BACKUP_FOLDER`: skip any root whose tenant component differs from the device's.

Read the current implementation whole before editing — it changed recently and carries a `keep=` argument that must not break. `tests/test_config_drift_history.py` covers both the cross-tenant move and the same-tenant hostname change; both must still pass.

- [ ] **Step 4: Run `tests.test_config_drift_history` and `tests.test_tenant_ip_overlap`, then the full suite**

- [ ] **Step 5: Commit**

---

### Task A4: Make `get_device_by_ip` answer within a tenant

**Files:**
- Modify: `services/inventory_manager.py` — `get_device_by_ip` and its cache
- Test: `tests/test_tenant_ip_overlap.py` (extend)

The `{"collision": True}` sentinel exists because the function could not answer. With `(tenant, IP)` identity it can, given a tenant.

- [ ] **Step 1: Read all 23 call sites first**

`grep -rn "get_device_by_ip" --include=*.py .` — two check the sentinel (`observability/ingesters/udp_server.py:73`; `core/net_ssh.py:jump_site_for` documents it). Every other caller currently receives a dict silently lacking the keys it expects when there is a collision.

Write down, in your report, what each call site knows about the tenant at the point it calls. Some — the UDP ingester attributing an exporter IP — genuinely do not know, and for those the sentinel remains the honest answer.

- [ ] **Step 2: Write the failing test**

Assert `get_device_by_ip("192.0.2.10", tenant="ACME")` returns ACME's row while BETA's identical IP exists, and that the no-tenant call still returns the collision sentinel rather than guessing.

- [ ] **Step 3: Implement**

Add an optional `tenant` parameter. Key the cache on `(tenant, ip)` as well as `ip`, or keep two maps — decide after reading how `_device_ip_cache` is invalidated, and say why. Preserve the sentinel for the no-tenant ambiguous case: a caller that cannot name a tenant must not be handed a guess.

- [ ] **Step 4: Update the callers that DO know their tenant** to pass it. Leave the ones that genuinely cannot.

- [ ] **Step 5: Full suite, then commit**

---

# Part B — Operator-chosen retention cap

Config history keeps every changed version forever, deliberately. The operator should be able to bound it.

### Task B1: A retention setting, and pruning on write

**Files:**
- Modify: `services/config_drift/history.py` — `record_version`, plus a new `prune`
- Modify: `core/app_settings.py` if defaults are enumerated there — read it first
- Test: `tests/test_config_drift_retention.py` (create)

**Interfaces:**
- Consumes: `core.app_settings.get_app_settings()`.
- Produces: `prune(device: dict) -> int` — versions removed. Setting key `config_drift_keep_versions`, integer, `0` means keep everything (current behaviour, and the default).

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""The operator decides how much config history to keep.

Default is keep-everything, which is what shipped. A cap prunes the oldest
versions and their files, and never touches the current backup.
"""
import os
import tempfile
import unittest
from unittest import mock

DEVICE = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco",
          "Hostname": "switch-01"}


class RetentionCap(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def _record(self, n):
        from services.config_drift import history
        for i in range(n):
            history.record_version(DEVICE, f"hostname switch-01\n! change {i}\n")

    def test_zero_means_keep_everything(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 0}):
            self._record(5)
        self.assertEqual(5, len(history.list_versions(DEVICE)))

    def test_a_cap_keeps_the_newest_and_drops_the_oldest(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 3}):
            self._record(5)
        versions = history.list_versions(DEVICE)
        self.assertEqual(3, len(versions))
        self.assertIn("change 4", history.read_version(DEVICE, versions[0]["seen_at"]))

    def test_pruned_files_are_removed_from_disk(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 2}):
            self._record(4)
        kept = {v["file"] for v in history.list_versions(DEVICE)}
        on_disk = {f for f in os.listdir(history.history_dir(DEVICE))
                   if f.endswith(".txt")}
        self.assertEqual(kept, on_disk)

    def test_lowering_the_cap_prunes_on_the_next_write(self):
        from services.config_drift import history
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 0}):
            self._record(5)
        with mock.patch("core.app_settings.get_app_settings",
                        return_value={"config_drift_keep_versions": 2}):
            history.record_version(DEVICE, "hostname switch-01\n! newest\n")
        self.assertEqual(2, len(history.list_versions(DEVICE)))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

- [ ] **Step 3: Implement `prune` and call it from `record_version`**

Prune *after* the new version is archived and the index saved, never before — a crash mid-prune must leave the index and the files consistent with each other. Remove a version's file and its index entry together. Never touch the current backup file; it is not a version.

An index entry whose file is already gone must not raise — that is the state `reset_topology` can leave behind.

- [ ] **Step 4: Run the retention tests, the drift history tests, then the full suite**

- [ ] **Step 5: Commit**

### Task B2: Expose the cap in Settings

**Files:**
- Modify: `templates/dashboard.html` — the Settings panel holding the other app settings
- Modify: `static/js/settings.js`
- Modify: `static/js/i18n.js` — both `it` and `en`
- Modify: the settings route that persists `app_settings`
- Test: extend `tests/test_config_drift_retention.py`

- [ ] **Step 1** Read how an existing numeric app setting is rendered, persisted and validated end to end, and follow it exactly. `#obsPruneDays` in the Observability settings block is the closest example.

- [ ] **Step 2** Write a test asserting the setting round-trips through the API and that a negative or non-numeric value is rejected at the boundary rather than stored.

- [ ] **Step 3** Implement. The field needs a label and a hint saying `0` keeps everything; both need i18n keys in both languages.

- [ ] **Step 4** `uv run python scripts/check_frontend.py`, `tests.test_i18n_parity`, full suite.

- [ ] **Step 5** Commit.

---

# Part C — Delete the EUVD leftovers

The vulnerability API is NIST NVD: `/api/search` in `routers/backup.py` already builds NVD v2.0 parameters and calls `NVD_BASE_URL`. The EUVD naming and data around it are ENISA-era leftovers.

**What the investigation found** — verify each before deleting, do not take this list on faith:

1. **The UI still tells the user it queries ENISA.** `templates/dashboard.html:702` and the `descVendorRegistry` key in both languages: *"Il campo EUVD Term è usato nelle query al database europeo delle vulnerabilità ENISA."* That is false. It is the only leftover a user can see and be misled by.
2. **`euvd_term` duplicates `VENDOR_NVD_MAP`.** `services/inventory_manager.py:779` maps every vendor to its NVD search term, with values identical to the `euvd_term` defaults in `get_all_vendors` (cisco→cisco, paloalto→"palo alto", …). `resolve_euvd_term()` reads the map, not the field, and the proxy applies it to whatever the frontend sends — so the registry field is a second, hand-maintained copy that works only because the two agree.
3. **`"euvd": cwe_str` in the proxy payload is dead and mislabelled.** `routers/backup.py:322` emits the CWE string under the name `euvd`, and the identical value again as `cwe`.
4. **The client reads neither.** `static/js/threat-intel.js:47` rebuilds `euvd` from `['id', 'euvdId', 'enisaId']`; NVD returns no `euvdId`/`enisaId`, so it lands on `item.id` — the CVE id. Both render sites then suppress it via their own `item.euvd !== item.cve` guard, so no EUVD value is ever displayed. `cwe` is not referenced in that file at all.

### Task C1: Remove the `euvd_term` field

**Files:**
- Modify: `routers/catalog.py` — `VendorSchema` (line 34), `/api/catalog` vendor payload (line 132)
- Modify: `services/inventory_manager.py` — `get_all_vendors` defaults
- Modify: `templates/dashboard.html` — vendor-registry table column (line 709), form field (line 723)
- Modify: the vendor registry CRUD in `static/js/` — grep for `euvd_term`
- Modify: `static/js/threat-intel.js` — Vendor Watch button filter (line 78) and term (lines 85, 90)
- Modify: `static/js/i18n.js` — remove `thVendorTerm`, `lblVendorTerm`; fix `descVendorRegistry` and `alertVendorRequired` in BOTH languages
- Test: `tests/test_vendor_registry_no_euvd.py` (create)

Vendor Watch buttons currently list only vendors with a non-empty `euvd_term`. With the field gone, list every registered vendor and send the display name — `resolve_euvd_term()` resolves it server-side to the same term, so the NVD query is unchanged.

- [ ] **Step 1: Write the failing test**

Assert that `/api/catalog`'s vendor payload has no `euvd_term` key; that a `vendors.json` **already containing** `euvd_term` — as every installed system has — still loads and its vendors still appear; and that `resolve_euvd_term("paloalto")` still returns `"palo alto"`, proving the NVD term survives the field's removal.

That middle case is the one that breaks customers on upgrade. Write it first.

- [ ] **Step 2: Run it, confirm it fails**

- [ ] **Step 3: Remove the field.** Loading must ignore a stale `euvd_term` key rather than choke on it — check whether `VendorSchema` forbids extra keys before assuming it tolerates them.

- [ ] **Step 4:** `tests.test_i18n_parity`, `scripts/check_frontend.py`, `tests.test_router_parity` (the schema set changes — extend the allow-list, do NOT regenerate the golden), full suite.

- [ ] **Step 5: Commit**

### Task C2: Remove the dead `euvd` payload and display

**Files:**
- Modify: `routers/backup.py` — drop `"euvd": cwe_str` from the item dict (line 322); keep `"cwe"`
- Modify: `static/js/threat-intel.js` — drop the `euvd` variable (line 47), its field in the returned record, the two suppressed render branches (lines 245, 283), and the search-filter join (line 213)
- Modify: `templates/dashboard.html` — the `CVE / EUVD` column header (line 1082) becomes `CVE`; give it an i18n key, which it currently lacks
- Test: extend `tests/test_vendor_registry_no_euvd.py`

- [ ] **Step 1** Write a test asserting the `/api/search` item shape has no `euvd` key and still carries `cve` and `cwe`. Mock the outbound NVD call — do not hit the real API from a test.

- [ ] **Step 2** Confirm it fails.

- [ ] **Step 3** Remove. `cwe` is currently unused by the client; leave it in the payload and say so in your report, so surfacing it later is a one-line change rather than a re-investigation.

- [ ] **Step 4** Full suite, `check_frontend.py`, `tests.test_i18n_parity`.

- [ ] **Step 5** Commit.

### Task C3: Version, docs and the full gate

- [ ] **Step 1** Bump `core/version.py` and `pyproject.toml` line 3 together — MINOR, for Part A's behaviour change. Run `tests.test_version`.

- [ ] **Step 2** Update the docs. Search `docs/`, `README.md` and `PRODUCT.md` for `euvd`, `EUVD` and `ENISA` and correct every hit — `docs/architecture.md` and `docs/roadmap.md` both mention it. `docs/netsec_troubleshooting_qa_v3.md` pins routes and element ids in a strict house style; match it.

Document the new tenant-IP behaviour and the retention setting in the same pass. Assert nothing you have not verified in the code.

- [ ] **Step 3** `uv run pyrefly check`, `uv run python scripts/check_frontend.py`, `uv run python -m unittest discover -s tests`, `graphify update .`.

- [ ] **Step 4** Commit.

---

## Notes for the executor

- **Task A1 is the one that matters most.** It is a silent cross-tenant data-loss bug on the write path. If you do nothing else in this plan, do that.
- **Parts B and C are independent** of Part A and of each other, and can be reordered or dropped. Part A's four tasks are sequential.
- **Do not regenerate the OpenAPI golden snapshots.** Changed schemas go in the allow-lists in `tests/test_router_parity.py`.
- **`tests/test_switch_provisioner.py` holds bare `test_*` functions that `unittest discover` never collects.** If you add a test near it, make it a `TestCase` or it will not run — and the suite will still look green.
- If a task's test passes on the first run, before you write the implementation, stop — the test is not testing what you think it is.
