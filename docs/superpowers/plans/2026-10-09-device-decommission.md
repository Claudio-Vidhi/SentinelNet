# Device Decommission and Bulk Delete Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** From the inventory, decommission, reactivate and delete many devices at once; a decommissioned device leaves every subsystem without any of them changing.

**Architecture:** Decommissioned rows move from `network_hosts.csv` to `decommissioned_hosts.csv` in the same directory, so the ~75 readers of `get_all_devices()` never see them. One guard in `safe_write_hosts_csv` refuses a new active row that is decommissioned. Three bulk endpoints act on `(tenant, ip)` pairs; the inventory gets a «Dismessi» tab, three selection-bar buttons and a confirmation modal.

**Tech Stack:** Python 3 / FastAPI / CSV files / classic-script JS (no bundler) / unittest run by pytest (`uv run pytest tests -n 4`).

**Spec:** `docs/superpowers/specs/2026-10-09-device-decommission-design.md`

## Global Constraints

- Identity is `(tenant, ip)` = `(row["Group"] or "Generale", row["IP"])` everywhere.
- Write order "copy first, remove second": an interrupted action leaves a row in both files, never in neither.
- The guard checks only rows **new to the active file in that write**; `reactivate` passes its pairs as an exemption.
- Routes: `require_tab("tab-devices")` + `require_operator` for POST; at most 1000 pairs per request; every pair scope-checked and existence-checked before any write.
- Audit lines in Italian, one per device: `Dispositivo '<ip>' (gruppo '<tenant>') dismesso|riattivato|eliminato dall'utente '<user>'.` (the `(gruppo` keeps them out of `device_history`'s audit backfill regexes).
- New comments in English; leave existing Italian comments alone (AGENTS.md).
- UI: strings via `tr()` in both languages, `openModal`/`closeModal`, delegated listeners on ids present in `dashboard.html`, accessible names on controls, no inline handlers.
- Example data only: `192.0.2.x`, `tenant-a`, `tenant-b`.
- Gate before each commit: `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py` (if JS/templates changed), `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`.

## Review Focus

1. **Reassigning or promoting a device onto a decommissioned `(tenant, ip)`** → 400 with the "reactivate or delete it" message, not a 500. Test in Task 2.
2. **A triage finishing on a device decommissioned meanwhile** (it calls `update_device_hostname` / version writes) → the device must not come back to the active file. Test in Task 1.
3. **A viewer calling the POST routes** → 403, nothing changes. Test in Task 2.
4. **Two tenants with the same IP, one selected** → only that one acts. Pair test in Task 1; UI keyed by tenant+IP, static test in Task 3.
5. **CSV import containing a decommissioned `(tenant, ip)`** → that row is reported as failed, the others import. Test in Task 2.

---

## File map

| File | Change |
|---|---|
| `services/inventory_manager.py` | `_HOSTS_FIELDS` at module level; `device_pair`, `get_decommissioned_csv`, `get_decommissioned_devices`, `_write_decommissioned`, `_refuse_decommissioned`, `decommission`, `reactivate`, `delete_devices`; `safe_write_hosts_csv(devices, exempt=..., relabel=...)` |
| `services/device_history.py` | `record(old_rows, new_rows, relabel=None)` |
| `core/data_config.py` | `decommissioned_hosts.csv` in `_STATE_FILES` |
| `routers/inventory.py` | `DevicePair`, `DeviceBulkSchema`, `_bulk_pairs`, `_audit_each`, 4 routes; `ValueError`→400 in reassign and promote |
| `static/js/devices.js` | selection keyed by tenant+IP, «Dismessi» rows, bar buttons, lifecycle modal |
| `static/js/device-history.js` | new kinds, buckets, service days |
| `static/js/i18n.js` | new keys IT+EN, three changed values |
| `templates/dashboard.html` | status tab, three buttons, modal |
| `static/css/dashboard.css` | three small rules |
| `docs/operations.md` | short section |
| Tests | `tests/test_device_decommission.py`, `tests/test_device_decommission_api.py`, `tests/test_device_decommission_ui.py` |

---

### Task 1: Storage, guard and history

**Model:** sonnet

**Files:**
- Modify: `services/inventory_manager.py` (`safe_write_hosts_csv` at ~258, new section after `delete_device` at ~529)
- Modify: `services/device_history.py` (`record` at ~81)
- Modify: `core/data_config.py:22-29`
- Test: `tests/test_device_decommission.py`

**Interfaces:**
- Produces:
  - `inventory_manager.device_pair(row: dict) -> tuple[str, str]` — `(tenant, ip)`
  - `inventory_manager.get_decommissioned_csv() -> str`
  - `inventory_manager.get_decommissioned_devices() -> list[dict]` — rows with `Decommissioned` (ISO `YYYY-MM-DDTHH:MM:SSZ`) and `Decommissioned By`
  - `inventory_manager.decommission(pairs, actor: str) -> int`
  - `inventory_manager.reactivate(pairs) -> int`
  - `inventory_manager.delete_devices(pairs) -> int`
  - `inventory_manager.safe_write_hosts_csv(devices, exempt=frozenset(), relabel=None)` — raises `ValueError` on a new decommissioned pair
  - `device_history.record(old_rows, new_rows, relabel=None)`; new event kinds `decommissioned`, `reactivated`

- [ ] **Step 1: Write the failing tests**

`tests/test_device_decommission.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Decommissioned devices live in their own file (spec 2026-10-09
device-decommission): every reader of the inventory stops seeing them, and
no inventory write can lose them."""
import os
import tempfile
import unittest
from unittest.mock import patch

from security import crypto_vault
from services import device_history, inventory_manager

A1 = ("tenant-a", "192.0.2.1")
A2 = ("tenant-a", "192.0.2.2")
B1 = ("tenant-b", "192.0.2.1")


def _row(ip, group="tenant-a", **kw):
    r = {"IP": ip, "Vendor": "cisco", "Profile": "ios", "Group": group, "Probe": "central",
         "Username": "admin", "Password": crypto_vault.encrypt_password("pw1")}
    r.update(kw)
    return r


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="decom_")
        self.csv = os.path.join(tmp, "network_hosts.csv")
        self.log = os.path.join(tmp, "device_history.jsonl")
        for p in (patch.object(inventory_manager, "get_hosts_csv", lambda: self.csv),
                  patch.object(device_history, "_path", lambda: self.log),
                  patch.object(device_history, "_audit_lines", lambda: [])):
            p.start()
            self.addCleanup(p.stop)
        inventory_manager.safe_write_hosts_csv(
            [_row("192.0.2.1"), _row("192.0.2.2"), _row("192.0.2.1", group="tenant-b")])

    def active(self):
        return sorted(inventory_manager.device_pair(d) for d in inventory_manager.get_all_devices())

    def decom(self):
        return sorted(inventory_manager.device_pair(d)
                      for d in inventory_manager.get_decommissioned_devices())

    def row(self, pair):
        return next(d for d in inventory_manager.get_all_devices()
                    if inventory_manager.device_pair(d) == pair)


class TestMoves(_Base):
    def test_decommission_moves_only_the_named_pair(self):
        self.assertEqual(inventory_manager.decommission([A1], "op"), 1)
        self.assertEqual(self.active(), [A2, B1])
        self.assertEqual(self.decom(), [A1])
        (d,) = inventory_manager.get_decommissioned_devices()
        self.assertEqual(d["Decommissioned By"], "op")
        self.assertRegex(d["Decommissioned"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_file_sits_next_to_the_inventory(self):
        self.assertEqual(os.path.dirname(inventory_manager.get_decommissioned_csv()),
                         os.path.dirname(self.csv))

    def test_reactivate_restores_the_identical_row(self):
        before = self.row(A1)
        inventory_manager.decommission([A1], "op")
        self.assertEqual(inventory_manager.reactivate([A1]), 1)
        self.assertEqual(self.row(A1), before)
        self.assertNotIn("Decommissioned", self.row(A1))
        self.assertEqual(self.decom(), [])

    def test_delete_from_both_files(self):
        inventory_manager.decommission([A1], "op")
        self.assertEqual(inventory_manager.delete_devices([A1, A2]), 2)
        self.assertEqual(self.active(), [B1])
        self.assertEqual(self.decom(), [])

    def test_unknown_pairs_are_a_noop(self):
        self.assertEqual(inventory_manager.decommission([("tenant-a", "192.0.2.99")], "op"), 0)
        self.assertEqual(inventory_manager.reactivate([A1]), 0)
        self.assertEqual(self.active(), [A1, A2, B1])


class TestGuard(_Base):
    def test_adding_a_decommissioned_pair_is_refused(self):
        inventory_manager.decommission([A1], "op")
        with self.assertRaisesRegex(ValueError, "192.0.2.1"):
            inventory_manager.add_or_update_device("192.0.2.1", "cisco", "ios", "u", "p", "",
                                                   "tenant-a")
        self.assertEqual(self.decom(), [A1])
        self.assertNotIn(A1, self.active())

    def test_unrelated_write_keeps_the_decommissioned_file(self):
        inventory_manager.decommission([A1], "op")
        with open(inventory_manager.get_decommissioned_csv(), encoding="utf-8") as f:
            before = f.read()
        inventory_manager.update_device_hostname("192.0.2.2", "sw-02", "tenant-a")
        with open(inventory_manager.get_decommissioned_csv(), encoding="utf-8") as f:
            self.assertEqual(f.read(), before)

    def test_late_triage_write_does_not_bring_it_back(self):
        inventory_manager.decommission([A1], "op")
        inventory_manager.update_device_hostname("192.0.2.1", "sw-01", "tenant-a")
        self.assertNotIn(A1, self.active())

    def test_interrupted_decommission_blocks_nothing_and_completes(self):
        # Crash after the first write: the row is in both files.
        inventory_manager._write_decommissioned(
            [dict(self.row(A1), **{"Decommissioned": "2026-10-09T12:00:00Z",
                                   "Decommissioned By": "op"})])
        inventory_manager.update_device_hostname("192.0.2.2", "sw-02", "tenant-a")
        inventory_manager.decommission([A1], "op")
        self.assertEqual(self.active(), [A2, B1])
        self.assertEqual(self.decom(), [A1])

    def test_interrupted_reactivate_completes(self):
        inventory_manager.decommission([A1], "op")
        row = {k: v for k, v in inventory_manager.get_decommissioned_devices()[0].items()
               if k not in ("Decommissioned", "Decommissioned By")}
        inventory_manager.safe_write_hosts_csv(inventory_manager.get_all_devices() + [row],
                                               exempt={A1})
        self.assertEqual(inventory_manager.reactivate([A1]), 1)
        self.assertEqual(self.active(), [A1, A2, B1])
        self.assertEqual(self.decom(), [])


class TestHistory(_Base):
    def test_lifecycle_events(self):
        inventory_manager.decommission([A1], "op")
        inventory_manager.reactivate([A1])
        inventory_manager.decommission([A1], "op")
        inventory_manager.delete_devices([A1])
        kinds = [e["event"] for e in device_history.events({"tenant-a"}, ip="192.0.2.1")]
        self.assertEqual(kinds, ["removed", "decommissioned", "reactivated",
                                 "decommissioned", "added"])

    def test_relabel_only_touches_named_kinds(self):
        device_history.record([_row("192.0.2.5")], [_row("192.0.2.6")],
                              relabel={"removed": "decommissioned"})
        kinds = {e["event"] for e in device_history.events({"tenant-a"})}
        self.assertIn("decommissioned", kinds)
        self.assertIn("added", kinds)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_device_decommission.py -q`
Expected: FAIL with `AttributeError: module 'services.inventory_manager' has no attribute 'device_pair'` (and similar).

- [ ] **Step 3: `device_history.record` relabel**

In `services/device_history.py`, replace the head of `record`:

```python
def record(old_rows: list, new_rows: list, relabel: "dict | None" = None) -> None:
    """Append the events turning ``old_rows`` into ``new_rows``. ``relabel``
    renames diff kinds for writes that are not plain adds/removes, e.g.
    ``{"removed": "decommissioned"}``."""
    found = diff(old_rows, new_rows)
    if not found:
        return
    for e in found:
        e["event"] = (relabel or {}).get(e["event"], e["event"])
```

(the rest of the function is unchanged).

- [ ] **Step 4: Module-level field list and the guard in `safe_write_hosts_csv`**

In `services/inventory_manager.py`, just above `safe_write_hosts_csv`, add:

```python
_HOSTS_FIELDS = ['IP', 'Vendor', 'Profile', 'Username', 'Password', 'Enable Secret', 'Group',
                 'Hostname', 'Probe', 'SSH Port', 'Transports', 'SNMP Community', 'SNMP Disabled']
```

Change the signature to `def safe_write_hosts_csv(devices, exempt=frozenset(), relabel=None):`, replace the local `_fieldnames = [...]` line with `_fieldnames = _HOSTS_FIELDS` (keep the comment above it), and right after `old_rows = ...` inside the lock add:

```python
        _refuse_decommissioned(devices, old_rows, exempt)
```

Change the history call at the end to:

```python
            device_history.record(old_rows, _read_hosts_csv(hosts_csv), relabel)
```

- [ ] **Step 5: The decommissioned section**

In `services/inventory_manager.py`, after `delete_device` (~line 536), add:

```python
# --- Decommissioned devices -------------------------------------------------
# A decommissioned device leaves network_hosts.csv for its own file next to
# it, so the ~75 readers of get_all_devices() and every read-rewrite path stop
# seeing it without a filter any of them could forget (spec 2026-10-09
# device-decommission). Moves write the copy first and remove second: an
# interrupted move leaves the row in both files, never in neither.
_DECOM_COLS = ['Decommissioned', 'Decommissioned By']


def device_pair(row: dict) -> tuple:
    """Inventory identity: (tenant, IP)."""
    return (row.get("Group") or "Generale", row.get("IP"))


def get_decommissioned_csv() -> str:
    return os.path.join(os.path.dirname(get_hosts_csv()), "decommissioned_hosts.csv")


def get_decommissioned_devices() -> list:
    path = get_decommissioned_csv()
    with _hosts_csv_lock:
        if not os.path.exists(path):
            return []
        return _read_hosts_csv(path)


def _write_decommissioned(rows: list) -> None:
    path = get_decommissioned_csv()
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_HOSTS_FIELDS + _DECOM_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    os.replace(tmp, path)


def _refuse_decommissioned(devices, old_rows, exempt) -> None:
    """A row new to the active file must not be a decommissioned device: two
    copies of one (tenant, IP) would later be reactivated over each other.
    Only new rows are checked, so the leftover of an interrupted move never
    blocks unrelated writes."""
    new = {device_pair(d) for d in devices} - {device_pair(r) for r in old_rows} - set(exempt)
    if not new:
        return
    clash = sorted(new & {device_pair(r) for r in get_decommissioned_devices()})
    if clash:
        raise ValueError("; ".join(
            f"{ip} è dismesso nel tenant {tenant}: riattivalo o eliminalo prima"
            for tenant, ip in clash))


def decommission(pairs, actor: str) -> int:
    want = set(pairs)
    with _hosts_csv_lock:
        active = get_all_devices()
        moving = [d for d in active if device_pair(d) in want]
        if not moving:
            return 0
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        kept = [r for r in get_decommissioned_devices() if device_pair(r) not in want]
        _write_decommissioned(kept + [dict(d, **{"Decommissioned": stamp,
                                                 "Decommissioned By": actor})
                                      for d in moving])
        safe_write_hosts_csv([d for d in active if device_pair(d) not in want],
                             relabel={"removed": "decommissioned"})
    return len(moving)


def reactivate(pairs) -> int:
    want = set(pairs)
    with _hosts_csv_lock:
        dec = get_decommissioned_devices()
        back = [r for r in dec if device_pair(r) in want]
        if not back:
            return 0
        active = get_all_devices()
        have = {device_pair(d) for d in active}
        restored = [{k: v for k, v in r.items() if k not in _DECOM_COLS}
                    for r in back if device_pair(r) not in have]
        if restored:
            safe_write_hosts_csv(active + restored,
                                 exempt={device_pair(r) for r in restored},
                                 relabel={"added": "reactivated"})
        _write_decommissioned([r for r in dec if device_pair(r) not in want])
    return len(back)


def delete_devices(pairs) -> int:
    want = set(pairs)
    with _hosts_csv_lock:
        active = get_all_devices()
        n = sum(1 for d in active if device_pair(d) in want)
        if n:
            safe_write_hosts_csv([d for d in active if device_pair(d) not in want])
        dec = get_decommissioned_devices()
        gone = [r for r in dec if device_pair(r) in want]
        if gone:
            _write_decommissioned([r for r in dec if device_pair(r) not in want])
            try:
                from services import device_history
                device_history.record(gone, [])
            except Exception:
                logger.exception("Storico dispositivi non aggiornato")
    return n + len(gone)
```

- [ ] **Step 6: State file list**

In `core/data_config.py` `_STATE_FILES`, change the last line to:

```python
    "device_categories.json", "network_hosts.csv", "decommissioned_hosts.csv",
```

- [ ] **Step 7: Run to verify it passes**

Run: `uv run pytest tests/test_device_decommission.py tests/test_device_history.py tests/test_hosts_csv_concurrency.py -q`
Expected: all pass. If `test_late_triage_write_does_not_bring_it_back` fails, `update_device_hostname` appends missing rows: make it update only existing rows (that is the bug the test exists for).

- [ ] **Step 8: Gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4 -q
uv run python scripts/check_no_private_data.py
git add services/inventory_manager.py services/device_history.py core/data_config.py tests/test_device_decommission.py
git commit -m "feat(inventory): decommissioned devices in their own file, with a write guard"
```

---

### Task 2: Bulk API

**Model:** sonnet

**Files:**
- Modify: `routers/inventory.py` (schemas after `PromoteDeviceSchema` ~line 75; routes after `delete_device` ~line 360; `reassign_device` and `promote_device`)
- Test: `tests/test_device_decommission_api.py`

**Interfaces:**
- Consumes: Task 1 functions.
- Produces: `GET /api/devices/decommissioned` → `{"devices": [row without Password/Enable Secret/SNMP Community]}`; `POST /api/devices/decommission|reactivate|delete` with `{"devices": [{"ip": str, "tenant": str}]}` → `{"status": "success", "count": int}`.

- [ ] **Step 1: Write the failing tests**

`tests/test_device_decommission_api.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Bulk decommission / reactivate / delete routes: scope and existence are
checked for every pair before anything is written."""
import os
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

import app_server
from routers.deps import CSRF_HEADER
from security import security_manager, user_manager
from services import inventory_manager

H = {CSRF_HEADER: "1"}
PW = "PasswordSicura1!"
A10 = {"ip": "192.0.2.10", "tenant": "tenant-a"}
B20 = {"ip": "192.0.2.20", "tenant": "tenant-b"}


class _Isolated(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp(prefix="decom_api_")
        for const, name in (("HOSTS_CSV", "network_hosts.csv"), ("GROUPS_JSON", "groups.json")):
            p = patch.object(inventory_manager, const, os.path.join(tmp, name))
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(user_manager, "USERS_JSON", os.path.join(tmp, "users.json"))
        p.start()
        self.addCleanup(p.stop)
        security_manager._failed_attempts.clear()
        inventory_manager.save_groups({"tenant-a": {"description": ""},
                                       "tenant-b": {"description": ""}})
        for ip, tenant in (("192.0.2.10", "tenant-a"), ("192.0.2.20", "tenant-a"),
                           ("192.0.2.20", "tenant-b")):
            inventory_manager.add_or_update_device(ip, "cisco", "custom", "u", "p", "", tenant)
        user_manager.create_user("adm", PW, role="admin")
        user_manager.create_user("op", PW, role="operator", groups=["tenant-a"])
        user_manager.create_user("view", PW, role="viewer")

    def _as(self, name):
        c = TestClient(app_server.app, raise_server_exceptions=False)
        r = c.post("/api/auth/login", json={"username": name, "password": PW})
        self.assertEqual(r.status_code, 200, r.text)
        c.headers.update(H)
        return c

    def active(self):
        return sorted(inventory_manager.device_pair(d) for d in inventory_manager.get_all_devices())


class TestRoutes(_Isolated):
    def test_round_trip(self):
        adm = self._as("adm")
        r = adm.post("/api/devices/decommission", json={"devices": [A10, B20]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["count"], 2)
        listed = adm.get("/api/devices/decommissioned").json()["devices"]
        self.assertEqual(sorted(d["IP"] for d in listed), ["192.0.2.10", "192.0.2.20"])
        self.assertTrue(all("Password" not in d for d in listed))
        r = adm.post("/api/devices/reactivate", json={"devices": [A10]})
        self.assertEqual(r.status_code, 200, r.text)
        r = adm.post("/api/devices/delete", json={"devices": [A10, B20]})
        self.assertEqual(r.json()["count"], 2)
        self.assertEqual(self.active(), [("tenant-a", "192.0.2.20")])
        self.assertEqual(inventory_manager.get_decommissioned_devices(), [])

    def test_scoped_operator_out_of_scope_pair_changes_nothing(self):
        r = self._as("op").post("/api/devices/decommission", json={"devices": [A10, B20]})
        self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(len(self.active()), 3)

    def test_scoped_list_hides_other_tenants(self):
        self._as("adm").post("/api/devices/decommission", json={"devices": [A10, B20]})
        listed = self._as("op").get("/api/devices/decommissioned").json()["devices"]
        self.assertEqual([d["Group"] for d in listed], ["tenant-a"])

    def test_viewer_cannot_act(self):
        r = self._as("view").post("/api/devices/delete", json={"devices": [A10]})
        self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(len(self.active()), 3)

    def test_unknown_pair_is_404_and_changes_nothing(self):
        r = self._as("adm").post("/api/devices/decommission",
                                 json={"devices": [A10, {"ip": "192.0.2.99", "tenant": "tenant-a"}]})
        self.assertEqual(r.status_code, 404, r.text)
        self.assertEqual(len(self.active()), 3)

    def test_reactivate_needs_a_decommissioned_pair(self):
        r = self._as("adm").post("/api/devices/reactivate", json={"devices": [A10]})
        self.assertEqual(r.status_code, 404, r.text)

    def test_limits(self):
        adm = self._as("adm")
        self.assertEqual(adm.post("/api/devices/delete", json={"devices": []}).status_code, 422)
        many = [{"ip": "192.0.2.1", "tenant": "tenant-a"}] * 1001
        self.assertEqual(adm.post("/api/devices/delete", json={"devices": many}).status_code, 422)


class TestGuardOverHttp(_Isolated):
    def test_reassign_onto_a_decommissioned_pair_is_400(self):
        adm = self._as("adm")
        adm.post("/api/devices/decommission", json={"devices": [B20]})
        r = adm.post("/api/reassign-device", json={"ip": "192.0.2.20", "new_group": "tenant-b"})
        self.assertEqual(r.status_code, 400, r.text)
        self.assertIn("riattivalo", r.json()["detail"])

    def test_promote_onto_a_decommissioned_pair_is_400(self):
        adm = self._as("adm")
        adm.post("/api/devices/decommission", json={"devices": [A10]})
        r = adm.post("/api/promote-device",
                     json={"node_id": "n1", "ip": "192.0.2.10", "group": "tenant-a"})
        self.assertEqual(r.status_code, 400, r.text)

    def test_csv_import_reports_the_decommissioned_row_and_imports_the_rest(self):
        adm = self._as("adm")
        adm.post("/api/devices/decommission", json={"devices": [A10]})
        csv_data = ("IP,Vendor,Group\n"
                    "192.0.2.10,cisco,tenant-a\n"
                    "192.0.2.30,cisco,tenant-a\n")
        r = adm.post("/api/import-csv", json={"csv_data": csv_data})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["imported"], ["192.0.2.30"])
        self.assertEqual([f["ip"] for f in body["failed"]], ["192.0.2.10"])


if __name__ == "__main__":
    unittest.main()
```

If the import route needs more columns than `IP,Vendor,Group` to accept a row, read `routers/inventory.py` `/api/import-csv` and add the minimum it requires to both rows — the test is about the decommissioned row failing alone.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_device_decommission_api.py -q`
Expected: FAIL — the new routes return 404/405; reassign/promote return 500.

- [ ] **Step 3: Schemas**

In `routers/inventory.py`, after `PromoteDeviceSchema`:

```python
class DevicePair(BaseModel):
    ip: str = Field(..., pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    tenant: str = "Generale"

class DeviceBulkSchema(BaseModel):
    devices: list[DevicePair] = Field(..., min_length=1, max_length=1000)
```

- [ ] **Step 4: Routes**

After `delete_device` (the `/api/delete-device` route):

```python
def _bulk_pairs(payload: DeviceBulkSchema, current_user, rows: list) -> list:
    """Every pair in scope and present in ``rows``, checked before anything is
    written: one bad pair fails the whole request with nothing changed."""
    known = {inventory_manager.device_pair(r) for r in rows}
    pairs = []
    for d in payload.devices:
        assert_group_allowed(current_user, d.tenant)
        if (d.tenant, d.ip) not in known:
            raise HTTPException(status_code=404,
                                detail=f"Dispositivo {d.ip} non trovato nel tenant '{d.tenant}'.")
        pairs.append((d.tenant, d.ip))
    return pairs


def _audit_each(pairs: list, verb: str, current_user) -> None:
    user = current_user.get('sub')
    for tenant, ip in pairs:
        log_audit(f"Dispositivo '{ip}' (gruppo '{tenant}') {verb} dall'utente '{user}'.")


@router.get("/api/devices/decommissioned", dependencies=[Depends(require_tab("tab-devices"))])
def list_decommissioned(current_user = Depends(get_current_user)):
    scope = user_group_scope(current_user)
    out = []
    for d in inventory_manager.get_decommissioned_devices():
        if scope is not None and (d.get('Group') or 'Generale') not in scope:
            continue
        for secret in ("Password", "Enable Secret", "SNMP Community"):
            d.pop(secret, None)
        out.append(d)
    return {"devices": out}


@router.post("/api/devices/decommission", dependencies=[Depends(require_tab("tab-devices"))])
def decommission_devices(payload: DeviceBulkSchema, current_user = Depends(require_operator)):
    pairs = _bulk_pairs(payload, current_user, inventory_manager.get_all_devices())
    n = inventory_manager.decommission(pairs, current_user.get('sub'))
    _audit_each(pairs, "dismesso", current_user)
    return {"status": "success", "count": n}


@router.post("/api/devices/reactivate", dependencies=[Depends(require_tab("tab-devices"))])
def reactivate_devices(payload: DeviceBulkSchema, current_user = Depends(require_operator)):
    pairs = _bulk_pairs(payload, current_user, inventory_manager.get_decommissioned_devices())
    n = inventory_manager.reactivate(pairs)
    _audit_each(pairs, "riattivato", current_user)
    return {"status": "success", "count": n}


@router.post("/api/devices/delete", dependencies=[Depends(require_tab("tab-devices"))])
def delete_devices(payload: DeviceBulkSchema, current_user = Depends(require_operator)):
    rows = inventory_manager.get_all_devices() + inventory_manager.get_decommissioned_devices()
    pairs = _bulk_pairs(payload, current_user, rows)
    n = inventory_manager.delete_devices(pairs)
    _audit_each(pairs, "eliminato", current_user)
    return {"status": "success", "count": n}
```

- [ ] **Step 5: `ValueError` → 400 in reassign and promote**

In `reassign_device`, replace `inventory_manager.safe_write_hosts_csv(devices)` with:

```python
    try:
        inventory_manager.safe_write_hosts_csv(devices)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
```

In `promote_device`, wrap the `inventory_manager.add_or_update_device(...)` call the same way:

```python
    try:
        inventory_manager.add_or_update_device(
            payload.ip, payload.vendor, "custom", "", "", "", payload.group
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
```

- [ ] **Step 6: Run to verify it passes**

Run: `uv run pytest tests/test_device_decommission_api.py tests/test_admin_tenant_scope.py -q`
Expected: all pass. If `test_admin_tenant_scope.py` or another route-registry test requires every route to be classified, add the four new paths next to the entry for `/api/delete-device`.

- [ ] **Step 7: Gate and commit**

```bash
uv run pyrefly check
uv run pytest tests -n 4 -q
uv run python scripts/check_no_private_data.py
git add routers/inventory.py tests/
git commit -m "feat(inventory): bulk decommission, reactivate and delete routes"
```

---

### Task 3: Inventory UI and device history

**Model:** sonnet

**Files:**
- Modify: `templates/dashboard.html` (status tabs ~636-640, selection bar ~667-673, new modal before `clsModelsModal` ~5060)
- Modify: `static/js/devices.js` (selection ~130-149, `renderDeviceTable` ~201-323, handlers ~2052-2090)
- Modify: `static/js/device-history.js` (`dhServiceDays` ~61, `dhVerb` ~84, `dhSingle` ~131, `renderDeviceHistory` ~185)
- Modify: `static/js/i18n.js` (IT dict and EN dict)
- Modify: `static/css/dashboard.css`
- Test: `tests/test_device_decommission_ui.py`

**Interfaces:**
- Consumes: Task 2 routes.
- Produces: tab `data-inv-status="decommissioned"`; ids `invKpiDecommissioned`, `btnSelDecommission`, `btnSelReactivate`, `btnSelDelete`, `invBulkModal`, `invBulkTitle`, `invBulkText`, `invBulkList`, `btnInvBulkConfirm`, `btnInvBulkCancel`, `btnCloseInvBulk`.

- [ ] **Step 1: Write the failing test**

`tests/test_device_decommission_ui.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The decommission controls exist in the template and are bound in
devices.js: a getElementById on a missing id leaves a button silently dead."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTML = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
JS = (ROOT / "static" / "js" / "devices.js").read_text(encoding="utf-8")
HIST = (ROOT / "static" / "js" / "device-history.js").read_text(encoding="utf-8")

BOUND = ("btnSelDecommission", "btnSelReactivate", "btnSelDelete",
         "btnInvBulkConfirm", "btnInvBulkCancel", "btnCloseInvBulk")


class TestDecommissionUi(unittest.TestCase):
    def test_controls_exist_and_are_bound(self):
        for el in BOUND + ("invBulkModal", "invBulkTitle", "invBulkText", "invBulkList",
                           "invKpiDecommissioned"):
            with self.subTest(el=el):
                self.assertIn(f'id="{el}"', HTML)
        for el in BOUND:
            with self.subTest(el=el):
                self.assertIn(f"getElementById('{el}')", JS)

    def test_status_tab_and_endpoints(self):
        self.assertIn('data-inv-status="decommissioned"', HTML)
        self.assertIn("'/api/devices/decommissioned'", JS)
        self.assertIn("`/api/devices/${action}`", JS)

    def test_selection_is_keyed_by_tenant_and_ip(self):
        self.assertNotIn("selectedDeviceIps", JS)
        self.assertIn("data-key=", JS)

    def test_history_knows_the_new_kinds(self):
        for kind in ("decommissioned", "reactivated"):
            with self.subTest(kind=kind):
                self.assertIn(kind, HIST)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/test_device_decommission_ui.py -q`
Expected: FAIL on missing ids.

- [ ] **Step 3: Template**

After the «Non misurabile» status tab (the `data-inv-status="unknown"` button):

```html
          <button type="button" class="inv-tab" data-inv-status="decommissioned" aria-pressed="false"><i class="fa-solid fa-box-archive" aria-hidden="true"></i><span data-i18n="invTabDecommissioned">Dismessi</span><span class="inv-tab-count" id="invKpiDecommissioned">&mdash;</span></button>
```

In `#invSelectionBar`, after `btnSelCommands`:

```html
          <button type="button" class="btn btn-secondary btn-small" id="btnSelDecommission" data-i18n="invSelDecommission"><i class="fa-solid fa-box-archive"></i> Dismetti</button>
          <button type="button" class="btn btn-secondary btn-small" id="btnSelReactivate" data-i18n="invSelReactivate" hidden><i class="fa-solid fa-rotate-left"></i> Riattiva</button>
          <button type="button" class="btn btn-secondary btn-small" id="btnSelDelete" data-i18n="invSelDelete"><i class="fa-solid fa-trash"></i> Elimina</button>
```

Before `<div class="modal-overlay" id="clsModelsModal">`:

```html
  <div class="modal-overlay" id="invBulkModal">
    <div class="modal" style="width: 560px; max-width: 96%;">
      <div class="modal-header">
        <h3 id="invBulkTitle"></h3>
        <i class="fa-solid fa-xmark modal-close" id="btnCloseInvBulk"></i>
      </div>
      <p id="invBulkText"></p>
      <ul id="invBulkList" class="inv-bulk-list"></ul>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" id="btnInvBulkCancel" data-i18n="btnCancel">Annulla</button>
        <button type="button" class="btn btn-primary" id="btnInvBulkConfirm"></button>
      </div>
    </div>
  </div>
```

- [ ] **Step 4: Selection keyed by tenant + IP (`static/js/devices.js`)**

Replace `const selectedDeviceIps = new Set();` and the first lines of `syncInventorySelection` (up to and including the `invSelectionCount` line) with:

```js
    // Keyed by tenant + IP: two tenants may own the same address, and the
    // lifecycle actions (decommission, reactivate, delete) act on one of them.
    const selectedDevices = new Set();
    const selKey = d => JSON.stringify([d.Group || 'Generale', d.IP]);
    const selectedIps = () => [...new Set([...selectedDevices].map(k => JSON.parse(k)[1]))];
    const selectedPairs = () => [...selectedDevices].map(k => {
        const [tenant, ip] = JSON.parse(k);
        return { tenant, ip };
    });
    let _decomCache = null;  // GET /api/devices/decommissioned; null = not loaded yet

    async function loadDecommissioned() {
        const res = await apiFetch('/api/devices/decommissioned');
        _decomCache = (res && res.ok) ? (await res.json()).devices : [];
    }

    function syncInventorySelection() {
        const decom = invStatusFilter === 'decommissioned';
        const pool = decom ? (_decomCache || []) : (globalDevices || []);
        const known = new Set(pool.map(selKey));
        selectedDevices.forEach(k => { if (!known.has(k)) selectedDevices.delete(k); });
        ['btnSelTriage', 'btnSelPing', 'btnSelCommands', 'btnSelDecommission'].forEach(id => {
            const b = document.getElementById(id);
            if (b) b.hidden = decom;
        });
        const re = document.getElementById('btnSelReactivate');
        if (re) re.hidden = !decom;
        const bar = document.getElementById('invSelectionBar');
        if (bar) bar.hidden = selectedDevices.size === 0;
        const count = document.getElementById('invSelectionCount');
        if (count) count.textContent = tr('invSelectedCount', { n: selectedDevices.size });
```

(the `invSelectAll` part that follows stays as is).

- [ ] **Step 5: Rows (`renderDeviceTable`)**

After the `_probesCache` line at the top of `renderDeviceTable`, add:

```js
        if (_decomCache === null) loadDecommissioned().then(renderDeviceTable);
        const decomCount = document.getElementById('invKpiDecommissioned');
        if (decomCount) decomCount.textContent = _decomCache ? String(_decomCache.length) : '—';
```

Right after `devBody.innerHTML = '';`, add:

```js
        if (invStatusFilter === 'decommissioned') {
            renderDecommissionedRows(devBody, selectedGroup, term, isViewer);
            syncInventorySelection();
            return;
        }
```

In the active-row template, replace `const selected = selectedDeviceIps.has(d.IP);` with `const selected = selectedDevices.has(selKey(d));`, and in the checkbox replace `data-ip="${ipAttr}"` with `data-ip="${ipAttr}" data-key="${escapeHtml(selKey(d))}"`.

Add above `renderDeviceTable`:

```js
    // Decommissioned rows: no live status, no row actions, only what the
    // lifecycle bar needs (selection) and who parked the device and when.
    function renderDecommissionedRows(devBody, selectedGroup, term, isViewer) {
        (_decomCache || []).forEach(d => {
            if (selectedGroup !== 'all' && d.Group !== selectedGroup) return;
            if (term && ![d.IP, d.Hostname, d.Vendor, d.Group, d.Probe, d['Decommissioned By']]
                .some(x => (x || '').toString().toLowerCase().includes(term))) return;
            const key = selKey(d);
            const selected = selectedDevices.has(key);
            const when = d.Decommissioned ? new Date(d.Decommissioned).toLocaleDateString() : '—';
            const by = tr('invDecomBy', { date: when, user: d['Decommissioned By'] || '—' });
            devBody.insertAdjacentHTML('beforeend', `<tr class="inv-decommissioned${selected ? ' is-selected' : ''}">
                ${isViewer ? '' : `<td class="inv-check"><input type="checkbox" data-action="select-device" data-key="${escapeHtml(key)}"
                    ${selected ? 'checked' : ''} aria-label="${escapeHtml(tr('ariaSelectDevice', { ip: d.IP }))}"></td>`}
                <td><span class="status" title="${escapeHtml(by)}">${escapeHtml(tr('invDecomStatus'))}</span></td>
                <td><div class="inv-host">
                    <span class="inv-host-name">${d.Hostname ? escapeHtml(d.Hostname) : '<span class="inv-muted">—</span>'}</span>
                    <span class="inv-host-where">${escapeHtml(orgLabel(d.Group))} · ${escapeHtml(d.Probe || 'central')}</span>
                </div></td>
                <td><strong>${escapeHtml(d.IP)}</strong></td>
                <td>${escapeHtml((d.Vendor || '').toUpperCase())}</td>
                <td><span class="inv-muted">${escapeHtml(by)}</span></td>
                <td><span class="inv-muted">—</span></td>
            </tr>`);
        });
        if (!devBody.children.length) {
            devBody.innerHTML = `<tr><td colspan="${isViewer ? 6 : 7}" class="inv-muted" style="text-align:center; padding:32px;">${escapeHtml(tr('invDecomEmpty'))}</td></tr>`;
        }
    }
```

- [ ] **Step 6: Handlers and lifecycle modal**

In the `.inv-tabs` click handler, replace `invStatusFilter = tab.dataset.invStatus;` with:

```js
        const wasDecom = invStatusFilter === 'decommissioned';
        invStatusFilter = tab.dataset.invStatus;
        // Active and decommissioned rows take different actions: never mix them.
        if (wasDecom !== (invStatusFilter === 'decommissioned')) selectedDevices.clear();
```

In the two selection handlers (`deviceTableBody` change and `invSelectAll` change) replace every `selectedDeviceIps.add(box.dataset.ip)` / `selectedDeviceIps.delete(box.dataset.ip)` with `selectedDevices.add(box.dataset.key)` / `selectedDevices.delete(box.dataset.key)`.

Replace the four bar bindings (`btnSelTriage` … `btnSelClear`) with:

```js
    document.getElementById('btnSelTriage')?.addEventListener('click', () => startGroupTriage('all', selectedIps()));
    document.getElementById('btnSelPing')?.addEventListener('click', () => runPingCheck(selectedIps()));
    document.getElementById('btnSelCommands')?.addEventListener('click', () => openBulkCommandModal(selectedIps()));
    document.getElementById('btnSelDecommission')?.addEventListener('click', () => openLifecycleModal('decommission'));
    document.getElementById('btnSelReactivate')?.addEventListener('click', () => openLifecycleModal('reactivate'));
    document.getElementById('btnSelDelete')?.addEventListener('click', () => openLifecycleModal('delete'));
    document.getElementById('btnInvBulkConfirm')?.addEventListener('click', runLifecycleAction);
    document.getElementById('btnInvBulkCancel')?.addEventListener('click', () => closeModal('invBulkModal'));
    document.getElementById('btnCloseInvBulk')?.addEventListener('click', () => closeModal('invBulkModal'));
    document.getElementById('btnSelClear')?.addEventListener('click', () => {
        selectedDevices.clear();
        renderDeviceTable();
    });
```

Add near `deleteDevice`:

```js
    const LIFECYCLE = {
        decommission: { title: 'invBulkDecomTitle', text: 'invBulkDecomText', confirm: 'invBulkDecomConfirm' },
        reactivate: { title: 'invBulkReactTitle', text: 'invBulkReactText', confirm: 'invBulkReactConfirm' },
        delete: { title: 'invBulkDelTitle', text: 'invBulkDelText', confirm: 'invBulkDelConfirm' },
    };
    let _lifecycleAction = null;
    const _el = id => /** @type {HTMLElement} */ (document.getElementById(id));

    function openLifecycleModal(action) {
        if (!selectedDevices.size) return;
        _lifecycleAction = action;
        const m = LIFECYCLE[action];
        const pool = invStatusFilter === 'decommissioned' ? (_decomCache || []) : globalDevices;
        const byKey = new Map(pool.map(d => [selKey(d), d]));
        _el('invBulkTitle').textContent = tr(m.title, { n: selectedDevices.size });
        _el('invBulkText').textContent = tr(m.text);
        _el('invBulkList').innerHTML = [...selectedDevices].map(k => {
            const [tenant, ip] = JSON.parse(k);
            const d = byKey.get(k) || {};
            return `<li><b>${escapeHtml(d.Hostname || ip)}</b> <span class="inv-muted">${escapeHtml(ip)} · ${escapeHtml(orgLabel(tenant))}</span></li>`;
        }).join('');
        const btn = _el('btnInvBulkConfirm');
        btn.textContent = tr(m.confirm);
        btn.classList.toggle('btn-danger', action === 'delete');
        btn.classList.toggle('btn-primary', action !== 'delete');
        openModal('invBulkModal');
    }

    async function runLifecycleAction() {
        const action = _lifecycleAction;
        const btn = /** @type {HTMLButtonElement} */ (_el('btnInvBulkConfirm'));
        btn.disabled = true;
        try {
            const res = await apiFetch(`/api/devices/${action}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ devices: selectedPairs() }),
            });
            const data = res ? await res.json().catch(() => ({})) : {};
            if (!res || !res.ok) {
                showToast(typeof data.detail === 'string' ? data.detail : tr('invBulkFailed'), 'error');
                return;
            }
            closeModal('invBulkModal');
            showToast(tr('invBulkDone', { n: data.count }));
            selectedDevices.clear();
            _decomCache = null;
            await refreshInventory();
            renderDeviceTable();
        } finally {
            btn.disabled = false;
        }
    }
```

- [ ] **Step 7: Device history (`static/js/device-history.js`)**

Above `dhFiltered`, add:

```js
// Decommission and reactivation are their own events, but they count with
// the removals and additions they mirror in the kind filter and the net total.
const DH_BUCKET = { decommissioned: 'removed', reactivated: 'added' };
const dhBucket = e => DH_BUCKET[e.event] || e.event;
```

In `dhServiceDays`, change `e.event === 'added'` to `(e.event === 'added' || e.event === 'reactivated')`.

Replace `dhVerb`'s two maps with:

```js
        ? { added: 'dhBatchAdded', removed: 'dhBatchRemoved', changed: 'dhBatchChanged',
            decommissioned: 'dhBatchDecommissioned', reactivated: 'dhBatchReactivated' }
        : { added: 'dhVerbAdded', removed: 'dhVerbRemoved', changed: 'dhVerbChanged',
            decommissioned: 'dhVerbDecommissioned', reactivated: 'dhVerbReactivated' };
```

In `dhSingle`, change `} else if (e.event === 'removed') {` to `} else if (dhBucket(e) === 'removed') {`, and `tr(e.event === 'removed' ? 'dhSnapLast' : 'dhSnapAt')` to `tr(dhBucket(e) === 'removed' ? 'dhSnapLast' : 'dhSnapAt')`.

In `renderDeviceHistory`, change `const count = k => inScope.filter(e => e.event === k).length;` to `const count = k => inScope.filter(e => dhBucket(e) === k).length;` and `inScope.filter(e => e.event === dhKind)` to `inScope.filter(e => dhBucket(e) === dhKind)`.

- [ ] **Step 8: i18n (`static/js/i18n.js`)**

In the **IT** dictionary, next to `invClearSelection`, add:

```js
        invTabDecommissioned: "Dismessi",
        invSelDecommission: '<i class="fa-solid fa-box-archive"></i> Dismetti',
        invSelReactivate: '<i class="fa-solid fa-rotate-left"></i> Riattiva',
        invSelDelete: '<i class="fa-solid fa-trash"></i> Elimina',
        invDecomStatus: "Dismesso",
        invDecomBy: "Dismesso il {date} da {user}",
        invDecomEmpty: "Nessun apparato dismesso.",
        invBulkDecomTitle: "Dismettere {n} apparati?",
        invBulkDecomText: "Escono da monitoraggio, triage, ping, backup e allarmi. Restano, credenziali comprese, nella scheda Dismessi e si possono riattivare.",
        invBulkDecomConfirm: "Dismetti",
        invBulkReactTitle: "Riattivare {n} apparati?",
        invBulkReactText: "Tornano in inventario esattamente com'erano e il monitoraggio riprende.",
        invBulkReactConfirm: "Riattiva",
        invBulkDelTitle: "Eliminare definitivamente {n} apparati?",
        invBulkDelText: "L'eliminazione non si può annullare: credenziali e impostazioni vanno perse. Lo Storico ne conserva la traccia.",
        invBulkDelConfirm: "Elimina",
        invBulkDone: "Fatto: {n} apparati.",
        invBulkFailed: "Operazione non riuscita.",
```

Next to `dhVerbRemoved`, change the two existing values and add four keys:

```js
        dhVerbRemoved: "eliminato da",
        dhBatchRemoved: "{n} apparati eliminati da",
        dhVerbDecommissioned: "dismesso da",
        dhBatchDecommissioned: "{n} apparati dismessi da",
        dhVerbReactivated: "riattivato in",
        dhBatchReactivated: "{n} apparati riattivati in",
```

and change `dhKindRemoved` to `"Rimossi"`.

In the **EN** dictionary, same keys:

```js
        invTabDecommissioned: "Decommissioned",
        invSelDecommission: '<i class="fa-solid fa-box-archive"></i> Decommission',
        invSelReactivate: '<i class="fa-solid fa-rotate-left"></i> Reactivate',
        invSelDelete: '<i class="fa-solid fa-trash"></i> Delete',
        invDecomStatus: "Decommissioned",
        invDecomBy: "Decommissioned on {date} by {user}",
        invDecomEmpty: "No decommissioned devices.",
        invBulkDecomTitle: "Decommission {n} devices?",
        invBulkDecomText: "They leave monitoring, triage, ping, backups and alerts. They stay, credentials included, in the Decommissioned tab and can be reactivated.",
        invBulkDecomConfirm: "Decommission",
        invBulkReactTitle: "Reactivate {n} devices?",
        invBulkReactText: "They return to the inventory exactly as they were, and monitoring resumes.",
        invBulkReactConfirm: "Reactivate",
        invBulkDelTitle: "Permanently delete {n} devices?",
        invBulkDelText: "Deletion cannot be undone: credentials and settings are lost. Device History keeps a record.",
        invBulkDelConfirm: "Delete",
        invBulkDone: "Done: {n} devices.",
        invBulkFailed: "The operation failed.",
```

```js
        dhVerbRemoved: "deleted from",
        dhBatchRemoved: "{n} devices deleted from",
        dhVerbDecommissioned: "decommissioned from",
        dhBatchDecommissioned: "{n} devices decommissioned from",
        dhVerbReactivated: "reactivated in",
        dhBatchReactivated: "{n} devices reactivated in",
```

and change `dhKindRemoved` to `"Removed"`.

- [ ] **Step 9: CSS (`static/css/dashboard.css`)**

Next to `.dh-node[data-ev="added"]`:

```css
.dh-node[data-ev="reactivated"] { background-color: var(--text); }
```

Near the `.inv-tab` rules:

```css
.inv-decommissioned td { opacity: .6; }
.inv-bulk-list { max-height: 260px; overflow: auto; margin: 8px 0 0; padding-left: 18px; }
```

- [ ] **Step 10: Run checks**

```bash
uv run pytest tests/test_device_decommission_ui.py -q
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4 -q
```

Expected: all clean / green.

- [ ] **Step 11: See it work**

Start a throwaway instance (`scripts/dev/capture_screenshots.py` shows how: empty data dir, port 8931) or use the `run` skill. Add two devices, select both, «Dismetti» → they appear under «Dismessi» with date and user; select one, «Riattiva» → back in «Tutti»; select the other, «Elimina» → gone. Open Storico: the events read «dismesso da», «riattivato in», «eliminato da».

- [ ] **Step 12: Gate and commit**

```bash
uv run python scripts/check_no_private_data.py
git add templates/dashboard.html static/js/devices.js static/js/device-history.js static/js/i18n.js static/css/dashboard.css tests/test_device_decommission_ui.py
git commit -m "feat(inventory): decommissioned tab, bulk lifecycle actions and history events"
```

---

### Task 4: Docs, graph, build

**Model:** the session's own model.

**Files:**
- Modify: `docs/operations.md`

- [ ] **Step 1: Document it**

Add to `docs/operations.md`, in the section about the inventory (or at the end if there is none):

```markdown
### Decommissioning and bulk delete

Tick devices in the inventory and use the selection bar:

- **Decommission** moves them to the *Decommissioned* tab. They leave
  polling, triage, ping, backups, alerts, probe-agent sync and the AI tools,
  and keep their credentials. They are stored in
  `decommissioned_hosts.csv` next to `network_hosts.csv`.
- **Reactivate** (in the *Decommissioned* tab) puts them back unchanged.
- **Delete** removes them permanently, active or decommissioned.

A decommissioned IP cannot be added again to the same tenant (by hand, CSV
import, promotion or move) until it is reactivated or deleted. Every action
is in the audit log and in Device History.
```

- [ ] **Step 2: Full gate, graph, commit**

```bash
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run pytest tests -n 4
uv run python scripts/check_no_private_data.py
graphify update .
git add docs/operations.md
git commit -m "docs(inventory): decommissioning and bulk delete"
```

- [ ] **Step 3: Screenshots and exe**

```bash
uv run python scripts/dev/capture_screenshots.py
uv run pyinstaller SentinelNet.spec --noconfirm
```

Commit `docs/images/*` only if they changed visibly (the inventory tab bar did).
