# Classification Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Discovered Devices & Classification the same server-side export machinery as Network Device Inventory, plus a serial column and a neighbour-device column.

**Architecture:** The classification tab endpoint already assembles the rows we want; its node loop is extracted into a shared assembler that the tab and a new export both call. Neighbour data comes free from the network map's links. Serial comes from scan data for inventoried devices, and from a small JSON store that the WLC tab fills for access points — so no export ever opens an SSH session.

**Tech Stack:** FastAPI, Python 3.14, `unittest`, vanilla classic scripts (no bundler), `uv` for everything.

**Spec:** `docs/superpowers/specs/2026-08-23-classification-export-design.md`

## Global Constraints

- **Version:** single source of truth is `core/version.py`, currently `0.11.2`; `pyproject.toml` must match. MINOR bump → `0.12.0`. Bump once, at the end.
- **No CI.** Gates are local: `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py`, `uv run python -m unittest discover -s tests`, then `graphify update .`.
- **Tests must be `unittest.TestCase` classes.** Bare `test_*` functions are NOT collected by `unittest discover` — `tests/test_switch_provisioner.py` is the existing example of that trap.
- **No real customer data in tracked files.** `data/` is gitignored and this repo is public. Use RFC 5737 (`192.0.2.x`, `198.51.100.x`), `switch-01`, `ACME`, `<hostname>`, invented serials.
- **New comments in English.** Existing Italian comments stay; do not translate them.
- **i18n:** every user-visible string needs a key in BOTH the `it` and `en` blocks of `static/js/i18n.js`, or `tests/test_i18n_parity.py` fails.
- **Never regenerate** `tests_data/openapi_golden.json` or `openapi_pre_destructure.json`. New paths go in `ALLOWED_NEW_PREFIXES` in `tests/test_router_parity.py`.
- **No inline handlers.** `templates/dashboard.html` has zero `onclick=`. Use an id or `data-action` plus a delegated listener.
- **Do not change the response shape of `/api/device-classification`.** The frontend and the OpenAPI golden both depend on it.
- Commit after every task.

---

### Task 1: AP inventory store

A small keyed store the WLC tab writes and the export reads. Built first because Task 4's serial column consumes it.

**Files:**
- Create: `services/ap_store.py`
- Test: `tests/test_ap_store.py` (create)

**Interfaces:**
- Consumes: `core.data_config.get_path` (the helper `inventory_manager` uses for `network_hosts.csv`).
- Produces:
  - `record_aps(wlc_ip: str, tenant: str, aps: list) -> int` — number of entries written. Each `ap` is a dict with at least `name`; `serial` and `model` optional.
  - `lookup(ap_name: str) -> dict | None` — `{"serial", "model", "wlc_ip", "tenant", "seen_at"}` or `None`.
  - `normalize_ap_name(name: str) -> str` — lowercase, stripped, FQDN suffix dropped.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""AP serials live in a small store, not in an SSH call during an export.

CDP announces an access point but carries no serial. The controller has it,
so the WLC tab writes it down when it visits; the export only ever reads.
"""
import os
import tempfile
import unittest
from unittest import mock


class ApStoreRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch("core.data_config.get_path",
                             side_effect=lambda name: os.path.join(self._tmp.name, name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_recorded_aps_can_be_looked_up(self):
        from services import ap_store
        written = ap_store.record_aps("192.0.2.10", "ACME", [
            {"name": "ap-lobby", "serial": "FCW0000AAAA", "model": "AIR-EXAMPLE"},
            {"name": "ap-floor2", "serial": "FCW0000BBBB", "model": "AIR-EXAMPLE"},
        ])
        self.assertEqual(2, written)
        entry = ap_store.lookup("ap-lobby")
        self.assertEqual("FCW0000AAAA", entry["serial"])
        self.assertEqual("192.0.2.10", entry["wlc_ip"])
        self.assertEqual("ACME", entry["tenant"])
        self.assertTrue(entry["seen_at"])

    def test_an_unknown_ap_is_none_not_an_empty_dict(self):
        from services import ap_store
        self.assertIsNone(ap_store.lookup("ap-nowhere"))

    def test_a_second_visit_replaces_that_controller_s_entries(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000AAAA"}])
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000CCCC"}])
        self.assertEqual("FCW0000CCCC", ap_store.lookup("ap-lobby")["serial"])

    def test_another_controller_s_entries_survive(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000AAAA"}])
        ap_store.record_aps("198.51.100.10", "BETA",
                            [{"name": "ap-remote", "serial": "FCW0000DDDD"}])
        self.assertEqual("FCW0000AAAA", ap_store.lookup("ap-lobby")["serial"])
        self.assertEqual("FCW0000DDDD", ap_store.lookup("ap-remote")["serial"])

    def test_an_ap_with_no_serial_is_not_recorded(self):
        """A summary row with no inventory match must not create an entry that
        claims to know a serial it does not have."""
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME", [{"name": "ap-lobby"}])
        self.assertIsNone(ap_store.lookup("ap-lobby"))


class ApNameMatching(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch("core.data_config.get_path",
                             side_effect=lambda name: os.path.join(self._tmp.name, name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cdp_announces_an_fqdn_the_controller_names_short(self):
        from services import ap_store
        ap_store.record_aps("192.0.2.10", "ACME",
                            [{"name": "ap-lobby", "serial": "FCW0000AAAA"}])
        self.assertIsNotNone(ap_store.lookup("AP-Lobby.example.local"))

    def test_normalize_is_idempotent(self):
        from services import ap_store
        once = ap_store.normalize_ap_name("AP-Lobby.example.local")
        self.assertEqual(once, ap_store.normalize_ap_name(once))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_ap_store -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'services.ap_store'`.

**Note on the mock target:** confirm how `services/inventory_manager.py` resolves `data_config.get_path` before writing the implementation (it keeps module-level defaults plus a getter that re-reads the path). Mirror whatever that file does, and correct the patch target above if `ap_store` ends up reading the path differently. Do not guess.

- [ ] **Step 3: Write the implementation**

```python
# -*- coding: utf-8 -*-
"""Last-known AP inventory, written by the WLC tab and read by the export.

CDP/LLDP makes an access point visible but advertises no serial number; only
the controller knows it. Querying every controller during an export would put
SSH back inside a request, so the WLC tab writes what it saw and the export
only ever reads this file.
"""
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

from core import data_config

_lock = threading.Lock()


def _path() -> str:
    return data_config.get_path("ap_inventory.json")


def normalize_ap_name(name: str) -> str:
    """Match key for an AP name.

    CDP announces the access point with whatever hostname it carries, which may
    be an FQDN in a different case from the controller's short AP name.
    """
    return (name or "").strip().lower().split(".")[0]


def _read() -> dict:
    try:
        with open(_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record_aps(wlc_ip: str, tenant: str, aps: list) -> int:
    """Store the serials this controller just reported.

    Entries of OTHER controllers are left alone: two controllers own different
    access points, and a visit to one must not erase what the other reported.
    An AP with no serial is skipped rather than stored empty -- an entry here
    is a claim to know the serial.
    """
    seen_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock:
        store = {k: v for k, v in _read().items()
                 if (v or {}).get("wlc_ip") != wlc_ip}
        written = 0
        for ap in aps or []:
            serial = (ap.get("serial") or "").strip()
            name = normalize_ap_name(ap.get("name", ""))
            if not name or not serial:
                continue
            store[name] = {"serial": serial, "model": (ap.get("model") or "").strip(),
                           "wlc_ip": wlc_ip, "tenant": tenant, "seen_at": seen_at}
            written += 1
        tmp = _path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
        os.replace(tmp, _path())
    return written


def lookup(ap_name: str) -> Optional[dict]:
    return _read().get(normalize_ap_name(ap_name))
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `uv run python -m unittest tests.test_ap_store -v`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add services/ap_store.py tests/test_ap_store.py
git commit -m "feat(wlc): store last-known AP serials so the export never needs SSH"
```

---

### Task 2: Bulk AP inventory command, wired into the WLC overview

**Files:**
- Modify: `services/wlc_service.py` — `COMMANDS` (around line 38), a new parser near `parse_ap_autorf`, and `overview()` (around line 317)
- Test: `tests/test_wlc_ap_inventory.py` (create)

**Interfaces:**
- Consumes: `services.ap_store.record_aps` from Task 1.
- Produces: `parse_ap_inventory(text: str) -> dict` — `{ap_name: serial}`.

**Verify before implementing:** the exact bulk command per platform. AireOS is `show ap inventory all`. Whether IOS-XE has a bulk form is NOT established — check it against a real controller or vendor documentation. If it has none, leave `COMMANDS["ap_inventory"]["iosxe"]` out and let the serial column stay empty on that platform. **Do not add a per-AP loop** — that is the fan-out this design exists to avoid.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""AP serial comes from one bulk inventory command, never one per AP.

'show ap summary' carries no serial on either platform. The inventory command
does, and it returns every AP in a single round-trip.
"""
import unittest

# Shape of 'show ap inventory all' on AireOS. Invented names and serials.
INVENTORY_OUTPUT = """
AP Name : ap-lobby
NAME: "ap-lobby" , DESCR: "Example Access Point"
PID: AIR-EXAMPLE-K9,  VID: V01,  SN: FCW0000AAAA

AP Name : ap-floor2
NAME: "ap-floor2" , DESCR: "Example Access Point"
PID: AIR-EXAMPLE-K9,  VID: V01,  SN: FCW0000BBBB
"""


class ParseApInventory(unittest.TestCase):
    def test_every_ap_maps_to_its_serial(self):
        from services import wlc_service
        self.assertEqual({"ap-lobby": "FCW0000AAAA", "ap-floor2": "FCW0000BBBB"},
                         wlc_service.parse_ap_inventory(INVENTORY_OUTPUT))

    def test_empty_output_is_an_empty_map_not_an_error(self):
        from services import wlc_service
        self.assertEqual({}, wlc_service.parse_ap_inventory(""))

    def test_output_without_serials_yields_nothing(self):
        from services import wlc_service
        self.assertEqual({}, wlc_service.parse_ap_inventory("AP Name : ap-lobby\n"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_wlc_ap_inventory -v`
Expected: FAIL — `AttributeError: module 'services.wlc_service' has no attribute 'parse_ap_inventory'`.

- [ ] **Step 3: Add the command and the parser**

In `COMMANDS`, beside `ap_summary`:

```python
    "ap_inventory": {
        "aireos": "show ap inventory all",
    },
```

Add the parser near `parse_ap_autorf`:

```python
def parse_ap_inventory(text: str) -> dict:
    """{ap name: serial} from the bulk AP inventory output.

    'show ap summary' prints no serial on either platform, and asking per AP
    would be one SSH round-trip each. Entries without an SN are skipped: a
    missing serial must read as unknown, not as an empty string.
    """
    out, current = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"\s*AP Name\s*:\s*(\S+)", line, re.IGNORECASE)
        if m:
            current = m.group(1).strip()
            continue
        m = re.search(r"\bSN\s*:\s*(\S+)", line, re.IGNORECASE)
        if m and current:
            out[current] = m.group(1).strip()
            current = None
    return out
```

- [ ] **Step 4: Run the parser tests and make sure they pass**

Run: `uv run python -m unittest tests.test_wlc_ap_inventory -v`
Expected: PASS, 3 tests.

- [ ] **Step 5: Wire it into `overview()`, best-effort**

Inside the `_session` block of `overview()`, after `aps = _table_rows(raw["ap_summary"], _AP_FIELDS)`, join the serials in. Match the surrounding style: every command in this function is already wrapped so a read-only account that cannot run one still gets the rest of the tab.

```python
        # Best-effort like every other command here: a controller that will not
        # answer costs the serial column, not the tab.
        cmd = COMMANDS["ap_inventory"].get(platform)
        if cmd:
            try:
                serials = parse_ap_inventory(_send(conn, cmd))
            except Exception:
                serials = {}
            for ap in aps:
                serial = serials.get(ap.get("name", ""))
                if serial:
                    ap["serial"] = serial
```

After the `with _session(...)` block closes, record what was seen:

```python
    from services import ap_store
    ap_store.record_aps(device["IP"], device.get("Group", "Generale"), aps)
```

- [ ] **Step 6: Write the wiring test**

Append to `tests/test_wlc_ap_inventory.py`:

```python
class OverviewRecordsSerials(unittest.TestCase):
    """The tab visit is what fills the store, so the export never needs SSH."""

    def test_a_failing_inventory_command_still_returns_the_other_aps(self):
        from unittest import mock
        from services import wlc_service

        def fake_send(conn, command, timeout=30):
            if "inventory" in command:
                raise RuntimeError("read-only account")
            if "ap summary" in command:
                return ("AP Name          IP Address     AP Model     Status\n"
                        "---------------  -------------  -----------  --------\n"
                        "ap-lobby         192.0.2.50     AIR-EXAMPLE  Registered\n")
            return ""

        with mock.patch.object(wlc_service, "_send", fake_send), \
             mock.patch.object(wlc_service, "_session") as sess, \
             mock.patch("services.ap_store.record_aps", return_value=0) as rec:
            sess.return_value.__enter__ = lambda s: (object(), "aireos", "")
            sess.return_value.__exit__ = lambda s, *a: False
            result = wlc_service.overview({"IP": "192.0.2.10", "Group": "ACME"})

        self.assertEqual(1, len(result["aps"]))
        self.assertNotIn("serial", result["aps"][0])
        rec.assert_called_once()
```

The `_session` context-manager mock above is a guess at the shape `overview()` needs — read `_session` before writing it and adjust so the mock yields `(conn, platform, sysinfo)` the way the real one does.

- [ ] **Step 7: Run the module, then the full suite**

Run: `uv run python -m unittest tests.test_wlc_ap_inventory -v`, then
`uv run python -m unittest discover -s tests`.
If an existing WLC test fails, read it before changing it and report what you changed and why.

- [ ] **Step 8: Commit**

```bash
git add services/wlc_service.py tests/test_wlc_ap_inventory.py
git commit -m "feat(wlc): pull AP serials with one bulk inventory command"
```

---

### Task 3: Extract the classification assembler

Pure refactor: no behaviour change, no response-shape change. Kept separate so Task 4's reviewer sees only new code.

**Files:**
- Modify: `routers/catalog.py` — `device_classification` (lines 146-202)
- Test: `tests/test_classification_assembler.py` (create)

**Interfaces:**
- Consumes: `core.core_engine.generate_network_map`, `routers.deps.filter_map_to_scope`, `services.inventory_manager.get_device_categories`.
- Produces: `assemble_classification(scope) -> dict` with keys `nodes`, `links`, `categories`, `counts_by_category`, `counts_by_group`, `vendors`, `models`, `total`. `scope` is `None` for an admin, else a set of allowed group names.

**Critical:** `/api/device-classification` must keep returning exactly the keys it returns today — `links` is new in the helper and must be dropped by the tab endpoint. Adding it to the response would change the OpenAPI golden.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""The tab and the export read the same assembler, so they cannot drift."""
import unittest
from unittest import mock

MAP = {
    "nodes": [
        {"id": "192.0.2.1", "label": "switch-01", "group": "ACME",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
        {"id": "discovered_ap-lobby", "label": "ap-lobby", "group": "ACME",
         "status": "discovered", "device_type": "ap", "reported_ip": "192.0.2.50"},
    ],
    "links": [
        {"source": "192.0.2.1", "target": "discovered_ap-lobby",
         "local_port": "Gi1/0/1", "remote_port": "Gi0"},
    ],
}
CATS = {"categories": {}, "assignments": {}}


class AssembleClassification(unittest.TestCase):
    def _assemble(self, scope=None):
        from routers import catalog
        with mock.patch("core.core_engine.generate_network_map", return_value=MAP), \
             mock.patch("services.inventory_manager.get_device_categories", return_value=CATS), \
             mock.patch("services.inventory_manager.get_all_vendors", return_value={}), \
             mock.patch("services.inventory_manager.get_models", return_value={}):
            return catalog.assemble_classification(scope)

    def test_it_returns_the_links_the_tab_endpoint_drops(self):
        self.assertEqual(1, len(self._assemble()["links"]))

    def test_a_discovered_node_reports_its_announced_ip(self):
        ap = next(n for n in self._assemble()["nodes"] if n["id"] == "discovered_ap-lobby")
        self.assertEqual("192.0.2.50", ap["display_ip"])
        self.assertTrue(ap["discovered"])

    def test_an_inventoried_node_reports_its_own_ip(self):
        sw = next(n for n in self._assemble()["nodes"] if n["id"] == "192.0.2.1")
        self.assertEqual("192.0.2.1", sw["display_ip"])
        self.assertFalse(sw["discovered"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_classification_assembler -v`
Expected: FAIL — `AttributeError: module 'routers.catalog' has no attribute 'assemble_classification'`.

- [ ] **Step 3: Extract**

Move the body of `device_classification` — from `data = core_engine.generate_network_map(...)` through the counts loop — into a module-level `assemble_classification(scope)` returning the dict above, including `"links": data.get("links", [])`. Reduce the route to:

```python
@router.get("/api/device-classification")
def device_classification(current_user = Depends(get_current_user)):
    """Elenco completo dei dispositivi (inventariati + scoperti via CDP/LLDP) con
    categoria, sede e conteggi per categoria. Usato dal pannello Dispositivi."""
    data = assemble_classification(user_group_scope(current_user))
    # `links` serve solo all'export: aggiungerlo qui cambierebbe la forma della
    # risposta su cui poggiano il frontend e lo snapshot OpenAPI.
    return {k: v for k, v in data.items() if k != "links"}
```

- [ ] **Step 4: Run the new module, then the full suite**

Run: `uv run python -m unittest tests.test_classification_assembler -v`, then
`uv run python -m unittest discover -s tests`.
`tests/test_router_parity.py` must stay green with no allow-list edit — if it does not, the response shape changed and the extraction is wrong.

- [ ] **Step 5: Commit**

```bash
git add routers/catalog.py tests/test_classification_assembler.py
git commit -m "refactor(catalog): extract assemble_classification so the export can share it"
```

---

### Task 4: Column registry and the export endpoints

**Files:**
- Create: `core/csv_safe.py`
- Modify: `routers/inventory.py` — remove `_CSV_FORMULA_LEADERS` / `_csv_cell` (lines 134-141), import from the new module
- Modify: `routers/catalog.py` — registry and two routes
- Modify: `tests/test_router_parity.py` — `ALLOWED_NEW_PREFIXES` (line 72)
- Test: `tests/test_classification_export.py` (create)

**Interfaces:**
- Consumes: `assemble_classification` (Task 3), `services.ap_store.lookup` (Task 1), `core.csv_safe.csv_cell`.
- Produces:
  - `GET /api/export/classification/columns` → `{"columns": [{"key", "header", "per_neighbour"}], "default": [...]}`
  - `GET /api/export/classification?columns=a,b&groups=X&categories=Y` → `text/csv`

`csv_cell` moves rather than being copied: it neutralises spreadsheet formula injection, and a second copy is a second thing to forget to fix.

**Neighbour direction rule — get this right, it is the whole point of the column.** A link records `source`/`target` plus `local_port` (the source's port) and `remote_port` (the target's port). For the row's node:

- node is the link's `target` → neighbour is `source`, neighbour port is `local_port`
- node is the link's `source` → neighbour is `target`, neighbour port is `remote_port`

Either way the port reported is **the neighbour's own port** — the one you patch, not the one on the device whose row this is. Neighbour device is the neighbour's `label`, never its id.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""The classification export: the inventory export's machinery, plus serial
and neighbour."""
import csv
import io
import unittest
from unittest import mock

MAP = {
    "nodes": [
        {"id": "192.0.2.1", "label": "switch-01", "group": "ACME",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
        {"id": "192.0.2.2", "label": "switch-02", "group": "BETA",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
        {"id": "discovered_ap-lobby", "label": "ap-lobby", "group": "ACME",
         "status": "discovered", "device_type": "ap", "reported_ip": "192.0.2.50"},
        {"id": "192.0.2.9", "label": "switch-lonely", "group": "ACME",
         "status": "online", "device_type": "switch", "vendor": "cisco"},
    ],
    "links": [
        {"source": "192.0.2.1", "target": "discovered_ap-lobby",
         "local_port": "Gi1/0/1", "remote_port": "Gi0"},
        {"source": "192.0.2.1", "target": "192.0.2.2",
         "local_port": "Gi1/0/2", "remote_port": "Gi1/0/24"},
    ],
}
CATS = {"categories": {}, "assignments": {}}
VERSIONS = {"192.0.2.1": {"serial": "SW0000AAAA", "version": "1.0", "status": "online"}}
AP_ENTRY = {"serial": "FCW0000AAAA", "model": "AIR-EXAMPLE", "wlc_ip": "192.0.2.10",
            "tenant": "ACME", "seen_at": "2026-08-23T10:00:00+00:00"}


def _export(query="", user=None):
    from fastapi.testclient import TestClient
    import app_server
    from routers.deps import get_current_user

    app_server.app.dependency_overrides[get_current_user] = \
        lambda: user or {"sub": "tester", "role": "admin"}
    try:
        with mock.patch("core.core_engine.generate_network_map", return_value=MAP), \
             mock.patch("services.inventory_manager.get_device_categories", return_value=CATS), \
             mock.patch("services.inventory_manager.get_all_vendors", return_value={}), \
             mock.patch("services.inventory_manager.get_models", return_value={}), \
             mock.patch("services.inventory_manager.get_detected_versions", return_value=VERSIONS), \
             mock.patch("services.ap_store.lookup",
                        side_effect=lambda n: AP_ENTRY if "ap-lobby" in (n or "").lower() else None), \
             mock.patch("routers.catalog.log_audit"):
            client = TestClient(app_server.app)
            return client.get("/api/export/classification" + query,
                              headers={"X-Requested-With": "x"})
    finally:
        app_server.app.dependency_overrides.pop(get_current_user, None)


def _rows(res):
    return list(csv.reader(io.StringIO(res.text)))


class ColumnRegistry(unittest.TestCase):
    def test_defaults_are_a_subset_of_the_registry(self):
        from routers import catalog
        self.assertTrue(set(catalog._DEFAULT_CLASSIFICATION_COLUMNS)
                        <= set(catalog._CLASSIFICATION_COLUMNS))

    def test_every_column_renders_without_raising(self):
        from routers import catalog
        node = {"id": "192.0.2.1", "label": "switch-01", "group": "ACME",
                "status": "online", "device_type": "switch", "subcategory": "",
                "vendor": "cisco", "model": "", "version": "1.0",
                "display_ip": "192.0.2.1", "discovered": False,
                "serial": "SW0000AAAA", "serial_seen_at": ""}
        for _key, (_header, fn) in catalog._CLASSIFICATION_COLUMNS.items():
            fn(node, {})


class ExportRows(unittest.TestCase):
    def test_without_a_neighbour_column_each_device_is_one_row(self):
        rows = _rows(_export("?columns=hostname,ip"))
        self.assertEqual(["Hostname", "IP"], rows[0])
        self.assertEqual(4, len(rows) - 1)

    def test_a_neighbour_column_gives_one_row_per_link(self):
        body = _rows(_export("?columns=hostname,neighbour_device,neighbour_port"))[1:]
        by_host = {}
        for r in body:
            by_host.setdefault(r[0], []).append(r[1:])
        self.assertEqual(2, len(by_host["switch-01"]))

    def test_the_port_reported_is_the_neighbour_s_own_port(self):
        """The AP hangs off switch-01 Gi1/0/1 -- that is the port you patch."""
        rows = _rows(_export("?columns=hostname,neighbour_device,neighbour_port"))[1:]
        row = next(r for r in rows if r[0] == "ap-lobby")
        self.assertEqual(["switch-01", "Gi1/0/1"], row[1:])

    def test_a_device_with_no_links_still_exports_one_row(self):
        """Selecting a column must never shrink the device list."""
        rows = [r for r in _rows(_export("?columns=hostname,neighbour_device"))[1:]
                if r[0] == "switch-lonely"]
        self.assertEqual(1, len(rows))
        self.assertEqual("", rows[0][1])


class SerialResolution(unittest.TestCase):
    def test_an_inventoried_device_resolves_from_scan_data(self):
        rows = _rows(_export("?columns=hostname,serial"))[1:]
        self.assertEqual("SW0000AAAA", next(r for r in rows if r[0] == "switch-01")[1])

    def test_a_discovered_ap_resolves_from_the_ap_store(self):
        rows = _rows(_export("?columns=hostname,serial"))[1:]
        self.assertEqual("FCW0000AAAA", next(r for r in rows if r[0] == "ap-lobby")[1])

    def test_an_ap_no_controller_has_reported_exports_an_empty_serial(self):
        with mock.patch("services.ap_store.lookup", return_value=None):
            rows = _rows(_export("?columns=hostname,serial"))[1:]
        self.assertEqual("", next(r for r in rows if r[0] == "ap-lobby")[1])

    def test_the_seen_at_date_is_available_so_staleness_is_visible(self):
        rows = _rows(_export("?columns=hostname,serial_seen_at"))[1:]
        row = next(r for r in rows if r[0] == "ap-lobby")
        self.assertTrue(row[1].startswith("2026-08-23"))


class Scoping(unittest.TestCase):
    def test_a_scoped_user_never_sees_another_tenant(self):
        res = _export("?columns=hostname,tenant",
                      user={"sub": "acme-op", "role": "operator", "groups": ["ACME"]})
        self.assertEqual({"ACME"}, {r[1] for r in _rows(res)[1:]})

    def test_an_unknown_column_is_rejected(self):
        self.assertEqual(400, _export("?columns=hostname,not_a_column").status_code)


if __name__ == "__main__":
    unittest.main()
```

**Note on the scoped-user fixture:** `user_group_scope` reads the scope from a user record whose exact shape must be copied from `tests/test_rbac_scope.py`. Read that file and correct the `user=` dict above to match — do not guess the key name.

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_classification_export -v`
Expected: FAIL — 404 on the route, `AttributeError` on `_CLASSIFICATION_COLUMNS`.

- [ ] **Step 3: Move the CSV cell guard into `core/csv_safe.py`**

```python
# -*- coding: utf-8 -*-
"""Shared CSV cell guard.

Two exports write CSV. A spreadsheet executes a cell that begins with one of
these characters, so the guard belongs in one place: a second copy is a second
thing to forget to fix.
"""

FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value):
    """Neutralise a cell a spreadsheet would execute.

    The leading apostrophe is the standard neutralisation: the sheet shows the
    text instead of evaluating it.
    """
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in FORMULA_LEADERS else s
```

Copy `FORMULA_LEADERS`' exact members from the existing `_CSV_FORMULA_LEADERS` in `routers/inventory.py` rather than trusting the tuple above. In `routers/inventory.py`, delete both names and import instead:

```python
from core.csv_safe import csv_cell as _csv_cell
```

The local alias keeps the existing call site at line 258 unchanged.

- [ ] **Step 4: Add the registry and the routes to `routers/catalog.py`**

```python
_CLASSIFICATION_COLUMNS = {
    "hostname":         ("Hostname",         lambda n, l: n.get("label") or n["id"]),
    "ip":               ("IP",               lambda n, l: n.get("display_ip", "")),
    "tenant":           ("Tenant",           lambda n, l: n.get("group", "")),
    "category":         ("Category",         lambda n, l: n.get("device_type", "")),
    "subcategory":      ("Subcategory",      lambda n, l: n.get("subcategory", "")),
    "vendor":           ("Vendor",           lambda n, l: n.get("vendor", "")),
    "model":            ("Model",            lambda n, l: n.get("model", "")),
    "version":          ("Version",          lambda n, l: n.get("version") or ""),
    "status":           ("Status",           lambda n, l: n.get("status", "")),
    "discovered":       ("Discovered",       lambda n, l: "yes" if n.get("discovered") else "no"),
    "serial":           ("Serial",           lambda n, l: n.get("serial", "")),
    "serial_seen_at":   ("Serial Seen At",   lambda n, l: n.get("serial_seen_at", "")),
    "neighbour_device": ("Neighbour Device", lambda n, l: l.get("device", "")),
    "neighbour_port":   ("Neighbour Port",   lambda n, l: l.get("port", "")),
}

# Asking for one of these means asking for one row per neighbour: a device with
# redundant uplinks has more than one, and a joined cell cannot be filtered or
# looked up in a spreadsheet -- the same reason _MEMBER_COLUMNS explodes rows.
_NEIGHBOUR_COLUMNS = frozenset(("neighbour_device", "neighbour_port"))

_DEFAULT_CLASSIFICATION_COLUMNS = ["hostname", "ip", "tenant", "category", "status"]


def _neighbours_of(node_id: str, links: list, label_of: dict) -> list:
    """Neighbours of one node, each as {device, port}.

    The port reported is the NEIGHBOUR's own port -- the one you patch -- not
    the port on the device whose row this is. A link stores local_port for its
    source and remote_port for its target, so which one to read depends on
    which end this node sits at.
    """
    out = []
    for link in links:
        if link.get("target") == node_id:
            other, port = link.get("source"), link.get("local_port")
        elif link.get("source") == node_id:
            other, port = link.get("target"), link.get("remote_port")
        else:
            continue
        out.append({"device": label_of.get(other, other or ""), "port": port or ""})
    return out


@router.get("/api/export/classification/columns")
def export_classification_columns(current_user = Depends(get_current_user)):
    """Colonne disponibili e default: la UI non duplica il registro."""
    return {
        "columns": [
            {"key": k, "header": h, "per_neighbour": k in _NEIGHBOUR_COLUMNS}
            for k, (h, _) in _CLASSIFICATION_COLUMNS.items()
        ],
        "default": _DEFAULT_CLASSIFICATION_COLUMNS,
    }


@router.get("/api/export/classification")
def export_classification_csv(
    columns: str = "",
    groups: str = "",
    categories: str = "",
    current_user = Depends(get_current_user),
):
    import csv, io
    from fastapi.responses import Response as FastResponse
    from core.csv_safe import csv_cell
    from services import ap_store

    selected = [c.strip() for c in columns.split(",") if c.strip()] \
        or _DEFAULT_CLASSIFICATION_COLUMNS
    unknown = [c for c in selected if c not in _CLASSIFICATION_COLUMNS]
    if unknown:
        raise HTTPException(status_code=400,
                            detail=f"Colonne sconosciute: {', '.join(unknown)}")

    data = assemble_classification(user_group_scope(current_user))
    nodes, links = data["nodes"], data["links"]

    want_groups = {v.strip() for v in groups.split(",") if v.strip()}
    want_categories = {v.strip() for v in categories.split(",") if v.strip()}
    if want_groups:
        nodes = [n for n in nodes if n.get("group", "") in want_groups]
    if want_categories:
        nodes = [n for n in nodes if n.get("device_type", "") in want_categories]

    versions = inventory_manager.get_detected_versions()
    label_of = {n["id"]: (n.get("label") or n["id"]) for n in data["nodes"]}
    explode = any(c in _NEIGHBOUR_COLUMNS for c in selected)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([_CLASSIFICATION_COLUMNS[c][0] for c in selected])
    for node in nodes:
        # Serial has two sources and one of them is a cache: an inventoried
        # device carries it from the last scan, an access point only from
        # whatever controller last reported it.
        scan = versions.get(node["id"], {})
        entry = ap_store.lookup(node.get("label") or "") if node.get("discovered") else None
        row_node = dict(node)
        row_node["serial"] = scan.get("serial") or (entry or {}).get("serial", "")
        row_node["serial_seen_at"] = (entry or {}).get("seen_at", "")

        # A device with no links still gets its row: selecting a column must
        # never make devices disappear from the export.
        neighbours = _neighbours_of(node["id"], links, label_of) if explode else []
        for link in (neighbours or [{}]):
            writer.writerow([
                csv_cell(_CLASSIFICATION_COLUMNS[c][1](row_node, link))
                for c in selected
            ])

    log_audit(f"Export CSV classificazione richiesto dall'utente "
              f"'{current_user.get('sub')}' (colonne: {','.join(selected)}).")
    return FastResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition":
                 "attachment; filename=sentinelnet-classification.csv"},
    )
```

Confirm `log_audit`, `HTTPException`, `user_group_scope` and `inventory_manager` are already imported in `catalog.py`; add whichever are missing.

- [ ] **Step 5: Add the new paths to the parity allow-list**

In `tests/test_router_parity.py`, add `"/api/export/classification"` to `ALLOWED_NEW_PREFIXES` (line 72) — one prefix covers both routes — with a short comment saying it is the classification export shipped in 0.12.0. **Do not regenerate the golden.**

- [ ] **Step 6: Run the module, then the full gate**

Run: `uv run python -m unittest tests.test_classification_export -v`, then
`uv run pyrefly check` and `uv run python -m unittest discover -s tests`.

- [ ] **Step 7: Commit**

```bash
git add core/csv_safe.py routers/catalog.py routers/inventory.py \
        tests/test_classification_export.py tests/test_router_parity.py
git commit -m "feat(catalog): server-side classification export with serial and neighbour columns"
```

---

### Task 5: The column-picker modal in the classification tab

**Files:**
- Modify: `templates/dashboard.html` — a new modal beside `deviceExportModal` (line 3939), and the classification panel's export button
- Modify: `static/js/topology.js` — delete `exportCategoriesCsv` (line 2278) and its listener (line 2904), add the modal wiring
- Modify: `static/js/i18n.js` — both `it` and `en`
- Test: `tests/test_classification_export_ui.py` (create)

**Interfaces:**
- Consumes: `/api/export/classification/columns` and `/api/export/classification` from Task 4.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""The classification export UI is wired, and the old browser-side CSV is gone."""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class ClassificationExportUi(unittest.TestCase):
    def test_the_modal_exists_in_the_template(self):
        self.assertIn('id="classificationExportModal"', _read("templates/dashboard.html"))

    def test_the_button_binds_to_an_id_that_exists(self):
        self.assertIn('id="btnExportClassification"', _read("templates/dashboard.html"))
        self.assertIn("btnExportClassification", _read("static/js/topology.js"))

    def test_the_browser_side_csv_builder_is_gone(self):
        """Two exports for one table is how they drift apart."""
        self.assertNotIn("exportCategoriesCsv", _read("static/js/topology.js"))

    def test_no_inline_handlers_were_introduced(self):
        self.assertNotIn("onclick=", _read("templates/dashboard.html"))

    def test_both_languages_carry_every_new_key(self):
        js = _read("static/js/i18n.js")
        for key in ("titleClassificationExport", "descClassificationExport",
                    "btnExportClassification", "lblClsCategory"):
            self.assertEqual(2, len(re.findall(r"\b%s\s*:" % key, js)),
                             f"{key} must appear in both the it and en blocks")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_classification_export_ui -v`
Expected: FAIL on the modal, the button and the i18n keys.

- [ ] **Step 3: Add the modal to `templates/dashboard.html`**

Copy the structure of `deviceExportModal` (line 3939) and simplify — this export has two filters, not four.

```html
  <div class="modal-overlay" id="classificationExportModal">
    <div class="modal" style="width: 720px; max-width: 96%;">
      <div class="modal-header">
        <h3 data-i18n="titleClassificationExport"><i class="fa-solid fa-file-csv" style="color: var(--primary);"></i> Esporta classificazione CSV</h3>
        <i class="fa-solid fa-xmark modal-close" id="btnCloseClassificationExport"></i>
      </div>
      <p style="color: var(--text-muted); font-size: 13px; margin: 0 0 14px;" data-i18n="descClassificationExport">
        Nessuna casella spuntata in un filtro significa «tutti». Le colonne del vicino producono una riga per ogni collegamento.
      </p>
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px; align-items:start;">
        <div>
          <div style="font-size:12px; font-weight:700; margin-bottom:4px;" data-i18n="thGroup">Gruppo</div>
          <div id="clsFilterGroups" style="max-height:150px; overflow-y:auto; border:1px solid var(--border); background:var(--surface-2); padding:6px;"></div>
          <div style="font-size:12px; font-weight:700; margin:10px 0 4px;" data-i18n="lblClsCategory">Categoria</div>
          <div id="clsFilterCategories" style="max-height:150px; overflow-y:auto; border:1px solid var(--border); background:var(--surface-2); padding:6px;"></div>
        </div>
        <div>
          <div style="font-size:12px; font-weight:700; margin-bottom:4px;" data-i18n="lblExportColumns">Colonne</div>
          <div id="clsColumnList" style="max-height:310px; overflow-y:auto; border:1px solid var(--border); background:var(--surface-2); padding:6px;"></div>
        </div>
      </div>
      <div class="modal-footer" style="margin-top:16px;">
        <button class="btn btn-primary btn-small" id="btnRunClassificationExport" style="width:auto; margin:0;" data-i18n="btnExportClassification">Esporta CSV</button>
      </div>
    </div>
  </div>
```

Rename the existing classification export button's id from `btnExportCategoriesCsv` to `btnExportClassification`.

- [ ] **Step 4: Wire it in `static/js/topology.js`**

Delete `exportCategoriesCsv` (line 2278) and its listener (line 2904). Add:

```javascript
    // The column registry lives in the backend, like the inventory export: a
    // second copy here is what lets the two drift apart.
    const CLS_EXPORT_PREFS_KEY = 'sentinelnet.classificationExportPrefs';
    let clsExportColumns = [];

    function readClsPrefs() {
        try { return JSON.parse(localStorage.getItem(CLS_EXPORT_PREFS_KEY)) || {}; }
        catch (e) { return {}; }
    }

    function clsChecked(containerId) {
        return Array.from(document.querySelectorAll(`#${containerId} input:checked`))
            .map(el => el.value);
    }

    async function openClassificationExportModal() {
        if (!clsExportColumns.length) {
            const res = await apiFetch('/api/export/classification/columns');
            if (!res || !res.ok) { alert(i18n[currentLang].alertExportError); return; }
            const data = await res.json();
            clsExportColumns = data.columns;
            const seed = readClsPrefs();
            if (!seed.columns) {
                seed.columns = data.default;
                localStorage.setItem(CLS_EXPORT_PREFS_KEY, JSON.stringify(seed));
            }
        }
        const prefs = readClsPrefs();
        const nodes = (categoriesData && categoriesData.nodes) || [];
        const uniq = key => Array.from(new Set(nodes.map(n => n[key]).filter(Boolean)))
            .sort().map(v => ({ value: v, label: v }));
        renderCheckList('clsFilterGroups', uniq('group'), prefs.groups);
        renderCheckList('clsFilterCategories', uniq('device_type'), prefs.categories);
        renderCheckList('clsColumnList',
            clsExportColumns.map(c => ({
                value: c.key, label: c.header + (c.per_neighbour ? ' *' : '') })),
            prefs.columns);
        document.getElementById('classificationExportModal').style.display = 'flex';
    }

    async function runClassificationExport() {
        const prefs = {
            groups: clsChecked('clsFilterGroups'),
            categories: clsChecked('clsFilterCategories'),
            columns: clsChecked('clsColumnList'),
        };
        if (!prefs.columns.length) { alert(i18n[currentLang].alertExportNoColumns); return; }
        localStorage.setItem(CLS_EXPORT_PREFS_KEY, JSON.stringify(prefs));
        const qs = new URLSearchParams();
        for (const [k, v] of Object.entries(prefs)) if (v.length) qs.set(k, v.join(','));
        const res = await apiFetch('/api/export/classification?' + qs.toString());
        if (!res || !res.ok) { alert(i18n[currentLang].alertExportError); return; }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sentinelnet-classification-' + new Date().toISOString().slice(0, 10) + '.csv';
        a.click();
        URL.revokeObjectURL(url);
        document.getElementById('classificationExportModal').style.display = 'none';
    }

    document.getElementById('btnExportClassification')
        ?.addEventListener('click', openClassificationExportModal);
    document.getElementById('btnRunClassificationExport')
        ?.addEventListener('click', runClassificationExport);
    document.getElementById('btnCloseClassificationExport')
        ?.addEventListener('click', () => {
            document.getElementById('classificationExportModal').style.display = 'none';
        });
```

`renderCheckList` currently lives in `devices.js`. Check whether it is exposed on `window`; if not, either expose it (`window.renderCheckList = renderCheckList` **and** an entry in `types/globals.d.ts`) or add a local copy in `topology.js`. An undeclared `window` property failing `check_frontend.py` is the intended behaviour, not noise to silence.

Confirm `categoriesData` is the variable holding the loaded classification payload in this file before relying on the name.

- [ ] **Step 5: Add the i18n keys**

In the `it` block of `static/js/i18n.js`:

```javascript
        titleClassificationExport: "Esporta classificazione CSV",
        descClassificationExport: "Nessuna casella spuntata in un filtro significa «tutti». Le colonne del vicino producono una riga per ogni collegamento.",
        btnExportClassification: "Esporta CSV",
        lblClsCategory: "Categoria",
```

In the `en` block:

```javascript
        titleClassificationExport: "Export classification CSV",
        descClassificationExport: "An empty filter means «all». Neighbour columns produce one row per link.",
        btnExportClassification: "Export CSV",
        lblClsCategory: "Category",
```

Reuse the existing `lblExportColumns`, `alertExportError` and `alertExportNoColumns` keys rather than adding near-duplicates; confirm each exists in both blocks before relying on it.

- [ ] **Step 6: Run the UI test and the frontend gates**

```
uv run python -m unittest tests.test_classification_export_ui -v
uv run python -m unittest tests.test_i18n_parity tests.test_lazy_tab_scripts -v
uv run python scripts/check_frontend.py
uv run python -m unittest discover -s tests
```

`topology.js` is already lazy-loaded for `tab-categories`, so `LAZY_TAB_SCRIPTS` needs no change — `test_lazy_tab_scripts` confirms it.

- [ ] **Step 7: Commit**

```bash
git add templates/dashboard.html static/js/topology.js static/js/i18n.js \
        tests/test_classification_export_ui.py
git commit -m "feat(ui): column-picker export for Discovered Devices & Classification"
```

---

### Task 6: Version, docs and the full gate

- [ ] **Step 1: Bump the version**

`core/version.py` and `pyproject.toml` line 3 together: `0.11.2` → `0.12.0` (MINOR, new feature).
Run: `uv run python -m unittest tests.test_version -v`

- [ ] **Step 2: Document the feature**

Search `docs/`, `README.md` and `PRODUCT.md` for the inventory export and describe the classification export beside it. Cover: the two new columns, that a neighbour column produces one row per link, and that an AP serial appears only once someone has opened that controller's WLC tab — with `Serial Seen At` showing how old it is. `docs/netsec_troubleshooting_qa_v3.md` pins routes and element ids in a strict house style; match it if you add an entry there.

Assert nothing you have not verified in the code. Example values only.

- [ ] **Step 3: Run the whole gate**

```
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run python -m unittest discover -s tests
graphify update .
```

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore(release): bump to 0.12.0 with the classification export"
```

---

## Notes for the executor

- **Task 4's neighbour direction rule is the one thing worth re-reading before writing code.** Reporting the local port instead of the neighbour's port produces a file that looks right and sends someone to the wrong patch panel.
- **Do not add a per-AP inventory loop** if the bulk command turns out to be unavailable on a platform. An empty serial column is the designed outcome; a fan-out is the failure this design was built to avoid.
- **Task 3 must not change `/api/device-classification`'s response shape.** If `test_router_parity` needs an allow-list edit after Task 3, the extraction went wrong.
- **Tasks 1 and 2 are independent of Tasks 3-5** and can be done in either order. Task 4 depends on both halves; Task 5 depends on Task 4.
- `tests/test_switch_provisioner.py` holds bare `test_*` functions that `unittest discover` never collects. If you add a test near it, make it a `TestCase` or it will not run — and the suite will still look green.
- If a task's test passes on the first run, before you write the implementation, stop — the test is not testing what you think it is.
