# Manual Config Repository Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator upload the config of a device SentinelNet cannot reach, guided by per-vendor commands, so the device lands in the inventory (tenant/site/category) and every backup-based analysis works on it.

**Architecture:** A manual device is a normal inventory row with transport `{"manual": null}`; every loop and session path that would contact it skips or refuses it. A pure service (`services/manual_config.py`) builds the command guide from the drivers and the triage's own accessory-command list, and turns an uploaded terminal session log into the exact backup layout the triage writes. A router reuses the site agent's ingest sequence (`save_backup` → `history.record_version` → `update_version_inventory`). The UI is one `ui-wizard.js` side sheet opened from the Import tab and from a manual device's row.

**Tech Stack:** Python 3 / FastAPI / pydantic, unittest + pytest runner, vanilla JS classic scripts, Jinja template.

**Spec:** `docs/superpowers/specs/2026-10-08-manual-config-repository-design.md`

## Global Constraints

- Every IP, hostname, serial in code, tests, docs, commit messages: RFC 5737 (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and placeholders (`switch-01`). Never a real value.
- New comments in English; leave surrounding Italian comments alone.
- User-facing strings: `tr('key')` with both `it` and `en` entries in `static/js/i18n.js`; never a `currentLang ===` ternary.
- No inline handlers in `templates/dashboard.html`; ids + delegated listeners. Every form control has an accessible name.
- Modals via `openModal`/`closeModal` (here through `createWizard`).
- Config size limit: `MAX_CONFIG_BYTES` (5 MB) from `routers/agent.py`, shared, not redefined.
- No new dependency (no `python-multipart`, no JS library).
- Before each commit (AGENTS.md): `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py` when `static/js`/`templates` change, `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`, `graphify update .`.
- Stage files by name. Never `git add -A`: the working tree carries unrelated uncommitted work (tutorials).

## Prerequisite (before Task 7)

`static/js/i18n.js`, `templates/dashboard.html`, `static/css/dashboard.css`, `types/globals.d.ts`, `static/js/core.js` carry the user's uncommitted tutorials work. Task 7 edits four of those files. Before Task 7 starts, that work must be committed by the user, or Task 7 runs in a worktree created from `Dev` HEAD. Tasks 1–6 touch none of those files.

## Review Focus

1. **Session log with CRLF line endings and a PuTTY header line** (`=~=~=~=~ PuTTY log …`): must still be split correctly — test in Task 5.
2. **A plain config with no command echo** (FortiGate GUI backup `.conf`): stored exactly as uploaded, version/model from the `#config-version=` header — test in Task 5.
3. **Abbreviated commands typed by hand** (`sh run` instead of `show running-config`): not recognized, stored as a plain file and flagged `structured: false` so the UI can warn — test in Task 5.
4. **Saving a manual device through another inventory path without transports** (agent sync, rename, reassign): must keep it manual — test in Task 1.
5. **Same IP in another tenant already reachable over SSH**: identity is (tenant, IP), so it is not a conflict — test in Task 6.

---

### Task 1: `manual` transport in the inventory

**Files:**
- Modify: `services/inventory_manager.py:49` (`ALLOWED_TRANSPORTS`), `services/inventory_manager.py:75-96` (`_validate_transports`), add `is_manual` after `parse_transports` (line ~73)
- Modify: `routers/inventory.py` inside `get_devices_and_versions` (the `for d in devices:` loop, line ~108; response key `"devices"` at line 138)
- Test: `tests/test_manual_transport.py`

**Interfaces:**
- Produces: `inventory_manager.is_manual(device: dict) -> bool`; `"manual"` accepted by `_validate_transports` (always stored with port `None`, refused together with any other transport); `/api/local-devices` rows carry `"manual": bool`.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The 'manual' transport: a device SentinelNet never connects to."""
import os
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="sentinelnet_manualtx_")
os.environ.setdefault("SENTINELNET_DATA_DIR", _TMP)

from services import inventory_manager as im  # noqa: E402


class ValidateManual(unittest.TestCase):
    def test_manual_alone_is_valid_and_portless(self):
        self.assertEqual(im._validate_transports({"manual": 22}), {"manual": None})

    def test_manual_with_another_transport_is_refused(self):
        with self.assertRaises(ValueError):
            im._validate_transports({"manual": None, "ssh": 22})

    def test_is_manual(self):
        self.assertTrue(im.is_manual({"Transports": '{"manual":null}'}))
        self.assertFalse(im.is_manual({"Transports": '{"ssh":22}'}))
        self.assertFalse(im.is_manual({"SSH Port": "22"}))  # legacy row


class ManualSurvivesOtherWrites(unittest.TestCase):
    """Review focus 4: a later write without transports keeps the device manual."""

    def setUp(self):
        self.hosts = os.path.join(tempfile.mkdtemp(prefix="sentinelnet_manualtx_"), "network_hosts.csv")
        p = mock.patch.object(im, "get_hosts_csv", return_value=self.hosts)
        p.start()
        self.addCleanup(p.stop)

    def test_update_without_transports_keeps_manual(self):
        im.add_or_update_device("192.0.2.30", "cisco", "", "", "", "", "Generale",
                                transports={"manual": None})
        im.add_or_update_device("192.0.2.30", "cisco", "", "", "", "", "Generale",
                                site="central")
        row = next(d for d in im.get_all_devices() if d["IP"] == "192.0.2.30")
        self.assertTrue(im.is_manual(row))


class LocalDevicesFlag(unittest.TestCase):
    def test_local_devices_marks_manual_rows(self):
        from fastapi.testclient import TestClient
        import app_server
        from routers.deps import get_current_user
        rows = [{"IP": "192.0.2.31", "Vendor": "cisco", "Group": "Generale",
                 "Site": "central", "Transports": '{"manual":null}'},
                {"IP": "192.0.2.32", "Vendor": "cisco", "Group": "Generale",
                 "Site": "central", "Transports": '{"ssh":22}'}]
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "root", "role": "super_admin"}
        self.addCleanup(app_server.app.dependency_overrides.pop, get_current_user, None)
        with mock.patch("services.inventory_manager.get_all_devices", return_value=rows), \
             mock.patch("redundancy.service.redundancy_badges_by_ip", return_value={}), \
             mock.patch("collectors.mac_history.device_positions", return_value={}):
            r = TestClient(app_server.app).get("/api/local-devices")
        self.assertEqual(r.status_code, 200, r.text)
        flags = {d["IP"]: d["manual"] for d in r.json()["devices"]}
        self.assertEqual(flags, {"192.0.2.31": True, "192.0.2.32": False})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_manual_transport.py -v`
Expected: FAIL — `ValueError: Protocollo di trasporto non supportato: 'manual'` and `AttributeError: ... has no attribute 'is_manual'`.

- [ ] **Step 3: Implement**

`services/inventory_manager.py:49`:

```python
ALLOWED_TRANSPORTS = ("ssh", "telnet", "netconf", "restconf", "tcp", "udp", "manual")
```

Right after `parse_transports` (before `_validate_transports`):

```python
def is_manual(device) -> bool:
    """A device SentinelNet never connects to: its config is uploaded by hand
    (services/manual_config.py), and nothing opens a session or a probe to it."""
    return "manual" in parse_transports(device)
```

In `_validate_transports`, inside the `for proto, port in transports.items():` loop, as its first statement after the `ALLOWED_TRANSPORTS` check:

```python
        if proto == "manual":
            # Nothing reaches a manual device, so a port would mean nothing.
            clean[proto] = None
            continue
```

and replace the final `return clean` with:

```python
    # Paired with a real transport, a device would be both reached and not.
    if "manual" in clean and len(clean) > 1:
        raise ValueError("Il trasporto 'manual' non si combina con altri protocolli.")
    return clean
```

`routers/inventory.py`, in the `for d in devices:` loop of `get_devices_and_versions`, next to `dev_copy["icmp_reachable"] = ...`:

```python
        dev_copy["manual"] = inventory_manager.is_manual(d)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_manual_transport.py tests/test_router_parity.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/inventory_manager.py routers/inventory.py tests/test_manual_transport.py
git commit -m "feat(inventory): 'manual' transport for devices configured by upload"
```

---

### Task 2: Nothing opens a session to a manual device

**Files:**
- Modify: `core/core_engine.py` — import list (line 13-16), `get_cli_transport` (line ~98), new `_manual_refusal`, first lines of `_run_backup_and_triage` (~260), `probe_device` (~514), `send_custom_command` (~569), `run_bulk_command` (~609)
- Modify: `services/route_table.py` `_collect_live` (~line 311)
- Test: `tests/test_manual_device_guards.py`

**Interfaces:**
- Consumes: `inventory_manager.is_manual` (Task 1).
- Produces: `core_engine._manual_refusal(device) -> dict | None`; `get_cli_transport` raises `ValueError` for a manual device.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A manual device has no credentials: any session would go out with the
defaults. Every per-device session path refuses it before connecting."""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_manualguard_"))

from core import core_engine  # noqa: E402

MANUAL = {"IP": "192.0.2.40", "Vendor": "cisco", "Group": "Generale",
          "Site": "central", "Transports": '{"manual":null}'}


class SessionGuards(unittest.TestCase):
    def test_cli_transport_refuses(self):
        with self.assertRaises(ValueError):
            core_engine.get_cli_transport(MANUAL)

    def test_triage_refuses_before_credentials(self):
        with mock.patch.object(core_engine, "get_device_credentials") as creds:
            out = core_engine._run_backup_and_triage(dict(MANUAL))
        self.assertEqual(out["status"], "error")
        creds.assert_not_called()

    def test_fortigate_manual_never_dispatched(self):
        fgt = dict(MANUAL, Vendor="fortinet")
        with mock.patch.object(core_engine, "_fortigate_backup_and_triage") as fg:
            out = core_engine._run_backup_and_triage(fgt)
        self.assertEqual(out["status"], "error")
        fg.assert_not_called()

    def test_custom_command_bulk_and_probe_refuse(self):
        with mock.patch.object(core_engine, "ConnectHandler") as conn:
            self.assertEqual(core_engine.send_custom_command(dict(MANUAL), "show clock")["status"], "error")
            self.assertEqual(core_engine.run_bulk_command(dict(MANUAL), ["show clock"])["status"], "error")
            self.assertEqual(core_engine.probe_device(dict(MANUAL))["status"], "error")
        conn.assert_not_called()

    def test_route_table_reads_only_the_backup(self):
        from services import route_table
        out = route_table._collect_live(dict(MANUAL))
        self.assertIn("error", out)
        self.assertNotIn("rows", out)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_manual_device_guards.py -v`
Expected: FAIL — no ValueError; triage calls credentials.

- [ ] **Step 3: Implement**

`core/core_engine.py` import block (line 13-16): add `is_manual`:

```python
from services.inventory_manager import (
    update_version_inventory, get_all_devices, get_detected_versions,
    update_device_hostname, get_all_vendors, get_category_assignments,
    parse_transports, meta_signature, is_manual,
)
```

`get_cli_transport`: after the `try/except` that computes `transports`, before `if transports:`:

```python
    if transports and 'manual' in transports:
        # Backstop for every CLI path (terminal, port actions, route
        # collection): a manual device has no credentials, so a session would
        # go out with the defaults to an address nobody said is reachable.
        raise ValueError(f"Il dispositivo {device.get('IP')} e' manuale: "
                         "la sua config si carica a mano, nessuna sessione.")
```

New helper, right above `run_backup_and_triage`:

```python
def _manual_refusal(device):
    """The error result for a manual device, None for any other.

    Same shape as the agent-site refusal, returned before anything resolves
    credentials or dials the device."""
    if not is_manual(device):
        return None
    return {"status": "error",
            "message": (f"Il dispositivo {device.get('IP')} e' manuale: la sua "
                        "config si carica a mano (Importa → Config manuale), "
                        "SentinelNet non apre sessioni verso di esso.")}
```

First statement of the body of `_run_backup_and_triage`, `probe_device`, `send_custom_command` (before the blacklist check) and `run_bulk_command`:

```python
    refusal = _manual_refusal(device)
    if refusal:
        return refusal
```

`services/route_table.py` `_collect_live`, right after `ip = device.get("IP")` (`inventory_manager` is already imported at module level):

```python
    if inventory_manager.is_manual(device):
        # Nothing to ask: collect_for shows the static routes of the uploaded
        # config, with this line as the reason there is no live table.
        return {"device_ip": ip,
                "error": "dispositivo manuale: rotte dalla config caricata"}
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_manual_device_guards.py tests/test_run_tagged.py tests/test_remote_site.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/core_engine.py services/route_table.py tests/test_manual_device_guards.py
git commit -m "feat(triage): refuse sessions to manual devices"
```

---

### Task 3: Scheduled loops skip manual devices

**Files:**
- Modify: `routers/triage.py:160` (`for d in devices:` in `run_triage`)
- Modify: `services/triage_scheduler.py:360` (`for d in devices:` in `execute_schedule_job`)
- Modify: `services/ping_monitor.py:80` (`_run_cycle`)
- Modify: `observability/ingesters/snmp_poller.py:374` (`_snmp_devices`)
- Modify: `observability/ingesters/linux_poller.py:182` (`_linux_devices`)
- Modify: `collectors/mac_collector.py:796` and `collectors/arp_collector.py:142` (`collect_all`)
- Test: `tests/test_manual_device_skips.py`

**Interfaces:**
- Consumes: `inventory_manager.is_manual` (Task 1).

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Loops over the whole inventory never hand a manual device to a probe."""
import os
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_manualskip_"))

MANUAL = {"IP": "192.0.2.50", "Vendor": "linux", "Group": "Generale",
          "Site": "central", "Transports": '{"manual":null}'}
DEVICES = "services.inventory_manager.get_all_devices"
TELEMETRY = "services.tenant_telemetry.is_telemetry_enabled"


class Skips(unittest.TestCase):
    def test_ping_cycle(self):
        from services import ping_monitor
        with mock.patch(DEVICES, return_value=[MANUAL]), \
             mock.patch(TELEMETRY, return_value=True), \
             mock.patch.object(ping_monitor, "_ping_one") as ping:
            ping_monitor._run_cycle()
        ping.assert_not_called()

    def test_snmp_targets(self):
        from observability.ingesters import snmp_poller
        with mock.patch(DEVICES, return_value=[MANUAL]), \
             mock.patch(TELEMETRY, return_value=True), \
             mock.patch("security.snmp_defaults.resolve_snmp_community", return_value="public"):
            self.assertEqual(snmp_poller._snmp_devices(), [])

    def test_linux_targets(self):
        from observability.ingesters import linux_poller
        with mock.patch(DEVICES, return_value=[MANUAL]):
            self.assertEqual(linux_poller._linux_devices(), [])

    def test_mac_collect_all(self):
        from collectors import mac_collector
        with mock.patch.object(mac_collector, "collect_one") as one, \
             mock.patch("collectors.mac_history.prune", return_value=0):
            out = mac_collector.collect_all([MANUAL])
        one.assert_not_called()
        self.assertEqual(out["scanned"], 0)

    def test_arp_collect_all(self):
        from collectors import arp_collector
        with mock.patch.object(arp_collector, "collect_from_device") as one:
            arp_collector.collect_all([MANUAL])
        one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_manual_device_skips.py -v`
Expected: FAIL on all five.

- [ ] **Step 3: Implement**

`services/ping_monitor.py` `_run_cycle`, first line inside `for d in devices:`:

```python
        if inventory_manager.is_manual(d):
            continue  # never reachable by design: a ping would only paint it red
```

`observability/ingesters/snmp_poller.py` `_snmp_devices`, first line inside the loop (`inventory_manager` is already imported locally there):

```python
        if inventory_manager.is_manual(device):
            continue
```

`observability/ingesters/linux_poller.py` `_linux_devices`, first line inside the loop:

```python
        if inventory_manager.is_manual(device):
            continue
```

`collectors/mac_collector.py` `collect_all`, after the local imports and before `if not devices:`:

```python
    from services import inventory_manager
    devices = [d for d in devices if not inventory_manager.is_manual(d)]
```

`collectors/arp_collector.py` `collect_all`, after the local imports and before `summary = ...`:

```python
    from services import inventory_manager
    devices = [d for d in devices if not inventory_manager.is_manual(d)]
```

`routers/triage.py` `run_triage` and `services/triage_scheduler.py` `execute_schedule_job`, first line inside `for d in devices:` (before the agent-site branch; both modules already import `inventory_manager`):

```python
        if inventory_manager.is_manual(d):
            continue  # its config is uploaded by hand; _manual_refusal backs this up
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_manual_device_skips.py tests/test_remote_site.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add routers/triage.py services/triage_scheduler.py services/ping_monitor.py observability/ingesters/snmp_poller.py observability/ingesters/linux_poller.py collectors/mac_collector.py collectors/arp_collector.py tests/test_manual_device_skips.py
git commit -m "feat(collectors): scheduled loops skip manual devices"
```

---

### Task 4: Triage accessory commands as data

Behavior-preserving refactor: the `if vendor == 'cisco': … elif vendor == 'windows': …` chain at `core/core_engine.py:355-470` becomes data that Task 5 also reads.

**Files:**
- Modify: `core/core_engine.py` (new module-level data + `triage_extra_commands` above `_run_tagged`, line ~209; chain at 355-470 replaced)
- Test: `tests/test_triage_extra_commands.py`

**Interfaces:**
- Produces: `core_engine.triage_extra_commands(vendor: str, privileged: bool = False) -> list[tuple[str, str]]`; `core_engine.TRIAGE_EXTRA_TIMEOUT: dict[str, int]`.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""The triage's accessory commands, read by the triage and the manual guide."""
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_extras_"))

from core import core_engine as ce  # noqa: E402


class Extras(unittest.TestCase):
    def test_cisco(self):
        cmds = ce.triage_extra_commands("cisco")
        self.assertEqual(cmds[0], ("show cdp neighbors", "--- SHOW CDP NEIGHBORS ---"))
        self.assertEqual(cmds[-1], ("show inventory", "--- SHOW INVENTORY ---"))
        self.assertEqual(len(cmds), 6)

    def test_linux_privileged_tier(self):
        base = ce.triage_extra_commands("linux")
        full = ce.triage_extra_commands("linux", privileged=True)
        self.assertIn(("sshd -T", "--- SSHD EFFECTIVE CONFIG ---"), full)
        self.assertNotIn(("sshd -T", "--- SSHD EFFECTIVE CONFIG ---"), base)
        self.assertEqual(full[:len(base)], base)

    def test_windows_comes_from_the_driver(self):
        from drivers.windows import TRIAGE_COMMANDS
        self.assertEqual(ce.triage_extra_commands("windows"), list(TRIAGE_COMMANDS))

    def test_fortinet_and_unknown_have_none(self):
        self.assertEqual(ce.triage_extra_commands("fortinet"), [])
        self.assertEqual(ce.triage_extra_commands("juniper"), [])

    def test_timeouts_match_the_old_branches(self):
        self.assertEqual(ce.TRIAGE_EXTRA_TIMEOUT,
                         {"cisco_9800": 30, "cisco_wlc": 30, "paloalto": 30, "windows": 45})

    def test_returned_list_is_a_copy(self):
        ce.triage_extra_commands("cisco").clear()
        self.assertEqual(len(ce.triage_extra_commands("cisco")), 6)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_triage_extra_commands.py -v`
Expected: FAIL — `AttributeError: module 'core.core_engine' has no attribute 'triage_extra_commands'`.

- [ ] **Step 3: Implement**

Above `def _run_tagged` add the skeleton below, then **cut each list literal verbatim, with its comments, from its branch in `_run_backup_and_triage`** into the matching slot:

- `'cisco'` ← the list in `if vendor == 'cisco':`
- `'hpe'` ← `elif vendor == 'hpe':`
- `'cisco_9800'` ← `elif vendor == 'cisco_9800':` (with its "Catalyst 9800 is IOS-XE" comment)
- `'cisco_wlc'` ← `elif vendor == 'cisco_wlc':` (with its AireOS comment)
- `'paloalto'` ← `elif vendor in ('fortinet', 'paloalto'):`
- `LINUX_TRIAGE_COMMANDS` ← the initial `linux_cmds = [...]` (with the `hostname` comment above it)
- `LINUX_PRIVILEGED_COMMANDS` ← the list added under `if secret:` (with the "Privileged tier" comment)

```python
# Accessory commands the triage runs after the config, each output stored
# under its tag. Data rather than branches so the manual-upload guide
# (services/manual_config.py) asks a human for exactly the sections the
# triage collects by itself. FortiGate is absent on purpose: it returns at
# the FORTINET_VENDORS dispatch in _run_backup_and_triage and never runs these.
TRIAGE_EXTRA_COMMANDS = {
    'cisco': [...],
    'hpe': [...],
    'cisco_9800': [...],
    'cisco_wlc': [...],
    'paloalto': [...],
}
# read_timeout per vendor; absent = netmiko's default. Windows pays the .NET
# runtime start on the first `powershell -Command`.
TRIAGE_EXTRA_TIMEOUT = {'cisco_9800': 30, 'cisco_wlc': 30, 'paloalto': 30, 'windows': 45}
LINUX_TRIAGE_COMMANDS = [...]
LINUX_PRIVILEGED_COMMANDS = [...]


def triage_extra_commands(vendor: str, privileged: bool = False) -> list:
    """[(command, tag)] the triage runs after the config for this vendor.

    privileged adds Linux's root-only tier (the session has a sudo password).
    """
    if vendor == 'linux':
        return LINUX_TRIAGE_COMMANDS + (LINUX_PRIVILEGED_COMMANDS if privileged else [])
    if vendor == 'windows':
        # The chain lives in drivers/windows.py: every command formats its
        # own delimited output because Windows' text output is localized.
        from drivers.windows import TRIAGE_COMMANDS
        return list(TRIAGE_COMMANDS)
    return list(TRIAGE_EXTRA_COMMANDS.get(vendor, ()))
```

Then replace the whole chain from `if vendor == 'cisco':` through the windows `config_out += _run_tagged(net_connect, windows_cmds, read_timeout=45)` (keep the preceding `from services.config_drift.normalize import TRIAGE_MARKER` and `config_out += f"\n\n{TRIAGE_MARKER}\n"` lines untouched) with:

```python
            extras = triage_extra_commands(vendor, privileged=bool(secret))
            if extras:
                # Linux's bare `hostname` output is written as `hostname <name>`
                # so extract_hostname_from_config reads it.
                config_out += _run_tagged(net_connect, extras,
                                          read_timeout=TRIAGE_EXTRA_TIMEOUT.get(vendor),
                                          prefix_hostname=(vendor == 'linux'))
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_triage_extra_commands.py tests/test_run_tagged.py tests/test_stack_detection.py -v`
Expected: PASS. Then `uv run pyrefly check` → 0 errors.

- [ ] **Step 5: Commit**

```bash
git add core/core_engine.py tests/test_triage_extra_commands.py
git commit -m "refactor(triage): accessory commands as data shared with the manual guide"
```

---

### Task 5: `services/manual_config.py` — guide, session log → backup, preview

**Files:**
- Create: `services/manual_config.py`
- Test: `tests/test_manual_config.py`

**Interfaces:**
- Consumes: `core_engine.resolve_driver`, `core_engine.triage_extra_commands` (Task 4), `core_engine.extract_hostname_from_config`, `ai.config_analyzer.detect_config_type`, `services.config_drift.normalize.TRIAGE_MARKER`.
- Produces:
  - `GUIDE_VENDORS: tuple[str, ...]`
  - `guide() -> list[dict]` — each `{"vendor", "paging", "commands": list[str], "notes": list[str]}`
  - `parse_session(text: str, known: list[str]) -> tuple[dict[str, str], str | None]`
  - `to_backup(vendor: str, text: str) -> dict` — `{"backup", "structured", "hostname", "version", "model", "serial"}`
  - `ip_candidates(text: str) -> list[str]`
  - `analyses_for(vendor: str, config_type: str, version: str) -> list[str]`
  - `preview(text: str, vendor: str = "") -> dict` — `{"vendor", "config_type", "structured", "hostname", "version", "model", "serial", "ip_candidates", "analyses"}` (no `"backup"`)

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual config upload: the guide, and a session log turned into the
backup layout the triage writes."""
import os
import tempfile
import unittest

os.environ.setdefault("SENTINELNET_DATA_DIR", tempfile.mkdtemp(prefix="sentinelnet_manualcfg_"))

from services import manual_config as mc  # noqa: E402
from services.config_drift.normalize import TRIAGE_MARKER  # noqa: E402

IOS_LOG = (
    "=~=~=~=~=~=~=~=~=~=~=~= PuTTY log 2026.10.08 10:00:00 =~=~=~=~=~=~=~=~=~=~=~=\r\n"
    "switch-01#terminal length 0\r\n"
    "switch-01#show running-config\r\n"
    "Building configuration...\r\n"
    "hostname switch-01\r\n"
    "interface Vlan10\r\n"
    " ip address 192.0.2.10 255.255.255.0\r\n"
    "interface Vlan20\r\n"
    " ip address 198.51.100.1 255.255.255.0\r\n"
    "end\r\n"
    "switch-01#show version\r\n"
    "Cisco IOS Software, C2960X Software, Version 15.2(7)E2, RELEASE SOFTWARE (fc3)\r\n"
    "Model Number                       : WS-C2960X-24TS-L\r\n"
    "System Serial Number               : FOC0000X0XX\r\n"
    "switch-01#show cdp neighbors detail\r\n"
    "Device ID: switch-02\r\n"
    "switch-01#\r\n"
)

FORTI_GUI = (
    "#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0\n"
    "config system global\n"
    "    set hostname \"FGT-01\"\n"
    "end\n"
    "config system interface\n"
    "    edit \"port1\"\n"
    "        set ip 192.0.2.1 255.255.255.0\n"
    "    next\n"
    "end\n"
)

PANOS = ("set deviceconfig system hostname PA-01\n"
         "set deviceconfig system ip-address 203.0.113.5\n")

JUNOS = ("set system host-name router-01\n"
         "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.2/24\n")


class Guide(unittest.TestCase):
    def test_every_vendor_resolves_and_has_its_backup_command(self):
        rows = {g["vendor"]: g for g in mc.guide()}
        self.assertEqual(set(rows), set(mc.GUIDE_VENDORS))
        self.assertEqual(rows["cisco"]["commands"][0], "show running-config")
        self.assertIn("show version", rows["cisco"]["commands"])
        self.assertIn("show cdp neighbors detail", rows["cisco"]["commands"])
        self.assertEqual(rows["cisco"]["paging"], "terminal length 0")
        self.assertEqual(rows["fortinet"]["commands"][0], "show full-configuration")
        self.assertIn("get system status", rows["fortinet"]["commands"])

    def test_commands_are_not_repeated(self):
        for g in mc.guide():
            self.assertEqual(len(g["commands"]), len(set(g["commands"])), g["vendor"])


class SessionLog(unittest.TestCase):
    """Review focus 1: CRLF and a PuTTY header line."""

    def test_ios_log_becomes_triage_layout(self):
        out = mc.to_backup("cisco", IOS_LOG)
        self.assertTrue(out["structured"])
        config, _, rest = out["backup"].partition(f"\n\n{TRIAGE_MARKER}\n")
        self.assertIn("hostname switch-01", config)
        self.assertNotIn("show version", config)
        self.assertNotIn("PuTTY log", out["backup"])
        self.assertIn("--- SHOW CDP NEIGHBORS DETAIL ---\nDevice ID: switch-02", rest)
        self.assertNotIn("Cisco IOS Software", out["backup"])  # read, not stored
        self.assertEqual(out["version"], "15.2(7)E2")
        self.assertEqual(out["model"], "WS-C2960X-24TS-L")
        self.assertEqual(out["serial"], "FOC0000X0XX")
        self.assertEqual(out["hostname"], "switch-01")

    def test_abbreviated_command_is_a_plain_file(self):
        """Review focus 3."""
        out = mc.to_backup("cisco", "switch-01#sh run\nhostname switch-01\nend\n")
        self.assertFalse(out["structured"])
        self.assertEqual(out["backup"], "switch-01#sh run\nhostname switch-01\nend\n")


class PlainFiles(unittest.TestCase):
    def test_fortigate_gui_backup_is_stored_as_is(self):
        """Review focus 2."""
        out = mc.to_backup("fortinet", FORTI_GUI)
        self.assertFalse(out["structured"])
        self.assertEqual(out["backup"], FORTI_GUI)
        self.assertEqual((out["model"], out["version"]), ("FGT60F", "7.2.5"))
        self.assertEqual(out["hostname"], "FGT-01")

    def test_hostnames_of_other_vendors(self):
        self.assertEqual(mc.to_backup("paloalto", PANOS)["hostname"], "PA-01")
        self.assertEqual(mc.to_backup("juniper", JUNOS)["hostname"], "router-01")


class Candidates(unittest.TestCase):
    def test_ip_candidates(self):
        self.assertEqual(mc.ip_candidates(IOS_LOG), ["192.0.2.10", "198.51.100.1"])
        self.assertEqual(mc.ip_candidates(FORTI_GUI), ["192.0.2.1"])
        self.assertEqual(mc.ip_candidates(PANOS), ["203.0.113.5"])
        self.assertEqual(mc.ip_candidates(JUNOS), ["192.0.2.2"])


class Preview(unittest.TestCase):
    def test_vendor_is_suggested_and_analyses_listed(self):
        p = mc.preview(FORTI_GUI)
        self.assertEqual(p["vendor"], "fortinet")
        self.assertEqual(p["config_type"], "fortios")
        self.assertEqual(p["analyses"], ["analyzer", "audit", "policy", "drift", "routes", "cve"])
        self.assertNotIn("backup", p)

    def test_junos_gets_drift_only(self):
        p = mc.preview(JUNOS)
        self.assertEqual(p["vendor"], "juniper")
        self.assertEqual(p["analyses"], ["drift"])

    def test_given_vendor_wins(self):
        self.assertEqual(mc.preview(IOS_LOG, "cisco")["vendor"], "cisco")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_manual_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'services.manual_config'`.

- [ ] **Step 3: Implement `services/manual_config.py`**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Configs of devices SentinelNet cannot reach, uploaded by hand.

One rule: what is stored must be indistinguishable from what the triage
would have written, so every reader of backup-config/ (analyzer, drift, audit,
policy test, routes, map) works on it unchanged.

- guide(): the commands to run, per vendor — the triage's own list.
- to_backup(): a terminal session log -> the triage's backup layout.
- preview(): what an upload says about the device, for the review form.

Spec: docs/superpowers/specs/2026-10-08-manual-config-repository-design.md
"""
import re

from core import core_engine
from services.config_drift.normalize import TRIAGE_MARKER

# Inventory vendor keys the guide offers (drivers/registry.VENDOR_DRIVER_DEFAULTS
# without its aliases).
GUIDE_VENDORS = ("cisco", "cisco_cbs", "cisco_9800", "cisco_wlc", "hpe", "aruba",
                 "juniper", "fortinet", "paloalto", "linux", "windows")

# The pager-off command a human types first; the triage gets the same effect
# from netmiko's session preparation.
PAGING = {
    "cisco": "terminal length 0",
    "cisco_9800": "terminal length 0",
    "cisco_cbs": "terminal datadump",
    "cisco_wlc": "config paging disable",
    "hpe": "no page",
    "aruba": "no paging",
    "juniper": "set cli screen-length 0",
    "fortinet": "config system console\n    set output standard\nend",
    "paloalto": "set cli pager off",
}

# Per-vendor notes, as i18n keys the UI translates.
NOTES = {
    "fortinet": ["mcNoteFortiGui"],
    "linux": ["mcNoteLinuxRoot"],
    "windows": ["mcNoteWindowsCmd"],
}

_VENDOR_BY_TYPE = {"ios": "cisco", "fortios": "fortinet", "panos": "paloalto",
                   "wlc-aireos": "cisco_wlc", "linux": "linux", "windows": "windows"}
_JUNOS = re.compile(r"^set (system host-name|interfaces) ", re.MULTILINE)

# What each config type unlocks (spec §4); 'cve' is added only with a version.
_ANALYSES = {
    "ios": ["analyzer", "audit", "policy", "drift", "routes"],
    "fortios": ["analyzer", "audit", "policy", "drift", "routes"],
    "panos": ["analyzer", "drift"],
    "wlc-aireos": ["analyzer", "drift"],
    "linux": ["analyzer", "audit", "drift"],
    "windows": ["analyzer", "drift"],
}

# First prompt-looking prefix ending in #, > or $, then the command.
_ECHO = re.compile(r"^(?P<prompt>\S[^\r\n]*?[#>$])\s*(?P<cmd>\S.*?)\s*$")
_FORTI_HEADER = re.compile(r"^#config-version=([A-Za-z0-9]+)-(\d+\.\d+\.\d+)", re.MULTILINE)
_HOSTNAMES = (
    re.compile(r"^set deviceconfig system hostname (\S+)", re.MULTILINE),  # PAN-OS
    re.compile(r"^set system host-name (\S+)", re.MULTILINE),              # Junos
    re.compile(r"^config sysname (\S+)", re.MULTILINE),                    # AireOS
)
_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_IP_PATTERNS = (  # management-specific first
    re.compile(r"^set deviceconfig system ip-address " + _IP, re.MULTILINE),    # PAN-OS
    re.compile(r"^config interface address management " + _IP, re.MULTILINE),  # AireOS
    re.compile(r"^\s*ip address " + _IP + r"[ /]", re.MULTILINE),               # IOS, ProCurve
    re.compile(r"^\s*set ip " + _IP + r"[ /]", re.MULTILINE),                    # FortiOS
    re.compile(r"family inet address " + _IP + r"/"),                             # Junos
    re.compile(r"^\S+\s+UP\s+" + _IP + r"/", re.MULTILINE),                      # Linux `ip -br a`
)
_UNKNOWN = ("Unknown", "Non Rilevato", "Non Rilevata")


def _norm(command: str) -> str:
    return " ".join((command or "").split())


class _Replay:
    """Connection stand-in for a driver: records what it is asked and answers
    from a captured session, so version, model and serial come from the
    driver's own parsers instead of a second copy of them."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.asked = []

    def send_command(self, command, *args, **kwargs):
        if command not in self.asked:
            self.asked.append(command)
        return self.answers.get(_norm(command), "")


def _driver_cls(vendor):
    driver_cls, _ = core_engine.resolve_driver(vendor)
    return driver_cls


def _commands(vendor):
    """(backup command, info commands, [(extra command, tag)]) for a vendor.

    The info commands are whatever the driver's get_version/get_model/
    get_serial send, recorded rather than listed by hand."""
    rec = _Replay()
    drv = _driver_cls(vendor)(rec)
    drv.get_version()
    drv.get_model()
    drv.get_serial()
    backup = drv.get_backup_command()
    extras = core_engine.triage_extra_commands(vendor, privileged=True)
    taken = {_norm(backup)} | {_norm(c) for c, _ in extras}
    info = [c for c in rec.asked if _norm(c) not in taken]
    return backup, info, extras


def guide() -> list:
    out = []
    for vendor in GUIDE_VENDORS:
        backup, info, extras = _commands(vendor)
        out.append({"vendor": vendor, "paging": PAGING.get(vendor, ""),
                    "commands": [backup, *info, *(c for c, _ in extras)],
                    "notes": NOTES.get(vendor, [])})
    return out


def parse_session(text: str, known: list):
    """Split a terminal session log at the echo of each known command.

    Returns ({normalized command: output}, prompt). The prompt is learned from
    the first known echo; after that any line starting with it (another
    command, or the bare prompt at the end) closes the current section, and
    only known commands open a new one."""
    wanted = {_norm(c) for c in known}
    sections, current, prompt = {}, None, None
    for line in (text or "").splitlines():
        if prompt is not None and line.startswith(prompt):
            cmd = _norm(line[len(prompt):])
            current = cmd if cmd in wanted else None
            if current:
                sections[current] = []
            continue
        if prompt is None:
            m = _ECHO.match(line)
            if m and _norm(m["cmd"]) in wanted:
                prompt, current = m["prompt"], _norm(m["cmd"])
                sections[current] = []
                continue
        if current is not None:
            sections[current].append(line)
    return {k: "\n".join(v).strip("\n") for k, v in sections.items()}, prompt


def _known(value) -> str:
    v = (value or "").strip()
    return "" if v in _UNKNOWN else v


def _hostname(text: str, prompt) -> str:
    name = core_engine.extract_hostname_from_config(text)
    if name:
        return name
    for pattern in _HOSTNAMES:
        m = pattern.search(text)
        if m:
            return m.group(1).strip('"')
    if prompt:
        # 'admin@PA-01>' -> 'PA-01', 'switch-01#' -> 'switch-01',
        # '(Cisco Controller) >' -> '' (not a name).
        return re.sub(r"^.*@|[:(].*$|[\s#>$]+$", "", prompt)
    return ""


def to_backup(vendor: str, text: str) -> dict:
    """The upload as the triage would have stored it, plus what it says."""
    backup_cmd, info, extras = _commands(vendor)
    sections, prompt = parse_session(text, [backup_cmd, *info, *(c for c, _ in extras)])
    config = sections.get(_norm(backup_cmd))
    if config is None:
        # No echo of the backup command: a plain config file, stored as is.
        stored, structured = text, False
    else:
        stored, structured = config + f"\n\n{TRIAGE_MARKER}\n", True
        for cmd, tag in extras:
            body = sections.get(_norm(cmd))
            if body is None:
                continue
            if vendor == "linux" and tag == "--- HOSTNAME ---":
                # Same rewrite as core_engine._run_tagged(prefix_hostname=True).
                body = f"hostname {body.strip()}"
            stored += f"\n{tag}\n{body}"
    drv = _driver_cls(vendor)(_Replay(sections))
    header = _FORTI_HEADER.search(text or "")
    return {
        "backup": stored,
        "structured": structured,
        "hostname": _hostname(stored, prompt),
        "version": _known(drv.get_version()) or (header.group(2) if header else ""),
        "model": _known(drv.get_model()) or (header.group(1) if header else ""),
        "serial": _known(drv.get_serial()),
    }


def ip_candidates(text: str) -> list:
    out = []
    for pattern in _IP_PATTERNS:
        for ip in pattern.findall(text or ""):
            if ip in out or ip.startswith(("127.", "0.")):
                continue
            if all(int(octet) <= 255 for octet in ip.split(".")):
                out.append(ip)
    return out


def analyses_for(vendor: str, config_type: str, version: str) -> list:
    # Junos has a driver but no parser: detect_config_type calls it 'ios', and
    # the IOS analyzer reads nothing out of `set` lines.
    base = ["drift"] if vendor == "juniper" else list(_ANALYSES.get(config_type, ["drift"]))
    return base + (["cve"] if version else [])


def preview(text: str, vendor: str = "") -> dict:
    from ai.config_analyzer import detect_config_type
    if not vendor:
        vendor = "juniper" if _JUNOS.search(text or "") else \
            _VENDOR_BY_TYPE.get(detect_config_type(text), "cisco")
    result = to_backup(vendor, text)
    backup = result.pop("backup")
    config_type = detect_config_type(backup, {"Vendor": vendor})
    return {**result, "vendor": vendor, "config_type": config_type,
            "ip_candidates": ip_candidates(backup),
            "analyses": analyses_for(vendor, config_type, result["version"])}
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_manual_config.py -v`
Expected: PASS. If a driver's `get_model`/`get_serial` returns a placeholder not in `_UNKNOWN` for empty input, add that exact string to `_UNKNOWN` (do not special-case the vendor).

- [ ] **Step 5: Commit**

```bash
git add services/manual_config.py tests/test_manual_config.py
git commit -m "feat(manual-config): command guide and session-log to backup conversion"
```

---

### Task 6: `routers/manual_config.py`

**Files:**
- Create: `routers/manual_config.py`
- Modify: `app_server.py` — import next to the other routers (after `from routers import firewall_traffic as _firewall_traffic_router`) and `app.include_router(_manual_config_router.router)` after `app.include_router(_firewall_traffic_router.router)`
- Test: `tests/test_manual_config_api.py`

**Interfaces:**
- Consumes: Task 1 `is_manual`; Task 5 `GUIDE_VENDORS`, `guide`, `preview`, `to_backup`, `analyses_for`.
- Produces:
  - `GET /api/manual-config/guide` → `{"vendors": [...guide()], "categories": {key: {"label", "subcategories"}}, "sites": [{"id", "name"}]}`
  - `POST /api/manual-config/preview` body `{"text", "vendor"?}` → `preview()`
  - `POST /api/manual-config/import` body `{"text", "ip", "vendor", "group", "site"?, "hostname"?, "category"?, "subcategory"?, "version"?, "model"?}` → `{"status": "success", "file", "hostname", "analyses"}`; 400 empty/invalid, 403 scope or role, 409 reachable device, 413 too large.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual config API: the router runs end to end into a temporary data dir."""
import os
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="sentinelnet_manualapi_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from routers.deps import get_current_user  # noqa: E402
from services.config_drift.normalize import TRIAGE_MARKER  # noqa: E402

IOS_LOG = (
    "switch-01#show running-config\n"
    "hostname switch-01\n"
    "interface Vlan10\n"
    " ip address 192.0.2.10 255.255.255.0\n"
    "end\n"
    "switch-01#show version\n"
    "Cisco IOS Software, C2960X Software, Version 15.2(7)E2, RELEASE SOFTWARE\n"
    "switch-01#show cdp neighbors detail\n"
    "Device ID: switch-02\n"
    "switch-01#\n"
)


class ManualConfigApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Same isolation as tests/test_remote_site.py: DATA_DIR is a global
        # another module on this xdist worker may have moved.
        from core import data_config
        from services import inventory_manager
        prev = data_config.DATA_DIR
        data_config.DATA_DIR = _TMP
        cls.addClassCleanup(setattr, data_config, "DATA_DIR", prev)
        for name, filename in (("get_hosts_csv", "network_hosts.csv"),
                               ("get_groups_json", "groups.json")):
            p = mock.patch.object(inventory_manager, name,
                                  return_value=os.path.join(_TMP, filename))
            p.start()
            cls.addClassCleanup(p.stop)
        inventory_manager.add_group("tenant-a")
        inventory_manager.add_group("tenant-b")
        cls.client = TestClient(app_server.app)

    def _as(self, role, groups=()):
        app_server.app.dependency_overrides[get_current_user] = \
            lambda: {"sub": "tester", "role": role}
        self.addCleanup(app_server.app.dependency_overrides.pop, get_current_user, None)
        for target, value in (("routers.deps.user_manager.get_user_groups", list(groups)),
                              ("routers.deps.user_manager.effective_tabs", None)):
            p = mock.patch(target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def _import(self, **overrides):
        body = {"text": IOS_LOG, "ip": "192.0.2.10", "vendor": "cisco",
                "group": "tenant-a", "site": "central"}
        body.update(overrides)
        return self.client.post("/api/manual-config/import", json=body)

    def test_viewer_is_refused(self):
        self._as("viewer")
        self.assertEqual(self._import().status_code, 403)

    def test_bad_body_is_422(self):
        self._as("operator")
        self.assertEqual(self.client.post("/api/manual-config/import", json={}).status_code, 422)

    def test_empty_config_is_400(self):
        self._as("operator")
        self.assertEqual(self._import(text="  \n").status_code, 400)

    def test_tenant_out_of_scope_is_403(self):
        self._as("operator", ["tenant-b"])
        self.assertEqual(self._import(ip="192.0.2.11").status_code, 403)

    def test_import_lands_where_every_analysis_reads(self):
        self._as("operator")
        r = self._import()
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        with open(body["file"], encoding="utf-8") as f:
            saved = f.read()
        self.assertIn("hostname switch-01", saved)
        self.assertIn(TRIAGE_MARKER, saved)
        self.assertIn("--- SHOW CDP NEIGHBORS DETAIL ---", saved)

        from ai import config_analyzer
        from services import inventory_manager
        from services.config_drift import history
        path, _tenant = config_analyzer._find_freshest_backup("192.0.2.10", "tenant-a")
        self.assertEqual(os.path.normcase(path), os.path.normcase(body["file"]))
        device = next(d for d in inventory_manager.get_all_devices()
                      if d["IP"] == "192.0.2.10" and d["Group"] == "tenant-a")
        self.assertTrue(inventory_manager.is_manual(device))
        self.assertEqual(device.get("Hostname"), "switch-01")
        entry = inventory_manager.get_detected_versions()["192.0.2.10"]
        self.assertEqual((entry["status"], entry["version"]), ("manual", "15.2(7)E2"))
        self.assertTrue(history.list_versions(device))
        self.assertIn("cve", body["analyses"])

    def test_reupload_adds_a_version(self):
        self._as("operator")
        self.assertEqual(self._import(ip="192.0.2.12").status_code, 200)
        changed = IOS_LOG.replace("interface Vlan10", "interface Vlan11")
        self.assertEqual(self._import(ip="192.0.2.12", text=changed).status_code, 200)
        from services import inventory_manager
        from services.config_drift import history
        device = next(d for d in inventory_manager.get_all_devices()
                      if d["IP"] == "192.0.2.12" and d["Group"] == "tenant-a")
        self.assertEqual(len(history.list_versions(device)), 2)

    def test_reachable_device_is_409(self):
        from services import inventory_manager
        inventory_manager.add_or_update_device("192.0.2.20", "cisco", "", "admin", "x", "",
                                               "tenant-a")
        self._as("operator")
        self.assertEqual(self._import(ip="192.0.2.20").status_code, 409)

    def test_same_ip_reachable_in_another_tenant_is_not_a_conflict(self):
        """Review focus 5: identity is (tenant, IP)."""
        from services import inventory_manager
        inventory_manager.add_or_update_device("192.0.2.21", "cisco", "", "admin", "x", "",
                                               "tenant-b")
        self._as("operator")
        self.assertEqual(self._import(ip="192.0.2.21").status_code, 200)

    def test_preview_and_guide(self):
        self._as("operator")
        p = self.client.post("/api/manual-config/preview", json={"text": IOS_LOG})
        self.assertEqual(p.status_code, 200, p.text)
        self.assertEqual(p.json()["hostname"], "switch-01")
        self.assertEqual(p.json()["ip_candidates"], ["192.0.2.10"])
        g = self.client.get("/api/manual-config/guide")
        self.assertEqual(g.status_code, 200, g.text)
        self.assertIn("central", [s["id"] for s in g.json()["sites"]])
        self.assertIn("switch", g.json()["categories"])
        self.assertIn("cisco", [v["vendor"] for v in g.json()["vendors"]])


if __name__ == "__main__":
    unittest.main()
```

Before running, read `services/config_drift/history.py:69` (`record_version`): if it skips a version whose normalized text equals the previous one, the `Vlan10`→`Vlan11` change above is a real difference and the two-version assertion stays valid.

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_manual_config_api.py -v`
Expected: FAIL — 404 on every route.

- [ ] **Step 3: Implement `routers/manual_config.py`**

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Manual config upload for devices SentinelNet cannot reach.

The same ingest as the site agent's POST /api/agent/backup (routers/agent.py),
with an operator instead of an agent as the source. One device per call: the
UI posts the rows one after another and shows each outcome as it lands.
Spec: docs/superpowers/specs/2026-10-08-manual-config-repository-design.md
"""
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ai.config_analyzer import detect_config_type
from core import backup_store
from routers.agent import MAX_CONFIG_BYTES
from routers.deps import assert_group_allowed, require_operator, require_tab
from security.security_manager import log_audit
from services import inventory_manager, manual_config, site_manager

router = APIRouter(tags=["manual-config"])
# Opened from the Import tab and from a manual device's row in Devices.
_TABS = ("tab-import", "tab-devices")


class ManualPreviewSchema(BaseModel):
    text: str
    vendor: str = ""


class ManualImportSchema(BaseModel):
    text: str
    ip: str
    vendor: str
    group: str
    site: str = "central"
    hostname: str = ""
    category: str = ""
    subcategory: str = ""
    version: str = ""
    model: str = ""


def _check_text(text: str) -> None:
    if not text.strip():
        raise HTTPException(status_code=400, detail="Config vuota: niente da caricare.")
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise HTTPException(status_code=413,
                            detail="Config oltre il limite di 5 MB: rifiutata, non troncata.")


def _row(ip: str, group: str):
    return next((d for d in inventory_manager.get_all_devices()
                 if d.get("IP") == ip and (d.get("Group") or "Generale") == group), None)


@router.get("/api/manual-config/guide", dependencies=[Depends(require_tab(*_TABS))])
def manual_config_guide(current_user=Depends(require_operator)):
    # Categories and sites ride along: the review form needs them, and their
    # own routes belong to tabs this user may not hold.
    cats = inventory_manager.get_device_categories()["categories"]
    return {
        "vendors": manual_config.guide(),
        "categories": {k: {"label": v["label"], "subcategories": v["subcategories"]}
                       for k, v in cats.items()},
        "sites": [{"id": s["id"], "name": s.get("name") or s["id"]}
                  for s in site_manager.list_sites()],
    }


@router.post("/api/manual-config/preview", dependencies=[Depends(require_tab(*_TABS))])
def manual_config_preview(payload: ManualPreviewSchema, current_user=Depends(require_operator)):
    _check_text(payload.text)
    vendor = inventory_manager.normalize_vendor(payload.vendor) if payload.vendor else ""
    if vendor and vendor not in manual_config.GUIDE_VENDORS:
        raise HTTPException(status_code=400, detail=f"Vendor '{payload.vendor}' non supportato.")
    return manual_config.preview(payload.text, vendor)


@router.post("/api/manual-config/import", dependencies=[Depends(require_tab(*_TABS))])
def manual_config_import(payload: ManualImportSchema, current_user=Depends(require_operator)):
    _check_text(payload.text)
    assert_group_allowed(current_user, payload.group)
    if payload.group not in inventory_manager.get_all_groups():
        raise HTTPException(status_code=400, detail=f"Tenant '{payload.group}' inesistente.")
    if payload.site not in {s["id"] for s in site_manager.list_sites()}:
        raise HTTPException(status_code=400, detail=f"Sede '{payload.site}' inesistente.")
    vendor = inventory_manager.normalize_vendor(payload.vendor)
    if vendor not in manual_config.GUIDE_VENDORS:
        raise HTTPException(status_code=400, detail=f"Vendor '{payload.vendor}' non supportato.")
    existing = _row(payload.ip, payload.group)
    if existing is not None and not inventory_manager.is_manual(existing):
        raise HTTPException(status_code=409, detail=(
            f"{payload.ip} e' gia' in inventario come dispositivo raggiungibile: "
            "il prossimo triage sovrascriverebbe la config caricata."))
    try:
        inventory_manager.add_or_update_device(
            payload.ip, vendor, "", "", "", "", payload.group,
            site=payload.site, transports={"manual": None})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    device = _row(payload.ip, payload.group)

    parsed = manual_config.to_backup(vendor, payload.text)
    hostname = payload.hostname.strip() or parsed["hostname"] or payload.ip
    file_path = backup_store.save_backup(device, hostname, parsed["backup"])
    try:
        from services.config_drift import history
        history.record_version(device, parsed["backup"])
    except Exception as e:
        logging.warning(f"Storico config non aggiornato per {payload.ip}: {e}")
    version = payload.version.strip() or parsed["version"]
    inventory_manager.update_version_inventory(
        payload.ip, vendor, version or "Non Rilevata", "manual",
        model=payload.model.strip() or parsed["model"] or None,
        serial=parsed["serial"] or None)
    inventory_manager.update_device_hostname(payload.ip, hostname, payload.group)
    if payload.category:
        inventory_manager.set_device_meta(payload.ip, tenant=payload.group,
                                          category=payload.category,
                                          subcategory=payload.subcategory)
    log_audit(f"Config manuale caricata per '{payload.ip}' (tenant '{payload.group}', "
              f"{len(payload.text)} caratteri) dall'utente '{current_user.get('sub')}'.")
    config_type = detect_config_type(parsed["backup"], device)
    return {"status": "success", "file": file_path, "hostname": hostname,
            "analyses": manual_config.analyses_for(vendor, config_type, version)}
```

`app_server.py`: add `from routers import manual_config as _manual_config_router` after the `firewall_traffic` router import and `app.include_router(_manual_config_router.router)` after its `include_router`.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_manual_config_api.py tests/test_route_classes.py tests/test_router_parity.py -v`
Expected: PASS (TAB routes are discovered through `require_tab`, no `route_classes.py` entry needed). If `test_route_classes.py` demands an explicit entry, follow its failure message.

- [ ] **Step 5: Commit**

```bash
git add routers/manual_config.py app_server.py tests/test_manual_config_api.py
git commit -m "feat(manual-config): guide, preview and import API"
```

---

### Task 7: UI — wizard, Import panel, Devices row, status

Prerequisite above must be satisfied first.

**Files:**
- Create: `static/js/manual-config.js`
- Modify: `templates/dashboard.html` — Import tab panel (inside `.import-steps`, after the CSV upload `<section class="panel">`), wizard sheet (after the `siteWizard` block), `<script src="/static/js/manual-config.js"></script>` after `<script src="/static/js/devices.js"></script>`
- Modify: `static/js/devices.js` — `inventoryStatusBucket` (~108), status pill + actions in `renderDeviceTable` (~240-300), click handler (~308)
- Modify: `static/js/home.js` — `homeStatusInfo` (43), reachability count (~122), bays (~370)
- Modify: `static/js/topology.js` — `nodeStatusMeta` (~704)
- Modify: `static/js/i18n.js` — `it` and `en` blocks
- Modify: `static/css/dashboard.css` — after `.dropzone-text > i` (~4370)
- Modify: `types/globals.d.ts` — `interface Window`

**Interfaces:**
- Consumes: Task 6 routes; Task 1 `manual` flag on `/api/local-devices` rows; globals `apiFetch`, `tr`, `escapeHtml`, `showToast`, `refreshInventory`, `globalDevices`, `globalGroups`, `createWizard`.
- Produces: `window.openManualConfigWizard(ip?: string): Promise<void>`.

- [ ] **Step 1: Template — Import panel**

```html
          <section class="panel">
            <div class="panel-head">
              <h3 data-i18n="mcPanelTitle">Device non raggiungibili</h3>
              <button type="button" class="btn btn-secondary btn-small" id="btnOpenManualConfig" style="width:auto;" data-i18n="btnOpenManualConfig"><i class="fa-solid fa-file-arrow-up"></i> Carica config</button>
            </div>
            <p class="set-desc" style="margin:0;" data-i18n="mcPanelBody">Per un apparato che SentinelNet non raggiunge, né in SSH né tramite agente: ti dice quali comandi lanciare, carichi il log della sessione e il dispositivo entra in inventario con analisi, drift, audit e CVE come gli altri.</p>
          </section>
```

- [ ] **Step 2: Template — wizard sheet**

```html
  <!-- Manual config upload for devices SentinelNet cannot reach (ui-wizard.js).
       Spec: docs/superpowers/specs/2026-10-08-manual-config-repository-design.md -->
  <div class="modal-overlay sheet-overlay" id="manualConfigWizard">
    <div class="modal sheet" aria-labelledby="mcTitle">
      <div class="modal-header">
        <h3 id="mcTitle" data-i18n="mcTitle">Carica config manuale</h3>
        <button type="button" class="modal-close" data-close-modal="manualConfigWizard" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <ol class="wizard-rail" data-wizard-rail aria-label="Passi" data-i18n-aria-label="swRailLabel"></ol>
      <form id="mcForm" class="sheet-body" novalidate>
        <section data-step="guide">
          <div class="form-group">
            <label for="mcVendor" data-i18n="mcLblVendor">Vendor</label>
            <select id="mcVendor"></select>
          </div>
          <p data-i18n="mcGuideIntro">Attiva il log della sessione nel client SSH (PuTTY: Session → Logging → All session output), poi lancia i comandi nell'ordine. Al passo successivo carichi il file di log.</p>
          <h4 data-i18n="mcLblPaging">Disattiva la paginazione</h4>
          <pre id="mcPaging" class="enroll-block"></pre>
          <h4 data-i18n="mcLblCommands">Comandi</h4>
          <pre id="mcCommands" class="enroll-block"></pre>
          <button type="button" class="btn btn-secondary" data-action="mc-copy" data-i18n="btnCopySiteEnroll"><i class="fa-solid fa-copy"></i> Copia tutto</button>
          <ul id="mcNotes" class="mc-notes"></ul>
        </section>
        <section data-step="files" hidden>
          <div id="mcDropZone" class="dropzone">
            <input type="file" id="mcFileInput" multiple accept=".txt,.log,.conf,.cfg" hidden aria-label="File di config" data-i18n-aria-label="mcAriaFiles">
            <input type="file" id="mcFolderInput" webkitdirectory multiple hidden aria-label="Cartella di config" data-i18n-aria-label="mcAriaFolder">
            <div class="dropzone-text"><i class="fa-solid fa-file-lines fa-2x"></i><br><span data-i18n="mcDropText">Trascina qui i log o le config, oppure clicca per sceglierli</span></div>
          </div>
          <button type="button" class="btn btn-secondary btn-small" data-action="mc-pick-folder" style="width:auto; margin-top:8px;" data-i18n="mcPickFolder">Scegli una cartella</button>
          <ul id="mcFileList" class="mc-file-list"></ul>
        </section>
        <section data-step="review" hidden>
          <fieldset id="mcApplyAll" class="mc-card">
            <legend data-i18n="mcApplyAllTitle">Uguale per tutti i file</legend>
            <div class="mc-grid">
              <label for="mcAllGroup"><span data-i18n="mcLblTenant">Tenant</span></label>
              <select id="mcAllGroup"></select>
              <label for="mcAllSite"><span data-i18n="mcLblSite">Sede</span></label>
              <select id="mcAllSite"></select>
              <label for="mcAllCategory"><span data-i18n="mcLblCategory">Categoria</span></label>
              <select id="mcAllCategory"></select>
            </div>
            <button type="button" class="btn btn-secondary btn-small" data-action="mc-apply-all" style="width:auto;" data-i18n="mcBtnApplyAll">Applica a tutti</button>
          </fieldset>
          <div id="mcReviewBody"></div>
        </section>
        <section data-step="result" hidden>
          <ul id="mcResultList" class="mc-result-list" aria-live="polite"></ul>
        </section>
      </form>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="manualConfigWizard" data-i18n="uiCancel">Annulla</button>
        <button type="button" class="btn btn-secondary" data-wizard-back data-i18n="wizBack">Indietro</button>
        <!-- No data-i18n: ui-wizard.js sets the label per step. -->
        <button type="button" class="btn btn-primary" data-wizard-next></button>
      </div>
    </div>
  </div>
```

- [ ] **Step 3: `static/js/manual-config.js`**

```js
// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
//
// Manual config upload for devices SentinelNet cannot reach: the commands to
// run, the session logs dropped in, one review card per file, then one POST
// per device. Opened from the Import tab and from a manual device's row.
// Spec: docs/superpowers/specs/2026-10-08-manual-config-repository-design.md
(function () {
    const $ = (id) => document.getElementById(id);
    // fixed: a manual device being re-uploaded from its row (fields locked).
    const mc = { guide: null, files: [], rows: [], results: null, fixed: null };

    // Analysis id -> [label key, tab that shows it].
    const ANALYSIS_TABS = {
        analyzer: ['mcAnAnalyzer', 'tab-config'],
        audit: ['mcAnAudit', 'tab-netsec-audit'],
        policy: ['mcAnPolicy', 'tab-policy-test'],
        drift: ['mcAnDrift', 'tab-config-drift'],
        routes: ['mcAnRoutes', 'tab-routes'],
        cve: ['mcAnCve', 'tab-security'],
    };

    const optionsHtml = (items, current, blankLabel) =>
        (blankLabel !== undefined ? `<option value="">${escapeHtml(blankLabel)}</option>` : '')
        + items.map(([value, label]) => `<option value="${escapeHtml(value)}"${value === current ? ' selected' : ''}>${escapeHtml(label)}</option>`).join('');

    async function loadGuide() {
        if (mc.guide) return mc.guide;
        const res = await apiFetch('/api/manual-config/guide');
        if (!res || !res.ok) return null;
        mc.guide = await res.json();
        $('mcVendor').innerHTML = optionsHtml(mc.guide.vendors.map((v) => [v.vendor, v.vendor.toUpperCase()]), '');
        return mc.guide;
    }

    function vendorValue() {
        const sel = $('mcVendor');
        return sel instanceof HTMLSelectElement ? sel.value : '';
    }

    function renderGuide() {
        const v = (mc.guide?.vendors || []).find((x) => x.vendor === vendorValue());
        if (!v) return;
        $('mcPaging').textContent = v.paging || tr('mcNoPaging');
        $('mcCommands').textContent = v.commands.join('\n');
        $('mcNotes').innerHTML = v.notes.map((k) => `<li>${escapeHtml(tr(k))}</li>`).join('');
    }

    function addFiles(list) {
        for (const f of Array.from(list || [])) {
            if (mc.fixed && mc.files.length) break; // a row re-upload takes one file
            if (!mc.files.some((x) => x.name === f.name && x.size === f.size)) mc.files.push(f);
        }
        renderFileList();
        wizard.refresh();
    }

    function renderFileList() {
        $('mcFileList').innerHTML = mc.files.map((f, i) => `<li>
            <span>${escapeHtml(f.webkitRelativePath || f.name)} · ${Math.max(1, Math.round(f.size / 1024))} KB</span>
            <button type="button" class="inv-icon-btn" data-action="mc-remove-file" data-index="${i}"
              aria-label="${escapeHtml(tr('mcRemoveFile', { name: f.name }))}"><i class="fa-solid fa-xmark"></i></button>
          </li>`).join('');
    }

    async function enterReview() {
        const vendor = vendorValue();
        $('mcReviewBody').innerHTML = `<p class="form-hint">${escapeHtml(tr('mcReading'))}</p>`;
        mc.rows = [];
        for (const file of mc.files) {
            const text = await file.text();
            const res = await apiFetch('/api/manual-config/preview', {
                method: 'POST', body: JSON.stringify({ text, vendor }) });
            const p = res && res.ok ? await res.json() : null;
            mc.rows.push({
                file, text, vendor,
                ip: mc.fixed?.ip || p?.ip_candidates?.[0] || '',
                candidates: p?.ip_candidates || [],
                hostname: mc.fixed?.hostname || p?.hostname || '',
                group: mc.fixed?.group || '',
                site: mc.fixed?.site || 'central',
                category: '',
                version: p?.version || '',
                model: p?.model || '',
                structured: !!p?.structured,
                analyses: p?.analyses || [],
                error: p ? '' : tr('mcPreviewFailed'),
            });
        }
        fillApplyAll();
        renderReview();
        wizard.refresh();
    }

    function groupItems() { return Object.keys(globalGroups || {}).map((g) => [g, g]); }
    function siteItems() { return (mc.guide?.sites || []).map((s) => [s.id, s.name]); }
    function categoryItems() { return Object.entries(mc.guide?.categories || {}).map(([k, c]) => [k, c.label]); }

    function fillApplyAll() {
        $('mcApplyAll').hidden = !!mc.fixed;
        $('mcAllGroup').innerHTML = optionsHtml(groupItems(), '', tr('mcAllNone'));
        $('mcAllSite').innerHTML = optionsHtml(siteItems(), '', tr('mcAllNone'));
        $('mcAllCategory').innerHTML = optionsHtml(categoryItems(), '', tr('mcAllNone'));
    }

    function renderReview() {
        const lock = mc.fixed ? ' disabled' : '';
        $('mcReviewBody').innerHTML = mc.rows.map((r, i) => `
          <fieldset class="mc-card" data-row="${i}">
            <legend>${escapeHtml(r.file.webkitRelativePath || r.file.name)}</legend>
            ${r.error ? `<p class="form-hint" role="alert">${escapeHtml(r.error)}</p>` : ''}
            <div class="mc-grid">
              <label>${escapeHtml(tr('mcLblHostname'))}<input data-field="hostname" value="${escapeHtml(r.hostname)}"${lock}></label>
              <label>IP<input data-field="ip" list="mcIps${i}" value="${escapeHtml(r.ip)}" inputmode="decimal"${lock}></label>
              <datalist id="mcIps${i}">${r.candidates.map((c) => `<option value="${escapeHtml(c)}"></option>`).join('')}</datalist>
              <label>${escapeHtml(tr('mcLblTenant'))}<select data-field="group"${lock}>${optionsHtml(groupItems(), r.group, '')}</select></label>
              <label>${escapeHtml(tr('mcLblSite'))}<select data-field="site"${lock}>${optionsHtml(siteItems(), r.site)}</select></label>
              <label>${escapeHtml(tr('mcLblCategory'))}<select data-field="category">${optionsHtml(categoryItems(), r.category, tr('mcCategoryAuto'))}</select></label>
              <label>${escapeHtml(tr('mcLblVersion'))}<input data-field="version" value="${escapeHtml(r.version)}"></label>
            </div>
            <p class="mc-analyses">${escapeHtml(tr('mcUnlocks'))}
              ${r.analyses.map((a) => `<span class="chip">${escapeHtml(tr(ANALYSIS_TABS[a][0]))}</span>`).join(' ')}</p>
            ${r.structured ? '' : `<p class="form-hint">${escapeHtml(tr('mcPlainFileHint'))}</p>`}
          </fieldset>`).join('');
    }

    function applyAll() {
        const read = (id) => { const el = $(id); return el instanceof HTMLSelectElement ? el.value : ''; };
        const values = { group: read('mcAllGroup'), site: read('mcAllSite'), category: read('mcAllCategory') };
        mc.rows.forEach((r) => { for (const [k, v] of Object.entries(values)) if (v) r[k] = v; });
        renderReview();
        wizard.refresh();
    }

    async function importAll() {
        const next = $('manualConfigWizard').querySelector('[data-wizard-next]');
        if (next instanceof HTMLButtonElement) next.disabled = true; // no double import
        mc.results = [];
        for (const r of mc.rows) {
            const res = await apiFetch('/api/manual-config/import', {
                method: 'POST',
                body: JSON.stringify({
                    text: r.text, vendor: r.vendor, ip: r.ip.trim(), group: r.group,
                    site: r.site, hostname: r.hostname.trim(), category: r.category,
                    version: r.version.trim(), model: r.model,
                }),
            });
            let body = null;
            try { body = res ? await res.json() : null; } catch (e) { body = null; }
            const detail = body && body.detail;
            mc.results.push({
                row: r, ok: !!(res && res.ok),
                detail: typeof detail === 'string' ? detail : (detail ? JSON.stringify(detail) : ''),
                analyses: (body && body.analyses) || [],
            });
        }
        await refreshInventory();
        wizard.goTo('result');
    }

    function renderResult() {
        $('mcResultList').innerHTML = mc.results.map((x) => `<li>
            <span class="led ${x.ok ? 'led-success' : 'led-danger'}"></span>
            <strong>${escapeHtml(x.row.hostname || x.row.ip)}</strong> <code>${escapeHtml(x.row.ip)}</code>
            ${x.ok
                ? x.analyses.map((a) => `<button type="button" class="chip" data-switch-tab="${ANALYSIS_TABS[a][1]}">${escapeHtml(tr(ANALYSIS_TABS[a][0]))}</button>`).join(' ')
                : `<span class="form-hint">${escapeHtml(x.detail || tr('alertError'))}</span>`}
          </li>`).join('');
    }

    const wizard = createWizard('manualConfigWizard', {
        steps: [
            { id: 'guide', label: 'mcStepGuide', skip: () => !!mc.results,
              onEnter: renderGuide, validate: () => !!vendorValue() },
            { id: 'files', label: 'mcStepFiles', skip: () => !!mc.results,
              validate: () => mc.files.length > 0 },
            { id: 'review', label: 'mcStepReview', skip: () => !!mc.results, onEnter: enterReview,
              validate: () => mc.rows.length > 0 && mc.rows.every((r) => r.ip.trim() && r.group && !r.error),
              finishLabel: 'mcBtnImport' },
            { id: 'result', label: 'mcStepResult', skip: () => !mc.results,
              onEnter: renderResult, finishLabel: 'btnClose' },
        ],
        onFinish: async (stepId) => {
            if (stepId === 'result') { wizard.close(); return; }
            await importAll();
        },
    });

    async function openManualConfigWizard(ip) {
        Object.assign(mc, { files: [], rows: [], results: null, fixed: null });
        const form = $('mcForm');
        if (form instanceof HTMLFormElement) form.reset();
        renderFileList();
        if (!(await loadGuide())) { showToast(tr('alertError'), 'error'); return; }
        if (ip) {
            const d = (globalDevices || []).find((x) => x.IP === ip && x.manual);
            if (d) {
                mc.fixed = { ip: d.IP, group: d.Group, site: d.Site || 'central', hostname: d.Hostname || '' };
                const sel = $('mcVendor');
                if (sel instanceof HTMLSelectElement && d.Vendor) sel.value = d.Vendor.toLowerCase();
            }
        }
        const input = $('mcFileInput');
        if (input instanceof HTMLInputElement) input.multiple = !mc.fixed;
        wizard.open();
    }
    window.openManualConfigWizard = openManualConfigWizard;

    $('btnOpenManualConfig')?.addEventListener('click', () => openManualConfigWizard());
    $('mcVendor')?.addEventListener('change', renderGuide);

    const zone = $('mcDropZone');
    zone?.addEventListener('click', (e) => {
        if (e.target instanceof HTMLInputElement) return;
        $('mcFileInput').click();
    });
    zone?.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('is-over'); });
    zone?.addEventListener('dragleave', () => zone.classList.remove('is-over'));
    zone?.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('is-over');
        addFiles(e.dataTransfer?.files);
    });
    for (const id of ['mcFileInput', 'mcFolderInput']) {
        $(id)?.addEventListener('change', (e) => {
            const t = e.target;
            if (!(t instanceof HTMLInputElement)) return;
            addFiles(t.files);
            t.value = '';
        });
    }

    $('manualConfigWizard')?.addEventListener('click', (e) => {
        const t = e.target instanceof Element ? e.target.closest('[data-action], [data-switch-tab]') : null;
        if (!(t instanceof HTMLElement)) return;
        // core.js switches the tab on the same click; the sheet must not stay over it.
        if (t.dataset.switchTab) { wizard.close(); return; }
        const action = t.dataset.action;
        if (action === 'mc-copy') {
            const text = [$('mcPaging').textContent, $('mcCommands').textContent].filter(Boolean).join('\n');
            navigator.clipboard?.writeText(text).then(() => showToast(tr('mcCopied'), 'success'));
        } else if (action === 'mc-pick-folder') {
            $('mcFolderInput').click();
        } else if (action === 'mc-remove-file') {
            mc.files.splice(Number(t.dataset.index), 1);
            renderFileList();
            wizard.refresh();
        } else if (action === 'mc-apply-all') {
            applyAll();
        }
    });

    const onFieldEdit = (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement || t instanceof HTMLSelectElement)) return;
        const card = t.closest('[data-row]');
        if (!(card instanceof HTMLElement) || !t.dataset.field) return;
        mc.rows[Number(card.dataset.row)][t.dataset.field] = t.value;
    };
    $('mcReviewBody')?.addEventListener('input', onFieldEdit);
    $('mcReviewBody')?.addEventListener('change', onFieldEdit);
})();
```

`[data-switch-tab]` clicks are already handled by the document-level listener in `core.js`; the sheet only closes itself. The review-field listeners sit on `#mcReviewBody`, a descendant of the wizard panel, so they update `mc.rows` before the panel's own `input` listener re-validates the step.

- [ ] **Step 4: Devices table, Home, map**

`static/js/devices.js` `inventoryStatusBucket`, first line of the body:

```js
        // A manual device is never probed: "not measurable", never offline.
        if (d.manual) return 'unknown';
```

In `renderDeviceTable`, replace `const info = homeStatusInfo(bucket);` with:

```js
            const info = homeStatusInfo(d.manual ? 'manual' : bucket);
            const pillTitle = d.manual
                ? tr('devConfigOf', { date: d.backup_ts ? new Date(d.backup_ts * 1000).toLocaleDateString() : '—' })
                : (bucket === 'unknown' ? tr('jumpLimitsPing') : '');
```

and in the status `<td>` replace `${bucket === 'unknown' ? ` title="${escapeHtml(tr('jumpLimitsPing'))}"` : ''}` with `${pillTitle ? ` title="${escapeHtml(pillTitle)}"` : ''}`.

Replace the actions expression (`${isViewer ? '<span class="inv-muted">—</span>' : [ iconBtn('ping-device', …), … ].join('')}`) with:

```js
                    ${isViewer ? '<span class="inv-muted">—</span>' : (d.manual ? [
                        // No ping/triage/CLI/edit: nothing connects to it, and the
                        // edit form has no 'manual' transport to save back.
                        iconBtn('upload-manual-config', 'fa-file-arrow-up', tr('devUploadConfig')),
                        iconBtn('download-backup', 'fa-download', tr('devDownloadBackup')),
                        iconBtn('delete-device', 'fa-trash-can', tr('uiDelete'), ' danger'),
                    ] : [
                        iconBtn('ping-device', 'fa-wifi', tr('devPingDevice')),
                        iconBtn('triage-device', 'fa-bolt-lightning', tr('devTriageDevice')),
                        iconBtn('open-cli', 'fa-terminal', 'CLI'),
                        iconBtn('edit-device', 'fa-pen', tr('devEditDevice')),
                        iconBtn('download-backup', 'fa-download', tr('devDownloadBackup')),
                        iconBtn('delete-device', 'fa-trash-can', tr('uiDelete'), ' danger'),
                    ]).join('')}
```

In the `deviceTableBody` click handler add:

```js
        else if (action === 'upload-manual-config') window.openManualConfigWizard(ip);
```

`static/js/home.js` `homeStatusInfo`, before the final `return`:

```js
    if (status === 'manual')      return { cls: 'idle', led: 'led-discovered', key: 'devStManual' };
```

In the reachability loop (the `devs.forEach` that does `notMeasurable++`), right after `const scan = globalVersions[d.IP] || {};`:

```js
        // Uploaded by hand, never probed: outside both counters, like a
        // jump-site device, but not listed as "via bastion".
        if (d.manual || scan.status === 'manual') { notMeasurable++; return; }
```

In the bays loop, before `else if (st === 'offline') b.down++;`:

```js
        else if (st === 'manual') b.unknown++;
```

`static/js/topology.js` `nodeStatusMeta`, before the `'unknown'` line:

```js
        if (status === 'manual')      return { ...lamp('idle'),  text: tr('devStManual'), problem: false };
```

- [ ] **Step 5: i18n, CSS, globals, script tag**

`static/js/i18n.js` — add to the `it:` block:

```js
        // Manual config upload (manual-config.js)
        mcPanelTitle: "Device non raggiungibili",
        mcPanelBody: "Per un apparato che SentinelNet non raggiunge, né in SSH né tramite agente: ti dice quali comandi lanciare, carichi il log della sessione e il dispositivo entra in inventario con analisi, drift, audit e CVE come gli altri.",
        btnOpenManualConfig: '<i class="fa-solid fa-file-arrow-up"></i> Carica config',
        mcTitle: "Carica config manuale",
        mcStepGuide: "Comandi",
        mcStepFiles: "File",
        mcStepReview: "Revisione",
        mcStepResult: "Esito",
        mcLblVendor: "Vendor",
        mcGuideIntro: "Attiva il log della sessione nel client SSH (PuTTY: Session → Logging → All session output), poi lancia i comandi nell'ordine. Al passo successivo carichi il file di log.",
        mcLblPaging: "Disattiva la paginazione",
        mcLblCommands: "Comandi",
        mcNoPaging: "Non serve per questo sistema.",
        mcCopied: "Comandi copiati",
        mcAriaFiles: "File di config",
        mcAriaFolder: "Cartella di config",
        mcDropText: "Trascina qui i log o le config, oppure clicca per sceglierli",
        mcPickFolder: "Scegli una cartella",
        mcRemoveFile: "Rimuovi {name}",
        mcReading: "Lettura dei file…",
        mcPreviewFailed: "File non leggibile: rimuovilo o caricalo di nuovo.",
        mcApplyAllTitle: "Uguale per tutti i file",
        mcBtnApplyAll: "Applica a tutti",
        mcAllNone: "— invariato —",
        mcLblHostname: "Hostname",
        mcLblTenant: "Tenant",
        mcLblSite: "Sede",
        mcLblCategory: "Categoria",
        mcCategoryAuto: "Automatica",
        mcLblVersion: "Versione",
        mcUnlocks: "Sblocca:",
        mcPlainFileHint: "Nessun comando riconosciuto nel file: salvato così com'è. Senza le sezioni dei vicini il dispositivo non avrà collegamenti sulla mappa.",
        mcAnAnalyzer: "Analisi config",
        mcAnAudit: "NetSec Audit",
        mcAnPolicy: "Policy test",
        mcAnDrift: "Config drift",
        mcAnRoutes: "Rotte",
        mcAnCve: "CVE",
        mcBtnImport: "Importa",
        mcNoteFortiGui: "In alternativa: GUI → Backup configurazione, e carichi il file .conf scaricato.",
        mcNoteLinuxRoot: "Lancia i comandi come root (sudo -s): alcune sezioni richiedono privilegi.",
        mcNoteWindowsCmd: "Lancia i comandi da cmd.exe, non da PowerShell.",
        devStManual: "Manuale",
        devConfigOf: "Config caricata a mano il {date}",
        devUploadConfig: "Carica nuova config",
```

and to the `en:` block:

```js
        // Manual config upload (manual-config.js)
        mcPanelTitle: "Unreachable devices",
        mcPanelBody: "For a device SentinelNet cannot reach, neither over SSH nor through an agent: it tells you which commands to run, you upload the session log, and the device joins the inventory with analysis, drift, audit and CVE like the others.",
        btnOpenManualConfig: '<i class="fa-solid fa-file-arrow-up"></i> Upload config',
        mcTitle: "Upload config manually",
        mcStepGuide: "Commands",
        mcStepFiles: "Files",
        mcStepReview: "Review",
        mcStepResult: "Result",
        mcLblVendor: "Vendor",
        mcGuideIntro: "Turn on session logging in your SSH client (PuTTY: Session → Logging → All session output), then run the commands in order. You upload the log file in the next step.",
        mcLblPaging: "Turn off paging",
        mcLblCommands: "Commands",
        mcNoPaging: "Not needed on this system.",
        mcCopied: "Commands copied",
        mcAriaFiles: "Config files",
        mcAriaFolder: "Config folder",
        mcDropText: "Drop logs or configs here, or click to choose them",
        mcPickFolder: "Choose a folder",
        mcRemoveFile: "Remove {name}",
        mcReading: "Reading files…",
        mcPreviewFailed: "File not readable: remove it or upload it again.",
        mcApplyAllTitle: "Same for every file",
        mcBtnApplyAll: "Apply to all",
        mcAllNone: "— unchanged —",
        mcLblHostname: "Hostname",
        mcLblTenant: "Tenant",
        mcLblSite: "Site",
        mcLblCategory: "Category",
        mcCategoryAuto: "Automatic",
        mcLblVersion: "Version",
        mcUnlocks: "Unlocks:",
        mcPlainFileHint: "No known command found in the file: stored as is. Without the neighbor sections the device will have no links on the map.",
        mcAnAnalyzer: "Config analysis",
        mcAnAudit: "NetSec Audit",
        mcAnPolicy: "Policy test",
        mcAnDrift: "Config drift",
        mcAnRoutes: "Routes",
        mcAnCve: "CVE",
        mcBtnImport: "Import",
        mcNoteFortiGui: "Alternatively: GUI → Configuration backup, and upload the downloaded .conf file.",
        mcNoteLinuxRoot: "Run the commands as root (sudo -s): some sections need privileges.",
        mcNoteWindowsCmd: "Run the commands from cmd.exe, not PowerShell.",
        devStManual: "Manual",
        devConfigOf: "Config uploaded by hand on {date}",
        devUploadConfig: "Upload new config",
```

`static/css/dashboard.css`, after `.dropzone-text > i { … }` (tokens `--primary`, `--seam`, `--font-code`, `--font-size-xs` exist in `:root`):

```css
/* Manual config wizard (manual-config.js) */
.dropzone.is-over { border-color: var(--primary); }
.mc-file-list, .mc-result-list, .mc-notes { list-style: none; margin: 10px 0 0; padding: 0; }
.mc-file-list li, .mc-result-list li { display: flex; align-items: center; gap: 8px; padding: 6px 0; border-bottom: var(--seam) solid var(--border); flex-wrap: wrap; }
.mc-file-list li span { flex: 1; min-width: 0; overflow-wrap: anywhere; }
.mc-notes li { font-size: var(--font-size-xs); color: var(--text-muted); }
.mc-card { border: var(--seam) solid var(--border); padding: 10px 12px; margin: 0 0 12px; }
.mc-card legend { font-family: var(--font-code); font-size: var(--font-size-xs); padding: 0 4px; overflow-wrap: anywhere; }
.mc-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 8px 12px; align-items: end; }
.mc-grid label { display: flex; flex-direction: column; gap: 4px; font-size: var(--font-size-xs); color: var(--text-muted); }
.mc-analyses { margin: 8px 0 0; font-size: var(--font-size-xs); color: var(--text-muted); }
```

`types/globals.d.ts`, inside `interface Window`:

```ts
    openManualConfigWizard: any; // manual-config.js, opened from devices.js rows
```

`templates/dashboard.html`: `<script src="/static/js/manual-config.js"></script>` right after `<script src="/static/js/devices.js"></script>`.

- [ ] **Step 6: Run the frontend gate**

Run:
```bash
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests/test_i18n_keys.py tests/test_a11y_dashboard.py tests/test_lazy_tab_scripts.py tests/test_ui_modal.py tests/js -v
```
Expected: all clean. Fix what they report (e.g. a label `for` mismatch) in the same task.

- [ ] **Step 7: See it work**

Run the app (`uv run python app_server.py`), log in, then in the browser:
1. Import → *Carica config* → vendor CISCO → copy works → drop a `.log` file with the `IOS_LOG` content from `tests/test_manual_config.py` → review shows `switch-01`, `192.0.2.10`, chips → pick tenant → *Importa* → result row green, chips open the tabs.
2. Devices: the row shows pill *Manuale* (grey), upload/download/delete only; upload opens the wizard with fields locked.
3. Config Drift on that device after a second upload shows the diff.
4. Narrow the window to phone width: review cards stack, no horizontal scroll.
5. Light and dark theme both readable.

- [ ] **Step 8: Commit**

```bash
git add static/js/manual-config.js static/js/devices.js static/js/home.js static/js/topology.js static/js/i18n.js static/css/dashboard.css types/globals.d.ts templates/dashboard.html
git commit -m "feat(ui): manual config wizard from Import and from manual device rows"
```

---

### Task 8: Docs, changelog, full gate, executable

**Files:**
- Modify: `CHANGELOG.md` (`## [Unreleased]` → `### Added`)
- Modify: `docs/operations.md` (new short section) — open it first and put the section next to the backup/import material
- Run `uv run python scripts/dev/capture_screenshots.py` only if the Import tab or Devices table is among the captured screens

- [ ] **Step 1: CHANGELOG**

Under `## [Unreleased]`:

```markdown
### Added

- **Config manuale per i dispositivi non raggiungibili**: dalla tab Importa
  (*Carica config*) o dalla riga di un dispositivo manuale, una procedura
  guidata mostra per ogni vendor i comandi da lanciare — gli stessi del
  triage — con la paginazione da disattivare; si carica il log della
  sessione (anche più file o una cartella), si assegnano tenant, sede e
  categoria, e il dispositivo entra in inventario come *Manuale*. La config
  viene salvata nello stesso formato del triage, quindi Analisi config,
  Config drift, NetSec Audit, Policy test, rotte statiche, mappa e CVE
  funzionano come per gli altri. Nessun ping, triage, SNMP o sessione verso
  un dispositivo manuale.
```

- [ ] **Step 2: `docs/operations.md` section**

```markdown
## Dispositivi non raggiungibili (config manuale)

Un dispositivo che SentinelNet non raggiunge — né in SSH dal centrale né
tramite un agente di sede — si aggiunge caricandone la config: *Importa →
Carica config*. La procedura mostra, per il vendor scelto, il comando per
disattivare la paginazione e l'elenco dei comandi da lanciare (gli stessi che
il triage esegue da sé). Con il log della sessione attivo nel client SSH, si
lanciano i comandi e si carica il file di log.

Il server divide il log a ogni comando riconosciuto e lo salva nel formato
del triage: config, poi le sezioni dei vicini e dell'inventario. Un file senza
comandi riconoscibili (per esempio il backup `.conf` scaricato dalla GUI di
un FortiGate) viene salvato così com'è.

Il dispositivo ha trasporto `manual`: nessun ping, triage, SNMP o sessione
CLI parte verso di esso. Per aggiornarlo si carica una nuova config dalla sua
riga in *Dispositivi*; ogni caricamento è una versione in Config drift.
```

- [ ] **Step 3: Full gate**

Run, and read each output:
```bash
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run pytest tests -n 4
uv run python scripts/check_no_private_data.py
graphify update .
```
Expected: 0 pyrefly errors, frontend clean, all tests green, no private data. If `graphify update .` refuses because the graph shrank, check what shrank before anything else (AGENTS.md) — do not pass `--force` blindly.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md docs/operations.md
git commit -m "docs: manual config upload for unreachable devices"
```

- [ ] **Step 5: Rebuild the executable**

Run: `uv run pyinstaller SentinelNet.spec`
Expected: build completes; `static/js/manual-config.js` ships because `static/` is bundled whole.
