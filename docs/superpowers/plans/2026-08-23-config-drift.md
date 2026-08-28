# Config Drift Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every device a config history and a per-tenant baseline, so an operator can ask "what changed on this network" and "does this device still match our standard".

**Architecture:** Config versions are archived beside the existing backup file, never replacing it, because the current file's path is a contract four other features depend on. A vendor-aware normaliser strips volatile lines before hashing, so an unchanged device does not produce a new version every run. A new tab reads it all, filtered by tenant — which is nearly free, because the backup tree is already partitioned by tenant.

**Tech Stack:** Python 3.14, FastAPI, Pydantic v2, `unittest` (no pytest), stdlib `difflib` and `hashlib`. Frontend is classic scripts, no bundler.

**Spec:** `docs/superpowers/specs/2026-08-23-config-drift-design.md`

## Global Constraints

- **Version:** single source of truth is `core/version.py`; `pyproject.toml` must match. This feature is a MINOR bump (new module + new tab). Bump once, in the final task.
- **No CI.** GitHub Actions was removed deliberately. Never add a workflow. The gates are local: `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py`, `uv run python -m unittest discover -s tests`, then `graphify update .`.
- **Tests are `unittest.TestCase` classes.** Bare `test_*` functions in a module are NOT collected by `unittest discover` — `tests/test_switch_provisioner.py` is an existing example of that trap. Always write a TestCase.
- **No real customer data in tracked files.** `data/` is gitignored and facts derived from it are as sensitive as the files. Use RFC 5737 (`192.0.2.x`, `198.51.100.x`), `switch-01`, `<hostname>`, `AA:BB:CC:DD:EE:FF`.
- **New comments in English.** Existing Italian comments stay untouched; do not "fix" them.
- **i18n:** every user-visible string needs a key in BOTH the `it` and `en` blocks of `static/js/i18n.js`, or `tests/test_i18n_parity.py` fails.
- **Frontend rules:** no inline `onclick=`; `core.js` globals are `let`, so they are NOT `window` properties (`window.globalDevices` is always `undefined`); anything cross-module needs `window.X = ...` **and** an entry in `types/globals.d.ts`; every interpolated value goes through `escapeHtml`.
- **Never widen a secret's reach.** Diffs and seeded patterns pass through `security/redaction.py` at the point they are produced.
- Commit after every task.

---

### Task 1: Vendor-aware normalisation

Volatile lines are why this feature would otherwise report drift on every run. This task is pure text in, text out — no I/O, no dependencies.

**Files:**
- Create: `services/config_drift/__init__.py`
- Create: `services/config_drift/normalize.py`
- Test: `tests/test_config_drift_normalize.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `normalize(vendor: str, text: str) -> str` — the config with volatile lines removed, for hashing and diffing only. An unknown or empty vendor returns the text with only the vendor-neutral rules applied.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""Volatile lines must not read as configuration changes.

Every one of these appears in a real backup and changes without anyone
touching the device. If they survive normalisation, the archive grows a new
version on every collection run and the whole feature becomes noise.
"""
import unittest

from services.config_drift import normalize


class VolatileLinesAreStripped(unittest.TestCase):
    def test_ios_byte_count_and_timestamps_are_ignored(self):
        first = (
            "Building configuration...\n"
            "Current configuration : 48210 bytes\n"
            "! Last configuration change at 10:02:11 UTC Mon Aug 19 2026\n"
            "hostname switch-01\n"
            "ntp clock-period 17179860\n"
        )
        second = (
            "Building configuration...\n"
            "Current configuration : 48244 bytes\n"
            "! Last configuration change at 03:14:07 UTC Fri Aug 22 2026\n"
            "hostname switch-01\n"
            "ntp clock-period 17179902\n"
        )
        self.assertEqual(normalize.normalize("cisco_ios", first),
                         normalize.normalize("cisco_ios", second))

    def test_a_real_ios_change_survives(self):
        base = "hostname switch-01\nip http server\n"
        changed = "hostname switch-01\nno ip http server\n"
        self.assertNotEqual(normalize.normalize("cisco_ios", base),
                            normalize.normalize("cisco_ios", changed))

    def test_fortios_config_header_is_ignored(self):
        first = "#config-version=FGT-7.4.1-FW-build2463-230314:opmode=0\nconfig system global\n"
        second = "#config-version=FGT-7.4.1-FW-build2470-230501:opmode=0\nconfig system global\n"
        self.assertEqual(normalize.normalize("fortigate", first),
                         normalize.normalize("fortigate", second))

    def test_a_real_fortios_change_survives(self):
        base = 'config system global\n    set hostname "fw-01"\nend\n'
        changed = 'config system global\n    set hostname "fw-02"\nend\n'
        self.assertNotEqual(normalize.normalize("fortigate", base),
                            normalize.normalize("fortigate", changed))

    def test_an_unknown_vendor_still_normalises_whitespace(self):
        self.assertEqual(normalize.normalize("", "hostname switch-01   \n\n\n"),
                         normalize.normalize("weird-os", "hostname switch-01\n"))

    def test_normalisation_is_idempotent(self):
        text = "Current configuration : 10 bytes\nhostname switch-01\n"
        once = normalize.normalize("cisco_ios", text)
        self.assertEqual(once, normalize.normalize("cisco_ios", once))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_config_drift_normalize -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'services.config_drift'`

- [ ] **Step 3: Implement the minimal code to make the test pass**

Create `services/config_drift/__init__.py` as an empty file (a package marker only — do not re-export anything from it, so importing one submodule does not drag in the others).

Create `services/config_drift/normalize.py`:

```python
# -*- coding: utf-8 -*-
"""Strip the parts of a config that change on their own.

A device rewrites byte counts, timestamps and clock drift without anyone
configuring anything. Hashing the raw text would archive a new version on
every collection run, so drift detection compares configs with those lines
removed.

This applies to the HASH and the DIFF only. The archived file is always the
config exactly as collected — a stripped archive could not be read back or
restored from.
"""
import re

# Lines that change by themselves, whatever the vendor is.
_COMMON = (
    re.compile(r"^\s*Building configuration\.\.\.\s*$", re.IGNORECASE),
    re.compile(r"^\s*$"),
)

_IOS = (
    re.compile(r"^\s*Current configuration\s*:\s*\d+\s*bytes\s*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*Last configuration change .*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*NVRAM config last updated .*$", re.IGNORECASE),
    re.compile(r"^\s*ntp clock-period\s+\d+\s*$", re.IGNORECASE),
    re.compile(r"^\s*!\s*Time:\s.*$", re.IGNORECASE),
)

_FORTIOS = (
    re.compile(r"^\s*#config-version=.*$", re.IGNORECASE),
    re.compile(r"^\s*#conf_file_ver=.*$", re.IGNORECASE),
    re.compile(r"^\s*#buildno=.*$", re.IGNORECASE),
    re.compile(r"^\s*#global_vdom=.*$", re.IGNORECASE),
)

# Vendor strings as they appear in the inventory's Vendor column.
_BY_VENDOR = {
    "cisco_ios": _IOS,
    "cisco_ios_xe": _IOS,
    "cisco_wlc": _IOS,
    "fortigate": _FORTIOS,
    "fortinet": _FORTIOS,
}


def normalize(vendor: str, text: str) -> str:
    """Return ``text`` without the lines that change on their own.

    An unknown vendor gets the vendor-neutral rules only: noisier drift is an
    acceptable answer, a crash or a skipped device is not.
    """
    patterns = _COMMON + _BY_VENDOR.get((vendor or "").strip().lower(), ())
    kept = [line.rstrip()
            for line in (text or "").splitlines()
            if not any(p.match(line) for p in patterns)]
    return "\n".join(kept) + "\n" if kept else ""
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `uv run python -m unittest tests.test_config_drift_normalize -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add services/config_drift/ tests/test_config_drift_normalize.py
git commit -m "feat(drift): normalise the config lines that change on their own"
```

---

### Task 2: The history store

Archive a version when the config actually changed, and record that we looked when it did not.

**Files:**
- Create: `services/config_drift/history.py`
- Test: `tests/test_config_drift_history.py`

**Interfaces:**
- Consumes: `normalize.normalize(vendor, text)` from Task 1.
- Produces:
  - `record_version(device: dict, config_text: str) -> bool` — True when a new version was archived, False when unchanged. `device` is an inventory row: keys `IP`, `Group`, `Vendor`, `Hostname`.
  - `list_versions(device: dict) -> list[dict]` — newest first, each `{"hash", "seen_at", "size", "file"}`.
  - `read_version(device: dict, seen_at: str) -> str` — archived text; `""` if absent.
  - `last_seen_at(device: dict) -> str` — `""` if never collected.
  - `history_dir(device: dict) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""Config history: a version per real change, and nothing on a no-op run.

RFC 5737 addresses and placeholder hostnames only.
"""
import tempfile
import unittest
from unittest import mock

DEVICE = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco_ios",
          "Hostname": "switch-01"}


class HistoryRecordsOnlyRealChanges(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_first_collection_creates_one_version(self):
        from services.config_drift import history
        self.assertTrue(history.record_version(DEVICE, "hostname switch-01\n"))
        self.assertEqual(1, len(history.list_versions(DEVICE)))

    def test_recollecting_the_same_config_creates_no_version(self):
        from services.config_drift import history
        history.record_version(DEVICE, "hostname switch-01\n")
        self.assertFalse(history.record_version(DEVICE, "hostname switch-01\n"))
        self.assertEqual(1, len(history.list_versions(DEVICE)))

    def test_volatile_lines_alone_are_not_a_change(self):
        from services.config_drift import history
        history.record_version(
            DEVICE, "Current configuration : 10 bytes\nhostname switch-01\n")
        self.assertFalse(history.record_version(
            DEVICE, "Current configuration : 99 bytes\nhostname switch-01\n"))

    def test_a_real_change_creates_a_second_version(self):
        from services.config_drift import history
        history.record_version(DEVICE, "hostname switch-01\n")
        self.assertTrue(history.record_version(
            DEVICE, "hostname switch-01\nip http server\n"))
        versions = history.list_versions(DEVICE)
        self.assertEqual(2, len(versions))
        self.assertGreaterEqual(versions[0]["seen_at"], versions[1]["seen_at"])

    def test_the_archived_text_is_raw_not_normalised(self):
        from services.config_drift import history
        raw = "Current configuration : 10 bytes\nhostname switch-01\n"
        history.record_version(DEVICE, raw)
        history.record_version(DEVICE, "hostname switch-02\n")
        first = history.list_versions(DEVICE)[-1]
        self.assertIn("Current configuration",
                      history.read_version(DEVICE, first["seen_at"]))

    def test_last_seen_is_updated_even_with_no_change(self):
        from services.config_drift import history
        history.record_version(DEVICE, "hostname switch-01\n")
        first = history.last_seen_at(DEVICE)
        with mock.patch("services.config_drift.history._now",
                        return_value="20260822T031407Z"):
            history.record_version(DEVICE, "hostname switch-01\n")
        self.assertNotEqual(first, history.last_seen_at(DEVICE))

    def test_an_unknown_device_has_no_versions(self):
        from services.config_drift import history
        self.assertEqual([], history.list_versions(
            {"IP": "192.0.2.99", "Group": "ACME", "Vendor": "cisco_ios"}))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_config_drift_history -v`
Expected: FAIL — no module `services.config_drift.history`.

- [ ] **Step 3: Implement the minimal code to make the test pass**

Create `services/config_drift/history.py`:

```python
# -*- coding: utf-8 -*-
"""Per-device config history, stored beside the current backup.

The current backup file keeps its exact path and name: the policy test loader,
the netsec audit, the config analyzer and download_backup all read it. History
is therefore additive — a '.history' folder next to it, and nothing else moves.
"""
import hashlib
import json
import os
import time

from services.config_drift import normalize

_INDEX = "index.json"


def _now() -> str:
    """UTC stamp used both as the version id and in the archived filename."""
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _device_dir(device: dict) -> str:
    from core import core_engine
    return core_engine.group_backup_dir(device.get("Group") or "Generale",
                                        device.get("Vendor") or "")


def history_dir(device: dict) -> str:
    path = os.path.join(_device_dir(device), ".history")
    os.makedirs(path, exist_ok=True)
    return path


def _index_path(device: dict) -> str:
    return os.path.join(history_dir(device), f"{device['IP']}-{_INDEX}")


def _load_index(device: dict) -> dict:
    try:
        with open(_index_path(device), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        # No history yet, or a truncated write. Either way the device has no
        # known past: recording the current config re-creates it.
        return {"device": device.get("IP", ""), "versions": [], "last_seen_at": ""}


def _save_index(device: dict, index: dict) -> None:
    with open(_index_path(device), "w", encoding="utf-8") as fh:
        json.dump(index, fh, indent=1)


def _digest(device: dict, config_text: str) -> str:
    body = normalize.normalize(device.get("Vendor") or "", config_text)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def record_version(device: dict, config_text: str) -> bool:
    """Archive ``config_text`` if it differs from the newest known version.

    Returns True when a version was archived. An unchanged config only updates
    last_seen_at, so the UI can tell "unchanged for 14 days" from "not
    collected for 14 days".
    """
    from core import core_engine
    index = _load_index(device)
    stamp = _now()
    index["device"] = device.get("IP", "")
    index["last_seen_at"] = stamp

    digest = _digest(device, config_text)
    versions = index.setdefault("versions", [])
    if versions and versions[0].get("hash") == digest:
        _save_index(device, index)
        return False

    name = core_engine.sanitize_filename(device.get("Hostname") or device["IP"])
    filename = f"{name}-{device['IP']}.{stamp}.txt"
    with open(os.path.join(history_dir(device), filename), "w", encoding="utf-8") as fh:
        fh.write(config_text)
    versions.insert(0, {"hash": digest, "seen_at": stamp,
                        "size": len(config_text), "file": filename})
    _save_index(device, index)
    return True


def list_versions(device: dict) -> list:
    """Every retained version, newest first."""
    return _load_index(device).get("versions", [])


def last_seen_at(device: dict) -> str:
    return _load_index(device).get("last_seen_at", "")


def read_version(device: dict, seen_at: str) -> str:
    """The archived config text for one version, or '' if it is not there."""
    entry = next((v for v in list_versions(device) if v.get("seen_at") == seen_at), None)
    if not entry:
        return ""
    try:
        with open(os.path.join(history_dir(device), entry["file"]), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `uv run python -m unittest tests.test_config_drift_history -v`
Expected: PASS, 7 tests.

Note: `test_last_seen_is_updated_even_with_no_change` patches `_now`, so the second stamp differs even when both calls land in the same second.

- [ ] **Step 5: Commit**

```bash
git add services/config_drift/history.py tests/test_config_drift_history.py
git commit -m "feat(drift): archive a config version per real change"
```

---

### Task 3: Collect history on every backup, and stop deleting it

Two edits in `core/core_engine.py`. The second is the dangerous one: today, moving a device to another tenant deletes its config, and with history in place it would delete the whole archive.

**Files:**
- Modify: `core/core_engine.py` — `remove_stale_backups()` (around line 81), `save_backup()` (line 69), `run_backup_and_triage()` (around line 321), `_fortigate_backup_and_triage()` (around line 261)
- Test: `tests/test_config_drift_history.py` (add a TestCase)

**Interfaces:**
- Consumes: `history.record_version` from Task 2.
- Produces: `remove_stale_backups(ip, new_dir=None)` — same name, one new optional argument; moves instead of deleting when given a destination.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config_drift_history.py`, before the `if __name__` block:

```python
class ChangingTenantKeepsTheHistory(unittest.TestCase):
    """A device moving between tenants is a normal operational event. It used
    to delete the device's config; with history it would delete the archive."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch("core.core_engine.BACKUP_FOLDER", self._tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._tmp.cleanup)

    def test_history_follows_the_device_to_the_new_tenant(self):
        from core import core_engine
        from services.config_drift import history

        history.record_version(DEVICE, "hostname switch-01\n")
        history.record_version(DEVICE, "hostname switch-01\nip http server\n")
        self.assertEqual(2, len(history.list_versions(DEVICE)))

        moved = dict(DEVICE, Group="BETA")
        core_engine.save_backup(moved, "switch-01", "hostname switch-01\n")

        self.assertEqual(2, len(history.list_versions(moved)))
        self.assertEqual([], history.list_versions(DEVICE))
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_config_drift_history.ChangingTenantKeepsTheHistory -v`
Expected: FAIL — the moved device has 0 versions, because `remove_stale_backups` deleted the old folder's files and nothing carried the archive across.

- [ ] **Step 3: Write the minimal implementation**

In `core/core_engine.py`, replace `remove_stale_backups` entirely:

```python
def remove_stale_backups(ip: str, new_dir: Optional[str] = None):
    """Move a device's backup and its history when it changes group/vendor.

    This used to delete every file for the IP found anywhere in the tree. With
    a config archive beside the backup, deleting would throw away the device's
    whole history because someone re-assigned it to another tenant — a normal
    operational event. Files move to ``new_dir`` instead; with no destination
    there is nothing to preserve them for and they are removed, as before.
    """
    if not os.path.exists(BACKUP_FOLDER):
        return
    for root, _dirs, files in os.walk(BACKUP_FOLDER):
        if new_dir and os.path.abspath(root) == os.path.abspath(new_dir):
            continue
        for f in files:
            if not (f.endswith(f"-{ip}.txt") or f.endswith(f"_{ip}.txt") or f == f"{ip}.txt"):
                continue
            src = os.path.join(root, f)
            try:
                if new_dir:
                    os.makedirs(new_dir, exist_ok=True)
                    os.replace(src, os.path.join(new_dir, f))
                else:
                    os.remove(src)
            except OSError as e:
                logging.warning(f"Backup obsoleto non spostato ({f}): {e}")
        _move_history(root, ip, new_dir)


def _move_history(root: str, ip: str, new_dir: Optional[str]) -> None:
    """Carry the device's .history entries across with its current backup."""
    src_hist = os.path.join(root, ".history")
    if not new_dir or not os.path.isdir(src_hist):
        return
    dst_hist = os.path.join(new_dir, ".history")
    if os.path.abspath(src_hist) == os.path.abspath(dst_hist):
        return
    os.makedirs(dst_hist, exist_ok=True)
    for f in os.listdir(src_hist):
        if f"-{ip}." in f or f.startswith(f"{ip}-"):
            try:
                os.replace(os.path.join(src_hist, f), os.path.join(dst_hist, f))
            except OSError as e:
                logging.warning(f"Storico non spostato ({f}): {e}")
```

Then change the first statements of `save_backup` so the move has a destination:

```python
def save_backup(device, sys_name: str, config_out: str) -> str:
    """Saves the text backup in backup-config/<group>/<vendor>/<name>-<ip>.txt,
    moving first any residual copies of the same IP elsewhere."""
    ip = device['IP']
    group_dir = group_backup_dir(device.get('Group', 'Generale'),
                                 device.get('Vendor', ''))
    remove_stale_backups(ip, new_dir=group_dir)
    file_path = os.path.join(group_dir, f"{sanitize_filename(sys_name)}-{ip}.txt")
```

The rest of `save_backup` is unchanged — note `group_dir` is now computed *before* the call instead of after it.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `uv run python -m unittest tests.test_config_drift_history -v`
Expected: PASS, 8 tests.

Then confirm nothing else relied on the delete behaviour:
Run: `uv run python -m unittest discover -s tests`
Expected: OK. If a backup or scan test fails, read it — an assertion that a moved device's old file is *gone* still holds (it moved), but one counting files in a folder may need its expectation updated.

- [ ] **Step 5: Hook detection into the collection path**

In `run_backup_and_triage(device)`, find the `save_backup(...)` call and add immediately after it, matching the surrounding indentation and using the local variable that actually holds the config text:

```python
        # The single point every collected config flows through: no second
        # scheduler and no separate collection path for drift.
        try:
            from services.config_drift import history
            history.record_version(device, config_out)
        except Exception as e:
            # History is an observer. A failure here must never fail a backup
            # that succeeded.
            logging.warning(f"Storico config non aggiornato per {device.get('IP')}: {e}")
```

Do the same in `_fortigate_backup_and_triage(device)`, which has its own save path.

- [ ] **Step 6: Run the gates and commit**

```bash
uv run pyrefly check
uv run python -m unittest discover -s tests
git add core/core_engine.py tests/test_config_drift_history.py
git commit -m "feat(drift): record a version on every backup, and move history instead of deleting it"
```

---

### Task 4: Optional git mirror for redundancy

A second copy of the archive. It is never read back — the `.history` archive is the only source of truth.

**Files:**
- Create: `services/config_drift/mirror.py`
- Modify: `services/config_drift/history.py` — call the mirror after a version is archived
- Test: `tests/test_config_drift_mirror.py`

**Interfaces:**
- Consumes: `history.history_dir`.
- Produces: `is_enabled() -> bool`, `enable() -> None` (raises `MirrorUnavailable`), `disable() -> None`, `commit_version(device: dict, filename: str) -> None`, `MirrorUnavailable(Exception)`.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""The git mirror is redundancy: a second copy, never a second source.

A redundancy feature that silently is not running is worse than one that is
off, so enabling it without git must fail loudly.
"""
import unittest
from unittest import mock

from services.config_drift import mirror

DEVICE = {"IP": "192.0.2.10", "Group": "ACME", "Vendor": "cisco_ios"}


class TheMirrorFailsLoudly(unittest.TestCase):
    def test_enabling_without_git_raises(self):
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaises(mirror.MirrorUnavailable):
                mirror.enable()

    def test_a_disabled_mirror_commits_nothing(self):
        with mock.patch.object(mirror, "is_enabled", return_value=False), \
             mock.patch("subprocess.run") as run:
            mirror.commit_version(DEVICE, "switch-01.txt")
        run.assert_not_called()

    def test_an_enabled_mirror_commits(self):
        with mock.patch.object(mirror, "is_enabled", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/git"), \
             mock.patch("subprocess.run") as run:
            mirror.commit_version(DEVICE, "switch-01.txt")
        self.assertTrue(run.called)

    def test_a_git_failure_never_escapes(self):
        import subprocess
        with mock.patch.object(mirror, "is_enabled", return_value=True), \
             mock.patch("shutil.which", return_value="/usr/bin/git"), \
             mock.patch("subprocess.run",
                        side_effect=subprocess.CalledProcessError(1, "git")):
            mirror.commit_version(DEVICE, "switch-01.txt")   # must not raise


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_config_drift_mirror -v`
Expected: FAIL — no module `services.config_drift.mirror`.

- [ ] **Step 3: Write the minimal implementation**

```python
# -*- coding: utf-8 -*-
"""Optional git mirror of the config archive — redundancy, not a backend.

The '.history' archive is the source of truth and the only thing the drift
engine reads. This module keeps a second copy in a git repository so the
archive survives losing the folder. Nothing here is ever read back.
"""
import logging
import os
import shutil
import subprocess

_SETTING = "config_drift_git_mirror"


class MirrorUnavailable(Exception):
    """git is not usable on this host, so the mirror cannot be turned on."""


def _git() -> str:
    path = shutil.which("git")
    if not path:
        raise MirrorUnavailable(
            "git non e' installato su questo host: il mirror di ridondanza "
            "non puo' essere attivato.")
    return path


def is_enabled() -> bool:
    from core.app_settings import get_app_settings
    return bool(get_app_settings().get(_SETTING))


def enable() -> None:
    """Turn the mirror on, refusing if git is missing."""
    from core.app_settings import get_app_settings, save_app_settings
    _git()
    settings = get_app_settings()
    settings[_SETTING] = True
    save_app_settings(settings)


def disable() -> None:
    from core.app_settings import get_app_settings, save_app_settings
    settings = get_app_settings()
    settings[_SETTING] = False
    save_app_settings(settings)


def commit_version(device: dict, filename: str) -> None:
    """Commit one archived version. Never raises into the collection path."""
    if not is_enabled():
        return
    from services.config_drift import history
    repo = history.history_dir(device)
    try:
        git = _git()
        if not os.path.isdir(os.path.join(repo, ".git")):
            subprocess.run([git, "init", "-q"], cwd=repo, check=True)
        subprocess.run([git, "add", "--", filename], cwd=repo, check=True)
        subprocess.run([git, "commit", "-q", "-m", f"{device.get('IP')} {filename}"],
                       cwd=repo, check=True)
    except (OSError, subprocess.SubprocessError, MirrorUnavailable) as e:
        logging.warning(f"Mirror git non aggiornato per {device.get('IP')}: {e}")
```

In `services/config_drift/history.py`, at the end of `record_version`, immediately before `return True`:

```python
    from services.config_drift import mirror
    mirror.commit_version(device, filename)
    return True
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `uv run python -m unittest tests.test_config_drift_mirror tests.test_config_drift_history -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services/config_drift/mirror.py services/config_drift/history.py tests/test_config_drift_mirror.py
git commit -m "feat(drift): optional git mirror of the config archive"
```

---

### Task 5: Tenant baseline matching

Required and forbidden line patterns, owned by a tenant. No score, no severity.

**Files:**
- Create: `services/config_drift/baseline.py`
- Test: `tests/test_config_drift_baseline.py`

**Interfaces:**
- Consumes: `normalize.normalize`, `security.redaction.redact`.
- Produces:
  - `parse(text: str) -> list[dict]` — `{"rule": "+"|"-", "pattern": str, "regex": bool}`
  - `evaluate(vendor: str, config_text: str, baseline_text: str) -> list[dict]` — deviations only, `{"rule", "pattern", "problem"}` where `problem` is `"missing"` or `"present"`
  - `load(tenant: str) -> str`, `save(tenant: str, text: str) -> None`
  - `seed_from_config(vendor: str, config_text: str) -> str`

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""A tenant baseline: which lines must be there, which must not.

Deliberately not an audit — no score, no grade, no severity. One answer per
pattern: present, or missing.
"""
import unittest

from services.config_drift import baseline

CONFIG = (
    "hostname switch-01\n"
    "ip dhcp snooping\n"
    "ip http server\n"
    "login block-for 120 attempts 5 within 60\n"
)

BASELINE = (
    "+ ip dhcp snooping\n"
    "+ service password-encryption\n"
    "- ip http server\n"
    "- transport input telnet\n"
)


class BaselineMatching(unittest.TestCase):
    def test_a_missing_required_line_is_a_deviation(self):
        problems = baseline.evaluate("cisco_ios", CONFIG, BASELINE)
        missing = [p for p in problems if p["problem"] == "missing"]
        self.assertEqual(["service password-encryption"],
                         [p["pattern"] for p in missing])

    def test_a_present_forbidden_line_is_a_deviation(self):
        problems = baseline.evaluate("cisco_ios", CONFIG, BASELINE)
        present = [p for p in problems if p["problem"] == "present"]
        self.assertEqual(["ip http server"], [p["pattern"] for p in present])

    def test_a_compliant_config_has_no_deviations(self):
        config = "ip dhcp snooping\nservice password-encryption\n"
        self.assertEqual([], baseline.evaluate("cisco_ios", config, BASELINE))

    def test_a_regex_pattern_is_honoured(self):
        self.assertEqual([], baseline.evaluate(
            "cisco_ios", "banner motd ^C Reserved ^C\n", "+ /banner motd/\n"))

    def test_a_malformed_regex_is_not_a_crash(self):
        problems = baseline.evaluate("cisco_ios", CONFIG, "+ /[unclosed/\n")
        self.assertEqual("missing", problems[0]["problem"])

    def test_blank_lines_and_comments_are_ignored(self):
        self.assertEqual(1, len(baseline.parse("\n# a comment\n+ ip dhcp snooping\n")))

    def test_a_line_without_a_marker_is_ignored(self):
        self.assertEqual([], baseline.parse("ip dhcp snooping\n"))

    def test_an_empty_baseline_reports_nothing(self):
        self.assertEqual([], baseline.evaluate("cisco_ios", CONFIG, ""))


class SeedingProposesRulesWithoutSecrets(unittest.TestCase):
    def test_security_lines_are_proposed_as_required(self):
        seeded = baseline.seed_from_config("cisco_ios", CONFIG)
        self.assertIn("+ ip dhcp snooping", seeded)

    def test_device_identity_is_not_proposed(self):
        """hostname and addresses differ per device by design: a baseline
        containing them would fail on the second switch."""
        self.assertNotIn("hostname", baseline.seed_from_config("cisco_ios", CONFIG))

    def test_a_seeded_rule_carries_no_secret(self):
        seeded = baseline.seed_from_config(
            "cisco_ios", "snmp-server group G v3 priv\nlogging host 192.0.2.50\n")
        self.assertNotIn("Sup3r", seeded)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_config_drift_baseline -v`
Expected: FAIL — no module `services.config_drift.baseline`.

- [ ] **Step 3: Write the minimal implementation**

```python
# -*- coding: utf-8 -*-
"""Per-tenant config baseline: required and forbidden lines.

A whole-file diff against a golden config produces noise, not signal: every
device legitimately differs in hostname, management address, VLAN set and port
ranges. So the baseline is a set of line rules instead.

This is not an audit. There is no score, no grade and no severity — the netsec
audit already owns that question, with its own benchmarks and export.
"""
import json
import re

from services.config_drift import normalize


def _store_path() -> str:
    from core import data_config
    return data_config.get_path("config_baselines.json")


def parse(text: str) -> list:
    """Turn baseline text into rules. Unmarked lines and comments are ignored,
    so a half-typed line never silently becomes a requirement."""
    rules = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line[0] not in "+-":
            continue
        pattern = line[1:].strip()
        if not pattern:
            continue
        is_regex = len(pattern) > 1 and pattern.startswith("/") and pattern.endswith("/")
        rules.append({"rule": line[0],
                      "pattern": pattern[1:-1] if is_regex else pattern,
                      "regex": is_regex})
    return rules


def _matches(rule: dict, config_text: str) -> bool:
    if rule["regex"]:
        try:
            return re.search(rule["pattern"], config_text, re.MULTILINE) is not None
        except re.error:
            # A malformed regex is the operator's typo, not a deviation: treat
            # it as unmatched rather than crashing the whole report.
            return False
    return rule["pattern"] in config_text


def evaluate(vendor: str, config_text: str, baseline_text: str) -> list:
    """Return only the deviations: required lines missing, forbidden present."""
    body = normalize.normalize(vendor, config_text)
    problems = []
    for rule in parse(baseline_text):
        found = _matches(rule, body)
        if rule["rule"] == "+" and not found:
            problems.append({"rule": "+", "pattern": rule["pattern"], "problem": "missing"})
        elif rule["rule"] == "-" and found:
            problems.append({"rule": "-", "pattern": rule["pattern"], "problem": "present"})
    return problems


def _load_all() -> dict:
    try:
        with open(_store_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def load(tenant: str) -> str:
    return _load_all().get(tenant, "")


def save(tenant: str, text: str) -> None:
    store = _load_all()
    store[tenant] = text or ""
    with open(_store_path(), "w", encoding="utf-8") as fh:
        json.dump(store, fh, indent=1)


# Lines worth proposing as a baseline: the security-relevant surface, not the
# device's own identity. Hostname, addresses and VLANs differ per device by
# design, and a baseline containing them would fail on the second switch.
_SEED_PREFIXES = (
    "service password-encryption", "ip dhcp snooping", "login block-for",
    "aaa new-model", "aaa authentication", "aaa authorization",
    "spanning-tree portfast bpduguard", "no ip http", "ip ssh",
    "snmp-server group", "logging host", "ntp server",
    "set strong-crypto", "set admin-lockout", "config system snmp",
)


def seed_from_config(vendor: str, config_text: str) -> str:
    """Candidate '+' rules from one device's config, for the operator to prune."""
    from security import redaction
    body = normalize.normalize(vendor, config_text)
    seen, out = set(), []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith(_SEED_PREFIXES):
            continue
        safe = redaction.redact(stripped)
        if safe not in seen:
            seen.add(safe)
            out.append(f"+ {safe}")
    return "\n".join(out) + "\n" if out else ""
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `uv run python -m unittest tests.test_config_drift_baseline -v`
Expected: PASS, 11 tests.

- [ ] **Step 5: Commit**

```bash
git add services/config_drift/baseline.py tests/test_config_drift_baseline.py
git commit -m "feat(drift): per-tenant baseline of required and forbidden lines"
```

---

### Task 6: The API

Every route scoped. Every diff redacted.

**Files:**
- Create: `routers/config_drift.py`
- Modify: `app_server.py` — import and `include_router` beside the others (around line 98)
- Modify: `tests/test_router_parity.py` — add `/api/drift` to the new-prefix allow-lists
- Test: `tests/test_config_drift_api.py`

**Interfaces:**
- Consumes: Tasks 1-5, plus `routers.deps.user_group_scope`, `assert_device_allowed`, `require_operator`, `require_admin`.
- Produces: `_unified(vendor, before, after, a_label, b_label) -> str` and the seven routes from the spec.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""Drift API: tenant isolation is enforced, and diffs carry no secrets."""
import unittest

from routers import config_drift


class ADiffNeverLeaksASecret(unittest.TestCase):
    """A config diff is dense with credentials. The operator does not need the
    secret in order to read the change."""

    def test_secrets_are_masked_in_the_unified_diff(self):
        before = "enable secret Sup3r-Enable\nhostname switch-01\n"
        after = "enable secret N3w-Enable\nhostname switch-02\n"
        diff = config_drift._unified("cisco_ios", before, after, "a", "b")
        self.assertNotIn("Sup3r-Enable", diff)
        self.assertNotIn("N3w-Enable", diff)
        self.assertIn("switch-02", diff)

    def test_an_identical_pair_produces_an_empty_diff(self):
        text = "hostname switch-01\n"
        self.assertEqual("", config_drift._unified("cisco_ios", text, text, "a", "b"))


class TenantIsolationIsEnforced(unittest.TestCase):
    """Scoping must not be cosmetic: a scoped user guessing an IP outside
    their tenant is refused, exactly as on every other device route."""

    def test_every_device_route_asserts_the_device_is_allowed(self):
        import inspect
        source = inspect.getsource(config_drift)
        self.assertGreaterEqual(source.count("assert_device_allowed"), 1)
        self.assertIn("_device_or_404", source)

    def test_the_device_list_is_filtered_by_scope(self):
        import inspect
        self.assertIn("user_group_scope", inspect.getsource(config_drift))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_config_drift_api -v`
Expected: FAIL — no module `routers.config_drift`.

- [ ] **Step 3: Write the minimal implementation**

```python
# -*- coding: utf-8 -*-
"""Router Config Drift: cosa e' cambiato, e cosa non rispetta lo standard."""

import difflib

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers.deps import (require_operator, require_admin, user_group_scope,
                          assert_device_allowed)
from security.security_manager import log_audit
from security import redaction
from services import inventory_manager
from services.config_drift import baseline, history, normalize

router = APIRouter(tags=["Config Drift"])


class BaselineSchema(BaseModel):
    text: str = ""


def _unified(vendor: str, before: str, after: str, a_label: str, b_label: str) -> str:
    """A redacted unified diff of two normalised configs.

    Redaction happens here, where the diff is produced, so no caller can forget
    it: this text is rendered straight into a browser.
    """
    diff = difflib.unified_diff(
        normalize.normalize(vendor, before).splitlines(),
        normalize.normalize(vendor, after).splitlines(),
        fromfile=a_label, tofile=b_label, lineterm="")
    return redaction.redact("\n".join(diff))


def _device_or_404(current_user, ip: str) -> dict:
    device = assert_device_allowed(current_user, ip)
    if not device:
        raise HTTPException(status_code=404, detail=f"Apparato {ip} non trovato.")
    return device


@router.get("/api/drift/devices")
def drift_devices(current_user=Depends(require_operator)):
    """Devices the caller may see, with when they last changed."""
    scope = user_group_scope(current_user)
    out = []
    for device in inventory_manager.get_all_devices():
        if scope is not None and device.get("Group") not in scope:
            continue
        versions = history.list_versions(device)
        out.append({
            "ip": device.get("IP"),
            "hostname": device.get("Hostname"),
            "tenant": device.get("Group"),
            "vendor": device.get("Vendor"),
            "versions": len(versions),
            "last_change": versions[0]["seen_at"] if versions else "",
            "last_seen": history.last_seen_at(device),
        })
    return {"devices": out}


@router.get("/api/drift/{ip}/versions")
def drift_versions(ip: str, current_user=Depends(require_operator)):
    return {"versions": history.list_versions(_device_or_404(current_user, ip))}


@router.get("/api/drift/{ip}/diff")
def drift_diff(ip: str, from_version: str = "", to_version: str = "",
               current_user=Depends(require_operator)):
    """Redacted diff between two archived versions of one device."""
    device = _device_or_404(current_user, ip)
    before = history.read_version(device, from_version)
    after = history.read_version(device, to_version)
    if not before or not after:
        raise HTTPException(status_code=404, detail="Versione non trovata.")
    return {"diff": _unified(device.get("Vendor") or "", before, after,
                             from_version, to_version)}


@router.get("/api/drift/baseline/{tenant}")
def drift_baseline_get(tenant: str, current_user=Depends(require_operator)):
    scope = user_group_scope(current_user)
    if scope is not None and tenant not in scope:
        raise HTTPException(status_code=403, detail="Tenant non consentito.")
    return {"tenant": tenant, "text": baseline.load(tenant)}


@router.put("/api/drift/baseline/{tenant}")
def drift_baseline_put(tenant: str, payload: BaselineSchema,
                       current_user=Depends(require_admin)):
    baseline.save(tenant, payload.text)
    log_audit(f"Baseline config del tenant '{tenant}' aggiornata da "
              f"'{current_user.get('sub')}'.")
    return {"status": "success"}


@router.post("/api/drift/baseline/{tenant}/seed")
def drift_baseline_seed(tenant: str, ip: str, current_user=Depends(require_admin)):
    """Candidate rules from one device, for the operator to prune. Saves nothing."""
    device = _device_or_404(current_user, ip)
    versions = history.list_versions(device)
    if not versions:
        raise HTTPException(status_code=404, detail="Nessuna configurazione archiviata.")
    text = history.read_version(device, versions[0]["seen_at"])
    return {"text": baseline.seed_from_config(device.get("Vendor") or "", text)}


@router.get("/api/drift/{ip}/baseline")
def drift_device_baseline(ip: str, current_user=Depends(require_operator)):
    device = _device_or_404(current_user, ip)
    versions = history.list_versions(device)
    if not versions:
        return {"deviations": [], "checked": False}
    text = history.read_version(device, versions[0]["seen_at"])
    rules = baseline.load(device.get("Group") or "")
    return {"deviations": baseline.evaluate(device.get("Vendor") or "", text, rules),
            "checked": bool(rules)}
```

In `app_server.py`, beside the other router imports and includes:

```python
from routers import config_drift as _config_drift_router
app.include_router(_config_drift_router.router)
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `uv run python -m unittest tests.test_config_drift_api -v`
Expected: PASS, 4 tests.

Then: `uv run python -m unittest tests.test_router_parity -v`
Expected: FAIL on the new paths. Add `"/api/drift"` to `TestRouterParity.ALLOWED_NEW_PREFIXES` and to `TestFullParity.NEW_PREFIXES` in `tests/test_router_parity.py`. Re-run; expected PASS.

**Do NOT regenerate `tests_data/openapi_golden.json` or `openapi_pre_destructure.json`.** Their header says they are regenerated only for deliberate additions, never to make a parity failure pass — the allow-lists are the mechanism.

- [ ] **Step 5: Commit**

```bash
uv run pyrefly check
git add routers/config_drift.py app_server.py tests/test_config_drift_api.py tests/test_router_parity.py
git commit -m "feat(drift): tenant-scoped API for history, diffs and baselines"
```

---

### Task 7: The Config Drift tab

**Files:**
- Modify: `templates/dashboard.html` — nav button beside `#navPolicyTest` (line ~228), panel beside `#tab-policy-test` (line ~3444)
- Create: `static/js/config-drift.js`
- Modify: `static/js/core.js` — `LAZY_TAB_SCRIPTS` (line ~768)
- Modify: `static/js/i18n.js` — keys in BOTH `it` and `en`
- Test: `tests/test_config_drift_tab.py`

**Interfaces:**
- Consumes: the routes from Task 6.
- Produces: the tab. Nothing is exported cross-module, so no `window.X` and no `types/globals.d.ts` entry is needed.

- [ ] **Step 1: Write the failing test**

```python
# -*- coding: utf-8 -*-
"""The Config Drift tab must be wired, translated and lazily loaded."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class TheTabIsWired(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT / "templates/dashboard.html").read_text(encoding="utf-8")
        self.core = (ROOT / "static/js/core.js").read_text(encoding="utf-8")
        self.i18n = (ROOT / "static/js/i18n.js").read_text(encoding="utf-8")

    def test_the_nav_button_and_panel_exist(self):
        self.assertIn('data-tab="tab-config-drift"', self.html)
        self.assertIn('id="tab-config-drift"', self.html)

    def test_the_module_is_lazily_loaded_for_its_tab(self):
        self.assertIn("'tab-config-drift': ['/static/js/config-drift.js']", self.core)

    def test_the_controls_it_binds_exist_in_the_template(self):
        for element_id in ("driftTenantSelect", "driftDeviceList",
                           "driftBaselineText", "btnDriftSaveBaseline",
                           "btnDriftSeedBaseline"):
            self.assertIn(f'id="{element_id}"', self.html, element_id)

    def test_no_inline_handler_was_introduced(self):
        panel = self.html.split('id="tab-config-drift"', 1)[1]
        self.assertNotIn("onclick=", panel.split("</div>")[0])

    def test_every_key_is_in_both_languages(self):
        it_block, en_block = self.i18n.split("    en: {", 1)
        for key in ("tabConfigDrift", "driftSubHistory", "driftSubBaseline",
                    "thDriftDevice", "thDriftLastChange", "thDriftLastSeen",
                    "driftNoVersions", "driftBaselineHint"):
            self.assertIn(f"{key}:", it_block, f"{key} missing from it")
            self.assertIn(f"{key}:", en_block, f"{key} missing from en")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `uv run python -m unittest tests.test_config_drift_tab -v`
Expected: FAIL on every assertion.

- [ ] **Step 3: Build the tab**

Add the nav button in `templates/dashboard.html` next to `#navPolicyTest`, copying that markup's shape exactly (same classes, same `nav-left` span):

```html
        <button id="navConfigDrift" class="nav-item" data-tab="tab-config-drift">
          <span class="nav-left" data-i18n="tabConfigDrift"><i class="fa-solid fa-code-compare"></i> Config Drift</span>
        </button>
```

Add the panel as a sibling of `#tab-policy-test`. It must contain the ids the test pins — `driftTenantSelect`, `driftDeviceList`, `driftBaselineText`, `btnDriftSaveBaseline`, `btnDriftSeedBaseline` — plus a two-button sub-tab bar (History / Baseline). Follow the WLC tab's tenant-first shape and the policy-test tab's sub-tab bar. Every label carries `data-i18n`. No inline handlers.

Add to `LAZY_TAB_SCRIPTS` in `static/js/core.js`:

```javascript
    'tab-config-drift': ['/static/js/config-drift.js'],
```

Write `static/js/config-drift.js` as an IIFE following `static/js/redundancy.js`'s shape:
- fetch `/api/drift/devices`, fill `#driftTenantSelect` with the distinct `tenant` values, render the rows for the selected tenant into `#driftDeviceList`;
- clicking a row loads `/api/drift/{ip}/versions` and, with two versions chosen, `/api/drift/{ip}/diff`;
- the Baseline sub-tab loads `/api/drift/baseline/{tenant}` into `#driftBaselineText`, `#btnDriftSaveBaseline` PUTs it, `#btnDriftSeedBaseline` POSTs the seed route and appends the result to the textarea.

Every interpolated value goes through `escapeHtml`. Every string comes from `i18n[currentLang]`.

Add all eight keys to BOTH language blocks in `static/js/i18n.js`.

- [ ] **Step 4: Run the checks**

```bash
uv run python -m unittest tests.test_config_drift_tab tests.test_i18n_parity tests.test_lazy_tab_scripts -v
uv run python scripts/check_frontend.py
```
Expected: all PASS, frontend check clean.

- [ ] **Step 5: Commit**

```bash
git add templates/dashboard.html static/js/config-drift.js static/js/core.js static/js/i18n.js tests/test_config_drift_tab.py
git commit -m "feat(drift): Config Drift tab, tenant-first, history and baseline"
```

---

### Task 8: Docs, version, and the full gate

**Files:**
- Modify: `core/version.py` and `pyproject.toml` — MINOR bump
- Modify: `docs/architecture.md`, `docs/development.md`, `docs/netsec_troubleshooting_qa_v3.md`
- Modify: `docs/superpowers/specs/2026-08-23-config-drift-design.md` — status to `shipped`

- [ ] **Step 1: Bump the version**

Read the current value in `core/version.py`, bump the MINOR component, set the identical value in `pyproject.toml` line 3.

Run: `uv run python -m unittest tests.test_version -v`
Expected: PASS.

- [ ] **Step 2: Update the docs**

Cover: the `.history` layout and that every changed version is kept; that the current backup file's path is unchanged and why; the git mirror being redundancy only and failing loudly without git; the seven routes and the tab's element ids; and that the baseline is deliberately not scored.

No real hostname, IP, model or serial in any of them.

- [ ] **Step 3: Run every gate**

```bash
uv run pyrefly check
uv run python scripts/check_frontend.py
uv run python -m unittest discover -s tests
graphify update .
```
Expected: 0 pyrefly errors, frontend clean, suite OK.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "feat(drift): config drift per tenant

History answers what changed, a per-tenant baseline answers whether it
matches the standard. Neither is scored - the netsec audit owns that.

The archive is additive: the current backup file keeps the exact path the
policy test, netsec audit, config analyzer and download_backup read. A
device that changes tenant now takes its history with it instead of having
it deleted."
```

---

## Notes for the executor

- **`remove_stale_backups` is the risky edit.** It currently deletes; Task 3 makes it move. Run the whole suite after that task, not just the drift tests.
- **Do not regenerate the OpenAPI golden snapshots.** New paths go in the allow-lists in `tests/test_router_parity.py`.
- **`services/config_drift/__init__.py` stays empty.** Re-exporting from it would make importing the normaliser pull in the git mirror and the settings store.
- **`history.record_version` must never break a backup.** It is wrapped in try/except at the call site on purpose; do not move that handling inside the function and do not let it raise.
- If a task's test passes on the first run, before you write the implementation, stop — the test is not testing what you think it is.
