# Offsite Backup Mirror Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mirror `backup-config/` (current files and `.history/`) to an SFTP host, verifiably and optionally encrypted, without the app ever reading from the remote.

**Architecture:** A new `services/cloud_backup/` package with one responsibility per module — settings (secrets via the existing Fernet vault), local state, optional payload encryption, SFTP transport, and the sync engine that walks/diffs/uploads/verifies. A thin `routers/cloud_backup.py` exposes six admin routes; `static/js/cloud-backup.js` drives them from a Settings-tab section. The local archive stays the single source of truth: v1 is write-only.

**Tech Stack:** Python 3.14, FastAPI, paramiko (already a dependency), `cryptography` Fernet (already used by `security/crypto_vault.py`), vanilla JS classic scripts (no bundler), pytest + unittest.

**Spec:** `docs/superpowers/specs/2026-08-25-cloud-backup-design.md`

## Global Constraints

- **No new dependency.** paramiko and cryptography are already in `pyproject.toml`; `SentinelNet.spec` must not need a new entry.
- **A new state file under `data/` gets its `.gitignore` entry in the same commit that creates it**, before the tool is ever run. Verify with `git status --porcelain data/` printing nothing.
- **Never write credentials.** The code reads the `key_path` and secrets the operator configured; it never creates, rotates or rewrites a key store, `users.json`, or the Fernet key file.
- **Real customer data never enters tracked files.** Tests and docs use RFC 5737 addresses (`192.0.2.x`), `switch-01`, `backup.example.net`.
- **Tenant scoping is a security gate.** `/api/cloud-backup/remote` filters by `user_group_scope(current_user)`; the other write routes are `require_admin`.
- **Bilingual UI.** Every new user-facing string needs an `it` and an `en` entry in `static/js/i18n.js`. A hardcoded string is a bug.
- **Frontend rules.** No inline `onclick`; ids + delegated listeners; `window.X` exports also declared in `types/globals.d.ts`; a module binding controls in a tab needs that tab's `LAZY_TAB_SCRIPTS` entry.
- **New comments in English.** Existing Italian comments are left alone.
- **Version:** `core/version.py` → `0.15.0` and `pyproject.toml` matched, in the final task (MINOR: new module + new settings surface).
- **Per-task green gate:** `uv run pyrefly check` (0 errors) and `uv run pytest tests -n 4`; add `uv run python scripts/check_frontend.py` when `static/js` or `templates/` changed; `graphify update .` after code changes.

---

## File Structure

| File | Responsibility |
|---|---|
| `services/cloud_backup/__init__.py` | Public surface: `run_mirror()`, `status()`, `is_enabled()` |
| `services/cloud_backup/settings.py` | Read/write the `cloud_backup` section of `app_settings.json`; encrypt/decrypt secrets |
| `services/cloud_backup/state.py` | `data/cloud_backup_state.json`: known-offsite hashes, last run, `last_success_at` |
| `services/cloud_backup/payload.py` | Optional client-side encryption of one file's bytes |
| `services/cloud_backup/sftp.py` | The only module that imports paramiko: pinned host key, `ensure_dir`, atomic `put`, `size`, `get` |
| `services/cloud_backup/sync.py` | Walk `backup-config/`, diff, upload, manifest, verification sample |
| `services/cloud_backup/restore_template.py` | The standalone `restore.py` uploaded next to the manifest |
| `routers/cloud_backup.py` | Six HTTP routes, RBAC, audit logging |
| `static/js/cloud-backup.js` | Settings-tab section: form, test, run, status |
| `tests/test_cloud_backup_*.py` | One test module per concern |

---

### Task 1: Settings module with vault-backed secrets

**Files:**
- Create: `services/cloud_backup/__init__.py`, `services/cloud_backup/settings.py`
- Test: `tests/test_cloud_backup_settings.py`

**Interfaces:**
- Consumes: `core.app_settings.get_app_settings() -> dict`, `save_app_settings(settings: dict) -> None`; `security.crypto_vault.encrypt_password(str) -> str`, `decrypt_password(str) -> str`
- Produces: `settings.read() -> dict` (secrets decrypted, internal use), `settings.redacted() -> dict` (secrets blanked, for the API), `settings.save(cfg: dict) -> None`, `settings.is_enabled() -> bool`, `settings.validate(cfg: dict) -> list[str]` (error messages, empty when valid), constant `SECTION = "cloud_backup"`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_settings.py
# -*- coding: utf-8 -*-
"""cloud_backup.settings: secrets never leave the vault in clear."""
import unittest
from unittest import mock

from services.cloud_backup import settings as cb_settings


class TestCloudBackupSettings(unittest.TestCase):

    def setUp(self):
        self.store = {}
        patcher_get = mock.patch("core.app_settings.get_app_settings",
                                 side_effect=lambda: dict(self.store))
        patcher_save = mock.patch("core.app_settings.save_app_settings",
                                  side_effect=self.store.update)
        patcher_get.start(); patcher_save.start()
        self.addCleanup(patcher_get.stop); self.addCleanup(patcher_save.stop)

    def _sample(self, **over):
        cfg = {"enabled": True, "kind": "sftp", "host": "backup.example.net",
               "port": 22, "username": "sentinelnet", "auth": "password",
               "password": "s3cret", "remote_root": "/srv/backups"}
        cfg.update(over)
        return cfg

    def test_password_is_stored_encrypted_and_read_back(self):
        cb_settings.save(self._sample())
        raw = self.store["cloud_backup"]
        self.assertNotIn("password", raw)
        self.assertNotEqual("s3cret", raw["password_enc"])
        self.assertEqual("s3cret", cb_settings.read()["password"])

    def test_redacted_never_exposes_a_secret(self):
        cb_settings.save(self._sample())
        red = cb_settings.redacted()
        self.assertEqual("", red["password"])
        self.assertNotIn("password_enc", red)
        self.assertTrue(red["has_password"])

    def test_saving_without_a_new_secret_keeps_the_stored_one(self):
        cb_settings.save(self._sample())
        cb_settings.save(self._sample(password=""))
        self.assertEqual("s3cret", cb_settings.read()["password"])

    def test_validate_rejects_an_unusable_config(self):
        errors = cb_settings.validate({"enabled": True, "kind": "sftp", "host": "",
                                       "port": 0, "username": "", "auth": "key",
                                       "key_path": "", "remote_root": ""})
        joined = " ".join(errors)
        for expected in ("host", "port", "username", "remote_root", "key_path"):
            self.assertIn(expected, joined)

    def test_validate_accepts_a_complete_config(self):
        self.assertEqual([], cb_settings.validate(self._sample()))

    def test_disabled_by_default(self):
        self.assertFalse(cb_settings.is_enabled())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_settings.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'services.cloud_backup'`

- [ ] **Step 3: Write minimal implementation**

```python
# services/cloud_backup/__init__.py
# -*- coding: utf-8 -*-
"""Offsite mirror of backup-config/ to an SFTP host.

The local archive stays the source of truth: nothing in the app ever reads
from the remote. See docs/superpowers/specs/2026-08-25-cloud-backup-design.md.
"""
```

```python
# services/cloud_backup/settings.py
# -*- coding: utf-8 -*-
"""Configuration of the offsite mirror, stored in app_settings.json.

Secrets go through the same Fernet vault the device credentials use: they are
written encrypted and never returned to the API in clear.
"""

from core.app_settings import get_app_settings, save_app_settings
from security.crypto_vault import encrypt_password, decrypt_password

SECTION = "cloud_backup"

# Secret fields: stored as "<name>_enc", returned to the API as "" plus a
# has_<name> flag so the UI can show "configured" without ever seeing it.
_SECRETS = ("password", "key_passphrase")

_DEFAULTS = {
    "enabled": False,
    "kind": "sftp",
    "host": "",
    "port": 22,
    "username": "",
    "auth": "key",              # "key" | "password"
    "key_path": "",
    "remote_root": "",
    "host_key_fingerprint": "",
    "encrypt_payload": False,
    "run_after_backup": True,
    "stale_after_hours": 48,
}


def _stored() -> dict:
    section = get_app_settings().get(SECTION)
    return dict(section) if isinstance(section, dict) else {}


def read() -> dict:
    """Full config with secrets decrypted. Internal use only."""
    cfg = dict(_DEFAULTS)
    cfg.update(_stored())
    for name in _SECRETS:
        cfg[name] = decrypt_password(cfg.pop(f"{name}_enc", "") or "")
    return cfg


def redacted() -> dict:
    """Config for the API: no secret, only whether one is configured."""
    stored = _stored()
    cfg = dict(_DEFAULTS)
    cfg.update(stored)
    for name in _SECRETS:
        cfg.pop(f"{name}_enc", None)
        cfg[name] = ""
        cfg[f"has_{name}"] = bool(stored.get(f"{name}_enc"))
    return cfg


def save(cfg: dict) -> None:
    """Persists the config. An empty secret keeps the stored one: the UI never
    receives the current value, so it cannot send it back."""
    stored = _stored()
    out = {k: v for k, v in cfg.items() if k not in _SECRETS}
    for name in _SECRETS:
        value = (cfg.get(name) or "").strip()
        key = f"{name}_enc"
        if value:
            out[key] = encrypt_password(value)
        elif stored.get(key):
            out[key] = stored[key]
    save_app_settings({SECTION: out})


def is_enabled() -> bool:
    return bool(_stored().get("enabled"))


def validate(cfg: dict) -> list[str]:
    """Boundary validation: this config comes from a user form."""
    errors = []
    if not (cfg.get("host") or "").strip():
        errors.append("host: obbligatorio")
    try:
        port = int(cfg.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        errors.append("port: fuori intervallo 1-65535")
    if not (cfg.get("username") or "").strip():
        errors.append("username: obbligatorio")
    if not (cfg.get("remote_root") or "").strip():
        errors.append("remote_root: obbligatorio")
    if cfg.get("auth") == "key" and not (cfg.get("key_path") or "").strip():
        errors.append("key_path: obbligatorio con autenticazione a chiave")
    if (cfg.get("auth") == "password" and not (cfg.get("password") or "").strip()
            and not _stored().get("password_enc")):
        errors.append("password: obbligatoria con autenticazione a password")
    return errors
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cloud_backup_settings.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Full gate**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
```

- [ ] **Step 6: Commit**

```bash
git add services/cloud_backup/__init__.py services/cloud_backup/settings.py tests/test_cloud_backup_settings.py
git commit -m "feat(cloud-backup): settings with vault-backed secrets

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: Local state file (and its .gitignore entry)

**Files:**
- Create: `services/cloud_backup/state.py`
- Modify: `.gitignore` (append `data/cloud_backup_state.json`)
- Test: `tests/test_cloud_backup_state.py`

**Interfaces:**
- Consumes: `core.data_config.get_path(filename: str) -> str`
- Produces: `state.STATE_FILE = "cloud_backup_state.json"`, `state.read() -> dict`, `state.write(data: dict) -> None`, `state.known_hashes() -> dict[str, str]`, `state.record_run(result: dict) -> None`, `state.hours_since_success(now: float | None = None) -> float | None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_state.py
# -*- coding: utf-8 -*-
"""cloud_backup.state: what this host believes is already offsite."""
import datetime as dt
import os
import tempfile
import unittest
from unittest import mock

from services.cloud_backup import state as cb_state


class TestCloudBackupState(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        patcher = mock.patch("core.data_config.get_path",
                             side_effect=lambda name: os.path.join(self.dir, name))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_absent_file_reads_as_empty_not_an_error(self):
        self.assertEqual({}, cb_state.known_hashes())
        self.assertIsNone(cb_state.hours_since_success())

    def test_corrupt_file_reads_as_empty(self):
        with open(os.path.join(self.dir, cb_state.STATE_FILE), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual({}, cb_state.known_hashes())

    def test_a_successful_run_records_its_time_and_hashes(self):
        cb_state.record_run({"ok": True, "uploaded": 2, "skipped": 5, "failed": 0,
                             "verified": 2, "error": None,
                             "files": {"site-a/cisco/switch-01-192.0.2.10.txt": "sha256:1f0a"}})
        self.assertEqual({"site-a/cisco/switch-01-192.0.2.10.txt": "sha256:1f0a"},
                         cb_state.known_hashes())
        self.assertLess(cb_state.hours_since_success(), 1)

    def test_a_failed_run_does_not_refresh_the_success_time(self):
        cb_state.record_run({"ok": True, "uploaded": 1, "skipped": 0, "failed": 0,
                             "verified": 1, "error": None, "files": {}})
        first = cb_state.read()["last_success_at"]
        cb_state.record_run({"ok": False, "uploaded": 0, "skipped": 0, "failed": 1,
                             "verified": 0, "error": "connection refused", "files": {}})
        data = cb_state.read()
        self.assertEqual(first, data["last_success_at"])
        self.assertFalse(data["last_run"]["ok"])
        self.assertEqual("connection refused", data["last_run"]["error"])

    def test_age_is_reported_even_when_the_last_success_is_old(self):
        cb_state.write({"schema": 1, "files": {},
                        "last_run": {"ok": True, "error": None},
                        "last_success_at": "2026-08-20T09:00:00Z"})
        now = dt.datetime(2026, 8, 25, 9, 0, tzinfo=dt.timezone.utc).timestamp()
        self.assertAlmostEqual(120.0, cb_state.hours_since_success(now), places=1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_state.py -v`
Expected: FAIL — `ImportError: cannot import name 'state'`

- [ ] **Step 3: Write minimal implementation**

```python
# services/cloud_backup/state.py
# -*- coding: utf-8 -*-
"""What this host believes is already offsite.

Absence and corruption both read as "nothing known": a lost state file must
cost one full re-upload, never a crash.
"""

import datetime as dt
import json
import os
import threading

from core import data_config

STATE_FILE = "cloud_backup_state.json"
_lock = threading.Lock()


def _path() -> str:
    return data_config.get_path(STATE_FILE)


def read() -> dict:
    try:
        with open(_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write(data: dict) -> None:
    tmp = _path() + ".tmp"
    with _lock:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, _path())


def known_hashes() -> dict:
    files = read().get("files")
    return dict(files) if isinstance(files, dict) else {}


def record_run(result: dict) -> None:
    """Stores the outcome. last_success_at moves only on a successful run: that
    is what lets the UI say "last good copy 120 hours ago" instead of showing a
    stale ok=true as if it were fresh."""
    data = read()
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    data["schema"] = 1
    data["last_run"] = {k: v for k, v in result.items() if k != "files"}
    data["last_run"]["finished_at"] = now
    if result.get("ok"):
        data["last_success_at"] = now
        data["files"] = dict(result.get("files") or {})
    write(data)


def hours_since_success(now: float | None = None) -> float | None:
    stamp = read().get("last_success_at")
    if not stamp:
        return None
    try:
        then = dt.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    current = now if now is not None else dt.datetime.now(dt.timezone.utc).timestamp()
    return (current - then.timestamp()) / 3600
```

- [ ] **Step 4: Add the .gitignore entry (same commit, before the tool ever runs)**

Append to `.gitignore`:

```
data/cloud_backup_state.json
```

- [ ] **Step 5: Run tests and verify nothing under data/ is tracked**

Run: `uv run pytest tests/test_cloud_backup_state.py -v` → PASS (5 tests)
Run: `git status --porcelain data/` → prints nothing

- [ ] **Step 6: Full gate**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
```

- [ ] **Step 7: Commit**

```bash
git add services/cloud_backup/state.py tests/test_cloud_backup_state.py .gitignore
git commit -m "feat(cloud-backup): local state file with success age

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: Optional payload encryption

**Files:**
- Create: `services/cloud_backup/payload.py`
- Test: `tests/test_cloud_backup_payload.py`

**Interfaces:**
- Consumes: `security.crypto_vault.CIPHER_SUITE` (a `cryptography.fernet.Fernet`)
- Produces: `payload.encrypt_bytes(data: bytes) -> bytes`, `payload.decrypt_bytes(token: bytes) -> bytes`, `payload.remote_name(rel_path: str, encrypted: bool) -> str`, `payload.SUFFIX = ".enc"`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_payload.py
# -*- coding: utf-8 -*-
"""cloud_backup.payload: client-side encryption of a single file."""
import unittest

from services.cloud_backup import payload


class TestCloudBackupPayload(unittest.TestCase):

    def test_round_trip(self):
        clear = b"hostname switch-01\ninterface GigabitEthernet1/0/1\n"
        token = payload.encrypt_bytes(clear)
        self.assertNotEqual(clear, token)
        self.assertEqual(clear, payload.decrypt_bytes(token))

    def test_remote_name_marks_encrypted_files(self):
        rel = "site-a/cisco/switch-01-192.0.2.10.txt"
        self.assertEqual(rel, payload.remote_name(rel, False))
        self.assertEqual(rel + ".enc", payload.remote_name(rel, True))

    def test_empty_file_survives_the_round_trip(self):
        self.assertEqual(b"", payload.decrypt_bytes(payload.encrypt_bytes(b"")))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_payload.py -v`
Expected: FAIL — `ImportError: cannot import name 'payload'`

- [ ] **Step 3: Write minimal implementation**

```python
# services/cloud_backup/payload.py
# -*- coding: utf-8 -*-
"""Optional client-side encryption of what is uploaded.

Off by default. When on, the offsite copy is unreadable without this install's
Fernet key store -- which is why the UI pairs the toggle with the instruction
to back that key up separately, offline.
"""

from security.crypto_vault import CIPHER_SUITE

SUFFIX = ".enc"


def encrypt_bytes(data: bytes) -> bytes:
    return CIPHER_SUITE.encrypt(data)


def decrypt_bytes(token: bytes) -> bytes:
    return CIPHER_SUITE.decrypt(token)


def remote_name(rel_path: str, encrypted: bool) -> str:
    return rel_path + SUFFIX if encrypted else rel_path
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cloud_backup_payload.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add services/cloud_backup/payload.py tests/test_cloud_backup_payload.py
git commit -m "feat(cloud-backup): optional client-side payload encryption

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: SFTP transport with pinned host key and atomic put

**Files:**
- Create: `services/cloud_backup/sftp.py`
- Test: `tests/test_cloud_backup_transport.py`

**Interfaces:**
- Consumes: `settings.read()`, paramiko
- Produces: `sftp.HostKeyMismatch(Exception)`; `class SftpTarget(ssh, client, pinned_fingerprint="")` with attributes `fingerprint: str`, `pinned_fingerprint: str` and methods `verify_host_key() -> None`, `ensure_dir(remote_dir: str) -> None`, `put(data: bytes, remote_path: str) -> None`, `size(remote_path: str) -> int | None`, `get(remote_path: str) -> bytes`, `close() -> None`; `sftp.open_target(cfg: dict) -> SftpTarget`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_transport.py
# -*- coding: utf-8 -*-
"""cloud_backup.sftp: the two things a transport must not get wrong --
never trust an unpinned host key, never leave a truncated file in place."""
import unittest
from unittest import mock

from services.cloud_backup import sftp


class FakeSftpClient:
    def __init__(self):
        self.calls = []
        self.files = {}

    def stat(self, path):
        if path not in self.files:
            raise IOError("no such file")
        return mock.Mock(st_size=len(self.files[path]))

    def mkdir(self, path):
        self.calls.append(("mkdir", path))
        self.files[path] = b""

    def open(self, path, mode):
        self.calls.append(("open", path, mode))
        client = self

        class _F:
            def write(self, data):
                client.files[path] = data

            def read(self):
                return client.files.get(path, b"")

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *exc):
                return False

        return _F()

    def posix_rename(self, src, dst):
        self.calls.append(("rename", src, dst))
        self.files[dst] = self.files.pop(src)

    def close(self):
        self.calls.append(("close",))


class FakeHostKey:
    def get_name(self):
        return "ssh-ed25519"

    def get_base64(self):
        return "AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleEx"


class TestSftpTarget(unittest.TestCase):

    def _target(self, pinned=""):
        client = FakeSftpClient()
        transport = mock.Mock()
        transport.get_remote_server_key.return_value = FakeHostKey()
        ssh = mock.Mock()
        ssh.get_transport.return_value = transport
        return sftp.SftpTarget(ssh, client, pinned_fingerprint=pinned), client

    def test_put_writes_a_temp_name_then_renames(self):
        target, client = self._target()
        target.put(b"hostname switch-01\n", "/srv/backups/site-a/switch-01.txt")
        kinds = [c[0] for c in client.calls if c[0] in ("open", "rename")]
        self.assertEqual(["open", "rename"], kinds)
        opened = [c for c in client.calls if c[0] == "open"][0][1]
        self.assertTrue(opened.endswith(".part"), opened)
        self.assertEqual(("rename", opened, "/srv/backups/site-a/switch-01.txt"),
                         [c for c in client.calls if c[0] == "rename"][0])

    def test_a_pinned_fingerprint_that_does_not_match_aborts_before_any_write(self):
        target, client = self._target(pinned="SHA256:something-else")
        with self.assertRaises(sftp.HostKeyMismatch):
            target.verify_host_key()
        self.assertEqual([], client.calls)

    def test_a_matching_fingerprint_passes(self):
        target, _ = self._target()
        target.pinned_fingerprint = target.fingerprint
        target.verify_host_key()  # must not raise

    def test_ensure_dir_creates_each_missing_level_once(self):
        target, client = self._target()
        target.ensure_dir("/srv/backups/site-a/cisco")
        made = [c[1] for c in client.calls if c[0] == "mkdir"]
        self.assertEqual(["/srv", "/srv/backups", "/srv/backups/site-a",
                          "/srv/backups/site-a/cisco"], made)
        client.calls.clear()
        target.ensure_dir("/srv/backups/site-a/cisco")
        self.assertEqual([], [c for c in client.calls if c[0] == "mkdir"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_transport.py -v`
Expected: FAIL — `ImportError: cannot import name 'sftp'`

- [ ] **Step 3: Write minimal implementation**

```python
# services/cloud_backup/sftp.py
# -*- coding: utf-8 -*-
"""SFTP transport. The only module here that imports paramiko.

Two rules carry the security of the whole feature:
  - the host key is pinned. AutoAddPolicy with no pin is how a redirected DNS
    entry turns a backup into an exfiltration channel;
  - every upload lands on a temporary name and is renamed into place, so an
    interrupted transfer never leaves a truncated config looking current.
"""

import base64
import hashlib
import posixpath

import paramiko


class HostKeyMismatch(Exception):
    """The server presented a key different from the pinned fingerprint."""


def _fingerprint(host_key) -> str:
    digest = hashlib.sha256(base64.b64decode(host_key.get_base64())).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class SftpTarget:

    def __init__(self, ssh, client, pinned_fingerprint: str = ""):
        self._ssh = ssh
        self._client = client
        self.pinned_fingerprint = pinned_fingerprint
        self.fingerprint = _fingerprint(ssh.get_transport().get_remote_server_key())
        self._known_dirs: set = set()

    def verify_host_key(self) -> None:
        if self.pinned_fingerprint and self.pinned_fingerprint != self.fingerprint:
            raise HostKeyMismatch(
                f"host key {self.fingerprint} diversa da quella attesa "
                f"{self.pinned_fingerprint}")

    def ensure_dir(self, remote_dir: str) -> None:
        path = ""
        for part in [p for p in remote_dir.strip("/").split("/") if p]:
            path = f"{path}/{part}"
            if path in self._known_dirs:
                continue
            try:
                self._client.stat(path)
            except IOError:
                self._client.mkdir(path)
            self._known_dirs.add(path)

    def put(self, data: bytes, remote_path: str) -> None:
        self.ensure_dir(posixpath.dirname(remote_path))
        tmp = remote_path + ".part"
        with self._client.open(tmp, "wb") as fh:
            fh.write(data)
        self._client.posix_rename(tmp, remote_path)

    def size(self, remote_path: str) -> int | None:
        try:
            return self._client.stat(remote_path).st_size
        except IOError:
            return None

    def get(self, remote_path: str) -> bytes:
        with self._client.open(remote_path, "rb") as fh:
            return fh.read()

    def close(self) -> None:
        try:
            self._client.close()
        finally:
            self._ssh.close()


def open_target(cfg: dict) -> SftpTarget:
    """Connects with the operator's key or password. The key file is read,
    never created or rewritten."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs = {
        "hostname": cfg["host"], "port": int(cfg.get("port") or 22),
        "username": cfg["username"], "timeout": 20, "allow_agent": False,
        "look_for_keys": False,
    }
    if cfg.get("auth") == "key":
        kwargs["key_filename"] = cfg["key_path"]
        if cfg.get("key_passphrase"):
            kwargs["passphrase"] = cfg["key_passphrase"]
    else:
        kwargs["password"] = cfg.get("password") or ""
    ssh.connect(**kwargs)
    target = SftpTarget(ssh, ssh.open_sftp(),
                        pinned_fingerprint=cfg.get("host_key_fingerprint") or "")
    try:
        target.verify_host_key()
    except HostKeyMismatch:
        target.close()
        raise
    return target
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cloud_backup_transport.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add services/cloud_backup/sftp.py tests/test_cloud_backup_transport.py
git commit -m "feat(cloud-backup): SFTP transport, pinned host key, atomic put

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: The standalone restore script

Built before the sync engine, because sync uploads it: a stub committed here
would ship a broken restore path.

**Files:**
- Create: `services/cloud_backup/restore_template.py`
- Test: `tests/test_cloud_backup_restore_script.py`

**Interfaces:**
- Consumes: nothing from this repo — that is the point
- Produces: `restore_template.RESTORE_SCRIPT: str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_restore_script.py
# -*- coding: utf-8 -*-
"""The uploaded restore.py must rebuild the archive with no import from this
repo: whoever finds that folder in three years has only Python."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

from services.cloud_backup.restore_template import RESTORE_SCRIPT


class TestRestoreScript(unittest.TestCase):

    def _archive(self, encrypted=False, key=None):
        root = tempfile.mkdtemp()
        rel = "site-a/cisco/switch-01-192.0.2.10.txt"
        clear = b"hostname switch-01\n"
        body = clear
        rel_remote = rel
        if encrypted:
            from cryptography.fernet import Fernet
            body = Fernet(key).encrypt(clear)
            rel_remote = rel + ".enc"
        path = os.path.join(root, *rel_remote.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)
        with open(os.path.join(root, "_manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"schema": 1, "encrypted": encrypted,
                       "files": {rel: {"sha256": "sha256:x", "size": len(clear)}}}, fh)
        script = os.path.join(root, "restore.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(RESTORE_SCRIPT)
        return root, script, rel, clear

    def test_rebuilds_a_plaintext_archive(self):
        root, script, rel, clear = self._archive()
        out = tempfile.mkdtemp()
        proc = subprocess.run([sys.executable, script, "--source", root, "--target", out],
                              capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)
        with open(os.path.join(out, *rel.split("/")), "rb") as fh:
            self.assertEqual(clear, fh.read())

    def test_rebuilds_an_encrypted_archive_with_the_key(self):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
        root, script, rel, clear = self._archive(encrypted=True, key=key)
        keyfile = os.path.join(root, "fernet.key")
        with open(keyfile, "wb") as fh:
            fh.write(key)
        out = tempfile.mkdtemp()
        proc = subprocess.run([sys.executable, script, "--source", root,
                               "--target", out, "--key-file", keyfile],
                              capture_output=True, text=True)
        self.assertEqual(0, proc.returncode, proc.stderr)
        with open(os.path.join(out, *rel.split("/")), "rb") as fh:
            self.assertEqual(clear, fh.read())

    def test_an_encrypted_archive_without_a_key_fails_loudly(self):
        from cryptography.fernet import Fernet
        root, script, _rel, _clear = self._archive(encrypted=True, key=Fernet.generate_key())
        out = tempfile.mkdtemp()
        proc = subprocess.run([sys.executable, script, "--source", root, "--target", out],
                              capture_output=True, text=True)
        self.assertNotEqual(0, proc.returncode)
        self.assertIn("--key-file", proc.stdout + proc.stderr)

    def test_the_script_does_not_import_this_repo(self):
        for forbidden in ("services.", "core.", "security."):
            self.assertNotIn(forbidden, RESTORE_SCRIPT)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_restore_script.py -v`
Expected: FAIL — `ModuleNotFoundError: services.cloud_backup.restore_template`

- [ ] **Step 3: Write minimal implementation**

```python
# services/cloud_backup/restore_template.py
# -*- coding: utf-8 -*-
"""The standalone restore script uploaded next to the manifest.

Kept as a string, not a module: it is data to be shipped, and it must not
import anything from this repository. A backup that needs the software that
produced it is a backup with a dependency nobody wrote down.
"""

RESTORE_SCRIPT = '''#!/usr/bin/env python3
"""Rebuild a SentinelNet configuration archive from this folder.

    python restore.py --source . --target ./restored [--key-file fernet.key]

Reads _manifest.json, copies every listed file into --target, decrypting when
the manifest says the archive is encrypted. Requires only Python 3 (plus the
`cryptography` package for an encrypted archive).
"""
import argparse
import json
import os
import sys


def main():
    ap = argparse.ArgumentParser(description="Restore a SentinelNet backup archive")
    ap.add_argument("--source", default=".", help="folder holding _manifest.json")
    ap.add_argument("--target", required=True, help="where to write the rebuilt tree")
    ap.add_argument("--key-file", help="Fernet key file, for an encrypted archive")
    args = ap.parse_args()

    manifest_path = os.path.join(args.source, "_manifest.json")
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except OSError as exc:
        print("cannot read %s: %s" % (manifest_path, exc), file=sys.stderr)
        return 2

    encrypted = bool(manifest.get("encrypted"))
    decrypt = None
    if encrypted:
        if not args.key_file:
            print("this archive is encrypted: pass --key-file with the Fernet key",
                  file=sys.stderr)
            return 2
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("an encrypted archive needs the 'cryptography' package: "
                  "pip install cryptography", file=sys.stderr)
            return 2
        with open(args.key_file, "rb") as fh:
            decrypt = Fernet(fh.read().strip()).decrypt

    written = failed = 0
    for rel in sorted(manifest.get("files") or {}):
        remote_rel = rel + ".enc" if encrypted else rel
        src = os.path.join(args.source, *remote_rel.split("/"))
        dst = os.path.join(args.target, *rel.split("/"))
        try:
            with open(src, "rb") as fh:
                data = fh.read()
            if decrypt is not None:
                data = decrypt(data)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(data)
            written += 1
        except Exception as exc:
            print("FAILED %s: %s" % (rel, exc), file=sys.stderr)
            failed += 1

    print("restored %d file(s), %d failed, into %s" % (written, failed, args.target))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
'''
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_cloud_backup_restore_script.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add services/cloud_backup/restore_template.py tests/test_cloud_backup_restore_script.py
git commit -m "feat(cloud-backup): ship a standalone restore.py with the archive

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: Sync engine — walk, diff, upload, manifest, verify

**Files:**
- Create: `services/cloud_backup/sync.py`
- Modify: `services/cloud_backup/__init__.py` (export `run_mirror`, `status`, `is_enabled`)
- Test: `tests/test_cloud_backup_sync.py`, `tests/test_cloud_backup_verify.py`

**Interfaces:**
- Consumes: `settings.read()`, `state.known_hashes()`, `state.record_run()`, `state.read()`, `state.hours_since_success()`, `payload.encrypt_bytes()`, `payload.remote_name()`, `sftp.open_target()`, `restore_template.RESTORE_SCRIPT`, `core.core_engine.BACKUP_FOLDER`
- Produces: `sync.walk_local(root: str) -> dict[str, dict]` (`{rel: {"sha256": str, "size": int}}`, POSIX separators), `sync.plan_uploads(local: dict, known: dict) -> list[str]`, `sync.run_mirror(open_target=sftp.open_target) -> dict`, `sync.status() -> dict`, and `__init__` re-exporting `run_mirror`, `status`, `is_enabled`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_cloud_backup_sync.py
# -*- coding: utf-8 -*-
"""cloud_backup.sync: what gets sent, and what is correctly skipped."""
import json
import os
import tempfile
import unittest
from unittest import mock

from services.cloud_backup import sync


def _write(root, rel, text):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class FakeTarget:
    def __init__(self):
        self.written = {}
        self.fingerprint = "SHA256:example"
        self.pinned_fingerprint = ""

    def verify_host_key(self):
        pass

    def ensure_dir(self, remote_dir):
        pass

    def put(self, data, remote_path):
        self.written[remote_path] = data

    def size(self, remote_path):
        return len(self.written[remote_path]) if remote_path in self.written else None

    def get(self, remote_path):
        return self.written[remote_path]

    def close(self):
        pass


class TestWalkAndPlan(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        _write(self.root, "site-a/cisco/switch-01-192.0.2.10.txt", "hostname switch-01\n")
        _write(self.root, "site-a/cisco/.history/192.0.2.10-index.json",
               '{"device":"192.0.2.10"}')
        _write(self.root, "site-a/cisco/.history/switch-01-192.0.2.10.20260819T110233.451207Z.txt",
               "hostname switch-01\n! older\n")

    def test_walk_includes_history_and_uses_posix_paths(self):
        local = sync.walk_local(self.root)
        self.assertIn("site-a/cisco/switch-01-192.0.2.10.txt", local)
        self.assertIn("site-a/cisco/.history/192.0.2.10-index.json", local)
        self.assertEqual(3, len(local))
        self.assertTrue(local["site-a/cisco/switch-01-192.0.2.10.txt"]["sha256"]
                        .startswith("sha256:"))

    def test_plan_skips_what_is_already_offsite(self):
        local = sync.walk_local(self.root)
        known = {p: e["sha256"] for p, e in local.items()}
        self.assertEqual([], sync.plan_uploads(local, known))

    def test_plan_reuploads_a_changed_file(self):
        local = sync.walk_local(self.root)
        known = {p: e["sha256"] for p, e in local.items()}
        known["site-a/cisco/switch-01-192.0.2.10.txt"] = "sha256:stale"
        self.assertEqual(["site-a/cisco/switch-01-192.0.2.10.txt"],
                         sync.plan_uploads(local, known))

    def test_plan_uploads_everything_when_nothing_is_known(self):
        self.assertEqual(3, len(sync.plan_uploads(sync.walk_local(self.root), {})))

    def test_empty_estate_is_a_no_op(self):
        self.assertEqual({}, sync.walk_local(tempfile.mkdtemp()))


class TestRunMirror(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        _write(self.root, "site-a/cisco/switch-01-192.0.2.10.txt", "hostname switch-01\n")
        self.target = FakeTarget()
        self.cfg = {"enabled": True, "kind": "sftp", "host": "backup.example.net",
                    "port": 22, "username": "sentinelnet", "auth": "password",
                    "password": "s3cret", "remote_root": "/srv/backups",
                    "encrypt_payload": False, "host_key_fingerprint": ""}
        for p in [mock.patch("services.cloud_backup.sync.BACKUP_FOLDER", self.root),
                  mock.patch("services.cloud_backup.settings.read",
                             side_effect=lambda: dict(self.cfg)),
                  mock.patch("services.cloud_backup.state.known_hashes", return_value={}),
                  mock.patch("services.cloud_backup.state.record_run")]:
            p.start(); self.addCleanup(p.stop)

    def test_uploads_then_writes_manifest_and_restore_script(self):
        result = sync.run_mirror(open_target=lambda cfg: self.target)
        self.assertTrue(result["ok"], result.get("error"))
        self.assertEqual(1, result["uploaded"])
        self.assertIn("/srv/backups/site-a/cisco/switch-01-192.0.2.10.txt", self.target.written)
        self.assertIn("/srv/backups/_manifest.json", self.target.written)
        self.assertIn("/srv/backups/restore.py", self.target.written)

    def test_encrypted_upload_changes_bytes_but_not_the_manifest_hash(self):
        self.cfg["encrypt_payload"] = True
        result = sync.run_mirror(open_target=lambda cfg: self.target)
        self.assertTrue(result["ok"], result.get("error"))
        rel = "site-a/cisco/switch-01-192.0.2.10.txt"
        self.assertIn(f"/srv/backups/{rel}.enc", self.target.written)
        self.assertNotEqual(b"hostname switch-01\n",
                            self.target.written[f"/srv/backups/{rel}.enc"])
        manifest = json.loads(self.target.written["/srv/backups/_manifest.json"])
        self.assertTrue(manifest["encrypted"])
        self.assertEqual(result["files"][rel], manifest["files"][rel]["sha256"])

    def test_a_disabled_mirror_does_not_connect(self):
        self.cfg["enabled"] = False
        def _boom(cfg):
            raise AssertionError("must not connect when disabled")
        result = sync.run_mirror(open_target=_boom)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
```

```python
# tests/test_cloud_backup_verify.py
# -*- coding: utf-8 -*-
"""A remote that accepts writes and discards them must not look like success."""
import tempfile
import unittest
from unittest import mock

from services.cloud_backup import sync
from tests.test_cloud_backup_sync import FakeTarget, _write


class LyingTarget(FakeTarget):
    def size(self, remote_path):
        if remote_path.endswith("_manifest.json") or remote_path.endswith("restore.py"):
            return len(self.written.get(remote_path, b""))
        return 0  # accepted the write, stored nothing


class TestVerification(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp()
        _write(self.root, "site-a/cisco/switch-01-192.0.2.10.txt", "hostname switch-01\n")
        cfg = {"enabled": True, "kind": "sftp", "host": "backup.example.net", "port": 22,
               "username": "sentinelnet", "auth": "password", "password": "s3cret",
               "remote_root": "/srv/backups", "encrypt_payload": False,
               "host_key_fingerprint": ""}
        for p in [mock.patch("services.cloud_backup.sync.BACKUP_FOLDER", self.root),
                  mock.patch("services.cloud_backup.settings.read", return_value=cfg),
                  mock.patch("services.cloud_backup.state.known_hashes", return_value={}),
                  mock.patch("services.cloud_backup.state.record_run")]:
            p.start(); self.addCleanup(p.stop)

    def test_a_discarded_upload_fails_the_run_and_names_the_file(self):
        result = sync.run_mirror(open_target=lambda cfg: LyingTarget())
        self.assertFalse(result["ok"])
        self.assertIn("switch-01-192.0.2.10.txt", result["error"])
        self.assertEqual({}, result["files"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cloud_backup_sync.py tests/test_cloud_backup_verify.py -v`
Expected: FAIL — `ImportError: cannot import name 'sync'`

- [ ] **Step 3: Write minimal implementation**

```python
# services/cloud_backup/sync.py
# -*- coding: utf-8 -*-
"""Walk backup-config/, send what changed, prove it arrived.

The mirror is write-only: nothing here ever reads the remote as a source of
truth. The verification pass exists because a remote that accepts writes and
discards them (full disk, quota, read-only export) otherwise looks exactly
like a successful run.
"""

import datetime as dt
import hashlib
import json
import os
import posixpath
import random
import threading

from core.core_engine import BACKUP_FOLDER
from services.cloud_backup import payload, settings, state
from services.cloud_backup.restore_template import RESTORE_SCRIPT
from services.cloud_backup.sftp import open_target as _open_target

MANIFEST_NAME = "_manifest.json"
RESTORE_NAME = "restore.py"
VERIFY_SAMPLE = 0.05

_run_lock = threading.Lock()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def walk_local(root: str) -> dict:
    """Every file under root, hashed. .history/ is included: it is the part
    that makes the mirror worth having."""
    out = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            out[rel] = {"sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                        "size": len(data)}
    return out


def plan_uploads(local: dict, known: dict) -> list:
    return sorted(rel for rel, entry in local.items()
                  if known.get(rel) != entry["sha256"])


def run_mirror(open_target=_open_target) -> dict:
    """One mirror pass. Returns the result dict, also recorded in state."""
    result = {"started_at": _now(), "ok": False, "uploaded": 0, "skipped": 0,
              "failed": 0, "verified": 0, "error": None, "files": {}}
    if not _run_lock.acquire(blocking=False):
        result["error"] = "un ciclo di mirror e' gia' in corso"
        return result
    try:
        cfg = settings.read()
        if not cfg.get("enabled"):
            result["error"] = "mirror non abilitato"
            return result

        local = walk_local(BACKUP_FOLDER)
        known = state.known_hashes()
        todo = plan_uploads(local, known)
        result["skipped"] = len(local) - len(todo)
        encrypt = bool(cfg.get("encrypt_payload"))
        root = cfg["remote_root"].rstrip("/")

        target = open_target(cfg)
        try:
            uploaded = []
            for rel in todo:
                try:
                    with open(os.path.join(BACKUP_FOLDER, *rel.split("/")), "rb") as fh:
                        data = fh.read()
                    body = payload.encrypt_bytes(data) if encrypt else data
                    remote = posixpath.join(root, payload.remote_name(rel, encrypt))
                    target.put(body, remote)
                    uploaded.append((rel, remote, len(body)))
                    result["uploaded"] += 1
                except (OSError, IOError) as exc:
                    # One unreadable file must not abandon the other 400.
                    result["failed"] += 1
                    result["error"] = result["error"] or f"{rel}: {exc}"

            manifest = {
                "schema": 1, "updated_at": _now(), "source": "sentinelnet",
                "encrypted": encrypt,
                "files": {rel: {"sha256": entry["sha256"], "size": entry["size"],
                                "uploaded_at": _now()}
                          for rel, entry in local.items()},
            }
            target.put(json.dumps(manifest, indent=2).encode("utf-8"),
                       posixpath.join(root, MANIFEST_NAME))
            target.put(RESTORE_SCRIPT.encode("utf-8"), posixpath.join(root, RESTORE_NAME))

            # Verification: everything sent this run, plus a rotating sample of
            # the rest. A size that does not match means the remote took the
            # write and kept nothing.
            checks = list(uploaded)
            sent = {rel for rel, _, _ in uploaded}
            rest = [rel for rel in local if rel not in sent]
            if rest:
                sample_size = min(len(rest), int(len(rest) * VERIFY_SAMPLE) + 1)
                for rel in random.sample(rest, sample_size):
                    checks.append((rel, posixpath.join(root, payload.remote_name(rel, encrypt)), None))
            for rel, remote, expected in checks:
                actual = target.size(remote)
                if actual is None or (expected is not None and actual != expected):
                    result["failed"] += 1
                    result["error"] = result["error"] or \
                        f"{rel}: il remoto riporta {actual} byte invece di {expected}"
                else:
                    result["verified"] += 1
        finally:
            target.close()

        if not result["failed"]:
            result["ok"] = True
            result["files"] = {rel: entry["sha256"] for rel, entry in local.items()}
    except Exception as exc:  # boundary: network, auth, host key
        result["error"] = str(exc)
    finally:
        _run_lock.release()
    state.record_run(result)
    return result


def status() -> dict:
    data = state.read()
    cfg = settings.read()
    local = walk_local(BACKUP_FOLDER) if cfg.get("enabled") else {}
    return {
        "enabled": bool(cfg.get("enabled")),
        "encrypt_payload": bool(cfg.get("encrypt_payload")),
        "last_run": data.get("last_run") or {},
        "last_success_at": data.get("last_success_at"),
        "hours_since_success": state.hours_since_success(),
        "stale_after_hours": cfg.get("stale_after_hours", 48),
        "pending": len(plan_uploads(local, state.known_hashes())),
    }
```

```python
# services/cloud_backup/__init__.py  (replace the file from Task 1)
# -*- coding: utf-8 -*-
"""Offsite mirror of backup-config/ to an SFTP host.

The local archive stays the source of truth: nothing in the app ever reads
from the remote. See docs/superpowers/specs/2026-08-25-cloud-backup-design.md.
"""

from services.cloud_backup.settings import is_enabled
from services.cloud_backup.sync import run_mirror, status

__all__ = ["is_enabled", "run_mirror", "status"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cloud_backup_sync.py tests/test_cloud_backup_verify.py -v`
Expected: PASS (9 tests)

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add services/cloud_backup/sync.py services/cloud_backup/__init__.py tests/test_cloud_backup_sync.py tests/test_cloud_backup_verify.py
git commit -m "feat(cloud-backup): sync engine with manifest and post-upload verification

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 7: HTTP routes

**Files:**
- Create: `routers/cloud_backup.py`
- Modify: `app_server.py` (import near line 76, `include_router` near line 105), `tests/test_router_smoke.py` (extend `SMOKE_ENDPOINTS`)
- Test: `tests/test_cloud_backup_api.py`

**Interfaces:**
- Consumes: `routers.deps.get_current_user`, `require_admin`, `user_group_scope`; `security.security_manager.log_audit`; `services.cloud_backup.run_mirror/status`, `services.cloud_backup.settings`, `services.cloud_backup.sftp`
- Produces: `GET|PUT /api/cloud-backup/settings`, `POST /api/cloud-backup/test`, `POST /api/cloud-backup/run`, `GET /api/cloud-backup/status`, `GET /api/cloud-backup/remote`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_api.py
# -*- coding: utf-8 -*-
"""Routes of the offsite mirror: RBAC, redaction, failure reporting."""
import unittest
from unittest import mock

from fastapi.testclient import TestClient

import app_server
from security import user_manager


class TestCloudBackupApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app_server.app, raise_server_exceptions=True)
        for name, role in (("cbadmin", "admin"), ("cbviewer", "viewer")):
            try:
                user_manager.create_user(name, "Pass123!", role=role)
            except Exception:
                pass
        cls.tokens = {}
        for name in ("cbadmin", "cbviewer"):
            r = cls.client.post("/api/auth/login",
                                json={"username": name, "password": "Pass123!"})
            cls.tokens[name] = r.json().get("access_token", "")

    def _headers(self, who):
        return {"Authorization": f"Bearer {self.tokens[who]}",
                "X-Requested-With": "SentinelNet"}

    def test_settings_require_admin(self):
        r = self.client.get("/api/cloud-backup/settings", headers=self._headers("cbviewer"))
        self.assertEqual(403, r.status_code)

    def test_settings_never_return_a_secret(self):
        r = self.client.get("/api/cloud-backup/settings", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        body = r.json()
        self.assertEqual("", body["password"])
        self.assertNotIn("password_enc", body)

    def test_invalid_config_is_rejected_before_being_stored(self):
        r = self.client.put("/api/cloud-backup/settings", headers=self._headers("cbadmin"),
                            json={"enabled": True, "kind": "sftp", "host": "",
                                  "port": 22, "username": "", "auth": "key",
                                  "key_path": "", "remote_root": ""})
        self.assertEqual(400, r.status_code)
        self.assertIn("host", r.text)

    def test_status_reports_age_and_pending(self):
        r = self.client.get("/api/cloud-backup/status", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        for key in ("enabled", "pending", "hours_since_success", "last_run"):
            self.assertIn(key, r.json())

    def test_run_reports_the_failure_instead_of_raising(self):
        with mock.patch("services.cloud_backup.run_mirror",
                        return_value={"ok": False, "error": "connection refused",
                                      "uploaded": 0, "skipped": 0, "failed": 1,
                                      "verified": 0, "files": {}}):
            r = self.client.post("/api/cloud-backup/run", headers=self._headers("cbadmin"))
        self.assertEqual(200, r.status_code)
        self.assertFalse(r.json()["ok"])
        self.assertIn("connection refused", r.json()["error"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_api.py -v`
Expected: FAIL — 404 on every route

- [ ] **Step 3: Write minimal implementation**

```python
# routers/cloud_backup.py
# -*- coding: utf-8 -*-
"""Routes of the offsite backup mirror.

Admin-only, except status: a triage needs to see whether the copy is current
without holding admin. Every route is audited -- "who pointed our configs at
which host" is a security question.
"""

import asyncio
import json
import posixpath

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from routers.deps import get_current_user, require_admin, user_group_scope
from security.security_manager import log_audit
from services import cloud_backup
from services.cloud_backup import settings as cb_settings
from services.cloud_backup import sftp as cb_sftp

router = APIRouter(tags=["Cloud Backup"])


class CloudBackupSettingsSchema(BaseModel):
    enabled: bool = False
    kind: str = "sftp"
    host: str = ""
    port: int = 22
    username: str = ""
    auth: str = "key"
    key_path: str = ""
    key_passphrase: str = ""
    password: str = ""
    remote_root: str = ""
    host_key_fingerprint: str = ""
    encrypt_payload: bool = False
    run_after_backup: bool = True
    stale_after_hours: int = 48


@router.get("/api/cloud-backup/settings")
def get_cloud_backup_settings(current_user=Depends(require_admin)):
    return cb_settings.redacted()


@router.put("/api/cloud-backup/settings")
def put_cloud_backup_settings(payload: CloudBackupSettingsSchema,
                              current_user=Depends(require_admin)):
    cfg = payload.dict()
    errors = cb_settings.validate(cfg)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    cb_settings.save(cfg)
    log_audit(f"Mirror offsite riconfigurato da '{current_user.get('sub')}' verso "
              f"{cfg['username']}@{cfg['host']}:{cfg['port']}{cfg['remote_root']}.")
    return cb_settings.redacted()


@router.post("/api/cloud-backup/test")
async def test_cloud_backup(current_user=Depends(require_admin)):
    cfg = cb_settings.read()

    def _probe():
        target = cb_sftp.open_target(cfg)
        try:
            root = cfg["remote_root"].rstrip("/")
            target.ensure_dir(root)
            target.put(b"ok\n", posixpath.join(root, ".sentinelnet-write-test"))
            return {"ok": True, "fingerprint": target.fingerprint, "error": None}
        finally:
            target.close()

    try:
        result = await asyncio.to_thread(_probe)
    except Exception as exc:
        result = {"ok": False, "fingerprint": "", "error": str(exc)}
    log_audit(f"Test mirror offsite da '{current_user.get('sub')}': "
              f"{'ok' if result['ok'] else result['error']}.")
    return result


@router.post("/api/cloud-backup/run")
async def run_cloud_backup(current_user=Depends(require_admin)):
    result = await asyncio.to_thread(cloud_backup.run_mirror)
    log_audit(f"Mirror offsite avviato da '{current_user.get('sub')}': "
              f"{result.get('uploaded', 0)} caricati, {result.get('failed', 0)} falliti.")
    return result


@router.get("/api/cloud-backup/status")
def get_cloud_backup_status(current_user=Depends(get_current_user)):
    return cloud_backup.status()


@router.get("/api/cloud-backup/remote")
async def list_cloud_backup_remote(current_user=Depends(require_admin)):
    """What the remote manifest holds, filtered to the caller's tenant scope.
    The first path segment is the tenant, by construction of the layout."""
    cfg = cb_settings.read()
    scope = user_group_scope(current_user)

    def _fetch():
        target = cb_sftp.open_target(cfg)
        try:
            raw = target.get(posixpath.join(cfg["remote_root"].rstrip("/"),
                                            "_manifest.json"))
        finally:
            target.close()
        return json.loads(raw.decode("utf-8"))

    try:
        manifest = await asyncio.to_thread(_fetch)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Remoto non leggibile: {exc}")
    files = manifest.get("files") or {}
    if scope is not None:
        files = {rel: meta for rel, meta in files.items() if rel.split("/")[0] in scope}
    return {"updated_at": manifest.get("updated_at"),
            "encrypted": bool(manifest.get("encrypted")), "files": files}
```

In `app_server.py`, beside the other routers:

```python
from routers import cloud_backup as _cloud_backup_router
...
app.include_router(_cloud_backup_router.router)
```

In `tests/test_router_smoke.py`, add to `SMOKE_ENDPOINTS`:

```python
    ("get", "/api/cloud-backup/settings", None),
    ("get", "/api/cloud-backup/status", None),
    ("post", "/api/cloud-backup/run", None),
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cloud_backup_api.py tests/test_router_smoke.py -v`
Expected: PASS

- [ ] **Step 5: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add routers/cloud_backup.py app_server.py tests/test_cloud_backup_api.py tests/test_router_smoke.py
git commit -m "feat(cloud-backup): admin routes with audit and tenant scope

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 8: Settings-tab UI section

**Files:**
- Create: `static/js/cloud-backup.js`
- Modify: `templates/dashboard.html` (new panel in the Settings tab), `static/js/i18n.js` (it + en), `static/js/core.js` (`LAZY_TAB_SCRIPTS['tab-settings']`), `types/globals.d.ts`
- Test: `tests/test_cloud_backup_ui.py`

**Interfaces:**
- Consumes: globals `apiFetch`, `escapeHtml`, `showToast`, `currentLang`, `i18n`; the routes from Task 7
- Produces: `window.loadCloudBackup(): Promise<void>`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_ui.py
# -*- coding: utf-8 -*-
"""Sezione UI del mirror offsite: id presenti e agganciati, stringhe in
entrambe le lingue, nessun handler inline, modulo caricato sul suo tab."""
import os
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    return open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8").read()


class TestCloudBackupUi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.src = _read("static", "js", "cloud-backup.js")
        cls.i18n = _read("static", "js", "i18n.js")
        cls.core = _read("static", "js", "core.js")

    def test_every_bound_id_exists_in_the_template(self):
        for element_id in ("cbEnabled", "cbHost", "cbPort", "cbUsername", "cbAuth",
                           "cbKeyPath", "cbSecret", "cbRemoteRoot", "cbEncrypt",
                           "cbRunAfterBackup", "cbBtnSave", "cbBtnTest", "cbBtnRun",
                           "cbStatusBox"):
            self.assertIn(f'id="{element_id}"', self.html, element_id)
            self.assertIn(f"getElementById('{element_id}')", self.src, element_id)

    def test_no_inline_handlers_in_the_section(self):
        start = self.html.index('id="cloudBackupPanel"')
        section = self.html[start:start + 8000]
        self.assertNotIn("onclick=", section)
        self.assertNotIn("onsubmit=", section)

    def test_strings_exist_in_both_languages(self):
        for key in ("cbTitle", "cbLblHost", "cbLblEncrypt", "cbEncryptWarning",
                    "cbBtnTest", "cbStale", "cbPending"):
            self.assertGreaterEqual(self.i18n.count(f"{key}:"), 2, key)

    def test_module_is_lazy_loaded_on_the_settings_tab(self):
        block = self.core[self.core.index("LAZY_TAB_SCRIPTS"):]
        block = block[:block.index("};")]
        self.assertIn("cloud-backup.js", block)

    def test_global_is_declared(self):
        self.assertIn("loadCloudBackup", _read("types", "globals.d.ts"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_ui.py -v`
Expected: FAIL — `FileNotFoundError: static/js/cloud-backup.js`

- [ ] **Step 3: Add the template section**

In `templates/dashboard.html`, inside the Settings tab, after the last existing `<article class="panel">` of that tab:

```html
        <article class="panel requires-write" id="cloudBackupPanel">
          <h3 style="font-size:17px; margin-bottom:6px;" data-i18n="cbTitle"><i class="fa-solid fa-cloud-arrow-up"></i> Copia offsite dei backup</h3>
          <p style="margin:0 0 12px; color:var(--text-muted); font-size:13px; max-width:64ch;" data-i18n="cbDesc">
            Copia i backup di configurazione su un host SFTP. L'archivio locale resta la fonte di verita': da qui si scrive soltanto.
          </p>
          <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); gap:10px; margin-bottom:12px;">
            <label style="display:flex; align-items:center; gap:8px; font-size:13px;">
              <input type="checkbox" id="cbEnabled" style="width:16px; height:16px;">
              <span data-i18n="cbLblEnabled">Attivo</span>
            </label>
            <label style="font-size:12px; color:var(--text-muted);"><span data-i18n="cbLblHost">Host</span>
              <input type="text" id="cbHost" placeholder="backup.example.net" style="width:100%;"></label>
            <label style="font-size:12px; color:var(--text-muted);"><span data-i18n="cbLblPort">Porta</span>
              <input type="number" id="cbPort" value="22" style="width:100%;"></label>
            <label style="font-size:12px; color:var(--text-muted);"><span data-i18n="cbLblUsername">Utente</span>
              <input type="text" id="cbUsername" style="width:100%;"></label>
            <label style="font-size:12px; color:var(--text-muted);"><span data-i18n="cbLblAuth">Autenticazione</span>
              <select id="cbAuth" style="width:100%;">
                <option value="key" data-i18n="cbAuthKey">Chiave SSH</option>
                <option value="password" data-i18n="cbAuthPassword">Password</option>
              </select></label>
            <label style="font-size:12px; color:var(--text-muted);"><span data-i18n="cbLblKeyPath">Percorso chiave</span>
              <input type="text" id="cbKeyPath" style="width:100%;"></label>
            <label style="font-size:12px; color:var(--text-muted);"><span data-i18n="cbLblPassphrase">Passphrase / password</span>
              <input type="password" id="cbSecret" autocomplete="new-password" style="width:100%;"></label>
            <label style="font-size:12px; color:var(--text-muted);"><span data-i18n="cbLblRemoteRoot">Cartella remota</span>
              <input type="text" id="cbRemoteRoot" placeholder="/srv/backups/sentinelnet" style="width:100%;"></label>
          </div>
          <label style="display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:4px;">
            <input type="checkbox" id="cbEncrypt" style="width:16px; height:16px;">
            <span data-i18n="cbLblEncrypt">Cifra i file prima di inviarli</span>
          </label>
          <p style="margin:0 0 12px; font-size:11.5px; color:var(--warning); max-width:64ch;" data-i18n="cbEncryptWarning">
            Senza cifratura le configurazioni arrivano in chiaro sull'host remoto. Con la cifratura la copia e' illeggibile senza la chiave di questo server: salvala altrove, offline.
          </p>
          <label style="display:flex; align-items:center; gap:8px; font-size:13px; margin-bottom:12px;">
            <input type="checkbox" id="cbRunAfterBackup" style="width:16px; height:16px;">
            <span data-i18n="cbLblRunAfterBackup">Esegui dopo ogni ciclo di backup</span>
          </label>
          <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px;">
            <button type="button" id="cbBtnSave" class="btn btn-primary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-floppy-disk"></i> <span data-i18n="cbBtnSave">Salva</span></button>
            <button type="button" id="cbBtnTest" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-plug-circle-check"></i> <span data-i18n="cbBtnTest">Prova connessione</span></button>
            <button type="button" id="cbBtnRun" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-cloud-arrow-up"></i> <span data-i18n="cbBtnRun">Copia adesso</span></button>
          </div>
          <div id="cbStatusBox" style="font-size:12.5px; color:var(--text-muted);">—</div>
        </article>
```

- [ ] **Step 4: Write the module**

```javascript
// static/js/cloud-backup.js
// Offsite backup mirror: settings form, connection test, manual run, status.
// Classic script, one shared global scope (see AGENTS.md).

(function () {
    const $ = id => document.getElementById(id);

    function fillForm(cfg) {
        $('cbEnabled').checked = !!cfg.enabled;
        $('cbHost').value = cfg.host || '';
        $('cbPort').value = cfg.port || 22;
        $('cbUsername').value = cfg.username || '';
        $('cbAuth').value = cfg.auth || 'key';
        $('cbKeyPath').value = cfg.key_path || '';
        $('cbRemoteRoot').value = cfg.remote_root || '';
        $('cbEncrypt').checked = !!cfg.encrypt_payload;
        $('cbRunAfterBackup').checked = !!cfg.run_after_backup;
        // The secret is never sent back by the API: an empty field means
        // "keep the stored one", and the placeholder says so.
        $('cbSecret').value = '';
        $('cbSecret').placeholder = (cfg.has_password || cfg.has_key_passphrase)
            ? (currentLang === 'en' ? 'stored - leave empty to keep'
                                    : 'salvata - lascia vuoto per mantenerla')
            : '';
    }

    function formValues() {
        const auth = $('cbAuth').value;
        const secret = $('cbSecret').value;
        return {
            enabled: $('cbEnabled').checked,
            kind: 'sftp',
            host: $('cbHost').value.trim(),
            port: parseInt($('cbPort').value, 10) || 22,
            username: $('cbUsername').value.trim(),
            auth: auth,
            key_path: $('cbKeyPath').value.trim(),
            key_passphrase: auth === 'key' ? secret : '',
            password: auth === 'password' ? secret : '',
            remote_root: $('cbRemoteRoot').value.trim(),
            encrypt_payload: $('cbEncrypt').checked,
            run_after_backup: $('cbRunAfterBackup').checked,
        };
    }

    function renderStatus(st) {
        const box = $('cbStatusBox');
        if (!box) return;
        if (!st.enabled) {
            box.textContent = i18n[currentLang].cbDisabled;
            return;
        }
        const hours = st.hours_since_success;
        const stale = hours === null || hours > (st.stale_after_hours || 48);
        const age = hours === null
            ? i18n[currentLang].cbNeverRan
            : `${i18n[currentLang].cbStale}: ${Math.round(hours)} h`;
        const last = st.last_run || {};
        box.innerHTML =
            `<div style="color:${stale ? 'var(--warning)' : 'var(--success)'}; font-weight:700;">${escapeHtml(age)}</div>` +
            `<div>${escapeHtml(i18n[currentLang].cbPending)}: <strong>${st.pending}</strong></div>` +
            `<div>${escapeHtml(i18n[currentLang].cbLastRun)}: ${last.ok ? 'ok' : escapeHtml(last.error || '—')}` +
            ` · ${last.uploaded || 0} ↑ · ${last.verified || 0} ✓</div>`;
    }

    async function loadCloudBackup() {
        const res = await apiFetch('/api/cloud-backup/settings');
        if (res && res.ok) fillForm(await res.json());
        const st = await apiFetch('/api/cloud-backup/status');
        if (st && st.ok) renderStatus(await st.json());
    }

    document.getElementById('cbBtnSave')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(formValues()),
        });
        if (res && res.ok) {
            showToast(i18n[currentLang].cbSaved, 'success');
            loadCloudBackup();
        } else {
            const body = res ? await res.json() : {};
            showToast(body.detail || 'errore', 'error');
        }
    });

    document.getElementById('cbBtnTest')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/test', { method: 'POST' });
        const data = (res && res.ok) ? await res.json() : { ok: false, error: 'HTTP' };
        showToast(data.ok ? `${i18n[currentLang].cbTestOk} ${data.fingerprint}` : data.error,
                  data.ok ? 'success' : 'error');
    });

    document.getElementById('cbBtnRun')?.addEventListener('click', async () => {
        const res = await apiFetch('/api/cloud-backup/run', { method: 'POST' });
        const data = (res && res.ok) ? await res.json() : { ok: false, error: 'HTTP' };
        showToast(data.ok ? i18n[currentLang].cbRunOk : data.error,
                  data.ok ? 'success' : 'error');
        loadCloudBackup();
    });

    window.loadCloudBackup = loadCloudBackup;
})();
```

- [ ] **Step 5: Register the module, the global and the strings**

`static/js/core.js` — `LAZY_TAB_SCRIPTS['tab-settings']` becomes:

```javascript
    'tab-settings': ['/static/js/settings.js', '/static/js/observability.js', '/static/js/cloud-backup.js'],
```

`types/globals.d.ts` — add:

```typescript
declare function loadCloudBackup(): Promise<void>;
```

`static/js/i18n.js`, in the `it` map:

```javascript
        cbTitle: "Copia offsite dei backup",
        cbDesc: "Copia i backup di configurazione su un host SFTP. L'archivio locale resta la fonte di verità: da qui si scrive soltanto.",
        cbLblEnabled: "Attivo",
        cbLblHost: "Host",
        cbLblPort: "Porta",
        cbLblUsername: "Utente",
        cbLblAuth: "Autenticazione",
        cbAuthKey: "Chiave SSH",
        cbAuthPassword: "Password",
        cbLblKeyPath: "Percorso chiave",
        cbLblPassphrase: "Passphrase / password",
        cbLblRemoteRoot: "Cartella remota",
        cbLblEncrypt: "Cifra i file prima di inviarli",
        cbEncryptWarning: "Senza cifratura le configurazioni arrivano in chiaro sull'host remoto. Con la cifratura la copia è illeggibile senza la chiave di questo server: salvala altrove, offline.",
        cbLblRunAfterBackup: "Esegui dopo ogni ciclo di backup",
        cbBtnSave: "Salva",
        cbBtnTest: "Prova connessione",
        cbBtnRun: "Copia adesso",
        cbSaved: "Impostazioni salvate",
        cbTestOk: "Connessione riuscita, host key",
        cbRunOk: "Copia completata",
        cbDisabled: "Copia offsite non attiva",
        cbNeverRan: "Mai eseguita",
        cbStale: "Ultima copia riuscita",
        cbPending: "File non ancora copiati",
        cbLastRun: "Ultimo ciclo",
```

and in the `en` map:

```javascript
        cbTitle: "Offsite backup copy",
        cbDesc: "Copies configuration backups to an SFTP host. The local archive stays the source of truth: this only writes.",
        cbLblEnabled: "Enabled",
        cbLblHost: "Host",
        cbLblPort: "Port",
        cbLblUsername: "User",
        cbLblAuth: "Authentication",
        cbAuthKey: "SSH key",
        cbAuthPassword: "Password",
        cbLblKeyPath: "Key path",
        cbLblPassphrase: "Passphrase / password",
        cbLblRemoteRoot: "Remote folder",
        cbLblEncrypt: "Encrypt files before sending",
        cbEncryptWarning: "Without encryption, configurations land in clear on the remote host. With it, the copy is unreadable without this server's key: back that key up elsewhere, offline.",
        cbLblRunAfterBackup: "Run after every backup cycle",
        cbBtnSave: "Save",
        cbBtnTest: "Test connection",
        cbBtnRun: "Copy now",
        cbSaved: "Settings saved",
        cbTestOk: "Connected, host key",
        cbRunOk: "Copy complete",
        cbDisabled: "Offsite copy is off",
        cbNeverRan: "Never ran",
        cbStale: "Last successful copy",
        cbPending: "Files not yet copied",
        cbLastRun: "Last run",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_cloud_backup_ui.py tests/test_lazy_tab_scripts.py tests/test_i18n_parity.py -v` → PASS
Run: `uv run python scripts/check_frontend.py` → clean

- [ ] **Step 7: Full gate and commit**

```bash
uv run pyrefly check && uv run pytest tests -n 4 && graphify update .
git add static/js/cloud-backup.js static/js/i18n.js static/js/core.js types/globals.d.ts templates/dashboard.html tests/test_cloud_backup_ui.py
git commit -m "feat(cloud-backup): settings section with status age and pending count

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 9: Trigger after backup, restore docs, version bump

**Files:**
- Modify: `core/core_engine.py` (new `maybe_mirror_offsite()` plus its call at the end of the backup cycle), `docs/operations.md`, `core/version.py`, `pyproject.toml`
- Test: `tests/test_cloud_backup_trigger.py`

**Interfaces:**
- Consumes: `services.cloud_backup.settings.read()`, `services.cloud_backup.run_mirror()`
- Produces: `core_engine.maybe_mirror_offsite() -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cloud_backup_trigger.py
# -*- coding: utf-8 -*-
"""Il mirror parte dopo un ciclo di backup solo se richiesto, e un suo
fallimento non deve mai far fallire il backup."""
import unittest
from unittest import mock

from core import core_engine


class TestMirrorTrigger(unittest.TestCase):

    def test_disabled_mirror_is_not_called(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": False, "run_after_backup": True}), \
             mock.patch("services.cloud_backup.run_mirror") as run:
            core_engine.maybe_mirror_offsite()
        run.assert_not_called()

    def test_run_after_backup_off_is_not_called(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": True, "run_after_backup": False}), \
             mock.patch("services.cloud_backup.run_mirror") as run:
            core_engine.maybe_mirror_offsite()
        run.assert_not_called()

    def test_enabled_mirror_runs(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": True, "run_after_backup": True}), \
             mock.patch("services.cloud_backup.run_mirror",
                        return_value={"ok": True}) as run:
            core_engine.maybe_mirror_offsite()
        run.assert_called_once()

    def test_a_failing_mirror_never_raises_into_the_backup_cycle(self):
        with mock.patch("services.cloud_backup.settings.read",
                        return_value={"enabled": True, "run_after_backup": True}), \
             mock.patch("services.cloud_backup.run_mirror",
                        side_effect=OSError("connection refused")):
            core_engine.maybe_mirror_offsite()  # must not raise


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cloud_backup_trigger.py -v`
Expected: FAIL — `AttributeError: module 'core.core_engine' has no attribute 'maybe_mirror_offsite'`

- [ ] **Step 3: Write minimal implementation**

Append to `core/core_engine.py`:

```python
def maybe_mirror_offsite() -> None:
    """Runs the offsite mirror after a backup cycle, when configured.

    Imported lazily and never allowed to raise: the mirror is redundancy, and a
    broken remote must not turn a successful backup collection into a failed
    one. The failure is recorded in the mirror's own state and shown in its
    status panel.
    """
    try:
        from services import cloud_backup
        from services.cloud_backup import settings as cb_settings
        cfg = cb_settings.read()
        if not (cfg.get("enabled") and cfg.get("run_after_backup")):
            return
        result = cloud_backup.run_mirror()
        if not result.get("ok"):
            logging.warning("[cloud_backup] mirror non riuscito: %s", result.get("error"))
    except Exception as exc:
        logging.warning("[cloud_backup] mirror non eseguito: %s", exc)
```

Then call `maybe_mirror_offsite()` once at the end of the function that completes a backup cycle — the one whose loop calls `save_backup` for each device, after the loop.

- [ ] **Step 4: Add the manual-restore section to `docs/operations.md`**

```markdown
## Restoring from the offsite mirror

The mirror is write-only: the app never reads it back. Recovering is a manual,
documented procedure - verify it once, by hand, before you need it.

1. Copy the archive locally:
   `scp -r user@backup.example.net:/srv/backups/sentinelnet ./archive`
2. Inspect `archive/_manifest.json`: `updated_at` is when the copy was last
   refreshed, `encrypted` says whether the files are ciphertext.
3. Rebuild the tree with the script shipped alongside it:

   ```sh
   python archive/restore.py --source archive --target ./restored
   # encrypted archive:
   python archive/restore.py --source archive --target ./restored --key-file fernet.key
   ```

4. Copy what you need back under `backup-config/<tenant>/<vendor>/`. Current
   configs keep their name; previous versions live in `.history/` with their UTC
   timestamp in the filename and are indexed by `<ip>-index.json`.

The Fernet key for an encrypted archive is the one in this install's key store.
Without it the copy cannot be read - which is why enabling encryption comes with
backing that key up separately, offline.
```

- [ ] **Step 5: Bump the version**

`core/version.py` → `__version__ = "0.15.0"`; `pyproject.toml` → `version = "0.15.0"`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `uv run pytest tests/test_cloud_backup_trigger.py tests/test_version.py -v`
Expected: PASS

- [ ] **Step 7: Full gate**

```bash
uv run pyrefly check
uv run pytest tests -n 4
uv run python scripts/check_frontend.py
graphify update .
git status --porcelain data/   # must print nothing
```

- [ ] **Step 8: Verify the executable still builds**

Run: `pyinstaller SentinelNet.spec`
Expected: build succeeds; no new asset was needed.

- [ ] **Step 9: Commit**

```bash
git add core/core_engine.py core/version.py pyproject.toml docs/operations.md tests/test_cloud_backup_trigger.py
git commit -m "feat(cloud-backup): run after backup cycle, restore docs, v0.15.0

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

## Out of scope for this plan

Per the spec: UI restore, S3/WebDAV transports, mirroring databases or settings,
automatic remote pruning, a scheduler, multiple destinations, compression.
Phase-2 items (staging-directory restore, orphan reporting, S3) get their own
plan once this one has run in a real deployment.
