# Site Wizard (bastion creation) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the three site modals (create, edit, agent enrollment) with one step-by-step side panel that tests the bastion before saving and makes the operator confirm its host-key fingerprint.

**Architecture:** Backend: `core/net_ssh.py` gains a no-pin draft probe, a 10-minute cache of probed keys and a confirm-then-pin function; `services/site_manager.py` gains `bastion_verified_ts`; `routers/sites.py` gains the draft endpoint and a `confirmed_fingerprint` field on create/update. Frontend: a reusable `static/js/ui-wizard.js` (step rail + validation on top of `ui-modal.js`) drives a `siteWizard` sheet in `templates/dashboard.html`, wired by `static/js/settings.js`.

**Tech Stack:** FastAPI + pydantic, paramiko, classic browser scripts (no bundler), pytest/unittest, node harnesses in `tests/js/*.mjs`.

**Spec:** `docs/superpowers/specs/2026-09-23-site-wizard-design.md`

## Global Constraints

- New and rewritten comments in English; leave existing Italian comments alone (AGENTS.md).
- No customer data anywhere: examples use RFC 5737 addresses (`198.51.100.x`, `192.0.2.x`), `switch-01`, `id-hk` style ids.
- Frontend: no inline handlers (`onclick=`), no new inline `style=` in the template, user-facing strings through `tr('key')` with IT **and** EN entries in `static/js/i18n.js`, modals only through `openModal`/`closeModal`, every `window.X =` has a `declare var X: any;` in `types/globals.d.ts`.
- CSS: existing tokens only (`--surface*`, `--border*`, `--text*`, `--lamp-*`, `--primary`, `--primary-glow`, `--font-code`, `--seam`, `--font-size-*`), `border-radius: 0`.
- Sites endpoints stay `require_unscoped_admin` + `require_tab("tab-sites")`.
- Do not bump the version (`core/version.py`, `pyproject.toml`): the user decides when.
- Gates before each commit (run and read the output): `uv run pyrefly check` (0 errors), `uv run python scripts/check_frontend.py` (when static/js or templates change), `uv run pytest tests -n 4`, `uv run python scripts/check_no_private_data.py`.
- Heredoc patches over ~130 lines get truncated in this environment: use the Edit/Write tools for code changes.

## Review Focus

1. **The operator edits the bastion host after a successful test, then saves** — the stale fingerprint must not be sent: the test result is invalidated on any change to host/port/identity (Task 7, `swInvalidateTest`) and the server rejects a fingerprint for a `(host, port)` it did not probe (Task 1 test `test_pin_confirmed_refuses_other_host`).
2. **The server restarts (or 10 minutes pass) between test and save** — save answers 409 and the panel returns to the Connection step instead of saving a pin nobody saw (Task 1 test `test_pin_confirmed_expires`, Task 3 test `test_stale_fingerprint_is_409`).
3. **Renaming a verified jump site** — must not clear the verified flag; only host/port/identity changes do (Task 2 test `test_rename_keeps_verified`).
4. **A bastion already pinned with a DIFFERENT key** — the draft test reports `host_key_mismatch`, never `success`, and caches nothing (Task 1 test `test_draft_probe_mismatch_raises`, Task 3 test `test_draft_statuses`).
5. **Scoped (tenant) admin opening the panel** — the draft endpoint refuses with 403 like every other sites endpoint (Task 3 test `test_scoped_admin_is_refused`).

---

### Task 1: Draft bastion probe and confirm-then-pin (`core/net_ssh.py`)

**Files:**
- Modify: `core/net_ssh.py` (imports at top; `_dial` at ~line 139; `probe_bastion` at ~line 226)
- Modify: `tests/test_jump_site.py:1212-1224` (`test_probe_bastion_ignores_the_cached_transport`)
- Test: `tests/test_bastion_fingerprint.py` (new)

**Interfaces:**
- Produces:
  - `net_ssh.fingerprint(key: paramiko.PKey) -> str` — `"SHA256:" + base64(sha256(key.asbytes()))` without padding, the form `ssh-keygen -lf` prints.
  - `net_ssh._dial(site: dict, pin: bool = True) -> paramiko.Transport`
  - `net_ssh.probe_bastion(site: dict) -> str` — now returns the fingerprint.
  - `net_ssh.probe_bastion_draft(host: str, port: int, identity: str) -> dict` — `{"fingerprint": str, "key_type": str, "known": bool}`; raises `BastionAuthError`, `BastionHostKeyError`, or the socket/SSH error.
  - `net_ssh.pin_confirmed(host: str, port: int, fp: str) -> bool`
  - `net_ssh.PROBE_TTL = 600`, `net_ssh._probed_keys: dict[tuple[str, int], tuple[PKey, float]]`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_bastion_fingerprint.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Bastion host key: probed without pinning, pinned only once confirmed.

The site wizard shows the fingerprint to the operator before trusting it.
Until then nothing may land in ssh_known_hosts, and what gets pinned must be
the key the SERVER saw — the browser only sends back the fingerprint.
"""
import os
import tempfile
import time
import unittest
from unittest import mock

import paramiko

from core import net_ssh

HOST, PORT = "198.51.100.50", 22


def _fake_transport(key):
    tr = mock.Mock()
    tr.get_remote_server_key.return_value = key
    return tr


class BastionFingerprint(unittest.TestCase):
    def setUp(self):
        net_ssh._probed_keys.clear()
        self.td = tempfile.TemporaryDirectory()
        self.known_hosts = os.path.join(self.td.name, "ssh_known_hosts")
        self.p_path = mock.patch("core.data_config.get_path", return_value=self.known_hosts)
        self.p_path.start()

    def tearDown(self):
        self.p_path.stop()
        self.td.cleanup()

    def _probe(self, key, connect_error=None):
        tr = _fake_transport(key)
        if connect_error:
            tr.connect.side_effect = connect_error
        with mock.patch.object(net_ssh.socket, "create_connection", return_value=mock.Mock()), \
             mock.patch.object(net_ssh.paramiko, "Transport", return_value=tr), \
             mock.patch("security.identity_manager.get_identity_credentials",
                        return_value=("u", "p", "")):
            return net_ssh.probe_bastion_draft(HOST, PORT, "id-hk")

    def test_fingerprint_is_openssh_sha256(self):
        key = paramiko.ECDSAKey.generate()
        fp = net_ssh.fingerprint(key)
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertFalse(fp.endswith("="))
        self.assertEqual(len(fp), len("SHA256:") + 43)

    def test_draft_probe_pins_nothing(self):
        key = paramiko.ECDSAKey.generate()
        out = self._probe(key)
        self.assertEqual(out["fingerprint"], net_ssh.fingerprint(key))
        self.assertEqual(out["key_type"], key.get_name())
        self.assertFalse(out["known"])
        self.assertIsNone(net_ssh._pinned_host_key(HOST, PORT))

    def test_pin_confirmed_pins_the_probed_key(self):
        key = paramiko.ECDSAKey.generate()
        fp = self._probe(key)["fingerprint"]
        self.assertTrue(net_ssh.pin_confirmed(HOST, PORT, fp))
        self.assertEqual(net_ssh._pinned_host_key(HOST, PORT), key)
        # One confirmation, one pin: the cache entry is consumed.
        self.assertFalse(net_ssh.pin_confirmed(HOST, PORT, fp))

    def test_pin_confirmed_refuses_a_different_fingerprint(self):
        self._probe(paramiko.ECDSAKey.generate())
        other = net_ssh.fingerprint(paramiko.ECDSAKey.generate())
        self.assertFalse(net_ssh.pin_confirmed(HOST, PORT, other))
        self.assertIsNone(net_ssh._pinned_host_key(HOST, PORT))

    def test_pin_confirmed_refuses_other_host(self):
        fp = self._probe(paramiko.ECDSAKey.generate())["fingerprint"]
        self.assertFalse(net_ssh.pin_confirmed("198.51.100.51", PORT, fp))

    def test_pin_confirmed_expires(self):
        fp = self._probe(paramiko.ECDSAKey.generate())["fingerprint"]
        key, _ = net_ssh._probed_keys[(HOST, PORT)]
        net_ssh._probed_keys[(HOST, PORT)] = (key, time.time() - net_ssh.PROBE_TTL - 1)
        self.assertFalse(net_ssh.pin_confirmed(HOST, PORT, fp))

    def test_known_key_is_reported(self):
        key = paramiko.ECDSAKey.generate()
        net_ssh._pin_host_key(HOST, PORT, key)
        self.assertTrue(self._probe(key)["known"])

    def test_draft_probe_mismatch_raises(self):
        net_ssh._pin_host_key(HOST, PORT, paramiko.ECDSAKey.generate())
        with self.assertRaises(net_ssh.BastionHostKeyError):
            self._probe(paramiko.ECDSAKey.generate(),
                        connect_error=paramiko.SSHException("Bad host key from server"))
        self.assertEqual(net_ssh._probed_keys, {})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_bastion_fingerprint.py -q`
Expected: FAIL — `AttributeError: module 'core.net_ssh' has no attribute '_probed_keys'`.

- [ ] **Step 3: Implement in `core/net_ssh.py`**

Add to the imports at the top (next to the existing `import logging` / `import os`):

```python
import base64
import hashlib
import time
```

Change the `_dial` signature and docstring:

```python
def _dial(site: dict, pin: bool = True) -> paramiko.Transport:
    """Open and authenticate one transport to the site's bastion. No caching.

    pin=False is the site wizard's draft test: the key is shown to the
    operator first and pinned only by pin_confirmed().
    """
```

and at the end of `_dial` replace

```python
    if pinned is None:
        _pin_host_key(host, port, tr.get_remote_server_key())
    return tr
```

with

```python
    if pinned is None and pin:
        _pin_host_key(host, port, tr.get_remote_server_key())
    return tr
```

Replace `probe_bastion` with:

```python
def probe_bastion(site: dict) -> str:
    """Dial the bastion with the site's current identity and hang up.

    Deliberately does NOT go through _transport: the point is to test the
    credential as configured now, and a cached transport opened with the
    previous one would answer 'fine'. Returns the host key fingerprint.
    Raises BastionAuthError on a refused login, or the underlying socket/SSH
    error otherwise.
    """
    tr = _dial(site)
    try:
        return fingerprint(tr.get_remote_server_key())
    finally:
        tr.close()


# Keys seen by a draft probe, waiting for the operator to confirm them.
# ponytail: in-process dict — a restart forgets pending confirmations, and
# the wizard then answers "test again", which is the safe direction.
PROBE_TTL = 600
_probed_keys: dict = {}


def fingerprint(key) -> str:
    """OpenSSH SHA256 fingerprint, the form `ssh-keygen -lf` prints."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def probe_bastion_draft(host: str, port: int, identity: str) -> dict:
    """Test an unsaved bastion. Pins nothing: the key waits in _probed_keys
    until the operator confirms its fingerprint (pin_confirmed)."""
    port = int(port)
    known = _pinned_host_key(host, port) is not None
    tr = _dial({"id": "(draft)", "jump_host": host, "jump_port": port,
                "jump_identity": identity}, pin=False)
    try:
        key = tr.get_remote_server_key()
    finally:
        tr.close()
    _probed_keys[(host, port)] = (key, time.time())
    return {"fingerprint": fingerprint(key), "key_type": key.get_name(), "known": known}


def pin_confirmed(host: str, port: int, fp: str) -> bool:
    """Pin the key a draft probe saw for (host, port) if fp is its fingerprint.

    The browser never sends key material: it sends back the fingerprint the
    operator confirmed, and this checks it against what the server saw.
    """
    port = int(port)
    entry = _probed_keys.get((host, port))
    if not entry or time.time() - entry[1] > PROBE_TTL:
        return False
    key = entry[0]
    if fingerprint(key) != fp:
        return False
    _pin_host_key(host, port, key)
    _probed_keys.pop((host, port), None)
    return True
```

Keep `_netmiko_connect` and everything after it unchanged.

- [ ] **Step 4: Fix the existing probe test for the new return value**

In `tests/test_jump_site.py`, `test_probe_bastion_ignores_the_cached_transport`, replace

```python
            with mock.patch.object(net_ssh, "_dial") as dial:
                net_ssh.probe_bastion(dict(self.SITE))
            dial.assert_called_once()
            dial.return_value.close.assert_called_once()
```

with

```python
            with mock.patch.object(net_ssh, "_dial") as dial:
                dial.return_value.get_remote_server_key.return_value = \
                    paramiko.ECDSAKey.generate()
                fp = net_ssh.probe_bastion(dict(self.SITE))
            dial.assert_called_once()
            dial.return_value.close.assert_called_once()
            self.assertTrue(fp.startswith("SHA256:"))
```

(Check `paramiko` is imported in that file: `grep -n "^import paramiko" tests/test_jump_site.py`; if absent, add `import paramiko` to its imports.)

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/test_bastion_fingerprint.py tests/test_jump_site.py -q`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add core/net_ssh.py tests/test_bastion_fingerprint.py tests/test_jump_site.py
git commit -m "feat(ssh): probe a draft bastion without pinning, pin on confirmed fingerprint"
```

---

### Task 2: `bastion_verified_ts` on sites (`services/site_manager.py`)

**Files:**
- Modify: `services/site_manager.py` (`create_site` ~line 185, `update_site` ~line 233; new function after `touch_last_seen`)
- Test: `tests/test_site_verified.py` (new)

**Interfaces:**
- Produces:
  - Site field `bastion_verified_ts: float | None` (None on create; absent on sites created before this change — read it with `.get`).
  - `site_manager.mark_bastion_verified(site_id: str) -> bool`
  - `update_site` clears `bastion_verified_ts` when `jump_host`, `jump_port` or `jump_identity` change.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_site_verified.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""A jump site remembers whether its bastion was verified, and forgets it
when the bastion it points at changes."""
import os
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_siteverified_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP

from core import data_config  # noqa: E402
data_config.DATA_DIR = _TMP

from services import site_manager  # noqa: E402

JUMP = {"jump_host": "198.51.100.60", "jump_port": 22, "jump_identity": "id-hk"}


class SiteVerified(unittest.TestCase):
    def _jump_site(self, name):
        site, _ = site_manager.create_site(name, "jump", [], **JUMP)
        return site["id"]

    def test_new_site_is_not_verified(self):
        sid = self._jump_site("verif-new")
        self.assertIsNone(site_manager.get_site(sid)["bastion_verified_ts"])

    def test_mark_sets_a_timestamp(self):
        sid = self._jump_site("verif-mark")
        self.assertTrue(site_manager.mark_bastion_verified(sid))
        self.assertIsInstance(site_manager.get_site(sid)["bastion_verified_ts"], float)
        self.assertFalse(site_manager.mark_bastion_verified("no-such-site"))

    def test_changing_the_bastion_clears_it(self):
        for field, value in (("jump_host", "198.51.100.61"), ("jump_port", 2222),
                             ("jump_identity", "id-other")):
            with self.subTest(field=field):
                sid = self._jump_site(f"verif-{field}")
                site_manager.mark_bastion_verified(sid)
                site_manager.update_site(sid, **{field: value})
                self.assertIsNone(site_manager.get_site(sid)["bastion_verified_ts"])

    def test_rename_keeps_verified(self):
        sid = self._jump_site("verif-rename")
        site_manager.mark_bastion_verified(sid)
        site_manager.update_site(sid, name="verif-renamed", subnets=["10.30.0.0/24"])
        self.assertIsNotNone(site_manager.get_site(sid)["bastion_verified_ts"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_site_verified.py -q`
Expected: FAIL — `KeyError: 'bastion_verified_ts'` / `AttributeError: ... mark_bastion_verified`.

- [ ] **Step 3: Implement**

In `create_site`, add the field to the stored dict:

```python
            "last_seen": None,
            "bastion_verified_ts": None,
            **jump_fields,
```

Add above `def update_site`:

```python
_BASTION_LINK = ("jump_host", "jump_port", "jump_identity")
```

In `update_site`, replace

```python
        if site["mode"] == "jump":
            site.update(_validate_jump({**site, **kwargs}))
```

with

```python
        if site["mode"] == "jump":
            before = tuple(site.get(k) for k in _BASTION_LINK)
            site.update(_validate_jump({**site, **kwargs}))
            # A verification vouches for one bastion: pointing the site at
            # another host, port or login makes it unverified again.
            if tuple(site.get(k) for k in _BASTION_LINK) != before:
                site["bastion_verified_ts"] = None
```

Add after `touch_last_seen`:

```python
def mark_bastion_verified(site_id: str) -> bool:
    """Record that the site's bastion answered a test with a confirmed key."""
    with _lock:
        data = _load()
        site = data.get(site_id)
        if not site:
            return False
        site["bastion_verified_ts"] = time.time()
        _save(data)
        return True
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_site_verified.py tests/test_sites.py tests/test_site_editing.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add services/site_manager.py tests/test_site_verified.py
git commit -m "feat(sites): bastion_verified_ts, cleared when the bastion changes"
```

---

### Task 3: Sites API — draft test, confirmed fingerprint, verified flag (`routers/sites.py`)

**Files:**
- Modify: `routers/sites.py` (schemas ~line 36-60, `create_site_ep` ~81, `update_site_ep` ~95, `test_bastion_ep` ~148)
- Test: `tests/test_site_wizard_api.py` (new)
- Possibly modify: `tests/test_router_parity.py` (only if Step 5 shows a failure)

**Interfaces:**
- Consumes: `net_ssh.probe_bastion_draft`, `net_ssh.pin_confirmed`, `net_ssh.probe_bastion -> str` (Task 1); `site_manager.mark_bastion_verified` (Task 2).
- Produces:
  - `POST /api/sites/test-bastion/draft` body `{jump_host: str, jump_port: int = 22, jump_identity: str}` → `{status, message?, fingerprint?, key_type?, known?}`, `status ∈ {success, auth_failed, unreachable, host_key_mismatch}`.
  - `POST /api/sites` and `POST /api/sites/update` accept `confirmed_fingerprint: str | null`; 409 when it cannot be pinned.
  - `POST /api/sites/test-bastion` → on success `{status: "success", fingerprint}` and marks the site verified; `host_key_mismatch` as its own status.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_site_wizard_api.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Site wizard API: test an unsaved bastion, save with a confirmed key.

net_ssh is mocked at the function boundary: the dial itself is covered by
tests/test_bastion_fingerprint.py.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="sentinelnet_test_sitewizard_")
os.environ["SENTINELNET_DATA_DIR"] = _TMP
os.environ.setdefault("SENTINELNET_JWT_SECRET", "test-secret-site-wizard")

from fastapi.testclient import TestClient  # noqa: E402

import app_server  # noqa: E402
from core import net_ssh  # noqa: E402

ADMIN, SCOPED, PW = "sitewiz_admin", "sitewiz_scoped", "PasswordSicura1!"
DRAFT = {"jump_host": "198.51.100.70", "jump_port": 22, "jump_identity": "id-hk"}
FP = "SHA256:" + "A" * 43


def _login(client, user):
    r = client.post("/api/auth/login", json={"username": user, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


class SiteWizardApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from security import user_manager
        user_manager.create_user(ADMIN, PW, role="admin")
        user_manager.create_user(SCOPED, PW, role="admin", groups=["tenant-a"])
        cls.client = TestClient(app_server.app)
        cls.h = _login(cls.client, ADMIN)
        cls.hs = _login(cls.client, SCOPED)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP, ignore_errors=True)

    def _site(self, sid):
        sites = self.client.get("/api/sites", headers=self.h).json()["sites"]
        return next(s for s in sites if s["id"] == sid)

    def _draft(self, **patch):
        with mock.patch.object(net_ssh, "probe_bastion_draft", **patch):
            return self.client.post("/api/sites/test-bastion/draft", headers=self.h, json=DRAFT)

    def test_draft_statuses(self):
        ok = self._draft(return_value={"fingerprint": FP, "key_type": "ssh-ed25519", "known": False})
        self.assertEqual(ok.json(), {"status": "success", "fingerprint": FP,
                                     "key_type": "ssh-ed25519", "known": False})
        cases = ((net_ssh.BastionAuthError("refused"), "auth_failed"),
                 (net_ssh.BastionHostKeyError("changed"), "host_key_mismatch"),
                 (OSError("timed out"), "unreachable"))
        for exc, status in cases:
            with self.subTest(status=status):
                r = self._draft(side_effect=exc)
                self.assertEqual(r.status_code, 200, r.text)
                self.assertEqual(r.json()["status"], status)
                self.assertIn(str(exc), r.json()["message"])

    def test_draft_rejects_a_bad_port(self):
        r = self.client.post("/api/sites/test-bastion/draft", headers=self.h,
                             json={**DRAFT, "jump_port": 70000})
        self.assertEqual(r.status_code, 400)

    def test_scoped_admin_is_refused(self):
        r = self.client.post("/api/sites/test-bastion/draft", headers=self.hs, json=DRAFT)
        self.assertEqual(r.status_code, 403)

    def test_confirmed_fingerprint_pins_and_verifies(self):
        with mock.patch.object(net_ssh, "pin_confirmed", return_value=True) as pin, \
             mock.patch("routers.sites.log_audit") as audit:
            r = self.client.post("/api/sites", headers=self.h, json={
                "name": "wiz-verified", "mode": "jump", **DRAFT,
                "confirmed_fingerprint": FP})
        self.assertEqual(r.status_code, 200, r.text)
        pin.assert_called_once_with("198.51.100.70", 22, FP)
        self.assertIsNotNone(self._site(r.json()["site"]["id"])["bastion_verified_ts"])
        self.assertTrue(any("impronta" in c.args[0] for c in audit.call_args_list))

    def test_stale_fingerprint_is_409(self):
        with mock.patch.object(net_ssh, "pin_confirmed", return_value=False):
            r = self.client.post("/api/sites", headers=self.h, json={
                "name": "wiz-stale", "mode": "jump", **DRAFT,
                "confirmed_fingerprint": FP})
        self.assertEqual(r.status_code, 409)
        sites = self.client.get("/api/sites", headers=self.h).json()["sites"]
        self.assertFalse(any(s["name"] == "wiz-stale" for s in sites))

    def test_unverified_save_is_allowed_and_audited(self):
        with mock.patch("routers.sites.log_audit") as audit:
            r = self.client.post("/api/sites", headers=self.h, json={
                "name": "wiz-unverified", "mode": "jump", **DRAFT})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(self._site(r.json()["site"]["id"])["bastion_verified_ts"])
        self.assertTrue(any("non verificato" in c.args[0] for c in audit.call_args_list))

    def test_update_with_new_host_needs_a_confirmation_to_stay_verified(self):
        r = self.client.post("/api/sites", headers=self.h, json={
            "name": "wiz-move", "mode": "jump", **DRAFT})
        sid = r.json()["site"]["id"]
        from services import site_manager
        site_manager.mark_bastion_verified(sid)
        r = self.client.post("/api/sites/update", headers=self.h,
                             json={"id": sid, "jump_host": "198.51.100.71"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(self._site(sid)["bastion_verified_ts"])
        with mock.patch.object(net_ssh, "pin_confirmed", return_value=True) as pin:
            r = self.client.post("/api/sites/update", headers=self.h, json={
                "id": sid, "jump_host": "198.51.100.72", "confirmed_fingerprint": FP})
        self.assertEqual(r.status_code, 200, r.text)
        pin.assert_called_once_with("198.51.100.72", 22, FP)
        self.assertIsNotNone(self._site(sid)["bastion_verified_ts"])

    def test_saved_site_test_marks_verified_and_returns_fingerprint(self):
        r = self.client.post("/api/sites", headers=self.h, json={
            "name": "wiz-table", "mode": "jump", **DRAFT})
        sid = r.json()["site"]["id"]
        with mock.patch.object(net_ssh, "probe_bastion", return_value=FP):
            r = self.client.post("/api/sites/test-bastion", headers=self.h, json={"id": sid})
        self.assertEqual(r.json(), {"status": "success", "fingerprint": FP})
        self.assertIsNotNone(self._site(sid)["bastion_verified_ts"])
        with mock.patch.object(net_ssh, "probe_bastion",
                               side_effect=net_ssh.BastionHostKeyError("changed")):
            r = self.client.post("/api/sites/test-bastion", headers=self.h, json={"id": sid})
        self.assertEqual(r.json()["status"], "host_key_mismatch")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_site_wizard_api.py -q`
Expected: FAIL — draft route 404/405, no `bastion_verified_ts` handling.

- [ ] **Step 3: Implement in `routers/sites.py`**

Replace `SiteSchema` with:

```python
class SiteSchema(BaseModel):
    name: str
    mode: str = "central"          # "central" | "agent" | "jump"
    subnets: List[str] = []
    # Bastion fields, required by site_manager only when mode == "jump".
    jump_host: Optional[str] = None
    jump_port: Optional[int] = None
    jump_identity: Optional[str] = None
    # Default identity for the devices behind the bastion (not the bastion's own).
    device_identity: Optional[str] = None
    # Fingerprint the operator confirmed in the wizard's test step.
    confirmed_fingerprint: Optional[str] = None
```

In `SiteUpdateSchema` add, after `central_manages_devices`:

```python
    confirmed_fingerprint: Optional[str] = None
```

After `SiteIdSchema` add:

```python
class BastionDraftSchema(BaseModel):
    jump_host: str
    jump_port: int = 22
    jump_identity: str
```

Add above `create_site_ep`:

```python
def _pin_or_409(host: str, port: int, fp: str) -> None:
    """Pin the key the draft test saw, or refuse: the confirmation is only
    worth something for the key the server itself observed."""
    from core import net_ssh
    if not net_ssh.pin_confirmed(host, port, fp):
        raise HTTPException(
            status_code=409,
            detail="Impronta non piu' valida per questo bastione: ripetere il test.")
```

Replace `create_site_ep` with:

```python
@router.post("/api/sites", dependencies=[Depends(require_tab("tab-sites"))])
def create_site_ep(payload: SiteSchema, current_user = Depends(require_unscoped_admin)):
    who = current_user.get('sub')
    fp = payload.confirmed_fingerprint if payload.mode == "jump" else None
    if fp:
        _pin_or_409((payload.jump_host or "").strip(), payload.jump_port or 22, fp)
    try:
        site, token = site_manager.create_site(
            payload.name, payload.mode, payload.subnets,
            jump_host=payload.jump_host, jump_port=payload.jump_port,
            jump_identity=payload.jump_identity,
            device_identity=payload.device_identity)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    log_audit(f"Sede '{site['id']}' (mode: {payload.mode}) creata da '{who}'.")
    if fp:
        site_manager.mark_bastion_verified(site["id"])
        site = site_manager.get_site(site["id"])
        log_audit(f"Sede '{site['id']}': impronta del bastione {fp} confermata da '{who}'.")
    elif payload.mode == "jump":
        log_audit(f"Sede '{site['id']}' salvata con bastione non verificato da '{who}'.")
    # Il token in chiaro è restituito UNA SOLA VOLTA (poi solo hash su disco).
    return {"status": "success", "site": site, "token": token}
```

In `update_site_ep`, right after the `jump_kwargs` block and before `try: ok = site_manager.update_site(...)`, insert:

```python
    who = current_user.get('sub')
    fp = payload.confirmed_fingerprint
    existing = site_manager.get_site(payload.id)
    if fp and existing:
        host = (payload.jump_host or existing.get("jump_host") or "").strip()
        port = payload.jump_port or existing.get("jump_port") or 22
        _pin_or_409(host, port, fp)
```

and right after the existing block

```python
    if any(k in jump_kwargs for k in ("jump_host", "jump_port", "jump_identity")):
        from core import net_ssh
        net_ssh.invalidate_site(payload.id)
```

insert:

```python
    if fp and existing:
        site_manager.mark_bastion_verified(payload.id)
        log_audit(f"Sede '{payload.id}': impronta del bastione {fp} confermata da '{who}'.")
    elif any(k in jump_kwargs for k in ("jump_host", "jump_port", "jump_identity")):
        log_audit(f"Sede '{payload.id}': bastione modificato senza verifica da '{who}'.")
```

Replace `test_bastion_ep` with the two endpoints below:

```python
@router.post("/api/sites/test-bastion", dependencies=[Depends(require_tab("tab-sites"))])
async def test_bastion_ep(payload: SiteIdSchema, current_user = Depends(require_unscoped_admin)):
    # Answers the question the device errors cannot: is it the BASTION login
    # that is wrong? A refused bastion and a refused device both surface as
    # "authentication failed" on the device row, and the operator ends up
    # rotating the credential on the wrong machine.
    from core import net_ssh
    from core.ssh_pool import run_ssh
    site = site_manager.get_site(payload.id)
    if not site:
        raise HTTPException(status_code=404, detail="Sede non trovata.")
    if site.get("mode") != "jump":
        raise HTTPException(status_code=400, detail="La sede non e' in modalita' jump.")
    who = current_user.get('sub')
    try:
        # WP11: il probe SSH del bastione gira sul pool dedicato.
        fp = await run_ssh(net_ssh.probe_bastion, site)
    except net_ssh.BastionAuthError as e:
        log_audit(f"Test bastione sede '{payload.id}' da '{who}': credenziali rifiutate.")
        return {"status": "auth_failed", "message": str(e)}
    except net_ssh.BastionHostKeyError as e:
        log_audit(f"Test bastione sede '{payload.id}' da '{who}': chiave host diversa.")
        return {"status": "host_key_mismatch", "message": str(e)}
    except Exception as e:
        log_audit(f"Test bastione sede '{payload.id}' da '{who}': irraggiungibile.")
        return {"status": "unreachable", "message": str(e)}
    site_manager.mark_bastion_verified(payload.id)
    log_audit(f"Test bastione sede '{payload.id}' da '{who}': OK.")
    return {"status": "success", "fingerprint": fp}


@router.post("/api/sites/test-bastion/draft", dependencies=[Depends(require_tab("tab-sites"))])
async def test_bastion_draft_ep(payload: BastionDraftSchema,
                                current_user = Depends(require_unscoped_admin)):
    # The wizard's test step: dial a bastion that is not saved yet. Nothing is
    # pinned here — the key waits for the operator to confirm its fingerprint.
    from core import net_ssh
    from core.ssh_pool import run_ssh
    host = payload.jump_host.strip()
    if not host or not (1 <= payload.jump_port <= 65535) or not payload.jump_identity:
        raise HTTPException(status_code=400, detail="Host, porta o identita' del bastione non validi.")
    who = current_user.get('sub')
    try:
        info = await run_ssh(net_ssh.probe_bastion_draft, host,
                             payload.jump_port, payload.jump_identity)
    except net_ssh.BastionAuthError as e:
        log_audit(f"Test bozza bastione {host} da '{who}': credenziali rifiutate.")
        return {"status": "auth_failed", "message": str(e)}
    except net_ssh.BastionHostKeyError as e:
        log_audit(f"Test bozza bastione {host} da '{who}': chiave host diversa.")
        return {"status": "host_key_mismatch", "message": str(e)}
    except Exception as e:
        log_audit(f"Test bozza bastione {host} da '{who}': irraggiungibile.")
        return {"status": "unreachable", "message": str(e)}
    log_audit(f"Test bozza bastione {host} da '{who}': OK, impronta {info['fingerprint']}.")
    return {"status": "success", **info}
```

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/test_site_wizard_api.py tests/test_site_editing.py tests/test_sites.py tests/test_jump_site.py -q`
Expected: all PASS.

- [ ] **Step 5: Run the OpenAPI parity test**

Run: `uv run pytest tests/test_router_parity.py -q`
Expected: PASS (`/api/sites/test-bastion` is already a `NEW_PREFIXES` entry and prefixes the draft path). If `TestFullParity` fails on `/api/sites` or `/api/sites/update` because their request schema gained `confirmed_fingerprint`, append exactly the failing path strings the test reports to `NEW_PREFIXES` in `tests/test_router_parity.py`, preceded by this comment:

```python
                    # Site wizard (2026-09-23): the confirmed bastion host-key
                    # fingerprint on create/update.
```

Do not regenerate `tests_data/openapi_golden.json`. Re-run until green.

- [ ] **Step 6: Commit**

```bash
git add routers/sites.py tests/test_site_wizard_api.py tests/test_router_parity.py
git commit -m "feat(sites): draft bastion test, confirmed fingerprint on save, verified flag"
```

---

### Task 4: Reusable step panel (`static/js/ui-wizard.js`)

**Files:**
- Create: `static/js/ui-wizard.js`
- Create: `tests/js/test_ui_wizard.mjs`
- Create: `tests/test_ui_wizard.py`
- Modify: `templates/dashboard.html` (script include right after `ui-modal.js`, ~line 5850)
- Modify: `types/globals.d.ts` (cross-module section)

**Interfaces:**
- Consumes: `openModal(id, onClose)`, `closeModal(id)` (ui-modal.js), `tr(key)` (i18n.js).
- Produces: `createWizard(panelId, { steps, onFinish }) -> { open({at?, editable?, onClose?}), close(), goTo(id), refresh(), current() }`.
  - `steps[i]`: `{ id: string, label: string (i18n key), validate?: () => boolean, onEnter?: () => void, skip?: () => boolean, finishLabel?: string (i18n key) }`.
  - Panel markup contract: `[data-wizard-rail]` (an `<ol>`), `[data-wizard-back]`, `[data-wizard-next]`, one `[data-step="<id>"]` per step.
  - `onFinish(stepId)` runs when Next is pressed on the last active step.

- [ ] **Step 1: Write the failing node harness and its pytest wrapper**

Create `tests/js/test_ui_wizard.mjs`:

```js
// ui-wizard.js against a fake DOM: Next is gated by validate(), skip() drops
// a step from both navigation and the rail, the rail is clickable only in
// edit mode, and Next on the last active step calls onFinish.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/ui-wizard.js', import.meta.url), 'utf8');

function el(tag) {
    return {
        tagName: tag, hidden: false, disabled: false, textContent: '', className: '',
        children: [], attrs: {}, listeners: {},
        setAttribute(k, v) { this.attrs[k] = v; },
        appendChild(c) { this.children.push(c); return c; },
        replaceChildren(...c) { this.children = c; },
        addEventListener(t, f) { (this.listeners[t] ||= []).push(f); },
        fire(t) { (this.listeners[t] || []).forEach((f) => f({})); },
    };
}

const sections = { a: el('section'), b: el('section'), c: el('section') };
const rail = el('ol'), back = el('button'), next = el('button');
const panel = el('div');
panel.querySelector = (sel) => {
    if (sel === '[data-wizard-rail]') return rail;
    if (sel === '[data-wizard-back]') return back;
    if (sel === '[data-wizard-next]') return next;
    const m = /data-step="(\w+)"/.exec(sel);
    return m ? sections[m[1]] : null;
};
global.window = {};
global.document = { getElementById: (id) => (id === 'wiz' ? panel : null), createElement: el };
global.tr = (k) => k;
let opened = null;
global.openModal = (id) => { opened = id; };
global.closeModal = (id) => { if (opened === id) opened = null; };

const createWizard = new Function(src + '; return createWizard;')();
assert.strictEqual(typeof window.createWizard, 'function', 'window.createWizard not exposed');

let aValid = false, skipB = false, finished = null;
const wiz = createWizard('wiz', {
    steps: [
        { id: 'a', label: 'la', validate: () => aValid },
        { id: 'b', label: 'lb', skip: () => skipB },
        { id: 'c', label: 'lc', finishLabel: 'save' },
    ],
    onFinish: (id) => { finished = id; },
});
const tick = () => new Promise((r) => setTimeout(r, 0));

wiz.open();
assert.strictEqual(opened, 'wiz');
assert.strictEqual(wiz.current(), 'a');
assert.ok(sections.b.hidden && sections.c.hidden && !sections.a.hidden, 'only the current step is visible');
assert.strictEqual(next.disabled, true, 'Next must be disabled while validate() is false');
assert.strictEqual(back.hidden, true, 'no Back on the first step');

next.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'a', 'a failing validate() must not advance');

aValid = true; panel.fire('input');
assert.strictEqual(next.disabled, false, 'refresh on input re-enables Next');
next.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'b');

back.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'a');

skipB = true; wiz.goTo('a');
assert.strictEqual(rail.children.length, 2, 'a skipped step leaves the rail');
next.fire('click'); await tick();
assert.strictEqual(wiz.current(), 'c', 'Next jumps over a skipped step');
assert.strictEqual(next.textContent, 'save', 'last step shows its finishLabel');

next.fire('click'); await tick();
assert.strictEqual(finished, 'c', 'Next on the last step calls onFinish');

// Rail: plain text when creating, buttons (except the current step) in edit mode.
assert.ok(rail.children.every((li) => li.children.length === 0), 'rail is not clickable when creating');
wiz.open({ at: 'c', editable: true });
const buttons = rail.children.filter((li) => li.children.length === 1);
assert.strictEqual(buttons.length, 1, 'every non-current step is a button in edit mode');
buttons[0].children[0].fire('click');
assert.strictEqual(wiz.current(), 'a');
assert.strictEqual(rail.children[0].attrs['aria-current'], 'step');

wiz.close();
assert.strictEqual(opened, null);
console.log('ok - ui-wizard navigation, validation, skip, rail');
```

Create `tests/test_ui_wizard.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""ui-wizard.js: the step panel shared by the site, device and provisioning
flows. The node harness runs the real file against a fake DOM."""
import os
import shutil
import subprocess
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class UiWizard(unittest.TestCase):
    def test_harness(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node non disponibile")
        proc = subprocess.run([node, os.path.join(_REPO_ROOT, "tests", "js", "test_ui_wizard.mjs")],
                              capture_output=True, text=True, cwd=_REPO_ROOT)
        self.assertEqual(0, proc.returncode, proc.stderr or proc.stdout)

    def test_loaded_after_the_modal_manager_and_before_core(self):
        html = _read("templates", "dashboard.html")
        modal = html.find("/static/js/ui-modal.js")
        wizard = html.find("/static/js/ui-wizard.js")
        core = html.find("/static/js/core.js")
        self.assertTrue(0 < modal < wizard < core, "order must be ui-modal, ui-wizard, core")

    def test_exposure_is_declared(self):
        self.assertIn("window.createWizard = createWizard", _read("static", "js", "ui-wizard.js"))
        self.assertIn("declare var createWizard: any;", _read("types", "globals.d.ts"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_ui_wizard.py -q`
Expected: FAIL — `ui-wizard.js` does not exist.

- [ ] **Step 3: Implement `static/js/ui-wizard.js`**

```js
// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
//
// Step-by-step panel on top of the modal manager (ui-modal.js): a rail of
// steps, one visible section at a time, Next gated by the step's validate().
// Shared by the site, device and provisioning flows.
//
// Markup contract inside the panel: [data-wizard-rail] (an <ol>),
// [data-wizard-back], [data-wizard-next], and one [data-step="<id>"] per step.
// A step: { id, label (i18n key), validate?, onEnter?, skip?, finishLabel? }.
function createWizard(panelId, { steps, onFinish }) {
    const panel = document.getElementById(panelId);
    const rail = panel.querySelector('[data-wizard-rail]');
    const btnBack = panel.querySelector('[data-wizard-back]');
    const btnNext = panel.querySelector('[data-wizard-next]');
    let index = 0;
    let editable = false;

    const section = (step) => panel.querySelector(`[data-step="${step.id}"]`);
    const active = () => steps.filter((s) => !(s.skip && s.skip()));

    function refresh() {
        const cur = steps[index];
        btnNext.disabled = !!cur.validate && !cur.validate();
    }

    function render() {
        const cur = steps[index];
        const list = active();
        const pos = list.indexOf(cur);
        steps.forEach((s) => { section(s).hidden = s !== cur; });
        rail.replaceChildren(...list.map((s, i) => {
            const li = document.createElement('li');
            li.className = 'wizard-step' + (s === cur ? ' is-current' : i < pos ? ' is-done' : '');
            if (s === cur) li.setAttribute('aria-current', 'step');
            const text = `${i + 1}. ${tr(s.label)}`;
            if (editable && s !== cur) {
                const b = document.createElement('button');
                b.type = 'button';
                b.textContent = text;
                b.addEventListener('click', () => goTo(s.id));
                li.appendChild(b);
            } else {
                li.textContent = text;
            }
            return li;
        }));
        btnBack.hidden = pos <= 0;
        btnNext.textContent = tr(pos === list.length - 1 ? (cur.finishLabel || 'wizNext') : 'wizNext');
        refresh();
    }

    function goTo(id) {
        const i = steps.findIndex((s) => s.id === id);
        if (i === -1) return;
        index = i;
        if (steps[i].onEnter) steps[i].onEnter();
        render();
    }

    function move(delta) {
        const list = active();
        const target = list[list.indexOf(steps[index]) + delta];
        if (target) goTo(target.id);
    }

    async function next() {
        const cur = steps[index];
        if (cur.validate && !cur.validate()) return;
        const list = active();
        if (list[list.length - 1] === cur) {
            await onFinish(cur.id);
            return;
        }
        move(1);
    }

    btnNext.addEventListener('click', next);
    btnBack.addEventListener('click', () => move(-1));
    // Any edit inside the panel may change what the current step accepts.
    panel.addEventListener('input', refresh);
    panel.addEventListener('change', refresh);

    return {
        open({ at, editable: canJump = false, onClose } = {}) {
            editable = canJump;
            openModal(panelId, onClose);
            goTo(at || active()[0].id);
        },
        close() { closeModal(panelId); },
        goTo,
        refresh,
        current: () => steps[index].id,
    };
}
window.createWizard = createWizard;
```

In `templates/dashboard.html`, after `<script src="/static/js/ui-modal.js"></script>` add:

```html
  <script src="/static/js/ui-wizard.js"></script>
```

In `types/globals.d.ts`, in the `// --- Cross-module exposures (window.X = ...) ---` section, add a group (keep the per-file grouping):

```ts
// ui-wizard.js
declare var createWizard: any;
```

- [ ] **Step 4: Run tests and the frontend gate**

Run: `uv run pytest tests/test_ui_wizard.py tests/test_ui_modal.py -q` then `uv run python scripts/check_frontend.py`
Expected: PASS; frontend check clean.

- [ ] **Step 5: Commit**

```bash
git add static/js/ui-wizard.js tests/js/test_ui_wizard.mjs tests/test_ui_wizard.py templates/dashboard.html types/globals.d.ts
git commit -m "feat(ui): reusable step panel (ui-wizard.js) on top of the modal manager"
```

---

### Task 5: Panel styles (`static/css/dashboard.css`)

**Files:**
- Modify: `static/css/dashboard.css` (append after the `.callout ul` rule, ~line 3294)

**Interfaces:**
- Produces classes used by Task 6 markup: `.sheet-overlay`, `.modal.sheet`, `.sheet-body`, `.wizard-rail`, `.wizard-step` (+ `.is-current`, `.is-done`), `.choice-group`, `.choice-card`, `.choice-title`, `.choice-desc`, `.pro`, `.con`, `.form-hint`, `.subnet-chips`, `.chip.is-bad`, `.chip.is-warn`, `.test-result` (+ `.is-ok`, `.is-bad`), `.fingerprint-confirm`, `dl.summary`, `pre.enroll-block`, `.heartbeat`.

- [ ] **Step 1: Verify the tokens exist**

Run: `grep -cE "^\s+--(seam|primary-glow|font-code|lamp-up-ink|lamp-fault-ink|lamp-warn-wash):" static/css/dashboard.css`
Expected: ≥ 6. If a token is missing, use the nearest existing one from the Global Constraints list — do not add new tokens.

- [ ] **Step 2: Append the styles**

```css
/* Side panel (ui-wizard.js): a modal anchored to the right edge, with a step
   rail on top. Site wizard first; device and provisioning flows reuse it. */
.modal-overlay.sheet-overlay { justify-content: flex-end; align-items: stretch; }
.modal.sheet {
  width: 560px; max-width: 100vw; height: 100vh;
  display: flex; flex-direction: column;
  animation: sheetIn 200ms cubic-bezier(0.22, 1, 0.36, 1);
}
.sheet .sheet-body { flex: 1; overflow-y: auto; }
.sheet .modal-actions { margin-top: auto; }
@keyframes sheetIn { from { transform: translateX(24px); opacity: 0; } to { transform: none; opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .modal.sheet { animation: none; } }
@media (max-width: 720px) { .modal.sheet { width: 100vw; } }

.wizard-rail { display: flex; gap: 4px; list-style: none; margin: 0 0 16px; padding: 0; }
.wizard-step {
  flex: 1; padding: 6px 0 0; border-top: 2px solid var(--border);
  font-size: var(--font-size-sm); color: var(--text-soft);
}
.wizard-step.is-done { border-top-color: var(--lamp-up); color: var(--text-muted); }
.wizard-step.is-current { border-top-color: var(--primary); color: var(--text); font-weight: 600; }
.wizard-step button {
  background: none; border: 0; padding: 0; color: inherit; font: inherit;
  cursor: pointer; text-align: left;
}
.wizard-step button:hover { color: var(--text); text-decoration: underline; }

.choice-group { border: 0; margin: 0; padding: 0; display: grid; gap: 10px; }
.choice-group legend { font-weight: 600; margin-bottom: 8px; padding: 0; }
.choice-card {
  display: grid; grid-template-columns: auto 1fr; gap: 2px 10px;
  padding: 12px 14px; border: var(--seam) solid var(--border);
  background: var(--surface-2); cursor: pointer;
}
.choice-card:has(input:checked) { border-color: var(--primary); background: var(--surface); }
.choice-card:has(input:disabled) { cursor: not-allowed; opacity: 0.6; }
.choice-card:focus-within { outline: 2px solid var(--primary-glow); outline-offset: 1px; }
.choice-card input { margin-top: 3px; }
.choice-title { font-weight: 600; }
.choice-desc, .choice-card ul { grid-column: 2; }
.choice-desc { color: var(--text-muted); font-size: var(--font-size-md); }
.choice-card ul { margin: 6px 0 0; padding: 0; list-style: none; font-size: var(--font-size-sm); line-height: 1.6; }
.choice-card .pro::before { content: "\2713  "; color: var(--lamp-up-ink); }
.choice-card .con::before { content: "\2717  "; color: var(--lamp-fault-ink); }

.form-hint { color: var(--text-muted); font-size: var(--font-size-sm); margin: 4px 0 0; }
.subnet-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
.chip.is-bad { border-color: var(--lamp-fault); color: var(--lamp-fault-ink); }
.chip.is-warn { border-color: var(--lamp-warn); color: var(--lamp-warn-ink); background: var(--lamp-warn-wash); }

.test-result {
  margin-top: 12px; padding: 10px 14px;
  border: var(--seam) solid var(--border); font-size: var(--font-size-md);
}
.test-result:empty { display: none; }
.test-result.is-ok { border-color: var(--lamp-up); background: var(--lamp-up-wash); }
.test-result.is-bad { border-color: var(--lamp-fault); background: var(--lamp-fault-wash); }
.test-result pre {
  font-family: var(--font-code); font-size: var(--font-size-sm);
  white-space: pre-wrap; word-break: break-all; margin: 6px 0 0;
}
.fingerprint-confirm { display: flex; gap: 8px; align-items: center; margin-top: 10px; }

.sheet dl.summary { display: grid; grid-template-columns: max-content 1fr; gap: 6px 14px; margin: 0; }
.sheet dl.summary dt { color: var(--text-muted); }
.sheet dl.summary dd { margin: 0; word-break: break-word; }

.sheet pre.enroll-block {
  background: var(--surface-3); border: var(--seam) solid var(--border);
  padding: 10px; font-family: var(--font-code); font-size: var(--font-size-xs);
  overflow-x: auto; margin: 0 0 12px;
}
.heartbeat { display: flex; align-items: center; gap: 8px; margin-top: 12px; font-size: var(--font-size-md); }
```

- [ ] **Step 3: Commit**

```bash
git add static/css/dashboard.css
git commit -m "feat(ui): side panel, step rail, choice cards and test-result styles"
```

---

### Task 6: `siteWizard` markup and i18n (`templates/dashboard.html`, `static/js/i18n.js`)

**Files:**
- Modify: `templates/dashboard.html` — replace `createSiteModal` (~line 5066), `editSiteModal` (~5142) and `siteEnrollModal` (search `id="siteEnrollModal"`) with one `siteWizard`; change the "Nuova sede" header button in `tab-sites` (~line 2749).
- Modify: `static/js/i18n.js` — new keys in `it` and `en`; delete `jumpLimitsTitle`.

**Interfaces:**
- Produces element ids used by Task 7: `siteWizard`, `siteWizardTitle`, `siteWizardForm`, radios `name="swMode"` (values `central`/`agent`/`jump`), `swName`, `swSubnets`, `swSubnetChips`, `swJumpFields`, `swJumpHost`, `swJumpPort`, `swJumpIdentity`, `swDeviceIdentity`, `swTestBtn`, `swTestResult`, `swFpConfirmWrap`, `swFpConfirm`, `swSkipVerify`, `swSummary`, `swModeWarning`, `swSaveError`, `siteEnrollConfig`, `siteEnrollCommands`, `swHeartbeat`, `swHeartbeatLed`, `swHeartbeatText`, `btnNewSite`; actions `data-action="sw-new-identity"`, `data-action="copy-site-enroll"`.

- [ ] **Step 1: Check the reused i18n keys exist**

Run: `grep -cE "^\s+(jumpLimitsWorks|jumpLimitsPing|jumpLimitsScan|jumpLimitsUdp|jumpLimitsRest|jumpLimitsIdentity|descSiteEnroll|btnCopySiteEnroll|lblSiteEnrollCommands|btnSaveSite|msgBastionOk|msgBastionAuthFailed|msgBastionUnreachable|optNoDeviceIdentity|titleNewSite|optSiteJump|phNewSiteName|phNewSiteSubnets|phNewSiteJumpHost|lblJumpHost|lblJumpPort|lblJumpIdentity|lblDeviceIdentity):" static/js/i18n.js`
Expected: 46 (23 keys × 2 languages). If lower, find the missing key with the same grep per key and add it to both dictionaries in Step 4.

- [ ] **Step 2: Replace the header button in `tab-sites`**

Replace

```html
          <button type="button" class="btn btn-primary" data-open-modal="createSiteModal"><i class="fa-solid fa-plus"></i> <span data-i18n="titleNewSite">Nuova sede</span></button>
```

with

```html
          <button type="button" class="btn btn-primary" id="btnNewSite"><i class="fa-solid fa-plus"></i> <span data-i18n="titleNewSite">Nuova sede</span></button>
```

- [ ] **Step 3: Delete the three old modals and add `siteWizard`**

Delete the whole `<div class="modal-overlay" id="createSiteModal">…</div>` block, the whole `<div class="modal-overlay" id="editSiteModal">…</div>` block together with its preceding `<!-- Modifica sede: … -->` comment, and the whole `<div class="modal-overlay" id="siteEnrollModal">…</div>` block. Where `createSiteModal` was, insert:

```html
  <!-- Site wizard: create, edit and agent enrollment in one side panel
       (ui-wizard.js). Spec: docs/superpowers/specs/2026-09-23-site-wizard-design.md -->
  <div class="modal-overlay sheet-overlay" id="siteWizard">
    <div class="modal sheet" aria-labelledby="siteWizardTitle">
      <div class="modal-header">
        <h3 id="siteWizardTitle" data-i18n="titleNewSite">Nuova sede</h3>
        <button type="button" class="modal-close" data-close-modal="siteWizard" aria-label="Chiudi" data-i18n-aria-label="btnClose"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <ol class="wizard-rail" data-wizard-rail aria-label="Passi" data-i18n-aria-label="swRailLabel"></ol>
      <form id="siteWizardForm" class="sheet-body" novalidate>
        <section data-step="mode">
          <fieldset class="choice-group" role="radiogroup" aria-labelledby="swModeLegend">
            <legend id="swModeLegend" data-i18n="swModeLegend">Come raggiunge i dispositivi il centrale?</legend>
            <label class="choice-card">
              <input type="radio" name="swMode" value="central">
              <span class="choice-title" data-i18n="swModeCentral">Central poll</span>
              <span class="choice-desc" data-i18n="swModeCentralDesc">Il centrale raggiunge i dispositivi direttamente, via routing VPN.</span>
              <ul>
                <li class="pro" data-i18n="swModeCentralPro1">Ping, SNMP, syslog e flow diretti</li>
                <li class="pro" data-i18n="swModeCentralPro2">Scansione e discovery dal centrale</li>
                <li class="con" data-i18n="swModeCentralCon1">Serve un percorso IP verso le subnet della sede</li>
              </ul>
            </label>
            <label class="choice-card">
              <input type="radio" name="swMode" value="agent">
              <span class="choice-title" data-i18n="swModeAgent">Site agent</span>
              <span class="choice-desc" data-i18n="swModeAgentDesc">Un agente in sede si collega in uscita al centrale e gli spinge i dati.</span>
              <ul>
                <li class="pro" data-i18n="swModeAgentPro1">Nessun accesso in ingresso alla sede</li>
                <li class="pro" data-i18n="swModeAgentPro2">Le credenziali dei dispositivi restano in sede</li>
                <li class="con" data-i18n="swModeAgentCon1">Va installato un agente Linux in sede</li>
              </ul>
            </label>
            <label class="choice-card">
              <input type="radio" name="swMode" value="jump">
              <span class="choice-title" data-i18n="optSiteJump">Jump (bastion SSH)</span>
              <span class="choice-desc" data-i18n="swModeJumpDesc">Il centrale entra in sede via SSH attraverso un bastione.</span>
              <ul>
                <li class="pro" data-i18n="jumpLimitsWorks">Funzionano: inventario, backup config, MAC/ARP, comandi CLI, audit.</li>
                <li class="con" data-i18n="jumpLimitsPing">Nessun ping ICMP: lo stato online/offline resta "non misurabile".</li>
                <li class="con" data-i18n="jumpLimitsScan">Nessuna scansione di subnet ne' discovery dal centrale.</li>
                <li class="con" data-i18n="jumpLimitsUdp">Nessun syslog, flow o SNMP in ingresso.</li>
                <li class="con" data-i18n="jumpLimitsRest">Nessuna API REST vendor (FortiGate): solo CLI.</li>
              </ul>
            </label>
          </fieldset>
        </section>

        <section data-step="details" hidden>
          <div class="form-group">
            <label for="swName" data-i18n="lblSiteName">Nome</label>
            <input id="swName" type="text" placeholder="es. Milano" data-i18n-placeholder="phNewSiteName">
          </div>
          <div class="form-group">
            <label for="swSubnets" data-i18n="lblSiteSubnets">Subnet (separate da virgola)</label>
            <input id="swSubnets" type="text" placeholder="es. 10.0.0.0/24, 10.0.1.0/24" data-i18n-placeholder="phNewSiteSubnets" aria-describedby="swSubnetsHint">
            <p id="swSubnetsHint" class="form-hint" data-i18n="swSubnetsHint">Formato CIDR, separate da virgola.</p>
            <div id="swSubnetChips" class="subnet-chips"></div>
          </div>
          <div id="swJumpFields" hidden>
            <div class="modal-grid">
              <div class="form-group">
                <label for="swJumpHost" data-i18n="lblJumpHost">Host bastione (IP/hostname)</label>
                <input id="swJumpHost" type="text" placeholder="es. 198.51.100.10" data-i18n-placeholder="phNewSiteJumpHost">
              </div>
              <div class="form-group">
                <label for="swJumpPort" data-i18n="lblJumpPort">Porta SSH bastione</label>
                <input id="swJumpPort" type="number" value="22" min="1" max="65535">
              </div>
            </div>
            <div class="form-group">
              <label for="swJumpIdentity" data-i18n="lblJumpIdentity">Identità (credenziali) bastione</label>
              <select id="swJumpIdentity"></select>
              <button type="button" class="btn btn-secondary btn-small" data-action="sw-new-identity" data-i18n="swNewIdentity">+ Nuova identità</button>
            </div>
            <div class="form-group">
              <label for="swDeviceIdentity" data-i18n="lblDeviceIdentity">Identità di default dei dispositivi</label>
              <select id="swDeviceIdentity" aria-describedby="swDeviceIdentityHint"></select>
              <p id="swDeviceIdentityHint" class="form-hint" data-i18n="jumpLimitsIdentity">L'identità del bastione e quella dei dispositivi sono distinte: la seconda vale per i dispositivi il cui profilo è "default".</p>
            </div>
          </div>
        </section>

        <section data-step="connect" hidden>
          <p data-i18n="swTestIntro">Prova il login sul bastione prima di salvare.</p>
          <button type="button" class="btn btn-secondary" id="swTestBtn"><i class="fa-solid fa-plug-circle-check"></i> <span data-i18n="swBtnTest">Test connessione</span></button>
          <div id="swTestResult" class="test-result" role="status" aria-live="polite"></div>
          <label id="swFpConfirmWrap" class="fingerprint-confirm" hidden>
            <input type="checkbox" id="swFpConfirm">
            <span data-i18n="swFpConfirm">È l'impronta del mio bastione</span>
          </label>
          <label class="fingerprint-confirm">
            <input type="checkbox" id="swSkipVerify">
            <span data-i18n="swSkipVerify">Salva senza verificare</span>
          </label>
          <p class="form-hint" data-i18n="swSkipWarn">La sede sarà segnata come non verificata e la chiave verrà accettata al primo collegamento.</p>
        </section>

        <section data-step="summary" hidden>
          <dl id="swSummary" class="summary"></dl>
          <p id="swModeWarning" class="callout" hidden></p>
          <p id="swSaveError" class="form-hint" role="alert"></p>
        </section>

        <section data-step="enroll" hidden>
          <p data-i18n="descSiteEnroll">Il token è mostrato una sola volta: copialo adesso. Chiudendo questa finestra non è più recuperabile (si può solo rigenerare).</p>
          <h4><code>agent.json</code></h4>
          <pre id="siteEnrollConfig" class="enroll-block"></pre>
          <h4 data-i18n="lblSiteEnrollCommands">Comandi di installazione</h4>
          <pre id="siteEnrollCommands" class="enroll-block"></pre>
          <button type="button" class="btn btn-secondary" data-action="copy-site-enroll"><i class="fa-solid fa-copy"></i> <span data-i18n="btnCopySiteEnroll">Copia tutto</span></button>
          <div id="swHeartbeat" class="heartbeat" role="status" aria-live="polite">
            <span id="swHeartbeatLed" class="led led-warning"></span>
            <span id="swHeartbeatText" data-i18n="swEnrollWaiting">In attesa del primo contatto dell'agente…</span>
          </div>
        </section>
      </form>
      <div class="modal-actions">
        <button type="button" class="btn btn-secondary" data-close-modal="siteWizard" data-i18n="uiCancel">Annulla</button>
        <button type="button" class="btn btn-secondary" data-wizard-back data-i18n="wizBack">Indietro</button>
        <button type="button" class="btn btn-primary" data-wizard-next data-i18n="wizNext">Avanti</button>
      </div>
    </div>
  </div>
```

If Step 1 showed that a reused key's Italian text differs from the fallback text above, copy the dictionary's text into the fallback so both match.

- [ ] **Step 4: Add the i18n keys**

In `static/js/i18n.js`, in the **Italian** dictionary, replace the line starting `        jumpLimitsTitle:` with:

```js
        swRailLabel: "Passi",
        wizNext: "Avanti",
        wizBack: "Indietro",
        swStepMode: "Modalità",
        swStepDetails: "Dettagli",
        swStepConnect: "Connessione",
        swStepSummary: "Riepilogo",
        swStepEnroll: "Arruolamento",
        swTitleEdit: "Modifica sede",
        swModeLegend: "Come raggiunge i dispositivi il centrale?",
        swModeCentral: "Central poll",
        swModeCentralDesc: "Il centrale raggiunge i dispositivi direttamente, via routing VPN.",
        swModeCentralPro1: "Ping, SNMP, syslog e flow diretti",
        swModeCentralPro2: "Scansione e discovery dal centrale",
        swModeCentralCon1: "Serve un percorso IP verso le subnet della sede",
        swModeAgent: "Site agent",
        swModeAgentDesc: "Un agente in sede si collega in uscita al centrale e gli spinge i dati.",
        swModeAgentPro1: "Nessun accesso in ingresso alla sede",
        swModeAgentPro2: "Le credenziali dei dispositivi restano in sede",
        swModeAgentCon1: "Va installato un agente Linux in sede",
        swModeJumpDesc: "Il centrale entra in sede via SSH attraverso un bastione.",
        swSubnetsHint: "Formato CIDR, separate da virgola.",
        swSubnetInvalid: "Non è una subnet CIDR valida",
        swNewIdentity: "+ Nuova identità",
        swTestIntro: "Prova il login sul bastione prima di salvare.",
        swBtnTest: "Test connessione",
        swTesting: "Test in corso…",
        swTestOk: "Bastione raggiungibile, login accettato.",
        swTestHostKey: "La chiave host è diversa da quella registrata: la tratta non è fidata.",
        swFpLabel: "Impronta della chiave host",
        swFpConfirm: "È l'impronta del mio bastione",
        swFpKnown: "Chiave già registrata per questo host.",
        swSkipVerify: "Salva senza verificare",
        swSkipWarn: "La sede sarà segnata come non verificata e la chiave verrà accettata al primo collegamento.",
        swSumBastion: "Bastione",
        swVerified: "Verificato",
        swNotVerified: "Non verificato",
        swEnrollWaiting: "In attesa del primo contatto dell'agente…",
        swEnrollOnline: "Agente collegato.",
        swSaved: "Sede salvata.",
        chipNotVerified: "Non verificata",
```

In the **English** dictionary, replace the line starting `        jumpLimitsTitle:` with:

```js
        swRailLabel: "Steps",
        wizNext: "Next",
        wizBack: "Back",
        swStepMode: "Mode",
        swStepDetails: "Details",
        swStepConnect: "Connection",
        swStepSummary: "Summary",
        swStepEnroll: "Enrollment",
        swTitleEdit: "Edit site",
        swModeLegend: "How does central reach the devices?",
        swModeCentral: "Central poll",
        swModeCentralDesc: "Central reaches the devices directly, over VPN routing.",
        swModeCentralPro1: "Direct ping, SNMP, syslog and flows",
        swModeCentralPro2: "Scanning and discovery from central",
        swModeCentralCon1: "Needs an IP path to the site's subnets",
        swModeAgent: "Site agent",
        swModeAgentDesc: "An agent at the site connects out to central and pushes the data.",
        swModeAgentPro1: "No inbound access to the site",
        swModeAgentPro2: "Device credentials stay at the site",
        swModeAgentCon1: "A Linux agent must be installed at the site",
        swModeJumpDesc: "Central enters the site over SSH through a bastion.",
        swSubnetsHint: "CIDR format, comma separated.",
        swSubnetInvalid: "Not a valid CIDR subnet",
        swNewIdentity: "+ New identity",
        swTestIntro: "Try the bastion login before saving.",
        swBtnTest: "Test connection",
        swTesting: "Testing…",
        swTestOk: "Bastion reachable, login accepted.",
        swTestHostKey: "The host key differs from the recorded one: the hop is not trusted.",
        swFpLabel: "Host key fingerprint",
        swFpConfirm: "This is my bastion's fingerprint",
        swFpKnown: "Key already recorded for this host.",
        swSkipVerify: "Save without verifying",
        swSkipWarn: "The site will be marked unverified and the key accepted on first connection.",
        swSumBastion: "Bastion",
        swVerified: "Verified",
        swNotVerified: "Not verified",
        swEnrollWaiting: "Waiting for the agent's first contact…",
        swEnrollOnline: "Agent connected.",
        swSaved: "Site saved.",
        chipNotVerified: "Not verified",
```

Then confirm `jumpLimitsTitle` has no remaining reference: `grep -rn "jumpLimitsTitle" static templates tests` → no output.

- [ ] **Step 5: Run the i18n and a11y gates**

Run: `uv run python scripts/check_i18n_coverage.py --strict` and `uv run python scripts/check_a11y.py --strict`
Expected: both clean. (`settings.js` still references old ids until Task 7, so do not run the full suite yet.)

- [ ] **Step 6: No commit yet** — Tasks 6 and 7 land together: the template and the JS that binds it must ship in one commit, or the Sites tab is dead in between.

---

### Task 7: Wire the wizard in `static/js/settings.js` and update the pinned UI tests

**Files:**
- Modify: `static/js/settings.js` — remove `onNewSiteModeChange`, `populateJumpIdentitySelect`, the old `window.refreshSiteIdentitySelects`, `createSite`, `testBastion`, `showSiteEnrollment`, `editingSite`, `onEditSiteModeChange`, `openEditSiteModal`, `saveEditSite` (roughly lines 108-398); keep `getIdentities`, `identityOptions`, `regenSiteToken`, `enrollmentText`, `copySiteEnrollment`, `modeChangeWarning`; update `renderSitesTable` status cell; replace the listeners at ~1633-1645 and ~1709-1710.
- Modify: `tests/test_site_editing.py` (`TestSiteEditingUi`, `TestSiteEnrollment`)
- Modify: `tests/test_ui_revamp.py:1423-1482` (sites-tab preserve-ids and component checks)
- Test: `tests/test_site_wizard_ui.py` (new)

**Interfaces:**
- Consumes: `createWizard` (Task 4); element ids (Task 6); API from Task 3; globals `apiFetch`, `tr`, `escapeHtml`, `showToast`, `isModalOpen`, `switchTab`, `loadSites`.
- Produces: `openNewSiteWizard()`, `openEditSiteWizard(siteId)`, `saveSiteWizard()`, `showSiteEnrollment(siteId, token)`, `testBastion(id)`, `window.refreshSiteIdentitySelects` (same name, same callers in provisioning.js).

- [ ] **Step 1: Write the failing UI contract test**

Create `tests/test_site_wizard_ui.py`:

```python
# -*- coding: utf-8 -*-
# Copyright 2026 Claudio Vidhi
# SPDX-License-Identifier: AGPL-3.0-only
"""Site wizard wiring: every id the JS binds exists in the template, the old
modals are gone, and the save sends the confirmed fingerprint only when the
operator ticked it."""
import os
import re
import unittest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_REPO_ROOT, *parts), encoding="utf-8") as f:
        return f.read()


class SiteWizardUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = _read("templates", "dashboard.html")
        cls.js = _read("static", "js", "settings.js")

    def test_old_modals_are_gone(self):
        for old in ("createSiteModal", "editSiteModal", "siteEnrollModal", "newSiteMode", "jumpLimitsTitle"):
            self.assertNotIn(old, self.html, old)
            self.assertNotIn(old, self.js, old)

    def test_every_bound_id_exists(self):
        ids = set(re.findall(r"swEl\('([A-Za-z]+)'\)", self.js))
        ids |= {"siteWizard", "siteWizardForm", "siteEnrollConfig", "siteEnrollCommands", "btnNewSite"}
        missing = sorted(i for i in ids if f'id="{i}"' not in self.html)
        self.assertEqual(missing, [])

    def test_wizard_is_created_on_the_panel(self):
        self.assertIn("createWizard('siteWizard'", self.js)
        self.assertIn('id="siteWizard"', self.html)
        self.assertIn("getElementById('siteWizard')?.addEventListener", self.js)
        self.assertIn("getElementById('btnNewSite')?.addEventListener", self.js)

    def test_fingerprint_is_sent_only_when_confirmed(self):
        self.assertIn("body.confirmed_fingerprint = sw.test.fingerprint", self.js)
        self.assertIn("swEl('swFpConfirm').checked", self.js)

    def test_test_result_is_announced(self):
        start = self.html.index('id="swTestResult"')
        tag = self.html[self.html.rindex("<", 0, start):self.html.index(">", start)]
        self.assertIn('aria-live="polite"', tag)

    def test_unverified_badge(self):
        self.assertIn("chipNotVerified", self.js)
        self.assertIn("bastion_verified_ts", self.js)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/test_site_wizard_ui.py -q`
Expected: FAIL — `createWizard('siteWizard'` not in settings.js; old ids still referenced in settings.js.

- [ ] **Step 3: Replace the site create/edit/enroll code in `settings.js`**

Delete these entirely: `onNewSiteModeChange`, `populateJumpIdentitySelect`, the `window.refreshSiteIdentitySelects = …` assignment, `createSite`, `testBastion`, `showSiteEnrollment`, the `let editingSite = null;` line with its comment block, `onEditSiteModeChange`, `openEditSiteModal`, `saveEditSite`. Keep `let identitiesCache`, `getIdentities`, `identityOptions`, `regenSiteToken`, `enrollmentText`, `copySiteEnrollment`, `modeChangeWarning`.

Insert, right after `identityOptions(...)`:

```js
    // --- Site wizard (docs/superpowers/specs/2026-09-23-site-wizard-design.md) ---
    // One side panel for create, edit and agent enrollment:
    // Mode → Details → Connection (jump only) → Summary → Enrollment (new token).
    const CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
    function isCidr(s) {
        const m = CIDR_RE.exec(s);
        return !!m && m.slice(1, 5).every((o) => +o <= 255) && +m[5] <= 32;
    }
    const sw = {
        editing: null,     // site being edited; null when creating
        test: null,        // last draft-test answer for the current bastion fields
        token: null,       // agent token to enroll, shown once
        siteId: null,      // site the enrollment step is about
        heartbeat: null,   // interval polling last_seen during enrollment
        keepDraft: false,  // closed only to go create an identity: keep the fields
    };
    const swEl = (id) => document.getElementById(id);
    const swMode = () => document.querySelector('input[name="swMode"]:checked')?.value || '';
    const swSubnets = () => swEl('swSubnets').value.split(',').map((x) => x.trim()).filter(Boolean);
    function swJumpFields() {
        return {
            jump_host: swEl('swJumpHost').value.trim(),
            jump_port: parseInt(swEl('swJumpPort').value, 10) || 22,
            jump_identity: swEl('swJumpIdentity').value,
        };
    }
    // Editing a jump site whose bastion is untouched needs no new test.
    function swJumpChanged() {
        const e = sw.editing;
        if (!e || e.mode !== 'jump') return true;
        const j = swJumpFields();
        return j.jump_host !== (e.jump_host || '') || j.jump_port !== (e.jump_port || 22)
            || j.jump_identity !== (e.jump_identity || '');
    }
    function swTestPassed() {
        return !!sw.test && sw.test.status === 'success' && swEl('swFpConfirm').checked;
    }

    const siteWizard = createWizard('siteWizard', {
        steps: [
            { id: 'mode', label: 'swStepMode', validate: () => !!swMode() },
            { id: 'details', label: 'swStepDetails', onEnter: onSwDetailsEnter,
              validate: () => {
                  if (!swEl('swName').value.trim() || !swSubnets().every(isCidr)) return false;
                  if (swMode() !== 'jump') return true;
                  const j = swJumpFields();
                  return !!j.jump_host && !!j.jump_identity && j.jump_port >= 1 && j.jump_port <= 65535;
              } },
            { id: 'connect', label: 'swStepConnect',
              skip: () => swMode() !== 'jump' || !swJumpChanged(),
              validate: () => swTestPassed() || swEl('swSkipVerify').checked },
            { id: 'summary', label: 'swStepSummary', onEnter: renderSwSummary, finishLabel: 'btnSaveSite' },
            { id: 'enroll', label: 'swStepEnroll', skip: () => !sw.token,
              onEnter: startSwHeartbeat, finishLabel: 'btnClose' },
        ],
        onFinish: async (stepId) => {
            if (stepId === 'enroll') { siteWizard.close(); return; }
            await saveSiteWizard();
        },
    });

    function resetSiteWizard() {
        stopSwHeartbeat();
        Object.assign(sw, { editing: null, test: null, token: null, siteId: null, keepDraft: false });
        swEl('siteWizardForm').reset();
        swInvalidateTest();
        swEl('swSubnetChips').replaceChildren();
        swEl('swSaveError').textContent = '';
        document.querySelectorAll('input[name="swMode"]').forEach((r) => { r.disabled = false; });
        swEl('siteWizardTitle').textContent = tr('titleNewSite');
    }

    function onSiteWizardClose() {
        stopSwHeartbeat();
        if (!sw.keepDraft) resetSiteWizard();
    }

    function openNewSiteWizard() {
        const resume = sw.keepDraft;
        if (!resume) resetSiteWizard();
        sw.keepDraft = false;
        siteWizard.open({ at: resume ? 'details' : 'mode', onClose: onSiteWizardClose });
    }

    async function openEditSiteWizard(siteId) {
        const res = await apiFetch('/api/sites');
        if (!res || !res.ok) return;
        const site = ((await res.json()).sites || []).find((s) => s.id === siteId);
        if (!site) return;
        resetSiteWizard();
        sw.editing = site;
        swEl('siteWizardTitle').textContent = tr('swTitleEdit');
        document.querySelectorAll('input[name="swMode"]').forEach((r) => {
            r.checked = r.value === (site.mode || 'central');
            // The default site is the central's own: changing its mode would
            // take away the central's direct path to its own devices.
            r.disabled = site.id === 'central';
        });
        swEl('swName').value = site.name || '';
        swEl('swSubnets').value = (site.subnets || []).join(', ');
        swEl('swJumpHost').value = site.jump_host || '';
        swEl('swJumpPort').value = site.jump_port || 22;
        await populateSwIdentitySelects(site.jump_identity || '', site.device_identity || '');
        siteWizard.open({ at: 'details', editable: true, onClose: onSiteWizardClose });
    }

    async function populateSwIdentitySelects(jumpValue, deviceValue) {
        const identities = await getIdentities();
        swEl('swJumpIdentity').innerHTML = identityOptions(identities, jumpValue);
        // The device default is optional: without it the devices behind the
        // bastion fall back to the global credentials (core/device_credentials.py).
        swEl('swDeviceIdentity').innerHTML = `<option value="">${escapeHtml(tr('optNoDeviceIdentity'))}</option>`
            + identityOptions(identities, deviceValue);
    }

    // Called after an identity is created, edited or deleted (provisioning.js).
    window.refreshSiteIdentitySelects = async function () {
        identitiesCache = null;
        if (!isModalOpen('siteWizard') && !sw.keepDraft) return;
        await populateSwIdentitySelects(swEl('swJumpIdentity').value, swEl('swDeviceIdentity').value);
    };

    // "+ New identity": the draft survives the trip to the identities panel,
    // and "Nuova sede" resumes it at the Details step.
    function goCreateIdentity() {
        sw.keepDraft = true;
        siteWizard.close();
        switchTab('tab-provisioning');
        document.getElementById('identitiesPanel')?.scrollIntoView();
    }

    async function onSwDetailsEnter() {
        const jump = swMode() === 'jump';
        swEl('swJumpFields').hidden = !jump;
        if (jump) await populateSwIdentitySelects(swEl('swJumpIdentity').value, swEl('swDeviceIdentity').value);
        renderSwSubnetChips();
        siteWizard.refresh();
    }

    function renderSwSubnetChips() {
        swEl('swSubnetChips').replaceChildren(...swSubnets().map((s) => {
            const chip = document.createElement('span');
            const ok = isCidr(s);
            chip.className = 'chip' + (ok ? '' : ' is-bad');
            chip.textContent = s;
            if (!ok) chip.title = tr('swSubnetInvalid');
            return chip;
        }));
    }

    // A test vouches for the exact host/port/identity it ran against.
    function swInvalidateTest() {
        sw.test = null;
        const out = swEl('swTestResult');
        out.replaceChildren();
        out.className = 'test-result';
        swEl('swFpConfirmWrap').hidden = true;
        swEl('swFpConfirm').checked = false;
    }

    async function swRunTest() {
        swInvalidateTest();
        const out = swEl('swTestResult');
        out.textContent = tr('swTesting');
        siteWizard.refresh();
        const res = await apiFetch('/api/sites/test-bastion/draft', {
            method: 'POST', body: JSON.stringify(swJumpFields()),
        });
        if (!res) { out.textContent = ''; return; }
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            out.className = 'test-result is-bad';
            out.textContent = data.detail || tr('uiError');
            return;
        }
        sw.test = data;
        renderSwTestResult(data);
        siteWizard.refresh();
    }

    function renderSwTestResult(data) {
        const out = swEl('swTestResult');
        const ok = data.status === 'success';
        out.className = 'test-result ' + (ok ? 'is-ok' : 'is-bad');
        const head = document.createElement('strong');
        head.textContent = ok ? tr('swTestOk')
            : data.status === 'auth_failed' ? tr('msgBastionAuthFailed')
            : data.status === 'host_key_mismatch' ? tr('swTestHostKey')
            : tr('msgBastionUnreachable');
        const pre = document.createElement('pre');
        pre.textContent = ok ? `${tr('swFpLabel')} (${data.key_type})\n${data.fingerprint}` : (data.message || '');
        out.replaceChildren(head, pre);
        if (!ok) return;
        swEl('swFpConfirmWrap').hidden = false;
        // Already pinned and matching: nothing new to trust.
        swEl('swFpConfirm').checked = !!data.known;
        if (data.known) {
            const note = document.createElement('p');
            note.textContent = tr('swFpKnown');
            out.appendChild(note);
        }
    }

    function renderSwSummary() {
        const mode = swMode();
        const modeLabel = { central: 'swModeCentral', agent: 'swModeAgent', jump: 'optSiteJump' }[mode];
        const rows = [
            ['lblSiteName', swEl('swName').value.trim()],
            ['lblSiteMode', tr(modeLabel)],
            ['lblSiteSubnets', swSubnets().join(', ') || '—'],
        ];
        if (mode === 'jump') {
            const j = swJumpFields();
            const verified = swJumpChanged() ? swTestPassed() : !!sw.editing.bastion_verified_ts;
            rows.push(['lblJumpHost', `${j.jump_host}:${j.jump_port}`]);
            rows.push(['swSumBastion', tr(verified ? 'swVerified' : 'swNotVerified')]);
        }
        swEl('swSummary').replaceChildren(...rows.flatMap(([key, value]) => {
            const dt = document.createElement('dt');
            dt.textContent = tr(key);
            const dd = document.createElement('dd');
            dd.textContent = value;
            return [dt, dd];
        }));
        // The consequences of a mode change are said BEFORE saving: two of
        // the three touch the token, i.e. the agent's ability to log in.
        const was = sw.editing ? sw.editing.mode : null;
        const warn = swEl('swModeWarning');
        warn.hidden = !was || was === mode;
        warn.textContent = warn.hidden ? '' : modeChangeWarning(swMode());
        swEl('swSaveError').textContent = '';
    }

    async function saveSiteWizard() {
        const mode = swMode();
        const editing = sw.editing;
        const body = { name: swEl('swName').value.trim(), subnets: swSubnets() };
        if (mode === 'jump') {
            Object.assign(body, swJumpFields(), { device_identity: swEl('swDeviceIdentity').value });
            if (swJumpChanged() && swTestPassed()) body.confirmed_fingerprint = sw.test.fingerprint;
        }
        if (editing) {
            body.id = editing.id;
            if (mode !== editing.mode) body.mode = mode;
        } else {
            body.mode = mode;
        }
        const res = await apiFetch(editing ? '/api/sites/update' : '/api/sites', {
            method: 'POST', body: JSON.stringify(body),
        });
        if (!res) return;
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            swEl('swSaveError').textContent = data.detail || tr('uiError');
            // 409: the confirmed key is not the one the server saw any more.
            if (res.status === 409) {
                swInvalidateTest();
                siteWizard.goTo('connect');
                swEl('swTestResult').textContent = data.detail || '';
            }
            return;
        }
        loadSites();
        const id = editing ? editing.id : data.site.id;
        // Switching to 'agent' issues the token in the save itself (see
        // routers/sites.py): shown once, like on creation.
        if (data.token) { showSiteEnrollment(id, data.token); return; }
        siteWizard.close();
        showToast(tr('swSaved'), 'info');
    }

    function showSiteEnrollment(siteId, token) {
        sw.token = token;
        sw.siteId = siteId;
        const { cfg, cmds } = enrollmentText(siteId, token);
        // textContent, not innerHTML: the token is a value, not markup.
        document.getElementById('siteEnrollConfig').textContent = cfg;
        document.getElementById('siteEnrollCommands').textContent = cmds;
        if (isModalOpen('siteWizard')) siteWizard.goTo('enroll');
        else siteWizard.open({ at: 'enroll', onClose: onSiteWizardClose });
    }

    function paintSwHeartbeat(online) {
        swEl('swHeartbeatLed').className = 'led ' + (online ? 'led-success' : 'led-warning');
        swEl('swHeartbeatText').textContent = tr(online ? 'swEnrollOnline' : 'swEnrollWaiting');
    }

    // Green on the first heartbeat AFTER the token was issued: an agent still
    // running with the old token cannot produce one.
    function startSwHeartbeat() {
        stopSwHeartbeat();
        paintSwHeartbeat(false);
        const since = Date.now() / 1000;
        sw.heartbeat = setInterval(async () => {
            const res = await apiFetch('/api/sites');
            if (!res || !res.ok) return;
            const site = ((await res.json()).sites || []).find((s) => s.id === sw.siteId);
            if (site && site.last_seen && site.last_seen >= since) {
                paintSwHeartbeat(true);
                stopSwHeartbeat();
                loadSites();
            }
        }, 5000);
    }

    function stopSwHeartbeat() {
        if (sw.heartbeat) clearInterval(sw.heartbeat);
        sw.heartbeat = null;
    }

    async function testBastion(id) {
        const res = await apiFetch('/api/sites/test-bastion', {
            method: 'POST', body: JSON.stringify({ id }),
        });
        if (!res) return;
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || tr('uiError'), 'error'); return; }
        if (data.status === 'success') showToast(`${tr('msgBastionOk')} ${data.fingerprint || ''}`, 'info');
        else if (data.status === 'auth_failed') showToast(`${tr('msgBastionAuthFailed')} ${data.message || ''}`, 'error');
        else if (data.status === 'host_key_mismatch') showToast(`${tr('swTestHostKey')} ${data.message || ''}`, 'error');
        else showToast(`${tr('msgBastionUnreachable')} ${data.message || ''}`, 'error');
        loadSites();
    }
```

In `renderSitesTable`, right after the `if (s.mode === 'agent') { … }` block that sets `statusCell`, add:

```js
            if (s.mode === 'jump' && !s.bastion_verified_ts) {
                statusCell = `<span class="chip is-warn">${escapeHtml(tr('chipNotVerified'))}</span>`;
            }
```

In the `sitesTableBody` click listener replace `else if (act === 'edit-site') openEditSiteModal(siteId);` with `else if (act === 'edit-site') openEditSiteWizard(siteId);`.

Replace the listener blocks bound to `editSiteModal`, `editSiteMode` and `siteEnrollModal` (including the comment `// Il modale vive fuori da sitesTableBody…`) with:

```js
    // The panel lives outside sitesTableBody: it needs its own listeners.
    document.getElementById('siteWizard')?.addEventListener('click', (e) => {
        if (e.target.closest('#swTestBtn')) swRunTest();
        else if (e.target.closest('[data-action="copy-site-enroll"]')) copySiteEnrollment();
        else if (e.target.closest('[data-action="sw-new-identity"]')) goCreateIdentity();
    });
    document.getElementById('siteWizard')?.addEventListener('input', (e) => {
        if (e.target.id === 'swSubnets') renderSwSubnetChips();
        if (['swJumpHost', 'swJumpPort'].includes(e.target.id)) swInvalidateTest();
    });
    document.getElementById('siteWizard')?.addEventListener('change', (e) => {
        if (e.target.name === 'swMode' || e.target.id === 'swJumpIdentity') swInvalidateTest();
    });
    // Enter in a field must not submit (and reload) the page.
    document.getElementById('siteWizardForm')?.addEventListener('submit', (e) => e.preventDefault());
```

Replace

```js
    document.getElementById('btnCreateSite')?.addEventListener('click', createSite);
    document.getElementById('newSiteMode')?.addEventListener('change', onNewSiteModeChange);
```

with

```js
    document.getElementById('btnNewSite')?.addEventListener('click', openNewSiteWizard);
```

Check no caller of the deleted names remains: `grep -nE "openEditSiteModal|saveEditSite|onEditSiteModeChange|onNewSiteModeChange|populateJumpIdentitySelect|createSite\(\)|editingSite" static/js/*.js` → no output.

- [ ] **Step 4: Update the tests pinned to the old modals**

In `tests/test_site_editing.py`, class `TestSiteEditingUi`, replace its test methods (keep `setUpClass`) with:

```python
    def test_the_panel_and_its_controls_exist(self):
        for el in ('id="siteWizard"', 'id="swName"', 'id="swSubnets"',
                   'name="swMode"', 'id="swJumpHost"', 'id="swJumpPort"'):
            self.assertIn(el, self.html, el)

    def test_the_row_offers_the_edit_action(self):
        self.assertIn('data-action="edit-site"', self.js)
        self.assertIn("act === 'edit-site'", self.js)

    def test_the_panel_listener_binds_an_id_that_exists(self):
        # getElementById('missing')?.addEventListener raises nothing: it
        # leaves the button silently dead.
        self.assertIn("getElementById('siteWizard')?.addEventListener", self.js)
        self.assertIn('id="siteWizard"', self.html)

    def test_the_panel_goes_through_the_modal_manager(self):
        self.assertIn("createWizard('siteWizard'", self.js)

    def test_a_mode_change_is_explained_before_saving(self):
        self.assertIn("modeChangeWarning(swMode())", self.js)

    def test_the_token_shown_after_the_save_comes_from_the_save(self):
        # Not from a second regenerate-token call: if that one failed the site
        # would be left without a token after a successful save.
        self.assertIn("if (data.token) { showSiteEnrollment(id, data.token)", self.js)
```

In class `TestSiteEnrollment`, replace `test_the_modal_exists`, `test_no_token_is_shown_as_a_bare_string_any_more` and `test_the_listener_binds_an_id_that_exists` with:

```python
    def test_the_enrollment_step_exists(self):
        for el in ('data-step="enroll"', 'id="siteEnrollConfig"',
                   'id="siteEnrollCommands"'):
            self.assertIn(el, self.html, el)

    def test_no_token_is_shown_as_a_bare_string_any_more(self):
        self.assertNotIn("prompt(tr('setSiteTokenShownOnly')", self.js)
        self.assertNotIn("prompt(tr('setNewTokenShownOnly')", self.js)
        # Token-issuing paths: the wizard save (creation AND switch to agent,
        # both answer with data.token) and the regeneration.
        call_sites = (self.js.count("showSiteEnrollment(")
                      - self.js.count("function showSiteEnrollment("))
        self.assertEqual(2, call_sites,
                         "a token-issuing path does not go through the panel")

    def test_the_listener_binds_an_id_that_exists(self):
        self.assertIn("getElementById('siteWizard')?.addEventListener", self.js)
        self.assertIn("siteWizard.goTo('enroll')", self.js)
```

Keep `test_the_token_is_written_as_text_not_markup` and `test_the_config_is_consistent_with_the_token` unchanged.

In `tests/test_ui_revamp.py` (sites-tab class ≈ line 1423):
- in `test_endpoint_contract_present`, replace `self.assertIn("apiFetch('/api/sites', {", html)` with `self.assertIn("'/api/sites/update' : '/api/sites'", html)` (create and update now share one call in `saveSiteWizard`);
- in `test_preserve_ids`, replace the tuple with `('sitesTableBody', 'swName', 'swSubnets', 'btnNewSite')` and its comment with `# sitesTableBody + the site wizard fields read by saveSiteWizard().`;
- in `test_admin_gated_functions_untouched`, replace `('createSite()', 'regenSiteToken(', 'deleteSite(')` with `('saveSiteWizard()', 'regenSiteToken(', 'deleteSite(')`;
- in `test_tab_uses_component_classes`, replace the two lines asserting `data-open-modal="createSiteModal"` and `id="jumpLimits"` with:

```python
        self.assertIn('id="btnNewSite"', tab)
        self.assertIn('id="siteWizard"', html)
```

  and the comment above them with `# sites table only; creation and editing live in the siteWizard side panel.`

- [ ] **Step 5: Run the gates**

Run, in order, and read each output:

```sh
uv run pytest tests/test_site_wizard_ui.py tests/test_site_editing.py tests/test_ui_revamp.py tests/test_jump_site.py tests/test_ui_modal.py tests/test_lazy_tab_scripts.py tests/test_i18n_keys.py -q
uv run python scripts/check_frontend.py
uv run python scripts/check_i18n_coverage.py --strict
uv run python scripts/check_a11y.py --strict
uv run pytest tests -n 4
uv run pyrefly check
uv run python scripts/check_no_private_data.py
```

Expected: all green / clean. A `test_i18n_keys.py` failure naming a key means a `tr('…')` key used above is missing in one language — add it to both dictionaries.

- [ ] **Step 6: Commit (Tasks 6 + 7 together)**

```bash
git add templates/dashboard.html static/js/i18n.js static/js/settings.js tests/test_site_wizard_ui.py tests/test_site_editing.py tests/test_ui_revamp.py
git commit -m "feat(sites): site wizard side panel replaces the create/edit/enroll modals"
```

---

### Task 8: Visual check, graph update, handoff

**Files:**
- Modify: `HANDOFF.md` (§2, one new bullet)
- Possibly modify: `static/css/dashboard.css` (fixes found by eye, Task 5 classes only)

- [ ] **Step 1: Run the app and ask the user to log in**

Start the server in the background (`uv run python app_server.py`; port per `docs/development.md`). Open the dashboard in the Chrome MCP (`mcp__plugin_ecc_chrome-devtools__new_page`) and ask the user to log in — never handle credentials.

- [ ] **Step 2: Walk the flow and screenshot each state**

In the Sites tab: open "Nuova sede"; screenshot step 1 (cards); pick Jump; step 2 with one invalid subnet chip (`10.0.0.0/33`); step 3 idle; step 3 after a test against the unreachable RFC 5737 host `198.51.100.250` (expect the red result with the raw error); tick "Save without verifying"; step 4. Then edit an existing site (rail clickable). Switch the theme to dark and check contrast; resize to 700px (`resize_page`) and check the panel is full width. Run `list_console_messages` — expect no errors.

- [ ] **Step 3: Fix what the screenshots show**

Layout defects go into `static/css/dashboard.css` (Task 5 classes only); re-run `uv run python scripts/check_frontend.py`; commit `fix(ui): <what>`.

- [ ] **Step 4: Update the graph and HANDOFF**

Run `graphify update .`. Add to `HANDOFF.md` §2 a bullet: "Site wizard (piece 1 of the provisioning UX revamp) shipped — spec `docs/superpowers/specs/2026-09-23-site-wizard-design.md`. Pieces 2 (add device) and 3 (Zero-Touch) reuse `ui-wizard.js` and each need their own spec. Version not bumped: the user decides."

```bash
git add HANDOFF.md
git commit -m "docs: handoff for the site wizard"
```

- [ ] **Step 5: Report**

Tell the user: commits made, gates run with their results, screenshots taken, anything deferred. Do not push and do not bump the version.
