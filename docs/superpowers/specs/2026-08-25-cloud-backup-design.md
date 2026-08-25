# Offsite backup mirror — design

Status: proposed · 2026-08-25 · target version 0.15.0 (MINOR: new module + tab
section)

## The problem

`backup-config/` is the only copy of every device configuration this install has
ever collected, and it lives on the same host as the app. A disk failure, a
ransomware event or a decommissioned server takes the archive with it. The
engineer who needs it is, by definition, already having a bad day.

There is precedent in the tree: the config-drift git mirror
(`services/config_drift/mirror.py`) exists for exactly this reason — *storage
redundancy, a second copy of the archive*. It is limited to a local git
repository. This feature is the same idea pointed at a machine that is not this
one.

## Decisions taken before writing this

| Question | Decision |
|---|---|
| First backend | **SFTP / SSH target** — paramiko is already a dependency, no new signing code, and it fits estates with a NAS or jump host and no object storage |
| Scope of the mirror | **`backup-config/` only** — current files and `.history/`. Databases, telemetry and settings stay on the host |
| Client-side encryption | **Optional, off by default** |
| Direction in v1 | **Push + list.** Restore is phase 2 |

> On the encryption default: off means device configurations — hostnames,
> management IPs, SNMP communities, VPN peers, ACLs — land on the remote host in
> plaintext, protected only by SSH transport and that host's file permissions.
> That is defensible when the target is the customer's own NAS and weak when it
> is rented storage. The setting stays off by default as decided; the UI states
> that consequence in one line next to the toggle, and `docs/operations.md`
> recommends enabling it whenever the target is not owned by the customer.

## Constraints this design has to survive

- **Isolated deployments exist.** Some installs sit on a management LAN with no
  route offsite. The feature is off by default and its absence must never
  degrade anything else.
- **No data leaks into the repo.** Any new state file under `data/` gets its
  `.gitignore` entry *in the same change that writes the code* — before anyone
  runs the tool (AGENTS.md).
- **Dual artifact.** PyInstaller executable and Docker image both keep building;
  no new asset files, no new dependency (paramiko is already in the spec).
- **Tenant scoping is a security gate.** The remote layout is partitioned by
  tenant and every API route filters on `user_group_scope`.
- **Never write credentials.** The implementation reads the SSH key path and
  passphrase the operator configured; it never creates, rotates or rewrites a
  key store.
- **Single-process SQLite writer.** The uploader runs in a worker thread and
  touches no async DB path directly.

## Model: a mirror, never a backend

The local archive stays the single source of truth. Nothing in the app ever
*reads* from the remote — not the config analyzer, not the drift engine, not the
policy tests. The mirror is write-only in v1, exactly like the git mirror.

Two consequences worth stating, because they remove whole classes of bug:

- No cache-coherency problem. There is no "which copy is newer" question, so no
  merge, no conflict resolution, no partial-state recovery.
- A failed upload is a *reported* failure, never a silent degradation. If the
  mirror is enabled and cannot run, it says so loudly — the same rule the git
  mirror already follows: a redundancy feature that quietly is not running is
  worse than one that is off.

## Remote layout

The local tree is mirrored verbatim under a configured root, partitioned by
tenant so a per-tenant restore is a directory copy:

```
<remote_root>/
  <tenant>/<vendor>/
    switch-01-192.0.2.10.txt
    .history/
      192.0.2.10-index.json
      switch-01-192.0.2.10.20260819T110233.451207Z.txt
  _manifest.json
```

`_manifest.json`, written last on every run, is what makes "is my offsite copy
current?" answerable without walking the tree:

```json
{
  "schema": 1,
  "updated_at": "2026-08-25T09:14:02Z",
  "source": "sentinelnet",
  "encrypted": false,
  "files": {
    "site-a/cisco/switch-01-192.0.2.10.txt": {
      "sha256": "1f0a…", "size": 48210, "uploaded_at": "2026-08-25T09:13:58Z"
    }
  }
}
```

With client-side encryption on, every uploaded file is suffixed `.enc`, the
manifest records the hash **of the plaintext** (so change detection keeps working
without decrypting), and `"encrypted": true` tells a future restore what it is
looking at.

## Local state

`data/cloud_backup_state.json` — what this host believes is already offsite:

```json
{
  "schema": 1,
  "last_run": {"started_at": "2026-08-25T09:13:40Z", "ok": true,
               "uploaded": 12, "skipped": 431, "failed": 0, "error": null,
               "verified": 34},
  "last_success_at": "2026-08-25T09:14:02Z",
  "files": {"site-a/cisco/switch-01-192.0.2.10.txt": "sha256:1f0a…"}
}
```

**Its `.gitignore` entry lands in the same commit as the code that creates it.**
`data/` is ignored file by file, and this file fills with tenant paths and device
filenames the first time it runs. Verification: `git status --porcelain data/`
prints nothing.

## Configuration and secrets

One section in `app_settings.json` — the same store the git mirror uses:

```json
{
  "cloud_backup": {
    "enabled": false,
    "kind": "sftp",
    "host": "backup.example.net",
    "port": 22,
    "username": "sentinelnet",
    "auth": "key",
    "key_path": "C:/ProgramData/SentinelNet/keys/offsite_ed25519",
    "key_passphrase_enc": "<fernet>",
    "password_enc": "<fernet>",
    "remote_root": "/srv/backups/sentinelnet",
    "host_key_fingerprint": "SHA256:…",
    "encrypt_payload": false,
    "run_after_backup": true
  }
}
```

- Passphrase and password go through `security.crypto_vault`
  (`encrypt_password` / `decrypt_password`), never stored in clear — the same
  Fernet key store the device credentials already use.
- **The host key is pinned.** The first connection records the fingerprint; a
  later mismatch aborts the run and reports it. `AutoAddPolicy` with no pin is
  how a redirected DNS entry becomes config exfiltration; the existing
  `data/ssh_known_hosts` handling is the model.
- `key_path` points at a key the operator created. The app reads it, and never
  generates or rewrites one.

## Module layout

```
services/cloud_backup/
  __init__.py     # run_mirror(), status(), is_enabled() — the only public surface
  settings.py     # read/write the app_settings section, secrets via crypto_vault
  sftp.py         # transport: connect (pinned host key), mkdir -p, atomic put
  sync.py         # walk backup-config/, diff against state, decide what to send
  payload.py      # optional client-side encryption of a single file
  state.py        # data/cloud_backup_state.json read/write
```

`sftp.py` is the only file that knows about paramiko. A second backend (S3,
WebDAV) later means a second transport module implementing the same three verbs
— `ensure_dir`, `put`, `list` — and nothing else moves. That is the *only*
abstraction this design allows itself: no plugin registry, no provider interface
class, until a second provider actually exists.

## Sync algorithm

1. Refuse to start if disabled, or if another run is in flight (module-level
   lock; the mirror is idempotent, but concurrent runs waste the link).
2. Walk `backup-config/`, collecting `(relative_path, sha256, size)`. Skip
   nothing: `.history/` is the part that makes the mirror worth having.
3. Diff against `state.json`: upload a file only when its hash differs or it is
   absent remotely. An unchanged estate uploads zero bytes.
4. Upload to a temporary name and rename into place (`put` + `posix_rename`), so
   an interrupted transfer never leaves a truncated config looking authoritative.
5. Write `_manifest.json` last, and `restore.py` beside it. A fresh `updated_at`
   is the proof the run completed.
6. Verify: re-`stat` every file uploaded this run, re-hash a rotating 5% of the
   rest. Any mismatch fails the run and names the path.
7. Update local state; record the outcome (counts, verified count, first error)
   and `last_success_at` for the UI.

Failure is per-file and non-fatal until the end: one unreadable file must not
abandon the other 400. The run reports `failed > 0`, the first error, and
`ok: false`.

## Optional client-side encryption

Off by default. When on, each file is encrypted with the Fernet key already in
the vault before upload, and the remote filename gains `.enc`.

The consequence belongs in the UI and in `docs/operations.md`, not buried here:
**the offsite copy is unreadable without this install's Fernet key store.** Lose
the host and the key together and the mirror is scrap. So enabling it comes with
exactly one instruction — back up the key file separately, offline.

That is also why it is not a silent default, and why the documentation
recommends turning it on whenever the remote host is not the customer's own.

## Making the copy trustworthy

Four additions that separate "we think there is a copy" from "we know there is a
current copy, and anyone can use it". All four are v1: each closes a hole the
rest of the design would otherwise leave open.

### Self-describing archive: `restore.py` on the remote

Every run uploads a standalone ~50-line Python script next to `_manifest.json`.
It reads the manifest, rebuilds the tree into a target directory, and decrypts
when given the key file. It imports nothing from this repo.

The point: whoever finds that folder in three years — a different engineer, a
different tool, no SentinelNet install — can use it. A backup that requires the
software that produced it is a backup with a dependency nobody wrote down.

### Status reports age, not just outcome

`status` returns `hours_since_success` alongside `last_run.ok`, and the UI turns
amber past a threshold (default 48h, configurable in the same settings section).

Without it, a run that succeeded nine days ago and has not fired since — because
backup collection itself has been failing — reads as healthy. "ok: true" with no
age is not a status, it is a reassurance.

### Verify a sample after upload

After the manifest is written, re-`stat` every file uploaded this run and re-hash
a rotating 5% of the rest. A mismatch marks the run `ok: false` with the
offending path.

This is what makes the "0 files not yet offsite" counter mean something. A remote
that accepts writes and discards them — full disk, exhausted quota, a broken FUSE
mount, a read-only export — otherwise looks exactly like success.

### Documented manual restore

`docs/operations.md` gains a section: how to pull a version back by hand, what the
`.history/` filename and index format mean, and how to decrypt when encryption is
on. Verified once, by hand, before the feature ships.

Restore proper is phase 2 — but an untested restore path is a backup you do not
have, and the first real restore always happens under pressure.

## Phase 2 additions

Scoped here so the v1 shape does not paint them into a corner.

- **Restore lands in a staging directory**, `restore/<timestamp>/`, never over
  `backup-config/`. The operator diffs, then copies. This removes the worst
  failure mode — a restore silently overwriting a config fresher than the copy
  being restored — and costs nothing to decide now.
- **Orphan reporting, never deletion.** List remote files with no local
  counterpart (decommissioned devices, renamed tenants) and let the operator
  delete deliberately from the UI. Auto-pruning is refused on purpose: one bug in
  the local walk would erase the archive the feature exists to protect.
- **S3-compatible transport.** The actual "cloud provider" backend. It will bend
  the three-verb interface: object stores have no directories and no rename, so
  temp-name-then-`posix_rename` atomicity does not port — it becomes
  upload-then-`copy_object`, or relying on multipart completion being atomic.
  Better to learn that against a real second backend than to over-design the
  interface now.

## If the scope later grows to disaster recovery

Today's scope rebuilds *devices*, not the *install*: lose the host and inventory,
tenants, incidents and ARP history go with it. Two additions would close that,
and both need their own decision about how much customer state may go offsite:

- **Database snapshot via `sqlite3 .backup`** — never a naive file copy, which
  captures a torn WAL and restores as a corrupt database. One consistent snapshot
  per run, mirrored beside the configs.
- **Key escrow acknowledgement** — when encryption is enabled, setup does not
  complete until the operator confirms the Fernet key has been exported
  elsewhere, and that acknowledgement is recorded. The current design depends on
  a manual step nothing enforces; an encrypted mirror plus a lost key is an
  expensive way to store noise.

## API

All routes admin-only (`require_admin`); `status` is readable by operators so a
triage can see whether the mirror is current.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/cloud-backup/settings` | Current config, secrets redacted |
| `PUT` | `/api/cloud-backup/settings` | Save config; validates before storing |
| `POST` | `/api/cloud-backup/test` | Connect, verify host key, check the root is writable, disconnect. Reports the exact failure |
| `POST` | `/api/cloud-backup/run` | Trigger a mirror run now (background thread) |
| `GET` | `/api/cloud-backup/status` | Last run outcome, counts, `hours_since_success`, and how far local is ahead of the manifest |
| `GET` | `/api/cloud-backup/remote` | What the remote manifest holds, filtered to the caller's tenant scope |

Every route writes to the audit trail (`log_audit`): "who pointed our configs at
which host" is a security question.

## UI

A section in the Settings tab, following the existing pattern — label, control,
one line of consequence:

- Enable toggle, transport fields, "Test connection" showing the real error text.
- Encryption toggle with its warning and the key-backup instruction.
- Status block: last run, **how long ago it last succeeded** (amber past the
  threshold), how many files, how many were verified, and the number that matters
  — *how many local files are not yet offsite*. Zero is the only good answer.
- A manual "Mirror now" button.

Strings go in `static/js/i18n.js` under both `it` and `en`. No inline handlers:
ids plus delegated listeners, cross-module globals declared in
`types/globals.d.ts`, and a `LAZY_TAB_SCRIPTS` entry for every tab whose controls
the module binds.

## Triggering

- After a successful backup collection run, when `run_after_backup` is true.
  That is the moment new versions exist, and it keeps the mirror current without
  a scheduler.
- Manually from the UI.

No cron and no interval setting in v1. If a periodic sweep is wanted later it
belongs next to the existing ping-monitor loop, not in a second scheduler.

## Tests

- `tests/test_cloud_backup_sync.py` — diff logic against a temp tree: new file
  uploads, unchanged file skips, changed hash re-uploads, `.history/` included,
  empty estate is a no-op.
- `tests/test_cloud_backup_settings.py` — secrets round-trip through the vault
  and never appear in the `GET` response; an invalid config is rejected before it
  is stored.
- `tests/test_cloud_backup_transport.py` — a paramiko double asserts the
  temp-name-then-rename order, and that a host-key mismatch aborts before any
  `put`.
- `tests/test_router_smoke.py` — extend with one `TestClient` call per new route
  (401/403/422 prove the handler ran), per the router rule in AGENTS.md.
- Encryption on/off: uploaded bytes differ from the plaintext, and the manifest
  hash stays the plaintext hash.
- `tests/test_cloud_backup_verify.py` — a transport double that reports a wrong
  size (or a wrong hash on the sampled file) makes the run `ok: false` and names
  the path. A remote that discards writes must not look like success.
- `tests/test_cloud_backup_restore_script.py` — run the uploaded `restore.py` in
  a subprocess against a manifest and a temp tree, encrypted and not: it must
  rebuild the exact bytes with no import from this repo.
- Status age: a state file whose `last_success_at` is 60 hours old reports
  `hours_since_success` past the threshold even when `last_run.ok` is true.

No test ever contacts a real host.

## Phases

1. **Settings + vault + `.gitignore` entry.** No transport yet. Ends with config
   persisting and secrets encrypted.
2. **Transport.** Connect with pinned host key, `ensure_dir`, atomic `put`, and
   the `test` endpoint. Ends with a green "Test connection".
3. **Sync + state + manifest + post-upload verification.** The mirror runs;
   `run` and `status` go live, and a lying remote fails the run.
4. **`restore.py` on the remote**, plus the manual-restore section in
   `docs/operations.md`, verified once by hand. From here the archive is usable
   without this app.
5. **UI section**: not-yet-offsite count and age-of-last-success.
6. **Optional encryption**, its warning, and the key-backup note.
7. **Trigger after a backup run.**

If early confidence matters more than order, phases 2–3 plus a status line are
the smallest slice that proves the whole idea; settings UI can follow.

Each phase ends green: `uv run pyrefly check`, `uv run pytest tests -n 4`,
`uv run python scripts/check_frontend.py` when the frontend moved, and
`graphify update .`.

## Version and packaging

- `core/version.py` → `0.15.0`, `pyproject.toml` matched (MINOR: new module and a
  new settings surface).
- No new dependency and no new asset, so `SentinelNet.spec` is unchanged —
  confirm the executable still builds before calling it done.

## Deliberately out of scope

- **Restore from the UI.** v1 proves the copy exists, is current and is usable by
  hand (`restore.py` + the operations section). Pulling a version back through
  the app is phase 2 and needs its own thinking about who may overwrite what.
- **Mirroring databases or settings.** More customer state offsite, a different
  consistency problem, and no demand yet — see the disaster-recovery section for
  what it would take.
- **Automatic remote pruning.** Orphans are reported, never deleted by the app. A
  bug in the local walk would otherwise erase the archive.
- **A scheduler for the mirror.** The post-backup trigger is the moment new
  versions exist; a second timer means two sources of truth about when it ran.
- **Multiple destinations.** Fan-out doubles the failure matrix of a redundancy
  feature that is not yet proven against one remote.
- **Compression.** Configs are text and SSH already compresses; it buys little
  and complicates the manifest hash.
