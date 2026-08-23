# Config Drift — design

Date: 2026-08-23
Status: shipped

> Example addresses are RFC 5737 (`192.0.2.x`, `198.51.100.x`) and hostnames are
> placeholders, as required by CLAUDE.md: `data/` holds real customer state and
> facts derived from it are as sensitive as the files.

## The problem

There is no way to answer "what changed on this network, and when". A device is
backed up on every triage run, but only one copy survives: `save_backup()`
(`core/core_engine.py`) calls `remove_stale_backups(ip)` first, which walks the
whole backup tree and deletes every previous file for that IP, then writes a
single `<name>-<ip>.txt`. There is no second version to compare against.

Two questions are in scope, and they are different questions:

- **History** — did this device change since we last saw it, and what changed?
- **Baseline** — does this device match the standard this tenant expects?

Both are scoped per tenant.

## Hard constraint: the current backup file cannot move

`backup-config/<group>/<vendor>/<name>-<ip>.txt` is read directly by the policy
test loader, the netsec audit, the config analyzer and `download_backup`.
History is therefore **additive**: the current file stays exactly where it is
and keeps its name. Everything new lives beside it.

`<group>` is the tenant, so the existing layout already partitions the data by
tenant. Per-tenant filtering falls out of the directory structure rather than
needing an index.

## Storage

```
backup-config/<tenant>/<vendor>/
  switch-01-192.0.2.10.txt                                 <- current, unchanged contract
  .history/
    192.0.2.10-index.json
    switch-01-192.0.2.10.20260819T110233.451207Z.txt
    switch-01-192.0.2.10.20260722T093011.118004Z.txt
```

`<ip>-index.json`, one entry per retained version, newest first:

```json
{
  "device": "192.0.2.10",
  "versions": [
    {"hash": "sha256:1f0a…", "seen_at": "20260819T110233.451207Z", "size": 48210,
     "file": "switch-01-192.0.2.10.20260819T110233.451207Z.txt"}
  ],
  "last_seen_at": "20260822T031407.902113Z"
}
```

`seen_at` is UTC in the compact form `YYYYMMDDTHHMMSS.ffffffZ` (microsecond
precision, not the second-precision `YYYYMMDDTHHMMSSZ` originally planned here:
two versions recorded inside the same second would otherwise share a stamp
*and* the archived filename built from it, and the second write would silently
overwrite the first with no way for `read_version` to tell the two apart). The
same string is the timestamp in the archived filename, so a file can be
located from its index entry without a second lookup.

**Every changed version is kept, never pruned.** Disk grows only when a config
actually changes, which is why normalisation (below) has to be right: a
normaliser that misses a volatile line turns every run into a new version.

`last_seen_at` is updated on every run whether or not the config changed, so the
UI can distinguish "unchanged for 14 days" from "not collected for 14 days".

### Git mirror

Optional, off by default, controlled by one setting. When enabled, each new
version is also committed to a git repository rooted at the backup folder.

Its purpose is **storage redundancy — a second copy of the archive**. It is not
a second backend and not a switchable storage mode: the `.history/` archive is
always the source of truth, and the feature reads from it exclusively. Nothing
in the drift engine ever reads from git.

If git is not available on the host, enabling the mirror **fails loudly** with
the reason. It must not silently degrade to not mirroring — a redundancy
feature that quietly is not running is worse than one that is off.

## Normalisation

Hashing raw config text makes every run look like drift: `Current configuration
: N bytes`, `uptime is ...`, `ntp clock-period`, and vendor-specific counters
change without anyone touching the device.

Normalisation is vendor-specific: one entry point, `normalize(vendor, text)`,
dispatching to per-vendor pattern tuples (`_IOS`, `_FORTIOS`) kept inline
rather than split into a module per vendor the way `services/policy_test/`
splits its parsers — the pattern lists are short enough that a file per
vendor would be one tuple per file.

```
services/config_drift/
  normalize.py     # normalize(vendor, text) -> str; _IOS / _FORTIOS pattern
                    # tuples dispatched by _BY_VENDOR
  history.py       # hash, archive, index
  mirror.py        # optional git mirror of the archive
  baseline.py      # required/forbidden matching
```

An unknown vendor normalises nothing and is still hashed: the result is noisier
drift, never a crash and never a skipped device.

Normalisation applies **only to the hash and the diff**. The archived file is
the config as collected — a stripped archive would be useless for restoring or
for reading later.

## Detection

`run_backup_and_triage(device)` is the single point every backup already flows
through. It calls `history.record_version(device, config_text)` after
`save_backup`. No new scheduler and no second collection path.

`record_version` normalises, hashes, compares against `versions[0].hash`, and
either updates `last_seen_at` or archives the previous current file and prepends
a new entry.

### `remove_stale_backups` becomes a move

Today it deletes every file for an IP anywhere in the tree, so a device that
changes tenant loses its config. With history in place it would also destroy the
entire archive. It becomes a move: the current file and its `.history/` follow
the device to the new tenant folder. A device changing tenant is a normal
operational event and must not be a data-loss event.

## Baseline

A whole-file diff against a golden config produces noise, not signal: every
device legitimately differs in hostname, management address, VLAN set and port
ranges. The baseline is therefore **rule-based**.

A tenant baseline is a list of patterns, one per line:

```
+ ip dhcp snooping
+ login block-for 120 attempts 5 within 60
+ service password-encryption
- ip http server
- transport input telnet
```

`+` must be present, `-` must be absent. A line matches if the pattern occurs in
the normalised config; patterns are matched literally unless wrapped in `/…/`,
in which case they are regular expressions.

A device is compliant when every `+` matches and no `-` does. **There is no
score, no grade and no severity** — deliberately. This is not an audit; the
netsec audit already exists for that and has its own benchmarks, scoring and
export. The baseline answers one question with one answer per line: present, or
missing.

**Seeding.** `POST /api/drift/baseline/{tenant}/seed?ip=` returns candidate `+`
patterns extracted from one device's current config — the security-relevant
lines, not the whole file. The operator prunes them in a textarea. No line-picker
UI, no template engine, no per-device variable substitution.

## API

All routes live in `routers/config_drift.py`. Every route is scoped: list routes
filter by `user_group_scope(current_user)`, device routes call
`assert_device_allowed`. A scoped user must not be able to read another tenant's
drift by guessing an IP — the same rule every other device route follows.

| Method | Path | Returns |
| :--- | :--- | :--- |
| GET | `/api/drift/devices` | tenant's devices: last change, last seen, version count |
| GET | `/api/drift/{ip}/versions` | version list for one device |
| GET | `/api/drift/{ip}/diff?from_version=&to_version=` | redacted unified diff between two versions |
| GET | `/api/drift/baseline/{tenant}` | the tenant's patterns |
| PUT | `/api/drift/baseline/{tenant}` | replace them (admin only, audited) |
| POST | `/api/drift/baseline/{tenant}/seed?ip=` | candidate patterns from a device |
| GET | `/api/drift/{ip}/baseline` | that device's deviations |

Diffs use `difflib.unified_diff` — stdlib, and currently unused in the tree, so
no new dependency.

### Diffs are redacted

A config diff is dense with `enable secret`, `username … secret`, `set password`
and SNMP keys. Every diff and every seeded pattern passes through
`security/redaction.py` before leaving the server, at the point they are
produced rather than at each endpoint, so a later caller cannot forget.

This is the same rule applied to push transcripts in `b9ab4ef`, for the same
reason: the operator does not need the secret to read the change, and the
response is rendered in a browser.

## UI

A new tab `#tab-config-drift`, lazy-loaded `static/js/config-drift.js` with its
`LAZY_TAB_SCRIPTS` entry (both halves — `tests/test_lazy_tab_scripts.py` checks
for it).

Tenant-first, like the WLC tab: choose a tenant, then its devices appear.
Two sub-tabs:

- **History** — device rows with last-change and last-seen, a version list, and a
  diff view between any two versions.
- **Baseline** — the tenant's patterns in a textarea, and the deviation list per
  device: which `+` are missing, which `-` are present.

Every label goes through i18n in both `it` and `en` — `tests/test_i18n_parity.py`
fails otherwise. Every interpolated value passes `escapeHtml`; no inline
handlers.

## Testing

| Check | Why |
| :--- | :--- |
| Re-collecting an unchanged config creates no new version | The whole feature is noise if normalisation leaks |
| A real change creates a version and the diff shows it | The core behaviour |
| Volatile lines alone do not count as a change, per vendor | Where the noise comes from |
| History survives a tenant move | `remove_stale_backups` used to delete it |
| A scoped user gets 403 on another tenant's device | Tenant isolation is enforced, not cosmetic |
| A diff containing `enable secret` carries no cleartext | Same class as the push-transcript leak |
| Required present / forbidden absent, and their negatives | Baseline matching |
| Enabling the git mirror without git fails loudly | Silent non-redundancy is the failure mode |
| `LAZY_TAB_SCRIPTS` has both halves for the new tab | The tab is dead when opened cold otherwise |

## Deliberately not in scope

- No scoring, grading or severity. That is the netsec audit's job.
- No pruning or retention limits. Revisit if a real archive grows enough to matter.
- No per-device variable substitution in baselines.
- No restore-from-history. Reading a past config is in scope; pushing it back is not.
- No alerting on drift. The tab answers the question when asked.
