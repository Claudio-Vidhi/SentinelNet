# Changelog

Notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/), with `core/version.py` as the single source of
truth.

This file starts at 0.24.0. Earlier releases were not written up as they
happened — `git log --grep="chore(release)"` is the record for those.

## [Unreleased]

### Security

- `users.json` (every password hash) and `sites.json` (every agent site-token
  hash) had no permission tightening at all — not on the temp copy, not on the
  final file — so on a shared data directory they were readable by whoever the
  directory allowed. Both are now restricted, temp copy first.

- A user restricted to some sites could download another customer's device
  backup. `GET /api/download-backup/{name}` checked the caller's scope against
  the FIRST IP in the requested name but resolved the file from the LAST one,
  so `192.0.2.10-198.51.100.7.txt` passed the check on a device the caller owns
  and returned the backup of one they do not. Every IP in the name is now
  checked. The path-traversal guard was already correct and now has a test.
- The audit report PDF is rendered from client-supplied HTML by a real browser
  running on the server, which would fetch any subresource that HTML named —
  an authenticated request forgery reading internal services from the
  appliance's network position, with the answer painted into the returned PDF.
  The browser is now started with name resolution refused outright (literal IP
  addresses included).
- The Content-Security-Policy gains `base-uri 'none'` and `form-action 'self'`.
  Without `base-uri`, an injected `<base href>` repoints every relative script
  URL and walks around `script-src 'self'`.
- The encryption key file is no longer briefly readable by anyone the data
  directory allows: permissions are tightened on the temporary file before it
  is renamed into place, not only afterwards.
- New guard test: every API route that takes a device IP must reach
  `assert_device_allowed`, directly or through a helper. The deliberate
  exceptions are listed one by one with the reason, so adding an unguarded
  route now fails the suite.


### Changed

- The Interfaces tab's six port-state cards, the verdict cards on Home and two
  modals now draw from the design system instead of inline styles: type-ramp
  sizes, lamp-wash tints, and the 1px state accent the system specifies rather
  than a 4px slab. The clickable KPI in MAC Tracker has a cue that reads as one.
- `DESIGN.md` documents the 8px plate radius the app actually ships and no
  longer claims modal titles use the 21px Plate Title step; both had drifted
  from the code.
- `docs/hardening.md` states the accepted risk behind FortiGate REST TLS
  verification defaulting to off, and what to do about it.

- The web interface now follows the browser's language on a first visit
  instead of always starting in Italian. An explicit choice from the language
  selector is still remembered and still wins.
- Startup messages no longer come out garbled on a Windows console using a
  legacy code page: `stdout`/`stderr` are reconfigured to UTF-8.
- The "latest snapshot per kind" query behind the observability API context
  now filters by tenant in the inner query too. When two customers each had a
  device on the same IP, a restricted user saw an empty panel instead of their
  own snapshot.

### Fixed

- `README.md` and `docs/development.md` claimed Python 3.14+; the supported
  floor is 3.11, which is what the Docker image and the pinned
  `requirements.txt` actually build against.
- `SECURITY.md` listed supported versions as 0.1.x/0.2.x, several minors
  behind the actual release line.

### Added

- Issue and pull-request templates under `.github/`, routing vulnerability
  reports to a private advisory rather than a public issue.
- `CHANGELOG.md`, this file.

## [0.24.0]

### Added

- Dedicated **Interfaces & Expected State** monitoring tab, with batch
  endpoints behind it.
- Client-side internationalization across the dashboard: every user-facing
  string resolves through the `it`/`en` dictionaries in `static/js/i18n.js`,
  including the correlation-rule catalogue, which `GET /api/incidents/rules`
  now serves in the requested language via an optional `lang` parameter.

### Fixed

- Key files written with Windows DPAPI could not be loaded on non-Windows
  hosts: the Linux/Docker fallback path is now handled instead of raising.
- Correlation rules hardened, and a hardcoded label that bypassed i18n
  corrected.
- Docker image build no longer stalls on an interactive apt prompt
  (`apt-get install -y`).

### Changed

- `data/` and `*.posix` are ignored wholesale, so no runtime state — device
  credentials, databases, backups, keys — can be committed by accident.

## [0.23.0]

### Changed

- Cloud backup enforces the pinned SSH host key after connecting, not only
  before.
- Dead code removed: orphaned functions with no callers, the two unused
  provisioner download endpoints, the per-vendor config-analyzer renderers,
  and the unreachable half of the ARP cluster.
