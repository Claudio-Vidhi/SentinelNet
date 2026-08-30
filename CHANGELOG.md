# Changelog

Notable changes per release. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/), with `core/version.py` as the single source of
truth.

This file starts at 0.24.0. Earlier releases were not written up as they
happened — `git log --grep="chore(release)"` is the record for those.

## [Unreleased]

### Changed

- The web interface now follows the browser's language on a first visit
  instead of always starting in Italian. An explicit choice from the language
  selector is still remembered and still wins.
- Startup messages no longer come out garbled on a Windows console using a
  legacy code page: `stdout`/`stderr` are reconfigured to UTF-8.

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
