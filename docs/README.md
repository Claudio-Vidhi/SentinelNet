# SentinelNet Documentation

Documentation explains **why**; the code shows **how**. Where a decision is
already argued in a module docstring, this folder links to it instead of
copying it.

All documentation is in English. (Code follows a different convention: Italian
for user-facing strings, logs and comments, English for identifiers — see
[CONTRIBUTING.md](../CONTRIBUTING.md) §1.)

## Reading paths

**I'm new here** → [principles.md](principles.md) →
[architecture.md](architecture.md) → [development.md](development.md)

**I need to install or run it** → [../README.md](../README.md) →
[operations.md](operations.md) → [hardening.md](hardening.md)

**I'm working on observability** → [architecture.md](architecture.md) →
[collectors.md](collectors.md) → [live-flows-and-siem.md](live-flows-and-siem.md)

**I need to know why a choice was made** → [adr/](adr/)

## Index

### Design

| Document | Contents |
|---|---|
| [principles.md](principles.md) | Engineering principles every module is measured against |
| [architecture.md](architecture.md) | Data pipeline end to end, event/evidence/incident model, module map |
| [adr/](adr/) | Architecture Decision Records — one decision per file |
| [roadmap.md](roadmap.md) | What isn't built yet and why, in priority order |

### Subsystems

| Document | Contents |
|---|---|
| [collectors.md](collectors.md) | Sources: IPFIX, NetFlow, sFlow, syslog, FortiGate REST, SNMP, site agents |
| [live-flows-and-siem.md](live-flows-and-siem.md) | The two flow tabs in depth: ingest, endpoints, frontend, past mistakes |
| [remote-sites.md](remote-sites.md) | Multi-site: central poll and site agent, deployment, CLI relay |

### Operations

| Document | Contents |
|---|---|
| [operations.md](operations.md) | Runbook: paths, logs, metrics, retention, symptoms and causes, backup |
| [hardening.md](hardening.md) | TLS, reverse proxy, session cookie, listener exposure |
| [security-audit.md](security-audit.md) | White-box security review, findings with status |
| [security-semgrep.md](security-semgrep.md) | SAST triage: verdicts and remediation plan |

### Building

| Document | Contents |
|---|---|
| [development.md](development.md) | Layout, tests, type checking, build, pre-commit checklist |
| [design-system.md](design-system.md) | UI design language: palette, typography, component rules |
| [reference/](reference/) | External vendor documentation, distilled |

## Maintenance rule

A document that is no longer true gets corrected or deleted, never left in
place: stale documentation leads to wrong decisions with more confidence than
missing documentation. When a change invalidates a line here, the change isn't
finished.

Superseded documents are removed rather than archived — `git log` is the
archive.
