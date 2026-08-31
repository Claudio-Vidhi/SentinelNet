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
| [collectors.md](collectors.md) | Sources: IPFIX, NetFlow, sFlow, syslog, FortiGate REST, SNMP, Linux health, site agents |
| [server-collection.md](server-collection.md) | Linux hosts: what the backup collects, which view each command feeds, what needs sudo |
| [live-flows-and-siem.md](live-flows-and-siem.md) | The two flow tabs in depth: ingest, endpoints, frontend, past mistakes |
| [remote-sites.md](remote-sites.md) | Multi-site: central poll and site agent, deployment, CLI relay |

### Operations

| Document | Contents |
|---|---|
| [operations.md](operations.md) | Runbook: paths, logs, metrics, retention, symptoms and causes, backup |
| [fedora-central-install.md](fedora-central-install.md) | Fedora Server: step-by-step Central server installation, systemd, SELinux, firewall |
| [ubuntu-agent-install.md](ubuntu-agent-install.md) | Ubuntu Server 24.04 LTS: step-by-step Site Agent deployment, token auth, systemd |
| [provisioning-tutorial.md](provisioning-tutorial.md) | Day-0 walkthrough: generate a switch/FortiGate config, push a switch config via SSH or console, and what to do when it fails |
| [hardening.md](hardening.md) | TLS, reverse proxy, session cookie, listener exposure |

### Building

| Document | Contents |
|---|---|
| [development.md](development.md) | Layout, tests, type checking, build, pre-commit checklist |
| [../DESIGN.md](../DESIGN.md) | UI design language (mimic panel): palette, typography, component rules — root-level authority, supersedes the old docs/design-system.md |
| [reference/](reference/) | External vendor documentation, distilled |

## Maintenance rule

A document that is no longer true gets corrected or deleted, never left in
place: stale documentation leads to wrong decisions with more confidence than
missing documentation. When a change invalidates a line here, the change isn't
finished.

Superseded documents are removed rather than archived — `git log` is the
archive.
