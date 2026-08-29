# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Network and system engineers responsible for infrastructure they cannot always
stand next to.

- **MSP engineer running several customer networks** — the growth case. Tenants
  and groups are customers. Every design decision must survive multi-customer
  use even when it is made for a single estate.
- **In-house sysadmin or small IT team on one estate** — the current core.
  Tenants and groups are sites or departments.

In-product roles: `admin`, `operator`, `viewer`. A user belongs to *multiple*
groups (`user_group_scope`) — scope is a set, never a scalar, and it is an
authorization boundary, not a filter.

UI languages: Italian (default) and English, switchable at runtime and persisted
per browser.

## Product Purpose

Self-hosted platform that centralizes management of network infrastructure:
configuration backup, firmware and vulnerability triage against the
NIST NVD database, passive telemetry collection (NetFlow, IPFIX, sFlow,
syslog, SNMP), and single-client L2+L3 diagnosis — all reachable from one
browser console.

The objective, taken from `docs/principles.md`: help the engineer understand
**what is up, what changed, and what is degraded**, instead of presenting raw
telemetry. Success is measured as reduced MTTD and MTTR.

## Positioning

**A status and management console, not a SIEM.** SentinelNet reports the state
of the network and of the firewalls, and helps manage them. It does not hunt
threats, score anomalies or investigate intrusions — mature products already do
that, and duplicating them adds weight without adding value. When a firewall
denies traffic, the firewall is the authority on that; SentinelNet does not
mirror its verdicts.

This is a scope boundary, not a gap. Anything that reads as threat detection is
out; anything that reads as **operational security** is core:

- **Firewall management** — policy inspection, address objects, sessions,
  provisioning.
- **Policy and configuration audit** — rule hygiene, drift against backups,
  compliance checklists.
- **Vulnerability triage** — firmware versions against the NIST NVD database.
- **Status of the estate** — reachability, redundancy health, link quality,
  configuration backups.

Three things a neighboring product could not truthfully copy:

- **Deterministic reporting.** Independent sources are normalized into one event
  model and evaluated by inspectable Python rules. No AI sits in the decision
  path (ADR-0006).
- **Every conclusion ships its evidence.** A finding carries what was observed,
  when, and from which source. "AI detected anomaly" is a defect, not an output.
- **Self-hosted with nothing leaving the estate.** Windows executable or
  container, local SQLite, credentials encrypted at rest. Customer network state
  never reaches a vendor cloud.

**One question, one surface, one collector.** Before a panel is added, name the
question it answers and check that nothing already answers it; before a
collector is added, check whether an existing one already learns the same fact.
See item 16 of `docs/console-rethink-plan.md`.

## Operating Context

Four confirmed usage scenes, all first-class — no single one may be optimized at
the cost of the others:

1. **Desk, incident in progress.** 1440–1920px, other tools open alongside. The
   engineer needs the answer fast and will not explore for it.
2. **Routine unhurried check.** Morning sweep: backups ran, no new CVEs, nothing
   red. Scanning for the absence of trouble, not hunting.
3. **On-site next to the rack.** Tablet or phone, standing, one hand. Needs
   switch/port, VLAN and client answers on a small screen.
4. **NOC wall / always-on display.** Read from a distance, rarely interacted
   with.

Deployment: PyInstaller executable and Docker image, both built from the same
tree; the app opens a browser at `localhost:8000`. First start is a setup wizard
that creates the local administrator. Devices are reached over SSH, vendor REST
and SNMP from the management LAN; remote sites via site agents.

## Capabilities and Constraints

- **No build step.** The UI is a single Jinja template plus vanilla JS modules
  in `static/js`, served by FastAPI. No framework, no bundler, no npm. Adding
  one is a product decision, not a design one.
- **Browser internet access varies by customer.** Some deployments sit on an
  isolated management LAN, so the console loads nothing from the network.
  Resolved 2026-08-05: every third-party asset is vendored — fonts in
  `static/fonts/`, FontAwesome, Vis.js and Xterm.js in `static/vendor/`. A new
  `<link>` or `<script>` pointing at a CDN is a regression; `static/` ships
  whole in both artifacts, so vendoring costs no spec change.
- **Dark and light are both required.** Confirmed 2026-08-05: the interface must
  ship a real dark rendition and a real light one, not a dark product with a
  bolted-on inversion. The four usage scenes force it — a lit office desk and an
  always-on NOC display do not want the same polarity.
- **Bilingual copy is mandatory.** User-facing strings are Italian, identifiers
  English (CONTRIBUTING §1). Any new UI string needs both an `it` and an `en`
  entry in `static/js/i18n.js`; a hardcoded string is a bug.
- **Tenant scoping is a security gate.** Views and queries filter by the user's
  full group set; device access goes through `assert_device_allowed`.
- **Single-process SQLite writer.** No horizontal scaling with observability
  enabled; async paths never touch `sqlite3` directly.
- **Dual artifact.** Every change must leave both the executable and the Docker
  image buildable; new asset files must be registered in `SentinelNet.spec`.
- **Real customer network state lives in the gitignored `data/`.** Facts derived
  from it — device models, versions, hostnames, serials, management IPs,
  topology roles — are as sensitive as the files. Documentation, comments and
  screenshots use RFC 5737 addresses and placeholder hostnames only.

## Brand Commitments

- Name: **SentinelNet**. Favicon is an inline SVG shield with connected network
  nodes — no external asset.
- An incumbent visual system exists and is fully implemented: the mimic-panel
  design language authored via the impeccable plugin — `DESIGN.md` at the
  repo root is the authority, implemented by `static/css/dashboard.css`.
  Recorded here as fact, not declared binding; `/impeccable document` is what
  captures it as an authority.
- Voice in the UI follows the product principle: state the finding and its
  cause, not the metric. Sections that cannot be answered say why rather than
  disappearing.

## Evidence on Hand

- Real engineering documentation: `docs/` (architecture, principles, collectors,
  operations, hardening, remote-sites) and `docs/adr/` for decision rationale.
- Public GitHub repository, MIT-licensed, plus a published Docker image.
- Working product with real deployments behind it.
- **Absent — must not be fabricated:** testimonials, named customers, logos,
  benchmark numbers, pricing, uptime or scale claims, case studies, certification
  or compliance badges.

## Product Principles

1. **Answer the question, don't show the metric.** A chart is supporting
   evidence; the conclusion is the deliverable.
2. **Every conclusion exposes its evidence, confidence and reasoning path.**
3. **Correlate several sources or reconsider the feature.** A single source is
   incomplete by construction.
4. **The dashboard is a lens, never the logic.** Business logic stays in the
   backend; the frontend renders what was already decided.
5. **Say why something is missing.** An unanswerable section explains itself
   instead of being omitted.

## Accessibility & Inclusion

**Target: WCAG 2.1 AA** (confirmed 2026-08-05). Text contrast at least 4.5:1 in
*both* renditions — the light one is where this fails first, because colour
literals inherited from the previous dark-only design do not follow the theme.
Every interactive element is operable from the keyboard with a visible focus
state; `onclick` on a non-native control is a defect, not a shortcut.

Two product-specific needs beyond AA are confirmed by the usage scenes and are
not hypothetical: legibility at distance on an always-on NOC display, and
one-handed operation on a small screen while standing at a rack.
