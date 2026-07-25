# Audit Manutenzione Firewall — guided assessment tab

Date: 2026-07-25
Branch: `feature/pyrefly-quality`
Source document: `checklist_x_c.docx` (9 sections, ~70 items)

## Purpose

A dedicated tab that walks a network security engineer through a firewall
maintenance audit at a customer site. The audience is explicitly both the
experienced professional and the junior: the tab must **guide the engineer to a
better decision**, not merely record a tick.

This is a different product from the existing NetSec Audit benchmark scan. The
benchmark scan answers "does this config violate CIS/NIST/PCI rules". This tab
answers "have I conducted a competent audit of this customer's firewall, and
what do I write in the relazione".

The source checklist is a professional field document. Most of its value is in
the notes attached to each item — thresholds, rationale, and hard-won caveats.
Those notes are the product. A checklist without them is a to-do list; with
them it is a teaching instrument.

## Core constraint: the checklist is data, not code

The owner's requirement: *"the guidance in this new era can be changed following
events or new spec, find a way also to update from admin checklist."*

Guidance evolves with threats, vendor changes, and regulation. Therefore:

- The checklist definition is **versioned data**, editable by an admin from the
  UI. No checklist text lives in Python or JavaScript source.
- A published version is **immutable**. Editing produces a new draft version.
- An engagement **pins the template version** it was performed against.

That last point is not a nicety. Without it, editing guidance in September
silently rewrites the questions that a completed March audit claims to have
asked, and the archived relazione stops matching its own evidence. Pinning keeps
historical audits honest.

## Data model

Six tables, following the existing `observability/storage/schema.sql` style.

**`audit_templates`** — one row per checklist version.
`id`, `version` (int, monotonic), `name`, `status` (`draft` | `published` |
`archived`), `created_ts`, `created_by`, `notes`.

**`audit_template_items`** — the checklist content.
`template_id`, `ref` (e.g. `"6.9"`), `section_no`, `section_title`, `title`,
`guidance_why`, `guidance_good`, `guidance_how`, `thresholds` (JSON),
`check_kind` (`manual` | `semi` | `auto`), `severity_default`,
`is_prerequisite` (bool), `requires_evidence` (bool), `sort_order`.

**`audit_engagements`** — one row per customer audit.
`id`, `customer_name`, `tenant` (nullable), `site_id` (nullable),
`template_id` (**pinned**), `status` (`draft` | `in_progress` | `completed`),
`created_ts`, `updated_ts`, `created_by`, `assigned_to`, `scope_notes`,
`onsite_or_remote`, `interviewee` (required by section 2's preamble, which
demands the audit record whether checks were done on site or by interview, and
who was interviewed).

`tenant` and `site_id` are nullable on purpose. The stated use case is a **new
customer not yet in inventory**. The engagement must be creatable from nothing
but a name, and optionally bound to a tenant/site later.

**`audit_engagement_items`** — per-item outcome.
`engagement_id`, `item_ref`, `status`, `severity`, `finding_text`,
`recommendation_text`, `assessed_by`, `assessed_ts`, `ai_assisted` (bool).

**`audit_evidence`** — attachments and references.
`engagement_id`, `item_ref`, `kind` (`file` | `config_ref` | `note` |
`scan_finding`), `payload` (JSON), `filename`, `path`, `uploaded_ts`,
`confidential` (bool, default true).

Item 1.1 states the previous audit report is confidential and its folder must be
protected. Evidence therefore defaults to confidential, is stored outside the
web root, and is served only through an authenticated, group-scoped route —
consistent with the existing `assert_device_allowed` scoping.

**`audit_engagement_history`** — append-only status changes for auditability.

### Status vocabulary

The source items are a mix of yes/no questions ("Esiste una procedura…?"),
verification actions ("verificare l'adeguatezza…"), and prescriptions ("Le
policy verso internet devono bloccare…"). One vocabulary covers all three:

`non_valutato` · `conforme` · `parziale` · `non_conforme` ·
`non_applicabile` · `da_verificare`

`da_verificare` is distinct from `non_valutato`: the engineer looked, could not
determine the answer, and needs information from the customer. That distinction
drives the follow-up list in the report.

Severity per finding: `critica` · `alta` · `media` · `bassa` ·
`osservazione`.

### Prerequisites and the completeness caveat

Several items are gates rather than findings. Item 1.3 says plainly that without
the logical and physical network diagrams the audit result is *"parziale e
superficiale, e va fatto notare nella relazione"*.

Items flagged `is_prerequisite` that end `non_conforme` or `da_verificare`
inject a prominent caveat block at the head of the generated relazione, stating
which prerequisites were unmet and that the audit's depth is limited
accordingly. This is a product feature, not a footnote: it protects the engineer
professionally and sets accurate expectations with the customer.

Prerequisite items: 1.3 (network diagrams), 1.6 (log access), 1.7 (config backup
access).

## Item classification

`auto` = derivable from a config file. `semi` = needs a live device, an external
feed, or config plus judgement. `manual` = interview, on-site, or process.

### 1 — Pre-audit, information gathering (all `manual`)

| Ref | Item | Kind |
|---|---|---|
| 1.1 | Obtain and read previous audit reports (confidential handling) | manual |
| 1.2 | Obtain corporate network security procedures | manual |
| 1.3 | Obtain logical and physical network diagrams — **prerequisite** | manual |
| 1.4 | Identify ISP connectivity and configured VPNs | semi |
| 1.5 | Vendor info: firmware version, known vulns, contracts, EOL date | semi |
| 1.6 | Verify access to logs — **prerequisite** | manual |
| 1.7 | Verify config backup access, currency, consistency — **prerequisite** | manual |
| 1.8 | Date and outcome of last DR / business continuity test | manual |

1.8 carries a strong note: the real test is powering off all primary equipment
and confirming the business still operates. Given the firewall's criticality the
framing is business continuity, not disaster recovery. Worth surfacing verbatim.

### 2 — Physical and OS security (all `manual`; on-site or interview)

Section preamble requires recording the modality and the interviewee — captured
on the engagement, not per item.

| Ref | Item | Thresholds to encode |
|---|---|---|
| 2.1 | Adequacy and security of the rooms housing the firewalls | 18–25 °C, redundant cooling, fire suppression, environmental monitoring, security camera, no drain pipes above the rack |
| 2.2 | Procedure restricting firewall access to authorised personnel | access must hold during support SLA hours |
| 2.3 | Hardware adequacy | HA pair, cat6 patch cords, physical replaceability — a cascade of cables resting on the units makes timely replacement impossible |
| 2.4 | Power adequacy | two redundant UPS lines, everything in-rack with no trailing sockets, monitored batteries, replaced per vendor schedule — **note ambient temperature can halve rated battery life** |
| 2.5 | OS hardening (CompTIA Security+ SY0-401: 3.6) | — |

### 3 — Administrator and log access (`semi` — config plus confirmation)

| Ref | Item | Kind | Automatable part |
|---|---|---|---|
| 3.1 | Identify admin users and permitted source networks | semi | `config system admin` accounts + `trusthost*` |
| 3.2 | Review admin profiles/policies bound to users | semi | `config system accprofile` bindings |
| 3.3 | Remove generic admin users, or restrict to DR use | semi | detect a generic `admin` account |
| 3.4 | Identify who can read browsing logs beyond 7 days retention | manual | — |
| 3.5 | Verify the log archive is encrypted and protected | semi | logs must not traverse the internet or shared networks in clear; FortiAnalyzer commands |

3.1's rule: all admin users must be confirmed by the customer and must be
nominal, with the exception of `admin`, usable only by the IT manager or a DR
procedure.

### 4 — Firewall management processes (all `manual`)

4.1 change authorisation chain · 4.2 sample-check that prior changes were
approved, where corporate policy requires it · 4.3 verify restricted
administrative users and their assigned profiles.

### 5 — Firewall operating system (mostly `semi`, needs a live device)

| Ref | Item | Kind | Thresholds |
|---|---|---|---|
| 5.1 | System date/time correct, pointing at trusted NTP | semi | — |
| 5.2 | Firmware up to date | semi | cross-check known vulns for the running version |
| 5.3 | Documented vendor vulnerabilities or significant bugs | manual | attach vendor advisories to the report |
| 5.4 | Licences active **and the licensed features actually usable** | semi | — |
| 5.5 | CPU, RAM and main interface utilisation during production hours | semi | **RAM > 70% critical, CPU > 55% critical** — headroom must absorb extraordinary events such as DDoS |
| 5.6 | System event log review for non-obvious problems | semi | at least the last week |
| 5.7 | Config backup procedure and consistency check | manual | marked *"ripetuto"* in the source — duplicates 1.7, see Data quality below |

### 6 — Base configuration audit (largely `auto` — the automatable core)

| Ref | Item | Kind |
|---|---|---|
| 6.1 | Understand the config and evaluate its role in the topology (perimeter vs ISFW, segmentation adequacy) | semi |
| 6.2 | A single point exists to isolate the network from the internet | semi |
| 6.3 | Policies that could be tightened — source and destination must always be specified except toward the internet; **cite the policy ID in the report** | auto |
| 6.4 | Exposed server services use encrypted protocols; only necessary services exposed; unknown protocols flagged via IPS | auto |
| 6.5 | Unused VPNs, shaping rules or policies — disable first, delete later | auto |
| 6.6 | Policy ordering (higher-traffic first) — less important on modern firewalls at low/medium traffic | auto |
| 6.7 | Internet policies block dangerous technologies — ActiveX, Java applets, WebFilter and Application Control configured, **botnet blocking**; server traffic inspected at the highest levels; note most traffic including malicious is HTTPS, so egress protocol selection is not critical; consider MDM | auto |
| 6.8 | DDoS filter enabled (alarm only) — only after per-service traffic study, and where exposed services warrant it | auto |
| 6.9 | Policies exposing servers have correctly configured IPS | auto — **quarantine ≥ 60 days for IPs triggering critical-category signatures** |
| 6.10 | Public IP scans blocked by IPS — *"not important in most cases"* | auto |
| 6.11 | Only authorised internal servers may issue DNS/NTP; block public DNS/NTP; consider SNMP too | auto |
| 6.12 | Where possible block encrypted files toward file servers | auto |
| 6.13 | Server access policies restricted to services clients actually need; full server access only for IT; **no wildcard user-to-server policies** | auto |
| 6.14 | Access policies based on user groups and job function | semi |
| 6.15 | Client VPN access mirrors internal policies, with adequate authentication and **two-factor** | auto |
| 6.16 | Supplier VPN access enabled only during SLA windows and limited to authorised networks | semi |
| 6.17 | Administrative network access from a dedicated VLAN that reaches everything but is reached by nothing — applies to admin client VPNs too | semi |
| 6.18a | Time-based policies for networks that must not operate outside working hours | auto |
| 6.18b | L2L VPN control | auto |
| 6.19 | Access outside the customer's control — VPNs or Remote Desktop traversing the firewall | semi |

Two items deserve emphasis in the guidance text:

**6.14** carries the sharpest reasoning in the document. Group- and
role-based policies statistically and substantially reduce the chance of server
compromise. If policies are built around *trust in the individual* rather than
*job function*, that is itself a security problem: the customer is using the
firewall as an employee-monitoring system rather than a security control, and
per-person policies become unreadable and unmanageable within a short time,
opening breaches exploitable for data breach.

**6.18a** carries a legal caveat: permitting services such as Facebook only
during the lunch break runs against Italian law on remote monitoring of
employees (*telecontrollo dei dipendenti*). This must be surfaced prominently in
the UI, not buried — it is a legal exposure, not a technical preference.

**6.18b** thresholds: L2L VPNs must be functional or else deconfigured and
cleaned up; authentication and encryption at least **AES256-SHA256, DH groups 5
and 14**; the PSK must always be distinct and must not live in the
documentation, except for VPNs sharing the same purpose and access. The note
"le policy di una VPN L2L non sono mai scontate" should appear verbatim.

### 7 — Firewall monitoring (`semi`)

7.1 monitoring that redundant functions are working and not merely active — HA
state, core switches, LACP, power, SD-WAN · 7.2 frequency of statistical log
review; a SOC or log-analysis service is an acceptable equivalent; direct review
with adequate tooling beats reports · 7.3 analyse traffic caught by DENY
policies — reveals misconfiguration, unnecessary services on servers, and
compromises that EDR missed · 7.4 session criticality weighting parameters ·
7.5 superficial analysis of traffic crossing the firewall.

7.3 connects directly to the existing Flow SIEM tab, which already renders DENY
events with an explanation badge. The engagement item links there rather than
duplicating the view.

### 8 — Procedures (all `manual`)

8.1 incident handling and remediation · 8.2 DR procedure, date and outcome of
last test or test report · 8.3 data breach procedure (GDPR) · 8.4 firewall
change procedure and notification to the network security officer (marked
*"Forse duplicato"* in the source — overlaps 4.1).

### 9 — Privacy / GDPR (`semi`)

| Ref | Item | Detail |
|---|---|---|
| 9.1 | Do not log access to privacy-sensitive sites | web filter categories **Medicina, Assistenza Sanitaria, Religione, Politica** — low security interest, high privacy impact; extendable to other recognised categories |
| 9.2 | Networks for private use (personal smartphones) | block illegal categories without enabling logs; treat as critical; must not reach the corporate logical network; rate-limit via traffic shaping |
| 9.3 | Guest networks isolated | — |
| 9.4 | Log only what is needed | porn is not a security problem but frames and ads are unwelcome in the workplace, hence blocked without logging; same for dating, gambling, etc. |
| 9.5 | Log retention respects GDPR | flag in the report if retention exceeds one week, and list any other configured syslog servers |

## Data quality issues in the source document

To resolve at seeding time rather than silently:

- **`6.18` appears twice** — time-based policies, and L2L VPN control. Seeded as
  `6.18` and `6.19`, shifting the original `6.19` to `6.20`. The original
  numbering is preserved in a `source_ref` field so the printed relazione can
  cite either.
- **`5.7` is annotated "ripetuto"** — duplicates `1.7`. Kept as a cross-reference
  to 1.7 rather than a second independent item.
- **`8.4` is annotated "Forse duplicato"** — overlaps `4.1`. Kept, cross-linked.
- **`2.1`** contains "umidità non ricordo" — the humidity range is missing from
  the source. **Resolved: humidity is dropped from the item entirely** (owner's
  decision, 2026-07-26). Item 2.1 keeps its other thresholds. Do not reintroduce
  a humidity figure without a sourced value.

## Tab structure

Navigation: a new `navAuditChecklist` entry, admin-gated and preview-gated
following the existing `applyNetSecAuditGating` pattern (settings toggle,
`display:none` by default).

Four views:

1. **Engagements list** — customers, status, progress, last modified, previous
   audits for the same customer (serving item 1.1 directly).
2. **Engagement workspace** — the main working view. Left: section/item tree
   with per-item status colouring and progress per section. Right: the selected
   item, showing title, why it matters, what good looks like, how to check,
   thresholds, status selector, finding text, recommendation, evidence
   attachments, and the AI assist actions.
3. **Report preview** — the generated relazione, including the prerequisite
   caveat block.
4. **Template admin** (admin only) — version list, item editor, clone-to-draft,
   publish, JSON import/export.

Progress is per section and overall, counting `non_valutato` as outstanding.

## AI assist

Uses the existing multi-provider assistant in `ai/ai_assistant.py` (Anthropic /
OpenAI / Gemini / Ollama), with `build_tenant_context` supplying customer
context where a tenant is bound.

Two per-item actions:

- **"Cosa devo verificare qui?"** — expands the item's guidance against this
  customer's actual context. This is the junior-engineer support the owner asked
  for.
- **"Redigi il testo per la relazione"** — drafts finding and recommendation
  prose from the engineer's rough notes.

**Cost control is a hard requirement.** The owner pays their own API credits.
Therefore: AI calls are never automatic, never triggered by navigation or page
load, and never batched across items. Each call is an explicit click, the button
carries a visible indication that it consumes credits, and the result is stored
on the item with `ai_assisted = true` so drafted text is distinguishable from
text the engineer wrote. Local Ollama, being free, is offered as the default
provider where configured.

## Connection to the NetSec Audit benchmark scan

The owner described this tab as "connected to the audit tab", but did **not**
select automatic pre-filling of findings. So the link is deliberately shallow in
this design:

An engagement may attach a benchmark scan result. Where a scan finding maps to a
checklist item (for example the CIS management-protocols rule → item 3.2, or the
any-to-any policy rule → item 6.3), the finding appears in that item's evidence
panel as a **suggestion the engineer explicitly accepts or dismisses**. It never
sets the item status on its own.

The mapping lives in the template item (`automation_hint`), so it is
admin-editable like everything else. Full auto-fill is a documented extension
point, not built now.

## Report generation

The relazione, exported as HTML consistent with the benchmark report export:

1. Header — customer, scope, dates, engineer, modality (on-site/remote) and
   interviewee.
2. **Prerequisite caveat block**, when any prerequisite is unmet.
3. Executive summary — counts by status and severity.
4. Findings by section — item, status, severity, finding, recommendation,
   evidence references.
5. Open points — every `da_verificare` item, as the customer follow-up list.
6. Annexes — vendor advisories (item 5.3), attached evidence.
7. Confidentiality notice, per item 1.1.

## Out of scope

- Full automatic pre-filling of item statuses from config (extension point,
  designed for, not built).
- Live device polling for section 5 (CPU/RAM/firmware/licences). The existing
  `fortigate_service` could supply these later; this round records them
  manually.
- Multi-language report output. The checklist and report are Italian, matching
  the source document and the existing UI.
- Scheduled or recurring audits.
- PDF export. HTML only, matching the existing export approach.

## Build order

1. Schema, template versioning, and the seeder from `checklist_x_c.docx`.
2. Engagements CRUD and the item workspace with manual status and notes.
3. Report generation with the prerequisite caveat.
4. Template admin editor with versioning.
5. AI assist actions.
6. Benchmark scan evidence suggestions.

## Verification

Per `CLAUDE.md`: `pyrefly check` and the full `unittest` suite before each
commit; `graphify update .` before merging to preview.

Tests target the parts that are testable without a browser: template version
pinning (a published template cannot be mutated; an engagement keeps its
version), the seeder (item count, refs, threshold parsing, the 6.18 duplicate
resolution), status/progress aggregation, prerequisite caveat triggering, and
report assembly.
