# Network status report for auditors (2026-11-13)

## Intent

A tenant's IT owner or its MSP must be able to hand an auditor one document that
says, with evidence, how the network side meets NIS2 and the usual control
frameworks (ISO/IEC 27001:2022 Annex A, CIS Controls v8, IEC 62443 for OT).
It is the "rete sotto controllo" job from the business model canvas, and it uses
only data SentinelNet already collects.

## Goals

- **A (this work):** an on-demand snapshot for one tenant, downloadable as Word
  (.docx) plus the raw JSON snapshot as a technical attachment.
- Built so that **B** (periodic MSP report with month-over-month comparison)
  needs only: store snapshots, schedule them, diff two JSON documents. No
  rewrite of collection or rendering.

## Non-goals

- No compliance verdict. The report shows **evidence**, never "compliant with
  NIS2". The document says so on the first page.
- No organisational controls (risk analysis, training, supply chain, HR,
  effectiveness assessment): SentinelNet cannot observe them. They are listed in
  an explicit "outside the technical scope" section, not hidden.
- No admin-editable mapping (decided: the mapping is product, maintained in the
  repo, shipped with releases).
- No snapshot storage, scheduling or diff yet (that is B).
- No new data collection. If an evidence source does not exist today, it is
  reported as "not available", not built.

## Anti-goals

- A report that differs between installations for the same data.
- Quoting ISO/IEC text (copyrighted). Cite the control number and a title
  written by us.
- Leaking another tenant's data into a report (tenant scope is the security
  boundary here).

## Approaches considered

1. **Snapshot JSON, then render (chosen).** Each evidence source is a small
   Python function `collect(tenant) -> dict`; a static mapping file links each
   evidence to controls and thresholds; the result is one timestamped JSON
   snapshot; the .docx is rendered only from that snapshot. Cost: one extra
   layer (the snapshot schema), designed once. B becomes storage + schedule +
   diff.
2. Query directly inside the document template. Shortest code, but there is
   nothing to store or compare, so B would be a rewrite.
3. A "NIS2 technical" template inside the Audit Checklist, prefilled by
   evidence. That is option C (manual engagement) brought forward: heavier than
   A needs. Possible later on top of approach 1.

Format: **.docx** via `python-docx` (already used by
`services/netsec_audit/docx_export.py`): auditors annotate and attach it; PDF is
"save as" from Word.

## Design

### Three parts, only the first is code

1. **Evidence collectors** (Python, e.g. `services/status_report/evidence.py`).
   One function per source; each returns
   `{"metrics": {...}, "rows": [...], "collected_at": ..., "available": bool}`.
   They read existing services, never raw files when a service exists.
2. **Mapping** (`services/status_report/mapping.yaml`, tracked, not under
   `data/`). Per evidence: the controls it supports per framework, a title in IT
   and EN written by us, and the thresholds that turn metrics into a status.
   A test checks the file loads, every evidence id has a collector and every
   collector has an entry.
3. **Renderer** (`.docx`) that reads only the snapshot.

Status per evidence: `ok` · `gap` · `partial` · `not_available`. Computed from
the mapping's thresholds, inside the snapshot (so B diffs statuses, not just
numbers).

### Evidence v1 and initial mapping

Control references to verify against the official texts (EUR-Lex for NIS2
Directive (EU) 2022/2555 art. 21(2) and Implementing Regulation (EU) 2024/2690
annex; the 2024/2690 annex applies to MSPs/MSSPs, our early-adopter segment).
ISO numbers are 27001:2022 Annex A.

| Evidence | Source in the app | NIS2 21(2) | 2024/2690 | ISO 27001 | CIS v8 | Default threshold |
|---|---|---|---|---|---|---|
| `asset_inventory`: devices, vendor, model/firmware known, last seen | inventory | (i) | 12.4 | A.5.9 | 1 | gap if firmware unknown on >10% |
| `vulnerabilities`: open critical/high CVEs on real firmware, data age, devices not evaluated | `services/cve_intel.summary()` | (e) | 6.10, 6.6 | A.8.8 | 7 | gap if critical open, partial if data older than CVE max age |
| `config_backup`: age of last backup per device, versions kept | `services/config_drift/history.py` | (c) | 4.2 | A.8.13 | 11 | gap if any device >7 days |
| `config_drift`: deviations from tenant baseline, changes in period | `services/config_drift/baseline.py` + history | (e) | 6.3, 6.4 | A.8.9, A.8.32 | 4 | partial if deviations |
| `hardening`: latest NetSec Audit / CIS benchmark result per device | `services/netsec_audit/history.py` | (e), (h) | 6.3, 6.7 | A.8.9, A.8.20 | 4, 12 | not_available if never run |
| `segmentation`: IT/OT zones and bypass findings | network zones (segments) | (e) | 6.8 | A.8.22 | 12 | gap on bypass; IEC 62443-3-3 zones/conduits |
| `logging`: devices sending syslog in the period vs inventory, retention days | `syslog_events`, data_config retention | (b) | 3.2 | A.8.15, A.8.16 | 8 | partial if <80% devices log |
| `platform_access`: users, roles, admins, audit-log chain integrity | user_manager, `security_manager.verify_audit_chain()` | (i), (j) | 11 | A.5.15, A.8.2, A.8.5, A.8.15 | 5, 6 | gap if chain broken |

Thresholds above are starting values; they live in the mapping file, not in
code.

### Outside the technical scope (always printed)

NIS2 21(2)(a) risk-analysis policies, (d) supply chain, (f) effectiveness
assessment, (g) cyber hygiene and training, HR security, and the policy side of
(h) cryptography and (j) MFA. MFA on SentinelNet's own login does not exist:
say so, do not omit it.

### Snapshot schema (the contract B builds on)

```json
{
  "schema_version": 1,
  "mapping_version": "2026-11-13",
  "app_version": "0.65.0",
  "generated_at": "2026-11-13T10:00:00Z",
  "generated_by": "<username>",
  "tenant": "<tenant>",
  "period_days": 30,
  "evidence": {
    "config_backup": {"status": "gap", "available": true,
                      "metrics": {"devices": 42, "older_than_days": 3},
                      "rows": [{"device": "switch-01", "last_backup": "..."}],
                      "collected_at": "..."}
  }
}
```

`schema_version` bumps on incompatible change; B refuses to diff across
versions.

### Document layout

1. Cover: tenant, date, period, app version, disclaimer (evidence, not
   certification).
2. Summary table: one row per evidence, status, controls covered.
3. Per-framework view: NIS2 21(2) letters, then ISO Annex A, CIS, IEC 62443;
   each control lists its evidence and status.
4. Evidence detail: metrics and rows (cap the rows, note the cap).
5. Outside the technical scope.
6. Method: data sources, collection time, thresholds used.

IT and EN, following the UI language.

### API, permissions, UI

- `GET /api/reports/network-status?tenant=<t>&format=docx|json`.
- One tenant per report. Tenant must be inside `user_group_scope`; refuse
  "all". Uses the global tenant selector (top-left) like every other view.
- Permission: `require_tab("tab-netsec-audit")` (our call: the report lives
  next to the existing audits).
- Audit log entry on each generation.
- UI: one button in the NetSec Audit tab, following the frontend rules in
  AGENTS.md (no inline handlers, `tr()` keys in both languages, accessible
  name, lazy-tab entry if needed).

## Left to the builder

File names, collector internals, row caps, docx styling (reuse the NetSec docx
helpers), exact i18n keys. Verify the 2024/2690 section numbers on EUR-Lex
before writing them into the mapping. Use only example data in tests and docs
(RFC 5737 addresses, `switch-01`).
