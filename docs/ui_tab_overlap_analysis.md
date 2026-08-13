# UI Tab & Feature Overlap Analysis

> **Status**: analysis only — no code changed. Re-verified on 2026-08-11 against
> `HEAD = e14c0c1` (`templates/dashboard.html`, `static/js/*.js`, `static/js/i18n.js`).
> Companion document: `docs/netsec_troubleshooting_qa_v3.md`.
>
> Re-verification result: counts and merge candidates hold (28 `tab-content`, 21 nav items,
> 13 `.subtab-bar` copies, 11 tenant selectors, `resetTopology()` twice, `client-map.js`
> serving both MAC Tracker and Client Map). Three claims were corrected — see B4
> (no drift), the target-IA arithmetic, and the FortiGate pill count.
>
> **A3 has since been implemented** (2026-08-11): the tree is now at 27 `tab-content`
> surfaces, 11 `.subtab-bar` copies and 10 tenant selectors. The counts above are the
> pre-merge baseline the rest of this analysis is written against.

Goal: identify repetitive tabs, low-value standalone surfaces, and features
implemented more than once in different tabs that could live in a single tab.

---

## Current information architecture

5 nav groups, 21 nav items, **28 `tab-content` surfaces**
(subtabs are full `tab-content` divs with a duplicated subtab bar).

| Group | Nav item | Tab surfaces inside |
| :--- | :--- | :--- |
| **Indaga** | Home | `#tab-home` |
| | Incidenti (preview) | `#tab-incidents` |
| | Traffico | `#tab-flows` — **merged 2026-08-11**: 4 pills `#trafPill-*` over panes `#trafPane-*` (Panoramica / Flussi / Ricerca / Anomalie), one header for window+tenant |
| | Localizzazione Endpoint | `#tab-endpoint` — **merged 2026-08-12**: 4 pills `#locPill-*` over panes `#locPane-*` (MAC Tracker / Client Map / Diagnosi Client / Endpoint Inventory), one header and tenant selector |
| | AI Assistant | `#tab-ai` |
| **Inventario** | Network Inventory | `#tab-devices` |
| | Topologia | `#tab-map` (Port-Channel report), `#tab-map-interactive` (2D map) |
| | Dispositivi & Categorie | `#tab-categories` |
| | Fortigate Management (admin) | `#tab-fortigate` (7 panes `#fgtPane-*` switched by the `#fgtSub-*` button bar, 25 pills `#fgtPill-*`) |
| | Cisco WLC | `#tab-wlc` |
| **Valuta** | Threat Intel (EUVD) | `#tab-security` (Matcher / Vendor Watch views) |
| | Config Analyzer | `#tab-config` (9 pills) |
| | NetSec Audit (preview, admin) | `#tab-netsec-audit` |
| | Checklist Audit Firewall (admin) | `#tab-audit-checklist` |
| **Modifica** | Provisioning (write) | `#tab-provisioning` (Provisioning Apparato), `#tab-provisioner` (Apparato da Zero) |
| | Importazione CSV (write) | `#tab-import` |
| **Amministra** | Utenti (admin) | `#tab-users` |
| | Gestione Tenant (admin) | `#tab-groups` |
| | Sedi (admin, preview) | `#tab-sites` |
| | Integrazioni (admin) | `#tab-mcp`, `#tab-mcp-client` |
| | Impostazioni (admin) | `#tab-settings` |

---

## A. High priority — merge into one tab

### A1. Localizzazione Endpoint: 4 subtabs → 1 tab with pills — **DONE** (2026-08-12, `c3eb863`..`a76d817`)

The four subtabs are four views over the same endpoint telemetry:

| Subtab | Data source | Content |
| :--- | :--- | :--- |
| `#tab-mac` | `/api/mac/scan`, `/api/mac/search`, `/api/mac/stats`, `/api/mac/overrides` | L2: MAC → switch/port/VLAN |
| `#tab-clientmap` | `/api/arp/scan`, `/api/arp/client-map` + the **same** `/api/mac/*` calls | L3: MAC ↔ IP, cross-referenced with tracker ports |
| `#tab-diagnosi` | `/api/diagnose/client`, `/api/diagnose/gateway-candidates`, `/api/diagnose/traceroute-gateway`, `/api/diagnose/port-bounce` | correlation view over both L2+L3 |
| `#tab-endpoints` | `/api/endpoints/list`, `/api/endpoints/ports` | persisted ARP bindings (history/staleness) |

Evidence of redundancy:

- **One module already serves two tabs**: `runMacScan()`, `macSearch()`,
  `runArpScan()`, `arpClientSearch()` all live in `static/js/client-map.js`
  (lines ~190–480). The MAC Tracker and Client Map tabs are two skins of the
  same module with identical device multi-select controls
  (`#macDeviceMenu`/`#arpDeviceMenu`) and identical tenant selects
  (`#macScanGroup`/`#arpScanGroup`).
- **The workflow forces tab-hopping**: the corrected Q&A guide (Q2.1) requires
  MAC Tracker → Client Map to go from MAC → port → IP for the *same* endpoint.
- **Endpoint Inventory is the persisted form of Client Map data** (same ARP
  bindings, plus a staleness filter and CSV/JSON export).
- **KPI duplication**: `#kpiMacUniqueMacs` ("MAC Univoci") and
  `#kpiArpUniqueMacs` ("MAC Univoci") show the same metric name from two
  collections, side by side in the same nav group.

Recommendation: one **Endpoint** tab with pills
`Ricerca` (unified MAC/IP search returning port + binding in one row),
`Raccolta` (MAC scan + ARP collection side by side), `Diagnosi`, `Inventario`.

Shipped as: one `#tab-endpoint` tab, four pills `#locPill-*` over panes
`#locPane-*` (`mac` / `clientmap` / `diagnosi` / `inventory`), one shared
header and tenant selector. Two pieces of the recommendation above stayed out
of scope, deliberately:

- **The Ricerca/Raccolta re-cut.** The merge kept the four original views as
  panes instead of re-cutting them into a unified `Ricerca` (search) and
  `Raccolta` (collection) pair. A row with only a MAC-side binding or only an
  ARP-side binding isn't an edge case to special-case in a unified search —
  it's most endpoints, since the two scans target different device
  populations (MAC on access switches, ARP on L3 gateways). Unifying the
  scans themselves would mean scanning devices the other scan was never
  aimed at.
- **§A2's three diagnosis surfaces.** Only the cross-vendor `#tab-diagnosi`
  pane (now `#locPane-diagnosi`) is inside this group. The FortiGate pill and
  the WLC row button stay where they are — collapsing them reaches into two
  tabs outside the endpoint group, which is a separate change.

### A2. Client diagnosis is implemented three times

| Location | Control | Route |
| :--- | :--- | :--- |
| Fortigate Management → Traffico pane | pill `#fgtPill-clientDiagnosis` (`fgtDiagClient/Dst/Port/Proto` fields) | `POST /api/fortigate/{ip}/diagnose-client` |
| Cisco WLC tab | **Diagnostica** button per client row → `#wlcDiagModal` | `GET /api/wlc/{ip}/diagnose-client/{mac}` |
| Localizzazione Endpoint → Diagnosi Client | `#tab-diagnosi` form | `POST /api/diagnose/client` (cross-vendor) — and it *also* calls `GET /api/wlc/{ip}/diagnose-client/{mac}` internally (`diagnosi.js` L479) |

Three UIs, same operator intent ("why can't this client reach X?").
The cross-vendor `#tab-diagnosi` is the superset (it delegates to WLC
diagnosis and adds traceroute/port-bounce).

Recommendation: keep the cross-vendor diagnosis as the **single** entry point
(pill inside the unified Endpoint tab, per A1). Keep the FortiGate pill and
the WLC row button only as *contextual shortcuts* that prefill the same
diagnosis surface — or drop them. Today an operator gets three different
result formats for the same question.

### A3. Traffico: 2 subtabs → 1 tab with pills — **DONE** (2026-08-11, `942632b`..`f1f40ca`)

`#tab-flows` (Flussi Live) and `#tab-flow-siem` (Flow SIEM) consume the same
observability pipeline and duplicate both controls and output:

| Duplicated element | `#tab-flows` | `#tab-flow-siem` |
| :--- | :--- | :--- |
| Time window select | `#flowsWindow` (15m/1h/24h/7d) | `#flowSiemWindow` (same 4 options) |
| Tenant filter | `#flowsTenantBtn` dropdown | `#flowSiemTenant` select |
| Per-flow records table | `#flowsTableBody` | `#flowSiemTableBody` |
| Protocol distribution | donut/bar/trend `#obsProtocolCanvas` | event-rate histogram `#flowSiemHistCanvas` |

The Flow SIEM additions (free-text/field:value query, facets, live tail,
threat flag column) are a *query mode* over the same events, not a separate
domain. The corrected Q&A (Q4.1) keeps both open in parallel.

Recommendation: one **Traffico** tab with pills
`Panoramica` (KPI strip, top talkers, protocol split),
`Flussi` (detail table), `Ricerca SIEM` (query + facets + histogram + live
tail), `Anomalie` (the `#anomTableBody` panel currently at the bottom of
`#tab-flows`).

### A4. Valuta: Config Analyzer + NetSec Audit → 1 config-audit tab

Both analyze the **same input** (stored device backup, or pasted config text)
of the **same devices**, from two angles:

- `#tab-config` (Config Analyzer): structural parsing — VLAN, routing, ACL,
  interfaces, firewall objects/policies, validation, FortiOS↔PAN-OS converter.
- `#tab-netsec-audit` (NetSec Audit): compliance scoring of the same config —
  CIS / NIST SP 800-53 / PCI-DSS, score, severity matrix, report export.

Q6.1 of the corrected Q&A explicitly ping-pongs between the two tabs for one
audit. NetSec Audit already accepts file upload + config text; Config Analyzer
reads stored backups — a merged tab would let one "scan" action feed both the
compliance matrix and the structural pills.

Recommendation: one **Config Audit** tab: `Compliance` pill (current NetSec
Audit) + the existing Config Analyzer pills. Checklist Audit stays separate
(it is an engagement/workflow tool, not config parsing) — see C3 for naming.

### A5. Topologia: Port-Channel report subtab → panel inside the 2D map

`#tab-map` is a text report of Port-Channels/interfaces per switch.
`#tab-map-interactive` already has an **Evidenzia Port-Channel** toggle
(`#togglePortChannel`) and hover tooltips with member ports, so the report
duplicates what the map renders. The `Reset Topologia` button
(`resetTopology()`) appears **verbatim in both subtabs**.

Recommendation: merge into one map tab; expose the Port-Channel report as a
drawer/panel of the interactive map.

---

## B. Medium priority — cross-tab duplication

### B1. Home attention queue vs Network Inventory table

`#tab-home` renders "Coda attenzione flotta" (hostname/IP/tenant/status
table) plus fleet KPIs; `#tab-devices` renders the full device table with the
same columns plus online/offline/auth-failed KPIs. Same data, two tables.

Recommendation: keep Home as a dashboard but make the attention queue a
deep link into Inventory with the status filter preset, instead of a second
device table.

### B2. Network Inventory vs Dispositivi & Categorie

Both list the same devices with the same per-tenant filter pattern and a CSV
export. `#tab-categories` adds category count cards, reclassification of
CDP/LLDP-discovered neighbors, and category creation.

Recommendation: categories as a pill/column-mode of Network Inventory (or at
minimum move category editing into the inventory row actions). The standalone
tab mostly duplicates the device list.

### B3. Ten independent tenant/site selectors

Every tab builds its own: `#filterGroupSelect`, `#topologyGroupSelect`,
`#interactiveGroupSelect`, `#categoriesGroupSelect`, `#threatGroupSelect`,
`#macScanGroup`, `#arpScanGroup`, `#arpTenantMenu`, `#trafTenantBtn`,
`#configGroupSelect` — ten since A3 merged `#flowsTenantBtn` and
`#flowSiemTenant` into one. No global tenant context; state is lost at every
tab switch.

Recommendation: a global tenant selector (sidebar or top bar) that prefills
each tab's filter. Removes ~10 controls and a class of "I filtered but
switched tab and lost the filter" confusion.

### B4. Subtab bar markup duplicated 13 times

The same `.subtab-bar` button row is copy-pasted in every subtab:
endpoint group ×4, flows group ×2, provisioning ×2, map ×2, mcp ×2, plus the
FortiGate pane bar — 13 `.subtab-bar` instances in `dashboard.html`.

*(Correction, 2026-08-11: an earlier version of this document claimed the four
endpoint copies had drifted. They have not — all four are byte-identical.
`loadClientMapTab()` / `loadEndpointsTab()` fire on the Client Map and Endpoint
buttons in every copy; the MAC Tracker and Diagnosi buttons carry no loader in
any copy, by design. The cost here is maintenance surface, not a live bug.)*

Recommendation: render the subtab bar once (single container or template
fragment); consolidate per A1–A5 first, which deletes most copies anyway.

### B5. Two alert queues with the same status model

- Anomalies panel in `#tab-flows` (`#anomTableBody`, status Nuove/Prese in
  carico/Risolte, `#anomStatus`).
- Incident queue in `#tab-incidents` (status new/ack/resolved,
  `#incStatusFilter`).

- And a **third** surface on Home: `#homeAnomBody`, an anomaly list next to the
  fleet attention queue.

Incidents are correlations of anomalies/events; operators see two or three
"inboxes" for one alert stream. Today nothing links an anomaly row to the
incident it was folded into.

Recommendation: not necessarily a merge (different granularity), but add a
deep link anomaly → incident, and consider an "Incidenti" pill inside the
unified Traffico tab.

---

## C. Low priority — naming & minor overlaps

### C1. Provisioning group: two near-identical names, different jobs

- `#tab-provisioning` = **device onboarding CRUD** (add/edit device, tenant,
  transports, credentials, identities). Comment in the HTML even says
  "estratto da Network Inventory".
- `#tab-provisioner` = **day-0 config generation** (Cisco/FortiGate bootstrap).

Both sit behind one nav item labeled "Provisioning"; subtab labels
("Provisioning" / "Apparato da Zero") don't convey the difference. Also:
`#tab-provisioning` embeds **inline tenant creation**
(`#btnInlineNewTenant`/`#inlineNewTenantRow`), duplicating Gestione Tenant
(`#tab-groups`), and the identities panel duplicates the credentials section
of the device form.

Recommendation: rename to "Onboarding Apparato" / "Config Day-0"; keep
tenant creation only in Gestione Tenant (link from onboarding).

### C2. Three AI entry points

`#tab-ai` (assistant), **Analizza con AI** button in `#tab-flows`
(`analyzeFlowsWithAi()`), and the incident AI narrative (`explainIncident`).
Acceptable, but all three should hand off to the same assistant surface with
injected context (flows already does this).

### C3. Three "audit" surfaces under Valuta

Config Analyzer + NetSec Audit + Checklist Audit Firewall are 3 of 4 items in
the Valuta group. Merging the first two (A4) leaves a clean pair:
**Config Audit** (automated) and **Checklist Audit** (manual engagements).

### C4. Name collisions

- `#fgtPill-deviceInventory` ("Inventario Dispositivi" inside FortiGate
  traffic pane = FortiGate-discovered devices) vs the top-level **Network
  Inventory** tab — different data, colliding name.
- "Diagnosi Client" appears as a FortiGate pill, a WLC button, and a subtab
  (see A2).

### C5. Not duplication (do not merge)

- **Cisco WLC tab vs FortiGate WiFi pane**: different vendors/APIs; rogue-AP
  work spans both, but unification would add abstraction with no data overlap.
- **Threat Intel (EUVD) vs triage/inventory firmware column**: matcher adds an
  external DB lookup; keep.
- **Sedi vs Topologia**: sites = agent/VPN management, map = LLDP/CDP graph.

---

## Target IA (after consolidation)

| Before | After |
| :--- | :--- |
| 28 `tab-content` surfaces | **21** (the five merges below remove 7; A3 already removed 1, so the tree is at 27) |
| 21 nav items | **20** (Dispositivi & Categorie folded into Network Inventory) |
| 13 duplicated subtab bars | **~6** |
| Client diagnosis ×3 UIs | 1 cross-vendor surface (+ optional contextual prefills) |
| Tenant selectors ×11 | 1 global selector |

Merge summary:

1. `tab-mac` + `tab-clientmap` + `tab-diagnosi` + `tab-endpoints` → 1 tab (A1, A2)
2. `tab-flows` + `tab-flow-siem` → 1 tab (A3)
3. `tab-config` + `tab-netsec-audit` → 1 tab (A4)
4. `tab-map` + `tab-map-interactive` → 1 tab (A5)
5. `tab-categories` → pill of `tab-devices` (B2)

All five merges preserve every existing route and control; they only relocate
surfaces. Suggested order: A1 (biggest workflow win, single module already
exists) → A3 → A4 → A5 → B2.
