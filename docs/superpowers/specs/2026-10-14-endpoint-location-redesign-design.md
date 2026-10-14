# Endpoint Location — tab redesign (2026-10-14)

Frontend redesign of the "Localizzazione Endpoint" tab (`#tab-endpoint`) and its
sub-views, with one small backend change (IP search). References from Mobbin:
Tailscale *Machines* (title + search + dense table), Twingate *Resources*
(underline sub-tabs, inline chip filters), Customer.io / Twenty (row → right
detail drawer), AWS RDS (summary + detail sections).

## Problem

The tab grew one sub-view at a time and it shows:

- **Inconsistency.** Each pane builds its own form, buttons, KPIs and tables
  (`.mac-row`, `.form-group` grid with inline styles, `.if-scope`, inline mode
  buttons). Four apps in one tab.
- **Navigation.** An old `hero` whose title changes per view, plus `ca-pill`s.
  Height spent, and the header does not tell where you are.
- **Density.** The MAC pane shows search, MAC scan, ARP collection, ad-hoc
  commands and retention at once; the daily job (find an endpoint) is lost.
- **Workflow.** The real question is "where is this endpoint?", but the user
  must know which sub-view answers it. Tracker MAC and Inventory overlap
  (sightings vs one row per MAC); Inventory "ports" mode and Port errors both
  look at a switch's ports. Locate is a modal, inventory detail is an inline
  expanded row: two detail UIs for the same entity.

## Decisions

| Question | Decision |
|---|---|
| Structure | One search on top + right-side detail drawer + underline sub-tabs. |
| Views | **Endpoint** \| **Porte** \| **Diagnosi** \| **Raccolta**. |
| Tracker MAC | Folded into Endpoint (its filters) and into the drawer (transit/path). No separate sightings view. |
| Inventory "ports" + Port errors | Merged into **Porte**: occupancy and errors in one table. |
| Endpoint detail | One drawer, replaces the `macLocate` modal and the inline expanded row. |
| Tenant | Unchanged: the global selector (`locTenant()`); no per-view tenant control. |
| Design language | Existing DESIGN.md ("Precision Telemetry"): square edges, Saira Condensed labels, Azeret Mono data, existing tokens. |
| Backend | Only change: `endpoint_inventory(q=…)` matches IPs. No new endpoint. |
| Hostname search | Out of scope: no hostname data in the endpoint rows. |
| Functionality | Nothing removed. Every action existing today has a place (table below). |

## Layout

```
Localizzazione endpoint                               [Raccogli ora]
Dove sono attaccati i dispositivi della rete, in base a MAC e ARP.
[ Cerca MAC, IP, vendor, switch o porta …                          ]

Endpoint   Porte   Diagnosi   Raccolta
────────
<view>                                              │ <drawer, when open>
```

### 1. Shell

- `page-head` (same component as `#tab-wlc`): fixed title, one-line
  description, action **Raccogli ora** (`requires-write`) that runs MAC scan and
  then ARP collection on the current tenant's devices, using the existing
  `runMacScan` / `runArpScan` with all devices selected.
- **Search** (`#locSearch`, `type="search"`, labelled). Enter:
  - calls `/api/endpoints/list?q=…` with the current tenant;
  - exactly one result → open the drawer for it (and show Endpoint view with
    the filter applied behind it);
  - more than one → switch to Endpoint view with `q` applied;
  - zero → inline "nessun endpoint" message under the search, no view change.
  `/` focuses the search while the tab is active.
- **Sub-tabs**: `role="tablist"` underline tabs replacing `#locPills` /
  `ca-pill`. Ids `locTab-endpoint|porte|diagnosi|raccolta`, panes
  `locPane-<view>`. Arrow-key navigation as in other tablists.
- Deep link: `#tab-endpoint/<view>` selects the view. The legacy aliases in
  `core.js` (`tab-mac`, `tab-clientmap`, `tab-diagnosi`, `tab-endpoints`) map
  to the matching view (`tab-mac`/`tab-endpoints`/`tab-clientmap` → endpoint,
  `tab-diagnosi` → diagnosi). Command palette entries "Run MAC scan" / "Run ARP
  collection" open **Raccolta**.
- `LOC_HEADINGS` and the title rewrite in `locSwitchView` go away.

### 2. View: Endpoint

- **KPI strip**, one row (`oneline-foot` pattern): endpoint, switch, VLAN,
  stale, nuovi, senza IP — from `counts` of `/api/endpoints/list`. Plain text;
  no click-to-filter (no such client-side filter exists today).
- **Toolbar** (one row, wraps on narrow screens): selects Switch, VLAN,
  Visto ultimi N giorni (`stale_days`), Periodo da/a (`frm`/`to`), Probe; reset;
  overflow menu "Esporta" with CSV and JSON (existing `endpointsExport`).
  The active `q` from the search shows as a removable chip.
- **Table**: MAC (+ vendor under it, muted), IP, Switch, Porta, VLAN, Ultimo
  avvistamento, flags (`_epFlag`). Sticky header, mono data font. Row is a
  focusable target (`tabindex=0`, Enter/Space) that opens the drawer; the
  selected row stays highlighted while the drawer is open.
- Truncation / outside-retention notices as today, in one notice line above the
  table.

### 3. Drawer: endpoint detail

A right-side panel inside the tab (not a modal backdrop), width ~420px,
full-height, list stays usable and scrollable beside it; below ~900px it
overlays the list. Generalise the topology `.drawer-*` classes
(`.drawer-header`, `.drawer-body`, `.drawer-section`, `.drawer-kpi-grid`) into
a shared `.side-drawer` container; topology keeps working on the same classes.

Opening: from an Endpoint row, from a Porte endpoint cell, or from the search.
Data: `/api/mac/locate?mac=&tenant=` (+ the row already in hand for IP/vendor).
Port errors section: `/api/interface-errors/port?…`, loaded lazily.

| Section | Content | Source |
|---|---|---|
| Header | MAC (mono, copy button), vendor, status badge (access / ambiguo / non trovato), tenant | locate + row |
| Posizione | switch name + IP, port, VLAN, origin type, device type | locate `origin*` |
| IP | ARP bindings with source gateway and last seen | row |
| Percorso | transit sightings / uplinks (what the modal shows today) | locate `transit` |
| Porta | errors in window with class badges, port config (collapsible, copy), "Leggi errori ora" | interface-errors + existing `_epLoadPortErrors` / port cfg |
| Storico | first seen, last seen, seen count | row |

Header actions: **Diagnosi** (switch to Diagnosi view, prefill client = MAC,
run — existing `endpointsDiagnose` / `diagnoseClientInTab`), **Config porta**
(existing `show-port-config` behaviour), close.

Accessibility: `role="dialog"` with `aria-labelledby` on the title, Esc closes,
focus moves into the drawer on open and back to the originating row on close.
Non-modal (no backdrop, no focus trap) on wide screens; on narrow screens it is
opened through `openModal`/`closeModal` so trap and backdrop apply. A test
asserts both paths close on Esc.

Deleted: the `macLocate` modal, `_renderEndpointDetailRow`,
`_toggleEndpointDetail`.

### 4. View: Porte

- **Toolbar**: Switch select ("Tutti gli apparati" shows only ports with
  problems, i.e. today's Port errors default; a specific switch shows all its
  ports), Finestra 1h/24h/7d, toggle "Solo problemi", Aggiorna, Leggi errori ora
  (`requires-write`, needs a switch).
- **Table**: Porta, Stato (uplink → neighbour / occupata / libera), Endpoint
  (one MAC → clickable, opens drawer; more → expandable list as `macCell`
  today), VLAN, Errori (count + class badges), Config (expandable, copy).
- Legend: `<details id="peLegend">` becomes a "?" button next to the Errori
  header opening a popover with the same `dl` content and i18n keys.
- Reuses `endpointsPorts` / `endpointsPortsRender` and the interface-errors
  fetch currently driving `#peResults`; the two renderers merge into one.

### 5. View: Diagnosi

- Form on one row: Client (IP/MAC), Destinazione, Protocollo, Porta, button
  Diagnosi. An "Avanzate" `<details>` holds Gateway select + manual input +
  Traceroute button.
- Results: existing `renderDiagnosi` cards, content unchanged; template inline
  styles replaced with classes. Bounce / isolate / restore, wifi diagnosis and
  tenant pick stay as they are. The "preview" badge stays.

### 6. View: Raccolta (operators; retention admin-only)

MAC stats line on top (sightings, unique MACs, switches, retention), then three
stacked blocks with the same markup pattern:

1. **Scansione MAC** — device picker (`mac-dev-menu`), transport, Avvia.
2. **ARP dai gateway L3** — device picker, Raccogli; `#arpScanSummary`
   renders inside this block.
3. **Comandi ad-hoc** — form + overrides list.

Footer: **Retention** (admin).

### Where every current control goes

| Today | New place |
|---|---|
| MAC search (mac/vlan/iface/switch) | Search + Endpoint toolbar |
| MAC results grouped by switch | Endpoint table (+ drawer Percorso) |
| `mac-locate` modal | Drawer |
| `show-port-config` | Drawer action; Porte config column |
| MAC scan, ARP collect, ad-hoc, retention | Raccolta (+ "Raccogli ora") |
| MAC KPIs | Raccolta stats line |
| Inventory list + KPIs + filters + export | Endpoint |
| Inventory row detail (diagnose, locate, portcfg, read errors) | Drawer |
| Inventory ports mode | Porte |
| Port errors pane + legend | Porte |
| Diagnosi | Diagnosi |

Open point for the plan: the MAC search's **interface** filter has no
equivalent in `/api/endpoints/list` except through `q` (which already matches
`interface LIKE`). Decision: the interface filter goes through the search, not
a separate select.

## Backend change

`collectors/mac_history.py::endpoint_inventory`: when `q` parses as an IP
address (`ipaddress.ip_address`), resolve it to MACs through `arp_entries`
(same tenant scope) and filter `mac IN (…)` instead of the `LIKE` clause. No
match → empty result. Partial IPs keep today's behaviour (no IP match).
The inventory cache key already includes `q`.

Test: an ARP binding `192.0.2.10 → aa:bb:cc:dd:ee:01` plus a sighting for
that MAC; `q="192.0.2.10"` returns exactly that endpoint; an unknown IP returns
zero.

## Code

- `templates/dashboard.html`: rewrite the `#tab-endpoint` markup only.
- `static/css/dashboard.css`: one endpoint-location block; generalise
  `.drawer-*` under `.side-drawer`. No inline styles in the new markup.
- `static/js/client-map.js`: shell (search, tabs, deep link, Raccogli ora) +
  Raccolta. MAC result rendering and locate modal removed.
- `static/js/endpoint-inventory.js`: Endpoint view, drawer, Porte view
  (absorbs the port-errors rendering).
- `static/js/diagnosi.js`: form markup changes only.
- `static/js/core.js`: legacy aliases → views; palette actions → Raccolta;
  `LAZY_TAB_SCRIPTS` unchanged unless a module moves.
- `static/js/i18n.js`: new keys in both languages; dead keys removed.
- `types/globals.d.ts`: any new `window.X`.

## Testing and gates

- New test: IP search (backend). Must stay green: `test_lazy_tab_scripts`,
  `test_ui_modal` (drawer narrow path), `test_a11y_dashboard`,
  `test_i18n_keys`. No router change, so no new TestClient smoke.
- Manual check in the browser at wide and narrow widths, light and dark, with
  real data, against every row of the "Where every current control goes" table.
- Gates (AGENTS.md): `pyrefly check`, `check_frontend.py`,
  `check_i18n_coverage.py --strict`, `check_a11y.py --strict`,
  `pytest tests -n 4`, `check_no_private_data.py`, `graphify update .`.
- README screenshots regenerated (`scripts/dev/capture_screenshots.py`).
- Version: MINOR bump (visible UI restructure).

## Out of scope

Hostname search, new data sources, changes to diagnosis logic, the WLC tab.
