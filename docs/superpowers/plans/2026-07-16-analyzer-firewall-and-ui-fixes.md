# Config Analyzer Firewall Support + UI Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add firewall (FortiGate) support to the Config Analyzer as a dedicated sub-tab, remove the "Understand" view, restrict the Config Converter to firewall-to-firewall vendor translation, and fix five UI/logic issues (provisioning transports, map layout, VTP mode badge, triage classification, Client Map tenant selection).

**Architecture:** SentinelNet is a FastAPI app (`app_server.py` + `routers/`) with a single monolithic frontend at `templates/dashboard.html` (~12.8k lines: HTML + i18n dicts (Italian ~line 2800-3450, English ~line 3450-4100) + all JS). Config Analyzer backend is `config_analyzer.py` exposed via `routers/analyzer.py`. FortiGate-specific logic lives in `fortigate_service.py` / `routers/fortigate.py` / `drivers/fortinet.py`. Device classification is `core_engine.py::classify_device_type` (line 567). Comments/UI copy are bilingual Italian/English — follow existing style (Italian comments in code).

**Tech Stack:** Python 3 / FastAPI, vanilla JS in dashboard.html, Vis.js for the map, unittest test files runnable as scripts (`uv run python test_x.py` style — check existing test files for the pattern).

## Global Constraints

- All UI strings must be added to BOTH i18n dicts (Italian and English) in dashboard.html with `data-i18n` keys, matching existing naming conventions (`pillCa*`, `lbl*`, `opt*`).
- Do not reintroduce CI. Local verification only.
- Never delete `.patch` files.
- Tests follow existing repo pattern (see `test_classify_device_type.py`): stdlib `unittest`, runnable directly.
- Keep changes minimal — no refactors of dashboard.html beyond the task scope.
- Final integration step (after all tasks): rebuild exe with `pyinstaller SentinelNet.spec` (done once at the end by the coordinator, not per task).

---

### Task 1: Remove "Understand" view from Config Analyzer

**Files:**
- Modify: `templates/dashboard.html` (pill at line ~1987; renderer `caRenderUnderstand` line ~10312; dispatch line ~10226; home card line ~10307; i18n keys `pillCaUnderstand`, `caHomeUnderstandDesc`, `caUnderstandTitle` and any other `caUnderstand*`/`caU*` keys near lines 3045-3051 and 3703-3709)
- Modify: `routers/analyzer.py` and/or `routers/ai.py` — remove any backend endpoint used ONLY by the understand view (grep for the fetch URL used in `caRenderUnderstand` and its submit handler; if the endpoint is shared with AI Assistant, leave backend alone)
- Modify: `config_analyzer.py` — same rule: remove code used only by understand.

**Interfaces:** Produces nothing; purely a deletion. Later tasks assume the `understand` pill no longer exists.

- [ ] **Step 1:** Grep `dashboard.html` for `understand`/`Understand` (case-insensitive) and for every i18n key rendered by `caRenderUnderstand`. List all hits.
- [ ] **Step 2:** Delete the pill button (line ~1987), the `if (caView === 'understand')` dispatch branch, `caRenderUnderstand` and every helper/submit function called only from it, the home card entry, and all now-unused i18n keys from both dicts.
- [ ] **Step 3:** Grep backend for the endpoint path(s) the deleted JS called. If exclusively used by understand, delete the route + supporting functions and their tests.
- [ ] **Step 4:** Verify: `python -c "import app_server"` succeeds; grep `dashboard.html` for `understand` returns only unrelated hits (e.g. none); load check — `grep -c caRenderUnderstand templates/dashboard.html` = 0.
- [ ] **Step 5:** Commit: `git commit -m "feat(analyzer): remove Understand view (superseded by AI Assistant tab)"`

### Task 2: Config Analyzer — Firewall sub-tab (FortiGate)

**Files:**
- Modify: `templates/dashboard.html` (pills block lines 1980-1989; `caSwitchView`/`renderCaResults` around line 10189-10230)
- Modify: `config_analyzer.py`, `routers/analyzer.py`
- Reference: `docs/fortios-notes/` (distilled FortiOS docs), `fortigate_service.py`, `drivers/fortinet.py`
- Test: `test_config_analyzer_fortigate.py` (create)

**Interfaces:**
- Produces: backend — analyzer device payload gains `is_firewall: bool` and, for FortiGate devices, `firewall: {policies: [...], interfaces_zones: [...], vips_nat: [...], addresses_services: [...]}` parsed from the stored FortiGate config. Frontend — new pill `data-view="firewall"` (i18n `pillCaFirewall`, IT "Firewall" / EN "Firewall") visible logic: view renders only firewall devices; existing views (VLAN/Routing/ACL/Interfacce/Validazione) remain switch-oriented.
- The firewall view contains its own small sub-menu (FortiGate-oriented): **Policy**, **Interfacce/Zone**, **NAT/VIP**, **Oggetti** (address/service objects) — implemented as inner pills `caFwView` with renderers `caRenderFwPolicies`, `caRenderFwIfaces`, `caRenderFwNat`, `caRenderFwObjects`.

- [ ] **Step 1:** Read `config_analyzer.py` fully + `routers/analyzer.py` to learn how per-device analysis payloads are built and how configs are read; read `drivers/fortinet.py` and `docs/fortios-notes/` for FortiOS config syntax (`config firewall policy`, `config system interface`, `config firewall vip`, `config firewall address/service`).
- [ ] **Step 2:** Write failing tests in `test_config_analyzer_fortigate.py` with an inline sample FortiOS config string covering: 2 policies (srcintf/dstintf/srcaddr/dstaddr/service/action/nat), 2 interfaces with `set vdom`/`set ip`/zone membership, 1 VIP, 1 address object, 1 service object. Assert the parser returns them structured.
- [ ] **Step 3:** Run tests — expect FAIL (parser missing).
- [ ] **Step 4:** Implement `parse_fortigate_config(text) -> dict` in `config_analyzer.py` (section-based parser: `config <path>` / `edit <name>` / `set k v...` / `next` / `end`) and wire it into the analyzer payload for devices whose vendor/driver is fortinet (`is_firewall=True`, `firewall={...}`). Non-FortiGate firewalls: `is_firewall=True, firewall=None` is acceptable.
- [ ] **Step 5:** Run tests — expect PASS.
- [ ] **Step 6:** Frontend: add the `Firewall` pill; in `renderCaResults` add `if (caView === 'firewall')` branch that lists only `is_firewall` devices, with inner pills Policy / Interfacce-Zone / NAT-VIP / Oggetti rendering tables from `dev.firewall`. Devices with `firewall=null` show a "vendor non supportato (solo FortiGate)" note. Add all i18n keys in both languages.
- [ ] **Step 7:** Verify: start app (`uv run python main.py` or repo's run pattern), open Config Analyzer, confirm Firewall pill renders with a FortiGate device (or with mocked data if no lab device: temporarily check via browser console).
- [ ] **Step 8:** Commit: `git commit -m "feat(analyzer): firewall sub-tab with FortiGate policy/interface/NAT/object views"`

### Task 3: Config Converter — firewall-vendors-only

**Files:**
- Modify: `templates/dashboard.html` (`caRenderConvert` line ~10347 and its vendor selects/submit)
- Modify: `config_analyzer.py` / `routers/analyzer.py` (convert endpoint — validate server-side)
- Test: extend `test_convert_config.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: convert source/target selectors list ONLY firewall vendors: `fortinet` (FortiGate), `paloalto` (PAN-OS), `cisco_asa`/`cisco_ftd` if already supported by the converter — check what the current converter supports and keep only firewall entries; drop switch vendors (cisco_ios, hp_procurve, aruba, juniper EX). Server rejects non-firewall vendor pairs with HTTP 400.

- [ ] **Step 1:** Read `caRenderConvert` + the convert endpoint + `test_convert_config.py` to enumerate currently supported vendors.
- [ ] **Step 2:** Write failing test: POST convert with a switch vendor (e.g. cisco_ios) as source or target → expect 400/ValueError `firewall vendors only`.
- [ ] **Step 3:** Run — FAIL.
- [ ] **Step 4:** Implement: define `FIREWALL_VENDORS` allowlist in the converter module; validate both source and target against it in the endpoint; update frontend selects to the same list and update the convert description copy (both i18n dicts) to say it translates between firewall vendors.
- [ ] **Step 5:** Run tests (`test_convert_config.py`) — PASS, existing firewall-to-firewall cases still pass.
- [ ] **Step 6:** Commit: `git commit -m "feat(analyzer): restrict config converter to firewall vendors"`

### Task 4: Provisioning — horizontal transports row + blank TCP/UDP entries

**Files:**
- Modify: `templates/dashboard.html` (HTML lines 1194-1230; JS `TRANSPORT_PROTOS` block lines 4903-4965)
- Check: `routers/provisioner.py` / `inventory_manager.py` — transports map is `{proto: port|null}`; confirm arbitrary keys `tcp`/`udp` pass validation, patch if a proto whitelist exists.
- Test: extend `test_transports.py`

**Interfaces:**
- Produces: transports form lays out each protocol row horizontally in a flex row-of-rows (all 6 rows aligned: fixed-width checkbox+label column, port input column). Two new rows: `TCP` and `UDP`, unchecked by default, port input EMPTY (no default), user fills port. `TRANSPORT_PROTOS = ['ssh','telnet','netconf','restconf','tcp','udp']`, `TRANSPORT_LABELS += {tcp:'TCP', udp:'UDP'}`, `defaults` map gets NO entry for tcp/udp (empty when not set).

- [ ] **Step 1:** Add the two HTML rows (`trTcpEnabled`/`trTcpPort`, `trUdpEnabled`/`trUdpPort`) mirroring existing rows but with `value=""` on the port inputs. Wrap the rows container in a consistent grid: `display:grid; grid-template-columns:auto 90px 90px; gap:6px 8px; align-items:center;` or equivalent flex so checkbox/label/port align across rows.
- [ ] **Step 2:** Update `TRANSPORT_PROTOS`, `TRANSPORT_LABELS`; in `setTransportsForm` change port fill to `(enabled && map[p]) ? map[p] : (defaults[p] ?? '')`.
- [ ] **Step 3:** Extend `test_transports.py`: saving a device with `{"ssh":22,"tcp":9000,"udp":161}` round-trips through inventory. Run — fix backend whitelist if it fails, rerun to PASS.
- [ ] **Step 4:** Manual verify in browser: rows aligned, TCP/UDP blank, summary shows `TCP:9000` when enabled.
- [ ] **Step 5:** Commit: `git commit -m "feat(provisioning): align transport rows, add user-defined TCP/UDP transports"`

### Task 5: New Map — tighter, organised layout

**Files:**
- Modify: `templates/dashboard.html` (Vis.js options lines ~6580-6670 and ~7151-7200)

**Interfaces:** none.

- [ ] **Step 1:** Read both Vis.js option blocks (map is created twice: shared instance ~6604 and second block ~7189) and current physics settings.
- [ ] **Step 2:** Tune the SHARED options (fix in one place per the existing comment at line 7151): use `physics: { solver: 'barnesHut', barnesHut: { gravitationalConstant: -3000, centralGravity: 0.4, springLength: 220, springConstant: 0.05, avoidOverlap: 1 }, stabilization: { iterations: 300 } }` as starting point; keep freeze-after-stabilization behavior. Goal: nodes stop flying far apart; clusters stay compact and non-overlapping. Iterate values against the real map until visually organised.
- [ ] **Step 3:** Manual verify: open new map with lab inventory; nodes compact, no overlap, layout stable after freeze.
- [ ] **Step 4:** Commit: `git commit -m "fix(map): compact organised layout, stop node drift"`

### Task 6: New Map — show VTP mode with domain in node rectangle

**Files:**
- Modify: `templates/dashboard.html` (`createNodeSvg` line 6139, VTP pill block lines 6182-6210, and every caller passing the `vtp` object — grep `createNodeSvg(`; also where `vtp_mode` originates, line ~5263 and the topology payload)
- Check: `routers/topology.py` / `core_engine.py` — confirm `vtp_mode` reaches the frontend node data; wire it through if missing.

**Interfaces:**
- Produces: when `vtp.showDomain && vtp.domain`, the pill text becomes `"<domain> · <mode>"` (mode lowercase: server/client/transparent/off), truncated to fit the 216px rect. `vtp` object gains `mode` field populated by callers.

- [ ] **Step 1:** Trace `vtp` object construction (grep `showDomain`) and confirm mode availability in node data; extend backend payload if absent.
- [ ] **Step 2:** In `createNodeSvg`, append mode to pill text when present: `const txt = dEsc + (vtp.mode ? ' · ' + vtp.mode : '')`, adjust slice/font if needed.
- [ ] **Step 3:** Manual verify on map with VTP domain toggle enabled: pill shows `LAB · server` style text.
- [ ] **Step 4:** Commit: `git commit -m "feat(map): show VTP mode alongside domain in node badge"`

### Task 7: Triage — device category logic fix

**Files:**
- Modify: `core_engine.py` (`classify_device_type` line 567; call sites lines 1299, 1383)
- Modify: `routers/triage.py` (triage flow)
- Test: `test_classify_device_type.py` (extend)

**Interfaces:**
- Produces: (a) a device type set manually by the user (triage/provisioning) is authoritative — auto-classification must never overwrite it on subsequent scans/triage runs (persist a `type_source: 'manual'|'auto'` flag or equivalent existing mechanism — inspect inventory schema first and reuse if present); (b) auto-classification after triage uses collected evidence (capabilities, platform, description from CDP/LLDP and parsed config), not hostname alone — hostname is lowest-priority signal (this direction already started in commit 4dc8f53/204a3f7; find remaining paths where hostname wins over evidence and fix).

- [ ] **Step 1:** Read `classify_device_type` + both call sites + `routers/triage.py` + inventory schema for existing manual-override flag. Reproduce the flaw: write a failing unittest capturing a real misclassification path (e.g. triaged device with firewall platform evidence classified as switch by hostname, or manual type clobbered by re-triage).
- [ ] **Step 2:** Run — FAIL.
- [ ] **Step 3:** Fix: enforce manual-type precedence at call sites; reorder/weight evidence in `classify_device_type` so capabilities > platform > description > hostname.
- [ ] **Step 4:** Run full `test_classify_device_type.py` — PASS, no regressions.
- [ ] **Step 5:** Commit: `git commit -m "fix(triage): manual device type is authoritative; evidence outweighs hostname"`

### Task 8: Client Map — tenant must be chosen first, one table per tenant

**Files:**
- Modify: `templates/dashboard.html` (Client Map tab lines 1748-1880; JS `arpClientSearch`, `populateArpTenantFilter`/`populateArpGatewayFilter`, results renderer — grep `arpResults`)
- Backend unchanged (`routers/arp.py` already filters by tenant).

**Interfaces:**
- Produces: `arpFilterTenant` becomes a multi-select tenant picker with NO "all tenants" default — initial state: nothing selected, `#arpResults` shows placeholder "Seleziona un tenant per visualizzare i binding" / "Select a tenant to view bindings" (i18n keys `arpPickTenantHint`). User picks first tenant → its table renders. User can add more tenants → EACH tenant renders as its own separate table with its own header (current grouped-render per screenshot may already do per-tenant sections — keep/reinforce that; never merge tenants in one table). Remove/repurpose the `optArpAllTenants` option. Gateway filter applies within selected tenants. KPIs count only selected tenants.

- [ ] **Step 1:** Read the Client Map JS block end-to-end (search + render + KPI functions).
- [ ] **Step 2:** Replace single `<select>` with a multi-select pattern already used in the same tab (`arpDeviceMenu` details/checkbox dropdown at lines 1785-1791 — reuse that pattern for tenants). Default: none checked.
- [ ] **Step 3:** In `arpClientSearch`: if no tenant selected → render placeholder hint and blank KPIs, skip fetch. Else fetch per selected tenant (or fetch once and split client-side) and render one `<table>` per tenant under a tenant header, in selection order.
- [ ] **Step 4:** Add i18n keys (`arpPickTenantHint`, updated `lblArpFilterTenant` if copy changes) to both dicts.
- [ ] **Step 5:** Manual verify: initial load shows hint, selecting `test_g` shows only test_g table, adding `Generale` adds second separate table; no mixed table.
- [ ] **Step 6:** Commit: `git commit -m "fix(client-map): explicit tenant selection, separate table per tenant"`

---

## Final integration (coordinator)

- [ ] Run all repo tests that exist as scripts (`test_*.py` in root, existing pattern).
- [ ] `graphify update .` if graphify CLI available (known missing — skip if absent).
- [ ] Rebuild exe: `pyinstaller SentinelNet.spec`.
