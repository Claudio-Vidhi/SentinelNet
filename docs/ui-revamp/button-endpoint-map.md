# UI Revamp — Dead-Button → Endpoint Audit Map (Task 0)

Ground truth: `templates/dashboard.html` (11,464 lines), traced against every route in
`app_server.py` + `routers/*.py` (142 `@app.*`/`@router.*` HTTP routes + 1 websocket route,
extracted via `grep -rhoE "@(app|router)\.(get|post|put|delete|patch)\(\"[^\"]+\"" app_server.py routers/*.py`).
Every `onclick="..."` in the file (138 occurrences, static markup + JS-templated row
markup — `grep` sees both) plus every button wired via `addEventListener` instead of
`onclick` (12 occurrences) was traced to its JS handler and, transitively, to the
`apiFetch()`/`fetch()` call (or legitimate pure-client action) it reaches.

**Verdict legend**
- `wired` — reaches a real endpoint in the 142-route ground-truth list.
- `preview-ok` — pure client-side action (tab switch, modal open/close, dropdown
  toggle, canvas/PDF export, clipboard copy) that legitimately needs no backend call.
- `dead→remove` — no matching endpoint exists and no legitimate client action either.
- `dead→wire to <endpoint>` — a matching endpoint exists but the control never calls it.

**Headline result:** of ~150 traced controls, **0 are `dead→remove` and 0 are
`dead→wire`**. Every button/onclick in the current dashboard reaches either a real
`/api/...` endpoint or a legitimate pure-client action. See `Notes` at the end for
caveats (endpoints with no UI surface, the prototype cross-check that could not be
performed, and one UX gap that is not a "dead button" but is relevant to the revamp).

Repeated row-action buttons generated from JS template literals (e.g. one "Delete"
icon per table row) are listed once with an occurrence note rather than once per
rendered row, since the handler/endpoint is identical for every row.

---

## Global chrome (login overlay, aside, tab-nav strip)

| Tab | Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|---|
| Global (auth overlay) | "Completa Configurazione ed Entra" `#btnRegisterAdmin` (addEventListener) | inline handler @3662 | `POST /api/auth/register` → `POST /api/auth/login` | wired |
| Global (auth overlay) | "Autenticati" `#btnLogin` (addEventListener) | inline handler @3699 | `POST /api/auth/login` | wired |
| Global (auth overlay) | "Imposta Password ed Entra" `#btnChangePass` (addEventListener) | inline handler @3741 | `POST /api/auth/change-password` | wired |
| Global (aside) | "Esci" `onclick="logout()"` | `logout()` @3771 | `POST /api/auth/logout` | wired |
| Global (aside, requires-write) | "Salva Apparato" `#btnSaveDevice` (addEventListener) | inline handler @4153 | `POST /api/add-device` | wired |
| Global (aside, requires-write) | "Annulla modifica" `onclick="resetDeviceForm()"` | `resetDeviceForm()` @4221 | none (form reset) | preview-ok |
| Global (aside, requires-write) | "Crea Gruppo" `#btnCreateGroup` (addEventListener) | inline handler @4274 | `POST /api/groups` | wired |
| Global (main) | 17× tab-nav buttons `onclick="switchTab('tab-*', this)"` (+ compound `loadClientMapTab()` / `flowsTabShown()` on 2 of them) | `switchTab()` @4816 | none (tab switch); compound calls trigger that tab's own `GET` loads (see below) | preview-ok |

---

## Tab: Network Inventory (`#tab-devices`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Avvia Triage Globale" `#btnRunTriage` (addEventListener) | opens scope modal or `startGroupTriage()` @8166 | `POST /api/run-triage` → poll `GET /api/triage-status` | wired |
| "Triage Sede" `onclick="triageCurrentSite()"` | `triageCurrentSite()` @8176 | `POST /api/run-triage` (via `startGroupTriage`) | wired |
| "Ping Sede" `onclick="runPingCheck()"` | `runPingCheck()` @10227 | `POST /api/ping-check` | wired |
| "Scansione Subnet" `onclick="openSubnetScanModal()"` | `openSubnetScanModal()` @8254 | none (opens modal) | preview-ok |
| "Invio Comandi" `onclick="openBulkCommandModal()"` | `openBulkCommandModal()` @8010 | none (opens modal) | preview-ok |
| "Esporta CSV" `onclick="exportDeviceCsv()"` | `exportDeviceCsv()` @10004 | `GET /api/export/devices` | wired |
| Row: rename hostname `onclick="renameDevice('${d.IP}')"` | `renameDevice()` @4253 | `POST /api/rename-device` | wired |
| Row: ping `onclick="pingSingleDevice('${d.IP}', this)"` | `pingSingleDevice()` @10108 | `GET /api/ping/{ip}` | wired |
| Row: triage `onclick="triageSingleDevice('${d.IP}', this)"` | `triageSingleDevice()` @10151 | `POST /api/triage/{ip}` | wired |
| Row: open CLI `onclick="openCliModal('${d.IP}')"` | `openCliModal()` @7430 | `POST /api/ws-token` → `WS /api/ws-terminal/{ip}` | wired |
| Row: edit `onclick="editDevice('${d.IP}')"` | `editDevice()` @4192 | none (pre-fills aside form) | preview-ok |
| Row: download backup `onclick="downloadBackup('${d.IP}')"` | `downloadBackup()` @9972 | `GET /api/download-backup/{ip_or_filename}` | wired |
| Row: delete `onclick="deleteDevice('${d.IP}')"` | `deleteDevice()` @4239 | `POST /api/delete-device` | wired |

---

## Tab: Groups / Sites management (`#tab-groups`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Aggiungi" (vendor) `onclick="addVendor()"` | `addVendor()` @4371 | `POST /api/vendors` | wired |
| Row: rename group `onclick="renameGroup(this.dataset.g)"` | `renameGroup()` @4308 | `POST /api/groups/rename` | wired |
| Row: delete group `onclick="deleteGroup(this.dataset.g)"` | `deleteGroup()` @4293 | `POST /api/groups/delete` | wired |
| Row: delete vendor `onclick="deleteVendor(this.dataset.v)"` | `deleteVendor()` @4388 | `POST /api/vendors/delete` | wired |

(Models table shown in this tab has no visible delete affordance traced to an
`onclick`; `GET /api/models` / `POST /api/models` / `POST /api/models/delete` exist
server-side but no button in `dashboard.html` calls `POST /api/models` or
`/api/models/delete` — see Notes.)

---

## Tab: Port-Channel & Link (`#tab-map`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Reset Topologia" `onclick="resetTopology()"` | `resetTopology()` @7397 | `POST /api/topology/reset` | wired |

(Table itself loads via `loadTopology()` → `GET /api/portchannels`, triggered by
`onchange` on the site-filter select, not a button.)

---

## Tab: Topology 2D (`#tab-map-interactive`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Classica" `onclick="setMapView('classic')"` | `setMapView()` @5547 | none (view mode + `loadInteractiveMap()` re-render) | preview-ok |
| "Nuova" `onclick="setMapView('minimal')"` | `setMapView()` @5547 | same as above | preview-ok |
| "Reset Topologia" `onclick="resetTopology()"` | `resetTopology()` @7397 | `POST /api/topology/reset` | wired |
| "Aggiorna Vista" `onclick="loadInteractiveMap()"` | `loadInteractiveMap()` @5351 | `GET /api/network-map` | wired |
| "Scarica Mappa" `onclick="downloadTopology()"` | `downloadTopology()` @7173 | none (client-side canvas → PNG) | preview-ok |
| "Esporta Visio" `onclick="exportVisioMap()"` | `exportVisioMap()` @7317 | `POST /api/map/export/vsdx` | wired |
| "Esporta PDF" `onclick="exportPdfMap()"` | `exportPdfMap()` @7213 | none (client-side canvas → JPEG→PDF, no library/backend) | preview-ok |
| Legend collapse `onclick="toggleLegend()"` | `toggleLegend()` @5043 | none (show/hide) | preview-ok |
| Custom link-category delete (×N) `onclick="deleteMinimalCustomCat('${nm}')"` | `deleteMinimalCustomCat()` @5789 | none (localStorage) | preview-ok |
| "+" add custom link-category `onclick="addMinimalCustomCat()"` | `addMinimalCustomCat()` @5777 | none (localStorage) | preview-ok |

---

## Tab: Devices & Categories (`#tab-categories`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Salva Modifiche" `onclick="saveCategoryEdits()"` | `saveCategoryEdits()` @6952 | `POST /api/device-categories/assign` (per pending edit) + `POST /api/promote-device` | wired |
| "Annulla" `onclick="discardCategoryEdits()"` | `discardCategoryEdits()` @6969 | none (clears pending edits) | preview-ok |
| "Esporta CSV" `onclick="exportCategoriesCsv()"` | `exportCategoriesCsv()` @6911 | none (client-side CSV of already-loaded data) | preview-ok |
| "Aggiorna" `onclick="loadCategoriesData()"` | `loadCategoriesData()` @6670 | `GET /api/device-classification` | wired |
| "Crea" (new category) `onclick="createCategory()"` | `createCategory()` @7059 | `POST /api/device-categories` | wired |
| Row: delete category `onclick="deleteCategory('${k}')"` | `deleteCategory()` @7079 | `POST /api/device-categories/delete` | wired |
| Row: delete subcategory `onclick="deleteSubcategory('${k}','${s}')"` | `deleteSubcategory()` @7090 | `POST /api/device-categories/delete-subcategory` | wired |
| Row: resolve name conflict `onclick="openConflictModal('${n.id}')"` | `openConflictModal()` @7018 | none (opens modal) | preview-ok |
| Row: promote discovered→managed `onclick="promoteDevice('${n.id}')"` | `promoteDevice()` @6975 | `POST /api/promote-device` | wired |
| Conflict modal: cancel `onclick="closeConflictModal()"` | `closeConflictModal()` @7014 | none (removes modal) | preview-ok |
| Conflict modal: apply `onclick="confirmConflict('${nodeId}')"` | `confirmConflict()` @7044 | `POST /api/device-categories/assign` | wired |
| Row: add discovered device to inventory `onclick="addDiscoveredDevice(...)"` | `addDiscoveredDevice()` @8371 | `POST /api/add-device` | wired |

---

## Tab: Threat Intel / EUVD (`#tab-security`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| Card: "Analizza" per managed device `onclick="runManagedVulnCheck(...)"` | `runManagedVulnCheck()` @9858 → `runEuvdQuery()` @9887 | `GET /api/search` (EUVD proxy) | wired |
| Card: "Analizza" per discovered neighbor `onclick="runDiscoveredVulnCheck(...)"` | `runDiscoveredVulnCheck()` @9810 → `runEuvdQuery()` | `GET /api/search` | wired |
| Result collapse toggle `onclick="toggleVulnResults('${id}', this)"` | `toggleVulnResults()` @9876 | none (show/hide) | preview-ok |
| Description collapse toggle `onclick="toggleVulnDesc('${id}', this)"` | `toggleVulnDesc()` @9867 | none (show/hide) | preview-ok |

(Scan itself is triggered by `onchange` on the site-select / "include discovered"
checkbox → `startThreatScan()` → `GET /api/local-devices` + `GET /api/network-map`,
not a button.)

---

## Tab: MAC Tracker (`#tab-mac`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Avvia MAC Scan" `#btnMacScan onclick="runMacScan()"` | `runMacScan()` @8555 | `POST /api/mac/scan` | wired |
| "Salva" (retention) `onclick="saveMacRetention()"` | `saveMacRetention()` @8995 | `POST /api/mac/settings` | wired |
| "Salva" (ad-hoc override) `onclick="saveMacOverride()"` | `saveMacOverride()` @8445 | `POST /api/mac/overrides` | wired |
| "Cerca" `onclick="macSearch()"` | `macSearch()` @8590 | `GET /api/mac/search` | wired |
| "Reset" `onclick="macSearchReset()"` | `macSearchReset()` @8605 | none (clears filters + re-search) | preview-ok |
| Row: remove ad-hoc override `onclick="removeMacOverride('${o.switch_ip}')"` | `removeMacOverride()` @8464 | `POST /api/mac/overrides/delete` | wired |
| CLI terminal MAC link / search result: locate `onclick="macLocate('${r.mac}')"` | `macLocate()` @8908 | `GET /api/mac/locate` | wired |
| Locate modal close (×2, same modal) `onclick="closeMacLocateModal()"` | `closeMacLocateModal()` @8975/8988 | none (removes modal) | preview-ok |

---

## Tab: Client Map — MAC ↔ IP (`#tab-clientmap`, PREVIEW)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Raccogli ARP (gateway L3)" `#btnArpScan onclick="runArpScan()"` | `runArpScan()` @8705 | `POST /api/arp/scan` | wired |
| "Cerca" `onclick="arpClientSearch()"` | `arpClientSearch()` @8760 | `GET /api/arp/client-map` | wired |
| "Reset" `onclick="arpSearchReset()"` | `arpSearchReset()` @8776 | none (clears filters + re-search) | preview-ok |

---

## Tab: Live Flows (`#tab-flows`, PREVIEW) + flow detail panel

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Tenants" filter dropdown `onclick="toggleFlowsTenantDropdown()"` | `toggleFlowsTenantDropdown()` @11291 | none (show/hide) | preview-ok |
| "Aggiorna" (flows) `onclick="loadTopTalkers()"` | `loadTopTalkers()` @10980 | `GET /api/observability/top` (or `GET /api/observability/syslog` when source=syslog) | wired |
| "Analizza con AI" `onclick="analyzeFlowsWithAi()"` | `analyzeFlowsWithAi()` @11378 → `_prepareFlowAiChat()` | none directly (switches to AI tab + pre-fills chat input; actual call is user clicking "Invia" → `POST /api/ai/chat`) | preview-ok |
| "Colonne" dropdown `onclick="toggleFlowsColsDropdown()"` | `toggleFlowsColsDropdown()` @10841 | none (show/hide) | preview-ok |
| "Aggiorna" (anomalie) `onclick="loadAnomalies()"` | `loadAnomalies()` @11392 | `GET /api/observability/anomalies` | wired |
| Anomaly IP-filter chip remove `onclick="clearAnomIpFilter()"` | `clearAnomIpFilter()` @11286 | none (clears filter + re-loads via `loadAnomalies()`) | preview-ok |
| Detail panel close `onclick="closeFlowDetailPanel()"` | `closeFlowDetailPanel()` @11243 | none (hides panel) | preview-ok |
| Source chips (×N, "all"/netflow/ipfix/sflow/syslog) `onclick="setFlowsSource('${s}')"` | `setFlowsSource()` @10835 | none (client filter of already-loaded flow data + re-render) | preview-ok |
| "Seleziona tutti" flow rows `onclick="toggleFlowsSelectAll(this)"` | `toggleFlowsSelectAll()` @11133 | none (checkbox state) | preview-ok |
| Row: open flow detail `onclick="openFlowDetailPanelByKey('${key}', event)"` | `openFlowDetailPanelByKey()` @11199 | none directly (opens panel; panel body calls `GET /api/arp/client-map` via `loadFlowPanelClientMap()`) | wired |
| Row icon: stop bubbling `onclick="event.stopPropagation()"` (×2) | inline | none | preview-ok |
| Row/detail icons: locate src/dst in topology (×6 occurrences across table row + detail panel + syslog render path) `onclick="highlightInTopology('${ip}')"` | `highlightInTopology()` @11308 | none directly (switches to Topology tab + `networkInstance.focus()`) | preview-ok |
| "Vedi anomalie" `onclick="jumpToAnomaliesForFlow()"` | `jumpToAnomaliesForFlow()` @11275 | none directly (sets filter + calls `loadAnomalies()` → `GET /api/observability/anomalies`) | wired |
| "Analizza con AI" (single flow) `onclick="analyzeSingleFlowWithAi()"` | `analyzeSingleFlowWithAi()` @11385 | same as `analyzeFlowsWithAi` | preview-ok |
| Anomaly row: transition buttons ×3 (`new→ack`, `new→resolved`, `ack→resolved`) `onclick="anomTransition(${a.id}, '${from}', '${to}')"` | `anomTransition()` @11442 | `POST /api/observability/anomalies/{event_id}/status` | wired |

---

## Tab: Config Analyzer (`#tab-config`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Aggiorna" `onclick="loadConfigAnalyzer(true)"` | `loadConfigAnalyzer()` @9020 | `GET /api/config-analyzer` | wired |
| Pills: VLAN / Routing / ACL / Interfacce / Validazione (×5) `onclick="caSwitchView('...')"` | `caSwitchView()` @9049 | none (client-side re-render of already-fetched `caData`) | preview-ok |
| "Riga di configurazione" icon `onclick="caShowRawRoute(this)"` | `caShowRawRoute()` @9180 | none (decodes inline base64 data-attr, opens modal) | preview-ok |
| Route group-mode toggle (×2: `flat`/`byhop`) `onclick="caSwitchRouteGroupMode('...', idx)"` | `caSwitchRouteGroupMode()` @9157 | none (client-side re-render) | preview-ok |
| Raw-route modal close `onclick="caCloseRawRouteModal()"` | `caCloseRawRouteModal()` @9187 | none (hides modal) | preview-ok |
| Interface raw-row toggle `onclick="caToggleIfaceRaw('${rowId}')"` | `caToggleIfaceRaw()` @9360 | none (show/hide row) | preview-ok |

---

## Tab: AI Assistant (`#tab-ai`)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| Refresh model list icon `onclick="refreshAiModels()"` | `refreshAiModels()` @10479 | `GET /api/ai/models` | wired |
| "Salva profilo" `onclick="saveAiSettings()"` | `saveAiSettings()` @10518 | `POST /api/ai/profiles` (or `PUT /api/ai/profiles/{id}` when editing) | wired |
| "Elimina profilo" `#btnAiDeleteProfile onclick="deleteAiProfile()"` | `deleteAiProfile()` @10564 | `DELETE /api/ai/profiles/{profile_id}` | wired |
| "Dispositivi" attach dropdown `onclick="toggleAiDeviceDropdown()"` | `toggleAiDeviceDropdown()` @10342 | none (show/hide) | preview-ok |
| "Seleziona tutti" / "Deseleziona tutti" attach devices (×2) `onclick="setAllAiAttachDevices(true/false)"` | `setAllAiAttachDevices()` @10326 | none (checkbox state) | preview-ok |
| "Nuova conversazione" `onclick="clearAiChat()"` | `clearAiChat()` @10583 | none (clears chat box) | preview-ok |
| "Invia" `#btnAiSend onclick="sendAiChat()"` | `sendAiChat()` @10718 | `POST /api/ai/chat` | wired |

(Profile-active state is loaded via `GET /api/ai/profiles`; activation itself —
`POST /api/ai/profiles/{profile_id}/activate` — is wired to the `onchange` handler
of `#aiProfileSelect`, not a button/onclick, so out of this table's scope per the
brief but confirmed present, not dead.)

---

## Tab: Zero-Touch Provisioner (`#tab-provisioner`, requires-write) — FortiGate token panel (requires-admin)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Salva token cifrato" `onclick="saveFgtToken()"` | `saveFgtToken()` @4683 | `POST /api/fortigate/token` | wired |
| "Rimuovi" `onclick="removeFgtToken()"` | `removeFgtToken()` @4729 | `POST /api/fortigate/token` (empty-token payload; there is no `DELETE /api/fortigate/token` route) | wired |
| "Test" `onclick="testFgtToken()"` | `testFgtToken()` @4759 | `GET /api/fortigate/{ip}/status` | wired |
| "Genera Config" `#btnProvGenerate` (addEventListener) | inline handler @4529 | `POST /api/provisioner/generate` or `POST /api/provisioner/fgt/generate` | wired |
| "Scarica .txt" `#btnProvDownload` (addEventListener) | inline handler @4540 | `POST /api/provisioner/download` or `/api/provisioner/fgt/download` | wired |
| "Applica via SSH" `#btnProvPushSsh` (addEventListener) | inline handler @4556 | `POST /api/provisioner/push-ssh` or `/api/provisioner/fgt/push-ssh` | wired |
| "Applica via Console" `#btnProvPushSerial` (addEventListener) | inline handler @4579 | `POST /api/provisioner/push-serial` or `/api/provisioner/fgt/push-serial` | wired |
| Refresh serial ports icon `#btnProvRefreshPorts` (addEventListener) | inline handler @4600 | `GET /api/provisioner/serial-ports` | wired |

---

## Tab: CSV Import (`#tab-import`, requires-write)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Elabora e Importa" `#btnUploadCsv` (addEventListener) | inline handler @10021 | `POST /api/import-csv` | wired |

---

## Tab: Users (`#tab-users`, requires-admin)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Crea Utente" `onclick="createUser()"` | `createUser()` @7700 | `POST /api/users` | wired |
| Row: save allowed tabs `onclick="saveUserTabs(this)"` | `saveUserTabs()` @7614 | `POST /api/users/tabs` | wired |
| Row: enable/disable toggle `onclick="toggleUserDisabled(this.dataset.u, ...)"` | `toggleUserDisabled()` @7634 | `POST /api/users/disable` | wired |
| Row: delete user `onclick="deleteUser(this.dataset.u)"` | `deleteUser()` @7648 | `POST /api/users/delete` | wired |

(Role change is via `onchange` on a row `<select>`, not a button; confirmed wired to
`POST /api/users/role`, out of table scope.)

---

## Tab: Sites (`#tab-sites`, requires-admin, PREVIEW)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Crea sede" `onclick="createSite()"` | `createSite()` @4883 | `POST /api/sites` | wired |
| Row: regenerate token `onclick="regenSiteToken(this.dataset.s)"` | `regenSiteToken()` @4906 | `POST /api/sites/regenerate-token` | wired |
| Row: delete site `onclick="deleteSite(this.dataset.s)"` | `deleteSite()` @4919 | `POST /api/sites/delete` | wired |

(`POST /api/sites/update` and `POST /api/sites/{id}/command` +
`GET /api/sites/{id}/command-jobs` exist server-side but no button in
`dashboard.html` currently calls them — see Notes.)

---

## Tab: MCP Server (`#tab-mcp`, requires-admin)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| "Copia JSON" `onclick="copyMcpConfig()"` | `copyMcpConfig()` @4980 | none (`navigator.clipboard.writeText`) | preview-ok |
| "Salva" (tool config) `onclick="saveMcpSettings()"` | `saveMcpSettings()` @4964 | `POST /api/mcp/settings` | wired |

---

## Tab: Settings (`#tab-settings`, requires-admin for 2 of 4 panels)

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| Network exposure "Salva" (JS-templated into `#netSettingsBody`) `onclick="saveAppSettings()"` | `saveAppSettings()` @7989 | `POST /api/settings/network` | wired |
| CLI blacklist toggle `onchange="saveCliBlacklistSetting()"` (checkbox, not onclick — noted for completeness) | `saveCliBlacklistSetting()` @7940 | `POST /api/settings/cli-blacklist` | wired |
| Observability "Salva" (JS-templated into `#obsSettingsBody`) `onclick="saveObsSettings()"` | `saveObsSettings()` @7896 | `POST /api/observability/config` | wired |
| App Advanced "Salva" (JS-templated into `#appAdvBody`) `onclick="saveAppAdvSettings()"` | `saveAppAdvSettings()` @7815 | `POST /api/settings/app` | wired |

---

## Global modals

| Control | JS function | Endpoint(s) hit | Verdict |
|---|---|---|---|
| Subnet-scan modal close (X) `onclick="closeSubnetScanModal()"` | `closeSubnetScanModal()` @8254 | none (hides modal) | preview-ok |
| "Avvia Scansione" `#btnAvviaScan onclick="startSubnetScan()"` | `startSubnetScan()` @8280 | `POST /api/scan-subnet` → poll `GET /api/scan-subnet/{job_id}` | wired |
| Triage-scope modal close (X) `onclick="closeTriageScopeModal()"` | `closeTriageScopeModal()` @8197 | none (hides modal) | preview-ok |
| "Scansiona tutte le sedi" `onclick="startGroupTriage('all')"` | `startGroupTriage()` @8201 | `POST /api/run-triage` → poll `GET /api/triage-status` | wired |
| Triage-scope modal: per-site button (×N) `onclick="startGroupTriage(this.dataset.g)"` | `startGroupTriage()` @8201 | same as above | wired |
| Bulk-command modal close (X) `onclick="closeBulkCommandModal()"` | `closeBulkCommandModal()` @8032 | none (hides modal) | preview-ok |
| "Esegui sui dispositivi" `#btnBulkRun onclick="startBulkCommand()"` | `startBulkCommand()` @8072 | `POST /api/bulk-command` → poll `GET /api/bulk-command/{job_id}` | wired |
| Raw-config-line modal close (X) `onclick="caCloseRawRouteModal()"` | `caCloseRawRouteModal()` @9187 | none (hides modal) | preview-ok |
| CLI terminal modal close (X) `onclick="closeCliModal()"` | `closeCliModal()` @7504 | none (closes WebSocket + hides modal) | preview-ok |

---

## Notes / caveats (read before starting downstream tasks)

1. **Zero dead buttons found.** Every one of the ~150 traced controls (138 static/
   templated `onclick` occurrences + 12 `addEventListener`-only buttons) reaches a
   real endpoint from the 142-route ground-truth list or performs a legitimate
   pure-client action. There is nothing to `remove` and nothing to `wire` in the
   current codebase. Downstream per-tab restyle tasks (5–20 in the implementation
   plan) can treat their "remove dead controls" step as a no-op **unless** a task's
   own closer read of its tab surfaces something this pass missed — the per-tab
   guard tests should still assert the endpoint strings from this map are present.

2. **Prototype cross-check could not be performed.** The task brief and the
   implementation plan (`docs/superpowers/plans/2026-07-14-ui-revamp.md`) reference
   "four prototype HTMLs" (`sentinelnet-homepage-prototype.html`,
   `sentinelnet-inventory-tab-prototype.html`, `sentinelnet-mac-tracker-prototype.html`,
   `sentinelnet-client-map-prototype.html`) and a `sentinelnet-design-language.md`.
   None of these files exist in this repository, worktree, any local branch, or
   anywhere else on the filesystem (verified via a full-disk `find`). They were
   presumably produced as Artifacts in an earlier session and never committed. This
   audit therefore could not check prototype-only buttons like "Customize view" or
   "Open design language" against the backend — there is nothing in the current
   codebase resembling those labels, so there is nothing to mark
   `drop from revamp — no backend` today. **Action for later tasks:** if/when those
   prototype files are supplied, re-run this cross-check step before authoring the
   Home tab (Task 3) or any tab whose "Layout target" cites a prototype file, and
   apply the `drop from revamp — no backend` verdict to anything in them with no
   entry in this map's `wired` set.

3. **Endpoints that exist server-side with no UI surface at all** (not a "dead
   button" finding — there is no control to flag — but relevant context for anyone
   designing the Home tab or new panels): all 12 `GET /api/wlc/{ip}/...` wireless
   controller routes, and most of the deep FortiGate diagnostic routes
   (`/api/fortigate/{ip}/policies`, `/interfaces`, `/arp`, `/device-inventory`,
   `/dhcp-leases`, `/full-config`, `/routes`, `/wifi/aps`, `/wifi/clients`,
   `/policy-stats`, `/logs`, `/sessions`, `/policy-lookup`, `/diagnose-client`) have
   no caller anywhere in `dashboard.html`. These appear to be MCP-tool-only surfaces
   (see `mcp_server.py`) rather than UI gaps. Also unused by any button:
   `GET/POST /api/models`, `POST /api/models/delete` (Groups tab shows a vendor
   table but the models CRUD has no UI), and `POST /api/sites/update` +
   `POST /api/sites/{id}/command` + `GET /api/sites/{id}/command-jobs` (Sites tab
   only exposes create/regenerate-token/delete). None of these are dead buttons;
   they are simply endpoints a future task could choose to surface.

4. **FortiGate token table has no per-row action** (UX gap, not a dead button): the
   `#fgtTokensTableBody` rows rendered by `renderFgtTokensTable()` (dashboard.html
   ~4634) show IP/port/TLS/status only — there is no delete/edit icon per row. The
   shared `saveFgtToken()` / `removeFgtToken()` / `testFgtToken()` buttons operate on
   whatever device is currently selected in the `#fgtTokenDevice` dropdown, not on a
   clicked row. Worth a UX note for the ZTP restyle (Task 14) but out of scope for
   this dead-button audit since no control exists to mark dead.

5. **Route count vs. brief's estimate:** the brief said "~108 routes"; the actual
   ground-truth extraction returned 142 (`@app.*` + `@router.*` combined, the
   fortigate/wlc/observability routers were likely added after that estimate was
   written) + 1 websocket route (`/api/ws-terminal/{ip}`). All 142 were used as the
   legal wire-target set for this audit.
