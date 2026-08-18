// Cross-module contract for the frontend.
//
// The files in static/js are classic scripts sharing one global scope: what a
// module exposes with `window.X = ...` is later called by another as `X()`.
// Without these declarations the type check flags both the assignment and the
// call; with them it flags ONLY unexpected names — which is exactly the case
// that left `window.globalDevices` permanently undefined (globalDevices is a
// `let` in core.js, not a window property, so it must NOT be added here).
//
// Add an entry ONLY together with its `window.X = ...` assignment.
// Regenerating: see docs/development.md.

// --- Vendored libraries (static/vendor), loaded via <script src>. ---
// `var` and not `const`: they are UMD and register themselves on window, so
// code reaches them both as `html2pdf` and as `window.html2pdf`.
declare var vis: any;
declare var Chart: any;
declare var html2pdf: any;
declare var Terminal: any;
declare var FitAddon: any;

// --- Cross-module exposures (window.X = ...) ---

// audit_checklist.js
declare var closeAuditWorkspace: any;
declare var closeNewAuditModal: any;
declare var closeTemplateItemModal: any;
declare var deleteTemplateItem: any;
declare var loadAuditChecklistTab: any;
declare var openAuditWorkspace: any;
declare var openNewAuditModal: any;
declare var openTemplateItemModal: any;
declare var saveAuditItem: any;
declare var submitNewAuditForm: any;
declare var submitTemplateItemForm: any;
declare var toggleTemplateEditor: any;
declare var viewAuditReport: any;
declare var viewAuditReportForId: any;

// core.js
declare var _tenantIdentities: any;

// devices.js
declare var _activeSubnetScanJob: any;

// flow-analytics.js
declare var applySiemFilter: any;
declare var filterSiemEvents: any;
declare var loadFlowSiemTab: any;
declare var siemTenantParam: any;
declare var suppressSiemAlert: any;
declare var toggleEventDrawer: any;
declare var toggleSiemStream: any;

// incidents.js
declare var explainIncident: any;
declare var loadIncidentsList: any;
declare var loadIncidentsTab: any;
declare var openIncident: any;
declare var saveDeviceSuppression: any;
declare var saveInterfaceExpectation: any;
declare var saveRuleParameters: any;
declare var setIncidentStatus: any;

// netsec-audit.js
declare var clearUploadedConfig: any;
declare var closeAuditReportModal: any;
declare var deleteAuditRun: any;
declare var downloadModalDocx: any;
declare var ensureHtml2Pdf: any;
declare var exportAuditReport: any;
declare var loadAuditHistory: any;
declare var loadNetSecAuditTab: any;
declare var openAuditReportModal: any;
declare var openAuditRun: any;
declare var renderAuditRulesTable: any;
declare var renderBenchmarkRequirements: any;
declare var runAuditScan: any;
declare var switchNetSecSubtab: any;
declare var toggleAuditDetail: any;
declare var toggleAuditSaveNameInput: any;

// observability.js
declare var trafSelectedTenants: any;

// redundancy.js
declare var closeCreateRedundancyModal: any;
declare var deleteRedundancyGroup: any;
declare var loadRedundancyTab: any;
declare var openCreateRedundancyModal: any;
declare var submitCreateRedundancyGroup: any;

// site-agent.js
declare var closeAgentControlModal: any;
declare var fetchAgentInventory: any;
declare var openAgentControlModal: any;
declare var saveAgentInventory: any;
declare var toggleAgentDataFlow: any;
declare var triggerAgentConfigSave: any;
declare var triggerAgentRestart: any;
declare var triggerAgentSelfUpdate: any;

// threat-intel.js
declare var _threatScanBusy: any;
declare var _vwVendor: any;

// Names that already exist as a top-level declaration in some module AND are
// also re-exposed on window: only the 'window' half belongs here, otherwise the
// identifier is declared twice.
interface Window {
    loadAssetOnce: any;      // core.js
    trafState: any;          // observability.js, read by flow-analytics.js
    _vwLoaded: any;          // threat-intel.js, first-load flag
    webkitAudioContext: any; // legacy Safari fallback in devices.js
}
