// Contratto fra i moduli del frontend.
//
// I file di static/js sono script classici che condividono un unico scope
// globale: quello che un modulo espone con `window.X = ...` viene poi chiamato
// da un altro come `X()`. Senza queste dichiarazioni il type check segnala sia
// l'assegnazione sia la chiamata; con queste, segnala SOLO i nomi non previsti
// — ed e' esattamente il caso che ha lasciato `window.globalDevices` sempre
// undefined (globalDevices e' un `let` di core.js, non una proprieta' di
// window, e non va aggiunto qui).
//
// Aggiungere una voce SOLO insieme al corrispondente `window.X = ...`.
// Rigenerabile: vedi docs/development.md.

// --- Librerie vendorizzate (static/vendor), caricate via <script src>. ---
// `var` e non `const`: sono UMD e si registrano su window, quindi il codice le
// raggiunge sia come `html2pdf` sia come `window.html2pdf`.
declare var vis: any;
declare var Chart: any;
declare var html2pdf: any;
declare var Terminal: any;
declare var FitAddon: any;

// --- Esposizioni cross-modulo (window.X = ...) ---

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

// Nomi che esistono gia' come dichiarazione top-level in un modulo e che
// vengono ANCHE riesposti su window: qui va dichiarata solo la meta' 'window',
// altrimenti si duplica l'identificatore.
interface Window {
    loadAssetOnce: any;      // core.js
    trafState: any;          // observability.js, letto da flow-analytics.js
    _vwLoaded: any;          // threat-intel.js, flag di primo caricamento
    webkitAudioContext: any; // fallback Safari legacy in devices.js
}
