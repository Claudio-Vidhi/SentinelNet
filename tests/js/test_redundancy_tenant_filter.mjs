// static/js/redundancy.js: la scheda HA raggruppa i cluster per tenant e li
// filtra con il selettore GLOBALE in alto. Non ne ha uno proprio.
//
// Il bug che questo file fissa, e che si vedeva a schermo: la select locale
// era popolata con i soli tenant che POSSEDEVANO un gruppo HA. Scegliere in
// alto un tenant senza gruppi scriveva su una option inesistente -- un no-op
// silenzioso -- e il pannello ripiegava su "tutti i tenant", mostrando i
// cluster di un altro cliente sotto un'intestazione che diceva il primo.
// Funzionava solo per i tenant che avevano un gruppo.
//
// Un grep sul sorgente non prenderebbe nessuno dei due modi in cui questo si
// rompe (i KPI che restano su tutta la flotta mentre la lista mostra un
// tenant, e lo scope globale ignorato), quindi qui gira il modulo vero contro
// un DOM finto.
//
//   node tests/js/test_redundancy_tenant_filter.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/redundancy.js'), 'utf8');

// --- DOM stub: solo cio' che il modulo tocca davvero -----------------------

const container = { innerHTML: '' };
const kpi = {
    haKpiTotal: { textContent: '' },
    haKpiHealthy: { textContent: '' },
    haKpiDegraded: { textContent: '' },
    haKpiCritical: { textContent: '' },
};
const nodes = { redundancyGroupsContainer: container, ...kpi };

const documentStub = {
    getElementById: (id) => nodes[id] || null,
    addEventListener: () => {},
};

let served = [];
const apiFetch = async () => ({ ok: true, json: async () => ({ results: served }) });
const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const windowStub = {};
const Option = function (label, value) { this.text = label; this.value = value; };
// Se qualcuno rimette una select locale, questa esplode invece di passare.
const tenantSelectSeed = () => { throw new Error('questa scheda non ha una select da seminare'); };

(0, eval)(`(function (document, apiFetch, escapeHtml, currentRole, window, Option, tenantSelectSeed) {
    ${src}
})`)(documentStub, apiFetch, escapeHtml, 'admin', windowStub, Option, tenantSelectSeed);

const load = windowStub.loadRedundancyTab;
const tenantChanged = windowStub.redundancyTenantChanged;
assert.equal(typeof load, 'function');
assert.equal(typeof tenantChanged, 'function',
    'il selettore globale ha bisogno di un punto da chiamare al cambio di scope');

// --- Fixture: sede-b ha un gruppo, sede-a due, sede-senza-ha nessuno -------

const GROUPS = [
    { id: 1, group_name: 'sede-b', group_type: 'stack', name: 'stack-b',
      health: 'ok', logical_device_ip: '192.0.2.20', members: [] },
    { id: 2, group_name: 'sede-a', group_type: 'ha_pair', name: 'ha-a',
      health: 'degraded', virtual_ip: '192.0.2.1', members: [] },
    { id: 3, group_name: 'sede-a', group_type: 'stack', name: 'stack-a',
      health: 'ok', logical_device_ip: '192.0.2.10', members: [] },
];

// --- Senza scope: ogni tenant e' una sezione, in ordine stabile -----------

served = GROUPS;
windowStub.globalSelectedTenant = 'all';
await load();

const sections = container.innerHTML.match(/<section /g) || [];
assert.equal(sections.length, 2, 'una sezione per tenant');
assert.ok(container.innerHTML.indexOf('sede-a') < container.innerHTML.indexOf('sede-b'),
    'le sezioni sono ordinate, cosi\' lo stesso cliente sta sempre nello stesso posto');
assert.ok(container.innerHTML.includes('2 cluster'), 'sede-a mostra il proprio conteggio');
assert.ok(container.innerHTML.includes('1 da verificare'),
    'un tenant con un cluster degradato lo dice nella propria intestazione');

// I KPI senza filtro descrivono tutta la flotta (gia' filtrata dall'API).
assert.equal(kpi.haKpiTotal.textContent, 3);
assert.equal(kpi.haKpiHealthy.textContent, 2);
assert.equal(kpi.haKpiDegraded.textContent, 1);

// --- Lo scope globale restringe le card E i KPI ---------------------------

windowStub.globalSelectedTenant = 'sede-b';
tenantChanged();
assert.ok(container.innerHTML.includes('sede-b'));
assert.ok(!container.innerHTML.includes('sede-a'),
    'l\'altro tenant e\' sparito dalla lista');
assert.equal(kpi.haKpiTotal.textContent, 1,
    'i KPI seguono il filtro: un cluster degradato non va attribuito al cliente sbagliato');
assert.equal(kpi.haKpiDegraded.textContent, 0);

// --- Un refresh non riapre la vista su tutti ------------------------------

await load();
assert.equal(kpi.haKpiTotal.textContent, 1, 'il refresh non allarga lo scope in silenzio');
assert.ok(!container.innerHTML.includes('sede-a'));

// --- IL BUG: un tenant SENZA gruppi HA -----------------------------------
//
// Prima il pannello ripiegava su "tutti", quindi qui si vedevano i cluster di
// sede-a e sede-b sotto un'intestazione che diceva "sede-senza-ha".

windowStub.globalSelectedTenant = 'sede-senza-ha';
tenantChanged();
assert.ok(!container.innerHTML.includes('sede-a'),
    'un tenant senza gruppi non deve mostrare i cluster di un altro cliente');
assert.ok(!container.innerHTML.includes('sede-b'),
    'nemmeno quelli del secondo');
assert.equal(kpi.haKpiTotal.textContent, 0, 'e i KPI dicono zero, non tutta la flotta');
assert.ok(container.innerHTML.includes('Nessun gruppo di ridondanza per il tenant'),
    'lo dice invece di mostrare altro');
assert.ok(!container.innerHTML.includes('Crea Gruppo HA'),
    'una vista filtrata non offre "crea il tuo primo gruppo": si legge come perdita di dati');

// --- Un'installazione davvero vuota tiene il proprio onboarding -----------

served = [];
windowStub.globalSelectedTenant = 'all';
await load();
assert.ok(container.innerHTML.includes('Nessun gruppo di ridondanza registrato'),
    'vuoto per davvero e vuoto per filtro sono due schermate diverse');

// --- 'all' e assente sono la stessa cosa ---------------------------------

served = GROUPS;
delete windowStub.globalSelectedTenant;
await load();
assert.equal(kpi.haKpiTotal.textContent, 3,
    'nessuno scope scelto significa tutta la flotta, non nessun cluster');

console.log('ok - lo scope della scheda HA viene dal selettore globale, per ogni tenant');
