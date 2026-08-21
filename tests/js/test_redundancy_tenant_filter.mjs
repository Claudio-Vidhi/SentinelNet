// static/js/redundancy.js: the HA tab groups its cards by tenant and filters
// them with the tenant select. A source-text grep would not catch the two ways
// this actually breaks — the KPI tiles staying on the whole fleet while the
// list shows one tenant, and the "all tenants" option being rebuilt away when
// the select is repopulated — so this runs the real module against a DOM stub.
//
//   node tests/js/test_redundancy_tenant_filter.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/redundancy.js'), 'utf8');

// --- DOM stub: only what the module actually touches ------------------------

class OptionStub {
    constructor(label, value) { this.text = label; this.value = value; }
}

class SelectStub {
    constructor() {
        this.id = 'haTenantFilter';   // the delegated handler dispatches on it
        this.opts = [new OptionStub('Tutti i tenant', '')];
        this.value = '';
    }
    get length() { return this.opts.length; }
    set length(n) { this.opts.length = n; }
    add(opt) { this.opts.push(opt); }
    values() { return this.opts.map(o => o.value); }
}

const container = { innerHTML: '' };
const select = new SelectStub();
const kpi = {
    haKpiTotal: { textContent: '' },
    haKpiHealthy: { textContent: '' },
    haKpiDegraded: { textContent: '' },
    haKpiCritical: { textContent: '' },
};
const nodes = { redundancyGroupsContainer: container, haTenantFilter: select, ...kpi };

const listeners = {};
const documentStub = {
    getElementById: (id) => nodes[id] || null,
    addEventListener: (type, fn) => { (listeners[type] ||= []).push(fn); },
};

let served = [];
const apiFetch = async () => ({ ok: true, json: async () => ({ results: served }) });
const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const load = (0, eval)(`(function (document, apiFetch, escapeHtml, currentRole, window, Option) {
    ${src}
    return window.loadRedundancyTab;
})`)(documentStub, apiFetch, escapeHtml, 'admin', {}, OptionStub);

const fireChange = () => listeners.change.forEach(fn => fn({ target: select }));

// --- Fixtures ---------------------------------------------------------------

const GROUPS = [
    { id: 1, group_name: 'sede-b', group_type: 'stack', name: 'stack-b',
      health: 'ok', logical_device_ip: '192.0.2.20', members: [] },
    { id: 2, group_name: 'sede-a', group_type: 'ha_pair', name: 'ha-a',
      health: 'degraded', virtual_ip: '192.0.2.1', members: [] },
    { id: 3, group_name: 'sede-a', group_type: 'stack', name: 'stack-a',
      health: 'ok', logical_device_ip: '192.0.2.10', members: [] },
];

// --- Every tenant is its own section, in a stable order ---------------------

served = GROUPS;
await load();

const sections = container.innerHTML.match(/<section /g) || [];
assert.equal(sections.length, 2, 'one section per tenant');
assert.ok(container.innerHTML.indexOf('sede-a') < container.innerHTML.indexOf('sede-b'),
    'tenant sections are sorted, so the same customer is always in the same place');
assert.ok(container.innerHTML.includes('2 cluster'), 'sede-a shows its cluster count');
assert.ok(container.innerHTML.includes('1 da verificare'),
    'a tenant with a degraded cluster says so in its header');

// The select keeps the template option 0 (it carries the data-i18n) and gains
// one option per tenant.
assert.deepEqual(select.values(), ['', 'sede-a', 'sede-b']);

// Unfiltered KPIs describe the whole (already scoped) fleet.
assert.equal(kpi.haKpiTotal.textContent, 3);
assert.equal(kpi.haKpiHealthy.textContent, 2);
assert.equal(kpi.haKpiDegraded.textContent, 1);

// --- Filtering narrows both the cards AND the KPI tiles ---------------------

select.value = 'sede-b';
fireChange();
assert.ok(container.innerHTML.includes('sede-b'));
assert.ok(!container.innerHTML.includes('sede-a'),
    'the other tenant is gone from the list');
assert.equal(kpi.haKpiTotal.textContent, 1,
    'KPIs follow the filter: a degraded cluster must not be attributed to the wrong tenant');
assert.equal(kpi.haKpiDegraded.textContent, 0);

// --- A refresh keeps the chosen tenant --------------------------------------

await load();
assert.equal(select.value, 'sede-b', 'refresh must not silently widen the view');
assert.deepEqual(select.values(), ['', 'sede-a', 'sede-b'],
    'repopulating does not duplicate or drop the "all tenants" option');
assert.equal(kpi.haKpiTotal.textContent, 1);

// --- A tenant that lost its last group falls back to "all" ------------------

served = [GROUPS[1], GROUPS[2]];   // sede-b has no group any more
await load();
assert.equal(select.value, '', 'a tenant with no option left cannot stay selected');
assert.equal(kpi.haKpiTotal.textContent, 2);

// --- Empty states distinguish "no data" from "filtered out" -----------------

served = [GROUPS[0]];              // only sede-b exists
await load();
select.value = 'sede-b';
fireChange();
served = [GROUPS[1]];              // sede-b is gone, but the operator re-picks it
await load();
select.value = 'sede-b';
fireChange();
assert.ok(container.innerHTML.includes('Nessun gruppo di ridondanza per il tenant'),
    'an empty tenant says it is empty');
assert.ok(!container.innerHTML.includes('Crea Gruppo HA'),
    'a filtered-out view must not offer "create your first group": that reads as data loss');

served = [];
await load();
assert.ok(container.innerHTML.includes('Nessun gruppo di ridondanza registrato'),
    'a genuinely empty install keeps its onboarding empty state');

console.log('ok');
