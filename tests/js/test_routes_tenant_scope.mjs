// static/js/routes-view.js: the device picker of the Routing Tables tab is
// scoped by the global tenant selector. A grep would not catch the two ways
// this breaks — the picker still listing another tenant's devices, and the
// rows of the previous tenant staying on screen after the switch — so this
// runs the real module against a DOM stub.
//
//   node tests/js/test_routes_tenant_scope.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/routes-view.js'), 'utf8');

// Every render function early-returns on a missing element, so a document
// that knows no ids exercises the data path alone.
const documentStub = { getElementById: () => null, addEventListener: () => {} };

const DEVICES = [
    { ip: '192.0.2.1', hostname: 'fw-a', group: 'sede-a', vendor: 'x' },
    { ip: '192.0.2.2', hostname: 'sw-a', group: 'sede-a', vendor: 'x' },
    { ip: '198.51.100.1', hostname: 'fw-b', group: 'sede-b', vendor: 'x' },
];

const apiFetch = async () => ({ ok: true, json: async () => ({ devices: DEVICES }) });

let rendered = null;
const renderPickerItems = (id, items) => { rendered = items; };

const windowListeners = {};
const windowStub = {
    globalSelectedTenant: 'all',
    addEventListener: (t, fn) => { (windowListeners[t] ||= []).push(fn); },
};

(0, eval)(`(function (document, window, apiFetch, renderPickerItems, pickerValues,
                      pickerSelected, escapeHtml, tr, setTimeout, clearTimeout) {
    ${src}
})`)(documentStub, windowStub, apiFetch, renderPickerItems, () => [], () => [],
     String, () => '', () => 0, () => {});

const fireTenant = async (tenant) => {
    windowStub.globalSelectedTenant = tenant;
    for (const fn of windowListeners.globalTenantChanged) await fn();
};

// 'all' means the whole scope the backend already granted: no extra filter.
await windowStub.loadRoutesTab();
assert.equal(rendered.length, 3, 'tenant "all" must not drop devices');

await fireTenant('sede-a');
assert.deepEqual(rendered.map(i => i.value), ['192.0.2.1', '192.0.2.2'],
    'picker must list only the selected tenant devices');

await fireTenant('sede-b');
assert.deepEqual(rendered.map(i => i.value), ['198.51.100.1']);

await fireTenant('all');
assert.equal(rendered.length, 3, 'going back to "all" must restore the list');

console.log('ok');
