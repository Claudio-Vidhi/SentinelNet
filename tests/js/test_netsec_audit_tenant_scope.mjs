// static/js/netsec-audit.js: the target-device dropdown follows the global
// tenant selector. It listed the whole inventory whatever tenant was chosen,
// and did not rebuild when the tenant changed.
//
//   node tests/js/test_netsec_audit_tenant_scope.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/netsec-audit.js'), 'utf8');

const select = { innerHTML: '', value: 'all', options: [{ value: 'all' }] };
const documentStub = {
    getElementById: (id) => (id === 'auditDeviceSelect' ? select : null),
    querySelectorAll: () => [],
    addEventListener: () => {},
    createElement: () => ({}),
};
const handlers = {};
const windowStub = { addEventListener: (name, fn) => { handlers[name] = fn; } };

const DEVICES = [
    { IP: '192.0.2.10', Hostname: 'switch-01', Vendor: 'cisco', Group: 'sede-a' },
    { IP: '192.0.2.20', Hostname: 'fw-01', Vendor: 'fortinet', Group: 'sede-b' },
    { IP: '192.0.2.30', Hostname: 'srv-01', Vendor: 'windows' },   // no Group -> Generale
];
const apiFetch = async (url) => ({
    ok: url === '/api/local-devices',
    json: async () => ({ devices: DEVICES }),
});
const escapeHtml = (s) => String(s ?? '');
const tr = (k) => k;

(0, eval)(`(function (document, window, apiFetch, escapeHtml, tr, currentLang, i18n) {
    ${src}
})`)(documentStub, windowStub, apiFetch, escapeHtml, tr, 'en', { en: {} });

assert.equal(typeof handlers.globalTenantChanged, 'function',
    'the dropdown must rebuild when the global tenant changes');

async function optionsFor(tenant) {
    windowStub.globalSelectedTenant = tenant;
    await handlers.globalTenantChanged();
    return (select.innerHTML.match(/value="192\.0\.2\.\d+"/g) || []).sort();
}

assert.deepEqual(await optionsFor('all'),
    ['value="192.0.2.10"', 'value="192.0.2.20"', 'value="192.0.2.30"']);
assert.deepEqual(await optionsFor('sede-a'), ['value="192.0.2.10"']);
assert.deepEqual(await optionsFor('Generale'), ['value="192.0.2.30"']);

console.log('ok');
