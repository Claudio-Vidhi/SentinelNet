// Endpoint UI contracts that a DOM-less test can still pin.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const src = read('../../static/js/endpoint-inventory.js');
const cm = read('../../static/js/client-map.js');
const html = read('../../templates/dashboard.html');

// One detail UI: the drawer. The inline row and the locate modal are gone.
assert.ok(src.includes('async function openEpDrawer('), 'missing openEpDrawer');
assert.ok(src.includes('function closeEpDrawer('), 'missing closeEpDrawer');
for (const gone of ['function _renderEndpointDetailRow', 'function _toggleEndpointDetail', 'ep-row-toggle']) {
    assert.ok(!src.includes(gone), `still present: ${gone}`);
}
assert.ok(!cm.includes('function macLocate('), 'macLocate modal still present');

// Rows open the drawer, and say which endpoint they are.
assert.ok(src.includes('data-action="ep-open"'), 'rows must carry data-action="ep-open"');

// Narrow screens go through the modal manager; the host exists in the template.
assert.ok(src.includes("openModal('epDrawerHost'"), 'narrow path must use openModal');
assert.ok(html.includes('id="epDrawerHost"') && html.includes('id="epDrawer"'), 'drawer host missing in template');

// A tenant change closes the drawer: its endpoint may be out of the new scope.
const tcStart = cm.indexOf('function locTenantChanged(');
const tc = cm.slice(tcStart, cm.indexOf('\n}\n', tcStart));
assert.ok(tc.includes('closeEpDrawer()'), 'locTenantChanged must close the drawer');

// Port config summary keeps working (used by the Porte view).
const fnStart = src.indexOf('function portCfgSummary');
const portCfgSummary = (0, eval)(`(${src.slice(fnStart, src.indexOf('\n}\n', fnStart) + 2)})`);
assert.deepEqual(
    portCfgSummary('interface GigabitEthernet1/0/4\n switchport access vlan 7\n spanning-tree portfast\n shutdown\n!'),
    { text: 'switchport access vlan 7 · spanning-tree portfast', more: 1, count: 3 });

console.log('endpoint_inventory_ui: ok');
