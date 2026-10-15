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

// Porte: a single-MAC port opens that endpoint's drawer.
assert.ok(src.includes('function loadPortsView('), 'missing loadPortsView');
assert.ok(src.includes('data-action="ep-open-mac"'), 'single-MAC port cell must open the drawer');

// Final review fixes.
// 1. A drawer opened without a list row (Porte, terminal, cold search) takes
//    its position from the locate answer instead of showing dashes.
{
    const start = src.indexOf('function _epRowFromLocate(');
    assert.ok(start >= 0, 'missing _epRowFromLocate');
    const fn = (0, eval)(`(${src.slice(start, src.indexOf('\n}\n', start) + 2)})`);
    const loc = { mac: 'aa:bb:cc:dd:ee:01', tenant: 'sede-a', status: 'resolved',
                  origin: [{ switch_ip: '192.0.2.11', switch_name: 'switch-01', interface: 'Gi1/0/5', vlan: '10' }] };
    const r = fn({ mac: 'aabb.ccdd.ee01', tenant: '' }, loc);
    assert.equal(r.switch_ip, '192.0.2.11');
    assert.equal(r.interface, 'Gi1/0/5');
    assert.equal(r.vlan, '10');
    assert.equal(r.mac, 'aa:bb:cc:dd:ee:01', 'the normalized MAC from the answer');
    assert.equal(r.tenant, 'sede-a');
    const full = { mac: 'aa:bb:cc:dd:ee:01', tenant: 'sede-a', switch_ip: '192.0.2.99', interface: 'Gi1/0/9', vlan: '20', ips: ['192.0.2.10'] };
    assert.deepEqual(fn(full, loc), full, 'a real list row is kept as is');
    assert.deepEqual(fn({ mac: 'x', tenant: '' }, null), { mac: 'x', tenant: '' }, 'no answer: unchanged');
}
// 2. A slower answer for an older open never renders into a newer drawer.
assert.ok(src.includes('if (_epDrawer !== tok) return;'), 'openEpDrawer must guard with a per-open token');
// 3. Esc already handled by a modal does not also close the docked drawer.
assert.ok(/e\.key === 'Escape' && !e\.defaultPrevented/.test(src), 'Esc listener must skip defaultPrevented events');
// 4. The narrow-mode dialog has a name from the start.
assert.ok(/id="epDrawerHost"[^>]*aria-labelledby="epDrawerTitle"/.test(html), 'epDrawerHost needs aria-labelledby');
// 5. The Raccolta loader rebuilds the pickers (inventory refresh resets the
//    loaders), and an empty inventory never freezes the collect locations.
{
    const lr = cm.slice(cm.indexOf('function loadRaccolta('), cm.indexOf('\n    }\n', cm.indexOf('function loadRaccolta(')));
    assert.ok(lr.includes('resetDevPickers()'), 'loadRaccolta must rebuild the pickers');
    const rc = cm.slice(cm.indexOf('function renderCollectLocs('), cm.indexOf('\n}\n', cm.indexOf('function renderCollectLocs(')));
    assert.ok(rc.includes('_collectLocs === null && groups.length'), 'collect locations must wait for devices');
}
// 6. A list answer for an older request (tenant switched, filters changed)
//    never renders: both fetch paths and the tenant change bump one counter.
for (const fn of ['async function endpointsSearch(', 'async function locSearchSubmit(']) {
    const body = src.slice(src.indexOf(fn), src.indexOf('\n}\n', src.indexOf(fn)));
    assert.ok(body.includes('const seq = ++_epSeq;') && body.includes('seq !== _epSeq'), `${fn} must drop stale answers`);
}
assert.ok(tc.includes('_epSeq++'), 'locTenantChanged must invalidate in-flight searches');
// 8. Search as you type: debounced, and a live search never opens the drawer.
{
    assert.ok(/getElementById\('locSearch'\)\?\.addEventListener\('input'/.test(src), 'search box must search while typing');
    assert.ok(src.includes('setTimeout(() => locSearchSubmit(true), 300)'), 'typing search must be debounced and live');
    assert.ok(src.includes('if (!live && (d.results || []).length === 1) openEpDrawer('), 'a live search must not open the drawer');
}
// 7. Diagnosi: the tenant selected at the top scopes the gateway list and
//    the report; no call may fall back to every tenant.
{
    const dg = read('../../static/js/diagnosi.js');
    const calls = dg.match(/loadDiagGatewayCandidates\([^\n;]*\)/g).filter(c => c !== 'loadDiagGatewayCandidates(tenant)');
    assert.ok(calls.length && calls.every(c => c === 'loadDiagGatewayCandidates(_diagScopeTenant())'),
              `gateway candidates must use the scope tenant: ${calls}`);
    assert.ok(dg.includes('const tenant = _diagScopeTenant();'), 'runDiagnosi must send the scope tenant');
}

console.log('endpoint_inventory_ui: ok');
