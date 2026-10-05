// static/js/routes-view.js: the prefix x device matrix and the address
// lookup. The view's whole claim is "this device has no route for that
// prefix", so the model behind it is run for real against synthetic rows:
// longest-prefix match, covering routes, holes, and the devices whose
// absence proves nothing.
//
//   node tests/js/test_routes_matrix.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/routes-view.js'), 'utf8');

const documentStub = { getElementById: () => null, addEventListener: () => {} };
const windowStub = { addEventListener: () => {} };
(0, eval)(`(function (document, window, apiFetch, renderPickerItems, pickerValues,
                      pickerSelected, escapeHtml, tr) {
    ${src}
})`)(documentStub, windowStub, async () => null, () => {}, () => [], () => [],
     String, () => '');

const { ip4, parseNet, rtLpm, rtBuildMatrix, rtQuery, rtMatches } = windowStub.rtModel;

// --- parsing
assert.equal(ip4('192.0.2.1'), 0xC0000201);
assert.equal(ip4('256.0.0.1'), null);
assert.equal(ip4('10.0.0'), null);
assert.deepEqual(parseNet('10.1.2.3/16'), { net: ip4('10.1.0.0'), len: 16, bits: 0xFFFF0000 });
assert.equal(parseNet('10.0.0.0 255.255.255.0').len, 24, 'dotted mask');
assert.equal(parseNet('0.0.0.0/0').len, 0);
assert.equal(parseNet('10.0.0.0/33'), null);

// --- longest-prefix match, then distance, ties kept (ECMP)
const r = (device_ip, network, extra = {}) =>
    ({ device: device_ip, device_ip, network, vrf: '', gateway: '', interface: '',
       type: 'static', distance: 1, metric: 0, from_backup: false, ...extra });
const a = [r('A', '0.0.0.0/0'), r('A', '10.0.0.0/8', { distance: 110 }),
           r('A', '10.30.0.0/16', { distance: 20 }), r('A', '10.30.0.0/16', { distance: 1 })];
const win = rtLpm(a, ip4('10.30.0.7'));
assert.equal(win.length, 1);
assert.equal(win[0].network, '10.30.0.0/16');
assert.equal(win[0].distance, 1, 'same prefix: lowest distance wins');
assert.equal(rtLpm(a, ip4('192.0.2.9'))[0].network, '0.0.0.0/0');
assert.equal(rtLpm([r('A', '10.0.0.0/8', { gateway: 'x' }), r('A', '10.0.0.0/8', { gateway: 'y' })],
                   ip4('10.1.1.1')).length, 2, 'ECMP keeps both');

// --- matrix: present / covered / hole / unknown
const devs = [{ value: 'A', label: 'a' }, { value: 'B', label: 'b' },
              { value: 'C', label: 'c' }, { value: 'D', label: 'd' }];
const rows = [
    r('A', '10.30.0.0/16'),
    r('B', '0.0.0.0/0'),                           // covers 10.30/16 on B
    r('C', '192.0.2.0/24', { type: 'connected' }), // C has no cover for 10.30/16
    r('D', '10.30.0.0/16', { from_backup: true }), // only backup: unknown elsewhere
];
const mx = rtBuildMatrix(rows, devs, new Set(['D']));
const e = mx.find(x => x.network === '10.30.0.0/16');
assert.ok(e.cells.A && e.cells.D, 'own rows sit in their cells');
assert.equal(e.cover.B.network, '0.0.0.0/0', 'B reaches it via the default');
assert.equal(e.cover.C, 'hole', 'C has nothing covering it');
assert.equal(e.missing, 2);
assert.equal(e.holes, 1);
const dflt = mx.find(x => x.network === '0.0.0.0/0');
assert.equal(dflt.cover.D, 'unknown', 'absence on a backup-only device proves nothing');
assert.equal(dflt.cover.A, 'hole');

// VRFs are separate tables: a default in VRF red does not cover the global one.
const vrf = rtBuildMatrix([r('A', '10.0.0.0/8'), r('B', '0.0.0.0/0', { vrf: 'red' })],
                          devs.slice(0, 2), new Set());
assert.equal(vrf.find(x => x.network === '10.0.0.0/8').cover.B, 'hole');

// --- the search box
assert.equal(rtQuery('10.30.0.7').kind, 'ip');
assert.equal(rtQuery('10.30.0.0/16').kind, 'net');
assert.equal(rtQuery('Gi0/1').kind, 'text', 'an interface name is not a prefix');
assert.equal(rtQuery('  ').kind, 'none');
assert.ok(rtMatches(e, rtQuery('10.30.200.1')), 'address inside the prefix');
assert.ok(!rtMatches(e, rtQuery('10.31.0.1')));
assert.ok(rtMatches(e, rtQuery('10.0.0.0/8')), 'query wider than the prefix overlaps');
assert.ok(rtMatches(e, rtQuery('10.30.5.0/24')), 'query narrower than the prefix overlaps');
assert.ok(!rtMatches(e, rtQuery('10.31.0.0/16')));
const withHop = rtBuildMatrix([r('A', '198.51.100.0/24', { interface: 'port3' })],
                              devs.slice(0, 1), new Set())[0];
assert.ok(rtMatches(withHop, rtQuery('PORT3')), 'text matches the interface, case-insensitive');

// A more specific route must not hide the covering one: B has the /8 and a
// /25 inside the /24 that only A has, so B covers the /24 via the /8.
const masked = rtBuildMatrix([r('A', '10.9.0.0/24'), r('B', '10.0.0.0/8'), r('B', '10.9.0.0/25')],
                             [{ value: 'A' }, { value: 'B' }], new Set())
    .find(x => x.network === '10.9.0.0/24');
assert.equal(masked.cover.B.network, '10.0.0.0/8', 'covered, not a hole');
assert.equal(parseNet('10.0.0.0/'), null, 'trailing slash while typing is not /0');
assert.equal(rtQuery('10.0.0.0/').kind, 'text');

console.log('ok');
