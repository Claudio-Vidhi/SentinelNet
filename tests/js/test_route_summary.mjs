// static/js/routes-view.js: the per-device route summary and the anomaly
// list of the "Riepilogo apparati" view, run against synthetic rows.
//
//   node tests/js/test_route_summary.mjs
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

const { rtSummaryByDevice, rtAnomalies } = windowStub.rtModel;

const row = (device_ip, network, gateway, type, extra = {}) => ({
    device_ip, device: device_ip, network, gateway, interface: 'port1', type,
    vrf: '', from_backup: false, disabled: false, blackhole: false, ...extra });
const A = '192.0.2.10', B = '192.0.2.20', C = '192.0.2.30';
const kinds = (list, ip) => list.filter(x => x.ip === ip).map(x => x.kind).sort();

// --- A: a connected net, a default, a static whose hop is on no connected net.
const rowsA = [
    row(A, '192.0.2.0/24', '0.0.0.0', 'connected'),
    row(A, '0.0.0.0/0', '192.0.2.1', 'static'),
    row(A, '198.51.100.0/24', '203.0.113.9', 'static'),
];
let [sA] = rtSummaryByDevice(rowsA);
assert.equal(sA.ip, A);
assert.equal(sA.total, 3);
assert.equal(sA.byType.static, 2);
assert.equal(sA.byType.connected, 1);
assert.deepEqual(sA.defaults, [{ gateway: '192.0.2.1', interface: 'port1' }]);
assert.equal(sA.ecmp, 0);
assert.equal(sA.fromBackup, false);
let an = rtAnomalies(rowsA, new Set([A]));
assert.deepEqual(an, [{ ip: A, kind: 'hop-unreachable', network: '198.51.100.0/24', gateway: '203.0.113.9' }]);

// --- B: no 0/0 -> no-default. An address-object name is not a default.
const rowsB = [row(B, '10.0.0.0/8', '192.0.2.1', 'static'), row(B, 'branch-nets', '', 'static')];
assert.deepEqual(kinds(rtAnomalies(rowsB, new Set([B])), B), ['no-default']);
assert.deepEqual(rtSummaryByDevice(rowsB)[0].defaults, []);
// A disabled default is not a default.
assert.deepEqual(kinds(rtAnomalies([row(B, '0.0.0.0/0', '192.0.2.1', 'static', { disabled: true })],
                                    new Set([B])), B), ['no-default']);

// --- Two identical rows (vrf, network, gateway) -> one duplicate.
const dup = [row(B, '0.0.0.0/0', '192.0.2.1', 'static'),
             row(B, '10.0.0.0/8', '192.0.2.1', 'static'),
             row(B, '10.0.0.0/8', '192.0.2.1', 'static')];
an = rtAnomalies(dup, new Set([B]));
assert.deepEqual(an.filter(x => x.kind === 'duplicate'),
                 [{ ip: B, kind: 'duplicate', network: '10.0.0.0/8', gateway: '192.0.2.1' }]);
// Same prefix in another VRF is not a duplicate.
an = rtAnomalies([dup[0], dup[1], row(B, '10.0.0.0/8', '192.0.2.1', 'static', { vrf: 'mgmt' })], new Set([B]));
assert.equal(an.filter(x => x.kind === 'duplicate').length, 0);

// --- A live + a backup global static -> static-missing.
const bk = extra => row(A, '203.0.113.0/24', '192.0.2.254', 'static', { from_backup: true, ...extra });
an = rtAnomalies([...rowsA.slice(0, 2), bk()], new Set([A]));
assert.deepEqual(an, [{ ip: A, kind: 'static-missing', network: '203.0.113.0/24', gateway: '192.0.2.254' }]);
for (const extra of [{ disabled: true }, { blackhole: true, gateway: '' }, { vrf: 'mgmt' },
                     { network: 'branch-nets' }]) {
    an = rtAnomalies([...rowsA.slice(0, 2), bk(extra)], new Set([A]));
    assert.deepEqual(an, [], JSON.stringify(extra));
}

// --- C: backup rows only, not live -> no static-missing (absence proves nothing).
const rowsC = [row(C, '0.0.0.0/0', '192.0.2.1', 'static', { from_backup: true }),
               row(C, '198.51.100.0/24', '192.0.2.254', 'static', { from_backup: true })];
an = rtAnomalies(rowsC, new Set());
assert.deepEqual(an, []);
assert.equal(rtSummaryByDevice(rowsC)[0].fromBackup, true);

// --- Same prefix, two gateways -> one ECMP prefix.
const ecmp = [row(B, '0.0.0.0/0', '192.0.2.1', 'static'), row(B, '0.0.0.0/0', '192.0.2.2', 'static'),
              row(B, '10.0.0.0/8', '192.0.2.1', 'static')];
const sB = rtSummaryByDevice(ecmp)[0];
assert.equal(sB.ecmp, 1);
assert.equal(sB.defaults.length, 2);
assert.deepEqual(sB.topHops, [{ hop: '192.0.2.1', n: 2 }, { hop: '192.0.2.2', n: 1 }]);

// --- No connected rows -> nothing to judge a hop against.
assert.deepEqual(rtAnomalies([row(B, '0.0.0.0/0', '203.0.113.9', 'static')], new Set([B])), []);

// --- topHops keeps five at most; on-link gateways are not hops.
const many = ['1', '2', '3', '4', '5', '6'].map(h => row(B, `10.${h}.0.0/16`, `192.0.2.${h}`, 'static'));
many.push(row(B, '192.0.2.0/24', '0.0.0.0', 'connected'));
assert.equal(rtSummaryByDevice(many)[0].topHops.length, 5);
assert.ok(!rtSummaryByDevice(many)[0].topHops.some(h => h.hop === '0.0.0.0'));

// Devices keep their first-seen order.
assert.deepEqual(rtSummaryByDevice([...rowsB, ...rowsA]).map(s => s.ip), [B, A]);

// --- SD-WAN default: backup gw '' vs live member gw on the same prefix -> no static-missing.
const sdwan = [row(A, '192.0.2.0/24', '0.0.0.0', 'connected'),
               row(A, '0.0.0.0/0', '192.0.2.1', 'static'),
               row(A, '0.0.0.0/0', '', 'static', { from_backup: true, interface: 'virtual-wan-link' })];
an = rtAnomalies(sdwan, new Set([A]));
assert.deepEqual(an, []);

// --- Device answered live: ECMP and defaults ignore its backup rows.
const sLive = rtSummaryByDevice(sdwan, new Set([A]))[0];
assert.equal(sLive.ecmp, 0);
assert.deepEqual(sLive.defaults, [{ gateway: '192.0.2.1', interface: 'port1' }]);
assert.equal(sLive.total, 3);
// Not live: the backup rows are all there is.
assert.equal(rtSummaryByDevice(sdwan, new Set())[0].defaults.length, 2);

// --- Dual-tunnel ECMP: same prefix, on-link gw, two tunnel interfaces.
const tun = [row(B, '0.0.0.0/0', '192.0.2.1', 'static'),
             row(B, '10.0.0.0/8', '0.0.0.0', 'static', { interface: 'tun1' }),
             row(B, '10.0.0.0/8', '0.0.0.0', 'static', { interface: 'tun2' })];
assert.equal(rtAnomalies(tun, new Set([B])).filter(x => x.kind === 'duplicate').length, 0);
assert.equal(rtSummaryByDevice(tun)[0].ecmp, 1);
// '' and '0.0.0.0' on the same interface are the same next hop: not ECMP.
assert.equal(rtSummaryByDevice([row(B, '10.0.0.0/8', '0.0.0.0', 'static', { interface: 'tun1' }),
                                row(B, '10.0.0.0/8', '', 'static', { interface: 'tun1' })])[0].ecmp, 0);

// --- Backup-only device without 0/0 -> no no-default (DHCP/PPPoE default is not in the config).
assert.deepEqual(rtAnomalies([row(C, '10.0.0.0/8', '192.0.2.1', 'static', { from_backup: true })],
                             new Set()), []);

console.log('route summary: ok');
