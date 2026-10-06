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

// --- Sankey model: device -> type -> next hop, counts conserved per column,
// next hops past the cap folded into one "other" node.
{
    const { rtBuildSankey, rtDeviceOwners, rtDeviceDepths, rtHopResolver } = windowStub.rtModel;
    const via = (owners, ctx = {}) => rtHopResolver(owners, ctx, 'DIRECT');
    const rows = [r('A', '10.1.0.0/16', { gateway: '192.0.2.1' }),
                  r('A', '10.2.0.0/16', { gateway: '192.0.2.1' }),
                  r('A', '10.3.0.0/16', { type: 'ospf', gateway: '192.0.2.2' }),
                  r('B', '10.4.0.0/16', { type: 'connected', interface: 'Gi0/1' }),
                  r('B', '10.5.0.0/16', { gateway: '192.0.2.3' })];
    const devs = [{ value: 'A', label: 'switch-01' }, { value: 'B', label: 'switch-02' }];
    const opts = { cap: 2, resolve: via(new Map()), otherLabel: 'OTHER' };
    const g = rtBuildSankey(rows, devs, opts);
    assert.equal(g.total, 5);
    for (const col of g.cols) assert.equal(col.reduce((s, n) => s + n.value, 0), 5, 'every column carries every route');
    assert.deepEqual(g.cols[0].map(n => n.label), ['switch-01', 'switch-02'], 'busiest device first');
    assert.deepEqual(g.cols[1].map(n => n.label), ['static', 'ospf', 'connected', 'static'],
                     'types grouped by device, then RT_TYPE_ORDER');
    assert.deepEqual(g.cols[2].map(n => n.label), ['192.0.2.1', '192.0.2.2', 'OTHER'], 'cap 2 (ties: first seen), rest folded, other last');
    const l = g.links.find(x => x.source === 'd|A' && x.target === 't|A|static');
    assert.equal(l.value, 2);
    assert.deepEqual(l.rows.map(x => x.network), ['10.1.0.0/16', '10.2.0.0/16'], 'a ribbon carries its routes');

    // Chain: A's next hop 192.0.2.2 is B's own interface (a /32 local route),
    // so B is a stage after A and A's ribbon lands on B's node.
    const chain = [r('A', '10.1.0.0/16', { gateway: '192.0.2.2' }),
                   r('A', '10.9.0.0/16', { gateway: '192.0.2.99' }),
                   r('B', '192.0.2.2/32', { type: 'local', interface: 'Gi0/1' }),
                   r('B', '10.1.0.0/16', { gateway: '198.51.100.1' })];
    const owners = rtDeviceOwners(chain, devs);
    assert.equal(owners.get('192.0.2.2'), 'B', 'local /32 names its owner');
    assert.equal(rtDeviceDepths(chain, devs, via(owners)).get('B'), 1);
    const gc = rtBuildSankey(chain, devs, { ...opts, cap: 12, resolve: via(owners) });
    assert.equal(gc.cols.length, 5, 'two stages: A, type, B, type, hop');
    assert.equal(gc.cols[2].find(n => n.id === 'd|B').kind, 'device', 'B sits where A\'s next hops are');
    assert.ok(gc.links.some(x => x.source === 't|A|static' && x.target === 'd|B'), 'A -> static -> B');

    // A loop (A via B, B via A) still yields a finite order; the back edge
    // is drawn as a named hop, not a ribbon going backwards.
    const loop = [r('A', '10.1.0.0/16', { gateway: 'B' }), r('B', '10.2.0.0/16', { gateway: 'A' })];
    const gl = rtBuildSankey(loop, devs, { ...opts, resolve: via(rtDeviceOwners(loop, devs)) });
    const colOf = id => gl.cols.flat().find(n => n.id === id).col;
    assert.ok(gl.links.every(x => colOf(x.target) > colOf(x.source)), 'every ribbon goes right');
    assert.ok(gl.cols.flat().some(n => n.label === 'A · switch-01'), 'back edge named after its device');

    // FortiGate: no local routes, its addresses come from the REST interface
    // list; a route into an IPsec tunnel has no gateway, only the tunnel name,
    // and the tunnel's remote gateway is the next hop (here: firewall B).
    const ctx = {
        A: { addresses: [], tunnels: [{ name: 'vpn-b', remote_gw: '203.0.113.2', up: false }] },
        B: { addresses: [{ iface: 'wan1', ip: '203.0.113.2', network: '203.0.113.0/24' }], tunnels: [] },
    };
    const fw = [r('A', '10.20.0.0/16', { gateway: '0.0.0.0', interface: 'vpn-b' }),
                r('A', '10.21.0.0/16', { gateway: '0.0.0.0', interface: 'vpn-other' }),
                r('B', '10.20.0.0/16', { type: 'connected', interface: 'internal' })];
    const fwOwners = rtDeviceOwners(fw, devs, ctx);
    assert.equal(fwOwners.get('203.0.113.2'), 'B', 'interface address names the firewall');
    const resolve = via(fwOwners, ctx);
    assert.deepEqual(resolve(fw[0]).to, 'B', 'the tunnel leads to B');
    assert.equal(resolve(fw[1]).label, 'vpn-other', 'an unknown tunnel stays its interface name');
    assert.equal(resolve(r('A', '10.0.0.0/8', { gateway: '0.0.0.0' })).label, 'DIRECT', '0.0.0.0 is no gateway');
    const gf = rtBuildSankey(fw, devs, { ...opts, cap: 12, resolve });
    const tl = gf.links.find(x => x.target === 'd|B');
    assert.ok(tl && tl.tunnel === 'vpn-b' && tl.down === true, 'ribbon into a down tunnel is marked');
    const remote = rtHopResolver(new Map(), ctx, 'DIRECT')(fw[0]);
    assert.equal(remote.label, 'vpn-b ⇢ 203.0.113.2', 'remote gateway outside the selection is named');

    // SD-WAN: a default route over two members; the ribbon and the hop carry
    // the member's state, worst wins when both feed the same hop.
    const sdCtx = { A: { addresses: [], tunnels: [], sdwan: [
        { interface: 'wan1', state: 'up', checks: [] },
        { interface: 'wan2', state: 'degraded', checks: [] }] } };
    const sd = [r('A', '0.0.0.0/0', { gateway: '198.51.100.1', interface: 'wan1' }),
                r('A', '0.0.0.0/0', { gateway: '198.51.100.9', interface: 'wan2' }),
                r('A', '10.30.0.0/16', { gateway: '198.51.100.9', interface: 'wan2' })];
    const gs = rtBuildSankey(sd, devs, { ...opts, cap: 12, resolve: via(new Map(), sdCtx) });
    const hop = id => gs.cols.flat().find(n => n.id === id);
    assert.equal(hop('h|2|198.51.100.1 · wan1').state, 'up');
    assert.equal(hop('h|2|198.51.100.9 · wan2').state, 'degraded', 'member state reaches the hop');
    const sl = gs.links.find(x => x.target === 'h|2|198.51.100.9 · wan2');
    assert.equal(sl.state, 'degraded');
    assert.equal(sl.sdwan.interface, 'wan2');
    assert.equal(gs.links.find(x => x.target === 't|A|static').state, undefined,
                 'the device -> type ribbon has no member of its own');

    // Policy routes: only enabled 'permit' ones become rows, of type
    // 'policy', and the search box reads their destinations.
    const { rtPolicyRows, rtPolicyMatches, rtQuery } = windowStub.rtModel;
    const pctx = { A: { policy_routes: [
        { seq: 1, enabled: true, permit: true, input: ['internal'], src: ['10.10.0.0/24'],
          dst: ['198.51.100.0/24'], gateway: '203.0.113.254', output: 'wan2', comment: '' },
        { seq: 2, enabled: false, permit: true, input: [], src: [], dst: [], gateway: '', output: 'wan1', comment: '' },
        { seq: 3, enabled: true, permit: false, input: [], src: [], dst: [], gateway: '', output: '', comment: '' },
        { seq: 4, enabled: true, permit: true, input: [], src: [], dst: [], gateway: '203.0.113.1', output: 'wan1', comment: '' }] } };
    const prs = rtPolicyRows(pctx, devs);
    assert.deepEqual(prs.map(x => x.policy.seq), [1, 4], 'disabled and deny are not paths');
    assert.equal(prs[0].type, 'policy');
    assert.equal(prs[0].network, '198.51.100.0/24');
    assert.equal(prs[1].network, '0.0.0.0/0', 'no destination = any');
    assert.ok(prs[0].raw_type.includes('src 10.10.0.0/24') && prs[0].raw_type.includes('in internal'));
    assert.ok(rtPolicyMatches(prs[0], rtQuery('198.51.100.7')), 'address inside the policy dst');
    assert.ok(!rtPolicyMatches(prs[0], rtQuery('192.0.2.7')));
    assert.ok(rtPolicyMatches(prs[1], rtQuery('192.0.2.7')), 'any matches every address');
    assert.ok(rtPolicyMatches(prs[0], rtQuery('wan2')), 'free text reads the output interface');
}

console.log('ok');
