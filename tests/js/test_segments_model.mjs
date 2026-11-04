// Network segments model in static/js/topology.js (plan 2026-11-03):
// membership, gateways, findings and the "detect" proposal.
//
//   node tests/js/test_segments_model.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/topology.js'), 'utf8');

function extract(marker) {
    const start = src.indexOf(marker);
    assert.ok(start > 0, `${marker} not found in topology.js`);
    let depth = 0;
    for (let j = src.indexOf('{', start); j < src.length; j++) {
        if (src[j] === '{') depth++;
        else if (src[j] === '}' && --depth === 0) return src.slice(start, j + 1) + ';';
    }
    throw new Error(`unbalanced braces after ${marker}`);
}

const { segmentModel, proposeSegments, ladderSegmentColumns } = new Function(
    ['const LADDER_MAX_DEPTH = 4;', extract('const ip4n ='), extract('const inCidr ='), extract('function segmentModel('),
     extract('function proposeSegments('), extract('function ladderSegmentColumns(')].join('\n')
    + '\nreturn { segmentModel, proposeSegments, ladderSegmentColumns };')();

// Synthetic site: IT dual core + access, an OT ring behind its firewall,
// and a WLC cabled straight into an OT switch (the bypass).
const N = (id, device_type = 'switch') => ({ id, device_type });
const nodes = [
    N('10.0.0.1'), N('10.0.0.2'),                      // cores
    N('10.0.1.11'), N('10.0.1.12'),                    // IT access
    N('10.0.0.50', 'wlc'),
    N('10.0.0.10', 'firewall'),                         // OT firewall
    N('10.20.0.1'), N('10.20.0.2'), N('10.20.0.3'),     // OT ring
];
const L = (source, target) => ({ source, target });
const bypass = [L('10.20.0.2', '10.0.0.50'), L('10.0.0.50', '10.20.0.2')];   // parallel cables
const clean = [
    L('10.0.0.1', '10.0.0.2'),
    L('10.0.0.1', '10.0.1.11'), L('10.0.0.2', '10.0.1.11'),
    L('10.0.0.1', '10.0.1.12'), L('10.0.0.2', '10.0.1.12'),
    L('10.0.0.2', '10.0.0.50'),
    L('10.0.0.1', '10.0.0.10'), L('10.0.0.2', '10.0.0.10'),
    L('10.0.0.10', '10.20.0.1'),
    L('10.20.0.1', '10.20.0.2'), L('10.20.0.2', '10.20.0.3'), L('10.20.0.3', '10.20.0.1'),
];
const links = [...clean, ...bypass];
const cores = ['10.0.0.1', '10.0.0.2'];
const ot = { id: 'ot', subnets: ['10.20.0.0/24'], members: ['10.0.0.10'], excluded: [] };
const seg = (segments, decided = []) => ({ segments, links: decided });

// Membership: CIDR + manual member; the firewall becomes the zone core (not
// a member) and its gateway; the parallel bypass cables are one finding.
let m = segmentModel(nodes, links, seg([ot]), cores);
assert.deepEqual(Object.keys(m.of).sort(), ['10.20.0.1', '10.20.0.2', '10.20.0.3']);
assert.deepEqual(m.cores.ot, ['10.0.0.10']);
assert.deepEqual([...m.gateways.ot], ['10.0.0.10']);
assert.deepEqual(m.findings, [{ a: '10.0.0.50', b: '10.20.0.2', segA: null, segB: 'ot', decision: null }]);

// Decisions travel with the finding; "gateway" adds the outside end.
m = segmentModel(nodes, links, seg([ot], [{ a: '10.0.0.50', b: '10.20.0.2', decision: 'gateway' }]), cores);
assert.equal(m.findings[0].decision, 'gateway');
assert.deepEqual([...m.gateways.ot].sort(), ['10.0.0.10', '10.0.0.50']);
m = segmentModel(nodes, links, seg([ot], [{ a: '10.0.0.50', b: '10.20.0.2', decision: 'allowed' }]), cores);
assert.equal(m.findings[0].decision, 'allowed');

// Excluded overrides the subnet; cores never join even when listed.
m = segmentModel(nodes, links, seg([{ ...ot, members: ['10.0.0.10', '10.0.0.1'], excluded: ['10.20.0.3'] }]), cores);
assert.equal(m.of['10.20.0.3'], undefined);
assert.equal(m.of['10.0.0.1'], undefined);

// One node, one segment: the first that claims it.
m = segmentModel(nodes, links, seg([ot, { id: 'b', subnets: ['10.20.0.0/16'], members: [], excluded: [] }]), cores);
assert.equal(m.of['10.20.0.1'], 'ot');
assert.deepEqual([...m.gateways.b], []);

// Subnet only: the firewall cabled into the zone is still its core.
m = segmentModel(nodes, links, seg([{ id: 'ot', subnets: ['10.20.0.0/24'], members: [], excluded: [] }]), cores);
assert.deepEqual(m.cores.ot, ['10.0.0.10']);
// No firewall (excluded): every member with an outside cable is a gateway.
m = segmentModel(nodes, links, seg([{ id: 'ot', subnets: ['10.20.0.0/24'], members: [], excluded: ['10.0.0.10'] }]), cores);
assert.deepEqual(m.cores.ot, []);
assert.deepEqual([...m.gateways.ot].sort(), ['10.20.0.1', '10.20.0.2']);
assert.deepEqual(m.findings, []);

// Zone cores: two firewalls; three are ambiguous (none picked); the saved
// ones win, any device, and one firewall can be the core of two zones.
{
    const fw = id => N(id, 'firewall');
    const n3 = [...nodes, fw('10.0.0.11'), fw('10.0.0.12'), N('10.30.0.1'), N('10.30.0.2')];
    const toOt = ['10.0.0.11', '10.0.0.12'].map(f => L(f, '10.20.0.3'));
    const two = segmentModel(n3, [...clean, L('10.0.0.11', '10.20.0.3')], seg([ot]), cores);
    assert.deepEqual(two.cores.ot, ['10.0.0.10', '10.0.0.11']);
    const many = segmentModel(n3, [...clean, ...toOt], seg([ot]), cores);
    assert.deepEqual(many.cores.ot, []);
    assert.equal(many.ambiguous.ot, 3);
    const pick = segmentModel(n3, [...clean, ...toOt], seg([{ ...ot, cores: ['10.0.0.12', '10.20.0.1', '10.0.0.1'] }]), cores);
    assert.deepEqual(pick.cores.ot, ['10.0.0.12', '10.20.0.1'], 'saved order, site core dropped');
    assert.equal(pick.of['10.20.0.1'], undefined, 'a core is not a member');
    // Shared: 10.0.0.10, in no zone, cabled into OT and into a second zone.
    // (A firewall member of one zone is never picked for another: set it by hand.)
    const z2 = { id: 'z2', subnets: ['10.30.0.0/24'], members: [], excluded: [] };
    const sh = segmentModel(n3, [...clean, L('10.0.0.10', '10.30.0.1'), L('10.30.0.1', '10.30.0.2')], seg([{ ...ot, members: [] }, z2]), cores);
    assert.deepEqual(sh.cores.ot, ['10.0.0.10']);
    assert.deepEqual(sh.cores.z2, ['10.0.0.10']);
    assert.deepEqual(sh.findings, [], 'cables to a shared core are no bypass');
    // A cable from a site core straight into a zone with a core: a bypass.
    const by = segmentModel(n3, [...clean, L('10.0.0.1', '10.20.0.2')], seg([ot]), cores);
    assert.deepEqual(by.findings.map(f => [f.a, f.b]), [['10.0.0.1', '10.20.0.2']]);
}

// Two segments cabled gateway to gateway: no finding.
const lab = { id: 'lab', subnets: ['10.0.1.0/24'], members: [], excluded: [] };
m = segmentModel(nodes, [...clean, L('10.0.1.11', '10.0.0.10')], seg([ot, lab]), cores);
assert.deepEqual(m.findings.map(f => [f.a, f.b]), []);

// Proposal: the OT ring with its firewall, /24 from the switches only.
assert.deepEqual(proposeSegments(nodes, clean, cores, {}),
    [{ members: ['10.0.0.10', '10.20.0.1', '10.20.0.2', '10.20.0.3'], firewalls: ['10.0.0.10'], subnets: ['10.20.0.0/24'] }]);
// A bypass cable joins the ring to the main network: nothing to cut, nothing proposed.
assert.deepEqual(proposeSegments(nodes, links, cores, {}), []);
// Already saved: nothing to propose.
assert.deepEqual(proposeSegments(nodes, clean, cores, segmentModel(nodes, clean, seg([ot]), cores).of), []);
// No cores: the largest part is the main network.
assert.equal(proposeSegments(nodes, clean, null, {}).length, 1);

// Ladder columns: the OT devices leave the main column; the firewall heads
// the OT column, the ring hangs from it; an AP single-homed to an OT switch
// goes with it; a main device under an OT switch becomes a top row.
{
    const nodes2 = [...nodes, N('10.20.0.90', 'ap'), N('10.0.1.13')];
    const links2 = [...links, L('10.20.0.3', '10.20.0.90'), L('10.20.0.3', '10.0.1.13'), L('10.0.1.13', '10.0.1.12')];
    const B = (from, to) => ({ from, to, type: 'link', members: [{}] });
    const bundles = links2.map(l => B(l.source, l.target));
    const plan = {
        A: '10.0.0.1', B: '10.0.0.2', upstream: ['10.0.0.10'],
        members: [
            { id: '10.0.1.11', depth: 0, parent: null },
            { id: '10.0.1.12', depth: 0, parent: null },
            { id: '10.20.0.1', depth: 0, parent: null },
            { id: '10.20.0.3', depth: 1, parent: '10.20.0.1' },
            { id: '10.0.1.13', depth: 2, parent: '10.20.0.3' },
        ],
        leaves: { '10.20.0.3': ['10.20.0.90'] },
    };
    const model = segmentModel(nodes2, links2, seg([{ ...ot, name: 'OT', color: 'teal' }]), cores);
    const cols = ladderSegmentColumns(plan, model, [{ ...ot, name: 'OT', color: 'teal' }], bundles, id => id);
    assert.equal(cols.length, 1);
    assert.deepEqual(cols[0].gateways, ['10.0.0.10']);
    assert.deepEqual([cols[0].ladder.A, cols[0].ladder.B], ['10.0.0.10', null], 'one core: on the left');
    assert.deepEqual(cols[0].members.map(m => [m.id, m.depth, m.parent]), [
        ['10.20.0.1', 0, null],
        ['10.20.0.2', 1, '10.20.0.1'],
        ['10.20.0.3', 1, '10.20.0.1'],
        ['10.20.0.90', 2, '10.20.0.3'],
    ]);
    assert.deepEqual(plan.upstream, []);
    assert.deepEqual(plan.members.map(m => [m.id, m.depth, m.parent]),
        [['10.0.1.11', 0, null], ['10.0.1.12', 0, null], ['10.0.1.13', 0, null]]);
    assert.deepEqual(plan.leaves, {});
    // Geometry: columns right of core B, gateways level with the cores, no overlaps.
    const consts = src.match(/^ {4}const (LADDER_[A-Z_]+|SCHEMA_GAP) = .*$/gm).join('\n');
    const { ladderPositions } = new Function(consts + '\n' + extract('function ladderLeafOffset(') + '\n'
        + extract('function ladderLeafRows(') + '\n' + extract('function ladderPositions(') + '\nreturn { ladderPositions };')();
    plan.segCols = cols;
    plan.kidPortW = {}; plan.leafPortW = {};
    const box = {};
    nodes2.forEach(n => { box[n.id] = { w: n.device_type === 'ap' ? 110 : 200, h: 50 }; });
    const pos = ladderPositions(plan, box, 0);
    const rect = id => ({ l: pos[id].x - box[id].w / 2, r: pos[id].x + box[id].w / 2, t: pos[id].y - box[id].h / 2, b: pos[id].y + box[id].h / 2 });
    const ids = Object.keys(pos);
    assert.equal(ids.length, nodes2.length - 1, 'every drawn device placed except the WLC (no ladder role)');
    const segIds = [...cols[0].gateways, ...cols[0].members.map(m => m.id)];
    segIds.forEach(id => assert.ok(rect(id).l > rect('10.0.0.2').r, `${id} right of core B`));
    assert.equal(pos['10.0.0.10'].y, pos['10.0.0.2'].y, 'zone core level with the site cores');
    cols[0].members.forEach(m => assert.ok(rect(m.id).l > rect('10.0.0.10').r, `${m.id} right of its core`));
    ids.forEach((p, i) => ids.slice(i + 1).forEach(q => {
        const a = rect(p), c = rect(q);
        assert.ok(a.r <= c.l || c.r <= a.l || a.b <= c.t || c.b <= a.t, `${p} overlaps ${q}`);
    }));
    // No segments: the plan is untouched.
    const p2 = { A: 'a', B: 'b', upstream: ['u'], members: [{ id: 'm', depth: 0, parent: null }], leaves: {} };
    assert.deepEqual(ladderSegmentColumns(p2, { of: {}, gateways: {} }, [], [], id => id), []);
    assert.deepEqual(p2.upstream, ['u']);
}

// Two zones sharing a firewall: side by side, the firewall right core of
// the first and left core of the second, the frames' columns apart.
{
    const fw = id => N(id, 'firewall');
    const ns = [N('10.0.0.1'), N('10.0.0.2'), N('10.0.1.11'), fw('10.0.0.21'), fw('10.0.0.22'), fw('10.0.0.23'),
                N('10.20.0.1'), N('10.20.0.2'), N('10.30.0.1'), N('10.30.0.2')];
    const ls = [L('10.0.0.1', '10.0.0.2'), L('10.0.0.1', '10.0.1.11'), L('10.0.0.2', '10.0.1.11'),
                L('10.0.0.2', '10.0.0.21'), L('10.0.0.2', '10.0.0.22'), L('10.0.0.2', '10.0.0.23'),
                L('10.0.0.21', '10.20.0.1'), L('10.0.0.21', '10.20.0.2'), L('10.0.0.22', '10.20.0.1'), L('10.0.0.22', '10.20.0.2'),
                L('10.0.0.22', '10.30.0.1'), L('10.0.0.22', '10.30.0.2'), L('10.0.0.23', '10.30.0.1'), L('10.0.0.23', '10.30.0.2')];
    // Saved the "wrong" way round: the shared one first in both.
    const zs = [{ id: 'z2', name: 'Z2', color: 'teal', subnets: ['10.30.0.0/24'], members: [], excluded: [], cores: ['10.0.0.22', '10.0.0.23'] },
                { id: 'ot', name: 'OT', color: 'rose', subnets: ['10.20.0.0/24'], members: [], excluded: [], cores: ['10.0.0.22', '10.0.0.21'] }];
    const md = segmentModel(ns, ls, seg(zs), cores);
    assert.deepEqual(md.findings, []);
    const bundles = ls.map(l => ({ from: l.source, to: l.target, type: 'link', members: [{}] }));
    const plan = { A: '10.0.0.1', B: '10.0.0.2', upstream: ['10.0.0.21', '10.0.0.22', '10.0.0.23'],
                   members: [{ id: '10.0.1.11', depth: 0, parent: null }], leaves: {} };
    const cs = ladderSegmentColumns(plan, md, zs, bundles, id => id);
    assert.deepEqual(cs.map(c => [c.id, c.ladder.A, c.ladder.B, c.joinCore || null]),
        [['z2', '10.0.0.23', '10.0.0.22', null], ['ot', '10.0.0.22', '10.0.0.21', '10.0.0.22']]);
    const consts = src.match(/^ {4}const (LADDER_[A-Z_]+|SCHEMA_GAP) = .*$/gm).join('\n');
    const { ladderPositions } = new Function(consts + '\n' + extract('function ladderLeafOffset(') + '\n'
        + extract('function ladderLeafRows(') + '\n' + extract('function ladderPositions(') + '\nreturn { ladderPositions };')();
    plan.segCols = cs;
    const box = {};
    ns.forEach(n => { box[n.id] = { w: 160, h: 50 }; });
    const pos = ladderPositions(plan, box, 0);
    const r = id => ({ l: pos[id].x - box[id].w / 2, r: pos[id].x + box[id].w / 2 });
    assert.ok(r('10.0.0.23').l > r('10.0.0.2').r);
    assert.ok(r('10.30.0.1').r < r('10.0.0.22').l && r('10.20.0.1').l > r('10.0.0.22').r, 'shared core between the columns');
    assert.ok(r('10.0.0.21').l > r('10.20.0.1').r);
    ['10.0.0.21', '10.0.0.22', '10.0.0.23'].forEach(id => assert.equal(pos[id].y, pos['10.0.0.2'].y));
    // One core, shared with the next zone: it goes on the right.
    const one = [{ ...zs[0], cores: ['10.0.0.22'] }, zs[1]];
    const c1 = ladderSegmentColumns({ ...plan, upstream: [], members: [] }, segmentModel(ns, ls, seg(one), cores), one, bundles, id => id);
    assert.deepEqual([c1[0].ladder.A, c1[0].ladder.B], [null, '10.0.0.22']);
}

// Router: a cable from a box down to another with a box in the way goes round it.
{
    const { segRoute } = new Function(extract('function segRoute(') + '\nreturn { segRoute };')();
    const bx = (l, t, w = 100, h = 50) => ({ left: l, top: t, right: l + w, bottom: t + h });
    const a = bx(0, 0), b = bx(200, 300), wall = bx(150, 100, 200, 100);   // wall: right of a, above b
    const taken = { v: [], h: [] };
    const pts = segRoute(a, b, 25, 325, [wall], taken);
    assert.ok(pts && pts.length >= 2);
    const crosses = (o, [x1, y1], [x2, y2]) => Math.max(x1, x2) > o.left && Math.min(x1, x2) < o.right
        && Math.max(y1, y2) > o.top && Math.min(y1, y2) < o.bottom;
    for (let i = 1; i < pts.length; i++) {
        assert.ok(pts[i][0] === pts[i - 1][0] || pts[i][1] === pts[i - 1][1], 'orthogonal');
        assert.ok(!crosses(wall, pts[i - 1], pts[i]), `segment ${i} crosses the box in the way`);
    }
    // Room for the port names: the first bend is that far out of each box.
    const roomy = segRoute(a, b, 25, 325, [wall], { v: [], h: [] }, 60, 50);
    assert.ok(Math.abs(roomy[1][0] - roomy[0][0]) >= 60, 'stub out of a');
    const n = roomy.length;
    assert.ok(Math.abs(roomy[n - 1][0] - roomy[n - 2][0]) >= 50, 'stub into b');
    // A lane taken by another cable is not reused.
    const lane = pts.find((p, i) => i && p[0] === pts[i - 1][0]);
    if (lane) {
        taken.v.push([lane[0], -1000, 1000]);
        const again = segRoute(a, b, 25, 325, [wall], taken);
        assert.ok(again.every((p, i) => !i || p[0] !== again[i - 1][0] || Math.abs(p[0] - lane[0]) >= 6), 'own lane');
    }
}

console.log('segments model OK');
