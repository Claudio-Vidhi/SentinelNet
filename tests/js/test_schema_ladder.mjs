// Ladder layout detection in static/js/topology.js: core pair, share of
// dual-homed devices, column tree and leaves.
//
//   node tests/js/test_schema_ladder.mjs
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
        else if (src[j] === '}' && --depth === 0) return src.slice(start, j + 1);
    }
    throw new Error(`unbalanced braces after ${marker}`);
}

const { schemaLadderPlan } = new Function(
    'const LADDER_MIN_SHARE = 0.6; const LADDER_MAX_DEPTH = 4;\n'
    + extract('function schemaLadderPlan(') + '\nreturn { schemaLadderPlan };')();

const LEAF = ['ap', 'phone', 'camera', 'pc', 'server'];
const b = (from, to, type = 'link') => ({ from, to, type, members: [{ local: 'Te1/1/1', remote: 'Gi1/1/3' }] });
const level = { 'core-a': 1, 'core-b': 1, 'rtr-01': 0 };
const levelOf = id => level[id] ?? 2;
const typeOf = id => (id.startsWith('ap-') ? 'ap' : id.startsWith('srv-') ? 'server' : 'switch');
const labelOf = id => id;
const plan = bs => schemaLadderPlan(bs, levelOf, typeOf, labelOf, LEAF, null);

// Three dual-homed accesses, one single-homed: 75%, a ladder.
const base = [
    b('core-a', 'core-b', 'peer'), b('core-a', 'core-b', 'keepalive'),
    b('rtr-01', 'core-a'), b('rtr-01', 'core-b'),
    b('core-a', 'sw-acc-01'), b('core-b', 'sw-acc-01'),
    b('core-a', 'sw-acc-02'), b('core-b', 'sw-acc-02'),
    b('core-a', 'sw-acc-10'), b('core-b', 'sw-acc-10'),
    b('core-a', 'sw-acc-03'),
];
let p = plan(base);
assert.ok(p, 'dual-core site detected');
assert.equal(p.A, 'core-a');
assert.equal(p.B, 'core-b');
assert.deepEqual(p.upstream, ['rtr-01']);
assert.equal(p.dual, 3);
assert.equal(p.total, 4);
// natural order: sw-acc-10 after sw-acc-03
assert.deepEqual(p.members.map(m => m.id), ['sw-acc-01', 'sw-acc-02', 'sw-acc-03', 'sw-acc-10']);
assert.ok(p.members.every(m => m.depth === 0 && m.parent === null));

// Under 60%: no ladder.
assert.equal(plan([b('core-a', 'core-b', 'peer'), b('core-a', 'sw-1'), b('core-b', 'sw-1'),
    b('core-a', 'sw-2'), b('core-b', 'sw-2'), b('core-a', 'sw-3'), b('core-a', 'sw-4'), b('core-b', 'sw-5')]), null);
// Chosen by the user: devices added later (discovered) keep the ladder.
const thin = [b('core-a', 'core-b', 'peer'), b('core-a', 'sw-1'), b('core-b', 'sw-1'),
    b('core-a', 'sw-2'), b('core-b', 'sw-2'), b('core-a', 'sw-3'), b('core-a', 'sw-4'), b('core-b', 'sw-5')];
assert.ok(schemaLadderPlan(thin, levelOf, typeOf, labelOf, LEAF, null, true), 'chosen ladder survives a low share');
// One dual-homed device is not a pattern.
assert.equal(plan([b('core-a', 'core-b', 'peer'), b('core-a', 'sw-1'), b('core-b', 'sw-1')]), null);

// Devices below the column: switches step in, single-homed APs are leaves,
// a switch with two parents goes under the first one.
p = plan(base.concat([
    b('sw-acc-01', 'ap-01'), b('sw-acc-01', 'ap-02'),
    b('sw-acc-01', 'sw-piano-1'), b('sw-piano-1', 'ap-07'), b('sw-piano-1', 'sw-stanza-1'),
    b('sw-acc-02', 'sw-x'), b('sw-acc-03', 'sw-x'),
]));
assert.deepEqual(p.leaves['sw-acc-01'], ['ap-01', 'ap-02']);
assert.deepEqual(p.leaves['sw-piano-1'], ['ap-07']);
const m = Object.fromEntries(p.members.map(x => [x.id, x]));
assert.equal(m['sw-piano-1'].parent, 'sw-acc-01');
assert.equal(m['sw-piano-1'].depth, 1);
assert.equal(m['sw-stanza-1'].depth, 2);
assert.equal(m['sw-x'].parent, 'sw-acc-02');
assert.equal(p.members.filter(x => x.id === 'sw-x').length, 1);

// A single-homed switch hanging from another single-homed column switch goes
// under it: as its own row it sorted last and its cable crossed the column.
p = plan(base.concat([b('sw-acc-03', 'sw-lab-01'), b('core-b', 'sw-lab-01')]));
const lab = p.members.find(x => x.id === 'sw-lab-01');
assert.equal(lab.parent, 'sw-acc-03');
assert.equal(lab.depth, 1);

// An AP with two uplinks is a box in the tree, not a leaf.
p = plan(base.concat([b('sw-acc-01', 'ap-09'), b('sw-acc-02', 'ap-09')]));
assert.ok(!p.leaves['sw-acc-01']);
assert.equal(Object.fromEntries(p.members.map(x => [x.id, x]))['ap-09'].parent, 'sw-acc-01');

// The Core menu pair wins over the best-scoring one.
p = schemaLadderPlan(base, levelOf, typeOf, labelOf, LEAF, ['core-b', 'core-a']);
assert.equal(p.A, 'core-a');

// --- Geometry: positions and cables ---------------------------------------
const geo = new Function(
    'const LADDER_IN = 40, LADDER_GAP = 80, SCHEMA_GAP = 70, LADDER_LANE = 18, LADDER_PAR = 20, LADDER_BRANCH = 44, LADDER_LEAF_GAP = 8, LADDER_PO_STEP = 12, '
    + 'LADDER_AP_GAP = 16, LADDER_ROW_GAP = 18, LADDER_LEAF_LANE = 8;\n'
    + 'let visioConnectorSink = null, schemaFocusId = null, hoverBundleKey = null, edgeHitSegs = [];\n'
    + 'const schemaPortLabelVisible = () => true, schemaDimmed = () => false, linkColor = () => "#333";\n'
    + 'const pillKey = b => b.from + "~" + b.to;\n'
    + 'let corePortNear = "0"; const schemaPref = (k, d) => (k === "schemaCorePortNear" ? corePortNear : d);\n'
    + 'const setNear = v => { corePortNear = v; };\n'
    + extract('function pcEndTags(') + '\n' + extract('function ladderLeafRows(') + '\n' + extract('function ladderPositions(') + '\n' + extract('function drawLadderCables(')
    + '\nreturn { ladderPositions, drawLadderCables, setNear };')();

const net = base.concat([
    b('sw-acc-01', 'ap-01'), b('sw-acc-01', 'ap-02'), b('sw-acc-01', 'ap-03'), b('sw-acc-01', 'ap-04'),
    b('sw-acc-01', 'ap-05'), b('sw-acc-01', 'sw-piano-1'), b('sw-piano-1', 'core-a'),
    b('sw-piano-1', 'sw-stanza-1'), b('sw-stanza-1', 'ap-07'),
]);
const lad = plan(net);
lad.W = 400;
const sizes = {};
const boxSize = id => sizes[id] || (id.startsWith('core') ? { w: 300, h: 80 } : id.startsWith('rtr') ? { w: 200, h: 60 }
    : id.startsWith('ap') ? { w: 90, h: 30 } : { w: 400 - (lad.members.find(x => x.id === id) || { depth: 0 }).depth * 40, h: 46 });
const ids = [lad.A, lad.B, ...lad.upstream, ...lad.members.map(x => x.id), ...[].concat(...Object.values(lad.leaves))];
const box = Object.fromEntries(ids.map(id => [id, boxSize(id)]));
const pos = geo.ladderPositions(lad, box, 0);
const rect = id => ({ left: pos[id].x - box[id].w / 2, right: pos[id].x + box[id].w / 2,
                      top: pos[id].y - box[id].h / 2, bottom: pos[id].y + box[id].h / 2 });
assert.deepEqual(Object.keys(pos).sort(), [...ids].sort(), 'every ladder device placed');
// No two boxes overlap.
for (let i = 0; i < ids.length; i++) for (let j = i + 1; j < ids.length; j++) {
    const p = rect(ids[i]), q = rect(ids[j]);
    assert.ok(p.right <= q.left || q.right <= p.left || p.bottom <= q.top || q.bottom <= p.top, `${ids[i]} overlaps ${ids[j]}`);
}
// Column: one right edge for every level, each level one step in, A left of it and B right.
const col = lad.members.map(x => rect(x.id));
assert.ok(col.every(r => Math.abs(r.right - col[0].right) < 0.01));
assert.equal(rect('sw-stanza-1').left - rect('sw-acc-01').left, 80);
assert.ok(rect(lad.A).right < col[0].left && rect(lad.B).left > col[0].right);
// Top to bottom in plan order; leaves under their parent and inside the column.
lad.members.slice(1).forEach((x, i) => assert.ok(rect(x.id).top > rect(lad.members[i].id).top));
lad.leaves['sw-acc-01'].forEach(l => {
    assert.ok(rect(l).top > rect('sw-acc-01').bottom && rect(l).bottom < rect('sw-piano-1').top);
    assert.ok(rect(l).right <= col[0].right + 0.01);
});

// Cables: the ladder draws core lanes, trunks and leaves; peer, keepalive and
// upstream stay with the general router.
const calls = [];
const ctx = new Proxy({ measureText: t => ({ width: String(t).length * 5 }) }, { get: (t, k) => (k in t ? t[k] : (...a) => calls.push([k, ...a])), set: (t, k, v) => { t[k] = v; return true; } });
const left = geo.drawLadderCables(ctx, lad, net, rect, () => ({ color: '#333', lw: 1.4, dash: null }), 'all');
assert.deepEqual(left.map(x => `${x.from}~${x.to}~${x.type}`).sort(),
    ['core-a~core-b~keepalive', 'core-a~core-b~peer', 'rtr-01~core-a~link', 'rtr-01~core-b~link']);
// Leaves that fit: side by side, a second row half a step over so its cables
// run down the first row's gaps; each its own straight cable, the switch port
// inside the switch above it.
assert.equal(lad.leafMode['sw-acc-01'], 'rows');
const lr = lad.leaves['sw-acc-01'].map(rect), row1 = lr.filter(r => r.top === lr[0].top);
assert.ok(row1.length > 1 && row1.length < lr.length, 'two rows');
lr.filter(r => r.top !== lr[0].top).forEach(r => {
    const cx = (r.left + r.right) / 2;
    assert.ok(row1.every(q => cx < q.left || cx > q.right), 'second-row cable clear of the first row');
});
const sw1 = rect('sw-acc-01');
lr.forEach(r => assert.ok(calls.some(c => c[0] === 'fillText' && c[1] === 'Te1/1/1' && c[2] === (r.left + r.right) / 2 && c[3] === sw1.bottom - 3),
    'switch port inside the switch, above the cable'));
// A child: each end's port inside its own box.
const kidR = rect('sw-piano-1');
assert.ok(calls.some(c => c[0] === 'fillText' && c[1] === 'Te1/1/1' && c[2] === sw1.left + 20 && c[3] === sw1.bottom - 3), 'parent port inside the parent');
assert.ok(calls.some(c => c[0] === 'fillText' && c[1] === 'Gi1/1/3' && c[2] === kidR.left + 5), 'child port inside the child');
// The A cable into sw-piano-1 crosses its parent's trunk: one hop.
assert.equal(calls.filter(c => c[0] === 'arc').length, 1);

// Core port names sit inside the core, above its bottom edge.
const texts = calls.filter(c => c[0] === 'translate');
assert.ok(texts.length > 0);
assert.ok(texts.every(([, x, y]) => y < rect(lad.A).bottom || y < rect(lad.B).bottom), 'port names inside the core');
assert.ok(texts.every(([, x, y]) => [lad.A, lad.B].some(c => y <= rect(c).bottom && y >= rect(c).top && x >= rect(c).left && x <= rect(c).right)));

// Option: the core port also on the cable, just outside the switch.
const texts0 = calls.filter(c => c[0] === 'fillText').length;
calls.length = 0;
geo.setNear('1');
geo.drawLadderCables(ctx, lad, net, rect, () => ({ color: '#333', lw: 1.4, dash: null }), 'all');
const coreLanes = net.filter(x => x.type === 'link' && [x.from, x.to].some(id => id === lad.A || id === lad.B)
    && [x.from, x.to].some(id => lad.members.some(m => m.id === id))).length;
assert.equal(calls.filter(c => c[0] === 'fillText').length, texts0 + coreLanes, 'one extra name per core lane');

// Port-channels: their name at both ends, as in the row view, and no two
// names touching. po11 and po12 are single cables on neighbouring lanes.
const pc = (from, to, n, a, z) => ({ from, to, type: 'pc', label: a, asymmetricPc: a !== z, localLabel: a, remoteLabel: z,
    members: Array.from({ length: n }, (_, k) => ({ local: `Te1/0/${k + 5}`, remote: `Te1/0/${k + 1}` })) });
const pnet = net.filter(x => !(x.from === 'core-a' && ['sw-acc-01', 'sw-acc-02', 'sw-acc-03'].includes(x.to)))
    .concat([pc('core-a', 'sw-acc-01', 3, 'po10', 'po1'), pc('core-a', 'sw-acc-02', 1, 'po11', 'po2'), pc('core-a', 'sw-acc-03', 1, 'po12', 'po3')]);
calls.length = 0;
geo.setNear('0');
geo.drawLadderCables(ctx, lad, pnet, rect, () => ({ color: '#333', lw: 1.4, dash: null }), 'all');
const fill = calls.filter(c => c[0] === 'fillText');
const at = t => fill.filter(c => c[1] === t);
['po10', 'po11', 'po12'].forEach(t => {
    assert.equal(at(t).length, 1, `${t} once`);
    const [, , x, y] = at(t)[0], r = rect(lad.A);
    assert.ok(x > r.left && x < r.right && y > r.top && y < r.bottom, `${t} inside the core`);
    // Above every vertical port name (the longest is 7 chars x 5).
    assert.ok(y <= r.bottom - 4 - 35 - 4 - 2, `${t} above the vertical port names`);
});
const nm = ['po10', 'po11', 'po12'].map(t => { const [, s, x, y] = at(t)[0]; return { x0: x - s.length * 2.5, x1: x + s.length * 2.5, y }; });
for (let i = 0; i < nm.length; i++) for (let j = i + 1; j < nm.length; j++) {
    const p = nm[i], q = nm[j];
    assert.ok(p.x1 <= q.x0 || q.x1 <= p.x0 || Math.abs(p.y - q.y) >= 10, 'Po names in the core do not touch');
}
['po1', 'po2', 'po3'].forEach((t, i) => {
    const [, , x, y] = at(t)[0], r = rect(['sw-acc-01', 'sw-acc-02', 'sw-acc-03'][i]);
    assert.ok(x > r.left && x < r.right && y > r.top && y < r.bottom, `${t} inside its switch`);
});

// Too many leaves for two rows: one column, one lane each, nested so none
// cross, the port under its cable just before the leaf.
const many = Array.from({ length: 9 }, (_, k) => `ap-1${k}`);
const cnet = base.concat(many.map(a => b('sw-acc-02', a)));
const clad = plan(cnet);
clad.W = 300;
const cids = [clad.A, clad.B, ...clad.upstream, ...clad.members.map(x => x.id), ...many];
const cbox = Object.fromEntries(cids.map(id => [id, id.startsWith('core') ? { w: 300, h: 80 } : id.startsWith('rtr') ? { w: 200, h: 60 }
    : id.startsWith('ap') ? { w: 90, h: 30 } : { w: 300, h: 46 }]));
const cpos = geo.ladderPositions(clad, cbox, 0);
const crect = id => ({ left: cpos[id].x - cbox[id].w / 2, right: cpos[id].x + cbox[id].w / 2,
                       top: cpos[id].y - cbox[id].h / 2, bottom: cpos[id].y + cbox[id].h / 2 });
assert.equal(clad.leafMode['sw-acc-02'], 'col');
assert.ok(many.every(a => crect(a).left === crect(many[0]).left), 'one column');
calls.length = 0;
geo.drawLadderCables(ctx, clad, cnet, crect, () => ({ color: '#333', lw: 1.4, dash: null }), 'all');
many.forEach(a => {
    const r = crect(a);
    assert.ok(calls.some(c => c[0] === 'fillText' && c[1] === 'Te1/1/1' && c[2] === r.left - 4 && c[3] === (r.top + r.bottom) / 2 + 2), `port before ${a}`);
});
// Lanes: the top leaf's nearest; all left of the column and right of the child trunk.
const lanes = many.map((a, k) => crect(a).left - 44 - 12 - k * 8);
assert.ok(lanes.every((x, k) => !k || x < lanes[k - 1]));
assert.ok(lanes[lanes.length - 1] > crect('sw-acc-02').left + 16);

console.log('schema ladder: ok');
