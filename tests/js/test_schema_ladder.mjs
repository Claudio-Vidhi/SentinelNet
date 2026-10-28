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

// An AP with two uplinks is a box in the tree, not a leaf.
p = plan(base.concat([b('sw-acc-01', 'ap-09'), b('sw-acc-02', 'ap-09')]));
assert.ok(!p.leaves['sw-acc-01']);
assert.equal(Object.fromEntries(p.members.map(x => [x.id, x]))['ap-09'].parent, 'sw-acc-01');

// The Core menu pair wins over the best-scoring one.
p = schemaLadderPlan(base, levelOf, typeOf, labelOf, LEAF, ['core-b', 'core-a']);
assert.equal(p.A, 'core-a');

// --- Geometry: positions and cables ---------------------------------------
const geo = new Function(
    'const LADDER_IN = 40, LADDER_GAP = 80, SCHEMA_GAP = 70, LADDER_LANE = 18;\n'
    + 'let visioConnectorSink = null, schemaFocusId = null, hoverBundleKey = null, edgeHitSegs = [];\n'
    + 'const schemaPortLabelVisible = () => true, schemaDimmed = () => false, linkColor = () => "#333";\n'
    + 'const pillKey = b => b.from + "~" + b.to;\n'
    + 'let corePortNear = "0"; const schemaPref = (k, d) => (k === "schemaCorePortNear" ? corePortNear : d);\n'
    + 'const setNear = v => { corePortNear = v; };\n'
    + extract('function ladderPositions(') + '\n' + extract('function drawLadderCables(')
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
const ctx = new Proxy({}, { get: (t, k) => (k in t ? t[k] : (...a) => calls.push([k, ...a])), set: (t, k, v) => { t[k] = v; return true; } });
const left = geo.drawLadderCables(ctx, lad, net, rect, () => ({ color: '#333', lw: 1.4, dash: null }), 'all');
assert.deepEqual(left.map(x => `${x.from}~${x.to}~${x.type}`).sort(),
    ['core-a~core-b~keepalive', 'core-a~core-b~peer', 'rtr-01~core-a~link', 'rtr-01~core-b~link']);
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

console.log('schema ladder: ok');
