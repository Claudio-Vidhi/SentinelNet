// Schema view readability helpers in static/js/topology.js: focus dimming,
// port-label mode, zigzag rows and grouped core-pair uplinks.
//
//   node tests/js/test_schema_readability.mjs
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

const { schemaDimmed, schemaNeighbors, schemaPortLabelVisible, zigzagRow, schemaUplinkGroups } = new Function(
    [extract('function schemaDimmed('), extract('function schemaNeighbors('),
     extract('function schemaPortLabelVisible('), extract('function zigzagRow('),
     extract('function schemaUplinkGroups(')].join('\n')
    + '\nreturn { schemaDimmed, schemaNeighbors, schemaPortLabelVisible, zigzagRow, schemaUplinkGroups };')();

const b = (from, to, extra = {}) => ({ from, to, members: [{ local: 'Gi1/0/49', remote: 'Gi1/0/1' }], type: 'link', ...extra });

// --- Task 1: focus -------------------------------------------------------
// no focus, no hover: nothing dims
assert.equal(schemaDimmed(b('core-01', 'access-01'), 'k1', null, null), false);
// focus dims cables not touching it
assert.equal(schemaDimmed(b('core-01', 'access-01'), 'k1', null, 'access-02'), true);
assert.equal(schemaDimmed(b('core-01', 'access-02'), 'k2', null, 'access-02'), false);
// hover beats focus
assert.equal(schemaDimmed(b('core-01', 'access-02'), 'k2', 'k1', 'access-02'), true);
assert.equal(schemaDimmed(b('core-01', 'access-01'), 'k1', 'k1', 'access-02'), false);
// grouped bundle: ends decide
assert.equal(schemaDimmed(b('__pair:core-01|core-02', 'access-01', { ends: ['core-01', 'core-02', 'access-01'] }), 'k3', null, 'core-02'), false);
// isolated node
assert.deepEqual([...schemaNeighbors([b('core-01', 'access-01')], 'switch-09')], ['switch-09']);
assert.deepEqual([...schemaNeighbors([b('core-01', 'access-01'), b('core-02', 'access-01')], 'access-01')].sort(),
                 ['access-01', 'core-01', 'core-02']);

// --- Task 2: port labels -------------------------------------------------
const L = b('core-01', 'access-01');
assert.equal(schemaPortLabelVisible('all', L, null), true);
assert.equal(schemaPortLabelVisible('none', L, 'core-01'), false);
assert.equal(schemaPortLabelVisible('focus', L, null), false);
assert.equal(schemaPortLabelVisible('focus', L, 'access-01'), true);
assert.equal(schemaPortLabelVisible('focus', L, 'access-02'), false);
assert.equal(schemaPortLabelVisible('bogus', L, null), true);   // unknown stored value = today's look

// --- Task 3: zigzag ------------------------------------------------------
const r = zigzagRow([100, 100, 100, 100], 70);
assert.deepEqual(r.map(p => p.sub), [0, 1, 0, 1]);
// same sub-row neighbours never closer than width + gap
assert.ok(r[2].x - r[0].x >= 100 + 70);
// wide box keeps drops in gaps: every lower centre is >= maxW/2 + gap/2 from every upper centre
{
    const w = [80, 260, 80, 80, 80], z = zigzagRow(w, 70);
    for (const lo of z.filter(p => p.sub === 1)) for (const up of z.filter(p => p.sub === 0))
        assert.ok(Math.abs(lo.x - up.x) >= 260 / 2 + 70 / 2 - 0.001);
    assert.ok(z[0].x - w[0] / 2 >= 0, 'starts at the row left edge');
}

// --- Task 4: grouped uplinks ----------------------------------------------
const boxes = {
    'core-01': [0, 180, 0], 'core-02': [220, 400, 0],
    'access-01': [0, 100, 1], 'access-02': [150, 250, 1], 'access-03': [300, 400, 1], 'access-04': [450, 550, 1],
};
const mkBox = extra => id => { const v = { ...boxes, ...extra }[id]; return v ? { left: v[0], right: v[1], top: v[2] * 200, bottom: v[2] * 200 + 60 } : null; };
const levelOf = id => ({ ...boxes, 'switch-09': [0, 0, 0] })[id][2];
const ids = Object.keys(boxes);
const bundles = [
    b('core-01', 'core-02', { type: 'pc' }),
    b('core-01', 'access-01'), b('core-02', 'access-01', { type: 'pc' }),
    b('core-01', 'access-02'), b('access-02', 'core-02'),
    b('core-01', 'access-03'), b('core-02', 'access-03'),
    b('core-01', 'access-04'),
];
const g = schemaUplinkGroups(bundles, ids, levelOf, mkBox({}), []);
assert.deepEqual(g.map(x => x.target), ['access-01', 'access-02', 'access-03']);
assert.deepEqual(g[0].pair, ['core-01', 'core-02']);
assert.equal(g[0].id, '__pair:core-01|core-02');
assert.equal(g[0].parts.length, 2);
// no link, no pair
const unlinked = bundles.filter(x => !(x.from === 'core-01' && x.to === 'core-02'));
assert.deepEqual(schemaUplinkGroups(unlinked, ids, levelOf, mkBox({}), []), []);
// ...unless the user named the two cores in the Core menu
assert.equal(schemaUplinkGroups(unlinked, ids, levelOf, mkBox({}), [['core-02', 'core-01']]).length, 3);
// one shared child, no pair
const onlyAccess01 = bundles.filter(x => ![x.from, x.to].some(e => e === 'access-02' || e === 'access-03'));
assert.deepEqual(schemaUplinkGroups(onlyAccess01, ids, levelOf, mkBox({}), []), []);
// a box between them, no pair
assert.deepEqual(schemaUplinkGroups(bundles, [...ids, 'switch-09'], levelOf, mkBox({ 'switch-09': [170, 230, 0] }), []), []);
// not on the same row height, no pair
assert.deepEqual(schemaUplinkGroups(bundles, ids, levelOf, id => {
    const bx = mkBox({})(id); return id === 'core-02' ? { ...bx, top: 100, bottom: 160 } : bx;
}, []), []);

// a cable is grouped once: dual core over a dual distribution pair, full mesh
{
    const bx = { c1: [0, 180, 0], c2: [220, 400, 0], d1: [0, 180, 1], d2: [220, 400, 1] };
    const box = id => ({ left: bx[id][0], right: bx[id][1], top: bx[id][2] * 200, bottom: bx[id][2] * 200 + 60 });
    const lvl = id => bx[id][2];
    const mesh = [b('c1', 'c2', { type: 'pc' }), b('d1', 'd2', { type: 'peer' }),
                  b('c1', 'd1'), b('c1', 'd2'), b('c2', 'd1'), b('c2', 'd2')];
    const gs = schemaUplinkGroups(mesh, Object.keys(bx), lvl, box, []);
    const parts = gs.flatMap(x => x.parts);
    assert.equal(parts.length, new Set(parts).size, 'no bundle in two groups');
    assert.equal(gs.length, 2);
}
// applySchemaFocus keeps the offline dimming
{
    const nodes = [{ id: 'core-01', opacity: 1 }, { id: 'access-01', opacity: 0.45 }, { id: 'access-02', opacity: 0.45 }];
    const ds = { getIds: () => nodes.map(n => n.id), get: id => nodes.find(n => n.id === id),
                 update: list => list.forEach(u => Object.assign(nodes.find(n => n.id === u.id), u)) };
    const focus = new Function('networkInstance', 'minimalOverlayData', `
        ${extract('function schemaNeighbors(')}
        ${extract('function schemaNodeOpacity(')}
        let schemaFocusId = null;
        ${extract('function applySchemaFocus(')}
        return applySchemaFocus;`)({ body: { data: { nodes: ds } }, redraw() {} }, { bundles: [b('core-01', 'access-01')] });
    focus('core-01');
    assert.deepEqual(nodes.map(n => n.opacity), [1, 0.45, 0.35]);
    focus(null);
    assert.deepEqual(nodes.map(n => n.opacity), [1, 0.45, 0.45], 'offline stays dim after focus clears');
}

// --- Overlay smoke run: grouping + label mode + focus, through the real
// drawMinimalOverlay with vis.js and the canvas stubbed out.
{
    const pos = { 'core-01': [90, 30], 'core-02': [310, 30], 'access-01': [50, 230], 'access-02': [200, 230], 'access-03': [350, 230] };
    const W = { 'core-01': 180, 'core-02': 180 };
    const lv = id => id.startsWith('core') ? 0 : 1;
    const net = {
        getPosition: id => ({ x: pos[id][0], y: pos[id][1] }),
        getBoundingBox: id => { const [x, y] = pos[id], w = W[id] || 100; return { left: x - w / 2, right: x + w / 2, top: y - 30, bottom: y + 30 }; },
        body: { data: { nodes: { getIds: () => Object.keys(pos), get: id => pos[id] ? { id, schemaLevel: lv(id) } : null, update() {} } } },
    };
    const mk = (from, to, type = 'link') => ({ from, to, type, members: [{ local: 'Gi1/0/49', remote: 'Gi1/0/1' }], label: type === 'pc' ? 'Po1' : '' });
    const bundles0 = [mk('core-01', 'core-02', 'pc'), ...['access-01', 'access-02', 'access-03'].flatMap(a => [mk('core-01', a), mk('core-02', a)])];
    const run = (prefs, focus, sink) => {
        const texts = [], strokes = [];   // strokes: one fillRect per cable end (terminal square)
        const ctx = new Proxy({}, { get: (t, k) => k in t ? t[k]
            : k === 'measureText' ? s => ({ width: String(s).length * 5 })
            : k === 'fillText' ? s => texts.push({ s, a: t.globalAlpha ?? 1 })
            : k === 'fillRect' ? () => strokes.push(t.globalAlpha ?? 1)
            : k === 'save' ? () => stack.push(t.globalAlpha) : k === 'restore' ? () => { t.globalAlpha = stack.pop(); }
            : () => {} });
        const stack = [];
        const body = [extract('function drawMinimalOverlay('), extract('function schemaDimmed('), extract('function schemaNeighbors('),
            extract('function schemaPortLabelVisible('), extract('function schemaUplinkGroups('), extract('function schemaPortLabelMode('),
            extract('function pcEndTags(')].join('\n');
        new Function('networkInstance', 'prefs', 'schemaFocusId', 'ctx', 'bundles', 'sink', `
            const MINIMAL_MAP_STYLE = { edge: { group: {} } };
            const initPillInteraction = () => {}, customStyleForEdge = () => null, linkColor = () => '#888888', hexToRgba = () => 'rgba(0,0,0,.1)';
            const visioColor = c => ({ hex: c }), routeMemo = {}, pillKey = b => b.from + '~' + b.to + '~' + (b.pcTag || '');
            const pillAdj = () => ({ dx: 0, dy: 0, scale: 1 }), labelAdj = () => ({ dx: 0, dy: 0 });
            const schemaPref = (k, f) => k in prefs ? prefs[k] : f, rootsOf = () => ({});
            let visioConnectorSink = sink, hoverBundleKey = null, layeredGroup = 'all';
            let pillHitboxes = [], labelHitboxes = [], edgeHitSegs = [];
            ${body}
            drawMinimalOverlay(ctx, bundles, []);`)(net, prefs, focus, ctx, bundles0, sink || null);
        return { texts, strokes };
    };
    const plain = run({}, null);
    assert.equal(plain.strokes.length / 2, 7, 'one cable per bundle');
    assert.ok(plain.texts.some(t => t.s === 'Gi1/0/49'), 'labels drawn by default');
    const grouped = run({ schemaGroupUplinks: '1', schemaPortLabels: 'none' }, null);
    assert.equal(grouped.strokes.length / 2, 4, 'core link + one grouped cable per access');
    assert.equal(grouped.texts.filter(t => t.s === '×2').length, 3);
    assert.ok(!grouped.texts.some(t => t.s === 'Gi1/0/49'), 'no port labels');
    const focused = run({ schemaPortLabels: 'focus' }, 'access-02');
    assert.equal(focused.strokes.filter(a => a === 1).length / 2, 2, 'only the focus cables stay full');
    assert.equal(focused.texts.filter(t => t.s === 'Gi1/0/49').length, 2, 'labels only on the focus cables');
    // The Visio export keeps full detail: every real cable, glued to real boxes, every port name.
    const sink = [];
    const exp = run({ schemaGroupUplinks: '1', schemaPortLabels: 'none' }, 'access-02', sink);
    assert.equal(sink.length, 7);
    assert.ok(sink.every(c => !String(c.from).startsWith('__pair:')));
    assert.equal(exp.texts.filter(t => t.s === 'Gi1/0/49').length, 7);
}

// --- Tidy smoke run: ten access switches under one core wrap in two sub-rows.
{
    const ids = ['core-01', ...Array.from({ length: 10 }, (_, i) => `access-${String(i + 1).padStart(2, '0')}`)];
    const tidy = wrap => {
        const moved = {};
        const nodes = ids.map(id => ({ id, schemaLevel: id === 'core-01' ? 0 : 1 }));
        const ds = { forEach: f => nodes.forEach(f), get: id => nodes.find(n => n.id === id) };
        const net = { body: { data: { nodes: ds } }, getBoundingBox: () => ({ left: 0, right: 100, top: 0, bottom: 60 }),
                      moveNode: (id, x, y) => { moved[id] = { x, y }; }, fit() {} };
        const bundles = ids.slice(1).map(a => ({ from: 'core-01', to: a, members: [{}] }));
        new Function('networkInstance', 'minimalOverlayData', 'prefs', `
            const topoZone = () => ({ key: 'z' }), saveSchemaPositions = () => {}, setTimeout = () => {};
            const schemaPref = (k, f) => k in prefs ? prefs[k] : f;
            const SCHEMA_GAP = 70, SCHEMA_WRAP_MIN = 8;
            ${extract('function zigzagRow(')}
            ${extract('function packSchemaRows(')}
            packSchemaRows();`)(net, { bundles }, { schemaWrap: wrap ? '1' : '0' });
        const acc = ids.slice(1).map(id => moved[id]);
        return { ys: new Set(acc.map(p => p.y)).size, width: Math.max(...acc.map(p => p.x)) - Math.min(...acc.map(p => p.x)), core: moved['core-01'], acc };
    };
    const flat = tidy(false), wrapped = tidy(true);
    assert.equal(flat.ys, 1);
    assert.equal(wrapped.ys, 2, 'two sub-rows');
    assert.ok(wrapped.width < flat.width * 0.6, `about half as wide: ${wrapped.width} vs ${flat.width}`);
    const mid = wrapped.acc.reduce((t, p) => t + p.x, 0) / wrapped.acc.length;
    assert.ok(Math.abs(mid - wrapped.core.x) < 1, 'block centred under the core');
}

// --- draw.io export: click a box and only its cables stay, click the site to bring all back.
{
    const pos = { 'core-01': { x: 0, y: 0 }, 'access-01': { x: -100, y: 200 }, 'access-02': { x: 100, y: 200 } };
    const nodes = Object.keys(pos).map(id => ({ id, nodeDataVal: { id, label: id, device_type: 'switch', status: 'online' } }));
    const lnk = (a, c) => ({ from: a, to: c, lnk: { local_port: 'GigabitEthernet1/0/49', remote_port: 'GigabitEthernet1/0/1' } });
    const net = { getPositions: () => pos, getBoundingBox: id => ({ left: pos[id].x - 50, right: pos[id].x + 50, top: pos[id].y - 30, bottom: pos[id].y + 30 }),
                  body: { data: { nodes: { forEach: f => nodes.forEach(f), get: id => nodes.find(n => n.id === id) },
                                  edges: { get: () => [lnk('core-01', 'access-01'), lnk('core-01', 'access-02')] } } } };
    let xml = '';
    new Function('networkInstance', 'capture', `
        const topoZone = () => ({ key: 'z', label: 'tenant-a' }), shortIface = s => s.replace('GigabitEthernet', 'Gi');
        const pcEnds = () => ({}), PC_COPPER = '#B45309', lastMapGroup = 'tenant-a', alert = () => {}, tr = k => k;
        const Blob = function (parts) { capture(parts.join('')); };
        const URL = { createObjectURL: () => 'blob:x', revokeObjectURL() {} };
        const document = { createElement: () => ({ click() {} }) };
        ${extract('function exportDrawioMap(')}
        exportDrawioMap();`)(net, x => { xml = x; });
    const attr = (tag, name) => (tag.match(new RegExp(name + '="([^"]*)"')) || [])[1];
    const unesc = v => v.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
    const objs = [...xml.matchAll(/<UserObject [^>]*>/g)].map(m => m[0]);
    const edges = [...xml.matchAll(/<UserObject [^>]*>\s*<mxCell [^>]*edge="1"/g)].map(m => m[0]);
    assert.equal(edges.length, 2, 'every cable is a tagged object');
    const boxOf = id => objs.find(o => unesc(attr(o, 'label') || '').includes(`<b>${id}</b>`));
    const tagOf = id => attr(boxOf(id), 'id');
    for (const e of edges) assert.ok(attr(e, 'tags').split(' ').includes('sn-cable'));
    const act = o => JSON.parse(unesc(attr(o, 'link')).replace('data:action/json,', '')).actions;
    // access-01: hide all cables, show its own
    const a1 = act(boxOf('access-01'));
    assert.deepEqual(a1[0], { hide: { tags: ['sn-cable'] } });
    assert.deepEqual(a1[1], { show: { tags: [tagOf('access-01')] } });
    const own = edges.filter(e => attr(e, 'tags').split(' ').includes(tagOf('access-01')));
    assert.equal(own.length, 1);
    assert.equal(edges.filter(e => attr(e, 'tags').split(' ').includes(tagOf('core-01'))).length, 2);
    // the site container brings every cable back
    const site = objs.find(o => attr(o, 'label') === 'TENANT-A');
    assert.deepEqual(act(site), [{ show: { tags: ['sn-cable'] } }]);
}

console.log('schema readability: ok');
