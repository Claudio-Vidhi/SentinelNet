// computeLayeredLevels() in static/js/topology.js: the tier of each node in the
// "Layered" map view. A substring test proves nothing here — the bug that made
// the view flat was a correct-looking level table keyed on device_type, where
// core, distribution and access are all "switch". This runs the real function.
//
//   node tests/js/test_layered_levels.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/topology.js'), 'utf8');

function extract(marker) {
    const start = src.indexOf(marker);
    assert.ok(start > 0, `${marker} not found in topology.js`);
    // Balanced-brace scan from the function's opening brace.
    let depth = 0;
    for (let j = src.indexOf('{', start); j < src.length; j++) {
        if (src[j] === '{') depth++;
        else if (src[j] === '}' && --depth === 0) return src.slice(start, j + 1);
    }
    throw new Error(`unbalanced braces after ${marker}`);
}

function constant(name) {
    const start = src.indexOf(`const ${name} =`);
    assert.ok(start > 0, `${name} not found in topology.js`);
    return src.slice(start, src.indexOf(';', start) + 1);
}

const build = (overrides, roots = {}, zones = {}) => (0, eval)(`(function () {
    const zoneKeyOf = id => (${JSON.stringify(zones)})[id] || '';
    ${constant('TIER_LEVEL')}
    ${constant('ROOT_TYPES')}
    const layeredLevels = ${JSON.stringify(overrides)};
    const layeredRoots = ${JSON.stringify(roots)};
    ${extract('function tierLevel(')}
    ${extract('function computeLayeredLevels(')}
    return computeLayeredLevels;
})()`);

// Synthetic three-tier site (RFC 5737 addresses): firewall → core → access → AP.
const nodes = [
    { id: '192.0.2.1',  device_type: 'firewall' },
    { id: '192.0.2.10', device_type: 'switch' },
    { id: '192.0.2.11', device_type: 'switch' },
    { id: '192.0.2.20', device_type: 'switch' },
    { id: '192.0.2.21', device_type: 'switch' },
    { id: '192.0.2.30', device_type: 'ap' },
];
const links = [
    { source: '192.0.2.1',  target: '192.0.2.10' },
    { source: '192.0.2.1',  target: '192.0.2.11' },
    { source: '192.0.2.10', target: '192.0.2.11' },
    { source: '192.0.2.10', target: '192.0.2.20' },
    { source: '192.0.2.11', target: '192.0.2.21' },
    { source: '192.0.2.20', target: '192.0.2.30' },
];

let levels = build({})(nodes, links, 'tenant-a');
// The whole point: same device_type, different tiers — core above access.
assert.equal(levels['192.0.2.1'], 0);
assert.equal(levels['192.0.2.10'], 1);
assert.equal(levels['192.0.2.11'], 1);
assert.equal(levels['192.0.2.20'], 2);
assert.equal(levels['192.0.2.21'], 2);
assert.equal(levels['192.0.2.30'], 3);

// A user override wins over the computed depth, and only for its own site.
levels = build({ 'tenant-a': { '192.0.2.20': 0 } })(nodes, links, 'tenant-a');
assert.equal(levels['192.0.2.20'], 0);
assert.equal(levels['192.0.2.21'], 2);
levels = build({ 'tenant-a': { '192.0.2.20': 0 } })(nodes, links, 'tenant-b');
assert.equal(levels['192.0.2.20'], 2);

// No boundary device: the most connected node becomes the root, so the map
// still gets tiers instead of collapsing onto one row.
const noFw = nodes.filter(n => n.device_type !== 'firewall');
const noFwLinks = links.filter(l => l.source !== '192.0.2.1');
levels = build({})(noFw, noFwLinks, 'tenant-a');
assert.equal(levels['192.0.2.10'], 0);
assert.equal(levels['192.0.2.20'], 1);
assert.equal(levels['192.0.2.30'], 2);

// An isolated node (no adjacency at all) falls back to its device type.
levels = build({})(nodes.concat([{ id: '192.0.2.99', device_type: 'server' }]), links, 'tenant-a');
assert.equal(levels['192.0.2.99'], 3);

// A hand-picked core is the only root: the firewall is no longer tier 0 and the
// whole map re-layers around the chosen switch, for that site only.
levels = build({}, { 'tenant-a': '192.0.2.20' })(nodes, links, 'tenant-a');
assert.equal(levels['192.0.2.20'], 0);
assert.equal(levels['192.0.2.10'], 1);
assert.equal(levels['192.0.2.30'], 1);
assert.equal(levels['192.0.2.1'], 2);
assert.equal(levels['192.0.2.21'], 3);
levels = build({}, { 'tenant-a': '192.0.2.20' })(nodes, links, 'tenant-b');
assert.equal(levels['192.0.2.1'], 0);
// A core pointing at a device that left the map falls back to the deduction.
levels = build({}, { 'tenant-a': '192.0.2.77' })(nodes, links, 'tenant-a');
assert.equal(levels['192.0.2.1'], 0);

// Two sites with no cable between them: each gets its own root, instead of
// the second falling back to per-type tiers (every switch on one row).
{
    const two = [{ id: 'a-core', device_type: 'switch' }, { id: 'a-acc', device_type: 'switch' },
                 { id: 'b-core', device_type: 'switch' }, { id: 'b-acc1', device_type: 'switch' },
                 { id: 'b-acc2', device_type: 'switch' }];
    const wires = [{ source: 'a-core', target: 'a-acc' },
                   { source: 'b-core', target: 'b-acc1' }, { source: 'b-core', target: 'b-acc2' }];
    const lv = build({})(two, wires, 't');
    assert.equal(lv['b-core'], 0, 'second site has its own root');
    assert.equal(lv['b-acc1'], 1);
    // A cable between two locations does not hang one site under the other.
    const zones = { 'a-core': 'A', 'a-acc': 'A', 'b-core': 'B', 'b-acc1': 'B', 'b-acc2': 'B' };
    const lz = build({}, {}, zones)(two, wires.concat({ source: 'a-acc', target: 'b-core' }), 't');
    assert.equal(lz['b-core'], 0, 'cross-site cable ignored for the tree');
    assert.equal(lz['b-acc2'], 1);
    // One core chosen by hand per location: each site's tree starts from its own.
    const lp = build({}, { t: { A: 'a-acc', B: 'b-acc1' } }, zones)(two, wires, 't');
    assert.equal(lp['a-acc'], 0, 'site A core chosen by hand');
    assert.equal(lp['a-core'], 1);
    assert.equal(lp['b-acc1'], 0, 'site B core chosen by hand, independently');
    assert.equal(lp['b-core'], 1);
}

// Two cores chosen for one location (a core pair): both on the top row, the
// access switches of either one on the row below.
{
    const zones = Object.fromEntries(nodes.map(n => [n.id, 'A']));
    const lv = build({}, { 'tenant-a': { A: ['192.0.2.10', '192.0.2.11'] } }, zones)(nodes, links, 'tenant-a');
    assert.equal(lv['192.0.2.10'], 0, 'first core on top');
    assert.equal(lv['192.0.2.11'], 0, 'second core on top too');
    assert.equal(lv['192.0.2.1'], 1);
    assert.equal(lv['192.0.2.20'], 1);
    assert.equal(lv['192.0.2.21'], 1);
    assert.equal(lv['192.0.2.30'], 2);
    // A save from before pairs (one id per location) still works.
    const one = build({}, { 'tenant-a': { A: '192.0.2.10' } }, zones)(nodes, links, 'tenant-a');
    assert.equal(one['192.0.2.10'], 0);
    assert.equal(one['192.0.2.11'], 1);
}

// moveLayeredLevels(): the card menu and Alt+arrows. Moves several cards,
// never above the top, "automatic" drops the override, a free-move position
// for the moved card is forgotten (it would pin the card to its old row).
{
    const st = (0, eval)(`(function () {
        const layeredGroup = 'tenant-a';
        const layeredLevels = { 'tenant-a': { 'switch-03': 4 } };
        const layeredFreePos = { 'tenant-a': { 'switch-01': { x: 1, y: 2 }, 'switch-09': { x: 3, y: 4 } } };
        const layeredAssigned = { 'switch-01': 1, 'switch-02': 0, 'switch-03': 4 };
        let redraws = 0, selected = null;
        const saveLayeredLevels = () => {}, saveLayeredFreePos = () => {};
        const redrawInteractiveMap = () => { redraws++; };
        const networkInstance = { body: { data: { nodes: { get: id => id !== 'gone' } } }, selectNodes: ids => { selected = ids; } };
        const getMapView = () => 'layered';
        let focused = null;
        const setLayeredFocus = ids => { focused = ids; };
        ${extract('function moveLayeredLevels(')}
        return { move: moveLayeredLevels, layeredLevels, layeredFreePos, layeredAssigned, get redraws() { return redraws; }, get selected() { return selected; }, get focused() { return focused; } };
    })()`);
    st.move(['switch-01', 'switch-02'], id => st.layeredAssigned[id] - 1);
    assert.deepEqual(st.layeredLevels['tenant-a'], { 'switch-03': 4, 'switch-01': 0, 'switch-02': 0 }, 'one up, clamped at the top');
    assert.deepEqual(Object.keys(st.layeredFreePos['tenant-a']), ['switch-09'], 'free position of the moved card dropped');
    st.move(['switch-03', 'gone'], () => null);
    assert.ok(!('switch-03' in st.layeredLevels['tenant-a']), 'automatic drops the override');
    assert.equal(st.redraws, 2);
    await Promise.resolve();
    assert.deepEqual(st.selected, ['switch-03'], 'still selected after the redraw, vanished cards skipped');
    assert.deepEqual(st.focused, ['switch-03'], 'and still lit');
}

// layeredAutoNames(): preset level names from what each row holds.
{
    const names = (0, eval)(`(function () { ${extract('function layeredAutoNames(')} return layeredAutoNames; })()`);
    assert.deepEqual(names({ 0: ['firewall'], 1: ['switch', 'switch'], 2: ['switch', 'wlc'], 3: ['switch'], 4: ['ap', 'ap'], 5: ['phone', 'camera'] }), {
        0: 'topoTierFirewall', 1: 'topoTierCore', 2: 'topoTierDistribution', 3: 'topoTierAccess', 4: 'topoTierWireless', 5: 'topoTierEndpoint' });
    // one switch row is the core; a WLC on its own row is the controller; a router counts as a firewall row
    assert.deepEqual(names({ 0: ['router', 'firewall'], 1: ['switch'], 2: ['wlc'], 3: ['ap', 'server'] }), {
        0: 'topoTierFirewall', 1: 'topoTierCore', 2: 'topoTierController', 3: 'topoTierEndpoint' });
}

// layeredLevelNamer(): repeated presets are numbered; once the user names a
// level, the presets go and unnamed levels read "Level N".
{
    const nodes = ['a', 'b', 'c', 'd', 'e'].map(id => ({ id, nodeDataVal: { device_type: 'switch' } }));
    const namer = names => (0, eval)(`(function () {
        const networkInstance = { body: { data: { nodes: ${JSON.stringify(nodes)} } } };
        const layeredAssigned = { a: 0, b: 1, c: 2, d: 3, e: 4 }, layeredGroup = 'g';
        const layeredLevelNames = { g: ${JSON.stringify(names)} };
        const tr = (k, p) => p ? k + p.n : k;
        ${extract('function layeredAutoNames(')}
        ${extract('function layeredLevelNamer(')}
        return layeredLevelNamer;
    })()`)();
    assert.deepEqual([0, 1, 2, 3, 4].map(namer(['', ''])),
        ['topoTierCore', 'topoTierDistribution 1', 'topoTierDistribution 2', 'topoTierDistribution 3', 'topoTierAccess']);
    assert.deepEqual([0, 1, 2, 3, 4, 5].map(namer(['', '', 'Agg'])),
        ['topoLevelN1', 'topoLevelN2', 'Agg', 'topoLevelN4', 'topoLevelN5', 'topoLevelN6']);
}

// applyLayeredAiRows(): an AI answer becomes the site's level overrides,
// a folded group hands its row to its members, and with free move on the
// row order becomes positions, each site laid out where it already is.
{
    const run = free => {
        const nodes = [
            { id: '192.0.2.1', zone: 'z1', nodeDataVal: {} },
            { id: '192.0.2.2', zone: 'z1', nodeDataVal: {} },
            { id: 'grp', zone: 'z1', nodeDataVal: { members: [{ id: 'ap-1' }, { id: 'ap-2' }] } },
            { id: '192.0.2.9', zone: 'z2', nodeDataVal: {} },
        ];
        const pos = { '192.0.2.1': { x: 0, y: 0 }, '192.0.2.2': { x: 200, y: 0 }, grp: { x: 100, y: 190 }, '192.0.2.9': { x: 3000, y: 0 } };
        const state = { levels: {}, freePos: {}, saved: 0, redrawn: 0 };
        new Function('st', 'free', 'pos', `
            const networkInstance = { getPositions: () => pos,
                body: { data: { nodes: { get: id => id === undefined ? st.nodes : st.nodes.find(n => n.id === id) } } } };
            const layeredGroup = 'acme', layeredLevels = st.levels, layeredFreePos = st.freePos, layeredFree = free;
            const mapAiZoneOf = nd => nd.zone;
            const saveLayeredLevels = () => { st.saved++; }, saveLayeredFreePos = () => {}, redrawInteractiveMap = () => { st.redrawn++; };
            ${constant('LAYERED_SEPARATION')}
            ${constant('LAYERED_PITCH')}
            ${extract('function applyLayeredAiRows(')}
            applyLayeredAiRows([['192.0.2.2', '192.0.2.9'], ['grp', '192.0.2.1', 'unknown']]);`)(Object.assign(state, { nodes }), free, pos);
        return state;
    };
    const fixed = run(false);
    assert.deepEqual(fixed.levels, { acme: { '192.0.2.2': 0, '192.0.2.9': 0, 'ap-1': 1, 'ap-2': 1, '192.0.2.1': 1 } });
    assert.deepEqual(fixed.freePos, {}, 'no positions without free move');
    assert.equal(fixed.redrawn, 1);
    const moved = run(true).freePos.acme;
    assert.ok(moved.grp.x < moved['192.0.2.1'].x, 'row order kept left to right');
    assert.equal(moved.grp.y, moved['192.0.2.1'].y);
    assert.ok(moved['192.0.2.2'].y < moved.grp.y, 'row 0 above row 1');
    assert.equal(moved['192.0.2.9'].x, 3000, 'the other site stays where it is');
    assert.ok(Math.abs(moved['192.0.2.2'].x - 100) < 1, 'a site is laid out around its own centre');
}

console.log('layered_levels: ok');
