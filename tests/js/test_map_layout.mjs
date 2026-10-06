// tidyLayeredTree() / drawLayeredLinks() in static/js/topology.js: the
// hierarchy view's layout and cables, checked on a small site without a
// browser. vis.js is replaced by a stub that holds positions and card sizes.
//
//   node tests/js/test_map_layout.mjs
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
const line = marker => { const i = src.indexOf(marker); assert.ok(i > 0, marker); return src.slice(i, src.indexOf('\n', i)); };

// A site: two firewalls on the core, three access switches under it, a WLC
// on a 4-port Po and one access switch on a 1-port Po.
const CARD_W = 220, CARD_H = 62, ROW = 190;
const cards = {
    'fw-a': [0, 0], 'fw-b': [400, 0],
    core: [200, ROW],
    a1: [0, 2 * ROW], a2: [100, 2 * ROW], a3: [900, 2 * ROW], wlc: [600, 2 * ROW], one: [300, 2 * ROW],
};
const po = (from, to, n) => ({
    id: `${from}-${to}`, from, to,
    lnk: { is_portchannel: true, local_pc: 'Port-channel1', remote_pc: 'Port-channel1',
           local_ports: Array.from({ length: n }, (_, i) => `GigabitEthernet1/0/${i + 1}`),
           remote_ports: Array.from({ length: n }, (_, i) => `GigabitEthernet0/${i + 1}`) },
});
const edges = [po('core', 'fw-a', 1), po('core', 'fw-b', 1), po('core', 'a1', 2), po('core', 'a2', 2),
               po('core', 'a3', 2), po('core', 'wlc', 4), po('core', 'one', 1)];

const pos = {};
Object.entries(cards).forEach(([id, [x, y]]) => { pos[id] = { x, y }; });
const networkInstance = {
    getPositions: () => Object.fromEntries(Object.entries(pos).map(([k, p]) => [k, { ...p }])),
    getBoundingBox: id => ({ left: pos[id].x - CARD_W / 2, right: pos[id].x + CARD_W / 2,
                             top: pos[id].y - CARD_H / 2, bottom: pos[id].y + CARD_H / 2 }),
    moveNode: (id, x, y) => { pos[id] = { x, y }; },
    body: { data: {
        nodes: { get: () => ({ nodeDataVal: { group: 'site' } }) },
        edges: { forEach: f => edges.forEach(f), get: () => edges },
    } },
};
const document = { createElement: () => ({ getContext: () => ({ font: '', measureText: t => ({ width: t.length * 6 }) }) }) };
const cssVar = (_, f) => f;
const hexToRgba = () => 'rgba(0,0,0,0.5)';
const drawEndTag = () => {};
// Indirect eval runs in the global scope: the stubs have to live there.
Object.assign(globalThis, { networkInstance, document, cssVar, hexToRgba, drawEndTag });

const { tidyLayeredTree, drawLayeredLinks, LAYERED_PITCH } = (0, eval)(`(function () {
    ${line('const LAYERED_PITCH =')}
    ${line('const LAYERED_SITE_GAP =')}
    ${line('const PC_COPPER =')}
    ${extract('function shortIface(')}
    ${extract('function pcEnds(')}
    ${extract('function tidyLayeredTree(')}
    ${extract('function drawLayeredLinks(')}
    return { tidyLayeredTree, drawLayeredLinks, LAYERED_PITCH };
})()`);

tidyLayeredTree();

// No two cards of a row closer than one pitch: no overlap.
const rows = {};
Object.entries(pos).forEach(([, p]) => (rows[p.y] || (rows[p.y] = [])).push(p.x));
Object.values(rows).forEach(xs => {
    xs.sort((a, b) => a - b);
    xs.slice(1).forEach((x, i) => assert.ok(x - xs[i] >= LAYERED_PITCH - 0.5, `cards ${xs[i]} and ${x} overlap`));
});

// The core sits centred over its children, the firewall pair over the core.
const kids = ['a1', 'a2', 'a3', 'wlc', 'one'].map(id => pos[id].x);
assert.equal(pos.core.x, (Math.min(...kids) + Math.max(...kids)) / 2, 'core centred over its children');
assert.equal((pos['fw-a'].x + pos['fw-b'].x) / 2, pos.core.x, 'firewall pair centred over the core');
assert.equal(Math.abs(pos['fw-a'].x - pos['fw-b'].x), LAYERED_PITCH, 'firewalls side by side');

// One line per configured port: 4 into the WLC, 1 into the one-port Po.
const ends = [];
const ctx = new Proxy({}, { get: (_, k) => k === 'lineTo' ? (x, y) => ends.push([x, y]) : (() => {}), set: () => true });
drawLayeredLinks(ctx);
const into = id => {
    const b = networkInstance.getBoundingBox(id);
    return ends.filter(([x, y]) => Math.abs(y - b.top) < 0.5 && x > b.left && x < b.right).length;
};
assert.equal(into('wlc'), 4, 'a 4-port Po draws 4 lines');
assert.equal(into('one'), 1, 'a 1-port Po draws 1 line');
assert.equal(into('a1'), 2);

console.log('ok');
