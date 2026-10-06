// pcEnds() / sideLabel() / aIsLeft() in static/js/topology.js: a Port-channel
// often has a different id on each end (Po8 on the core, Po1 on the access
// switch). The map showed one shared name, so the user could not tell which
// was which. Each end keeps its own name, an unknown end is '?', and a
// mid-cable label is written left device first.
//
//   node tests/js/test_pc_ends.mjs
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

const { pcEnds, sideLabel, aIsLeft } = (0, eval)(`(function () {
    ${extract('function shortIface(')}
    ${extract('function pcEnds(')}
    ${extract('function sideLabel(')}
    ${extract('function aIsLeft(')}
    return { pcEnds, sideLabel, aIsLeft };
})()`);

// Different ids: both shown, source end first.
const asym = pcEnds({ pc_name: 'Port-channel1', local_pc: 'Port-channel8', remote_pc: 'Port-channel1' });
assert.deepEqual([asym.local, asym.remote, asym.same, asym.text], ['Po8', 'Po1', false, 'Po8 ⇄ Po1']);

// Same id on both ends: one name.
assert.equal(pcEnds({ local_pc: 'Port-channel2', remote_pc: 'Port-channel2' }).text, 'Po2');

// One end unknown: '?', never the other end's name.
const half = pcEnds({ pc_name: 'Port-channel8', local_pc: 'Port-channel8', remote_pc: null });
assert.equal(half.text, 'Po8 ⇄ ?');

// No per-end data at all (old payload, or a LAG without channel-group).
assert.equal(pcEnds({ pc_name: 'Port-channel3' }).text, 'Po3');
assert.equal(pcEnds({ member_count: 2 }).text, 'LAG ×2');

// Orientation: the device on the left (or above) is written first.
const s = { prefix: '⛓ ', a: 'Po8', b: 'Po1', same: false, am: 'Gi1/0/44+Gi1/0/45', bm: 'Te1/1/1' };
assert.equal(sideLabel(s, true), '⛓ Po8 ⇄ Po1\nGi1/0/44+Gi1/0/45 ⇄ Te1/1/1');
assert.equal(sideLabel(s, false), '⛓ Po1 ⇄ Po8\nTe1/1/1 ⇄ Gi1/0/44+Gi1/0/45', 'name and members flip together');
const pos = { A: { x: 0, y: 0 }, B: { x: 300, y: 40 }, C: { x: 10, y: -200 } };
assert.equal(aIsLeft(pos, 'A', 'B'), true, 'horizontal cable: smaller x first');
assert.equal(aIsLeft(pos, 'B', 'A'), false);
assert.equal(aIsLeft(pos, 'A', 'C'), false, 'vertical cable: the upper device first');
assert.equal(aIsLeft(pos, 'A', 'missing'), true, 'unknown position: source first');

console.log('ok');
