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

const build = (overrides, roots = {}) => (0, eval)(`(function () {
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

let levels = build({})(nodes, links, 'site-a');
// The whole point: same device_type, different tiers — core above access.
assert.equal(levels['192.0.2.1'], 0);
assert.equal(levels['192.0.2.10'], 1);
assert.equal(levels['192.0.2.11'], 1);
assert.equal(levels['192.0.2.20'], 2);
assert.equal(levels['192.0.2.21'], 2);
assert.equal(levels['192.0.2.30'], 3);

// A user override wins over the computed depth, and only for its own site.
levels = build({ 'site-a': { '192.0.2.20': 0 } })(nodes, links, 'site-a');
assert.equal(levels['192.0.2.20'], 0);
assert.equal(levels['192.0.2.21'], 2);
levels = build({ 'site-a': { '192.0.2.20': 0 } })(nodes, links, 'site-b');
assert.equal(levels['192.0.2.20'], 2);

// No boundary device: the most connected node becomes the root, so the map
// still gets tiers instead of collapsing onto one row.
const noFw = nodes.filter(n => n.device_type !== 'firewall');
const noFwLinks = links.filter(l => l.source !== '192.0.2.1');
levels = build({})(noFw, noFwLinks, 'site-a');
assert.equal(levels['192.0.2.10'], 0);
assert.equal(levels['192.0.2.20'], 1);
assert.equal(levels['192.0.2.30'], 2);

// An isolated node (no adjacency at all) falls back to its device type.
levels = build({})(nodes.concat([{ id: '192.0.2.99', device_type: 'server' }]), links, 'site-a');
assert.equal(levels['192.0.2.99'], 3);

// A hand-picked core is the only root: the firewall is no longer tier 0 and the
// whole map re-layers around the chosen switch, for that site only.
levels = build({}, { 'site-a': '192.0.2.20' })(nodes, links, 'site-a');
assert.equal(levels['192.0.2.20'], 0);
assert.equal(levels['192.0.2.10'], 1);
assert.equal(levels['192.0.2.30'], 1);
assert.equal(levels['192.0.2.1'], 2);
assert.equal(levels['192.0.2.21'], 3);
levels = build({}, { 'site-a': '192.0.2.20' })(nodes, links, 'site-b');
assert.equal(levels['192.0.2.1'], 0);
// A core pointing at a device that left the map falls back to the deduction.
levels = build({}, { 'site-a': '192.0.2.77' })(nodes, links, 'site-a');
assert.equal(levels['192.0.2.1'], 0);

console.log('layered_levels: ok');
