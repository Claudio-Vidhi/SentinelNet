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

const { segmentModel, proposeSegments } = new Function(
    [extract('const ip4n ='), extract('const inCidr ='), extract('function segmentModel('),
     extract('function proposeSegments(')].join('\n')
    + '\nreturn { segmentModel, proposeSegments };')();

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

// Membership: CIDR + manual member; the firewall is the gateway; the
// parallel bypass cables are one finding.
let m = segmentModel(nodes, links, seg([ot]), cores);
assert.deepEqual(Object.keys(m.of).sort(), ['10.0.0.10', '10.20.0.1', '10.20.0.2', '10.20.0.3']);
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

// No firewall in the segment: every member with an outside cable is a gateway.
m = segmentModel(nodes, links, seg([{ id: 'ot', subnets: ['10.20.0.0/24'], members: [], excluded: [] }]), cores);
assert.deepEqual([...m.gateways.ot].sort(), ['10.20.0.1', '10.20.0.2']);
assert.deepEqual(m.findings, []);

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

console.log('segments model OK');
