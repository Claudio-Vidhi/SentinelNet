// groupLayeredLeaves() in static/js/topology.js: leaves of the same type under
// the same parent collapse into one node in the "Layered" map view. Grouping
// the wrong nodes (a switch, a leaf of another parent) or losing a member is
// invisible to a substring test, so this runs the real function.
//
//   node tests/js/test_layered_groups.mjs
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

function constant(name) {
    const start = src.indexOf(`const ${name} =`);
    assert.ok(start > 0, `${name} not found in topology.js`);
    return src.slice(start, src.indexOf(';', start) + 1);
}

const build = expanded => (0, eval)(`(function () {
    ${constant('GROUPABLE_TYPES')}
    ${constant('GROUP_MIN')}
    ${constant('GROUP_PREFIX')}
    const layeredExpanded = ${JSON.stringify(expanded)};
    const deviceTypeLabel = t => t;
    ${extract('function groupLayeredLeaves(')}
    return groupLayeredLeaves;
})()`);

// Two access switches: one with 4 APs and 1 phone, one with 2 APs.
const nodes = [
    { id: '192.0.2.10', label: 'switch-01', device_type: 'switch', status: 'online', group: 'site-a' },
    { id: '192.0.2.11', label: 'switch-02', device_type: 'switch', status: 'online', group: 'site-a' },
    { id: '192.0.2.20', label: 'ap-01', device_type: 'ap', status: 'online' },
    { id: '192.0.2.21', label: 'ap-02', device_type: 'ap', status: 'online' },
    { id: '192.0.2.22', label: 'ap-03', device_type: 'ap', status: 'offline' },
    { id: '192.0.2.23', label: 'ap-04', device_type: 'ap', status: 'online' },
    { id: '192.0.2.24', label: 'phone-01', device_type: 'phone', status: 'online' },
    { id: '192.0.2.30', label: 'ap-05', device_type: 'ap', status: 'online' },
    { id: '192.0.2.31', label: 'ap-06', device_type: 'ap', status: 'online' },
];
const links = [
    { source: '192.0.2.10', target: '192.0.2.11' },
    { source: '192.0.2.10', target: '192.0.2.20' },
    { source: '192.0.2.10', target: '192.0.2.21' },
    { source: '192.0.2.10', target: '192.0.2.22' },
    { source: '192.0.2.10', target: '192.0.2.23' },
    { source: '192.0.2.10', target: '192.0.2.24' },
    { source: '192.0.2.11', target: '192.0.2.30' },
    { source: '192.0.2.11', target: '192.0.2.31' },
];

let out = build({})(nodes, links, 'site-a');
const ids = out.nodes.map(n => n.id);
const groupId = 'grp:192.0.2.10:ap';

// The 4 APs of switch-01 collapse into one node...
assert.ok(ids.includes(groupId));
['192.0.2.20', '192.0.2.21', '192.0.2.22', '192.0.2.23'].forEach(
    id => assert.ok(!ids.includes(id), `${id} should be hidden inside the group`));
const grp = out.nodes.find(n => n.id === groupId);
assert.equal(grp.member_count, 4);
assert.equal(grp.device_type, 'ap');
// ...and the group reports the worst state of its members, never a green box
// hiding a device that is down.
assert.equal(grp.status, 'offline');

// A single phone stays a phone: below the threshold nothing is grouped.
assert.ok(ids.includes('192.0.2.24'));
// Two APs under switch-02 are below the threshold too.
assert.ok(ids.includes('192.0.2.30') && ids.includes('192.0.2.31'));
assert.ok(!ids.includes('grp:192.0.2.11:ap'));
// Switches are structure, never grouped.
assert.ok(ids.includes('192.0.2.10') && ids.includes('192.0.2.11'));

// One dashed link parent → group replaces the members' links.
const groupLinks = out.links.filter(l => l.kind === 'group');
assert.equal(groupLinks.length, 1);
assert.equal(groupLinks[0].source, '192.0.2.10');
assert.equal(groupLinks[0].target, groupId);
assert.equal(groupLinks[0].member_count, 4);
assert.ok(!out.links.some(l => l.target === '192.0.2.20'));
// The switch-to-switch link survives untouched.
assert.ok(out.links.some(l => l.source === '192.0.2.10' && l.target === '192.0.2.11'));

// Expanded: the members come back, the group node disappears, and every member
// maps back to its group so a double-click can collapse it again.
out = build({ 'site-a': [groupId] })(nodes, links, 'site-a');
const ids2 = out.nodes.map(n => n.id);
assert.ok(!ids2.includes(groupId));
['192.0.2.20', '192.0.2.21', '192.0.2.22', '192.0.2.23'].forEach(
    id => assert.equal(out.groupOfChild[id], groupId));
assert.equal(out.links.filter(l => l.kind === 'group').length, 0);

// The expanded state is per site: another site's map is unaffected.
out = build({ 'site-b': [groupId] })(nodes, links, 'site-a');
assert.ok(out.nodes.map(n => n.id).includes(groupId));

console.log('layered_groups: ok');
