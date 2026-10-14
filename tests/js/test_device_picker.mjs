// Device picker grouping and summary (client-map.js), extracted and run in isolation.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/client-map.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const fn = name => {
    const start = src.indexOf(`function ${name}(`);
    assert.ok(start >= 0, `missing ${name}`);
    const end = src.indexOf('\n}\n', start) + 2;
    return (0, eval)(`(${src.slice(start, end)})`);
};
const pickerGroups = fn('pickerGroups');
const pickerSummary = fn('pickerSummary');

const devs = [
    { IP: '192.0.2.11', Hostname: 'switch-01', Location: 'loc-a' },
    { IP: '192.0.2.12', Hostname: 'switch-02', Location: 'loc-a' },
    { IP: '198.51.100.13', Hostname: 'switch-03', Location: 'loc-b' },
    { IP: '203.0.113.16', Hostname: '', Location: '' },
];
const label = id => ({ 'loc-a': 'Sede A', 'loc-b': 'Sede B' })[id] || 'Senza sede';

// Grouping: by site, sorted, devices without a site last and not dropped.
let g = pickerGroups(devs, new Set(devs.map(d => d.IP)), label);
assert.deepEqual(g.map(x => x.label), ['Sede A', 'Sede B', 'Senza sede']);
assert.deepEqual(g.map(x => [x.n, x.total]), [[2, 2], [1, 1], [1, 1]]);
assert.equal(g[2].devices[0].name, '203.0.113.16', 'no hostname: the IP is the name');
assert.deepEqual(pickerSummary(g), { kind: 'all', n: 4, total: 4, locations: ['Sede A', 'Sede B', 'Senza sede'] });

// Nothing ticked is "none", never "all".
g = pickerGroups(devs, new Set(), label);
assert.deepEqual(pickerSummary(g), { kind: 'none', n: 0, total: 4, locations: [] });

// Whole locations only.
g = pickerGroups(devs, new Set(['192.0.2.11', '192.0.2.12']), label);
assert.deepEqual(pickerSummary(g), { kind: 'locations', n: 2, total: 4, locations: ['Sede A'] });

// Part of a site.
g = pickerGroups(devs, new Set(['192.0.2.11', '198.51.100.13']), label);
assert.equal(g[0].n, 1);
assert.deepEqual(pickerSummary(g), { kind: 'partial', n: 2, total: 4, locations: ['Sede A', 'Sede B'] });

console.log('device_picker: ok');
