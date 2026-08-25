// vlansFromSwitchPort() in static/js/topology.js: the VLANs of a device that
// has no config of its own (an access point, a phone) are written on the switch
// port that feeds it. Matching "Gi1/0/4" (CDP) against "GigabitEthernet1/0/4"
// (config) is exactly the part a substring test cannot check.
//
//   node tests/js/test_drawer_vlans.mjs
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

const vlansFromSwitchPort = (0, eval)(`(function () {
    ${extract('function shortIface(')}
    ${extract('function ifaceKey(')}
    ${extract('function vlansFromSwitchPort(')}
    return vlansFromSwitchPort;
})()`);

const analysis = {
    interfaces: [
        { name: 'GigabitEthernet1/0/4', mode: 'access', access_vlan: '10',
          voice_vlan: '20', trunk_allowed: '', trunk_native: '' },
        { name: 'TenGigabitEthernet1/1/1', mode: 'trunk', access_vlan: '',
          voice_vlan: '', trunk_allowed: '10,20,50', trunk_native: '99' },
        { name: 'GigabitEthernet1/0/9', mode: 'routed', access_vlan: '',
          voice_vlan: '', trunk_allowed: '', trunk_native: '' },
    ],
};

// The CDP short name resolves to the config's long name.
assert.deepEqual(vlansFromSwitchPort(analysis, 'Gi1/0/4'), ['10 (access)', '20 (voice)']);
// ...and the long name works just as well.
assert.deepEqual(vlansFromSwitchPort(analysis, 'GigabitEthernet1/0/4'), ['10 (access)', '20 (voice)']);
// A trunk lists the native VLAN first, then everything it allows.
assert.deepEqual(vlansFromSwitchPort(analysis, 'Te1/1/1'), ['99 (native)', '10', '20', '50']);
// A routed port carries no VLAN, and an unknown port must not guess.
assert.deepEqual(vlansFromSwitchPort(analysis, 'Gi1/0/9'), []);
assert.deepEqual(vlansFromSwitchPort(analysis, 'Gi9/9/9'), []);
// Missing inputs are not an error, just nothing to say.
assert.deepEqual(vlansFromSwitchPort(null, 'Gi1/0/4'), []);
assert.deepEqual(vlansFromSwitchPort(analysis, ''), []);

console.log('drawer_vlans: ok');
