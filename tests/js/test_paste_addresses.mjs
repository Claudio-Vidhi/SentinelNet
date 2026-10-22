// expandAddressList (devices.js): pasted addresses for the CSV import.
// Runs the real function, sliced out of the source.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/devices.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const start = src.indexOf('    function expandAddressList(');
const end = src.indexOf('\n    }\n', start);
assert.ok(start > 0 && end > start, 'expandAddressList not found');
const expand = new Function(src.slice(start, end + 6) + '; return expandAddressList;')();

let r = expand('192.0.2.10\n192.0.2.11, 192.0.2.12; 192.0.2.10');
assert.deepStrictEqual(r.ips, ['192.0.2.10', '192.0.2.11', '192.0.2.12'], 'separators and duplicates');

r = expand('192.0.2.10-12 192.0.2.20-192.0.2.21');
assert.deepStrictEqual(r.ips, ['192.0.2.10', '192.0.2.11', '192.0.2.12', '192.0.2.20', '192.0.2.21'], 'ranges');

r = expand('198.51.100.0/30');
assert.deepStrictEqual(r.ips, ['198.51.100.1', '198.51.100.2'], '/30 leaves out network and broadcast');
assert.strictEqual(expand('198.51.100.7/24').ips.length, 254, '/24 from any host address');
assert.deepStrictEqual(expand('198.51.100.5/32').ips, ['198.51.100.5']);
assert.deepStrictEqual(expand('198.51.100.4/31').ips, ['198.51.100.4', '198.51.100.5']);

r = expand('192.0.2.300 10.0.0.0/16 192.0.2.20-10 192.0.2.1-198.51.100.2 switch-01');
assert.deepStrictEqual(r.ips, []);
assert.deepStrictEqual(r.bad, ['192.0.2.300', '10.0.0.0/16', '192.0.2.20-10', '192.0.2.1-198.51.100.2', 'switch-01']);

r = expand('192.0.2.0/24 198.51.100.0/24', 300);
assert.strictEqual(r.ips.length, 300);
assert.strictEqual(r.truncated, true);
console.log('paste_addresses: ok');
