// Device select search (ui-select-search.js), extracted and run in isolation.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/ui-select-search.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const fn = name => {
    const start = src.indexOf(`function ${name}(`);
    assert.ok(start >= 0, `missing ${name}`);
    const end = src.indexOf('\n}\n', start) + 2;
    return (0, eval)(`(${src.slice(start, end)})`);
};
const selectSearchMatches = fn('selectSearchMatches');

// Case-insensitive, every term must appear.
assert.equal(selectSearchMatches('switch-01 (192.0.2.11)', 'SW 192.0.2'), true);
assert.equal(selectSearchMatches('fw-01 (198.51.100.1)', 'switch'), false);
assert.equal(selectSearchMatches('fw-01 (198.51.100.1)', 'fw 203.0.113'), false);
assert.equal(selectSearchMatches('fw-01 (198.51.100.1)', ''), true);
assert.equal(selectSearchMatches('fw-01 (198.51.100.1)', '   '), true);

// A select whose change event triggers a load: searching must never touch
// the value nor fire an event, only hide options.
assert.ok(!/\.value\s*=[^=]/.test(src), 'ui-select-search.js must not assign .value');
assert.ok(!src.includes('dispatchEvent'), 'ui-select-search.js must not dispatch events');

console.log('select_search: ok');
