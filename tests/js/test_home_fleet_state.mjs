// renderFleetOneline()'s worst-of-bay `state` function in static/js/home.js:
// a source-text grep is not enough here (see test_sort_table.mjs for the
// same argument) — the exact bug the coordinator found was an operator that
// reads fine as text ("st === 'offline' || st === 'unknown'") but is wrong.
// This runs the real function against synthetic bucket counts.
//
//   node tests/js/test_home_fleet_state.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/home.js'), 'utf8');
const start = src.indexOf('const state = b =>');
assert.ok(start > 0, 'state() worst-of-bay function not found in home.js');
const semi = src.indexOf(';', start);
assert.ok(semi > start, 'state() assignment is not a single statement ending in ;');
const stateSrc = src.slice(start, semi + 1);

const state = (0, eval)(`(function () { ${stateSrc} return state; })()`);

// Bastion-only tenant (the coordinator's concrete failure case): a single
// device, not measurable, must not read as an outage.
assert.equal(state({ total: 1, down: 0, warn: 0, idle: 0, unknown: 1 }), 'unknown');

// A real, fully-down tenant is unaffected by the new bucket.
assert.equal(state({ total: 1, down: 1, warn: 0, idle: 0, unknown: 0 }), 'down');

// Mixed: some genuinely down AND some not measurable — attention, not a
// clean 'down' (not all down) and not a clean 'unknown' (not all unknown).
assert.equal(state({ total: 2, down: 1, warn: 0, idle: 0, unknown: 1 }), 'warn');

// Mixed: some confirmed up AND some not measurable — attention, never
// silently 'up' (that would be the opposite lie) and never 'down'.
assert.equal(state({ total: 2, down: 0, warn: 0, idle: 0, unknown: 1 }), 'warn');

// All confirmed up: unchanged.
assert.equal(state({ total: 1, down: 0, warn: 0, idle: 0, unknown: 0 }), 'up');

// Never polled: unchanged, still takes priority over everything else.
assert.equal(state({ total: 1, down: 0, warn: 0, idle: 1, unknown: 0 }), 'idle');

console.log('home_fleet_state: ok');
