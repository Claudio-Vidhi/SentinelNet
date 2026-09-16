// The legacy tab id merge lives twice: user_manager.TAB_ALIASES (server-side
// enforcement, admin-permissions Task 1) and normalizeAllowedTabs() in
// core.js (client-side UI hiding, older). Both must resolve the same ids to
// the same target or a saved legacy id would show different tabs to the
// server gate and the nav bar.
//
// TAB_ALIASES arrives as JSON on argv[2], passed by the Python wrapper so
// the source of truth stays in Python.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const pyAliases = JSON.parse(process.argv[2]);

const coreSrc = readFileSync(new URL('../../static/js/core.js', import.meta.url), 'utf8');

// --- extract the real function from its source, same technique as
// tests/js/test_assignable_tabs.mjs ---
const start = coreSrc.indexOf('function normalizeAllowedTabs');
assert.ok(start !== -1, 'normalizeAllowedTabs assente da core.js');
const end = coreSrc.indexOf('\n}', start);
const body = coreSrc.slice(start, end + 2);
const normalizeAllowedTabs = new Function(body + '; return normalizeAllowedTabs;')();

for (const [legacy, target] of Object.entries(pyAliases)) {
    const result = normalizeAllowedTabs([legacy]);
    assert.deepStrictEqual(result, [target],
        `normalizeAllowedTabs(['${legacy}']) = ${JSON.stringify(result)}, atteso ['${target}']`);
}

console.log(`ok - ${Object.keys(pyAliases).length} alias legacy allineati fra core.js e user_manager.TAB_ALIASES`);
