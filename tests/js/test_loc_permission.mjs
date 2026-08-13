// A saved permission naming the old tab must still reveal the merged tab.
// This is the one silent regression the merge can cause: no error, the nav
// item simply stops rendering for every non-admin who had 'tab-mac'.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/core.js', import.meta.url), 'utf8');
const start = src.indexOf('function normalizeAllowedTabs');
assert.ok(start !== -1, 'normalizeAllowedTabs missing from core.js');
const body = src.slice(start, src.indexOf('\n}', start) + 2);
const normalizeAllowedTabs = new Function(body + '; return normalizeAllowedTabs;')();

// Legacy permission -> merged tab.
assert.deepStrictEqual(normalizeAllowedTabs(['tab-mac']), ['tab-endpoint']);
// New permission passes through.
assert.deepStrictEqual(normalizeAllowedTabs(['tab-endpoint']), ['tab-endpoint']);
// Unrelated permissions untouched, and no duplicate appears.
assert.deepStrictEqual(
    normalizeAllowedTabs(['tab-devices', 'tab-mac', 'tab-endpoint']).sort(),
    ['tab-devices', 'tab-endpoint']);
// Empty means "all tabs" and must stay empty.
assert.deepStrictEqual(normalizeAllowedTabs([]), []);

console.log('ok - legacy tab-mac permission still resolves');

// The admin user editor (settings.js) has a second reader of allowed_tabs,
// independent from applyRoleUI(). If it reads u.allowed_tabs raw instead of
// through normalizeAllowedTabs(), a user saved with a legacy id like
// 'tab-mac' renders with the endpoint checkbox unchecked, and the next save
// silently revokes that permission. Assert the editor routes through the
// same normalizer.
const settingsSrc = readFileSync(new URL('../../static/js/settings.js', import.meta.url), 'utf8');
assert.ok(
    /normalizeAllowedTabs\(\s*u\.allowed_tabs\s*\)/.test(settingsSrc),
    'settings.js admin user editor must read allowed_tabs through normalizeAllowedTabs()');

console.log('ok - settings.js user editor normalizes allowed_tabs too');
