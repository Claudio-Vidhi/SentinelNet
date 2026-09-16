// tab-home is the fallback panel for every user and is never offered as a
// grant (assignableTabs skips it, create_user_ep strips it when copying the
// actor's tabs onto a new account). A restricted allowed_tabs list therefore
// never contains it, same as the server's ALWAYS_GRANTED_TABS. Before this
// fix, applyRoleUI's nav-hiding loop treated "not in the list" as "hide",
// which hid Home for every tab-restricted user (operator or admin) the
// moment /api/auth/me started returning a real list. See core.js
// ALWAYS_GRANTED_TABS mirror in applyRoleUI.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const coreSrc = readFileSync(new URL('../../static/js/core.js', import.meta.url), 'utf8');

// --- extract normalizeAllowedTabs + applyRoleUI together: applyRoleUI calls
// the former directly, same technique as test_tab_alias_parity.mjs. ---
const start = coreSrc.indexOf('function normalizeAllowedTabs');
assert.ok(start !== -1, 'normalizeAllowedTabs assente da core.js');
const applyStart = coreSrc.indexOf('function applyRoleUI', start);
assert.ok(applyStart !== -1, 'applyRoleUI assente da core.js');
const end = coreSrc.indexOf('\n}', applyStart);
const body = coreSrc.slice(start, end + 2);

// --- fake nav bar: tab-home plus two ordinary tabs ---
function navButton(tabId) {
    return {
        _tabId: tabId,
        style: { display: '' },
        getAttribute: (name) => (name === 'data-tab' ? tabId : null),
    };
}
const navButtons = [navButton('tab-home'), navButton('tab-devices'), navButton('tab-settings')];

global.document = {
    body: { classList: { remove: () => {}, add: () => {} } },
    getElementById: () => null,
    querySelector: () => null,
    querySelectorAll: (sel) => (sel === '.nav-item' ? navButtons : []),
};
global.currentUsername = '';
global.currentRole = 'viewer';
global.currentUserGroups = [];
global.currentAllowedTabs = [];

const fn = new Function(body + '; return { normalizeAllowedTabs, applyRoleUI };')();

fn.applyRoleUI('op', 'operator', ['tab-devices'], []);

const byId = Object.fromEntries(navButtons.map((b) => [b._tabId, b]));
assert.notStrictEqual(byId['tab-home'].style.display, 'none',
    'tab-home nascosta per un utente con tab ristrette');
assert.notStrictEqual(byId['tab-devices'].style.display, 'none',
    'tab-devices (concessa) nascosta per errore');
assert.strictEqual(byId['tab-settings'].style.display, 'none',
    'tab-settings (non concessa) resta visibile');

console.log('ok - tab-home resta visibile per un utente con tab ristrette');
