// A grouped nav entry (data-tabs) must survive a tab grant that holds only its
// secondary panel: "Routing e policy" groups tab-routes + tab-policy-test, and
// a user granted only tab-policy-test used to see the entry hidden.
// Runs the real allowed-tabs block of applyRoleUI() against fake buttons.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const core = readFileSync(new URL('../../static/js/core.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const html = readFileSync(new URL('../../templates/dashboard.html', import.meta.url), 'utf8');

const fn = core.slice(core.indexOf('function applyRoleUI('));
const start = fn.indexOf('    if (allowed.length > 0) {');
const end = fn.indexOf('\n    }\n', start);
assert.ok(start > 0 && end > start, 'allowed-tabs block not found in applyRoleUI');
const block = fn.slice(start, end + 6);

function el(attrs) {
    const a = { ...attrs };
    return {
        style: {},
        getAttribute: (k) => (k in a ? a[k] : null),
        setAttribute: (k, v) => { a[k] = v; },
    };
}

function run(allowed) {
    const nav = [
        el({ 'data-tab': 'tab-home' }),
        el({ 'data-tab': 'tab-routes', 'data-tabs': 'tab-routes tab-policy-test' }),
        el({ 'data-tab': 'tab-flows' }),
    ];
    const subs = [el({ 'data-switch-tab': 'tab-routes' }), el({ 'data-switch-tab': 'tab-policy-test' })];
    global.document = {
        querySelectorAll: (sel) => (sel === '.nav-item' ? nav : subs),
        querySelector: (sel) => nav.find((b) => (b.getAttribute('data-tabs') || '').split(' ')
            .includes(/data-tabs~="([^"]+)"/.exec(sel)?.[1])) || null,
    };
    new Function('allowed', block)(allowed);
    return { nav, subs };
}

// Only the secondary panel granted: entry visible, opens on it, the other sub-tab hidden.
let r = run(['tab-policy-test']);
assert.notStrictEqual(r.nav[1].style.display, 'none');
assert.strictEqual(r.nav[1].getAttribute('data-tab'), 'tab-policy-test');
assert.strictEqual(r.subs[0].style.display, 'none');
assert.notStrictEqual(r.subs[1].style.display, 'none');
assert.strictEqual(r.nav[2].style.display, 'none');
assert.notStrictEqual(r.nav[0].style.display, 'none', 'tab-home is never hidden');

// Neither panel granted: entry hidden.
r = run(['tab-flows']);
assert.strictEqual(r.nav[1].style.display, 'none');

// Both granted: untouched.
r = run(['tab-routes', 'tab-policy-test']);
assert.strictEqual(r.nav[1].getAttribute('data-tab'), 'tab-routes');
assert.notStrictEqual(r.subs[0].style.display, 'none');

// The template really groups the two panels and gives each a sub-tab bar.
assert.ok(/data-tabs="tab-routes tab-policy-test" data-tab="tab-routes"/.test(html));
for (const tab of ['tab-routes', 'tab-policy-test']) {
    const panel = html.slice(html.indexOf(`<div id="${tab}" class="tab-content"`));
    const bar = panel.slice(0, panel.indexOf('</div>', panel.indexOf('class="subtab-bar"')));
    assert.ok(bar.includes('data-switch-tab="tab-routes"') && bar.includes('data-switch-tab="tab-policy-test"'),
        `${tab} has no routes/policy sub-tab bar`);
}
assert.ok(!/data-tab="tab-policy-test"/.test(html), 'policy test must not keep its own nav entry');
console.log('ok');
