// Sidebar favorites: contracts a DOM-less test can pin.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(p, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const core = read('../../static/js/core.js');
const html = read('../../templates/dashboard.html');
const fn = head => core.slice(core.indexOf(head), core.indexOf('\n}\n', core.indexOf(head)));

// Template: the group and the star exist, hidden until there is something to show.
assert.ok(/id="navFavorites"[^>]*hidden/.test(html), 'favorites group must start hidden');
assert.ok(/id="btnFavToggle"[^>]*aria-pressed="false"[^>]*hidden/.test(html), 'star must be a toggle button, hidden on load');

// The entries are not nav tabs: no data-tab, no role="tab", or every lookup
// over the real nav (permissions, active state, assignable tabs) would see them.
const render = fn('function renderNavFavorites(');
assert.ok(render.includes('class="nav-item nav-fav'), 'favorites reuse the nav item look');
assert.ok(!/data-tab=|role="tab"/.test(render.replace(/\.nav-item\[data-tab=/g, '')), 'favorite entries must not carry data-tab or role="tab"');
// Permission is decided at render time, the stored list is not pruned.
assert.ok(render.includes('navFavorites.filter(canOpenTab)'), 'tabs the user cannot open are not drawn');
assert.ok(render.includes("star.hidden = cur === 'tab-home'"), 'home is not a favorite');
assert.ok(render.includes('escapeHtml(id)'), 'tab id escaped in the attribute');

// Rendered on every tab switch and language change, loaded once at init.
assert.ok(fn('function syncTopbarCrumb(').includes('renderNavFavorites()'), 'crumb sync must redraw favorites');
assert.ok(/applyRoleUI\(me\.username[^\n]*\n\s*loadNavFavorites\(\);/.test(core), 'favorites load after the role UI');

// Saved through the API; a failure is said, not swallowed.
const toggle = fn('async function toggleNavFavorite(');
assert.ok(toggle.includes("'/api/profile/favorites'") && toggle.includes("method: 'PUT'"), 'toggle saves via PUT');
assert.ok(toggle.includes("tr('favSaveError')"), 'save failure shows a toast');

console.log('nav_favorites: ok');
