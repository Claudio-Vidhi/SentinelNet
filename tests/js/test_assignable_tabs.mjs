// Le tab concedibili a un utente non-admin sono derivate dalla barra di
// navigazione di dashboard.html. Elencarle a mano in settings.js le aveva
// fatte divergere: sei tab spedite non erano concedibili a nessuno, e una
// spunta concedeva una tab requires-admin che resta comunque nascosta.
//
// L'harness fa il parsing del template (lato test) e passa i pulsanti alla
// funzione vera: cosi' la selezione sotto esame e' quella che gira in
// produzione, contro il markup che gira in produzione.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../../templates/dashboard.html', import.meta.url), 'utf8');
const settingsSrc = readFileSync(new URL('../../static/js/settings.js', import.meta.url), 'utf8');

// --- elemento finto per ogni <button class="nav-item" ...> del template ---
function element(attrs) {
    const attr = (name) => {
        const m = new RegExp(name + '="([^"]*)"').exec(attrs);
        return m ? m[1] : null;
    };
    const classes = (attr('class') || '').split(/\s+/);
    const i18nKey = null;   // il label vive in uno <span> figlio: qui non serve
    return {
        classList: { contains: (c) => classes.includes(c) },
        getAttribute: attr,
        querySelector: () => (i18nKey ? { getAttribute: () => i18nKey } : null),
    };
}

const buttons = [...html.matchAll(/<button([^>]*\bnav-item\b[^>]*)>/g)]
    .map((m) => m[1])
    .filter((attrs) => /data-tab="/.test(attrs))
    .map(element);
assert.ok(buttons.length > 20, `pulsanti di navigazione trovati: ${buttons.length}`);

global.document = { querySelectorAll: () => buttons };

// --- la funzione vera, estratta dal sorgente ---
const start = settingsSrc.indexOf('const SECONDARY_TAB_LABELS');
assert.ok(start !== -1, 'SECONDARY_TAB_LABELS assente da settings.js');
const end = settingsSrc.indexOf('\n    }', settingsSrc.indexOf('function assignableTabs', start));
const body = settingsSrc.slice(start, end + 6);
const assignableTabs = new Function(body + '; return assignableTabs;')();

const ids = assignableTabs().map((t) => t.id);

// Le sei tab che la lista a mano aveva perso.
for (const id of ['tab-wlc', 'tab-interfaces', 'tab-redundancy',
                  'tab-policy-test', 'tab-routes', 'tab-config-drift']) {
    assert.ok(ids.includes(id), `tab non concedibile: ${id}`);
}
// Quelle che c'erano restano.
for (const id of ['tab-devices', 'tab-map', 'tab-map-interactive', 'tab-endpoint',
                  'tab-flows', 'tab-security', 'tab-categories', 'tab-config',
                  'tab-netsec-audit', 'tab-ai', 'tab-provisioning',
                  'tab-provisioner', 'tab-import']) {
    assert.ok(ids.includes(id), `tab concedibile sparita: ${id}`);
}
// requires-admin e home non sono concessioni.
for (const id of ['tab-users', 'tab-settings', 'tab-sites', 'tab-mcp',
                  'tab-incidents', 'tab-fortigate', 'tab-groups', 'tab-home']) {
    assert.ok(!ids.includes(id), `tab non assegnabile offerta: ${id}`);
}
// Nessun duplicato: un pulsante con data-tabs elenca anche il proprio data-tab.
assert.strictEqual(new Set(ids).size, ids.length, 'id duplicati fra le tab');

// Ogni pannello nel template che non sia requires-admin deve essere
// concedibile: e' l'invariante che la lista a mano violava.
const navTabs = new Set();
for (const m of html.matchAll(/<button([^>]*\bnav-item\b[^>]*)>/g)) {
    const attrs = m[1];
    if (/requires-admin/.test(attrs)) continue;
    const all = /data-tabs="([^"]*)"/.exec(attrs);
    const one = /data-tab="([^"]*)"/.exec(attrs);
    const list = (all ? all[1] : one ? one[1] : '').split(/\s+/);
    list.forEach((t) => { if (t && t !== 'tab-home') navTabs.add(t); });
}
assert.deepStrictEqual([...navTabs].sort(), [...ids].sort(),
    'la derivazione e la barra di navigazione non concordano');

console.log(`ok - ${ids.length} tab concedibili derivate dalla navigazione`);
