// Il cassetto di dettaglio del Triage Flow Log si apre davvero al clic.
//
// La riga aveva cursor:pointer e il clic non faceva nulla: toggleEventDrawer
// riceve row.dataset.id, che il DOM restituisce SEMPRE come stringa, mentre
// e.id arriva dal JSON dove syslog_events.id e' un INTEGER. `"42" === 42` e'
// false, quindi isSelected non era mai vero e il <tr> di dettaglio non veniva
// emesso. Un test "grep" sul sorgente non lo avrebbe visto: le parole giuste
// c'erano tutte.
//
//   node tests/js/test_siem_row_click.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/flow-analytics.js'), 'utf8');

const start = src.indexOf('function renderSiemTable()');
const end = src.indexOf('async function suppressSiemAlert');
assert.ok(start > 0 && end > start,
    'renderSiemTable/toggleEventDrawer non trovate in flow-analytics.js');

// DOM minimo: al renderer servono solo il tbody e il suo contenitore.
const tbody = { innerHTML: '', closest: () => null };
const document = { getElementById: id => (id === 'flowSiemTableBody' ? tbody : null) };
const escapeHtml = s => String(s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const tr = k => k;

const api = (0, eval)(
    `((document, escapeHtml, tr) => {
        let _flowSiemData = [];
        let _selectedEventId = null;
        ${src.slice(start, end)};
        return {
            renderSiemTable, toggleEventDrawer,
            setData: d => { _flowSiemData = d; },
            selected: () => _selectedEventId,
        };
     })`
)(document, escapeHtml, tr);

// id NUMERICO, come lo manda /api/flow-siem/events (INTEGER PRIMARY KEY).
api.setData([
    { id: 42, timestamp: null, src_ip: '192.0.2.10', dst_ip: '192.0.2.20',
      proto: 'TCP', action: 'DENY', is_deny: true, bytes: 2048 },
    { id: 43, timestamp: null, src_ip: '192.0.2.11', dst_ip: '192.0.2.21',
      proto: 'UDP', action: 'ACCEPT', is_deny: false, bytes: null },
]);

api.renderSiemTable();
assert.ok(!tbody.innerHTML.includes('Raw SIEM Flow Event Payload'),
    'il cassetto e\' aperto prima di qualsiasi clic');

// Il clic passa la stringa che il DOM espone in dataset.id.
api.toggleEventDrawer('42');
assert.ok(tbody.innerHTML.includes('Raw SIEM Flow Event Payload'),
    'il clic su una riga non apre il cassetto di dettaglio');
assert.ok(tbody.innerHTML.includes('192.0.2.10'),
    'il cassetto non contiene il payload dell\'evento selezionato');

// Un secondo clic sulla stessa riga lo richiude.
api.toggleEventDrawer('42');
assert.equal(api.selected(), null, 'il secondo clic non chiude il cassetto');
assert.ok(!tbody.innerHTML.includes('Raw SIEM Flow Event Payload'),
    'il cassetto resta aperto dopo il secondo clic');

// Cliccare un'altra riga sposta la selezione invece di aprirne due.
api.toggleEventDrawer('42');
api.toggleEventDrawer('43');
assert.equal(api.selected(), '43');
assert.ok(tbody.innerHTML.includes('192.0.2.11'), 'la selezione non si e\' spostata');
assert.equal(tbody.innerHTML.split('Raw SIEM Flow Event Payload').length - 1, 1,
    'due cassetti aperti insieme');

console.log('ok — la riga del Triage Flow Log apre, chiude e sposta il cassetto');
