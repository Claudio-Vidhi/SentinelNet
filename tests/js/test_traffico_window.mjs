// La finestra del tab deve arrivare a tutte e quattro le viste.
//
// La chiamata anomalie nasceva con window=7d cablato nel sorgente: il pannello
// mostrava una settimana mentre il resto del tab mostrava un quarto d'ora, e
// nessun controllo sullo schermo diceva che le due cose non coincidevano. Non
// era una scelta, era una stringa.
//
//   node tests/js/test_traffico_window.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const obs = readFileSync(join(root, 'static/js/observability.js'), 'utf8');
const siem = readFileSync(join(root, 'static/js/flow-analytics.js'), 'utf8');

// 1. Nessuna finestra cablata in una URL: devono venire tutte da trafState.
for (const [name, src] of [['observability.js', obs], ['flow-analytics.js', siem]]) {
    const hardcoded = src.match(/window=(15m|1h|24h|7d)\b/g) || [];
    assert.deepEqual(hardcoded, [],
        `${name}: finestra cablata nella query (${hardcoded.join(', ')})`);
}

// 2. loadAnomalies legge la finestra del tab.
const start = obs.indexOf('async function loadAnomalies()');
assert.ok(start > 0, 'loadAnomalies() non trovata');
const body = obs.slice(start, obs.indexOf('\n    }', start));
assert.match(body, /trafState\.window/,
    'loadAnomalies() non legge trafState.window');

// 3. La riga anomalia porta al suo incidente: l'id restituito da
//    /api/observability/anomalies E' l'id dell'incidente (la rotta legge
//    "FROM incidents"), quindi il collegamento non richiede altre chiamate.
assert.match(obs.slice(start, obs.indexOf('async function anomTransition', start)),
    /openIncident\(/, 'la riga anomalia non porta al suo incidente');

// 4. Il default del tab e' una sola finestra, dichiarata una volta sola.
const stateBlock = obs.slice(obs.indexOf('const trafState'), obs.indexOf('let _trafView'));
const declared = stateBlock.match(/window:\s*'([^']+)'/);
assert.ok(declared, 'trafState non dichiara una finestra iniziale');
assert.equal(declared[1], '1h', 'la finestra iniziale del tab non e\' 1h');

console.log('ok — una sola finestra, dalle quattro viste all\'incidente');
