// Verdetto di qualita' Wi-Fi: esegue davvero wlcQuality() di static/js/wlc.js.
// Le soglie sono la logica del badge (e del KPI di riepilogo): una tabella di
// livelli sbagliata resta piena delle parole giuste e promuove a "Ottima" un
// client a -85 dBm.
//
//   node tests/js/test_wlc_quality.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/wlc.js'), 'utf8');
const start = src.indexOf('const WLC_QUALITY_LEVELS');
const end = src.indexOf('let wlcClients');
assert.ok(start > 0 && end > start, 'wlcQuality() non trovata in wlc.js');
const wlcQuality = (0, eval)(`(() => { ${src.slice(start, end)}; return wlcQuality; })`)();

const label = (rssi, snr) => (wlcQuality(rssi, snr) || {}).label;

// 1. Entrambe le cifre buone: vale il livello piu' alto.
assert.equal(label('-55', '40'), 'Ottima');
assert.equal(label('-70', '22'), 'Buona');
assert.equal(label('-78', '16'), 'Sufficiente');
assert.equal(label('-90', '8'), 'Scarsa');

// 2. Un SNR eccellente non compensa un segnale debole, ne' viceversa: vince
//    sempre la cifra peggiore.
assert.equal(label('-85', '45'), 'Scarsa');
assert.equal(label('-50', '9'), 'Scarsa');
assert.equal(label('-60', '21'), 'Buona');

// 3. Cifra mancante: si giudica su quella che c'e' (il controller espone il
//    dettaglio radio solo per una parte dei client).
assert.equal(label('-60', ''), 'Ottima');
assert.equal(label('', '18'), 'Sufficiente');
assert.equal(wlcQuality(undefined, undefined), null, 'senza dati nessun verdetto');
assert.equal(wlcQuality('n/d', '-'), null);

// 4. I valori arrivano dal parser CLI come stringhe, non sempre ripulite
//    dall'unita': parseFloat deve reggerle.
assert.equal(label('-67 dBm', '30 dB'), 'Buona');

// 5. Sulla soglia esatta il livello vale (il confronto e' >=).
assert.equal(label('-65', '25'), 'Ottima');
assert.equal(label('-80', '15'), 'Sufficiente');

console.log('wlc_quality: ok');
