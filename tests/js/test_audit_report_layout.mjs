// Il report di audit si impagina misurando, non stimando.
//
// Le pagine erano di altezza fissa con «overflow: hidden» e le schede venivano
// distribuite su un'altezza indovinata dalla lunghezza dei testi. Una stima
// bassa non lasciava una pagina brutta: tagliava le evidenze contro il bordo
// senza che niente lo dicesse, e le evidenze sono la prova su cui si firma il
// report.
//
//   node tests/js/test_audit_report_layout.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/netsec-audit.js'), 'utf8');

// 1. Nessuna stima di altezza rimasta in giro.
assert.doesNotMatch(src, /paginateRules/,
    'paginateRules(): l\'impaginazione a stima e\' tornata');
assert.doesNotMatch(src, /page1Cap|otherPagesCap/,
    'soglie di pagina cablate: l\'altezza va misurata, non decisa a priori');

// 2. L'impaginazione misura la posizione reale del piede di pagina.
const fnStart = src.indexOf('function paginateReport() {');
assert.ok(fnStart > 0, 'paginateReport() non trovata');
const fn = src.slice(fnStart, src.indexOf('\n}\n', fnStart));
assert.match(fn, /getBoundingClientRect/,
    'paginateReport() non misura nulla');
assert.match(fn, /paddingBottom/,
    'paginateReport() ignora il padding: il piede finirebbe fuori dal margine');

// 3. Una scheda piu' alta di una pagina fa crescere la pagina invece di essere
//    tagliata: senza questo il report perde evidenze in silenzio.
assert.match(fn, /pdf-page-tall/,
    'nessuna via d\'uscita per una scheda piu\' alta di una pagina');
assert.match(src, /\.pdf-page\.pdf-page-tall\s*\{[^}]*height:\s*auto/,
    'pdf-page-tall non toglie l\'altezza fissa');

// 4. Dopo una pagina cresciuta si riparte da una pagina nuova, altrimenti
//    tutte le schede successive ci finiscono dentro.
assert.match(fn, /startNewPage\s*=\s*true/,
    'dopo una pagina cresciuta non si apre una pagina nuova');

// 5. I comandi CLI non vanno spezzati a meta' parola ne' legati in un glifo
//    solo: chi legge il report li ridigita sull'apparato.
assert.doesNotMatch(src, /\.evidence-txt\s*\{[^}]*word-break:\s*break-all/,
    'evidence-txt spezza a meta\' parola');
assert.match(src, /font-variant-ligatures:\s*none/,
    'legature attive sul monospace dei comandi');

// 6. Guida, verifica ed evidenze occupano la larghezza piena: incolonnate
//    sotto il titolo allungavano la scheda lasciando vuota meta' riga.
assert.match(src, /\.col-detail\s*\{[^}]*grid-column:\s*2\s*\/\s*-1/,
    'col-detail non si estende sulle colonne di destra');
assert.match(src, /class="col-detail"/,
    'renderRuleCard() non emette col-detail');

console.log('ok - impaginazione report audit');
