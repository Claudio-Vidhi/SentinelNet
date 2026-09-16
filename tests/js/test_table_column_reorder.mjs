// Riordino colonne (static/js/core.js): esegue davvero le funzioni pure e la
// riapplicazione dietro il MutationObserver contro un DOM finto. Copre lo
// stesso pattern di test_sort_table.mjs, per lo stesso motivo: un grep sul
// sorgente non avrebbe preso l'errore che questo file previene (appendChild
// su un indice della collezione live invece che su uno snapshot, che sposta
// la colonna sbagliata dopo il primo elemento riordinato).
//
//   node tests/js/test_table_column_reorder.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/core.js'), 'utf8');
const start = src.indexOf('function arrayMoveItem');
const end = src.indexOf('// ===== Tastiera sugli elementi cliccabili non nativi');
assert.ok(start > 0 && end > start, 'funzioni di riordino colonne non trovate in core.js');

const localStorageStub = (() => {
    let store = {};
    let throwing = false;
    return {
        getItem: k => { if (throwing) throw new Error('storage disabled'); return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
        setItem: (k, v) => { if (throwing) throw new Error('storage disabled'); store[k] = String(v); },
        removeItem: k => { if (throwing) throw new Error('storage disabled'); delete store[k]; },
        _reset: () => { store = {}; },
        _setThrowing: v => { throwing = v; },
        _dump: () => ({ ...store }),
    };
})();

const trStub = key => key;

const { arrayMoveItem, isValidColumnOrder, isTableReorderEligible, columnOrderStorageKey,
    currentColumnOrder, applyColumnOrder, saveColumnOrder, applySavedColumnOrder,
    resetColumnOrder, moveTableColumn, reapplyColumnOrder, makeTableReorderable } = (0, eval)(
    `(function (localStorage, tr) { ${src.slice(start, end)};
      return { arrayMoveItem, isValidColumnOrder, isTableReorderEligible, columnOrderStorageKey,
        currentColumnOrder, applyColumnOrder, saveColumnOrder, applySavedColumnOrder,
        resetColumnOrder, moveTableColumn, reapplyColumnOrder, makeTableReorderable }; })`
)(localStorageStub, trStub);

// --- DOM stub: th/td con appendChild "sequenziale" come i td/tr veri --------

function cell(text, { colSpan = 1 } = {}) {
    const c = {
        colSpan, textContent: text, attrs: {}, dataset: {}, tabIndex: -1, draggable: false,
        getAttribute(n) { return Object.prototype.hasOwnProperty.call(this.attrs, n) ? this.attrs[n] : null; },
        setAttribute(n, v) { this.attrs[n] = String(v); },
        hasAttribute(n) { return Object.prototype.hasOwnProperty.call(this.attrs, n); },
        addEventListener() { },
        focus() { },
    };
    return c;
}

function row(cells) {
    const r = { cells, dataset: {} };
    r.appendChild = function (node) {
        // Come il DOM vero: rimuove il nodo da dov'era e lo mette in fondo.
        const i = this.cells.indexOf(node);
        if (i >= 0) this.cells.splice(i, 1);
        this.cells.push(node);
        return node;
    };
    return r;
}

function table({ id = null, headTexts, bodyRows = [], noReorder = false, extraTheadRow = false, ancestor = null }) {
    const headCells = headTexts.map(t => cell(t));
    const theadRows = [row(headCells)];
    if (extraTheadRow) theadRows.push(row([cell('x')]));
    const tBodyRows = bodyRows.map(row);
    const tb = { rows: tBodyRows };
    const attrs = {};
    if (noReorder) attrs['data-no-reorder'] = '';
    const t = {
        id: id || '',
        dataset: {},
        tHead: { rows: theadRows },
        tBodies: [tb],
        hasAttribute(n) { return Object.prototype.hasOwnProperty.call(attrs, n); },
        getAttribute(n) { return attrs[n] ?? null; },
        closest(sel) {
            if (sel !== '[id]') return null;
            return ancestor;
        },
    };
    return { table: t, headCells, tb };
}

// --- 1. arrayMoveItem: permutazione pura ------------------------------------
{
    assert.deepEqual(arrayMoveItem([0, 1, 2, 3], 0, 2), [1, 2, 0, 3]);
    assert.deepEqual(arrayMoveItem([0, 1, 2, 3], 3, 0), [3, 0, 1, 2]);
    assert.deepEqual(arrayMoveItem(['a', 'b', 'c'], 1, 1), ['a', 'b', 'c']);
}

// --- 2. isValidColumnOrder: permutazione valida solo se completa -----------
{
    assert.equal(isValidColumnOrder([0, 1, 2], 3), true);
    assert.equal(isValidColumnOrder([0, 1], 3), false, 'lunghezza diversa dal numero di colonne');
    assert.equal(isValidColumnOrder([0, 1, 1], 3), false, 'valore duplicato');
    assert.equal(isValidColumnOrder([0, 1, 5], 3), false, 'valore fuori range');
    assert.equal(isValidColumnOrder(null, 3), false, 'niente salvato');
    assert.equal(isValidColumnOrder('nope', 3), false, 'non e\' un array');
}

// --- 3. Eligibilita' --------------------------------------------------------
{
    const t1 = table({ headTexts: ['A', 'B', 'C'], bodyRows: [[cell('1'), cell('2'), cell('3')]] });
    assert.equal(isTableReorderEligible(t1.table), true);

    const t2 = table({ headTexts: ['A', 'B'], noReorder: true, bodyRows: [] });
    assert.equal(isTableReorderEligible(t2.table), false, 'data-no-reorder esclude la tabella');

    const t3 = table({ headTexts: ['A', 'B'], extraTheadRow: true, bodyRows: [] });
    assert.equal(isTableReorderEligible(t3.table), false, 'thead multi-riga non e\' gestibile');

    const t4 = table({ headTexts: ['A', 'B'], bodyRows: [] });
    t4.headCells[0].colSpan = 2;
    assert.equal(isTableReorderEligible(t4.table), false, 'intestazione unita (colSpan>1)');

    const t5 = table({ headTexts: ['A', 'B', 'C'], bodyRows: [[cell('1'), cell('2')]] });
    assert.equal(isTableReorderEligible(t5.table), false, 'riga di corpo con meno celle dell\'header');

    // Riga di dettaglio (cella singola a tutta larghezza): non conta come mismatch.
    const t6 = table({
        headTexts: ['A', 'B', 'C'],
        bodyRows: [[cell('1'), cell('2'), cell('3')], [cell('dettaglio', { colSpan: 3 })]],
    });
    assert.equal(isTableReorderEligible(t6.table), true, 'la riga di dettaglio e\' l\'eccezione nota');
}

// --- 4. columnOrderStorageKey -----------------------------------------------
{
    const t1 = table({ id: 'devicesTable', headTexts: ['A', 'B'], bodyRows: [] });
    assert.equal(columnOrderStorageKey(t1.table), 'sn.colorder.devicesTable.2');

    const ancestor = { id: 'panelX', querySelectorAll: () => [t2NoId] };
    var t2NoId; // populated below to close the self-reference
    const t2 = table({ headTexts: ['A', 'B', 'C'], bodyRows: [], ancestor });
    t2NoId = t2.table;
    assert.equal(columnOrderStorageKey(t2.table), 'sn.colorder.panelX.0.3');

    const t3 = table({ headTexts: ['A', 'B'], bodyRows: [], ancestor: null });
    assert.equal(columnOrderStorageKey(t3.table), null, 'nessun antenato con id: non persistibile');
}

// --- 5. moveTableColumn muove header E celle insieme, verso entrambi -------
{
    localStorageStub._reset();
    const t = table({
        id: 'movable',
        headTexts: ['ID', 'Nome', 'Stato'],
        bodyRows: [[cell('1'), cell('rossi'), cell('ok')]],
    });
    makeTableReorderable(t.table);
    assert.deepEqual(t.headCells.map(c => c.getAttribute('data-col-orig')), ['0', '1', '2']);

    // Sposta la colonna 0 (ID) in posizione 2 (dopo Stato).
    moveTableColumn(t.table, 0, 2);
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['Nome', 'Stato', 'ID']);
    assert.deepEqual(t.tb.rows[0].cells.map(c => c.textContent), ['rossi', 'ok', '1'],
        'la cella del corpo segue la sua colonna, non resta all\'indice fisico vecchio');

    // Sposta indietro: colonna in posizione 2 (ID) a posizione 0.
    moveTableColumn(t.table, 2, 0);
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['ID', 'Nome', 'Stato']);
    assert.deepEqual(t.tb.rows[0].cells.map(c => c.textContent), ['1', 'rossi', 'ok']);
}

// --- 6. Reset (doppio clic) ripristina l'ordine originale e cancella lo storage
{
    localStorageStub._reset();
    const t = table({ id: 'resettable', headTexts: ['A', 'B', 'C'], bodyRows: [[cell('1'), cell('2'), cell('3')]] });
    makeTableReorderable(t.table);
    moveTableColumn(t.table, 0, 2);
    assert.ok(localStorageStub._dump()['sn.colorder.resettable.3'], 'la mossa e\' stata salvata');

    resetColumnOrder(t.table);
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['A', 'B', 'C']);
    assert.deepEqual(t.tb.rows[0].cells.map(c => c.textContent), ['1', '2', '3']);
    assert.equal(localStorageStub._dump()['sn.colorder.resettable.3'], undefined,
        'il reset cancella l\'ordine salvato');
}

// --- 7. Ordine salvato applicato a un render nuovo --------------------------
{
    localStorageStub._reset();
    localStorageStub.setItem('sn.colorder.saved.3', JSON.stringify([2, 0, 1]));
    const t = table({ id: 'saved', headTexts: ['A', 'B', 'C'], bodyRows: [[cell('a'), cell('b'), cell('c')]] });
    makeTableReorderable(t.table); // prima enhance: dovrebbe leggere lo storage e riordinare
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['C', 'A', 'B']);
    assert.deepEqual(t.tb.rows[0].cells.map(c => c.textContent), ['c', 'a', 'b']);
}

// --- 8. Ordine salvato invalido (colonne cambiate) viene ignorato ----------
{
    localStorageStub._reset();
    localStorageStub.setItem('sn.colorder.stale.3', JSON.stringify([1, 0])); // lunghezza sbagliata
    const t = table({ id: 'stale', headTexts: ['A', 'B', 'C'], bodyRows: [[cell('a'), cell('b'), cell('c')]] });
    makeTableReorderable(t.table);
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['A', 'B', 'C'],
        'un ordine salvato non valido lascia la tabella nell\'ordine originale');
}

// --- 9. reapplyColumnOrder: righe nuove nella stessa passata del MutationObserver
{
    localStorageStub._reset();
    const t = table({
        id: 'reapply', headTexts: ['A', 'B', 'C'],
        bodyRows: [[cell('1'), cell('2'), cell('3')]],
    });
    makeTableReorderable(t.table);
    moveTableColumn(t.table, 0, 2); // A finisce in fondo: header ora B,C,A
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['B', 'C', 'A']);

    // Il re-render riscrive tbody: righe nuove sempre nell'ordine ORIGINALE
    // delle colonne, come farebbe il render di una tabella vera.
    const freshRow = row([cell('x1'), cell('x2'), cell('x3')]);
    t.tb.rows = [freshRow];
    reapplyColumnOrder(t.table);
    assert.deepEqual(t.tb.rows[0].cells.map(c => c.textContent), ['x2', 'x3', 'x1'],
        'la riga nuova va riportata all\'ordine visivo corrente');

    // Seconda passata sulla stessa riga: gia' taggata, nessuna riscrittura.
    const before = t.tb.rows[0].cells.slice();
    reapplyColumnOrder(t.table);
    assert.deepEqual(t.tb.rows[0].cells, before, 'una riga gia\' in ordine non va ritoccata');
}

// --- 10. Righe di dettaglio restano intoccate dal riordino -----------------
{
    localStorageStub._reset();
    const t = table({
        id: 'detailrow', headTexts: ['A', 'B', 'C'],
        bodyRows: [[cell('1'), cell('2'), cell('3')], [cell('dettaglio', { colSpan: 3 })]],
    });
    makeTableReorderable(t.table);
    const detail = t.tb.rows[1].cells[0];
    moveTableColumn(t.table, 0, 2);
    assert.equal(t.tb.rows[1].cells.length, 1, 'la riga di dettaglio resta a cella singola');
    assert.equal(t.tb.rows[1].cells[0], detail, 'lo stesso nodo, mai spostato');
}

// --- 11. localStorage che lancia non deve rompere nulla ---------------------
{
    localStorageStub._reset();
    localStorageStub._setThrowing(true);
    const t = table({ id: 'nostorage', headTexts: ['A', 'B', 'C'], bodyRows: [[cell('1'), cell('2'), cell('3')]] });
    assert.doesNotThrow(() => makeTableReorderable(t.table));
    assert.doesNotThrow(() => moveTableColumn(t.table, 0, 1));
    assert.doesNotThrow(() => resetColumnOrder(t.table));
    localStorageStub._setThrowing(false);
}

console.log('table_column_reorder: ok');
