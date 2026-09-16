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
// Include anche il codice di ordinamento (_cellSortValue.._applySort..
// sortTableByColumn..makeTableSortable): due dei bug che questo file copre
// sono nell'INTERAZIONE fra riordino e ordinamento (indice catturato allo
// static bind vs letto al click), quindi vanno eseguiti insieme, non isolati.
const start = src.indexOf('function _cellSortValue');
const end = src.indexOf('// ===== Tastiera sugli elementi cliccabili non nativi');
assert.ok(start > 0 && end > start, 'funzioni di ordinamento/riordino non trovate in core.js');

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
    resetColumnOrder, moveTableColumn, reapplyColumnOrder, makeTableReorderable,
    makeTableSortable, sortTableByColumn } = (0, eval)(
    `(function (localStorage, tr) { ${src.slice(start, end)};
      return { arrayMoveItem, isValidColumnOrder, isTableReorderEligible, columnOrderStorageKey,
        currentColumnOrder, applyColumnOrder, saveColumnOrder, applySavedColumnOrder,
        resetColumnOrder, moveTableColumn, reapplyColumnOrder, makeTableReorderable,
        makeTableSortable, sortTableByColumn }; })`
)(localStorageStub, trStub);

// --- DOM stub: th/td con appendChild "sequenziale" come i td/tr veri, e
// addEventListener/dispatch reali (necessari per il bug dell'indice
// catturato al bind e per la guardia drag-non-e'-click). ------------------

function cell(text, { colSpan = 1 } = {}) {
    const c = {
        colSpan, textContent: text, attrs: {}, dataset: {}, tabIndex: -1, draggable: false,
        style: {}, parentNode: null, _listeners: {},
        getAttribute(n) { return Object.prototype.hasOwnProperty.call(this.attrs, n) ? this.attrs[n] : null; },
        setAttribute(n, v) { this.attrs[n] = String(v); },
        removeAttribute(n) { delete this.attrs[n]; },
        hasAttribute(n) { return Object.prototype.hasOwnProperty.call(this.attrs, n); },
        querySelector: () => null, // _cellSortValue: niente input/select editabile nello stub
        addEventListener(type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); },
        // Non e' dispatchEvent(): invoca direttamente i listener registrati,
        // nello stesso ordine di registrazione, rispettando
        // stopImmediatePropagation() come farebbe il DOM vero sullo stesso
        // elemento.
        dispatch(type, evtProps = {}) {
            let stopped = false;
            let defaultPrevented = false;
            const e = Object.assign({
                preventDefault() { defaultPrevented = true; },
                stopImmediatePropagation() { stopped = true; },
            }, evtProps);
            for (const fn of (this._listeners[type] || [])) {
                if (stopped) break;
                fn(e);
            }
            e.defaultPrevented = defaultPrevented;
            return e;
        },
        focus() { },
    };
    return c;
}

function row(cells) {
    const r = { cells, dataset: {} };
    cells.forEach(c => { c.parentNode = r; });
    r.appendChild = function (node) {
        // Come il DOM vero: rimuove il nodo da dov'era e lo mette in fondo.
        const i = this.cells.indexOf(node);
        if (i >= 0) this.cells.splice(i, 1);
        this.cells.push(node);
        node.parentNode = this;
        return node;
    };
    return r;
}

function table({ id = null, headTexts, bodyRows = [], noReorder = false, extraTheadRow = false, ancestor = null }) {
    const headCells = headTexts.map(t => cell(t));
    const theadRows = [row(headCells)];
    if (extraTheadRow) theadRows.push(row([cell('x')]));
    const tBodyRows = bodyRows.map(row);
    const tb = {
        rows: tBodyRows,
        appendChild(r) {
            // Necessario per sortTableByColumn/_applySort, che riordina il
            // tbody con lo stesso trucco (appendChild in sequenza).
            const i = this.rows.indexOf(r);
            if (i >= 0) this.rows.splice(i, 1);
            this.rows.push(r);
            return r;
        },
    };
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

// --- 12. Il click di ordinamento dopo un riordino ordina la colonna VISTA,
//     non quella catturata al bind. Regressione: makeTableSortable legava
//     `idx` una volta sola nel forEach; dopo uno spostamento il th cliccato
//     non e' piu' alla posizione con cui era stato legato, e il click
//     ordinava la colonna sbagliata (quella che ora occupa il vecchio indice).
{
    localStorageStub._reset();
    // ID e Nome NON sono in accordo: ID gia' ascendente, Nome no. Se il
    // click ordina ancora per il vecchio indice (ID, dopo lo spostamento),
    // l'ordine delle righe non cambia; solo ordinando per Nome (la colonna
    // vista) le righe si scambiano.
    const t = table({
        id: 'sortafterreorder', headTexts: ['ID', 'Nome', 'Stato'],
        bodyRows: [[cell('1'), cell('z'), cell('ok')], [cell('2'), cell('a'), cell('ok')]],
    });
    makeTableReorderable(t.table);
    makeTableSortable(t.table);

    // Sposta "Nome" (indice 1) in prima posizione: l'header che il click
    // colpira' e' lo stesso nodo, ma ora e' all'indice 0.
    moveTableColumn(t.table, 1, 0);
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['Nome', 'ID', 'Stato']);

    const nomeHeader = t.table.tHead.rows[0].cells[0];
    nomeHeader.dispatch('click');

    assert.deepEqual(t.tb.rows.map(r => r.cells[0].textContent), ['a', 'z'],
        'il click deve ordinare per la colonna Nome mostrata ora in prima posizione, non per il vecchio indice');
}

// --- 13. Un drag non deve far scattare l'ordinamento -----------------------
{
    localStorageStub._reset();
    const t = table({ id: 'dragnoclick', headTexts: ['A', 'B'], bodyRows: [[cell('1'), cell('2')]] });
    makeTableReorderable(t.table);
    makeTableSortable(t.table);
    const th = t.table.tHead.rows[0].cells[0];

    th.dispatch('dragstart', { dataTransfer: null });
    th.dispatch('click');
    assert.equal(th.getAttribute('data-sort-asc'), null,
        'il click che segue un drag non deve avviare l\'ordinamento');

    // Un click genuino, senza drag precedente, deve invece funzionare.
    th.dispatch('click');
    assert.equal(th.getAttribute('data-sort-asc'), 'true', 'un click vero ordina normalmente');
}

// --- 14. Alt+freccia al primo/ultimo header: nessuno spostamento possibile,
//     quindi preventDefault() non va chiamato (altrimenti Alt+freccia
//     blocca in silenzio indietro/avanti del browser senza fare nulla).
{
    localStorageStub._reset();
    const t = table({ id: 'boundary', headTexts: ['A', 'B', 'C'], bodyRows: [] });
    makeTableReorderable(t.table);
    const first = t.table.tHead.rows[0].cells[0];
    const last = t.table.tHead.rows[0].cells[2];

    const eLeft = first.dispatch('keydown', { altKey: true, key: 'ArrowLeft' });
    assert.equal(eLeft.defaultPrevented, false, 'nessuno spostamento a sinistra del primo header');
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['A', 'B', 'C']);

    const eRight = last.dispatch('keydown', { altKey: true, key: 'ArrowRight' });
    assert.equal(eRight.defaultPrevented, false, 'nessuno spostamento a destra dell\'ultimo header');
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['A', 'B', 'C']);

    // Nel mezzo invece si muove, e li' preventDefault() e' atteso.
    const middle = t.table.tHead.rows[0].cells[1];
    const eMid = middle.dispatch('keydown', { altKey: true, key: 'ArrowRight' });
    assert.equal(eMid.defaultPrevented, true, 'uno spostamento valido chiama preventDefault');
    assert.deepEqual(t.table.tHead.rows[0].cells.map(c => c.textContent), ['A', 'C', 'B']);
}

console.log('table_column_reorder: ok');
