// Ordinamento colonne: esegue davvero sortTableByColumn() di static/js/core.js
// contro un DOM finto. Un test "grep" sul sorgente non basta — la regressione
// che questo file esiste per impedire (appendChild di un array invece di una
// riga) lasciava il sorgente pieno delle parole giuste e la tabella immobile.
//
//   node tests/js/test_sort_table.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/core.js'), 'utf8');
const start = src.indexOf('function _cellSortValue');
const end = src.indexOf('function enhanceAllTables');
assert.ok(start > 0 && end > start, 'funzioni di ordinamento non trovate in core.js');
// document minimo: serve solo se l'implementazione crea ancora nodi.
const document = {
    createElement: () => ({ style: {}, dataset: {}, classList: { add() {} } }),
};
const { sortTableByColumn, makeTableSortable, reapplySort } = (0, eval)(
    `(document => { ${src.slice(start, end)};
      return { sortTableByColumn, makeTableSortable, reapplySort }; })`
)(document);

const cell = (text, colSpan = 1) => ({
    colSpan, textContent: text,
    getAttribute: () => null,
    querySelector: () => null,
});
const rule = (id, name) => ({ id, cells: [cell(name), cell('titolo')] });
const detail = id => ({ id, cells: [cell('', 6)] });   // <td colspan="6">

function build(rows) {
    const tbody = {
        rows,
        moves: 0,
        appendChild(r) {
            this.moves++;
            // Come il DOM vero: tutto ciò che non è un nodo è un TypeError.
            if (!r || !Array.isArray(r.cells)) {
                throw new TypeError('appendChild: parameter 1 is not of type Node');
            }
            const i = this.rows.indexOf(r);
            if (i >= 0) this.rows.splice(i, 1);
            this.rows.push(r);
        },
    };
    const th = {
        attrs: {}, dataset: {}, style: {}, innerHTML: 'ID', children: [],
        getAttribute(n) { return this.attrs[n] ?? null; },
        setAttribute(n, v) { this.attrs[n] = String(v); },
        removeAttribute(n) { delete this.attrs[n]; },
        querySelector: () => null,
        appendChild(n) { this.children.push(n); },
        addEventListener(_, fn) { this.onclick = fn; },
    };
    const table = {
        dataset: {}, tBodies: [tbody], tHead: { rows: [{ cells: [th] }] },
    };
    return { table, tbody, th };
}

function order(tbody) {
    return tbody.rows.map(r => r.id);
}

// 1. Ordinamento crescente: le righe di dettaglio seguono la loro regola.
{
    const { table, tbody, th } = build([
        rule('B', 'AUD-B'), detail('B-ev'),
        rule('A', 'AUD-A'), detail('A-ev'),
        rule('C', 'AUD-C'), detail('C-ev'),
    ]);
    sortTableByColumn(table, 0, th);
    assert.deepEqual(order(tbody), ['A', 'A-ev', 'B', 'B-ev', 'C', 'C-ev']);

    // 2. Secondo click: decrescente, dettagli ancora appaiati.
    sortTableByColumn(table, 0, th);
    assert.deepEqual(order(tbody), ['C', 'C-ev', 'B', 'B-ev', 'A', 'A-ev']);
}

// 3. Tabella senza righe di dettaglio: comportamento invariato.
{
    const { table, tbody, th } = build([rule('2', 'b'), rule('1', 'a'), rule('3', 'c')]);
    sortTableByColumn(table, 0, th);
    assert.deepEqual(order(tbody), ['1', '2', '3']);
}

// 4. Riga a tutta larghezza in testa (stato vuoto): non ha una riga da seguire
//    e resta una voce a sé, senza far esplodere l'ordinamento.
{
    const { table, tbody, th } = build([detail('empty'), rule('A', 'a')]);
    sortTableByColumn(table, 0, th);
    assert.equal(tbody.rows.length, 2);
}

// 5. L'affordance di ordinamento deve vivere in un ATTRIBUTO, non in un nodo
//    figlio: applyLanguage() riscrive l'innerHTML di ogni [data-i18n], quindi
//    una <span class="sort-ind"> appesa all'intestazione spariva al primo
//    cambio lingua (e al caricamento) e non tornava piu'. Restavano colonne
//    ordinabili senza freccia, senza verso e senza alcun segno di esserlo.
{
    const { table, th } = build([rule('B', 'b'), rule('A', 'a')]);
    makeTableSortable(table);
    assert.equal(th.getAttribute('data-sortable'), '1',
        'l\'intestazione deve dichiararsi ordinabile con un attributo');

    th.innerHTML = 'ID Regola';          // esattamente cio' che fa applyLanguage()
    assert.equal(th.getAttribute('data-sortable'), '1',
        'l\'affordance non deve dipendere da un nodo figlio');

    sortTableByColumn(table, 0, th);
    assert.equal(th.getAttribute('data-sort-asc'), 'true', 'primo click: crescente');
    sortTableByColumn(table, 0, th);
    assert.equal(th.getAttribute('data-sort-asc'), 'false', 'secondo click: decrescente');
}

// 6. Un re-render azzera l'ordinamento. renderAuditRulesTable() riscrive
//    tbody.innerHTML dai dati originali a ogni apertura di dettaglio, a ogni
//    cambio filtro e a ogni refresh: l'ordine, che vive solo nel DOM, spariva
//    e la tabella tornava all'ordine di partenza sotto gli occhi dell'utente.
{
    const { table, tbody, th } = build([
        rule('B', 'AUD-B'), detail('B-ev'),
        rule('A', 'AUD-A'), detail('A-ev'),
        rule('C', 'AUD-C'), detail('C-ev'),
    ]);
    makeTableSortable(table);
    sortTableByColumn(table, 0, th);
    assert.deepEqual(order(tbody), ['A', 'A-ev', 'B', 'B-ev', 'C', 'C-ev']);

    // Il re-render: righe nuove, ordine dei dati, stesso <thead>.
    tbody.rows = [
        rule('B', 'AUD-B'), detail('B-ev'),
        rule('A', 'AUD-A'), detail('A-ev'),
        rule('C', 'AUD-C'), detail('C-ev'),
    ];
    reapplySort(table);
    assert.deepEqual(order(tbody), ['A', 'A-ev', 'B', 'B-ev', 'C', 'C-ev'],
        'dopo un re-render l\'ordinamento attivo va riapplicato');

    // Il verso va conservato: riapplicare non e' cliccare di nuovo.
    sortTableByColumn(table, 0, th);                      // -> decrescente
    tbody.rows = [rule('A', 'AUD-A'), rule('C', 'AUD-C'), rule('B', 'AUD-B')];
    reapplySort(table);
    assert.deepEqual(order(tbody), ['C', 'B', 'A'], 'il verso non deve invertirsi');
}

// 7. Riapplicare su una tabella gia' in ordine non deve toccare il DOM. La
//    riapplicazione gira dentro il MutationObserver: se scrivesse comunque,
//    ogni passata genererebbe le mutazioni che schedulano la successiva.
{
    const { table, tbody, th } = build([rule('A', 'a'), rule('B', 'b'), rule('C', 'c')]);
    makeTableSortable(table);
    sortTableByColumn(table, 0, th);
    tbody.moves = 0;
    reapplySort(table);
    assert.equal(tbody.moves, 0, 'nessuna scrittura se l\'ordine e\' gia\' quello giusto');
}

// 8. Nessuna colonna ordinata: riapplicare non fa nulla.
{
    const { table, tbody } = build([rule('B', 'b'), rule('A', 'a')]);
    makeTableSortable(table);
    reapplySort(table);
    assert.deepEqual(order(tbody), ['B', 'A']);
}

console.log('sort_table: ok');
