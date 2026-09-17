// Column resizing (static/js/core.js): runs the real width helpers against a
// stub DOM. Guards the two ways it breaks silently: a width that follows the
// position instead of the ORIGINAL column after a reorder, and a stale saved
// layout (column count changed) being applied to a different table.
//
//   node tests/js/test_table_column_resize.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/core.js'), 'utf8');
const start = src.indexOf('function _cellSortValue');
const end = src.indexOf('// ===== Tastiera sugli elementi cliccabili non nativi');
assert.ok(start > 0 && end > start, 'table helpers not found in core.js');

let store = {};
const localStorageStub = {
    getItem: k => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
    removeItem: k => { delete store[k]; },
};

const { resizedColumnWidths, isValidColumnWidths, currentColumnWidths, applyColumnWidths,
    saveColumnWidths, resetColumnWidths, makeTableResizable } = (0, eval)(
    `(function (localStorage, tr) { ${src.slice(start, end)};
      return { resizedColumnWidths, isValidColumnWidths, currentColumnWidths, applyColumnWidths,
        saveColumnWidths, resetColumnWidths, makeTableResizable }; })`
)(localStorageStub, k => k);

function th(width, orig) {
    const attrs = orig === undefined ? {} : { 'data-col-orig': String(orig) };
    return {
        colSpan: 1, style: {}, dataset: {}, draggable: false, classList: { toggle() {}, remove() {} },
        getAttribute: n => (n in attrs ? attrs[n] : null),
        setAttribute: (n, v) => { attrs[n] = String(v); },
        hasAttribute: n => n in attrs,
        addEventListener() {},
        getBoundingClientRect() { return { width: parseFloat(this.style.width) || width, right: 0 }; },
    };
}
function table(id, cells) {
    return { id, style: {}, dataset: {}, tHead: { rows: [{ cells }] }, hasAttribute: () => false };
}

// Pure helper: clamps to the minimum, leaves other columns alone.
assert.deepEqual(resizedColumnWidths([100, 200], 1, 30), [100, 230]);
assert.deepEqual(resizedColumnWidths([100, 200], 0, -500), [40, 200]);
assert.equal(isValidColumnWidths([100, 200], 2), true);
assert.equal(isValidColumnWidths([100, 200], 3), false, 'column count changed');
assert.equal(isValidColumnWidths([100, 'x'], 2), false);

// Widths are indexed by original column, not position: after a reorder the
// header in position 0 is original column 1 and keeps its own width.
const moved = table('t1', [th(150, 1), th(90, 0)]);
assert.deepEqual(currentColumnWidths(moved), [90, 150]);
applyColumnWidths(moved, [60, 300]);
assert.equal(moved.tHead.rows[0].cells[0].style.width, '300px');
assert.equal(moved.tHead.rows[0].cells[1].style.width, '60px');
assert.equal(moved.style.tableLayout, 'fixed');
assert.equal(moved.style.width, '360px');

// Save -> fresh table with the same identity -> widths come back.
saveColumnWidths(moved, [60, 300]);
const fresh = table('t1', [th(10), th(10)]);
makeTableResizable(fresh);
assert.equal(fresh.dataset.resizable, '1');
assert.equal(fresh.tHead.rows[0].cells[0].style.width, '60px');

// A saved layout for 2 columns is not applied to a 3-column table.
const wider = table('t1', [th(10), th(10), th(10)]);
makeTableResizable(wider);
assert.equal(wider.style.tableLayout, undefined);

// Reset clears the styles and the stored widths.
resetColumnWidths(fresh);
assert.equal(fresh.style.tableLayout, '');
assert.equal(fresh.tHead.rows[0].cells[0].style.width, '');
assert.equal(Object.keys(store).length, 0);

console.log('table_column_resize: ok');

// --- Column picker: pure visibility rule --------------------------------
const { hiddenColumns, applyColumnVisibility } = (0, eval)(
    `(function (localStorage, tr) { ${src.slice(start, end)};
      return { hiddenColumns, applyColumnVisibility }; })`
)(localStorageStub, k => k);

assert.deepEqual(hiddenColumns(null, [3], 5), [3], 'default-hidden applies until the user chooses');
assert.deepEqual(hiddenColumns([], [3], 5), [], 'a saved "show all" beats the default');
assert.deepEqual(hiddenColumns([9], [3], 5), [3], 'a stale choice falls back to the defaults');
assert.deepEqual(hiddenColumns([0, 1], [], 2), [], 'never every column');

// Hidden by ORIGINAL index: after a reorder the right cells disappear.
{
    const cell = () => ({ style: {}, dataset: {} });
    const heads = [th(10, 1), th(10, 0)];
    const row = { cells: [cell(), cell()], dataset: {} };
    const t = { dataset: { colHidden: '[1]' }, tHead: { rows: [{ cells: heads }] },
        tBodies: [{ rows: [row] }] };
    applyColumnVisibility(t);
    assert.equal(heads[0].style.display, 'none');
    assert.equal(row.cells[0].style.display, 'none');
    assert.equal(row.cells[1].style.display, '');
}

console.log('table_column_picker: ok');
