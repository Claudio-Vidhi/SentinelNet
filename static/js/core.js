// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// Escape di una stringa dentro un literal JavaScript, per la convenzione di
// casa escapeHtml(jsStr(x)). Viveva in mcp-client.js, che era caricato con un
// <script> fisso: alla rimozione di quella tab sarebbe sparito da sotto ai
// tre moduli che lo usano (diagnosi, incidents, fortigate-management), tutti
// lazy, tutti in questo unico scope globale. Sta qui perche' core.js c'e'
// sempre.
const jsStr = s => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");

// --- SIDEBAR RAIL (collasso a icone) ---

const SIDEBAR_COLLAPSED_KEY = 'sidebarCollapsed';

// Con la rail collassata restano solo le icone: il tooltip nativo è l'unica
// etichetta disponibile. Il testo viene DERIVATO dal label già tradotto, così
// non esiste una seconda copia della stringa da tenere allineata: basta
// richiamare questa funzione dopo ogni cambio lingua.
function syncNavTooltips() {
    const collapsed = document.body.classList.contains('sidebar-collapsed');
    document.querySelectorAll('.sidenav .nav-item').forEach(btn => {
        const label = btn.querySelector('.nav-left');
        if (!label) return;
        const text = label.textContent.trim();
        if (collapsed && text) btn.setAttribute('title', text);
        else btn.removeAttribute('title');
    });
}

function applySidebarCollapsed(collapsed) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    const btn = document.getElementById('sidebarToggle');
    if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    syncNavTooltips();
}

function toggleSidebar() {
    const collapsed = !document.body.classList.contains('sidebar-collapsed');
    try { localStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? '1' : '0'); } catch (e) { }
    applySidebarCollapsed(collapsed);
}

// --- NAV GROUPS (collapsible) ---
// Rarely used groups start closed so the everyday ones fit without scrolling.
// Only the user's choice is stored; the group holding the open tab is always
// opened by switchTab, otherwise the active item would be hidden.
const NAV_GROUPS_KEY = 'navGroupsCollapsed';
const NAV_GROUPS_DEFAULT = ['tools', 'change', 'admin'];

function setNavGroupCollapsed(group, collapsed) {
    group.classList.toggle('collapsed', collapsed);
    group.querySelector('.nav-group-toggle')?.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
}

function saveNavGroups() {
    const closed = Array.from(document.querySelectorAll('.nav-group.collapsed'))
        .map(g => g.getAttribute('data-nav-group'));
    try { localStorage.setItem(NAV_GROUPS_KEY, JSON.stringify(closed)); } catch (e) { }
}

(function restoreNavGroups() {
    let closed = NAV_GROUPS_DEFAULT;
    try {
        const saved = JSON.parse(localStorage.getItem(NAV_GROUPS_KEY) || 'null');
        if (Array.isArray(saved)) closed = saved;
    } catch (e) { }
    document.querySelectorAll('.nav-group[data-nav-group]').forEach(g => {
        setNavGroupCollapsed(g, closed.includes(g.getAttribute('data-nav-group')));
    });
})();

document.addEventListener('click', e => {
    const toggle = e.target.closest('.nav-group-toggle');
    const group = toggle?.closest('.nav-group');
    if (!group) return;
    setNavGroupCollapsed(group, !group.classList.contains('collapsed'));
    saveNavGroups();
});

// Topbar breadcrumb: nav group › page, read from the translated nav labels so
// there is no second copy of the strings. Called on tab switch and language change.
function syncTopbarCrumb() {
    const btn = document.querySelector('.sidenav .nav-item.active');
    const page = document.getElementById('topbarCrumbPage');
    const group = document.getElementById('topbarCrumbGroup');
    if (!btn || !page || !group) return;
    page.textContent = btn.querySelector('.nav-left')?.textContent.trim() || '';
    group.textContent = btn.closest('.nav-group')?.querySelector('.nav-group-label')?.textContent.trim() || '';
    group.parentElement?.classList.toggle('no-group', !group.textContent);
}

// --- RESA CHIARA / SCURA ---
// Il quadro esiste in due rese reali: targa incisa e schermo SCADA. Senza
// preferenza salvata si segue il sistema operativo, quindi il primo click
// deve partire dalla polarità effettivamente a schermo, non da un default.
const THEME_KEY = 'sentinelnet_theme';
const UI_VARIANT_KEY = 'sentinelnet_ui_variant';

function toggleTheme() {
    const explicit = document.documentElement.getAttribute('data-theme');
    const current = explicit
        || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem(THEME_KEY, next); } catch (e) { }
}

function applyUiVariant(variant, saveServer = false) {
    const valid = ['default', 'design-1', 'design-2', 'design-3'];
    const selected = valid.includes(variant) ? variant : 'default';

    document.documentElement.setAttribute('data-ui-variant', selected);
    try { localStorage.setItem(UI_VARIANT_KEY, selected); } catch (e) { }

    let linkEl = document.getElementById('theme-variant-stylesheet');
    if (selected === 'default') {
        if (linkEl) linkEl.remove();
    } else {
        if (!linkEl) {
            linkEl = document.createElement('link');
            linkEl.id = 'theme-variant-stylesheet';
            linkEl.rel = 'stylesheet';
            document.head.appendChild(linkEl);
        }
        linkEl.href = `/static/css/themes/${selected}.css`;
    }

    const selectEl = document.getElementById('uiVariantSelect');
    if (selectEl && selectEl.value !== selected) {
        selectEl.value = selected;
    }

    if (saveServer) {
        const headers = { 'Content-Type': 'application/json', 'X-Requested-With': 'SentinelNet' };
        fetch('/api/settings/ui-variant', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ ui_variant: selected })
        }).catch(err => console.warn('Save UI variant failed:', err));
    }
}

function initUiVariant() {
    let saved = null;
    try { saved = localStorage.getItem(UI_VARIANT_KEY); } catch (e) { }
    if (saved) {
        applyUiVariant(saved);
        return;
    }
    fetch('/api/settings/ui-variant', {
        headers: { 'X-Requested-With': 'SentinelNet' }
    })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
            if (data && data.ui_variant) {
                applyUiVariant(data.ui_variant);
            }
        })
        .catch(() => {});
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initUiVariant);
} else {
    initUiVariant();
}

// Canvas e librerie esterne (vis.js, xterm.js) vogliono un colore vero: una
// stringa 'var(--x)' non la sanno risolvere. Qui il token viene letto dallo
// stile calcolato, così anche la mappa e il terminale seguono la resa attiva.
function cssVar(name, fallback) {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback || '#000000';
}

let globalDevices = [];
let globalGroups = {};
let globalVendors = {};
let globalVersions = {}; // Cache globale per lo stato delle scansioni (ottimizzazione UI)
let currentRole = 'viewer';   // ruolo dell'utente loggato (admin/operator/viewer)
let currentUsername = '';
let currentUserGroups = [];   // tenant dell'utente loggato (vuoto = tutti); da /api/auth/me
let currentAllowedTabs = [];  // tab concesse all'utente loggato (vuoto = tutte), normalizzate
let appLoading = false;

// --- AUTENTICAZIONE E UTILITY ---

// Escaping HTML per tutti i valori dinamici (hostname dai config, nomi gruppo/vendor,
// descrizioni EUVD): previene markup rotto e stored XSS nelle tabelle e nei tooltip.
function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Neutralizza la formula injection nei CSV: i valori che iniziano con = + - @ TAB CR
// possono essere interpretati come formule da Excel/LibreOffice. L'apostrofo iniziale
// forza il testo; la quotatura CSV avviene dopo per mantenere l'apostrofo nella cella.
function csvCell(v) {
    let s = Array.isArray(v) ? v.join(' ') : (v === null || v === undefined ? '' : String(v));
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",;\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

// ===== Ordinamento generico colonne per TUTTE le tabelle =====
// Click sull'intestazione: ordina crescente/decrescente. Le celle editabili
// (input/select) ordinano per valore del campo
function _cellSortValue(td) {
    if (!td) return '';
    const sv = td.getAttribute('data-sort-value');
    if (sv !== null && sv !== undefined) return String(sv).trim();
    const f = td.querySelector('input, select');
    return f ? String(f.value || '').trim() : td.textContent.trim();
}
function _applySort(table, colIdx, asc) {
    const tbody = table.tBodies[0];
    if (!tbody) return;
    // Una riga di dettaglio (cella unica a tutta larghezza, es. le evidenze
    // aperte nella matrice audit) non e' una voce autonoma: e' la coda della
    // riga che l'ha aperta. Ordinarla da sola la staccava dalla sua regola e
    // la spediva in cima, perche' non ha la colonna su cui si ordina.
    const groups = [];
    Array.from(tbody.rows).forEach(r => {
        if (groups.length && r.cells.length === 1 && r.cells[0].colSpan > 1) {
            groups[groups.length - 1].push(r);
        } else {
            groups.push([r]);
        }
    });
    groups.sort((ga, gb) => {
        const x = _cellSortValue(ga[0].cells[colIdx]);
        const y = _cellSortValue(gb[0].cells[colIdx]);
        const numX = Number(x);
        const numY = Number(y);
        if (x !== '' && y !== '' && !isNaN(numX) && !isNaN(numY)) {
            if (numX === 0 && numY !== 0) return 1;
            if (numY === 0 && numX !== 0) return -1;
            return asc ? numX - numY : numY - numX;
        }
        const c = x.localeCompare(y, undefined, { numeric: true, sensitivity: 'base' });
        return asc ? c : -c;
    });
    const target = groups.flat();
    const current = Array.from(tbody.rows);
    // reapplySort() gira dentro il MutationObserver: riscrivere quando l'ordine
    // e' gia' quello giusto produrrebbe le mutazioni che schedulano la passata
    // successiva, senza mai fermarsi.
    if (target.length === current.length && target.every((r, i) => r === current[i])) return;
    target.forEach(r => tbody.appendChild(r));
}

function sortTableByColumn(table, colIdx, th) {
    const asc = th.getAttribute('data-sort-asc') !== 'true';
    Array.from(table.tHead.rows[0].cells).forEach(c => {
        c.removeAttribute('data-sort-asc');
    });
    th.setAttribute('data-sort-asc', asc ? 'true' : 'false');
    _applySort(table, colIdx, asc);
}

// L'ordine vive solo nel DOM, quindi qualunque re-render lo cancella: la
// matrice audit riscrive tbody.innerHTML dai dati a ogni apertura di dettaglio
// e a ogni cambio filtro, e la tabella tornava all'ordine di partenza sotto gli
// occhi di chi l'aveva appena ordinata. Qui l'ordinamento scelto viene
// riapplicato, conservando il verso: riapplicare non e' cliccare di nuovo.
function reapplySort(table) {
    if (!table.tHead || !table.tHead.rows.length) return;
    const cells = Array.from(table.tHead.rows[0].cells);
    const idx = cells.findIndex(c => c.getAttribute('data-sort-asc') !== null);
    if (idx < 0) return;
    _applySort(table, idx, cells[idx].getAttribute('data-sort-asc') === 'true');
}
function makeTableSortable(table) {
    if (!table || table.dataset.sortable === '1') return;
    if (!table.tHead || !table.tHead.rows.length) return;
    table.dataset.sortable = '1';
    Array.from(table.tHead.rows[0].cells).forEach(th => {
        if (th.dataset.noSort === '1') return;
        th.setAttribute('data-sortable', '1');
        th.style.cursor = 'pointer';
        th.style.userSelect = 'none';
        // Le intestazioni sono etichette brevi: il nowrap evita che il glifo
        // vada a capo da solo; il margine sinistro del pseudo-elemento non
        // inserisce spazi nel content e quindi non crea punti di rottura.
        th.style.whiteSpace = 'nowrap';
        // L'indice va letto al click, non catturato qui: il riordino colonne
        // sposta il th senza ricreare il listener, e un idx catturato una
        // volta sola sarebbe rimasto quello di prima dello spostamento,
        // ordinando la colonna sbagliata dopo un drag o un Alt+freccia.
        th.addEventListener('click', () => {
            const liveIdx = Array.from(th.parentNode.cells).indexOf(th);
            sortTableByColumn(table, liveIdx, th);
        });
    });
}
function enhanceAllTables(root) {
    (root || document).querySelectorAll('table').forEach(t => {
        makeTableReorderable(t);
        makeTableResizable(t);
        makeTableColumnPicker(t);
        makeTableSortable(t);
    });
}

// ===== Riordino colonne (drag & drop + tastiera) per TUTTE le tabelle =====
// Stesso meccanismo dell'ordinamento sopra: header e celle si spostano insieme,
// cosi' sortTableByColumn (che indicizza per posizione fisica) resta corretto
// senza bisogno di aggiustamenti.

// Permutazione pura: sposta l'elemento in posizione `from` alla posizione `to`.
function arrayMoveItem(arr, from, to) {
    const a = arr.slice();
    const [item] = a.splice(from, 1);
    a.splice(to, 0, item);
    return a;
}

// Un ordine salvato e' valido solo se e' una permutazione completa delle
// colonne attuali: lunghezza diversa o un valore fuori range/duplicato indica
// che la tabella e' cambiata da quando l'ordine e' stato salvato.
function isValidColumnOrder(order, colCount) {
    if (!Array.isArray(order) || order.length !== colCount) return false;
    const seen = new Set();
    for (const v of order) {
        if (!Number.isInteger(v) || v < 0 || v >= colCount || seen.has(v)) return false;
        seen.add(v);
    }
    return true;
}

// Eligibilita': layout con thead multi-riga, celle di intestazione unite o
// righe di corpo con un numero di celle diverso da quello dell'header (righe
// con rowspan/colspan) non si prestano a spostare "la colonna all'indice N" in
// modo sicuro. Le righe di dettaglio (cella singola a tutta larghezza) sono
// l'eccezione gia' nota dal codice di ordinamento sopra.
function isTableReorderEligible(table) {
    if (!table || table.hasAttribute('data-no-reorder')) return false;
    if (!table.tHead || table.tHead.rows.length !== 1) return false;
    const headCells = Array.from(table.tHead.rows[0].cells);
    if (headCells.length < 2 || headCells.some(th => th.colSpan > 1)) return false;
    const headCount = headCells.length;
    const bodies = table.tBodies ? Array.from(table.tBodies) : [];
    for (const tbody of bodies) {
        for (const row of Array.from(tbody.rows)) {
            const cells = Array.from(row.cells);
            if (cells.length === 1 && cells[0].colSpan > 1) continue; // riga di dettaglio
            if (cells.length !== headCount) return false;
        }
    }
    return true;
}

// Chiave di storage: identita' della tabella (il proprio id, altrimenti quello
// dell'antenato piu' vicino con un id, piu' l'indice fra le tabelle al suo
// interno) + numero di colonne, cosi' un layout cambiato invalida da solo la
// chiave. Nessun antenato con id -> non persistibile (ritorna null), la
// tabella resta comunque riordinabile per la sessione corrente.
function columnOrderStorageKey(table) {
    let id = table.id;
    if (!id) {
        const ancestor = table.closest ? table.closest('[id]') : null;
        if (!ancestor || !ancestor.id) return null;
        const siblings = Array.from(ancestor.querySelectorAll('table'));
        id = ancestor.id + '.' + siblings.indexOf(table);
    }
    const colCount = table.tHead && table.tHead.rows.length ? table.tHead.rows[0].cells.length : 0;
    return 'sn.colorder.' + id + '.' + colCount;
}

// Ordine visivo corrente come sequenza di indici ORIGINALI (data-col-orig),
// uno per ogni th nella posizione in cui si trova adesso.
function currentColumnOrder(table) {
    return Array.from(table.tHead.rows[0].cells).map(th => Number(th.getAttribute('data-col-orig')));
}

// Riposiziona th e celle di ogni riga (skip righe di dettaglio) secondo
// `order` (sequenza di indici originali). Il trucco e' lo stesso di
// _applySort: appendChild in sequenza sposta ogni nodo alla fine, quindi
// ripetuto nell'ordine desiderato produce l'ordine finale corretto a
// prescindere dalla posizione di partenza.
function applyColumnOrder(table, order) {
    const headRow = table.tHead.rows[0];
    const headCells = Array.from(headRow.cells); // snapshot: posizioni PRIMA dello spostamento
    const headByOrig = {};
    headCells.forEach(th => { headByOrig[th.getAttribute('data-col-orig')] = th; });
    order.forEach(origIdx => headRow.appendChild(headByOrig[String(origIdx)]));

    const orderKey = order.join(',');
    const rows = [];
    (table.tBodies ? Array.from(table.tBodies) : []).forEach(tb => rows.push(...Array.from(tb.rows)));
    if (table.tFoot) rows.push(...Array.from(table.tFoot.rows));
    rows.forEach(row => {
        const cells = Array.from(row.cells);
        if (cells.length === 1 && cells[0].colSpan > 1) return; // riga di dettaglio: intoccata
        if (cells.length !== headCells.length) return;
        const rowByOrig = {};
        headCells.forEach((th, pos) => { rowByOrig[th.getAttribute('data-col-orig')] = cells[pos]; });
        order.forEach(origIdx => row.appendChild(rowByOrig[String(origIdx)]));
        row.dataset.colOrdered = orderKey;
    });
}

function saveColumnOrder(table, order) {
    const key = columnOrderStorageKey(table);
    if (!key) return;
    try { localStorage.setItem(key, JSON.stringify(order)); } catch (e) { }
}

function applySavedColumnOrder(table) {
    const key = columnOrderStorageKey(table);
    if (!key) return;
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(key)); } catch (e) { saved = null; }
    const headCount = table.tHead.rows[0].cells.length;
    if (!isValidColumnOrder(saved, headCount)) return;
    applyColumnOrder(table, saved);
}

function resetColumnOrder(table) {
    const headCount = table.tHead.rows[0].cells.length;
    applyColumnOrder(table, Array.from({ length: headCount }, (_, i) => i));
    const key = columnOrderStorageKey(table);
    if (key) { try { localStorage.removeItem(key); } catch (e) { } }
}

function moveTableColumn(table, fromIdx, toIdx) {
    if (fromIdx === toIdx || fromIdx < 0 || toIdx < 0) return;
    const order = arrayMoveItem(currentColumnOrder(table), fromIdx, toIdx);
    applyColumnOrder(table, order);
    saveColumnOrder(table, order);
}

// Passata del MutationObserver: le tabelle gia' riordinate mantengono thead
// invariato ma riscrivono tbody.innerHTML (stesso motivo di reapplySort). Le
// righe nuove nascono nell'ordine ORIGINALE delle colonne (il render delle
// singole tabelle non viene toccato), quindi vanno riportate all'ordine
// visivo corrente. data-col-ordered marca le righe gia' a posto: il controllo
// e' O(righe) ed evita di riscrivere (e quindi ri-schedulare l'observer)
// righe che sono gia' nell'ordine giusto.
function reapplyColumnOrder(table) {
    if (!table.tHead || !table.tHead.rows.length) return;
    const headCells = Array.from(table.tHead.rows[0].cells);
    const order = headCells.map(th => th.getAttribute('data-col-orig'));
    if (order.some(v => v === null)) return;
    if (order.every((v, i) => Number(v) === i)) return; // ordine originale: righe fresche gia' a posto
    const orderKey = order.join(',');
    const rows = [];
    (table.tBodies ? Array.from(table.tBodies) : []).forEach(tb => rows.push(...Array.from(tb.rows)));
    rows.forEach(row => {
        const cells = Array.from(row.cells);
        if (cells.length === 1 && cells[0].colSpan > 1) return; // riga di dettaglio
        if (row.dataset.colOrdered === orderKey) return;
        if (cells.length !== headCells.length) return;
        order.forEach(origIdx => row.appendChild(cells[Number(origIdx)]));
        row.dataset.colOrdered = orderKey;
    });
}

let _colDragFromTh = null;

function makeTableReorderable(table) {
    if (!table || table.dataset.reorderable === '1') return;
    if (!isTableReorderEligible(table)) return;
    table.dataset.reorderable = '1';
    const hint = tr('tableColumnReorderHint');
    Array.from(table.tHead.rows[0].cells).forEach((th, idx) => {
        th.setAttribute('data-col-orig', String(idx));
        th.draggable = true;
        if (!th.hasAttribute('tabindex')) th.tabIndex = 0;
        th.setAttribute('aria-description', hint);
        // Il drag nativo HTML5 non genera di norma un click al drop (nessuna
        // coppia mousedown/mouseup senza spostamento sullo stesso elemento),
        // ma il flag sotto e' una rete di sicurezza esplicita: e' registrato
        // PRIMA del click di ordinamento (makeTableSortable gira dopo, vedi
        // enhanceAllTables), quindi sullo stesso elemento viene invocato
        // prima e puo' bloccarlo con stopImmediatePropagation().
        th.addEventListener('dragstart', e => {
            _colDragFromTh = th;
            th.dataset.colDragging = '1';
            if (e.dataTransfer) { e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', ''); }
        });
        th.addEventListener('dragover', e => {
            e.preventDefault();
            if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
        });
        th.addEventListener('drop', e => {
            e.preventDefault();
            const fromTh = _colDragFromTh;
            _colDragFromTh = null;
            if (!fromTh || fromTh === th) return;
            const cells = Array.from(table.tHead.rows[0].cells);
            moveTableColumn(table, cells.indexOf(fromTh), cells.indexOf(th));
        });
        th.addEventListener('dragend', () => { _colDragFromTh = null; delete th.dataset.colDragging; });
        th.addEventListener('click', e => {
            if (th.dataset.colDragging !== '1') return;
            delete th.dataset.colDragging;
            e.stopImmediatePropagation();
        });
        th.addEventListener('dblclick', () => resetColumnOrder(table));
        th.addEventListener('keydown', e => {
            // Alt+Shift+arrow belongs to column resizing.
            if (!e.altKey || e.shiftKey || (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight')) return;
            const cells = Array.from(table.tHead.rows[0].cells);
            const fromIdx = cells.indexOf(th);
            const toIdx = fromIdx + (e.key === 'ArrowLeft' ? -1 : 1);
            // Fuori range: nessuno spostamento, quindi nessun preventDefault -
            // altrimenti Alt+freccia al primo/ultimo header blocca in
            // silenzio indietro/avanti del browser senza fare nulla.
            if (toIdx < 0 || toIdx >= cells.length) return;
            e.preventDefault();
            moveTableColumn(table, fromIdx, toIdx);
            th.focus();
        });
    });
    applySavedColumnOrder(table);
}

// ===== Column widths (drag the header's right edge) for EVERY table =====
// No handle element: many <th> carry data-i18n, and applyI18n rewrites their
// innerHTML on language switch, which would wipe an injected child. The edge
// is detected from the pointer position instead. The first resize freezes
// every column to its measured width and switches the table to
// table-layout: fixed, so one column can shrink without the browser
// redistributing the space. Widths are stored by ORIGINAL column index
// (data-col-orig), so they follow a column that was moved.
const COL_RESIZE_EDGE_PX = 6;
const COL_MIN_WIDTH_PX = 40;
const COL_RESIZE_KEY_STEP_PX = 20;

// Pure: widths with column `idx` changed by `delta`, never below the minimum.
function resizedColumnWidths(widths, idx, delta) {
    const out = widths.slice();
    out[idx] = Math.max(COL_MIN_WIDTH_PX, Math.round(widths[idx] + delta));
    return out;
}

function isValidColumnWidths(widths, colCount) {
    return Array.isArray(widths) && widths.length === colCount
        && widths.every(w => Number.isFinite(w) && w >= COL_MIN_WIDTH_PX);
}

function columnWidthStorageKey(table) {
    const key = columnOrderStorageKey(table);
    return key ? key.replace('sn.colorder.', 'sn.colwidth.') : null;
}

// widths[orig] for every column, as rendered now.
function currentColumnWidths(table) {
    const widths = [];
    Array.from(table.tHead.rows[0].cells).forEach(th => {
        widths[Number(th.getAttribute('data-col-orig'))] = Math.round(th.getBoundingClientRect().width);
    });
    return widths;
}

function applyColumnWidths(table, widths) {
    Array.from(table.tHead.rows[0].cells).forEach(th => {
        th.style.width = widths[Number(th.getAttribute('data-col-orig'))] + 'px';
    });
    table.style.tableLayout = 'fixed';
    table.style.width = widths.reduce((a, b) => a + b, 0) + 'px';
    table.dataset.colResized = '1';
}

function resetColumnWidths(table) {
    Array.from(table.tHead.rows[0].cells).forEach(th => { th.style.width = ''; });
    table.style.tableLayout = '';
    table.style.width = '';
    delete table.dataset.colResized;
    const key = columnWidthStorageKey(table);
    if (key) { try { localStorage.removeItem(key); } catch (e) { } }
}

function saveColumnWidths(table, widths) {
    const key = columnWidthStorageKey(table);
    if (!key) return;
    try { localStorage.setItem(key, JSON.stringify(widths)); } catch (e) { }
}

function applySavedColumnWidths(table) {
    const key = columnWidthStorageKey(table);
    if (!key) return;
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(key)); } catch (e) { saved = null; }
    if (isValidColumnWidths(saved, table.tHead.rows[0].cells.length)) applyColumnWidths(table, saved);
}

function isNearRightEdge(th, clientX) {
    return th.getBoundingClientRect().right - clientX <= COL_RESIZE_EDGE_PX;
}

function makeTableResizable(table) {
    if (!table || table.dataset.resizable === '1') return;
    if (table.hasAttribute('data-no-resize')) return;
    if (!table.tHead || table.tHead.rows.length !== 1) return;
    const headCells = Array.from(table.tHead.rows[0].cells);
    if (headCells.length < 2 || headCells.some(th => th.colSpan > 1)) return;
    table.dataset.resizable = '1';
    headCells.forEach((th, pos) => {
        // Reorderable tables already set it; for the others position == original.
        if (!th.hasAttribute('data-col-orig')) th.setAttribute('data-col-orig', String(pos));
        /** @type {{startX: number, widths: number[], draggable: boolean} | null} */
        let drag = null;
        th.addEventListener('pointermove', e => {
            if (drag) {
                const orig = Number(th.getAttribute('data-col-orig'));
                applyColumnWidths(table, resizedColumnWidths(drag.widths, orig, e.clientX - drag.startX));
                return;
            }
            th.classList.toggle('col-resize-edge', isNearRightEdge(th, e.clientX));
        });
        th.addEventListener('pointerleave', () => { if (!drag) th.classList.remove('col-resize-edge'); });
        th.addEventListener('pointerdown', e => {
            if (e.button !== 0 || !isNearRightEdge(th, e.clientX)) return;
            e.preventDefault();
            drag = { startX: e.clientX, widths: currentColumnWidths(table), draggable: th.draggable };
            // Otherwise moving the pointer starts the column-reorder drag.
            th.draggable = false;
            th.setPointerCapture(e.pointerId);
        });
        const endDrag = () => {
            if (!drag) return;
            th.draggable = drag.draggable;
            drag = null;
            th.dataset.colResizing = '1';
            saveColumnWidths(table, currentColumnWidths(table));
        };
        th.addEventListener('pointerup', endDrag);
        th.addEventListener('pointercancel', endDrag);
        // Capture phase: runs before the sort click and the reorder dblclick.
        th.addEventListener('click', e => {
            if (th.dataset.colResizing !== '1') return;
            delete th.dataset.colResizing;
            e.stopImmediatePropagation();
        }, true);
        th.addEventListener('dblclick', e => {
            if (!isNearRightEdge(th, e.clientX)) return;
            e.stopImmediatePropagation();
            resetColumnWidths(table);
        }, true);
        th.addEventListener('keydown', e => {
            if (!e.altKey || !e.shiftKey || (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight')) return;
            e.preventDefault();
            const orig = Number(th.getAttribute('data-col-orig'));
            const delta = e.key === 'ArrowLeft' ? -COL_RESIZE_KEY_STEP_PX : COL_RESIZE_KEY_STEP_PX;
            const widths = resizedColumnWidths(currentColumnWidths(table), orig, delta);
            applyColumnWidths(table, widths);
            saveColumnWidths(table, widths);
        });
    });
    applySavedColumnWidths(table);
}

// ===== Column picker (show / hide columns) for EVERY table =====
// A small "Columns" button in the table's <caption>: not inside a <th>, whose
// innerHTML applyI18n rewrites. Hidden columns are stored by ORIGINAL index
// (data-col-orig), like order and width, so they survive a reorder. A header
// marked data-col-default-hidden starts hidden until the user chooses.

function columnVisibilityStorageKey(table) {
    const key = columnOrderStorageKey(table);
    return key ? key.replace('sn.colorder.', 'sn.colhide.') : null;
}

// Pure: which original columns are hidden. The saved choice wins when it is
// still valid for this table; never every column, or the table disappears.
function hiddenColumns(saved, defaults, colCount) {
    const valid = Array.isArray(saved)
        && saved.every(v => Number.isInteger(v) && v >= 0 && v < colCount);
    const hidden = valid ? saved : defaults;
    return hidden.length >= colCount ? [] : hidden;
}

function applyColumnVisibility(table) {
    if (!table.tHead || !table.tHead.rows.length) return;
    const hidden = new Set(JSON.parse(table.dataset.colHidden || '[]'));
    const head = Array.from(table.tHead.rows[0].cells);
    const positions = [];
    head.forEach((th, pos) => {
        const off = hidden.has(Number(th.getAttribute('data-col-orig')));
        th.style.display = off ? 'none' : '';
        if (off) positions.push(pos);
    });
    const key = positions.join(',');
    const rows = [];
    (table.tBodies ? Array.from(table.tBodies) : []).forEach(tb => rows.push(...Array.from(tb.rows)));
    if (table.tFoot) rows.push(...Array.from(table.tFoot.rows));
    rows.forEach(row => {
        const cells = Array.from(row.cells);
        if (cells.length !== head.length) return;          // detail rows: untouched
        if (row.dataset.colHiddenKey === key) return;
        cells.forEach((c, pos) => { c.style.display = positions.includes(pos) ? 'none' : ''; });
        row.dataset.colHiddenKey = key;
    });
}

function makeTableColumnPicker(table) {
    if (!table || table.dataset.colPicker === '1' || table.hasAttribute('data-no-colpicker')) return;
    if (!table.tHead || table.tHead.rows.length !== 1) return;
    const head = Array.from(table.tHead.rows[0].cells);
    if (head.length < 2 || head.some(th => th.colSpan > 1)) return;
    // Nothing to choose from when fewer than two columns have a name.
    if (head.filter(th => (th.textContent || '').trim()).length < 2) return;
    table.dataset.colPicker = '1';
    head.forEach((th, pos) => {
        if (!th.hasAttribute('data-col-orig')) th.setAttribute('data-col-orig', String(pos));
    });
    const defaults = head.filter(th => th.hasAttribute('data-col-default-hidden'))
        .map(th => Number(th.getAttribute('data-col-orig')));
    const storageKey = columnVisibilityStorageKey(table);
    let saved = null;
    if (storageKey) { try { saved = JSON.parse(localStorage.getItem(storageKey) || 'null'); } catch (e) { saved = null; } }
    table.dataset.colHidden = JSON.stringify(hiddenColumns(saved, defaults, head.length));

    const cap = table.createCaption();
    cap.classList.add('col-picker-cap');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'col-picker-btn';
    btn.innerHTML = '<i class="fa-solid fa-table-columns"></i>';
    btn.title = tr('tableColumnsBtn');
    btn.setAttribute('aria-label', tr('tableColumnsBtn'));
    btn.setAttribute('aria-haspopup', 'true');
    btn.setAttribute('aria-expanded', 'false');
    const menu = document.createElement('div');
    menu.className = 'col-picker-menu';
    menu.hidden = true;
    cap.append(btn, menu);

    const save = (hidden) => {
        table.dataset.colHidden = JSON.stringify(hidden);
        if (storageKey) { try { localStorage.setItem(storageKey, JSON.stringify(hidden)); } catch (e) { } }
        applyColumnVisibility(table);
    };
    const open = () => {
        const hidden = new Set(JSON.parse(table.dataset.colHidden || '[]'));
        const cells = Array.from(table.tHead.rows[0].cells);
        menu.textContent = '';
        cells.forEach(th => {
            const label = (th.textContent || '').trim();
            if (!label) return;
            const orig = Number(th.getAttribute('data-col-orig'));
            const row = document.createElement('label');
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = !hidden.has(orig);
            cb.addEventListener('change', () => {
                const now = new Set(JSON.parse(table.dataset.colHidden || '[]'));
                if (cb.checked) now.delete(orig); else now.add(orig);
                if (now.size >= cells.length) { cb.checked = true; return; }
                save([...now]);
            });
            row.append(cb, document.createTextNode(' ' + label));
            menu.append(row);
        });
        const reset = document.createElement('button');
        reset.type = 'button';
        reset.className = 'col-picker-reset';
        reset.textContent = tr('tableColumnsReset');
        reset.addEventListener('click', () => {
            if (storageKey) { try { localStorage.removeItem(storageKey); } catch (e) { } }
            table.dataset.colHidden = JSON.stringify(defaults);
            applyColumnVisibility(table);
            open();
        });
        menu.append(reset);
        // Fixed, not absolute: .table-container scrolls (overflow-x:auto), so an
        // absolute menu was clipped inside short tables and covered the header.
        const r = btn.getBoundingClientRect();
        menu.style.top = r.bottom + 'px';
        menu.style.right = (window.innerWidth - r.right) + 'px';
        menu.hidden = false;
        btn.setAttribute('aria-expanded', 'true');
    };
    btn.addEventListener('click', e => {
        e.stopPropagation();
        if (menu.hidden) open();
        else { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); }
    });
    applyColumnVisibility(table);
}

// A click outside or Esc closes open menus (listeners: initSortableTables).
function closeColumnPickers(except) {
    document.querySelectorAll('.col-picker-menu:not([hidden])').forEach(m => {
        const menu = /** @type {HTMLElement} */ (m);
        if (except && menu.parentElement && menu.parentElement.contains(except)) return;
        menu.hidden = true;
        menu.parentElement?.querySelector('.col-picker-btn')?.setAttribute('aria-expanded', 'false');
    });
}
// ===== Tastiera sugli elementi cliccabili non nativi =====
// Un onclick su <tr>/<div>/<span> non e' raggiungibile da tastiera: la matrice
// audit, le righe della topologia e la client map si aprivano solo col mouse
// (WCAG 2.1.1 Keyboard). Invece di correggere ogni punto di render, gli
// elementi vengono resi focusabili qui, dove passa tutto il DOM generato.
const NATIVE_INTERACTIVE = 'a[href], button, input, select, textarea, summary, [contenteditable]';
function makeClickablesFocusable(root) {
    (root || document).querySelectorAll('[onclick]').forEach(el => {
        if (el.dataset.kbd === '1' || el.matches(NATIVE_INTERACTIVE)) return;
        el.dataset.kbd = '1';
        if (!el.hasAttribute('tabindex')) el.tabIndex = 0;
        // Una riga o una cella restano tali: role="button" su <tr>/<td>
        // romperebbe la struttura di tabella annunciata dallo screen reader.
        if (!el.hasAttribute('role') && el.tagName !== 'TR' && el.tagName !== 'TD') {
            el.setAttribute('role', 'button');
        }
    });
}
document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = e.target;
    if (!(el instanceof Element) || el.dataset.kbd !== '1') return;
    e.preventDefault();          // lo spazio non deve scorrere la pagina
    el.click();
});

function initSortableTables() {
    document.addEventListener('click', e => closeColumnPickers(/** @type {Node|null} */ (e.target)));
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeColumnPickers(null); });
    // A fixed menu would drift away from its button on scroll: close it instead.
    document.addEventListener('scroll', e => {
        if (!(e.target instanceof Element && e.target.closest('.col-picker-menu'))) closeColumnPickers(null);
    }, true);
    enhanceAllTables(document);
    makeClickablesFocusable(document);
    // Una passata per frame invece di una per nodo inserito: il render di una
    // tabella lunga produce centinaia di mutazioni, e ognuna rilanciava un
    // querySelectorAll sull'intero sottoalbero.
    let scheduled = false;
    const obs = new MutationObserver(() => {
        if (scheduled) return;
        scheduled = true;
        requestAnimationFrame(() => {
            scheduled = false;
            enhanceAllTables(document);
            makeClickablesFocusable(document);
            // Il riordino colonne va riapplicato PRIMA dell'ordinamento nella
            // stessa passata: entrambi operano per indice di colonna fisico.
            document.querySelectorAll('table[data-reorderable="1"]').forEach(reapplyColumnOrder);
            // Rows re-rendered through tbody.innerHTML come back visible.
            document.querySelectorAll('table[data-col-picker="1"]').forEach(applyColumnVisibility);
            document.querySelectorAll('table[data-sortable="1"]').forEach(reapplySort);
        });
    });
    obs.observe(document.body, { childList: true, subtree: true });
}
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSortableTables);
} else {
    initSortableTables();
}

// ===== Port Config Modal (promosso da static/js/topology.js: usato anche
// dal tab MAC-tracker/ARP inline e da static/js/config-analyzer.js) =====
// Espande le abbreviazioni comuni delle interfacce ('Gi1/0/5' -> 'GigabitEthernet1/0/5').
// Speculare a expand_iface() di mac_collector.py: tenerli allineati.
function expandIface(name) {
    if (!name) return '';
    name = String(name).trim();
    /** @type {[RegExp, string][]} */
    const abbr = [
        [/^(?:GigabitEthernet|Gi)(?=\d)/i, 'GigabitEthernet'],
        [/^(?:TenGigabitEthernet|TenGigE|Te|XGi|10Ge)(?=\d)/i, 'TenGigabitEthernet'],
        [/^(?:TwentyFiveGigE|Twe|25Ge)(?=\d)/i, 'TwentyFiveGigE'],
        [/^(?:FortyGigabitEthernet|FortyGigE|Fo|40Ge)(?=\d)/i, 'FortyGigE'],
        [/^(?:HundredGigE|Hu|100Ge)(?=\d)/i, 'HundredGigE'],
        [/^(?:FastEthernet|Fa|fe)(?=\d)/i, 'FastEthernet'],
        [/^(?:Ethernet|Eth|Et|e)(?=\d)/i, 'Ethernet'],
        [/^(?:Port-channel|Port-Channel|Po)(?=\d)/i, 'Port-channel'],
    ];
    for (const [pat, full] of abbr) {
        if (pat.test(name)) return name.replace(pat, full);
    }
    return name;
}

// ===== Interface error counters (/api/interface-errors) =====
// Shared by the Interfaces tab, the endpoint detail and the port occupancy
// column, so the three say the same thing about the same port.
// `row` is a port as the API returns it: {status, worst_class, errors,
// discards, window, last_read}.
// Static key maps instead of keys built by concatenation: the i18n checks
// resolve keys from the source, and a concatenated key is invisible to them.
const IFERR_FIELD_KEYS = {
    in_errors: 'ifErrField_in_errors', out_errors: 'ifErrField_out_errors',
    crc: 'ifErrField_crc', alignment: 'ifErrField_alignment', symbol: 'ifErrField_symbol',
    runts: 'ifErrField_runts', giants: 'ifErrField_giants',
    late_collisions: 'ifErrField_late_collisions', excessive_collisions: 'ifErrField_excessive_collisions',
    carrier_sense: 'ifErrField_carrier_sense', mac_rx_errors: 'ifErrField_mac_rx_errors',
    mac_tx_errors: 'ifErrField_mac_tx_errors', in_discards: 'ifErrField_in_discards',
    out_discards: 'ifErrField_out_discards',
};
const IFERR_CLASS_KEYS = {
    physical: 'ifErrClass_physical', duplex: 'ifErrClass_duplex', hardware: 'ifErrClass_hardware',
    errors: 'ifErrClass_errors', discards: 'ifErrClass_discards',
};

function ifaceErrorsTitle(row) {
    const parts = [];
    const describe = (label, item) => {
        if (!item || !item.delta) return;
        const grown = Object.entries(item.delta).filter(([, v]) => v)
            .map(([f, v]) => `${IFERR_FIELD_KEYS[f] ? tr(IFERR_FIELD_KEYS[f]) : f} +${v}`);
        parts.push(`${label}: ${grown.length ? grown.join(', ') : tr('ifErrNoGrowth')}`);
    };
    const w = row && row.window;
    if (w) describe(tr('ifErrWindowLabel', { h: String(Math.max(1, Math.round((w.span_s || 0) / 3600))) }), w);
    const r = row && row.last_read;
    if (r) {
        describe(tr('ifErrReadLabel', {
            src: String(r.source || '').toUpperCase(), s: String(r.interval_s || ''),
            t: new Date((r.ts || 0) * 1000).toLocaleString(),
        }), r);
    }
    if (w && w.reset) parts.push(tr('ifErrReset'));
    return parts.join('\n');
}

function ifaceErrorsBadge(row) {
    if (!row) return `<span class="iferr iferr-na">—</span>`;
    const title = escapeHtml(ifaceErrorsTitle(row));
    switch (row.status) {
        case 'erroring':
            return `<span class="iferr iferr-bad" title="${title}"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(String(row.errors))} · ${escapeHtml(IFERR_CLASS_KEYS[row.worst_class] ? tr(IFERR_CLASS_KEYS[row.worst_class]) : '')}</span>`;
        case 'discards':
            return `<span class="iferr iferr-warn" title="${title}">${escapeHtml(tr('ifErrDiscardsN', { n: String(row.discards) }))}</span>`;
        case 'clean':
            return `<span class="iferr iferr-ok" title="${title}"><i class="fa-solid fa-check"></i> 0</span>`;
        default:
            return `<span class="iferr iferr-na" title="${escapeHtml(tr('ifErrSingleSample'))}">…</span>`;
    }
}

// Last keyboard/pointer input. Requests made within ACTIVE_WINDOW_MS of it tell
// the server the operator is working, and the server slides the session, so it
// ends after the administrator's idle timeout counted from the last input.
// Background polling on an unattended tab carries no such claim.
let _lastUserActivity = Date.now();
let _lastApiCall = 0;
const ACTIVE_WINDOW_MS = 2 * 60 * 1000;
['pointerdown', 'keydown', 'wheel'].forEach(ev =>
    document.addEventListener(ev, () => { _lastUserActivity = Date.now(); }, { capture: true, passive: true }));
// A tab that shows static content sends no request while the operator reads
// and scrolls it: without this the session would lapse under an active user.
setInterval(() => {
    const now = Date.now();
    if (_sessionConfirmed && now - _lastUserActivity < ACTIVE_WINDOW_MS && now - _lastApiCall > 50 * 1000) {
        apiFetch('/api/auth/me');
    }
}, 60 * 1000);

function getAuthHeaders() {
    // Autenticazione via cookie HttpOnly (impostato dal server al login).
    // L'header custom è la prova anti-CSRF sulle richieste che modificano stato.
    const headers = { "X-Requested-With": "SentinelNet" };
    if (Date.now() - _lastUserActivity < ACTIVE_WINDOW_MS) headers["X-SentinelNet-Active"] = "1";
    return headers;
}

// Sessione confermata dal server (auth/me ok). Distingue "non ancora
// loggato" — 401 pre-login, da ignorare in silenzio — da "sessione scaduta"
// durante il lavoro, che invece forza il logout. Senza questo flag ogni
// fetch pre-login innescava logout() -> POST logout 401 -> re-check auth.
let _sessionConfirmed = false;

// Dati di /api/auth/me letti in checkAuthRequirements: appInit li riusa
// invece di rifare la stessa chiamata per ruolo/username/tab.
let _meCache = null;

// Funzione centralizzata per iniettare e controllare gli header di autenticazione ed evitare disallineamenti della UI
async function apiFetch(url, options = {}) {
    options.headers = options.headers || {};
    Object.assign(options.headers, getAuthHeaders());
    if (options.body && typeof options.body === 'string' && !options.headers['Content-Type'] && !options.headers['content-type']) {
        options.headers['Content-Type'] = 'application/json';
    }

    try {
        _lastApiCall = Date.now();
        const res = await fetch(url, options);
        if (res.status === 401) {
            if (_sessionConfirmed) {
                console.warn("[AUTH] Sessione scaduta o non valida (401). Forzatura Logout.");
                // Say why the login screen came back instead of dropping the
                // operator there with no explanation.
                logout().then(() => {
                    const errDiv = document.getElementById('loginError');
                    if (errDiv) { errDiv.textContent = tr('sessionExpiredNotice'); errDiv.style.display = 'block'; }
                });
            }
            return null;
        }
        return res;
    } catch (err) {
        console.error(`[ApiFetch Error] ${url}:`, err);
        return null;
    }
}

async function checkAuthRequirements() {
    const overlay = document.getElementById('authOverlay');
    const changePw = document.getElementById('changePwSection');
    const wiz = document.getElementById('wizardSection');
    const login = document.getElementById('loginSection');

    const resetPw = document.getElementById('resetPwSection');
    const acceptInvite = document.getElementById('acceptInviteSection');

    if (changePw) changePw.style.display = 'none';
    if (resetPw) resetPw.style.display = 'none';
    if (acceptInvite) acceptInvite.style.display = 'none';

    // Arrivo da un link ricevuto via email: si sceglie la password prima di
    // qualunque altra schermata, senza interrogare lo stato del setup.
    const emailParams = new URLSearchParams(window.location.search);
    const verifyToken = emailParams.get('verify_email_token');
    if (verifyToken) confirmEmailFromLink(verifyToken);
    const landing = emailParams.get('reset_token') ? resetPw
                  : emailParams.get('invite_token') ? acceptInvite
                  : null;
    if (landing) {
        if (wiz) wiz.style.display = 'none';
        if (login) login.style.display = 'none';
        landing.style.display = 'block';
        if (overlay) overlay.style.display = 'flex';
        return false;
    }

    try {
        // Interroga lo stato del setup/utenti nel sistema
        const res = await fetch('/api/auth/status');
        if (!res.ok) throw new Error('Status endpoint HTTP ' + res.status);
        const data = await res.json();

        if (!data.has_users) {
            // Nessun utente su disco: mostriamo la procedura guidata di primo setup
            if (wiz) wiz.style.display = 'block';
            if (login) login.style.display = 'none';
            if (overlay) overlay.style.display = 'flex';
            return false;
        } else {
            // Esiste già un amministratore: mostriamo la maschera di login standard
            if (wiz) wiz.style.display = 'none';
            if (login) login.style.display = 'block';
            showSsoButtonIfEnabled();
            // La sessione vive nel cookie HttpOnly: la verifichiamo lato server.
            const me = await fetch('/api/auth/me');
            if (!me.ok) {
                if (overlay) overlay.style.display = 'flex';
                return false;
            }
            _sessionConfirmed = true;
            _meCache = await me.json().catch(() => null);
            if (overlay) overlay.style.display = 'none';
            return true;
        }
    } catch (err) {
        console.warn('[auth] Error checking auth requirements, displaying login fallback:', err);
        if (wiz) wiz.style.display = 'none';
        if (login) login.style.display = 'block';
        if (overlay) overlay.style.display = 'flex';
        return false;
    }
}

// Evento per la registrazione guidata del primo utente amministratore
document.getElementById('btnRegisterAdmin').addEventListener('click', async () => {
    const user = document.getElementById('wizUser').value.trim();
    const pass = document.getElementById('wizPass').value.trim();

    if (!user || !pass) { alert(i18n[currentLang].alertFirstSetupFill); return; }
    if (pass.length < 8) { alert(i18n[currentLang].alertPassTooShort); return; }

    const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });

    if (res.ok) {
        // Login automatico con le credenziali appena create: evita di
        // dover ridigitare la stessa password nel form di login.
        const loginRes = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        if (loginRes.ok) {
            // La sessione è nel cookie HttpOnly impostato dal server.
            const wp = document.getElementById('wizPass'); if (wp) wp.value = '';
            document.getElementById('authOverlay').style.display = 'none';
            appInit();
        } else {
            // Fallback improbabile: account creato ma login fallito.
            alert(i18n[currentLang].alertFirstSetupSuccess);
            checkAuthRequirements();
        }
    } else {
        const err = await res.json();
        alert(i18n[currentLang].alertFirstSetupError + (err.detail || "Impossibile creare l'account."));
    }
});

// Evento per il Login Standard
document.getElementById('btnLogin').addEventListener('click', async () => {
    const user = document.getElementById('loginUser').value.trim();
    const passInput = document.getElementById('loginPass');
    const pass = passInput ? passInput.value.trim() : '';
    const errDiv = document.getElementById('loginError');

    if (!user || !pass) { errDiv.innerText = i18n[currentLang].alertLoginFill; errDiv.style.display = 'block'; return; }
    errDiv.style.display = 'none';

    const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });

    if (res.ok) {
        if (passInput) passInput.value = '';
        const data = await res.json();
        // La sessione è nel cookie HttpOnly impostato dal server: nessun
        // token conservato lato JavaScript (finding L-1).
        if (data.must_change_password) {
            // Account creato da un amministratore: forziamo il cambio password.
            pendingOldPass = pass;
            document.getElementById('loginSection').style.display = 'none';
            document.getElementById('changePwSection').style.display = 'block';
            document.getElementById('cpwNewPass').value = '';
            document.getElementById('cpwConfirmPass').value = '';
            document.getElementById('cpwNewPass').focus();
            return;
        }
        // Sblocca la UI nascondendo la schermata oscurante
        document.getElementById('authOverlay').style.display = 'none';
        appInit(); // Avvia il caricamento dei dispositivi di rete
    } else {
        errDiv.innerText = i18n[currentLang].alertLoginDenied;
        errDiv.style.display = 'block';
    }
});

// Password nota all'utente al momento del cambio obbligatorio (usata come
// vecchia password per l'endpoint /api/auth/change-password).
let pendingOldPass = '';

// Il pulsante SSO compare solo se l'installazione lo ha configurato: la rotta
// pubblica dice se e con che nome, niente altro.
async function showSsoButtonIfEnabled() {
    const box = document.getElementById('ssoLoginBox');
    if (!box) return;
    try {
        const res = await fetch('/api/auth/sso/config');
        if (!res.ok) return;
        const cfg = await res.json();
        if (!cfg.enabled) { box.style.display = 'none'; return; }
        const label = document.getElementById('ssoLoginBtnText');
        if (label && cfg.provider_name) label.textContent = cfg.provider_name;
        box.style.display = 'block';
    } catch (e) {
        // Nessun pulsante: si entra comunque con le credenziali locali.
        console.debug('[sso] config non disponibile:', e);
    }
}

// Recupero password: richiesta del link via email
document.getElementById('linkForgotPassword')?.addEventListener('click', (e) => {
    e.preventDefault();
    const box = document.getElementById('forgotPwBox');
    if (box) box.style.display = box.style.display === 'none' ? 'block' : 'none';
});

document.getElementById('btnSendForgotPw')?.addEventListener('click', async () => {
    const userEl = document.getElementById('forgotPwUser');
    const msgEl = document.getElementById('forgotPwMsg');
    const username = userEl ? userEl.value.trim() : '';
    if (!msgEl) return;
    if (!username) {
        msgEl.textContent = i18n[currentLang].fpNeedUser;
        msgEl.style.color = 'var(--danger)';
        msgEl.style.display = 'block';
        return;
    }
    try {
        const res = await fetch('/api/auth/forgot-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username }),
        });
        const d = await res.json().catch(() => ({}));
        // 200 e 429 dicono entrambi quello che l'utente puo' sapere: il
        // messaggio del server non distingue mai un account esistente.
        msgEl.textContent = d.message || d.detail || i18n[currentLang].fpSent;
        msgEl.style.color = res.ok ? 'var(--success)' : 'var(--danger)';
        msgEl.style.display = 'block';
    } catch (err) {
        msgEl.textContent = String(err);
        msgEl.style.color = 'var(--danger)';
        msgEl.style.display = 'block';
    }
});

// Scelta della nuova password dal link ricevuto via email
document.getElementById('btnSubmitResetPw')?.addEventListener('click', async () => {
    const token = new URLSearchParams(window.location.search).get('reset_token');
    const np = document.getElementById('rpNewPass')?.value.trim() || '';
    const cp = document.getElementById('rpConfirmPass')?.value.trim() || '';
    const errDiv = document.getElementById('loginError');
    errDiv.style.display = 'none';

    if (np.length < 8) { errDiv.innerText = i18n[currentLang].alertPassTooShort; errDiv.style.display = 'block'; return; }
    if (np !== cp) { errDiv.innerText = i18n[currentLang].alertPassMismatch; errDiv.style.display = 'block'; return; }

    const res = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: np }),
    });
    if (res.ok) {
        // Via il token dalla barra degli indirizzi prima di mostrare il login:
        // resta nella cronologia del browser e non serve piu' a niente.
        window.history.replaceState({}, document.title, window.location.pathname);
        document.getElementById('resetPwSection').style.display = 'none';
        document.getElementById('loginSection').style.display = 'block';
        errDiv.innerText = i18n[currentLang].rpDone;
        errDiv.style.color = 'var(--success)';
        errDiv.style.display = 'block';
    } else {
        const d = await res.json().catch(() => ({}));
        errDiv.innerText = d.detail || i18n[currentLang].rpFailed;
        errDiv.style.display = 'block';
    }
});

// Creazione dell'account dal link di invito: username e ruolo vengono
// dall'invito, qui si sceglie solo la password.
document.getElementById('btnSubmitAcceptInvite')?.addEventListener('click', async () => {
    const token = new URLSearchParams(window.location.search).get('invite_token');
    const np = document.getElementById('aiNewPass')?.value.trim() || '';
    const cp = document.getElementById('aiConfirmPass')?.value.trim() || '';
    const errDiv = document.getElementById('loginError');
    errDiv.style.display = 'none';

    if (np.length < 8) { errDiv.innerText = i18n[currentLang].alertPassTooShort; errDiv.style.display = 'block'; return; }
    if (np !== cp) { errDiv.innerText = i18n[currentLang].alertPassMismatch; errDiv.style.display = 'block'; return; }

    const res = await fetch('/api/auth/accept-invite', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, password: np }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) {
        errDiv.innerText = d.detail || i18n[currentLang].aiFailed;
        errDiv.style.display = 'block';
        return;
    }
    // Via il token dalla barra degli indirizzi: resta nella cronologia.
    window.history.replaceState({}, document.title, window.location.pathname);
    // No automatic sign-in: the account waits for an administrator's approval.
    document.getElementById('acceptInviteSection').style.display = 'none';
    document.getElementById('loginSection').style.display = 'block';
    errDiv.innerText = tr(d.pending_approval ? 'aiPending' : 'aiDone');
    errDiv.style.color = 'var(--success)';
    errDiv.style.display = 'block';
});

// Link mailed to a new recovery address (?verify_email_token=...). Confirming
// needs no session: the token itself proves access to the mailbox.
async function confirmEmailFromLink(token) {
    window.history.replaceState({}, document.title, window.location.pathname);
    const res = await fetch('/api/auth/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
    }).catch(() => null);
    showToast(tr(res && res.ok ? 'veDone' : 'veFailed'), res && res.ok ? 'success' : 'error');
}

// Cambio password obbligatorio al primo accesso
document.getElementById('btnChangePass').addEventListener('click', async () => {
    const npEl = document.getElementById('cpwNewPass');
    const cpEl = document.getElementById('cpwConfirmPass');
    const np = npEl ? npEl.value.trim() : '';
    const cp = cpEl ? cpEl.value.trim() : '';
    const errDiv = document.getElementById('loginError');
    errDiv.style.display = 'none';

    if (np.length < 8) { errDiv.innerText = i18n[currentLang].alertPassTooShort; errDiv.style.display = 'block'; return; }
    if (np !== cp) { errDiv.innerText = i18n[currentLang].alertPassMismatch; errDiv.style.display = 'block'; return; }

    const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'SentinelNet'
        },
        body: JSON.stringify({ old_password: pendingOldPass, new_password: np })
    });

    if (res.ok) {
        pendingOldPass = '';
        if (npEl) npEl.value = '';
        if (cpEl) cpEl.value = '';
        document.getElementById('changePwSection').style.display = 'none';
        document.getElementById('loginSection').style.display = 'block';
        document.getElementById('authOverlay').style.display = 'none';
        appInit();
    } else {
        errDiv.innerText = i18n[currentLang].alertPassChangeErr;
        errDiv.style.display = 'block';
    }
});

async function logout() {
    _sessionConfirmed = false;
    _meCache = null;
    // Pulisce campi sensibili in memoria nel DOM
    document.querySelectorAll('input[type="password"]').forEach(el => { el.value = ''; });
    // Cancella il cookie di sessione lato server (best-effort).
    try {
        await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'X-Requested-With': 'SentinelNet' }
        });
    } catch (e) { /* sessione già scaduta: ignora */ }
    currentRole = 'viewer';
    currentUsername = '';
    document.body.classList.remove('role-super_admin', 'role-admin', 'role-operator', 'role-viewer');
    checkAuthRequirements();
}

// --- ETA' DEL BACKUP ---

// Quanto e' vecchio il dato che si sta guardando. Va detto ovunque si mostri
// config letta da un backup: un "2/2 UP" di due settimane fa e uno di tre
// minuti fa altrimenti si leggono uguali.
// Oltre una settimana il testo passa a var(--warning): e' il punto in cui il
// dato smette di descrivere la rete di adesso.
// Età in forma breve ("40 min", "6 h", "3 g"). Una sola formula per tutti i
// riquadri che mostrano "quanto tempo fa": copiarla porta a unità divergenti.
function relativeAge(h) {
    return h < 1 ? `${Math.max(1, Math.round(h * 60))} min`
        : (h < 48 ? `${Math.round(h)} h` : `${Math.round(h / 24)} ${tr('coreD')}`);
}

function backupAgeLabel(ts) {
    if (!ts) return '';
    const h = (Date.now() / 1000 - ts) / 3600;
    const txt = relativeAge(h);
    const label = tr('coreBackupAgo', {txt: txt});
    return `<span style="font-size:11px; color:${h > 168 ? 'var(--warning)' : 'var(--text-muted)'};"`
        + ` title="${tr('coreBackupAge')}">${escapeHtml(label)}</span>`;
}

// --- RUOLI / PRIVILEGI ---

// Mirrors security/user_manager.py ROLE_RANK. Hiding a control is a
// convenience only: the API enforces the same ladder.
const ROLE_RANK = { viewer: 0, operator: 1, admin: 2, super_admin: 3 };

function isAdminRole(role) {
    return role === 'super_admin' || role === 'admin';
}

function canManageRole(actorRole, targetRole) {
    if (actorRole === 'super_admin') return true;
    return (ROLE_RANK[targetRole] ?? 0) < (ROLE_RANK[actorRole] ?? 0);
}

function canAssignRole(actorRole, newRole) {
    if (!(newRole in ROLE_RANK)) return false;
    return actorRole === 'super_admin' || ROLE_RANK[newRole] < (ROLE_RANK[actorRole] ?? 0);
}

function roleLabel(role) {
    if (role === 'super_admin') return tr('coreSuperAdministrator');
    if (role === 'admin') return tr('coreAdministrator');
    if (role === 'operator') return tr('coreOperator');
    return tr('coreViewer');
}

// Tab permissions are stored per user in users.json and predate the endpoint
// merge, where four tabs became one. A saved 'tab-mac' must keep revealing the
// group, so the old id is aliased on READ. The stored file is never rewritten:
// it is the user's data, not ours.
function normalizeAllowedTabs(tabs) {
    if (!Array.isArray(tabs) || tabs.length === 0) return [];
    const LEGACY = { 'tab-mac': 'tab-endpoint', 'tab-clientmap': 'tab-endpoint',
                     'tab-diagnosi': 'tab-endpoint', 'tab-endpoints': 'tab-endpoint' };
    return [...new Set(tabs.map(t => LEGACY[t] || t))];
}

function applyRoleUI(username, role, allowedTabs, groups) {
    if (username !== undefined && username !== null) currentUsername = username;
    if (role !== undefined && role !== null) currentRole = role;
    if (!currentRole) currentRole = 'viewer';
    if (groups !== undefined && groups !== null) currentUserGroups = groups;
    document.body.classList.remove('role-super_admin', 'role-admin', 'role-operator', 'role-viewer');
    document.body.classList.add('role-' + currentRole);
    // requires-admin controls (dashboard.css) stay visible to a super_admin.
    if (currentRole === 'super_admin') document.body.classList.add('role-admin');
    // Role selects offer only what this account may assign.
    document.querySelectorAll('select[data-role-select]').forEach(sel => {
        sel.querySelectorAll('option').forEach(opt => {
            const ok = canAssignRole(currentRole, opt.value);
            opt.hidden = !ok;
            opt.disabled = !ok;
        });
        if (sel.selectedOptions[0]?.disabled) sel.value = 'viewer';
    });
    const badge = document.getElementById('userBadgeLabel');
    if (badge) {
        const icon = isAdminRole(currentRole) ? 'fa-user-shield'
            : currentRole === 'operator' ? 'fa-user-gear' : 'fa-user';
        const initials = String(currentUsername || '?').slice(0, 2).toUpperCase();
        badge.innerHTML = `<span class="user-avatar" aria-hidden="true">${escapeHtml(initials)}</span>` +
            `<span class="user-meta"><span class="user-name"><i class="fa-solid ${icon}"></i> ${escapeHtml(currentUsername)}</span>` +
            `<span class="role-pill role-pill-${currentRole}">${roleLabel(currentRole)}</span></span>`;
    }
    // ponytail: restrizione solo lato frontend (nasconde i pulsanti); vuoto = tutte le tab.
    const allowed = normalizeAllowedTabs(allowedTabs);
    currentAllowedTabs = allowed;
    if (allowed.length > 0) {
        document.querySelectorAll('.nav-item').forEach(btn => {
            const tabId = btn.getAttribute('data-tab');
            // tab-home is never in a stored/assignable list (mirrors the
            // server's ALWAYS_GRANTED_TABS): a restricted list must not hide it.
            if (tabId && tabId !== 'tab-home' && !allowed.includes(tabId)) btn.style.display = 'none';
        });
    }
    // A tenant-scoped admin's invite would 403 server-side (invite is an
    // unscoped-admin route): hide the entry point instead of a dead button.
    const isUnscopedAdmin = currentRole === 'super_admin'
        || (currentRole === 'admin' && currentUserGroups.length === 0);
    const inviteBtn = document.querySelector('[data-open-modal="inviteUserModal"]');
    if (inviteBtn) inviteBtn.style.display = isUnscopedAdmin ? '' : 'none';
}

// Invio rapido con tasto Enter su login, setup wizard e creazione gruppo
function bindEnterKey(inputIds, buttonId) {
    inputIds.forEach(id => {
        document.getElementById(id).addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById(buttonId).click();
        });
    });
}
bindEnterKey(['loginUser', 'loginPass'], 'btnLogin');
bindEnterKey(['wizUser', 'wizPass'], 'btnRegisterAdmin');
bindEnterKey(['newGroupName'], 'btnCreateGroup');
bindEnterKey(['scanNetworkInput'], 'btnAvviaScan');

document.getElementById('themeToggle')?.addEventListener('click', toggleTheme);
document.getElementById('sidebarToggle')?.addEventListener('click', toggleSidebar);
document.getElementById('btnLogout')?.addEventListener('click', (e) => {
    e.preventDefault();
    logout();
});

// Chiusura modali (click sul velo, Esc, trappola del focus): la fa ui-modal.js
// per TUTTE, non piu' a mano per due. Il terminale CLI resta escluso da Esc via
// data-esc-close="off" nel template, perche' il tasto serve alla sessione SSH.

// --- INITIALIZATION ---

// La meta' di appInit() che dipende da /api/local-devices: inventario,
// gruppi, versioni rilevate e tutto cio' che si ridisegna con loro.
//
// Estratta perche' DIECI azioni sui dispositivi (salva, elimina, rinomina,
// cambio sede, CRUD tenant, import CSV, aggiungi da scansione, fine triage)
// chiamavano appInit() per ottenere questo, e con esso si ripagavano ogni
// volta /api/auth/status, /api/auth/me, /api/version, /api/vendors,
// /api/settings/snmp-defaults e una loadHome() che rifaceva
// /api/local-devices appena caricato: sei round trip e un ridisegno
// completo del cruscotto per cambiare il tenant di un apparato.
//
// Ritorna false se l'inventario non e' arrivato, cosi' il chiamante sa che
// i globali NON sono stati aggiornati e non ridisegna su dati vecchi.
async function refreshInventory() {
    const res = await apiFetch('/api/local-devices');
    if (!res || !res.ok) return false;
    const data = await res.json();

    globalDevices = data.devices;
    globalGroups = data.groups;
    globalVersions = data.detected_versions; // Cache globale delle versioni rilevate
    // Endpoint panes build their device pickers once per load: an added or
    // removed device must show up the next time they are opened.
    if (typeof _locLoaded !== 'undefined') for (const v in _locLoaded) _locLoaded[v] = false;

    // Popola tendine Vendor + tendina Gruppi del form di provisioning
    // (estratto in populateProvisioningFormSelects: riusato anche da loadProvisioningTab).
    populateProvisioningFormSelects();

    // Memorizza la selezione corrente del filtro se esiste
    const filterSelect = document.getElementById('filterGroupSelect');
    const prevFilter = filterSelect ? filterSelect.value : 'all';

    // Popola tendina Filtro Gruppi nella tabella dell'inventario
    if (filterSelect) {
        filterSelect.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
            Object.keys(globalGroups).map(g =>
                `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
        filterSelect.value = prevFilter;
        if (filterSelect.selectedIndex === -1) filterSelect.value = 'all';
    }

    // Popola tendina Filtro Gruppi in TAB 3
    const topoSelect = document.getElementById('topologyGroupSelect');
    if (topoSelect) {
        // Default = nessuna scelta: il report Port-Channel resta vuoto
        // finché l'utente non indica un Tenant.
        const prevTopoFilter = topoSelect.value || '';
        topoSelect.innerHTML = `<option value="">${i18n[currentLang].optSelectSite}</option>` +
            `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
            Object.keys(globalGroups).map(g =>
                `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
        topoSelect.value = prevTopoFilter;
        if (topoSelect.selectedIndex === -1) topoSelect.value = '';
    }

    // Popola tendina Filtro Gruppi in TAB 4
    const interSelect = document.getElementById('interactiveGroupSelect');
    if (interSelect) {
        // Default = nessuna scelta: la mappa interattiva non disegna nulla
        // finché l'utente non indica una Sede.
        const prevInterFilter = interSelect.value || '';
        interSelect.innerHTML = `<option value="">${i18n[currentLang].optSelectSite}</option>` +
            `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
            Object.keys(globalGroups).map(g =>
                `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
        interSelect.value = prevInterFilter;
        if (interSelect.selectedIndex === -1) interSelect.value = '';
    }

    // Popola la tendina globale dei Tenant nella barra superiore
    populateGlobalTenantSelect();

    // Popola Tabella Dispositivi tramite la nuova funzione autonoma filtrabile
    renderDeviceTable();

    // Popola Tabella Gestione Gruppi
    renderGroupsTable();

    // La Home rispecchia l'inventario, ma rifa' /api/local-devices per conto
    // suo: si aggiorna solo se e' la tab davanti agli occhi. Al login lo e'
    // (tab di default), quindi il primo caricamento non cambia.
    if (document.querySelector('.tab-content.active')?.id === 'tab-home') loadHome();

    return true;
}

async function appInit() {
    appLoading = true;
    initLanguageSelector();
    const isAuth = await checkAuthRequirements();
    if (!isAuth) {
        appLoading = false;
        return;
    }

    // Determina ruolo/privilegi dell'utente corrente e adatta la UI.
    // I dati arrivano dalla cache di checkAuthRequirements; il fetch resta
    // solo come fallback se la cache non si e' riempita.
    try {
        let me = _meCache;
        if (!me) {
            const meRes = await apiFetch('/api/auth/me');
            if (meRes && meRes.ok) me = await meRes.json();
        }
        if (me) {
            currentRole = me.role || 'viewer';
            applyRoleUI(me.username, currentRole, me.allowed_tabs || [], me.groups || []);
        }
    } catch (e) { /* non bloccante */ }

    // Sincronizza badge di versione dell'applicazione
    try {
        const verRes = await apiFetch('/api/version');
        if (verRes && verRes.ok) {
            const vData = await verRes.json();
            const badge = document.getElementById('appVersionBadge');
            if (badge && vData.version) {
                badge.textContent = 'v' + vData.version;
            }
        }
    } catch (e) { /* non bloccante */ }

    // Flow SIEM, NetSec Audit, Incidenti e Fortigate Management non sono piu'
    // dietro un flag: le tab sono sempre presenti, gated solo dalla RBAC di
    // nav come ogni altra voce.

    try {
        // I vendor prima dell'inventario: le tendine costruite dentro
        // refreshInventory() leggono globalVendors. E' un round trip in serie
        // al login, contro i cinque risparmiati a OGNI azione sui dispositivi.
        const vRes = await apiFetch('/api/vendors');
        if (vRes && vRes.ok) globalVendors = await vRes.json();

        if (!await refreshInventory()) {
            appLoading = false;
            return;
        }

        // Stato SNMP di tenant: solo i nomi, la community non arriva al browser
        loadSnmpDefaults();

        // Reopen the tab the address names. A tab this role cannot open (its nav
        // item is hidden by RBAC or allowed_tabs) falls back to the overview.
        const addressTab = tabFromAddress();
        if (addressTab && addressTab !== 'tab-home') {
            const navBtn = document.querySelector(`.nav-item[data-tab="${addressTab}"]`)
                || document.querySelector(`.nav-item[data-tabs~="${addressTab}"]`);
            const allowed = navBtn && getComputedStyle(navBtn).display !== 'none';
            if (allowed) await switchTab(addressTab, undefined, { fromHistory: true });
            else syncAddressToTab('tab-home', false);
        } else if (!addressTab) {
            syncAddressToTab('tab-home', false);
        }

        // Forza il reload delle mappe se le tab sono attive (switchTab above already
        // loaded the tab it opened, so this only covers a tab left active in the DOM)
        const activeTabId = addressTab && addressTab !== 'tab-home' ? null
            : document.querySelector('.tab-content.active')?.id;
        if (activeTabId === 'tab-map') {
            await loadTopology();
        } else if (activeTabId === 'tab-map-interactive') {
            await loadInteractiveMap();
        } else if (activeTabId === 'tab-security') {
            loadThreatIntel();
        }

        startTriageStatusPolling();

    } catch (err) {
        console.error(err);
    } finally {
        appLoading = false;
    }
}

// --- CARICAMENTO LAZY DEI MODULI PER TAB ---
// I moduli pesanti e legati a una singola tab non bloccano piu' il primo
// paint: vengono iniettati alla prima visita della tab che li usa.
// I vendor restano in bundle con il modulo che li consuma (vis-network
// prima di topology.js: async=false conserva l'ordine di esecuzione).
const LAZY_TAB_SCRIPTS = {
    'tab-map': ['/static/vendor/vis/vis-network.min.js', '/static/js/topology.js'],
    'tab-map-interactive': ['/static/vendor/vis/vis-network.min.js', '/static/js/topology.js'],
    'tab-categories': ['/static/js/topology.js'],
    'tab-flows': ['/static/js/flow-analytics.js', '/static/js/observability.js'],
    'tab-config': ['/static/js/config-analyzer.js'],
    'tab-ai': ['/static/js/ai.js'],
    // The AI config generator is a panel of the Provisioner sub-tab, so its
    // module has to load there too, not only on the AI tab.
    'tab-provisioner': ['/static/js/ai.js'],
    'tab-fortigate': ['/static/js/fortigate-management.js'],
    'tab-wlc': ['/static/js/wlc.js'],
    // settings.js owns the CRUD of four tabs, not just Settings: opening any of
    // the other three cold left every control on it dead and its table empty.
    'tab-settings': ['/static/js/settings.js', '/static/js/observability.js', '/static/js/cloud-backup.js'],
    'tab-sites': ['/static/js/settings.js'],
    'tab-users': ['/static/js/settings.js'],
    'tab-mcp': ['/static/js/settings.js'],
    'tab-incidents': ['/static/js/incidents.js'],
    'tab-interfaces': ['/static/js/interfaces.js'],
    'tab-redundancy': ['/static/js/redundancy.js'],
    // The Firewall Audit Checklist is a sub-tab of NetSec Audit: its module
    // has to load together with the tab that contains it.
    'tab-netsec-audit': ['/static/vendor/html2pdf/html2pdf.bundle.min.js', '/static/js/netsec-audit.js', '/static/js/audit_checklist.js'],
    'tab-policy-test': ['/static/js/policy-test.js'],
    'tab-config-drift': ['/static/js/config-drift.js'],
    'tab-routes': ['/static/js/routes-view.js'],
    'tab-notifications': ['/static/js/notifications.js'],
};

const _lazyLoaded = new Set();
const _lazyLoading = new Map();

function loadAssetOnce(src) {
    if (_lazyLoaded.has(src)) return Promise.resolve();
    if (_lazyLoading.has(src)) return _lazyLoading.get(src);
    const isCss = src.endsWith('.css');
    const p = new Promise((resolve, reject) => {
        let el;
        if (isCss) {
            el = document.createElement('link');
            el.rel = 'stylesheet';
            el.href = src;
        } else {
            el = document.createElement('script');
            el.src = src;
            el.async = false;
        }
        el.onload = () => { _lazyLoaded.add(src); _lazyLoading.delete(src); resolve(); };
        el.onerror = () => { _lazyLoading.delete(src); reject(new Error('Load failed: ' + src)); };
        document.head.appendChild(el);
    });
    _lazyLoading.set(src, p);
    return p;
}

async function ensureTabScripts(tabId) {
    const scripts = LAZY_TAB_SCRIPTS[tabId];
    if (!scripts) return;
    try {
        await Promise.all(scripts.map(loadAssetOnce));
    } catch (e) {
        console.error('[lazy]', e);
        showToast((i18n[currentLang] || {}).toastModuleLoadError || 'Errore di caricamento modulo', 'error');
    }
}

// Delega per l'apertura delle tab: niente piu' onclick inline (CSP senza
// 'unsafe-inline'). data-tab marca le voci della nav, data-switch-tab gli
// altri pulsanti (home, sotto-tab). I secondi non passano il pulsante:
// switchTab risale alla voce di nav da sola, come prima.
document.addEventListener('click', e => {
    const el = e.target.closest('[data-tab], [data-switch-tab]');
    if (!el) return;
    const tabId = el.getAttribute('data-tab') || el.getAttribute('data-switch-tab');
    switchTab(tabId, el.classList.contains('nav-item') ? el : undefined);
});


// --- Semantica tablist (WCAG 2.1 AA) ------------------------------------
// La sidenav e' un tablist: senza aria-selected chi usa uno screen reader
// sente 23 pulsanti senza sapere quale schermata e' aperta. Il tabindex
// mobile ("roving") e' l'altra meta' obbligatoria del pattern: dentro un
// tablist il Tab entra ed esce, fra le voci ci si muove con le frecce.
function syncTablistState(activeBtn) {
    const items = document.querySelectorAll('.nav-item[role="tab"]');
    items.forEach(el => {
        const on = el === activeBtn || el.classList.contains('active');
        el.setAttribute('aria-selected', on ? 'true' : 'false');
        el.tabIndex = on ? 0 : -1;
    });
}

// Sul document e non sulla nav: querySelector rende un Element, e su Element
// il gestore riceve Event senza .key (il type check lo segnala, giustamente).
document.addEventListener('keydown', e => {
    const KEYS = ['ArrowDown', 'ArrowUp', 'Home', 'End'];
    if (!KEYS.includes(e.key)) return;
    const items = Array.from(document.querySelectorAll('.nav-item[role="tab"]'))
        .filter(el => el.offsetParent !== null);
    const i = items.indexOf(document.activeElement);
    if (i === -1) return;
    e.preventDefault();
    const next = e.key === 'Home' ? 0
        : e.key === 'End' ? items.length - 1
            : (i + (e.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
    items[next].focus();
});

// --- Tab addresses: /devices, /settings, ... (served by read_tab in app_server.py) ---
// The address is the tab, so a reload or a shared link reopens it. The query
// string (?tenant=...) rides along untouched.
function tabFromAddress() {
    const slug = window.location.pathname.replace(/^\/+|\/+$/g, '');
    if (!slug) return 'tab-home';
    return document.getElementById('tab-' + slug)?.classList.contains('tab-content') ? 'tab-' + slug : null;
}

function syncAddressToTab(tabId, push) {
    const path = tabId === 'tab-home' ? '/' : '/' + tabId.replace(/^tab-/, '');
    if (path === window.location.pathname) return;
    const url = path + window.location.search;
    if (push) window.history.pushState({ tabId }, '', url);
    else window.history.replaceState({ tabId }, '', url);
}

// Back/forward: follow the address without writing a new history entry.
window.addEventListener('popstate', () => {
    const tabId = tabFromAddress();
    if (tabId) switchTab(tabId, undefined, { fromHistory: true });
});

async function switchTab(tabId, clickedBtn, opts = {}) {
    // Swap the visible panel FIRST, then await the module. Awaiting up here
    // meant a cold tab looked frozen for the whole download of its script
    // (vis-network, the html2pdf bundle): no active class, no panel change.
    // Only the data-loading dispatch below actually needs the module.
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    // Show a skeleton while the lazy module loads so the panel does not read as broken.
    const tabEl = document.getElementById(tabId);
    if (tabEl) tabEl.classList.add('tab-loading');
    // Se chiamato senza pulsante (es. dopo import CSV) evidenzia comunque la tab corretta.
    // I sotto-tab passano solo il tabId: la voce di nav che li raggruppa si
    // dichiara con data-tabs, così una sola voce resta attiva per piu' tab.
    const btn = clickedBtn
        || document.querySelector(`.nav-item[data-tab="${tabId}"]`)
        || document.querySelector(`.nav-item[data-tabs~="${tabId}"]`);
    if (btn) {
        btn.classList.add('active');
        const group = btn.closest('.nav-group.collapsed');
        if (group) setNavGroupCollapsed(group, false);
    }
    syncTablistState(btn);
    syncTopbarCrumb();
    if (!opts.fromHistory) syncAddressToTab(tabId, true);

    await ensureTabScripts(tabId);
    if (tabEl) tabEl.classList.remove('tab-loading');

    if (tabId === 'tab-home') {
        loadHome();
    } else {
        // Leaving home: stop the ping-monitor auto-refresh so it doesn't keep
        // polling and re-rendering a hidden tab. loadHome() re-arms it on return.
        if (typeof _pingRefreshTimer !== 'undefined' && _pingRefreshTimer) {
            clearInterval(_pingRefreshTimer); _pingRefreshTimer = null;
        }
    }
    if (tabId === 'tab-devices') {
        renderDeviceTable();
    } else if (tabId === 'tab-provisioning') {
        // Awaited so editDevice() fills the form after the tab's own reload,
        // not before: otherwise that reload resets tenant/profile/identities.
        await loadProvisioningTab();
    } else if (tabId === 'tab-map') loadTopology();
    else if (tabId === 'tab-map-interactive') loadInteractiveMap();
    else if (tabId === 'tab-categories') loadCategoriesData();
    else if (tabId === 'tab-security' && !appLoading) {
        loadThreatIntel();
    }
    else if (tabId === 'tab-endpoint') locSwitchView(_locView);
    else if (tabId === 'tab-config') loadConfigAnalyzer();
    else if (tabId === 'tab-ai') loadAiTab();
    else if (tabId === 'tab-import' && typeof loadImportSiteIds === 'function') loadImportSiteIds();
    else if (tabId === 'tab-users') loadUsers();
    else if (tabId === 'tab-sites') loadSites();
    else if (tabId === 'tab-mcp') loadMcpTab();
    else if (tabId === 'tab-fortigate') loadFgtTab();
    else if (tabId === 'tab-wlc' && typeof loadWlcTab === 'function') loadWlcTab();
    else if (tabId === 'tab-settings') loadAppSettings();
    // Queste tre tab prima si inizializzavano con una seconda chiamata
    // nell'onclick del pulsante nav; ora il dispatch e' unico e arriva
    // dopo il caricamento lazy del modulo.
    else if (tabId === 'tab-flows') flowsTabShown();
    else if (tabId === 'tab-incidents') loadIncidentsTab();
    else if (tabId === 'tab-interfaces' && typeof loadInterfacesTab === 'function') loadInterfacesTab();
    else if (tabId === 'tab-redundancy') loadRedundancyTab();
    else if (tabId === 'tab-netsec-audit') loadNetSecAuditTab();
    else if (tabId === 'tab-policy-test') loadPolicyTestTab();
    else if (tabId === 'tab-config-drift') loadConfigDriftTab();
    else if (tabId === 'tab-routes') loadRoutesTab();
    else if (tabId === 'tab-notifications' && typeof loadNotificationsTab === 'function') loadNotificationsTab();
}

// --- FLUSSI LIVE (fase 5): top talker + anomalie correlate -------------
// Toast minimale non bloccante (il resto della dashboard usa alert()).
function showToast(msg, kind) {
    const el = document.createElement('div');
    el.textContent = msg;
    // Il colore significa stato: il fondo resta una superficie del sistema e lo
    // stato lo porta il bordo. Prima erano tre colori fissi (fra cui uno slate
    // che nella palette non esiste): sul laminato chiaro erano fuori sistema.
    const edge = kind === 'error' ? 'var(--lamp-fault)'
        : kind === 'warning' ? 'var(--lamp-warn)'
            : 'var(--border-strong)';
    el.style.cssText = 'position:fixed; bottom:24px; right:24px; z-index:9999;'
        + 'padding:10px 16px; border-radius:0; font-size:13px;'
        + 'font-family:var(--font-prose); color:var(--text);'
        + 'background:var(--surface-3); box-shadow:var(--shadow-float);'
        + 'border:1px solid ' + edge + ';';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

// --- Shared across tabs (promoted from templates/dashboard.html during
// static/js/provisioning.js extraction): renderVendorTable/buildVendorOptions
// are used by the Provisioning tab (populateProvisioningFormSelects) AND by
// the still-inline Groups tab (loadVendors) AND by changeLanguage() in
// static/js/i18n.js. refreshIdentityOptions/renderIdentitiesPanel are used by
// the Provisioning tab AND by the still-inline Devices tab's editDevice() AND
// by the still-inline Groups tab's btnCreateGroup handler. ---

function buildVendorOptions(selected) {
    const builtins = ["cisco", "hpe"];
    const all = [...new Set([...builtins, ...Object.keys(globalVendors)])];
    return all.map(v =>
        `<option value="${escapeHtml(v)}" ${v === selected ? "selected" : ""}>${escapeHtml(v.toUpperCase())}</option>`
    ).join("");
}

// Vendor select della finestra di scansione. Ha in piu' la voce vuota, che le
// altre select non hanno: aggiungere un dispositivo scoperto senza scegliere un
// vendor deve scrivere "nessun vendor", non il primo della lista. Senza questa
// voce la select non sa dire "non scelto" e il vendor tornerebbe indovinato.
function buildScanVendorOptions(selected) {
    const L = (typeof i18n !== "undefined" && i18n[currentLang]) || {};
    return `<option value="">${escapeHtml(L.optScanNoVendor || "— non impostato —")}</option>`
         + buildVendorOptions(selected);
}

function renderVendorTable() {
    const body = document.getElementById('vendorTableBody');
    if (!body) return;
    body.innerHTML = '';
    Object.entries(globalVendors).forEach(([name, meta]) => {
        const isSystem = name === 'cisco' || name === 'hpe';
        const systemText = tr('coreSystem');
        const deleteText = tr('uiDelete');
        body.innerHTML += `<tr>
            <td><strong>${escapeHtml(name)}</strong></td>
            <td><span style="font-family:var(--font-code); font-size:12px; color:var(--text-muted);">${escapeHtml(meta.driver) || '—'}</span></td>
            <td>${currentRole === 'viewer'
                ? '<span style="color:var(--text-muted); font-size:12px;">—</span>'
                : (isSystem
                    ? `<span style="color:var(--text-muted); font-size:12px;">${systemText}</span>`
                    : `<button data-action="delete-vendor" data-v="${escapeHtml(name)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${deleteText}</button>`)
            }</td>
        </tr>`;
    });
}

document.getElementById('vendorTableBody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="delete-vendor"]');
    if (btn && btn.dataset.v) {
        deleteVendor(btn.dataset.v);
    }
});

// Carica le identita' del tenant selezionato nella select devProfile,
// preservando default/custom. Chiamata al load della tab e al cambio tenant.
async function refreshIdentityOptions(preserve) {
    const tenant = document.getElementById('devGroupSelect').value;
    const sel = document.getElementById('devProfile');
    const keep = preserve || sel.value;
    const res = await apiFetch('/api/identities?tenant=' + encodeURIComponent(tenant));
    const idents = res && res.ok ? (await res.json()).identities : [];
    sel.innerHTML = `<option value="default">${i18n[currentLang].optProfileDefault.replace(/<[^>]*>/g, '')}</option>` +
        idents.map(i => `<option value="identity:${i.id}">${escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('') +
        `<option value="custom">${i18n[currentLang].optProfileCustom.replace(/<[^>]*>/g, '')}</option>`;
    sel.value = Array.from(sel.options).some(o => o.value === keep) ? keep : 'default';
    document.getElementById('customCredsForm').style.display = sel.value === 'custom' ? 'block' : 'none';
    window._tenantIdentities = idents;
}

function renderIdentitiesPanel() {
    const body = document.getElementById('identitiesTableBody');
    const idents = window._tenantIdentities || [];
    body.innerHTML = idents.length ? idents.map(i => {
        let tenantLabel = '';
        if (!i.tenant || i.tenant === 'all') {
            tenantLabel = `<span class="badge" style="background:var(--surface-2); color:var(--text-muted); font-size:10.5px; padding:2px 6px; border:1px solid var(--border); text-transform:uppercase; letter-spacing:0.02em;">${escapeHtml(i18n[currentLang].optTenantAll || 'Globale')}</span>`;
        } else if (Array.isArray(i.tenant)) {
            tenantLabel = i.tenant.map(t => `<span class="badge" style="background:color-mix(in srgb, var(--primary) 12%, transparent); color:var(--primary); border:1px solid color-mix(in srgb, var(--primary) 30%, transparent); font-size:10.5px; padding:2px 6px; margin-right:3px; display:inline-block; text-transform:uppercase; letter-spacing:0.02em;">${escapeHtml(t)}</span>`).join('');
        } else {
            const parts = String(i.tenant).split(',').map(s => s.trim()).filter(Boolean);
            tenantLabel = parts.map(t => `<span class="badge" style="background:color-mix(in srgb, var(--primary) 12%, transparent); color:var(--primary); border:1px solid color-mix(in srgb, var(--primary) 30%, transparent); font-size:10.5px; padding:2px 6px; margin-right:3px; display:inline-block; text-transform:uppercase; letter-spacing:0.02em;">${escapeHtml(t)}</span>`).join('');
        }
        return `<tr style="border-bottom:1px solid color-mix(in srgb, var(--border) 50%, transparent);">
        <td style="padding:8px 6px; font-weight:600; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;" title="${escapeHtml(i.name)}">${escapeHtml(i.name)}</td>
        <td style="padding:8px 6px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;">${tenantLabel}</td>
        <td style="padding:8px 6px; font-family:var(--font-code); font-size:12px; text-overflow:ellipsis; overflow:hidden; white-space:nowrap;" title="${escapeHtml(i.username)}">${escapeHtml(i.username)}</td>
        <td style="padding:8px 6px; text-align:center; font-family:var(--font-code); font-size:12px;">${i.devices_using}</td>
        <td style="padding:8px 6px; text-align:right;">
          <div style="display:flex; gap:4px; justify-content:flex-end;">
            <button class="btn-icon" data-action="assign-identity" data-id="${i.id}" style="width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center;" title="${escapeHtml(i18n[currentLang].btnAssignIdentityTitle || 'Assign to devices')}"><i class="fa-solid fa-users-rectangle" style="font-size:11px;"></i></button>
            <button class="btn-icon" data-action="edit-identity" data-id="${i.id}" style="width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center;" title="Edit"><i class="fa-solid fa-pen" style="font-size:11px;"></i></button>
            <button class="btn-icon danger" data-action="delete-identity" data-id="${i.id}" style="width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center;" title="Delete"><i class="fa-solid fa-trash-can" style="font-size:11px;"></i></button>
          </div>
        </td></tr>`;
    }).join('')
        : `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding:16px; font-size:13px;">${i18n[currentLang].emptyIdentities}</td></tr>`;
}

// ===== Port Config Modal (promosso da static/js/topology.js: usato anche
// dal tab MAC-tracker/ARP inline e da static/js/config-analyzer.js) =====
// expandIface() is declared once, further up in this same file.

// Deep-link verso il Config Analyzer (impostati da showPortConfig, letti da renderCaResults).
let caFocusIp = null;
let caFocusPort = null;

function closePortConfigModal() {
    const m = document.getElementById('portConfigModal');
    if (m) m.remove();
}

async function showPortConfig(switchIp, port, switchName) {
    const L = i18n[currentLang];
    let iface = null;
    try {
        const res = await apiFetch('/api/config-analyzer/' + encodeURIComponent(switchIp));
        if (res && res.ok) {
            const d = await res.json();
            const want = expandIface(port).toLowerCase();
            iface = (d.interfaces || []).find(i => expandIface(i.name).toLowerCase() === want) || null;
        }
    } catch (e) { /* trattato come non trovato */ }

    closePortConfigModal();
    const body = iface
        ? `<pre style="font-family:var(--font-code); background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:12px; margin:0; white-space:pre-wrap; font-size:12px;">${escapeHtml(iface.raw || '—')}</pre>`
        : `<div style="font-size:13px; color:var(--text-muted); padding:10px 0;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.portConfigNotFound)}</div>`;
    const ov = document.createElement('div');
    ov.id = 'portConfigModal';
    ov.style.cssText = 'position:fixed; inset:0; z-index:10050; background:color-mix(in srgb, var(--bg) 82%, transparent); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(4px);';
    ov.innerHTML = `
            <div style="background:var(--surface); border:1px solid var(--border); border-radius:0; padding:22px; width:min(560px,94vw); max-height:86vh; overflow:auto; box-shadow:var(--shadow-float);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <h3 style="font-size:17px;"><i class="fa-solid fa-ethernet" style="color:var(--primary);"></i> ${escapeHtml(L.portConfigTitle)}</h3>
                    <i class="fa-solid fa-xmark" data-action="close-port-config" style="cursor:pointer; color:var(--text-muted); font-size:17px;"></i>
                </div>
                <div style="font-family:var(--font-code); font-size:13px; color:var(--primary); margin-bottom:16px;">${escapeHtml(switchName || switchIp)} — ${escapeHtml(port)}</div>
                ${body}
                <div style="display:flex; justify-content:flex-end; align-items:center; gap:10px; margin-top:16px;">
                    <button data-action="open-port-in-analyzer" data-ip="${escapeHtml(switchIp)}" data-port="${escapeHtml(port)}" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-up-right-from-square"></i> ${escapeHtml(L.openInAnalyzer)}</button>
                    <button data-action="close-port-config" class="btn btn-secondary btn-small" style="width:auto; margin:0;">${tr('coreClose')}</button>
                </div>
            </div>`;
    ov.addEventListener('click', e => {
        if (e.target === ov || e.target.closest('[data-action="close-port-config"]')) closePortConfigModal();
        const openBtn = e.target.closest('[data-action="open-port-in-analyzer"]');
        if (openBtn && openBtn.dataset.ip) {
            openPortInAnalyzer(openBtn.dataset.ip, openBtn.dataset.port);
        }
    });
    document.body.appendChild(ov);
}

function openPortInAnalyzer(switchIp, port) {
    caFocusIp = switchIp;
    caFocusPort = port;
    closePortConfigModal();
    switchTab('tab-config');
}

// --- GLOBAL KEYBOARD SHORTCUTS (Power User Alex) ---
let _gPendingKey = false;
let _gPendingTimer = null;

document.addEventListener('keydown', e => {
    const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
    const isInput = activeTag === 'input' || activeTag === 'select' || activeTag === 'textarea' || (document.activeElement && document.activeElement.isContentEditable);

    if (e.key === 'Escape') {
        closePortConfigModal();
        return;
    }

    if (isInput) return;

    if (e.key === '/' || (e.ctrlKey && e.key.toLowerCase() === 'k')) {
        e.preventDefault();
        const searchEl = document.querySelector('input[type="search"], input[placeholder*="Search"], input[placeholder*="Cerca"]');
        if (searchEl) searchEl.focus();
        return;
    }

    if (e.key === 'g' && !_gPendingKey) {
        _gPendingKey = true;
        clearTimeout(_gPendingTimer);
        _gPendingTimer = setTimeout(() => { _gPendingKey = false; }, 1000);
        return;
    }

    if (_gPendingKey) {
        _gPendingKey = false;
        clearTimeout(_gPendingTimer);
        const target = e.key.toLowerCase();
        if (target === 'h') switchTab('tab-home');
        else if (target === 's') switchTab('tab-settings');
        else if (target === 'd') switchTab('tab-devices');
        // 'tab-ai-chat' era l'id del prototype: la tab reale e' tab-ai, e il
        // vecchio id faceva morire switchTab su getElementById(null).
        else if (target === 'a') switchTab('tab-ai');
    }
});


// ===== Selettore multiplo (apparati, firewall) ==============================
// Una <select multiple> nativa non prende il tema, non dice quanti elementi
// sono scelti, obbliga a Ctrl/Cmd e alza il proprio riquadro fuori dalla barra
// dei filtri. Qui e' un <details>, cioe' lo stesso dropdown del resto dell'app
// (l'elevazione sopra il pannello e' gia' gestita piu' sotto), con dentro un
// filtro, le caselle e il conteggio nel riepilogo.

/** Gli identificativi scelti dentro il selettore ``rootId``. */
function pickerValues(rootId) {
    const root = document.getElementById(rootId);
    if (!root) return [];
    return [...root.querySelectorAll('input[type="checkbox"]:checked')]
        .map(c => /** @type {HTMLInputElement} */ (c).value);
}

/** Le voci scelte, con la loro etichetta: serve a chi deve rimostrarle. */
function pickerSelected(rootId) {
    const root = document.getElementById(rootId);
    if (!root) return [];
    return [...root.querySelectorAll('input[type="checkbox"]:checked')].map(c => ({
        value: /** @type {HTMLInputElement} */ (c).value,
        label: (c.closest('.picker-item')?.querySelector('.picker-item-label')
                || {}).textContent || '',
    }));
}

/**
 * Riempie il selettore. ``items`` sono ``{value, label, hint}``; la selezione
 * corrente sopravvive al ridisegno, cosi' aggiornare l'elenco non la azzera.
 */
function renderPickerItems(rootId, items, keep) {
    const root = document.getElementById(rootId);
    if (!root) return;
    const list = root.querySelector('.picker-list');
    if (!list) return;
    const chosen = new Set(keep !== undefined ? keep : pickerValues(rootId));
    list.innerHTML = (items || []).map(it => `
        <li class="picker-item">
          <label>
            <input type="checkbox" value="${escapeHtml(it.value)}"${
                chosen.has(it.value) ? ' checked' : ''}>
            <span class="picker-item-label">${escapeHtml(it.label)}</span>
            ${it.hint ? `<span class="picker-item-hint">${escapeHtml(it.hint)}</span>` : ''}
          </label>
        </li>`).join('');
    updatePickerSummary(root);
}

function updatePickerSummary(root) {
    const out = root.querySelector('.picker-value');
    if (!out) return;
    const total = root.querySelectorAll('.picker-item input').length;
    const chosen = root.querySelectorAll('.picker-item input:checked').length;
    if (!total) { out.textContent = tr('pickerEmpty'); return; }
    if (!chosen) { out.textContent = tr('pickerNone'); return; }
    if (chosen === 1) {
        const one = root.querySelector('.picker-item input:checked');
        out.textContent = (one?.closest('.picker-item')
            ?.querySelector('.picker-item-label')?.textContent || '').trim();
        return;
    }
    out.textContent = tr('pickerCount', { n: chosen, total: total });
}

/** Notifica il modulo: il selettore ha cambiato scelta. */
function pickerChanged(root) {
    updatePickerSummary(root);
    root.dispatchEvent(new CustomEvent('picker-change'));
}

document.addEventListener('input', (e) => {
    const target = /** @type {HTMLElement} */ (e.target);
    const root = target.closest?.('.picker');
    if (!root) return;
    if (target.classList.contains('picker-search')) {
        // Filtro sulle voci, non una richiesta: con quaranta apparati scorrere
        // un elenco e' peggio che scriverne tre lettere.
        const needle = /** @type {HTMLInputElement} */ (target).value.trim().toLowerCase();
        root.querySelectorAll('.picker-item').forEach(li => {
            const text = (li.textContent || '').toLowerCase();
            /** @type {HTMLElement} */ (li).hidden = !!needle && !text.includes(needle);
        });
        return;
    }
    if (target instanceof HTMLInputElement && target.type === 'checkbox') {
        pickerChanged(root);
    }
});

document.addEventListener('click', (e) => {
    const btn = /** @type {HTMLElement} */ (e.target).closest?.('.picker [data-picker]');
    if (!btn) return;
    const root = btn.closest('.picker');
    if (!root) return;
    const wanted = btn.dataset.picker === 'all';
    root.querySelectorAll('.picker-item').forEach(li => {
        const box = /** @type {HTMLInputElement|null} */ (li.querySelector('input'));
        // "Tutti" sceglie quello che si sta guardando: con un filtro attivo,
        // selezionare anche le voci nascoste sarebbe una sorpresa.
        if (box && !(/** @type {HTMLElement} */ (li).hidden)) box.checked = wanted;
    });
    pickerChanged(root);
});

// Esc chiude il selettore aperto, come ogni altro dropdown della console.
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = /** @type {HTMLElement} */ (e.target).closest?.('.picker[open]');
    if (open) open.removeAttribute('open');
});

// --- DROPDOWN STACKING ELEVATION (Fix clipped dropdown menus across themes) ---
document.addEventListener('toggle', function(e) {
    if (e.target && e.target.tagName === 'DETAILS') {
        const panel = e.target.closest('.panel, .hero-card, .filterbar, aside, main');
        if (panel) {
            if (e.target.open) {
                panel.style.zIndex = '500';
                panel.style.position = 'relative';
                panel.classList.add('has-open-dropdown');
            } else {
                const hasOtherOpen = panel.querySelector('details[open]');
                if (!hasOtherOpen) {
                    panel.style.zIndex = '';
                    panel.classList.remove('has-open-dropdown');
                }
            }
        }
    }
}, true);

// The <tbody> is the container renderIdentitiesPanel() fills: bind the
// delegated listener here, not to a wrapper that does not exist.
document.getElementById('identitiesTableBody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn || !btn.dataset.id) return;
    const act = btn.dataset.action;
    if (act === 'assign-identity') assignIdentityToDevices(btn.dataset.id);
    else if (act === 'edit-identity') editIdentity(btn.dataset.id);
    else if (act === 'delete-identity') deleteIdentity(btn.dataset.id);
});

// --- GLOBAL TENANT SELECTOR ---
// Lo scope vive nell'URL: incollare un link a un collega e' l'handoff piu'
// comune, e senza il tenant nella query arriva silenziosamente su un'altra
// vista. L'URL e' anche cio' che fa sopravvivere lo scope a un reload.
window.globalSelectedTenant = 'all';

function tenantFromUrl() {
    return new URLSearchParams(window.location.search).get('tenant') || '';
}

function reflectTenantInUrl(tenant) {
    const params = new URLSearchParams(window.location.search);
    if (tenant && tenant !== 'all') params.set('tenant', tenant);
    else params.delete('tenant');
    const qs = params.toString();
    window.history.replaceState({}, document.title,
        window.location.pathname + (qs ? '?' + qs : ''));
}

function populateGlobalTenantSelect() {
    const sel = document.getElementById('globalTenantSelect');
    if (!sel) return;
    const cur = tenantFromUrl() || window.globalSelectedTenant || sel.value || 'all';
    const groups = Object.keys(globalGroups || {});
    const L = i18n[currentLang] || {};
    // The card already says "Tenant": the first option only needs "All".
    sel.innerHTML = `<option value="all">${L.invTabAll || 'Tutti'}</option>` +
        groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
    sel.value = groups.includes(cur) ? cur : 'all';
    window.globalSelectedTenant = sel.value;
    reflectTenantInUrl(sel.value);
    if (sel.value !== 'all') applyGlobalTenant(sel.value);
}

// A panel's tenant select is repopulated when its panel loads, which is almost
// always AFTER applyGlobalTenant ran: setting .value on a select that has no
// options yet is a silent no-op, so the panel read back '' and fell back to
// "all" — the global scope was dropped without a trace. Seed from the global
// tenant whenever the select has no usable value of its own.
function tenantSelectSeed(cur, groups, fallback) {
    if (groups.includes(cur)) return cur;
    const g = window.globalSelectedTenant;
    return (g && g !== 'all' && groups.includes(g)) ? g : fallback;
}
window.tenantSelectSeed = tenantSelectSeed;

// Propaga lo scope ai selettori che i pannelli leggono ancora.
function applyGlobalTenant(val) {
    window.globalSelectedTenant = val;
    const fSel = document.getElementById('filterGroupSelect');
    if (fSel instanceof HTMLSelectElement) { fSel.value = val; renderDeviceTable(); }
    // Endpoint Location non ha piu' un select proprio: legge direttamente
    // window.globalSelectedTenant, e qui basta dirgli di ridisegnare.
    if (typeof locTenantChanged === 'function') locTenantChanged();
    // The overview was computed once for the whole fleet and never redrawn.
    if (document.getElementById('tab-home')?.classList.contains('active')) loadHome();
    const topSel = document.getElementById('topologyGroupSelect');
    if (topSel instanceof HTMLSelectElement && val !== 'all') { topSel.value = val; }
    // Sync remaining per-panel VIEW FILTERS: set value and fire change so the
    // panel's own handler reacts (re-fetches data, etc.).
    // La scheda HA non ha piu' una select propria: legge
    // window.globalSelectedTenant e basta, come Endpoint Location.
    if (typeof window.redundancyTenantChanged === 'function') window.redundancyTenantChanged();
    for (const sid of ['ptTenantSelect', 'driftTenantSelect',
                       'wlcTenantSelect', 'ifTenantFilter', 'categoriesGroupSelect',
                       'configGroupSelect', 'interactiveGroupSelect',
                       'bulkGroupFilter']) {
        const sel = document.getElementById(sid);
        if (sel instanceof HTMLSelectElement && val !== 'all') {
            sel.value = val;
            sel.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }
    // I filtri delle tre viste Threat Intel. Il valore va seminato sempre — chi
    // sceglie una sede in cima alla pagina si aspetta di trovarla anche qui —
    // ma il ricarico costa (una scansione, o la lettura di ogni snapshot su
    // disco) e pagarlo per un pannello che nessuno sta guardando e' spreco.
    // Si ricarica quindi solo il pannello DAVVERO a schermo; gli altri leggono
    // il valore aggiornato quando vengono aperti.
    //
    // Seminare senza ricaricare quello visibile era meta' del bug: la tendina
    // mostrava la sede nuova e la lista sotto restava quella di prima, cioe'
    // il filtro sembrava non avere effetto fino a un refresh della pagina.
    //
    // La visibilita' si misura con offsetParent e non con style.display: un
    // pannello con display:block dentro una scheda non attiva e' comunque
    // invisibile, e sul suo style.display non c'e' scritto niente.
    for (const [selId, paneId] of [['threatGroupSelect', 'tiViewMatcher'],
                                   ['cvePrioTenant', 'tiViewPriority'],
                                   ['cveReportTenant', 'tiViewReport']]) {
        const sel = document.getElementById(selId);
        if (!(sel instanceof HTMLSelectElement) || val === 'all') continue;
        sel.value = val;
        const pane = document.getElementById(paneId);
        if (pane instanceof HTMLElement && pane.offsetParent !== null) {
            sel.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }

    // FORM FIELDS are not filters: they choose which tenant a config is
    // generated for, or an identity assigned to. Pre-filling an untouched one
    // is a convenience; overwriting a choice the user made themselves is data
    // loss they never see. Only seed fields the user has not set, and never
    // dispatch change on them — that fires the form's own side effects.
    for (const sid of ['aiAttachTenant', 'genCfgTenant', 'identTenant']) {
        const sel = document.getElementById(sid);
        if (sel instanceof HTMLSelectElement && val !== 'all'
            && sel.dataset.userSet !== '1') {
            sel.value = val;
        }
    }
    window.dispatchEvent(new CustomEvent('globalTenantChanged', { detail: { tenant: val } }));
}

// A real user picking a tenant in a form marks it as theirs, so the global
// selector stops seeding it. isTrusted separates a human change from the
// synthetic ones dispatched above.
document.addEventListener('change', (e) => {
    const t = e.target;
    if (!e.isTrusted || !(t instanceof HTMLSelectElement)) return;
    if (['aiAttachTenant', 'genCfgTenant', 'identTenant'].includes(t.id)) {
        t.dataset.userSet = '1';
    }
});

document.getElementById('globalTenantSelect')?.addEventListener('change', (e) => {
    const target = e.target;
    if (!(target instanceof HTMLSelectElement)) return;
    reflectTenantInUrl(target.value);
    applyGlobalTenant(target.value);
});

// --- GLOBAL DEVICE CONTEXT CHIP ---
window.globalDeviceContext = null;

function setGlobalDeviceContext(ctx) {
    if (!ctx || !ctx.ip) {
        clearGlobalDeviceContext();
        return;
    }
    window.globalDeviceContext = ctx;
    const chip = document.getElementById('globalDeviceChip');
    const label = document.getElementById('globalDeviceChipLabel');
    if (chip && label) {
        label.textContent = `${ctx.name || ctx.ip} · ${ctx.ip}`;
        chip.style.display = 'inline-flex';
    }
    window.dispatchEvent(new CustomEvent('globalDeviceContextChanged', { detail: ctx }));
}

function clearGlobalDeviceContext() {
    window.globalDeviceContext = null;
    const chip = document.getElementById('globalDeviceChip');
    if (chip) chip.style.display = 'none';
    window.dispatchEvent(new CustomEvent('globalDeviceContextChanged', { detail: null }));
}

document.getElementById('btnRemoveDeviceContext')?.addEventListener('click', () => {
    clearGlobalDeviceContext();
});

// --- COMMAND PALETTE (Ctrl+K) & SHORTCUTS ---
let _cmdSelectedIdx = 0;
let _cmdItems = [];

function buildCommandPaletteItems(query = '') {
    const q = query.trim().toLowerCase();
    const items = [];

    // 1. Viste / Schede
    // Device tools lead the list: they no longer have a nav entry, so the
    // palette is their only route until the capability chips land on the
    // inventory rows. Last in the array they sat below the fold with an
    // empty query, which is the same as not being there.
    const navItems = [
        { id: 'tab-fortigate', title: 'Fortigate Management', desc: tr('coreFirewallPoliciesAddressObjects'), group: tr('coreDeviceTools') },
        { id: 'tab-wlc', title: 'Cisco WLC', desc: tr('coreAccessPointsSsidsAnd'), group: tr('coreDeviceTools') },
        { id: 'tab-redundancy', title: tr('coreHighAvailabilityHa'), desc: tr('coreRedundancyPairsAndFailover'), group: tr('coreDeviceTools') },
        { id: 'tab-home', title: tr('coreOverviewPosture'), desc: tr('coreFleetPostureVerdictsAnd'), group: tr('coreViews') },
        { id: 'tab-incidents', title: tr('coreIncidents'), desc: tr('coreCorrelatedSecurityAndOperational'), group: tr('coreViews') },
        { id: 'tab-flows', title: tr('coreTrafficObservability'), desc: tr('coreTopTalkersAnomaliesAnd'), group: tr('coreViews') },
        { id: 'tab-endpoint', title: tr('coreEndpointInventoryMacTracker'), desc: tr('coreDiscoveredEndpointsMacTracking'), group: tr('coreViews') },
        { id: 'tab-ai', title: 'AI Assistant', desc: tr('coreNetworkAssistantAndConfig'), group: tr('coreViews') },
        { id: 'tab-devices', title: 'Network Inventory', desc: tr('coreDeviceListCredentialsAnd'), group: tr('coreViews') },
        { id: 'tab-map', title: tr('coreTopology'), desc: tr('coreLLTopologyAnd'), group: tr('coreViews') },
        { id: 'tab-categories', title: tr('coreCategoriesDevices'), desc: tr('coreHardwareModelsRolesAnd'), group: tr('coreViews') },
        { id: 'tab-security', title: 'Threat Intel (NVD NIST)', desc: tr('coreCveVulnerabilitiesAcrossDevices'), group: tr('coreViews') },
        { id: 'tab-config', title: 'Config Analyzer', desc: tr('coreConfigurationParsingAndInterface'), group: tr('coreViews') },
        { id: 'tab-netsec-audit', title: 'NetSec Audit', desc: tr('coreFirewallAndSecurityAudit'), group: tr('coreViews') },
        { id: 'tab-policy-test', title: tr('corePolicyRoutingValidation'), desc: tr('corePolicyTraceAndRouting'), group: tr('coreViews') },
        { id: 'tab-config-drift', title: 'Config Drift', desc: tr('coreRunningConfigVsBackup'), group: tr('coreViews') },
        { id: 'tab-routes', title: tr('coreRoutingTables'), desc: tr('coreRoutesAcrossDevices'), group: tr('coreViews') },
        { id: 'tab-provisioning', title: 'Provisioning', desc: tr('coreAddNewDevicesAnd'), group: tr('coreViews') },
        { id: 'tab-import', title: tr('coreCsvImport'), desc: tr('coreBulkImportDevicesFrom'), group: tr('coreViews') },
        { id: 'tab-users', title: tr('coreUsers'), desc: tr('coreManageLocalUserAccounts'), group: tr('coreViews') },
        { id: 'tab-groups', title: tr('coreTenantManagement'), desc: tr('coreConfigureTenantsAndSnmp'), group: tr('coreViews') },
        { id: 'tab-sites', title: tr('coreSites'), desc: tr('corePhysicalSitesAndSite'), group: tr('coreViews') },
        { id: 'tab-mcp', title: tr('coreIntegrationsMcp'), desc: tr('coreMcpServersAndExternal'), group: tr('coreViews') },
        { id: 'tab-settings', title: tr('coreSettings'), desc: tr('coreAppSettingsPingMonitor'), group: tr('coreViews') },
    ];

    navItems.forEach(item => {
        if (!q || item.title.toLowerCase().includes(q) || item.desc.toLowerCase().includes(q)) {
            items.push({
                type: 'tab',
                tabId: item.id,
                title: item.title,
                desc: item.desc,
                group: item.group,
                icon: 'fa-table-columns',
                action: () => switchTab(item.id)
            });
        }
    });

    // 2. Apparati
    (globalDevices || []).forEach(d => {
        const h = (d.Hostname || '').toLowerCase();
        const ip = (d.IP || '').toLowerCase();
        const t = (d.Group || '').toLowerCase();
        if (!q || h.includes(q) || ip.includes(q) || t.includes(q)) {
            items.push({
                type: 'device',
                title: `${d.Hostname || d.IP} (${d.IP})`,
                desc: `Tenant: ${d.Group || '—'} · ${d.Site || 'central'}`,
                group: tr('coreDevices'),
                icon: 'fa-server',
                action: () => {
                    setGlobalDeviceContext({ ip: d.IP, name: d.Hostname || d.IP, tenant: d.Group || '' });
                    switchTab('tab-devices');
                }
            });
        }
    });

    // 3. Azioni rapide
    const quickActions = [
        { title: tr('coreRunGlobalTriage'), desc: tr('coreExecuteTriageCheckAcross'), icon: 'fa-bolt-lightning', action: () => { const b = document.getElementById('btnHomeRunTriage'); if (b) b.click(); } },
        { title: tr('coreRunMacScan'), desc: tr('coreCollectMacAddressTable'), icon: 'fa-satellite-dish', action: () => { switchTab('tab-endpoint'); if (typeof locSwitchView === 'function') locSwitchView('mac'); const b = document.getElementById('btnMacScan'); if (b) b.click(); } },
        { title: tr('coreRunArpCollection'), desc: tr('coreCollectArpBindingsFrom'), icon: 'fa-network-wired', action: () => { switchTab('tab-endpoint'); if (typeof locSwitchView === 'function') locSwitchView('mac'); const b = document.getElementById('btnArpScan'); if (b) b.click(); } },
        { title: tr('coreAddNewDevice'), desc: tr('coreOpenProvisioningFormFor'), icon: 'fa-circle-plus', action: () => switchTab('tab-provisioning') },
        { title: tr('coreToggleTheme'), desc: tr('coreSwitchDarkLightTheme'), icon: 'fa-circle-half-stroke', action: () => toggleTheme() },
    ];

    quickActions.forEach(a => {
        if (!q || a.title.toLowerCase().includes(q) || a.desc.toLowerCase().includes(q)) {
            items.push({
                type: 'action',
                title: a.title,
                desc: a.desc,
                group: tr('coreQuickActions'),
                icon: a.icon,
                action: a.action
            });
        }
    });

    return items;
}

function renderCommandPalette(items) {
    const host = document.getElementById('cmdPaletteResults');
    if (!host) return;
    _cmdItems = items;
    if (_cmdSelectedIdx >= items.length) _cmdSelectedIdx = Math.max(0, items.length - 1);

    if (!items.length) {
        host.innerHTML = `<div style="padding:24px; text-align:center; color:var(--text-muted); font-size:13px;">
            <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(tr('coreNoMatchingCommandsOr'))}</div>`;
        return;
    }

    let html = '';
    let curGroup = '';
    items.forEach((item, idx) => {
        if (item.group !== curGroup) {
            curGroup = item.group;
            html += `<div class="cmd-group-header">${escapeHtml(curGroup)}</div>`;
        }
        const isSel = idx === _cmdSelectedIdx;
        html += `<div class="cmd-item ${isSel ? 'selected' : ''}" data-cmd-idx="${idx}">
            <div class="cmd-item-left">
                <i class="fa-solid ${item.icon}" style="color:var(--primary); font-size:13px; width:16px; text-align:center;"></i>
                <div>
                    <div class="cmd-item-title">${escapeHtml(item.title)}</div>
                    <div class="cmd-item-desc">${escapeHtml(item.desc)}</div>
                </div>
            </div>
            <span class="cmd-item-badge">${escapeHtml(item.type.toUpperCase())}</span>
        </div>`;
    });
    host.innerHTML = html;

    const selEl = host.querySelector('.cmd-item.selected');
    if (selEl) selEl.scrollIntoView({ block: 'nearest' });
}

function openCommandPalette() {
    const modal = document.getElementById('commandPaletteModal');
    const input = document.getElementById('cmdPaletteInput');
    if (!modal || !input) return;
    _cmdSelectedIdx = 0;
    if (input instanceof HTMLInputElement) input.value = '';
    openModal(modal);
    renderCommandPalette(buildCommandPaletteItems(''));
    input.focus();
}

function closeCommandPalette() {
    const modal = document.getElementById('commandPaletteModal');
    if (modal) closeModal(modal);
}

function openShortcutsModal() {
    const modal = document.getElementById('shortcutsModal');
    if (modal) openModal(modal);
}

function closeShortcutsModal() {
    const modal = document.getElementById('shortcutsModal');
    if (modal) closeModal(modal);
}

document.getElementById('btnOpenCommandPalette')?.addEventListener('click', openCommandPalette);
document.getElementById('btnOpenShortcuts')?.addEventListener('click', openShortcutsModal);
document.getElementById('btnCloseShortcuts')?.addEventListener('click', closeShortcutsModal);

document.getElementById('commandPaletteModal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeCommandPalette();
});
document.getElementById('shortcutsModal')?.addEventListener('click', (e) => {
    if (e.target === e.currentTarget) closeShortcutsModal();
});

document.getElementById('cmdPaletteInput')?.addEventListener('input', (e) => {
    const target = e.target;
    const val = (target instanceof HTMLInputElement) ? target.value : '';
    _cmdSelectedIdx = 0;
    renderCommandPalette(buildCommandPaletteItems(val));
});

document.getElementById('cmdPaletteInput')?.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') {
        e.preventDefault();
        _cmdSelectedIdx = Math.min(_cmdItems.length - 1, _cmdSelectedIdx + 1);
        renderCommandPalette(_cmdItems);
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        _cmdSelectedIdx = Math.max(0, _cmdSelectedIdx - 1);
        renderCommandPalette(_cmdItems);
    } else if (e.key === 'Enter') {
        e.preventDefault();
        if (_cmdItems[_cmdSelectedIdx]) {
            const act = _cmdItems[_cmdSelectedIdx].action;
            closeCommandPalette();
            if (typeof act === 'function') act();
        }
    } else if (e.key === 'Escape') {
        e.preventDefault();
        closeCommandPalette();
    }
});

document.getElementById('cmdPaletteResults')?.addEventListener('click', (e) => {
    const itemEl = e.target instanceof Element ? e.target.closest('[data-cmd-idx]') : null;
    if (!itemEl) return;
    const idx = parseInt(itemEl.getAttribute('data-cmd-idx') || '0', 10);
    if (_cmdItems[idx]) {
        const act = _cmdItems[idx].action;
        closeCommandPalette();
        if (typeof act === 'function') act();
    }
});

// Global Shortcuts
document.addEventListener('keydown', (e) => {
    const activeTag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
    const isInput = activeTag === 'input' || activeTag === 'textarea' || activeTag === 'select';

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const modal = document.getElementById('commandPaletteModal');
        if (modal && modal.style.display === 'flex') closeCommandPalette();
        else openCommandPalette();
        return;
    }

    if (e.key === 'Escape') {
        const cmdModal = document.getElementById('commandPaletteModal');
        if (cmdModal && cmdModal.style.display === 'flex') {
            closeCommandPalette();
            return;
        }
        const scModal = document.getElementById('shortcutsModal');
        if (scModal && scModal.style.display === 'flex') {
            closeShortcutsModal();
            return;
        }
        if (window.globalDeviceContext) {
            clearGlobalDeviceContext();
            return;
        }
    }

    if (!isInput) {
        if (e.key === '?') {
            e.preventDefault();
            openShortcutsModal();
            return;
        }
        if (e.key === '/') {
            e.preventDefault();
            openCommandPalette();
            return;
        }
        if (e.key === 't' || e.key === 'T') {
            e.preventDefault();
            toggleTheme();
            return;
        }
    }
});

window.loadAssetOnce = loadAssetOnce;
window.setGlobalDeviceContext = setGlobalDeviceContext;
window.clearGlobalDeviceContext = clearGlobalDeviceContext;
window.openCommandPalette = openCommandPalette;
window.closeCommandPalette = closeCommandPalette;

