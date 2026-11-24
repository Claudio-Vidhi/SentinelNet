// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// Search box on top of device dropdowns.
//
// Any <select data-device-search> gets an <input type="search"> right before
// it that hides the options not matching the typed text. It only toggles
// option.hidden: it never sets the select's value nor fires change, because
// several of these selects load data on change.
//
// Always loaded, no dependency on lazy modules: one MutationObserver on the
// body picks up selects that lazy tabs build or refill later.

const SELECT_SEARCH_MIN_OPTIONS = 10;

function selectSearchMatches(text, query) {
    const hay = String(text).toLowerCase();
    return String(query).toLowerCase().split(/\s+/).filter(Boolean).every(term => hay.includes(term));
}

function _selectSearchFilter(sel, input) {
    for (const opt of sel.options) opt.hidden = !selectSearchMatches(opt.text, input.value);
}

function enhanceDeviceSelects(root) {
    (root || document).querySelectorAll('select[data-device-search]').forEach(sel => {
        let input = /** @type {any} */ (sel)._searchInput;
        if (!input) {
            input = document.createElement('input');
            input.type = 'search';
            input.className = 'select-search';
            input.setAttribute('placeholder', tr('selSearchPh'));
            input.setAttribute('aria-label', tr('selSearchPh'));
            input.setAttribute('data-i18n-placeholder', 'selSearchPh');
            input.setAttribute('data-i18n-aria-label', 'selSearchPh');
            input.addEventListener('input', () => _selectSearchFilter(sel, input));
            sel.parentNode.insertBefore(input, sel);
            /** @type {any} */ (sel)._searchInput = input;
        }
        input.hidden = sel.options.length < SELECT_SEARCH_MIN_OPTIONS;
        // Refilled options start visible: re-apply the current query.
        if (input.value) _selectSearchFilter(sel, input);
    });
}

window.enhanceDeviceSelects = enhanceDeviceSelects;

// Coalesce bursts of mutations (a refill replaces every option) into one pass.
// Toggling option.hidden / input.hidden is an attribute change, so this pass
// does not re-trigger the childList observer.
let _selectSearchPending = false;
new MutationObserver(() => {
    if (_selectSearchPending) return;
    _selectSearchPending = true;
    requestAnimationFrame(() => {
        _selectSearchPending = false;
        enhanceDeviceSelects();
    });
}).observe(document.body, { childList: true, subtree: true });
enhanceDeviceSelects();
