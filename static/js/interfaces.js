// -*- coding: utf-8 -*-
/**
 * SentinelNet - Monitoraggio Interfacce & Stato Atteso
 * Gestione dello stato operativo delle interfacce, finestre di manutenzione e soppressioni.
 */

(function () {
    'use strict';

    /** @type {Array<any>} */
    let _ifaces = [];
    /** @type {Array<any>} */
    let _suppressions = [];
    let _activeFilter = 'all';
    let _searchQuery = '';
    let _minTransitions = 4;
    /** @type {Set<number>} */
    const _selectedIndices = new Set();

    const _ifL = (key) => {
        const lang = (typeof currentLang !== 'undefined' && currentLang) ? currentLang : 'it';
        if (typeof i18n !== 'undefined' && i18n[lang] && i18n[lang][key]) {
            return i18n[lang][key];
        }
        return (typeof i18n !== 'undefined' && i18n.it && i18n.it[key]) || key;
    };

    const _ifEsc = (str) => {
        return String(str || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };

    const _toLocalIso = (ts) => {
        if (!ts) return '';
        const d = new Date(ts * 1000);
        const pad = (n) => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    };

    // Lo stato lo calcola il server e viaggia con la riga. Prima esisteva
    // anche qui, con un vocabolario diverso: bastava correggerne uno perche'
    // i cartelli in cima smettessero di combaciare con la tabella sotto.
    const _computeState = (r) => r.state || 'unknown';

    const _renderCards = (counts) => {
        const tally = (state) => _ifaces.filter(i => _computeState(i) === state).length;
        const c = counts || {
            total: _ifaces.length,
            up: tally('up'),
            outage: tally('outage'),
            flapping: tally('flapping'),
            maint: tally('maint'),
            by_design: tally('by_design'),
            unknown: tally('unknown'),
        };

        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = String(val);
        };

        setVal('ifCardTotal', c.total);
        setVal('ifCardUp', c.up);
        setVal('ifCardOutage', c.outage);
        setVal('ifCardFlap', c.flapping);
        setVal('ifCardMaint', c.maint);
        setVal('ifCardByDesign', c.by_design);
        setVal('ifCardUnknown', c.unknown);
    };

    const _getFilteredRows = () => {
        const q = _searchQuery.trim().toLowerCase();
        return _ifaces.filter(r => {
            const state = _computeState(r);
            if (_activeFilter !== 'all' && state !== _activeFilter) {
                return false;
            }
            if (!q) return true;
            const host = (r.hostname || '').toLowerCase();
            const ip = (r.device_ip || '').toLowerCase();
            const iface = (r.interface || '').toLowerCase();
            const note = (r.note || '').toLowerCase();
            return host.includes(q) || ip.includes(q) || iface.includes(q) || note.includes(q);
        });
    };

    const _renderTable = () => {
        const box = document.getElementById('ifacesTableBox');
        if (!box) return;

        const rows = _getFilteredRows();
        const selectedCount = _selectedIndices.size;
        const bulkBar = document.getElementById('ifBulkActionsBar');
        if (bulkBar) {
            bulkBar.style.display = selectedCount > 0 ? 'flex' : 'none';
            const countEl = document.getElementById('ifSelectedCount');
            if (countEl) countEl.textContent = String(selectedCount);
        }

        if (!rows.length) {
            const nothingCollected = _ifaces.length === 0;
            box.innerHTML = `<div class="if-empty">
                <i class="fa-solid ${nothingCollected ? 'fa-satellite-dish' : 'fa-filter'} if-empty-icon"></i>
                ${_ifL(nothingCollected ? 'ifNoData' : 'ifNoMatching')}
            </div>`;
            return;
        }

        const allSelected = rows.length > 0 && rows.every(r => _selectedIndices.has(r._idx));

        let html = `<table style="width:100%; border-collapse:collapse; font-size:12px; text-align:left;">
            <thead>
                <tr style="border-bottom:2px solid var(--border); background:var(--surface-1); color:var(--text-muted); font-size:11px; text-transform:uppercase; letter-spacing:0.5px;">
                    <th style="padding:8px; width:36px; text-align:center;">
                        <input type="checkbox" id="ifSelectAll" aria-label="Seleziona tutte" ${allSelected ? 'checked' : ''} style="cursor:pointer;">
                    </th>
                    <th style="padding:8px 10px;">${_ifL('ifThDevice')}</th>
                    <th style="padding:8px 10px;">${_ifL('ifThInterface')}</th>
                    <th style="padding:8px 10px;">${_ifL('ifThStatus')}</th>
                    <th style="padding:8px 10px;">${_ifL('ifThFlaps')}</th>
                    <th style="padding:8px 10px;">${_ifL('ifThExpected')}</th>
                    <th style="padding:8px 10px;">${_ifL('ifThUntil')}</th>
                    <th style="padding:8px 10px;">${_ifL('ifThReason')}</th>
                    <th style="padding:8px 10px; width:80px; text-align:right;">${_ifL('ifThActions')}</th>
                </tr>
            </thead>
            <tbody>`;

        rows.forEach(r => {
            const state = _computeState(r);
            const isChecked = _selectedIndices.has(r._idx);
            let badge = '';
            if (state === 'up') {
                badge = `<span class="badge if-badge-up"><i class="fa-solid fa-circle if-badge-dot"></i>UP</span>`;
            } else if (state === 'outage') {
                badge = `<span class="badge if-badge-down"><i class="fa-solid fa-circle-exclamation if-badge-dot"></i>DOWN</span>`;
            } else if (state === 'flapping') {
                badge = `<span class="badge if-badge-flap"><i class="fa-solid fa-bolt if-badge-dot"></i>FLAP</span>`;
            } else if (state === 'maint') {
                badge = `<span class="badge if-badge-maint"><i class="fa-solid fa-screwdriver-wrench if-badge-dot"></i>MAINT</span>`;
            } else if (state === 'by_design') {
                badge = `<span class="badge if-badge-design"><i class="fa-solid fa-ban if-badge-dot"></i>DESIGN</span>`;
            } else {
                // Ne' su ne' rotta: dirlo e' il punto. Finiva fra le operative.
                badge = `<span class="badge if-badge-unknown" title="${_ifEsc(String(r.link || ''))}"><i class="fa-solid fa-question if-badge-dot"></i>?</span>`;
            }

            const adminBadge = r.admin_status
                ? `<span style="font-size:10px; color:var(--text-muted); font-family:var(--font-code);">admin: ${_ifEsc(r.admin_status)}</span>`
                : '';

            const flapColor = r.transitions >= _minTransitions ? 'color:var(--warning); font-weight:700;' : 'color:var(--text-muted);';

            html += `<tr style="border-bottom:1px solid var(--border); ${isChecked ? 'background:rgba(59,130,246, 0.08);' : ''}">
                <td style="padding:8px; text-align:center;">
                    <input type="checkbox" class="if-row-check" data-idx="${r._idx}" aria-label="Seleziona interfaccia" ${isChecked ? 'checked' : ''} style="cursor:pointer;">
                </td>
                <td style="padding:8px 10px;">
                    <div style="font-weight:600; color:var(--text);">${_ifEsc(r.hostname || r.device_ip)}</div>
                    ${r.hostname ? `<div style="font-size:11px; color:var(--text-muted); font-family:var(--font-code);">${_ifEsc(r.device_ip)}</div>` : ''}
                </td>
                <td style="padding:8px 10px;">
                    <code style="font-size:12px; font-weight:700;">${_ifEsc(r.interface)}</code>
                </td>
                <td style="padding:8px 10px;">
                    <div style="display:flex; flex-direction:column; gap:2px;">
                        <div>${badge}</div>
                        ${adminBadge}
                    </div>
                </td>
                <td style="padding:8px 10px;">
                    <span style="${flapColor}">${r.transitions || 0}</span>
                </td>
                <td style="padding:8px 10px;">
                    <label style="display:inline-flex; align-items:center; gap:6px; font-size:11px; cursor:pointer;">
                        <input type="checkbox" id="ifx-chk-${r._idx}" ${r.suppressed ? 'checked' : ''}>
                        <span style="font-weight:600;">${_ifL('ifOptSuppressed')}</span>
                    </label>
                </td>
                <td style="padding:8px 10px;">
                    <input type="datetime-local" id="ifx-until-${r._idx}" value="${_ifEsc(_toLocalIso(r.to_ts))}" aria-label="Fino a data"
                           style="padding:3px 6px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:11px;">
                </td>
                <td style="padding:8px 10px;">
                    <input type="text" id="ifx-note-${r._idx}" value="${_ifEsc(r.note || '')}" placeholder="${_ifL('incReasonPl')}" aria-label="Nota interfaccia"
                           style="width:100%; min-width:120px; padding:3px 6px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:11px;">
                </td>
                <td style="padding:8px 10px; text-align:right;">
                    <button class="btn btn-primary btn-sm" data-action="save-single-if" data-idx="${r._idx}" style="padding:3px 8px; font-size:11px; margin:0;" title="${_ifL('ifBtnSaveTooltip')}">
                        <i class="fa-solid fa-floppy-disk"></i>
                    </button>
                </td>
            </tr>`;
        });

        html += `</tbody></table>`;
        box.innerHTML = html;
    };

    const _renderDeclaredSuppressions = () => {
        const box = document.getElementById('ifDeclaredSuppressionsBox');
        if (!box) return;

        if (!_suppressions.length) {
            box.innerHTML = `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">${_ifL('ifNoDeclaredSupp')}</div>`;
            return;
        }

        const when = (r) => r.to_ts
            ? `${_ifL('incSuppUntil')} ${new Date(r.to_ts * 1000).toLocaleString()}`
            : _ifL('incSuppNoExpiry');

        box.innerHTML = `<div style="display:flex; flex-direction:column; gap:6px; font-size:11px; margin-top:8px;">
            ${_suppressions.map(r => `<div style="padding:6px 10px; background:var(--surface-1); border:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; ${r.expired ? 'opacity:.45; text-decoration:line-through;' : ''}">
                <div>
                    <code>${_ifEsc(r.device_ip || '')}</code>${r.interface ? ':' + _ifEsc(r.interface) : ` <em>${_ifL('incSuppWholeDevice')}</em>`}
                    <span style="color:var(--primary); font-weight:600; margin:0 6px;">—</span>
                    <span>${_ifEsc(when(r))}</span>
                    ${r.note ? `<span style="color:var(--text-muted); margin-left:8px;">· ${_ifEsc(r.note)}</span>` : ''}
                    <span style="color:var(--text-muted); margin-left:8px;">· ${_ifEsc(r.by || '')}</span>
                </div>
                <div>
                    <button class="btn btn-secondary btn-sm" data-action="remove-declared-supp" data-tenant="${_ifEsc(r.tenant || '')}" data-ip="${_ifEsc(r.device_ip || '')}" data-iface="${_ifEsc(r.interface || '')}" style="padding:2px 6px; font-size:10px;" title="${_ifL('ifBtnClearMaint')}">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            </div>`).join('')}
        </div>`;
    };

    const saveSingleInterface = async (idx) => {
        const r = _ifaces[idx];
        if (!r) return;

        const chk = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-chk-${idx}`));
        const until = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-until-${idx}`));
        const note = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-note-${idx}`));
        const statusBox = document.getElementById('ifTabStatus');

        const untilVal = until ? until.value : '';
        const payload = {
            tenant: r.tenant,
            device_ip: r.device_ip,
            interface: r.interface,
            suppressed: chk ? chk.checked : false,
            to_ts: untilVal ? Math.floor(new Date(untilVal).getTime() / 1000) : null,
            note: note ? note.value : ''
        };

        try {
            const res = await apiFetch('/api/incidents/interfaces/expected', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!res || !res.ok) {
                const err = await res.json().catch(() => ({}));
                if (statusBox) statusBox.textContent = err.detail || _ifL('incErrGeneric');
                return;
            }
            if (statusBox) statusBox.textContent = `${r.device_ip}:${r.interface} ${_ifL('incUpdated')}`;
            await loadInterfacesTab();
        } catch (e) {
            if (statusBox) statusBox.textContent = _ifL('incErrGeneric');
        }
    };

    const _applyPresetToSelected = (hours) => {
        if (!_selectedIndices.size) return;
        const now = Math.floor(Date.now() / 1000);
        const toTs = hours ? now + (hours * 3600) : null;
        const defaultNote = hours ? `Manutenzione (${hours}h)` : 'Non utilizzata per progetto';

        _selectedIndices.forEach(idx => {
            const chk = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-chk-${idx}`));
            const until = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-until-${idx}`));
            const note = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-note-${idx}`));
            if (chk) chk.checked = true;
            if (until) until.value = toTs ? _toLocalIso(toTs) : '';
            if (note && !note.value) note.value = defaultNote;
        });
    };

    const saveBulkSelection = async () => {
        if (!_selectedIndices.size) return;
        const statusBox = document.getElementById('ifTabStatus');
        const items = [];

        _selectedIndices.forEach(idx => {
            const r = _ifaces[idx];
            if (!r) return;
            const chk = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-chk-${idx}`));
            const until = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-until-${idx}`));
            const note = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-note-${idx}`));
            const untilVal = until ? until.value : '';

            items.push({
                tenant: r.tenant,
                device_ip: r.device_ip,
                interface: r.interface,
                suppressed: chk ? chk.checked : false,
                to_ts: untilVal ? Math.floor(new Date(untilVal).getTime() / 1000) : null,
                note: note ? note.value : ''
            });
        });

        try {
            const res = await apiFetch('/api/incidents/interfaces/expected', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ items: items })
            });
            if (!res || !res.ok) {
                const err = await res.json().catch(() => ({}));
                if (statusBox) statusBox.textContent = err.detail || _ifL('incErrGeneric');
                return;
            }
            if (statusBox) statusBox.textContent = `${items.length} ${_ifL('ifBulkUpdated')}`;
            await loadInterfacesTab();
        } catch (e) {
            if (statusBox) statusBox.textContent = _ifL('incErrGeneric');
        }
    };

    const clearBulkSelection = async () => {
        if (!_selectedIndices.size) return;
        _selectedIndices.forEach(idx => {
            const chk = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-chk-${idx}`));
            const until = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-until-${idx}`));
            const note = /** @type {HTMLInputElement|null} */ (document.getElementById(`ifx-note-${idx}`));
            if (chk) chk.checked = false;
            if (until) until.value = '';
            if (note) note.value = '';
        });
        await saveBulkSelection();
    };

    const loadInterfacesTab = async () => {
        const root = document.getElementById('tab-interfaces');
        if (!root) return;
        const statusBox = document.getElementById('ifTabStatus');
        if (statusBox) statusBox.textContent = '';

        try {
            const res = await apiFetch('/api/incidents/interfaces');
            if (!res || !res.ok) {
                const tableBox = document.getElementById('ifacesTableBox');
                if (tableBox) tableBox.innerHTML = `<div style="color:var(--danger); font-size:12px; padding:16px;">${_ifL('ifErrLoad')}</div>`;
                return;
            }
            const data = await res.json();
            _ifaces = (data.interfaces || []).map((r, idx) => ({ ...r, _idx: idx }));
            _suppressions = data.suppressions || [];
            _minTransitions = data.min_transitions || 4;
            _selectedIndices.clear();

            _renderCards(data.counts);
            _renderTable();
            _renderDeclaredSuppressions();

            const capNote = document.getElementById('ifTruncatedNote');
            if (capNote) {
                capNote.hidden = !data.truncated;
                if (data.truncated) {
                    capNote.textContent = _ifL('ifTruncated').replace('{n}', String(data.limit));
                }
            }
        } catch (err) {
            console.error('[interfaces]', err);
        }
    };

    // Event Listeners
    const _initIfEvents = () => {
        const root = document.getElementById('tab-interfaces');
        if (!root) return;

        // Search Filter
        const searchInput = /** @type {HTMLInputElement|null} */ (document.getElementById('ifSearchInput'));
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                _searchQuery = searchInput.value;
                _renderTable();
            });
        }

        // Status Filter Chips
        document.querySelectorAll('[data-if-filter]').forEach(el => {
            el.addEventListener('click', (e) => {
                const tgt = /** @type {HTMLElement|null} */ (e.target);
                const btn = /** @type {HTMLElement|null} */ (tgt?.closest('[data-if-filter]'));
                if (!btn) return;
                document.querySelectorAll('[data-if-filter]').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                _activeFilter = btn.getAttribute('data-if-filter') || 'all';
                _renderTable();
            });
        });

        // Quick Preset dropdown
        const presetSelect = /** @type {HTMLSelectElement|null} */ (document.getElementById('ifPresetSelect'));
        if (presetSelect) {
            presetSelect.addEventListener('change', () => {
                const val = presetSelect.value;
                if (!val) return;
                if (val === 'permanent') {
                    _applyPresetToSelected(0);
                } else {
                    _applyPresetToSelected(Number(val));
                }
                presetSelect.value = '';
            });
        }

        // Refresh Button
        document.getElementById('ifBtnRefresh')?.addEventListener('click', () => {
            loadInterfacesTab();
        });

        // Bulk Actions
        document.getElementById('ifBtnBulkSave')?.addEventListener('click', saveBulkSelection);
        document.getElementById('ifBtnBulkClear')?.addEventListener('click', clearBulkSelection);

        // Table Delegations
        root.addEventListener('click', async (e) => {
            const target = /** @type {HTMLElement|null} */ (e.target);

            // Single save
            const saveBtn = /** @type {HTMLElement|null} */ (target?.closest('[data-action="save-single-if"]'));
            if (saveBtn && saveBtn.dataset.idx != null) {
                saveSingleInterface(Number(saveBtn.dataset.idx));
                return;
            }

            // Remove declared suppression
            const remBtn = /** @type {HTMLElement|null} */ (target?.closest('[data-action="remove-declared-supp"]'));
            if (remBtn && remBtn.dataset.tenant && remBtn.dataset.ip) {
                await apiFetch('/api/incidents/interfaces/expected', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        tenant: remBtn.dataset.tenant,
                        device_ip: remBtn.dataset.ip,
                        interface: remBtn.dataset.iface || null,
                        suppressed: false
                    })
                });
                await loadInterfacesTab();
                return;
            }
        });

        // Checkbox delegations
        root.addEventListener('change', (e) => {
            const target = /** @type {HTMLInputElement|null} */ (e.target);
            if (!target) return;

            // Select All
            if (target.id === 'ifSelectAll') {
                const filtered = _getFilteredRows();
                if (target.checked) {
                    filtered.forEach(r => _selectedIndices.add(r._idx));
                } else {
                    filtered.forEach(r => _selectedIndices.delete(r._idx));
                }
                _renderTable();
                return;
            }

            // Row Checkbox
            if (target.classList.contains('if-row-check')) {
                const idx = Number(target.dataset.idx);
                if (target.checked) {
                    _selectedIndices.add(idx);
                } else {
                    _selectedIndices.delete(idx);
                }
                _renderTable();
                return;
            }
        });
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _initIfEvents);
    } else {
        _initIfEvents();
    }

    window.loadInterfacesTab = loadInterfacesTab;
    window.saveSingleInterface = saveSingleInterface;
    window.saveBulkSelection = saveBulkSelection;
    window.clearBulkSelection = clearBulkSelection;
})();
