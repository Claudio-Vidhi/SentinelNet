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
    let _tenantFilter = 'all';
    let _deviceFilter = 'all';
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


    const _fillSelect = (el, values, current, labelOf) => {
        if (!el) return;
        const all = el.options[0];
        el.textContent = '';
        el.appendChild(all);
        values.forEach(v => {
            const opt = document.createElement('option');
            opt.value = v;
            opt.textContent = labelOf ? labelOf(v) : v;
            el.appendChild(opt);
        });
        // Una scelta che non esiste piu' nei dati torna ad "all", altrimenti
        // la tabella resta vuota senza che il controllo lo mostri.
        el.value = values.includes(current) ? current : 'all';
        return el.value;
    };

    const _populateScope = () => {
        const tenants = [...new Set(_ifaces.map(r => r.tenant || '').filter(Boolean))].sort();
        const devices = [...new Set(_ifaces.map(r => r.device_ip || '').filter(Boolean))].sort();
        const names = {};
        _ifaces.forEach(r => { if (r.device_ip && r.hostname) names[r.device_ip] = r.hostname; });

        _tenantFilter = _fillSelect(
            /** @type {HTMLSelectElement|null} */ (document.getElementById('ifTenantFilter')),
            tenants, _tenantFilter) || 'all';
        _deviceFilter = _fillSelect(
            /** @type {HTMLSelectElement|null} */ (document.getElementById('ifDeviceFilter')),
            devices, _deviceFilter,
            (ip) => (names[ip] ? `${names[ip]} · ${ip}` : ip)) || 'all';
    };

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
            if (_tenantFilter !== 'all' && (r.tenant || '') !== _tenantFilter) {
                return false;
            }
            if (_deviceFilter !== 'all' && (r.device_ip || '') !== _deviceFilter) {
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
        const matchEl = document.getElementById('ifMatchCount');
        if (matchEl) {
            matchEl.textContent = rows.length === _ifaces.length
                ? _ifL('ifMatchAll').replace('{n}', String(_ifaces.length))
                : _ifL('ifMatchSome').replace('{n}', String(rows.length))
                                     .replace('{total}', String(_ifaces.length));
        }
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

        let html = `<div class="if-scroll"><table class="if-table">
            <thead>
                <tr>
                    <th class="if-col-check">
                        <input type="checkbox" id="ifSelectAll" aria-label="Seleziona tutte" data-i18n-aria-label="ifSelectAllAria" ${allSelected ? 'checked' : ''}>
                    </th>
                    <th>${_ifL('ifThDevice')}</th>
                    <th>${_ifL('ifThInterface')}</th>
                    <th>${_ifL('ifThStatus')}</th>
                    <th class="if-col-num">${_ifL('ifThFlaps')}</th>
                    <th>${_ifL('ifThExpected')}</th>
                    <th>${_ifL('ifThUntil')}</th>
                    <th>${_ifL('ifThReason')}</th>
                    <th class="if-col-act">${_ifL('ifThActions')}</th>
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
                const raw = String(r.link || '').trim();
                badge = `<span class="badge if-badge-unknown">${_ifEsc(raw ? raw.toUpperCase() : 'N/D')}</span>`;
            }

            const adminBadge = r.admin_status
                ? `<span class="if-admin">admin: ${_ifEsc(r.admin_status)}</span>`
                : '';

            const flapClass = r.transitions >= _minTransitions ? 'if-flaps-hot' : '';
            // Editable when the row is being worked on: already declared, or
            // picked for a bulk action.
            const editing = r.suppressed || isChecked;

            html += `<tr class="${isChecked ? 'is-selected' : ''}">
                <td class="if-col-check">
                    <input type="checkbox" class="if-row-check" data-idx="${r._idx}" aria-label="Seleziona interfaccia" data-i18n-aria-label="ifSelectRowAria" ${isChecked ? 'checked' : ''}>
                </td>
                <td>
                    ${r.hostname ? `<div class="if-host">${_ifEsc(r.hostname)}</div>` : ''}
                    <div class="if-addr${r.hostname ? '' : ' if-addr-lead'}">${_ifEsc(r.device_ip)}</div>
                </td>
                <td><span class="if-port">${_ifEsc(r.interface)}</span></td>
                <td>
                    <div style="display:flex; flex-direction:column; gap:2px;">
                        <div>${badge}</div>
                        ${adminBadge}
                    </div>
                </td>
                <td class="if-col-num ${flapClass}">${r.transitions || 0}</td>
                <td>
                    <label class="if-declare">
                        <input type="checkbox" id="ifx-chk-${r._idx}" ${r.suppressed ? 'checked' : ''}>
                        <span>${_ifL('ifOptSuppressed')}</span>
                    </label>
                </td>
                <td>${editing
                    ? `<input type="datetime-local" class="if-input" id="ifx-until-${r._idx}" value="${_ifEsc(_toLocalIso(r.to_ts))}" aria-label="Fino a data" data-i18n-aria-label="ifUntilAria">`
                    : `<span class="if-quiet">${r.to_ts ? _ifEsc(_toLocalIso(r.to_ts).replace('T', ' ')) : '—'}</span>`}</td>
                <td>${editing
                    ? `<input type="text" class="if-input if-input-wide" id="ifx-note-${r._idx}" value="${_ifEsc(r.note || '')}" placeholder="${_ifL('incReasonPl')}" aria-label="Nota interfaccia" data-i18n-aria-label="ifNoteAria">`
                    : `<span class="if-quiet">${r.note ? _ifEsc(r.note) : '—'}</span>`}</td>
                <td class="if-col-act">${editing
                    ? `<button class="btn btn-primary btn-sm if-save" data-action="save-single-if" data-idx="${r._idx}" title="${_ifL('ifBtnSaveTooltip')}"><i class="fa-solid fa-floppy-disk"></i></button>`
                    : ''}</td>
            </tr>`;
        });

        html += `</tbody></table></div>`;
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

            _populateScope();
            _renderCards(data.counts);
            _renderTable();

            const stamp = document.getElementById('ifUpdatedAt');
            if (stamp) {
                // Una vista che non si aggiorna da sola deve almeno dire di
                // quando e' il dato che mostra.
                stamp.textContent = _ifL('ifUpdatedAt').replace(
                    '{t}', new Date().toLocaleTimeString());
            }
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

        const bindScope = (id, apply) => {
            const el = /** @type {HTMLSelectElement|null} */ (document.getElementById(id));
            el?.addEventListener('change', () => { apply(el.value); _renderTable(); });
        };
        bindScope('ifTenantFilter', (v) => { _tenantFilter = v; });
        bindScope('ifDeviceFilter', (v) => { _deviceFilter = v; });

        // Status Filter Chips
        document.querySelectorAll('[data-if-filter]').forEach(el => {
            el.addEventListener('click', (e) => {
                const tgt = /** @type {HTMLElement|null} */ (e.target);
                const btn = /** @type {HTMLElement|null} */ (tgt?.closest('[data-if-filter]'));
                if (!btn) return;
                document.querySelectorAll('[data-if-filter]').forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-pressed', 'false');
                });
                btn.classList.add('active');
                btn.setAttribute('aria-pressed', 'true');
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
