// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// static/js/client-map.js
// Estratto da templates/dashboard.html: tab-mac (MAC Address Tracker) e
// tab-clientmap (Client Map MAC <-> IP dalle ARP dei gateway L3). Le due
// sezioni erano contigue nell'inline script originale e condividono lo
// stesso pattern (multi-selezione device via checkbox, filtro tenant,
// tabelle raggruppate). showPortConfig/closePortConfigModal (usati dai
// bottoni di riga) vivono in core.js: chiamata cross-modulo a runtime,
// nessun cambio di comportamento.

// The endpoint group is one tab with four views. Each view loads on its first
// activation, not when the tab opens.
let _locView = 'endpoint';
const _locLoaded = { endpoint: false, porte: false, diagnosi: false, raccolta: false };

const LOC_LOADERS = {
    endpoint: () => loadEndpointsTab(),
    porte: () => loadPortsView(),
    diagnosi: () => diagnosiTabShown(),
    raccolta: () => loadRaccolta(),
};

// One tenant for the whole group, ed e' quello scelto in alto: queste tre viste
// non hanno piu' un filtro proprio. Due controlli per lo stesso concetto sono
// due posti dove leggere lo scope e uno dove sbagliarlo.
function locTenant() {
    return window.globalSelectedTenant || 'all';
}

function locSwitchView(view) {
    if (!document.getElementById('locPane-' + view)) return;
    if (_collectLocs === null) resetDevPickers();
    _locView = view;
    for (const v of Object.keys(LOC_LOADERS)) {
        const pane = document.getElementById('locPane-' + v);
        const tab = document.getElementById('locTab-' + v);
        if (pane) pane.hidden = v !== view;
        if (tab) {
            tab.setAttribute('aria-selected', v === view ? 'true' : 'false');
            tab.tabIndex = v === view ? 0 : -1;
        }
    }
    if (!_locLoaded[view]) {
        _locLoaded[view] = true;
        LOC_LOADERS[view]();
    }
}

// Tenant change redraws only the pane on screen; the others redraw when opened.
function locTenantChanged() {
    closeEpDrawer();
    resetDevPickers();
    for (const v of Object.keys(_locLoaded)) _locLoaded[v] = (v === _locView);
    LOC_LOADERS[_locView]();
}

// Devices grouped by site (the inventory's Location) for the scan pickers.
// Devices without a site get their own group, last: dropping them would hide
// them from every scan.
function pickerGroups(devs, sel, labelOf) {
    const byKey = new Map();
    for (const d of devs) {
        const key = d.Location || '';
        if (!byKey.has(key)) byKey.set(key, { key, label: labelOf(key), devices: [], n: 0, total: 0 });
        const g = byKey.get(key);
        const checked = sel.has(d.IP);
        g.devices.push({ ip: d.IP, name: d.Hostname || d.IP, checked });
        g.total += 1;
        if (checked) g.n += 1;
    }
    return [...byKey.values()].sort((a, b) =>
        Number(a.key === '') - Number(b.key === '') || a.label.localeCompare(b.label));
}

// What the closed picker says. "none" is its own state: the old picker read an
// empty selection as "every device", which is exactly what must not happen.
function pickerSummary(groups) {
    const n = groups.reduce((s, g) => s + g.n, 0);
    const total = groups.reduce((s, g) => s + g.total, 0);
    const touched = groups.filter(g => g.n);
    const locations = touched.map(g => g.label);
    if (!n) return { kind: 'none', n, total, locations };
    if (n === total) return { kind: 'all', n, total, locations };
    if (touched.every(g => g.n === g.total)) return { kind: 'locations', n, total, locations };
    return { kind: 'partial', n, total, locations };
}

// ===== Location-grouped device pickers (Raccolta) =====
const _pickSel = { mac: new Set(), arp: new Set() };
const _pickFilter = { mac: '', arp: '' };

function _pickLocLabel(loc) {
    return loc ? locationLabel(loc) : tr('locNoLocation');
}

// First load or tenant change: everything selected, the old default.
function resetDevPickers() {
    const ips = macFilteredDevices().map(d => d.IP);
    _pickSel.mac = new Set(ips);
    _pickSel.arp = new Set(ips);
    _collectLocs = null;
    renderDevPicker('mac');
    renderDevPicker('arp');
    renderCollectLocs();
}

function pickerSelectedIps(kind) {
    return [..._pickSel[kind]];
}

function renderDevPicker(kind) {
    const host = document.getElementById(kind + 'Picker');
    if (!host) return;
    const wasOpen = !!host.querySelector('details')?.open;
    const groups = pickerGroups(macFilteredDevices(), _pickSel[kind], _pickLocLabel);
    const sm = pickerSummary(groups);
    const summary = sm.kind === 'none' ? tr('pickSumNone')
        : sm.kind === 'all' ? tr('pickSumAll', { n: String(sm.n), s: String(groups.length) })
        : sm.kind === 'locations' ? tr('pickSumLocs', { locs: sm.locations.join(', '), n: String(sm.n) })
        : tr('pickSumPartial', { n: String(sm.n), total: String(sm.total), s: String(sm.locations.length) });
    const f = _pickFilter[kind].toLowerCase();
    const list = groups.map(g => {
        const shown = g.devices.filter(d => !f || (d.name + ' ' + d.ip + ' ' + g.label).toLowerCase().includes(f));
        if (!shown.length) return '';
        return `<label class="pk-loc"><input type="checkbox" data-pick-loc="${escapeHtml(g.key)}" ${g.n === g.total ? 'checked' : ''}
                    ${g.n && g.n < g.total ? 'data-mixed="1"' : ''}> ${escapeHtml(g.label)} <small>${g.n}/${g.total}</small></label>` +
            shown.map(d => `<label class="pk-dev"><input type="checkbox" data-pick-ip="${escapeHtml(d.ip)}" ${d.checked ? 'checked' : ''}>
                    ${escapeHtml(d.name)} <span>${escapeHtml(d.ip)}</span></label>`).join('');
    }).join('') || `<div class="pk-empty">${escapeHtml(tr('uiNoDevices'))}</div>`;
    const chips = groups.map(g => `<button type="button" class="pk-chip" data-pick-only="${escapeHtml(g.key)}"
            aria-label="${escapeHtml(tr('pickOnlyLoc', { loc: g.label }))}">${escapeHtml(g.label)}</button>`).join('');
    host.innerHTML = `<details class="pk" ${wasOpen ? 'open' : ''}>
        <summary aria-label="${escapeHtml(tr(kind === 'mac' ? 'ariaMacPicker' : 'ariaArpPicker'))}"><span>${escapeHtml(summary)}</span><i class="fa-solid fa-chevron-down" aria-hidden="true"></i></summary>
        <div class="pk-panel">
          <div class="pk-chips">${chips}</div>
          <div class="pk-search"><input type="search" data-pick-filter="1" value="${escapeHtml(_pickFilter[kind])}"
              placeholder="${escapeHtml(tr('pickFilterPh'))}" aria-label="${escapeHtml(tr('pickFilterPh'))}"></div>
          <div class="pk-list">${list}</div>
          <div class="pk-foot"><span>${escapeHtml(tr('pickSelectedN', { n: String(sm.n) }))}</span>
            <span><button type="button" data-pick-all="1">${escapeHtml(tr('pickAll'))}</button>
                  <button type="button" data-pick-none="1">${escapeHtml(tr('pickNone'))}</button></span></div>
        </div></details>`;
    host.querySelectorAll('[data-mixed]').forEach(cb => { /** @type {HTMLInputElement} */ (cb).indeterminate = true; });
}

for (const kind of ['mac', 'arp']) {
    const host = document.getElementById(kind + 'Picker');
    host?.addEventListener('change', (e) => {
        const t = /** @type {HTMLInputElement} */ (e.target);
        if (t.dataset.pickFilter) return;
        const set = _pickSel[kind];
        if (t.dataset.pickIp) { if (t.checked) set.add(t.dataset.pickIp); else set.delete(t.dataset.pickIp); }
        if (t.dataset.pickLoc !== undefined) {
            macFilteredDevices().filter(d => (d.Location || '') === t.dataset.pickLoc)
                .forEach(d => { if (t.checked) set.add(d.IP); else set.delete(d.IP); });
        }
        renderDevPicker(kind);
    });
    host?.addEventListener('input', (e) => {
        const t = /** @type {HTMLInputElement} */ (e.target);
        if (!t.dataset.pickFilter) return;
        _pickFilter[kind] = t.value;
        const pos = t.selectionStart;
        renderDevPicker(kind);
        const again = /** @type {HTMLInputElement|null} */ (host.querySelector('[data-pick-filter]'));
        again?.focus();
        if (again && pos !== null) again.setSelectionRange(pos, pos);
    });
    host?.addEventListener('click', (e) => {
        const t = /** @type {HTMLElement} */ (e.target);
        const devs = macFilteredDevices();
        if (t.closest('[data-pick-all]')) _pickSel[kind] = new Set(devs.map(d => d.IP));
        else if (t.closest('[data-pick-none]')) _pickSel[kind] = new Set();
        else {
            const only = /** @type {HTMLElement|null} */ (t.closest('[data-pick-only]'));
            if (!only) return;
            _pickSel[kind] = new Set(devs.filter(d => (d.Location || '') === only.dataset.pickOnly).map(d => d.IP));
        }
        renderDevPicker(kind);
    });
}

// An open picker or the collect popover closes on an outside click.
document.addEventListener('click', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    document.querySelectorAll('#tab-endpoint details.pk[open], #locCollectPop[open]').forEach(d => {
        if (!d.contains(t)) /** @type {HTMLDetailsElement} */ (d).open = false;
    });
});

// ===== "Raccogli ora": MAC scan then ARP on the chosen locations =====
/** @type {Set<string>|null} */
let _collectLocs = null;      // Location ids ('' = no location); null = not built yet (all)

function renderCollectLocs() {
    const box = document.getElementById('locCollectLocs');
    if (!box) return;
    const devs = macFilteredDevices();
    const groups = pickerGroups(devs, new Set(), _pickLocLabel);
    if (_collectLocs === null) _collectLocs = new Set(groups.map(g => g.key));
    const locs = _collectLocs;
    box.innerHTML = groups.map(g => `<label class="pk-dev pk-dev-loc"><input type="checkbox" data-collect-loc="${escapeHtml(g.key)}"
        ${locs.has(g.key) ? 'checked' : ''}> ${escapeHtml(g.label)} <span>${g.total}</span></label>`).join('')
        || `<div class="pk-empty">${escapeHtml(tr('uiNoDevices'))}</div>`;
    const n = devs.filter(d => locs.has(d.Location || '')).length;
    const sum = document.getElementById('locCollectSum');
    if (sum) sum.textContent = tr('locCollectSum', { n: String(n), s: String(locs.size) });
    const go = /** @type {HTMLButtonElement|null} */ (document.getElementById('locCollectGo'));
    if (go) go.disabled = !n;
}

document.getElementById('locCollectLocs')?.addEventListener('change', (e) => {
    const t = /** @type {HTMLInputElement} */ (e.target);
    if (t.dataset.collectLoc === undefined || !_collectLocs) return;
    if (t.checked) _collectLocs.add(t.dataset.collectLoc); else _collectLocs.delete(t.dataset.collectLoc);
    renderCollectLocs();
});

async function runCollect() {
    const locs = _collectLocs || new Set();
    const ips = macFilteredDevices().filter(d => locs.has(d.Location || '')).map(d => d.IP);
    const pop = /** @type {HTMLDetailsElement|null} */ (document.getElementById('locCollectPop'));
    if (pop) pop.open = false;
    const go = /** @type {HTMLButtonElement|null} */ (document.getElementById('locCollectGo'));
    await runMacScan(ips, go);
    await runArpScan(ips, go);
}
document.getElementById('locCollectGo')?.addEventListener('click', runCollect);

    // --- MAC ADDRESS TRACKER (storico MAC -> switch/porta/vlan) ---

    function loadRaccolta() {
        fillMacDeviceSelect(document.getElementById('macOvDevice'), false);
        loadMacOverrides();
        refreshMacStats(true);
    }

    // Comandi ad-hoc per apparati non ordinari (override CLI per singolo switch).
    async function loadMacOverrides() {
        fillMacDeviceSelect(document.getElementById('macOvDevice'), false);
        try {
            const r = await apiFetch('/api/mac/overrides');
            if (r && r.ok) renderMacOverrides((await r.json()).overrides || []);
        } catch (e) {}
    }

    function renderMacOverrides(list) {
        const box = document.getElementById('macOverridesList');
        if (!box) return;
        if (!list.length) {
            box.innerHTML = `<div style="font-size:12px; color:var(--text-muted);">${tr('cmapNoAdHocCommands')}</div>`;
            return;
        }
        box.innerHTML = list.map(o => `<div style="display:flex; align-items:center; gap:10px; padding:6px 0; border-bottom:1px solid var(--border); font-size:12px;">
            <span style="font-family:var(--font-code); color:var(--primary); min-width:120px;">${escapeHtml(o.switch_ip)}</span>
            <span style="font-family:var(--font-code); flex:1;">${escapeHtml(o.command)}</span>
            <span class="badge" style="font-size:10px;">${escapeHtml(o.fmt)}</span>
            <button data-action="remove-mac-override" data-switch-ip="${escapeHtml(o.switch_ip)}" title="${tr('cmapRemove')}" style="border:none; background:none; color:var(--danger); cursor:pointer;"><i class="fa-solid fa-trash-can"></i></button>
        </div>`).join('');
    }

    async function saveMacOverride() {
        const val = id => { const el = document.getElementById(id); return el ? el.value : ''; };
        const ip = val('macOvDevice');
        const command = (val('macOvCommand') || '').trim();
        const fmt = val('macOvFmt') || 'generic';
        if (!ip || !command) { alert(tr('cmapSelectADeviceAnd')); return; }
        const res = await apiFetch('/api/mac/overrides', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ ip, command, fmt })
        });
        if (res && res.ok) {
            const c = document.getElementById('macOvCommand'); if (c) c.value = '';
            loadMacOverrides();
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            alert((tr('uiError')) + (e.detail || ''));
        }
    }

    async function removeMacOverride(ip) {
        const res = await apiFetch('/api/mac/overrides/delete', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ ip })
        });
        if (res && res.ok) loadMacOverrides();
    }

    // Dispositivi filtrati per il tenant selezionato (globalDevices è già scoped
    // per utente lato server; qui si applica solo il filtro del tenant scelto).
    function macFilteredDevices() {
        const group = locTenant();
        let devs = globalDevices || [];
        if (group && group !== 'all') devs = devs.filter(d => d.Group === group);
        return devs;
    }

    function fillMacDeviceSelect(sel, includeAll) {
        if (!sel) return;
        const cur = sel.value;
        const opts = macFilteredDevices().map(d => {
            const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
            return `<option value="${escapeHtml(d.IP)}">${escapeHtml(d.IP)}${name}</option>`;
        }).join('');
        const allLabel = (i18n[currentLang] && tr('optMacAllDevices')) || 'All devices';
        sel.innerHTML = (includeAll ? `<option value="all">${allLabel}</option>` : '') + opts;
        if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
    }







    async function refreshMacStats(fillRetention) {
        try {
            const grp = locTenant();
            const qs = (grp && grp !== 'all') ? ('?tenant=' + encodeURIComponent(grp)) : '';
            const r = await apiFetch('/api/mac/stats' + qs);
            if (!r || !r.ok) return;
            const s = await r.json();
            // KPI del cartiglio: stessa risposta, nessuna chiamata aggiuntiva.
            const kSight = document.getElementById('kpiMacSightings'); if (kSight) kSight.textContent = s.sightings;
            const kUniq = document.getElementById('kpiMacUniqueMacs'); if (kUniq) kUniq.textContent = s.unique_macs;
            const kSw = document.getElementById('kpiMacSwitches'); if (kSw) kSw.textContent = s.switches;
            const kRet = document.getElementById('kpiMacRetention'); if (kRet) kRet.textContent = s.retention_days;
            const rin = document.getElementById('macRetentionDays');
            if (rin && (fillRetention || !rin.value)) rin.value = s.retention_days;
        } catch (e) {}
    }

    async function runMacScan(ips, btn) {
        const result = document.getElementById('macScanResult');
        if (!ips.length) {
            if (result) { result.hidden = false; result.textContent = tr('pickEmptyRun'); }
            return;
        }
        const transport = /** @type {HTMLSelectElement|null} */ (document.getElementById('macScanTransport'))?.value || '';
        const payload = { group: locTenant(), transport };
        payload.ips = ips;
        const orig = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${tr('cmapScanning')}`; }
        try {
            const res = await apiFetch('/api/mac/scan', {
                method: 'POST', headers: {'Content-Type':'application/json'},
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                const d = await res.json();
                const okc = d.results.filter(r => !r.error).length;
                const errc = d.results.filter(r => r.error).length;
                if (result) {
                    result.hidden = false;
                    result.textContent = tr('cmapMacScanDoneDevices', {scanned: d.scanned, okc: okc, errc: errc, pruned: d.pruned});
                }
                _locLoaded.endpoint = false;   // the list reloads the next time it is opened
                refreshMacStats(false);
            } else if (res) {
                const e = await res.json().catch(() => ({}));
                showToast((tr('uiError')) + (e.detail || ''), 'error');
            }
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = orig; }
        }
    }



    function fmtMacTime(iso) {
        if (!iso) return '—';
        try { return new Date(iso).toLocaleString(tr('cmapEnUs')); }
        catch (e) { return iso; }
    }

    // --- RACCOLTA ARP: MAC <-> IP dalle ARP dei gateway L3 ---
    // The Client Map tab that searched and rendered these bindings is gone;
    // Endpoint Inventory covers the lookup. What stays is the collection panel
    // in the MAC Tracker view, which fills the arp_entries history that
    // Endpoint Inventory and client diagnosis read. loadRaccolta() populates
    // the device picker.






    async function runArpScan(ips, btn) {
        const box = document.getElementById('arpScanSummary');
        if (!ips.length) {
            if (box) { box.hidden = false; box.textContent = tr('pickEmptyRun'); }
            return;
        }
        const oldHtml = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...'; }
        try {
            const payload = { group: locTenant() };
            payload.ips = ips;
            const res = await apiFetch('/api/arp/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!res) return;
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                box.hidden = false;
                box.innerHTML = `<span style="color:var(--danger);">${escapeHtml(err.detail || (tr('cmapArpScanError')))}</span>`;
                return;
            }
            const d = await res.json();
            const locOf = ip => _pickLocLabel((macFilteredDevices().find(x => x.IP === ip) || {}).Location || '');
            const rows = Object.entries(d.devices || {}).map(([ip, r]) => {
                const color = r.status === 'success' ? 'var(--success, #7bd88f)'
                            : r.status === 'empty' ? 'var(--text-muted)' : 'var(--danger)';
                const detail = r.status === 'success'
                    ? (tr('cmapEntriesNewUpdated', {entries: r.entries, new: r.new, updated: r.updated}))
                    : escapeHtml(r.message || r.status);
                return `<div>• <b>${escapeHtml(locOf(ip))} · ${escapeHtml(ip)}</b> — <span style="color:${color};">${r.status}</span>: ${detail}</div>`;
            }).join('');
            box.hidden = false;
            box.innerHTML = `<b>${tr('titleArpScanSummary') || 'Esito raccolta ARP'}</b>` +
                `<div style="margin-top:6px;">${rows || '—'}</div>`;
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = oldHtml; }
        }
    }


    // MOVED to static/js/core.js (showPortConfig / closePortConfigModal / openPortInAnalyzer / expandIface / caFocusIp / caFocusPort)

    // --- DIAGNOSI CLIENT (L2 + L3 in un referto solo) ---
    // Il bottone sta sulla riga della Client Map e non in una scheda nuova:
    // quella riga ha già tutto ciò che serve all'endpoint (MAC e IP), e chi
    // sta guardando un client è già qui.
    //
    // Regola di rendering, ereditata dal referto: una sezione che non sa DICE
    // perché. Non viene mai nascosta — un buco taciuto manda l'ingegnere a
    // cercare nel posto sbagliato.

    // La diagnosi client vive in static/js/diagnosi.js e nella sua tab: qui
    // resta solo il pulsante di riga, che ci porta. Un referto reso in due
    // posti sarebbero due copie da tenere allineate.

    async function saveMacRetention() {
        const days = parseInt(document.getElementById('macRetentionDays') ? document.getElementById('macRetentionDays').value : '', 10);
        if (!days || days < 1) { alert(tr('cmapEnterAValidNumber')); return; }
        const res = await apiFetch('/api/mac/settings', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ days })
        });
        if (res && res.ok) {
            const d = await res.json();
            alert((tr('cmapRetentionSetTo')) + d.retention_days + (tr('cmapDays')));
            refreshMacStats(false);
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            alert((tr('uiError')) + (e.detail || ''));
        }
    }

    // Delegated event listeners for dynamic containers in client-map.js
    document.getElementById('macOverridesList')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="remove-mac-override"]');
        if (btn && btn.dataset.switchIp) {
            removeMacOverride(btn.dataset.switchIp);
        }
    });



    // Static event listeners for MAC Tracker & Client Map tabs
    document.getElementById('locTabs')?.addEventListener('click', (e) => {
        const tab = e.target.closest('[data-loc-view]');
        if (tab) locSwitchView(tab.dataset.locView);
    });
    // Arrow keys move between the tabs, as in every WAI-ARIA tablist.
    document.getElementById('locTabs')?.addEventListener('keydown', (e) => {
        if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
        const tabs = [...document.querySelectorAll('#locTabs [role="tab"]')];
        const i = tabs.indexOf(document.activeElement);
        if (i < 0) return;
        const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
        next.focus();
        locSwitchView(next.dataset.locView);
    });
    document.getElementById('btnMacScan')?.addEventListener('click', (e) =>
        runMacScan(pickerSelectedIps('mac'), /** @type {HTMLButtonElement} */ (e.currentTarget)));
    document.getElementById('btnSaveMacRetention')?.addEventListener('click', saveMacRetention);
    document.getElementById('btnSaveMacOverride')?.addEventListener('click', saveMacOverride);
    document.getElementById('btnArpScan')?.addEventListener('click', (e) =>
        runArpScan(pickerSelectedIps('arp'), /** @type {HTMLButtonElement} */ (e.currentTarget)));
