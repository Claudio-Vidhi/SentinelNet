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
    porte: () => loadPortErrorsPane(),
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

    // --- MAC ADDRESS TRACKER (storico MAC -> switch/porta/vlan) ---

    function loadRaccolta() {
        populateMacScanDevices();
        populateArpScanDevices();
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



    // Popola i selettori dispositivo (scan e ad-hoc) in base al tenant scelto:
    // così scegliendo un tenant si vedono SOLO i suoi switch, non tutti.
    // Lo scan usa una multi-selezione a checkbox (più device in un'unica scansione).
    function populateMacScanDevices() {
        const box = document.getElementById('macDeviceList');
        if (box) {
            const devs = macFilteredDevices();
            const head = `<label style="display:flex; align-items:center; gap:8px; padding:5px 6px; font-size:12px; cursor:pointer; border-bottom:1px solid var(--border); margin-bottom:4px;">
                <input type="checkbox" id="macDevAll" data-action="toggle-all-mac-devices" style="accent-color:var(--primary);">
                <strong>${tr('cmapAllDevices')}</strong></label>`;
            const items = devs.map(d => {
                const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
                return `<label style="display:flex; align-items:center; gap:8px; padding:4px 6px; font-size:12px; cursor:pointer;">
                    <input type="checkbox" class="mac-dev-cb" value="${escapeHtml(d.IP)}" data-action="update-mac-device-summary" style="accent-color:var(--primary);">
                    <span style="font-family:var(--font-code);">${escapeHtml(d.IP)}</span>
                    <span style="color:var(--text-muted);">${name}</span></label>`;
            }).join('');
            box.innerHTML = head + (items ||
                `<div style="font-size:12px; color:var(--text-muted); padding:6px;">${tr('uiNoDevices')}</div>`);
        }
        updateMacDeviceSummary();
        fillMacDeviceSelect(document.getElementById('macOvDevice'), false);
    }

    function selectedMacDevices() {
        return [...document.querySelectorAll('#macDeviceList .mac-dev-cb:checked')].map(cb => cb.value);
    }

    function toggleAllMacDevices(on) {
        document.querySelectorAll('#macDeviceList .mac-dev-cb').forEach(cb => cb.checked = on);
        updateMacDeviceSummary();
    }

    function updateMacDeviceSummary() {
        const total = document.querySelectorAll('#macDeviceList .mac-dev-cb').length;
        const sel = selectedMacDevices().length;
        const all = document.getElementById('macDevAll');
        if (all) all.checked = (total > 0 && sel === total);
        const sum = document.getElementById('macDeviceSummary');
        if (sum) sum.textContent = (sel === 0)
            ? (tr('cmapAllDevices'))
            : `${sel} ${tr('cmapSelected')}`;
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

    async function runMacScan() {
        const btn = document.getElementById('btnMacScan');
        const val = id => { const el = document.getElementById(id); return el ? el.value : ''; };
        const group = locTenant();
        const transport = val('macScanTransport') || '';
        const ips = selectedMacDevices();
        const payload = { group, transport };
        if (ips.length) payload.ips = ips;   // device specifici (multi-selezione)
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${tr('cmapScanning')}`;
        try {
            const res = await apiFetch('/api/mac/scan', {
                method: 'POST', headers: {'Content-Type':'application/json'},
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                const d = await res.json();
                const okc = d.results.filter(r => !r.error).length;
                const errc = d.results.filter(r => r.error).length;
                alert(tr('cmapMacScanDoneDevices', {scanned: d.scanned, okc: okc, errc: errc, pruned: d.pruned}));
                _locLoaded.endpoint = false;   // the list reloads the next time it is opened
                refreshMacStats(false);
            } else if (res) {
                const e = await res.json().catch(() => ({}));
                alert((tr('uiError')) + (e.detail || ''));
            }
        } finally {
            btn.disabled = false;
            btn.innerHTML = orig;
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

    // Dispositivi filtrati per il tenant selezionato.
    function arpFilteredDevices() {
        const group = locTenant();
        let devs = globalDevices || [];
        if (group && group !== 'all') devs = devs.filter(d => (d.Group || '') === group);
        return devs;
    }

    // Multi-selezione dei gateway da interrogare (stesso pattern del MAC Tracker).
    function populateArpScanDevices() {
        const box = document.getElementById('arpDeviceList');
        if (box) {
            const L = i18n[currentLang];
            const devs = arpFilteredDevices();
            const head = `<label style="display:flex; align-items:center; gap:8px; padding:5px 6px; font-size:12px; cursor:pointer; border-bottom:1px solid var(--border); margin-bottom:4px;">
                <input type="checkbox" id="arpDevAll" data-action="toggle-all-arp-devices" style="accent-color:var(--primary);">
                <strong>${L.optMacAllDevices || 'Tutti i dispositivi'}</strong></label>`;
            const items = devs.map(d => {
                const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
                return `<label style="display:flex; align-items:center; gap:8px; padding:4px 6px; font-size:12px; cursor:pointer;">
                    <input type="checkbox" class="arp-dev-cb" value="${escapeHtml(d.IP)}" data-action="update-arp-device-summary" style="accent-color:var(--primary);">
                    <span style="font-family:var(--font-code);">${escapeHtml(d.IP)}</span>
                    <span style="color:var(--text-muted);">${name}</span></label>`;
            }).join('');
            box.innerHTML = head + (items ||
                `<div style="font-size:12px; color:var(--text-muted); padding:6px;">${L.msgAiNoDevices || 'Nessun dispositivo'}</div>`);
        }
        updateArpDeviceSummary();
    }

    function selectedArpDevices() {
        return [...document.querySelectorAll('#arpDeviceList .arp-dev-cb:checked')].map(cb => cb.value);
    }

    function toggleAllArpDevices(on) {
        document.querySelectorAll('#arpDeviceList .arp-dev-cb').forEach(cb => cb.checked = on);
        updateArpDeviceSummary();
    }

    function updateArpDeviceSummary() {
        const total = document.querySelectorAll('#arpDeviceList .arp-dev-cb').length;
        const sel = selectedArpDevices().length;
        const all = document.getElementById('arpDevAll');
        if (all) all.checked = (total > 0 && sel === total);
        const sum = document.getElementById('arpDeviceSummary');
        if (sum) sum.textContent = (sel === 0)
            ? (tr('optMacAllDevices') || 'Tutti i dispositivi')
            : `${sel} ${tr('lblAiDevSelected') || 'selezionati'}`;
    }

    async function runArpScan() {
        const btn = document.getElementById('btnArpScan');
        btn.disabled = true;
        const oldHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...';
        try {
            const payload = { group: locTenant() };
            const ips = selectedArpDevices();
            if (ips.length) payload.ips = ips;
            const res = await apiFetch('/api/arp/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!res) return;
            const box = document.getElementById('arpScanSummary');
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                box.style.display = 'block';
                box.innerHTML = `<span style="color:var(--danger);">${escapeHtml(err.detail || (tr('cmapArpScanError')))}</span>`;
                return;
            }
            const d = await res.json();
            const rows = Object.entries(d.devices || {}).map(([ip, r]) => {
                const color = r.status === 'success' ? 'var(--success, #7bd88f)'
                            : r.status === 'empty' ? 'var(--text-muted)' : 'var(--danger)';
                const detail = r.status === 'success'
                    ? (tr('cmapEntriesNewUpdated', {entries: r.entries, new: r.new, updated: r.updated}))
                    : escapeHtml(r.message || r.status);
                return `<div>• <b>${escapeHtml(ip)}</b> — <span style="color:${color};">${r.status}</span>: ${detail}</div>`;
            }).join('');
            box.style.display = 'block';
            box.innerHTML = `<b>${tr('titleArpScanSummary') || 'Esito raccolta ARP'}</b>` +
                `<div style="margin-top:6px;">${rows || '—'}</div>`;
        } finally {
            btn.disabled = false;
            btn.innerHTML = oldHtml;
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

    document.getElementById('macDeviceList')?.addEventListener('change', (e) => {
        const allCb = e.target.closest('input[data-action="toggle-all-mac-devices"]');
        if (allCb) {
            toggleAllMacDevices(allCb.checked);
            return;
        }
        const devCb = e.target.closest('input[data-action="update-mac-device-summary"]');
        if (devCb) {
            updateMacDeviceSummary();
        }
    });

    document.getElementById('arpDeviceList')?.addEventListener('change', (e) => {
        const allCb = e.target.closest('input[data-action="toggle-all-arp-devices"]');
        if (allCb) {
            toggleAllArpDevices(allCb.checked);
            return;
        }
        const devCb = e.target.closest('input[data-action="update-arp-device-summary"]');
        if (devCb) {
            updateArpDeviceSummary();
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
    document.getElementById('btnMacScan')?.addEventListener('click', runMacScan);
    document.getElementById('btnSaveMacRetention')?.addEventListener('click', saveMacRetention);
    document.getElementById('btnSaveMacOverride')?.addEventListener('click', saveMacOverride);
    document.getElementById('btnArpScan')?.addEventListener('click', runArpScan);
