// static/js/config-drift.js
// ===== Config Drift: per-tenant version history and baseline rules =====
// Not an audit: no score, no grade, no severity. The netsec audit already
// owns that question; this tab only shows what changed and what deviates
// from the tenant's own baseline text.

(function () {
    let driftDevices = [];
    let driftTenant = '';
    let driftSelectedIp = '';
    let driftVersions = [];
    let driftSubtab = 'history';

    async function loadConfigDriftTab() {
        const tenantSel = document.getElementById('driftTenantSelect');
        const tbody = document.getElementById('driftDeviceList');
        if (!tenantSel) return;
        try {
            const res = await apiFetch('/api/drift/devices');
            if (!res || !res.ok) {
                if (tbody) tbody.innerHTML = `<tr><td colspan="3"><div class="alert-box alert-danger">${escapeHtml(i18n[currentLang].driftLoadError)}</div></td></tr>`;
                return;
            }
            const data = await res.json();
            driftDevices = data.devices || [];

            const tenants = [...new Set(driftDevices.map(d => d.tenant))].sort();
            const cur = tenantSel.value;
            const L = i18n[currentLang];
            tenantSel.innerHTML = `<option value="">${escapeHtml(L.driftChooseTenant)}</option>` +
                tenants.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
            tenantSel.value = tenants.includes(cur) ? cur : '';
            onDriftTenantChanged();
        } catch (e) {
            console.error('Config Drift: failed to load devices', e);
            if (tbody) tbody.innerHTML = `<tr><td colspan="3"><div class="alert-box alert-danger">${escapeHtml(i18n[currentLang].driftLoadError)}</div></td></tr>`;
        }
    }

    function onDriftTenantChanged() {
        const tenantSel = document.getElementById('driftTenantSelect');
        driftTenant = tenantSel ? tenantSel.value : '';
        driftSelectedIp = '';
        renderDriftDeviceList();
        clearDriftVersions();
        if (driftSubtab === 'baseline') loadDriftBaselineTab();
    }

    function driftTenantDevices() {
        return driftTenant ? driftDevices.filter(d => d.tenant === driftTenant) : [];
    }

    function renderDriftDeviceList() {
        const tbody = document.getElementById('driftDeviceList');
        if (!tbody) return;
        const devs = driftTenantDevices();
        const L = i18n[currentLang];
        if (devs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="3" style="text-align:center; color:var(--text-muted);">${escapeHtml(L.driftNoDevices)}</td></tr>`;
            return;
        }
        tbody.innerHTML = devs.map(d => `
            <tr data-action="drift-select-device" data-ip="${escapeHtml(d.ip)}" style="cursor:pointer;" class="${d.ip === driftSelectedIp ? 'active' : ''}">
                <td style="font-weight:700;">${escapeHtml(d.hostname || d.ip)} <span style="color:var(--text-muted); font-weight:400;">(${escapeHtml(d.ip)})</span></td>
                <td>${escapeHtml(d.last_change || '-')}</td>
                <td>${escapeHtml(d.last_seen || '-')}</td>
            </tr>
        `).join('');
    }

    function clearDriftVersions() {
        driftVersions = [];
        const container = document.getElementById('driftVersionsContainer');
        const L = i18n[currentLang];
        if (container) container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">${escapeHtml(L.driftNoVersions)}</div>`;
        ['driftFromVersionSelect', 'driftToVersionSelect'].forEach(id => {
            const sel = document.getElementById(id);
            if (sel) { sel.innerHTML = ''; sel.disabled = true; }
        });
        const btn = document.getElementById('btnDriftShowDiff');
        if (btn) btn.disabled = true;
        const diff = document.getElementById('driftDiffContainer');
        if (diff) diff.textContent = '';
    }

    async function onDriftDeviceSelected(ip) {
        driftSelectedIp = ip;
        renderDriftDeviceList();
        await loadDriftVersions(ip);
        if (driftSubtab === 'baseline') loadDriftDeviations(ip);
    }

    async function loadDriftVersions(ip) {
        const container = document.getElementById('driftVersionsContainer');
        const L = i18n[currentLang];
        try {
            const res = await apiFetch(`/api/drift/${encodeURIComponent(ip)}/versions`);
            if (!res || !res.ok) { clearDriftVersions(); return; }
            const data = await res.json();
            driftVersions = data.versions || [];
            if (driftVersions.length === 0) {
                clearDriftVersions();
                return;
            }
            if (container) {
                container.innerHTML = `
                    <div class="table-wrap">
                        <table>
                            <tbody>
                                ${driftVersions.map(v => `
                                    <tr>
                                        <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml(v.seen_at)}</td>
                                        <td>${escapeHtml(String(v.size))} B</td>
                                        <td style="color:var(--text-muted); font-size:11px;">${escapeHtml(v.hash || '')}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            const opts = driftVersions.map(v => `<option value="${escapeHtml(v.seen_at)}">${escapeHtml(v.seen_at)}</option>`).join('');
            const fromSel = document.getElementById('driftFromVersionSelect');
            const toSel = document.getElementById('driftToVersionSelect');
            if (fromSel) { fromSel.innerHTML = opts; fromSel.disabled = false; }
            if (toSel) { toSel.innerHTML = opts; toSel.disabled = false; toSel.selectedIndex = 0; if (driftVersions.length > 1) fromSel.selectedIndex = 1; }
            const btn = document.getElementById('btnDriftShowDiff');
            if (btn) btn.disabled = driftVersions.length < 2;
        } catch (e) {
            console.error('Config Drift: failed to load versions', e);
            clearDriftVersions();
        }
    }

    function renderColouredDiff(text) {
        if (!text) return '';
        return text.split('\n').map(line => {
            const escaped = escapeHtml(line);
            if (line.startsWith('+') && !line.startsWith('+++')) {
                return `<div style="background:color-mix(in srgb, var(--success) 12%, transparent);">${escaped}</div>`;
            }
            if (line.startsWith('-') && !line.startsWith('---')) {
                return `<div style="background:color-mix(in srgb, var(--danger) 12%, transparent);">${escaped}</div>`;
            }
            if (line.startsWith('@@')) {
                return `<div style="color:var(--primary); font-weight:600;">${escaped}</div>`;
            }
            return `<div>${escaped}</div>`;
        }).join('');
    }

    async function showDriftDiff() {
        const fromSel = document.getElementById('driftFromVersionSelect');
        const toSel = document.getElementById('driftToVersionSelect');
        const diffBox = document.getElementById('driftDiffContainer');
        if (!fromSel || !toSel || !diffBox || !driftSelectedIp) return;
        const from = fromSel.value, to = toSel.value;
        if (!from || !to) return;
        try {
            const res = await apiFetch(`/api/drift/${encodeURIComponent(driftSelectedIp)}/diff?from_version=${encodeURIComponent(from)}&to_version=${encodeURIComponent(to)}`);
            if (!res || !res.ok) {
                showToast(i18n[currentLang].driftDiffLoadError, 'error');
                return;
            }
            const data = await res.json();
            // Config diff text comes from device backups: attacker-influenced,
            // must be escaped like any other device-supplied string.
            diffBox.innerHTML = renderColouredDiff(data.diff || '');
        } catch (e) {
            console.error('Config Drift: failed to load diff', e);
            showToast(i18n[currentLang].driftDiffLoadError + ': ' + e.message, 'error');
        }
    }

    function switchDriftSubtab(subtab) {
        driftSubtab = subtab;
        document.querySelectorAll('#driftSubtabNav button').forEach(b => {
            b.classList.toggle('active', b.dataset.subtab === subtab);
        });
        const historyEl = document.getElementById('driftSubtabHistory');
        const baselineEl = document.getElementById('driftSubtabBaseline');
        if (historyEl) historyEl.style.display = (subtab === 'history') ? '' : 'none';
        if (baselineEl) baselineEl.style.display = (subtab === 'baseline') ? '' : 'none';

        if (subtab === 'baseline') {
            loadDriftBaselineTab();
            if (driftSelectedIp) loadDriftDeviations(driftSelectedIp);
        }
    }

    async function loadDriftBaselineTab() {
        const textEl = document.getElementById('driftBaselineText');
        if (!textEl) return;
        if (!driftTenant) { textEl.value = ''; return; }
        try {
            const res = await apiFetch(`/api/drift/baseline/${encodeURIComponent(driftTenant)}`);
            if (!res || !res.ok) {
                textEl.value = '';
                showToast(i18n[currentLang].driftBaselineLoadError, 'error');
                return;
            }
            const data = await res.json();
            textEl.value = data.text || '';
        } catch (e) {
            console.error('Config Drift: failed to load baseline', e);
            showToast(i18n[currentLang].driftBaselineLoadError + ': ' + e.message, 'error');
        }
    }

    async function saveDriftBaseline() {
        const textEl = document.getElementById('driftBaselineText');
        if (!textEl || !driftTenant) return;
        try {
            const res = await apiFetch(`/api/drift/baseline/${encodeURIComponent(driftTenant)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: textEl.value })
            });
            if (!res || !res.ok) {
                showToast(i18n[currentLang].driftSaveError, 'error');
                return;
            }
            showToast(i18n[currentLang].driftSaveOk, 'ok');
            if (driftSelectedIp) loadDriftDeviations(driftSelectedIp);
        } catch (e) {
            showToast(i18n[currentLang].driftSaveError + ': ' + e.message, 'error');
        }
    }

    async function seedDriftBaseline() {
        const textEl = document.getElementById('driftBaselineText');
        if (!textEl || !driftTenant) return;
        if (!driftSelectedIp) {
            showToast(i18n[currentLang].driftChooseDeviceFirst, 'warning');
            return;
        }
        try {
            const res = await apiFetch(`/api/drift/baseline/${encodeURIComponent(driftTenant)}/seed?ip=${encodeURIComponent(driftSelectedIp)}`, { method: 'POST' });
            if (!res || !res.ok) {
                showToast(i18n[currentLang].driftSaveError, 'error');
                return;
            }
            const data = await res.json();
            const candidate = data.text || '';
            textEl.value = textEl.value ? (textEl.value.replace(/\n+$/, '') + '\n' + candidate) : candidate;
        } catch (e) {
            showToast(i18n[currentLang].driftSaveError + ': ' + e.message, 'error');
        }
    }

    async function loadDriftDeviations(ip) {
        const container = document.getElementById('driftDeviationsContainer');
        if (!container) return;
        const L = i18n[currentLang];
        try {
            const res = await apiFetch(`/api/drift/${encodeURIComponent(ip)}/baseline`);
            if (!res || !res.ok) return;
            const data = await res.json();
            if (!data.checked) {
                container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">${escapeHtml(L.driftBaselineNotSet)}</div>`;
                return;
            }
            const deviations = data.deviations || [];
            if (deviations.length === 0) {
                container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">${escapeHtml(L.driftDeviationsNone)}</div>`;
                return;
            }
            container.innerHTML = `
                <div class="table-wrap">
                    <table>
                        <thead>
                            <tr>
                                <th data-i18n="thDriftRule">${escapeHtml(L.thDriftRule)}</th>
                                <th data-i18n="thDriftPattern">${escapeHtml(L.thDriftPattern)}</th>
                                <th data-i18n="thDriftProblem">${escapeHtml(L.thDriftProblem)}</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${deviations.map(dv => `
                                <tr>
                                    <td>${escapeHtml(dv.rule || '')}</td>
                                    <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml(dv.pattern || '')}</td>
                                    <td>${escapeHtml(dv.problem === 'missing' ? L.driftProblemMissing : L.driftProblemPresent)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (e) {
            console.error('Config Drift: failed to load deviations', e);
        }
    }

    document.addEventListener('click', e => {
        const row = e.target.closest('[data-action="drift-select-device"]');
        if (row) { onDriftDeviceSelected(row.getAttribute('data-ip')); return; }

        const subtabBtn = e.target.closest('#driftSubtabNav button[data-subtab]');
        if (subtabBtn) { switchDriftSubtab(subtabBtn.dataset.subtab); return; }

        if (e.target.closest('#btnDriftShowDiff')) { showDriftDiff(); return; }
        if (e.target.closest('#btnDriftSaveBaseline')) { saveDriftBaseline(); return; }
        if (e.target.closest('#btnDriftSeedBaseline')) { seedDriftBaseline(); return; }
    });

    document.addEventListener('change', e => {
        if (e.target && e.target.id === 'driftTenantSelect') onDriftTenantChanged();
    });

    // switchTab (core.js) calls this after the lazy script has loaded — see
    // LAZY_TAB_SCRIPTS['tab-config-drift']. A self-registered click listener
    // on the nav button does not work here: the click that triggers the lazy
    // load has already finished dispatching by the time the listener for it
    // would be attached, so the tab opens empty on the first click.
    window.loadConfigDriftTab = loadConfigDriftTab;
})();
