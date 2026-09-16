// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// static/js/config-drift.js
// ===== Config Drift: per-tenant version history and baseline rules =====
// Not an audit: no score, no grade, no severity. The netsec audit already
// owns that question; this tab only shows what changed and what deviates
// from the tenant's own baseline text.
//
// Layout is master-detail: the device list stays on screen and the right pane
// shows either ONE device (deviations / history) or the tenant baseline. The
// old sub-tabs hid which device "Generate" and "Deviations" referred to.

(function () {
    let driftDevices = [];
    let driftTenant = '';
    let driftSelectedIp = '';
    let driftVersions = [];
    // 'device' | 'baseline': what the right pane is showing.
    let driftView = 'device';
    // Saved baseline text per config profile of the current tenant: the
    // coverage is computed on it, not on the unsaved textarea, because the
    // server evaluated that one. A switch, a WLC and a firewall speak different
    // config grammars, so each profile has its own rules.
    let driftSavedBaselines = {};
    // Profile shown in the baseline view.
    let driftProfile = '';
    // Rule highlighted from the coverage table: marks the failing devices in
    // the list pane.
    let driftFocusRule = null;
    // Le due versioni scelte sui marcatori della timeline. Restano
    // allineate alle select: sono due modi di dire la stessa cosa.
    let driftPicked = [];

    async function loadConfigDriftTab() {
        const tenantSel = document.getElementById('driftTenantSelect');
        const list = document.getElementById('driftDeviceList');
        if (!tenantSel) return;
        try {
            const res = await apiFetch('/api/drift/devices');
            if (!res || !res.ok) {
                if (list) list.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(tr('driftLoadError'))}</div>`;
                return;
            }
            const data = await res.json();
            driftDevices = data.devices || [];

            const tenants = [...new Set(driftDevices.map(d => d.tenant))].sort();
            const cur = tenantSel.value || driftTenant;
            tenantSel.innerHTML = `<option value="">${escapeHtml(tr('driftChooseTenant'))}</option>` +
                tenants.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
            tenantSel.value = tenantSelectSeed(cur, tenants, '');
            await onDriftTenantChanged(true);
        } catch (e) {
            console.error('Config Drift: failed to load devices', e);
            if (list) list.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(tr('driftLoadError'))}</div>`;
        }
    }

    // keepSelection: a reload (after saving the baseline) must not throw the
    // operator out of the device they were looking at.
    async function onDriftTenantChanged(keepSelection) {
        const tenantSel = document.getElementById('driftTenantSelect');
        const next = tenantSel ? tenantSel.value : '';
        const sameTenant = next === driftTenant;
        driftTenant = next;
        if (!(keepSelection && sameTenant && driftTenantDevices().some(d => d.ip === driftSelectedIp))) {
            driftSelectedIp = '';
            driftFocusRule = null;
            clearDriftVersions();
        }
        const btn = document.getElementById('btnDriftOpenBaseline');
        if (btn) btn.disabled = !driftTenant;
        await loadDriftSavedBaseline();
        renderDriftTenantStats();
        renderDriftDeviceList();
        renderDriftPane();
    }

    // Proper names of config grammars: identical in every language.
    const DRIFT_PROFILE_LABELS = {
        'ios': 'Cisco IOS / IOS-XE', 'wlc-aireos': 'Cisco WLC (AireOS)', 'fortios': 'FortiOS',
        'panos': 'PAN-OS', 'linux': 'Linux', 'windows': 'Windows',
    };

    function driftProfileLabel(p) {
        return DRIFT_PROFILE_LABELS[p] || p;
    }

    // Profiles present in the tenant, in the order they first appear.
    function driftTenantProfiles() {
        return [...new Set(driftTenantDevices().map(d => d.profile).filter(Boolean))];
    }

    function driftTenantDevices() {
        return driftTenant ? driftDevices.filter(d => d.tenant === driftTenant) : [];
    }

    function driftSelectedDevice() {
        return driftTenantDevices().find(d => d.ip === driftSelectedIp) || null;
    }

    // Same grammar as services/config_drift/baseline.parse: only '+'/'-'
    // lines count, '/x/' is a regex and is reported with the slashes stripped.
    function driftParseRules(text) {
        const rules = [];
        (text || '').split('\n').forEach(raw => {
            const line = raw.trim();
            if (!line || (line[0] !== '+' && line[0] !== '-')) return;
            let pattern = line.slice(1).trim();
            if (!pattern) return;
            if (pattern.length > 1 && pattern.startsWith('/') && pattern.endsWith('/')) pattern = pattern.slice(1, -1);
            rules.push({ rule: line[0], pattern: pattern });
        });
        return rules;
    }

    function driftDeviceState(d) {
        if (!d.versions) return { cls: 'idle', led: 'led-discovered', label: tr('driftStateNoBackup') };
        if (!Array.isArray(d.deviations)) return { cls: 'idle', led: 'led-discovered', label: tr('driftStateNotChecked') };
        if (d.deviations.length === 0) return { cls: 'ok', led: 'led-success', label: tr('driftStateCompliant') };
        return { cls: 'warn', led: 'led-warning', label: tr('driftStateDeviations', { n: d.deviations.length }) };
    }

    function renderDriftTenantStats() {
        const host = document.getElementById('driftTenantStats');
        const ruleCount = document.getElementById('driftRuleCount');
        const devs = driftTenantDevices();
        if (ruleCount) ruleCount.textContent = driftTenant
            ? String(Object.values(driftSavedBaselines).reduce((n, t) => n + driftParseRules(t).length, 0)) : '';
        if (!host) return;
        if (!driftTenant) { host.innerHTML = ''; return; }
        const checked = devs.filter(d => Array.isArray(d.deviations));
        const deviating = checked.filter(d => d.deviations.length);
        host.innerHTML = [
            [tr('driftStatDevices'), devs.length],
            [tr('driftStatChecked'), checked.length],
            [tr('driftStatDeviating'), deviating.length],
        ].map(([k, v]) => `<div class="drift-stat"><span class="drift-stat-value">${escapeHtml(String(v))}</span><span class="drift-stat-label">${escapeHtml(k)}</span></div>`).join('');
    }

    function driftDeviceFails(d, rule) {
        return d.profile === rule.profile && Array.isArray(d.deviations)
            && d.deviations.some(x => x.rule === rule.rule && x.pattern === rule.pattern);
    }

    function renderDriftDeviceList() {
        const list = document.getElementById('driftDeviceList');
        const count = document.getElementById('driftDeviceCount');
        if (!list) return;
        const all = driftTenantDevices();
        const filterEl = document.getElementById('driftDeviceFilter');
        const q = (filterEl ? filterEl.value : '').trim().toLowerCase();
        const devs = q ? all.filter(d => `${d.hostname || ''} ${d.ip}`.toLowerCase().includes(q)) : all;
        if (count) count.textContent = driftTenant ? String(all.length) : '';
        if (!driftTenant) {
            list.innerHTML = `<div class="drift-list-empty">${escapeHtml(tr('driftChooseTenant'))}</div>`;
            return;
        }
        if (devs.length === 0) {
            list.innerHTML = `<div class="drift-list-empty">${escapeHtml(tr('driftNoDevices'))}</div>`;
            return;
        }
        list.innerHTML = devs.map(d => {
            const st = driftDeviceState(d);
            const active = d.ip === driftSelectedIp && driftView === 'device';
            const flagged = driftFocusRule && driftDeviceFails(d, driftFocusRule);
            return `
            <button type="button" role="listitem" class="drift-device-item${active ? ' is-active' : ''}${flagged ? ' is-flagged' : ''}"
                data-action="drift-select-device" data-ip="${escapeHtml(d.ip)}" aria-current="${active ? 'true' : 'false'}">
                <span class="led ${st.led}" aria-hidden="true"></span>
                <span class="drift-device-item-main">
                    <span class="drift-device-item-name">${escapeHtml(d.hostname || d.ip)}</span>
                    <span class="drift-device-item-ip">${escapeHtml(d.ip)}</span>
                </span>
                <span class="drift-device-item-state ${st.cls}">${escapeHtml(st.label)}</span>
            </button>`;
        }).join('');
    }

    // One place decides which of the three right-pane blocks is visible.
    function renderDriftPane() {
        const empty = document.getElementById('driftEmptyState');
        const deviceView = document.getElementById('driftDeviceView');
        const baselineView = document.getElementById('driftBaselineView');
        const showBaseline = driftView === 'baseline' && !!driftTenant;
        const device = driftSelectedDevice();
        if (empty) empty.style.display = (!showBaseline && !device) ? '' : 'none';
        if (deviceView) deviceView.style.display = (!showBaseline && device) ? '' : 'none';
        if (baselineView) baselineView.style.display = showBaseline ? '' : 'none';
        if (showBaseline) renderDriftBaselineView();
        else if (device) renderDriftDeviceHeader(device);
    }

    function renderDriftDeviceHeader(d) {
        const title = document.getElementById('driftDeviceTitle');
        const meta = document.getElementById('driftDeviceMeta');
        const badge = document.getElementById('driftDeviceBadge');
        const st = driftDeviceState(d);
        if (title) title.innerHTML = `${escapeHtml(d.hostname || d.ip)} <span class="drift-device-item-ip">${escapeHtml(d.ip)}</span>`;
        if (meta) {
            const parts = [d.tenant, driftProfileLabel(d.profile),
                tr('driftMetaLastChange', { when: d.last_change ? driftStampLabel(d.last_change) : '—' }),
                tr('driftMetaLastSeen', { when: d.last_seen ? driftStampLabel(d.last_seen) : '—' })];
            meta.textContent = parts.filter(Boolean).join(' · ');
        }
        if (badge) badge.innerHTML = `<span class="status-badge ${st.cls === 'idle' ? 'warn' : st.cls}">${escapeHtml(st.label)}</span>`;
        const devCount = document.getElementById('driftDeviationsCount');
        if (devCount) devCount.textContent = Array.isArray(d.deviations) ? String(d.deviations.length) : '';
        const verCount = document.getElementById('driftVersionsCount');
        if (verCount) verCount.textContent = String(d.versions || 0);
        renderDriftDeviations(d);
    }

    function clearDriftVersions() {
        driftVersions = [];
        const container = document.getElementById('driftVersionsContainer');
        if (container) container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);">${escapeHtml(tr('driftNoVersions'))}</div>`;
        ['driftFromVersionSelect', 'driftToVersionSelect'].forEach(id => {
            const sel = document.getElementById(id);
            if (sel) { sel.innerHTML = ''; sel.disabled = true; }
        });
        const btn = document.getElementById('btnDriftShowDiff');
        if (btn) btn.disabled = true;
        const diff = document.getElementById('driftDiffContainer');
        if (diff) diff.textContent = '';
        const timeline = document.getElementById('driftTimeline');
        if (timeline) timeline.innerHTML = '';
        driftPicked = [];
    }

    async function onDriftDeviceSelected(ip) {
        driftSelectedIp = ip;
        driftView = 'device';
        driftFocusRule = null;
        clearDriftVersions();
        renderDriftDeviceList();
        renderDriftPane();
        await loadDriftVersions(ip);
    }

    async function loadDriftVersions(ip) {
        const container = document.getElementById('driftVersionsContainer');
        try {
            const res = await apiFetch(`/api/drift/${encodeURIComponent(ip)}/versions`);
            if (!res || !res.ok) { clearDriftVersions(); return; }
            const data = await res.json();
            // The operator may have clicked another device while this loaded.
            if (ip !== driftSelectedIp) return;
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
                                        <td>${escapeHtml(driftStampLabel(v.seen_at))}</td>
                                        <td>${escapeHtml(String(v.size))} B</td>
                                        <td style="color:var(--text-muted); font-size:11px; font-family:var(--font-code);">${escapeHtml((v.hash || '').slice(0, 19))}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                `;
            }
            const opts = driftVersions.map(v => `<option value="${escapeHtml(v.seen_at)}">${escapeHtml(driftStampLabel(v.seen_at))}</option>`).join('');
            const fromSel = document.getElementById('driftFromVersionSelect');
            const toSel = document.getElementById('driftToVersionSelect');
            if (fromSel) { fromSel.innerHTML = opts; fromSel.disabled = false; }
            if (toSel) { toSel.innerHTML = opts; toSel.disabled = false; toSel.selectedIndex = 0; if (fromSel && driftVersions.length > 1) fromSel.selectedIndex = 1; }
            const btn = document.getElementById('btnDriftShowDiff');
            if (btn) btn.disabled = driftVersions.length < 2;
            renderDriftTimeline();
        } catch (e) {
            console.error('Config Drift: failed to load versions', e);
            clearDriftVersions();
        }
    }

    // --- TIMELINE GRAFICA DELLE VERSIONI ---

    // seen_at arriva come "20260908T143012.123456Z", cioe' ISO 8601 nella
    // forma BASIC. new Date() parsa solo quella ESTESA e su questa restituisce
    // Invalid Date senza lamentarsi: va espansa prima.
    function driftStampToDate(stamp) {
        const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(?:\.(\d{1,6}))?Z?$/.exec(stamp || '');
        if (!m) return null;
        const ms = (m[7] || '0').padEnd(3, '0').slice(0, 3);
        const d = new Date(`${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}.${ms}Z`);
        return isNaN(d.getTime()) ? null : d;
    }

    function driftStampLabel(stamp) {
        const d = driftStampToDate(stamp);
        return d ? d.toLocaleString() : stamp;
    }

    function renderDriftTimeline() {
        const host = document.getElementById('driftTimeline');
        if (!host) return;
        host.innerHTML = '';
        driftPicked = [];
        if (driftVersions.length === 0) return;

        // Piu' vecchia a sinistra: driftVersions arriva dal piu' recente.
        const asc = driftVersions.slice().reverse();
        const times = asc.map(v => {
            const d = driftStampToDate(v.seen_at);
            return d ? d.getTime() : null;
        });
        const known = times.filter(t => t !== null);
        const first = known.length ? Math.min.apply(null, known) : 0;
        const last = known.length ? Math.max.apply(null, known) : 0;
        // Una sola versione, o tutte nello stesso istante: dividere per
        // (last - first) darebbe 0/0 e ogni marcatore finirebbe a sinistra.
        const span = last - first;

        // L'altezza dice quanto e' cambiata la configurazione: differenza di
        // dimensione rispetto alla versione precedente. E' un'approssimazione
        // — una riga sostituita con una di pari lunghezza non si vede — ma non
        // costringe a leggere ogni diff solo per disegnare la timeline.
        const deltas = asc.map((v, i) => i === 0 ? 0 : Math.abs((v.size || 0) - (asc[i - 1].size || 0)));
        const maxDelta = Math.max.apply(null, deltas.concat([1]));

        const track = document.createElement('div');
        track.className = 'drift-timeline-track';

        asc.forEach((v, i) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'drift-timeline-mark';
            btn.dataset.version = v.seen_at;
            const pct = span > 0
                ? ((times[i] - first) / span) * 100
                : (asc.length === 1 ? 50 : (i / (asc.length - 1)) * 100);
            btn.style.left = pct + '%';
            // 6px minimi: un marcatore alto zero non e' cliccabile, e la prima
            // versione ha delta 0 per definizione.
            btn.style.height = (6 + Math.round((deltas[i] / maxDelta) * 30)) + 'px';
            const when = driftStampLabel(v.seen_at);
            const diff = i === 0 ? 0 : (v.size || 0) - (asc[i - 1].size || 0);
            btn.setAttribute('aria-label', i === 0
                ? tr('driftTimelineMarker', { when: when, size: String(v.size) })
                : tr('driftTimelineMarkerDelta', {
                    when: when, size: String(v.size),
                    delta: (diff >= 0 ? '+' : '') + diff
                }));
            btn.title = btn.getAttribute('aria-label');
            btn.addEventListener('click', () => onDriftMarkerClick(v.seen_at));
            track.appendChild(btn);
        });

        const ends = document.createElement('div');
        ends.className = 'drift-timeline-ends';
        ends.innerHTML = `<span>${escapeHtml(driftStampLabel(asc[0].seen_at))}</span>`
            + `<span>${escapeHtml(driftStampLabel(asc[asc.length - 1].seen_at))}</span>`;

        const hint = document.createElement('div');
        hint.className = 'drift-timeline-hint';
        hint.textContent = asc.length < 2 ? tr('driftTimelineOnlyOne') : tr('driftTimelineHint');

        host.appendChild(track);
        host.appendChild(ends);
        host.appendChild(hint);
        paintDriftSelection();
    }

    // Due click = un intervallo. Il terzo ricomincia, invece di pretendere un
    // pulsante "azzera" che nessuno troverebbe.
    function onDriftMarkerClick(seenAt) {
        if (driftPicked.length >= 2) driftPicked = [];
        if (driftPicked.indexOf(seenAt) === -1) driftPicked.push(seenAt);
        paintDriftSelection();
        if (driftPicked.length !== 2) return;

        // Le select restano la fonte per showDriftDiff: la timeline le pilota
        // invece di duplicarne la logica. driftVersions e' dal piu' recente,
        // quindi indice piu' ALTO = piu' vecchio = "da".
        const order = driftVersions.map(v => v.seen_at);
        const pair = driftPicked.slice().sort((a, b) => order.indexOf(b) - order.indexOf(a));
        const fromSel = document.getElementById('driftFromVersionSelect');
        const toSel = document.getElementById('driftToVersionSelect');
        if (fromSel) fromSel.value = pair[0];
        if (toSel) toSel.value = pair[1];
        showDriftDiff();
    }

    function paintDriftSelection() {
        const host = document.getElementById('driftTimeline');
        if (!host) return;
        host.querySelectorAll('.drift-timeline-mark').forEach(el => {
            const picked = driftPicked.indexOf(el.dataset.version) !== -1;
            el.classList.toggle('is-picked', picked);
            el.setAttribute('aria-pressed', picked ? 'true' : 'false');
        });
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
                showToast(tr('driftDiffLoadError'), 'error');
                return;
            }
            const data = await res.json();
            // Config diff text comes from device backups: attacker-influenced,
            // must be escaped like any other device-supplied string.
            diffBox.innerHTML = renderColouredDiff(data.diff || '');
        } catch (e) {
            console.error('Config Drift: failed to load diff', e);
            showToast(tr('driftDiffLoadError') + ': ' + e.message, 'error');
        }
    }

    function switchDriftSubtab(subtab) {
        document.querySelectorAll('#driftSubtabNav button').forEach(b => {
            b.classList.toggle('active', b.dataset.subtab === subtab);
        });
        const historyEl = document.getElementById('driftSubtabHistory');
        const deviationsEl = document.getElementById('driftSubtabDeviations');
        if (historyEl) historyEl.style.display = (subtab === 'history') ? '' : 'none';
        if (deviationsEl) deviationsEl.style.display = (subtab === 'deviations') ? '' : 'none';
    }

    // Deviations come with /api/drift/devices: no second request per click.
    function renderDriftDeviations(d) {
        const container = document.getElementById('driftDeviationsContainer');
        if (!container) return;
        const muted = msg => `<div class="drift-list-empty">${escapeHtml(msg)}</div>`;
        if (!d.versions) { container.innerHTML = muted(tr('driftNoVersions')); return; }
        if (!Array.isArray(d.deviations)) {
            container.innerHTML = muted(tr('driftBaselineNotSet'))
                + `<div style="text-align:center;"><button type="button" class="btn btn-secondary" style="width:auto;" data-action="drift-open-baseline"><i class="fa-solid fa-list-check"></i> ${escapeHtml(tr('driftBtnTenantBaseline'))}</button></div>`;
            return;
        }
        if (d.deviations.length === 0) { container.innerHTML = muted(tr('driftDeviationsNone')); return; }
        container.innerHTML = `
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>${escapeHtml(tr('thDriftRule'))}</th>
                            <th>${escapeHtml(tr('thDriftPattern'))}</th>
                            <th>${escapeHtml(tr('thDriftProblem'))}</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${d.deviations.map(dv => `
                            <tr>
                                <td>${escapeHtml(dv.rule === '+' ? tr('driftRuleRequired') : tr('driftRuleForbidden'))}</td>
                                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(dv.pattern || '')}</td>
                                <td><span class="status-badge warn">${escapeHtml(dv.problem === 'missing' ? tr('driftProblemMissing') : tr('driftProblemPresent'))}</span></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    async function loadDriftSavedBaseline() {
        driftSavedBaselines = {};
        if (!driftTenant) return;
        const tenant = driftTenant;
        const loaded = {};
        try {
            for (const profile of driftTenantProfiles()) {
                const res = await apiFetch(`/api/drift/baseline/${encodeURIComponent(tenant)}?profile=${encodeURIComponent(profile)}`);
                if (!res || !res.ok) {
                    showToast(tr('driftBaselineLoadError'), 'error');
                    return;
                }
                loaded[profile] = (await res.json()).text || '';
            }
            if (tenant === driftTenant) driftSavedBaselines = loaded;
        } catch (e) {
            console.error('Config Drift: failed to load baseline', e);
            showToast(tr('driftBaselineLoadError') + ': ' + e.message, 'error');
        }
    }

    function driftBaselineDirty() {
        const textEl = document.getElementById('driftBaselineText');
        return !!textEl && driftView === 'baseline' && textEl.value !== (driftSavedBaselines[driftProfile] || '');
    }

    function openDriftBaseline() {
        if (!driftTenant) return;
        driftView = 'baseline';
        const profiles = driftTenantProfiles();
        const current = driftSelectedDevice();
        selectDriftProfile(current && current.profile ? current.profile : (profiles[0] || 'ios'));
    }

    // Loads one profile into the editor: text, seed devices, coverage.
    function selectDriftProfile(profile) {
        driftProfile = profile;
        driftFocusRule = null;
        const textEl = document.getElementById('driftBaselineText');
        if (textEl) textEl.value = driftSavedBaselines[profile] || '';
        // The seed source is explicit: default to the device the operator was
        // on, otherwise the first one of this profile with a collected config.
        const seedSel = document.getElementById('driftSeedDeviceSelect');
        if (seedSel) {
            const withConfig = driftTenantDevices().filter(d => d.versions && d.profile === profile);
            seedSel.innerHTML = withConfig.map(d => `<option value="${escapeHtml(d.ip)}">${escapeHtml(d.hostname || d.ip)} (${escapeHtml(d.ip)})</option>`).join('');
            if (withConfig.some(d => d.ip === driftSelectedIp)) seedSel.value = driftSelectedIp;
            seedSel.disabled = withConfig.length === 0;
        }
        renderDriftDeviceList();
        renderDriftPane();
    }

    function closeDriftBaseline() {
        driftView = 'device';
        driftFocusRule = null;
        renderDriftDeviceList();
        renderDriftPane();
    }

    function renderDriftBaselineView() {
        const devs = driftTenantDevices().filter(d => d.profile === driftProfile);
        const checked = devs.filter(d => Array.isArray(d.deviations));
        const title = document.getElementById('driftBaselineTitle');
        const meta = document.getElementById('driftBaselineMeta');
        if (title) title.textContent = tr('driftBaselineViewTitle', { tenant: driftTenant, profile: driftProfileLabel(driftProfile) });
        if (meta) meta.textContent = tr('driftBaselineViewMeta', { devices: devs.length, checked: checked.length });

        const nav = document.getElementById('driftProfileNav');
        if (nav) {
            nav.innerHTML = driftTenantProfiles().map(p => {
                const n = driftTenantDevices().filter(d => d.profile === p).length;
                const rules = driftParseRules(driftSavedBaselines[p]).length;
                return `<button type="button" class="btn btn-secondary${p === driftProfile ? ' active' : ''}" data-action="drift-select-profile" data-profile="${escapeHtml(p)}" aria-pressed="${p === driftProfile ? 'true' : 'false'}">`
                    + `${escapeHtml(driftProfileLabel(p))} <span class="drift-count">${n}</span>`
                    + ` <span class="drift-profile-rules">${escapeHtml(tr('driftProfileRules', { n: rules }))}</span></button>`;
            }).join('');
        }
        const back = document.getElementById('btnDriftCloseBaseline');
        if (back) back.style.display = driftSelectedDevice() ? '' : 'none';

        const host = document.getElementById('driftCoverageContainer');
        if (!host) return;
        const rules = driftParseRules(driftSavedBaselines[driftProfile]).map(r => Object.assign(r, { profile: driftProfile }));
        if (rules.length === 0) {
            host.innerHTML = `<div class="drift-list-empty">${escapeHtml(tr('driftBaselineNotSet'))}</div>`;
            return;
        }
        if (checked.length === 0) {
            host.innerHTML = `<div class="drift-list-empty">${escapeHtml(tr('driftCoverageNoConfigs'))}</div>`;
            return;
        }
        host.innerHTML = `
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>${escapeHtml(tr('thDriftRule'))}</th>
                            <th>${escapeHtml(tr('thDriftPattern'))}</th>
                            <th>${escapeHtml(tr('thDriftCoverage'))}</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rules.map((r, i) => {
                            const failing = checked.filter(d => driftDeviceFails(d, r));
                            const pct = Math.round(((checked.length - failing.length) / checked.length) * 100);
                            const focused = !!driftFocusRule && driftFocusRule.rule === r.rule && driftFocusRule.pattern === r.pattern;
                            return `
                            <tr class="${focused ? 'active' : ''}">
                                <td>${escapeHtml(r.rule === '+' ? tr('driftRuleRequired') : tr('driftRuleForbidden'))}</td>
                                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(r.pattern)}</td>
                                <td>
                                    <div class="drift-coverage">
                                        <div class="drift-coverage-bar" aria-hidden="true"><span style="width:${pct}%;"></span></div>
                                        ${failing.length
                                            ? `<button type="button" class="btn btn-secondary btn-small" style="width:auto; margin:0;" data-action="drift-focus-rule" data-rule-index="${i}" aria-pressed="${focused ? 'true' : 'false'}">${escapeHtml(tr('driftCoverageFailing', { n: failing.length, total: checked.length }))}</button>`
                                            : `<span class="status-badge ok">${escapeHtml(tr('driftCoverageAll', { total: checked.length }))}</span>`}
                                    </div>
                                </td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    function focusDriftRule(index) {
        const r = driftParseRules(driftSavedBaselines[driftProfile])[index];
        if (!r) return;
        r.profile = driftProfile;
        const same = driftFocusRule && driftFocusRule.rule === r.rule && driftFocusRule.pattern === r.pattern;
        driftFocusRule = same ? null : r;
        renderDriftDeviceList();
        renderDriftBaselineView();
    }

    async function saveDriftBaseline() {
        const textEl = document.getElementById('driftBaselineText');
        if (!textEl || !driftTenant) return;
        try {
            const res = await apiFetch(`/api/drift/baseline/${encodeURIComponent(driftTenant)}?profile=${encodeURIComponent(driftProfile)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text: textEl.value })
            });
            if (!res || !res.ok) {
                showToast(tr('driftSaveError'), 'error');
                return;
            }
            showToast(tr('driftSaveOk'), 'ok');
            // Deviations are computed server-side on the saved text: reload
            // the list so badges and coverage reflect the new rules.
            await loadConfigDriftTab();
            selectDriftProfile(driftProfile);
        } catch (e) {
            showToast(tr('driftSaveError') + ': ' + e.message, 'error');
        }
    }

    async function seedDriftBaseline() {
        const textEl = document.getElementById('driftBaselineText');
        const seedSel = document.getElementById('driftSeedDeviceSelect');
        const ip = seedSel ? seedSel.value : '';
        if (!textEl || !driftTenant) return;
        if (!ip) {
            showToast(tr('driftNoVersions'), 'warning');
            return;
        }
        try {
            const res = await apiFetch(`/api/drift/baseline/${encodeURIComponent(driftTenant)}/seed?ip=${encodeURIComponent(ip)}`, { method: 'POST' });
            if (!res || !res.ok) {
                showToast(tr('driftSaveError'), 'error');
                return;
            }
            const data = await res.json();
            const candidate = data.text || '';
            textEl.value = textEl.value ? (textEl.value.replace(/\n+$/, '') + '\n' + candidate) : candidate;
        } catch (e) {
            showToast(tr('driftSaveError') + ': ' + e.message, 'error');
        }
    }

    document.addEventListener('click', e => {
        const row = e.target.closest('[data-action="drift-select-device"]');
        if (row) { onDriftDeviceSelected(row.getAttribute('data-ip')); return; }

        const subtabBtn = e.target.closest('#driftSubtabNav button[data-subtab]');
        if (subtabBtn) { switchDriftSubtab(subtabBtn.dataset.subtab); return; }

        const profileBtn = e.target.closest('[data-action="drift-select-profile"]');
        if (profileBtn) {
            if (profileBtn.dataset.profile !== driftProfile && driftBaselineDirty() && !confirm(tr('driftDiscardEdits'))) return;
            selectDriftProfile(profileBtn.dataset.profile);
            return;
        }

        const focusBtn = e.target.closest('[data-action="drift-focus-rule"]');
        if (focusBtn) { focusDriftRule(Number(focusBtn.dataset.ruleIndex)); return; }

        if (e.target.closest('#btnDriftOpenBaseline, [data-action="drift-open-baseline"]')) { openDriftBaseline(); return; }
        if (e.target.closest('#btnDriftCloseBaseline')) { closeDriftBaseline(); return; }
        if (e.target.closest('#btnDriftShowDiff')) { showDriftDiff(); return; }
        if (e.target.closest('#btnDriftSaveBaseline')) { saveDriftBaseline(); return; }
        if (e.target.closest('#btnDriftSeedBaseline')) { seedDriftBaseline(); return; }
    });

    document.addEventListener('change', e => {
        if (e.target && e.target.id === 'driftTenantSelect') onDriftTenantChanged(false);
    });

    document.addEventListener('input', e => {
        if (e.target && e.target.id === 'driftDeviceFilter') renderDriftDeviceList();
    });

    // switchTab (core.js) calls this after the lazy script has loaded — see
    // LAZY_TAB_SCRIPTS['tab-config-drift']. A self-registered click listener
    // on the nav button does not work here: the click that triggers the lazy
    // load has already finished dispatching by the time the listener for it
    // would be attached, so the tab opens empty on the first click.
    window.loadConfigDriftTab = loadConfigDriftTab;
})();
