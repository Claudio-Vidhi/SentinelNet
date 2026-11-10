// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
    // --- OBSERVABILITY SETTINGS (§11.5a) ---

    const OBS_LISTENERS = ['syslog'];
    // The default port is platform-dependent: the server sends it as
    // d[listener].default_port (GET /api/observability/config).

    async function loadObsSettings() {
        if (!isAdminRole(currentRole)) return;
        const box = document.getElementById('obsSettingsBody');
        if (!box) return;
        const res = await apiFetch('/api/observability/config');
        if (!res || !res.ok) { box.innerHTML = ''; return; }
        const d = await res.json();
        renderObsSettings(d);
    }

    function renderObsSettings(d) {
        const box = document.getElementById('obsSettingsBody');
        if (!box) return;
        const L = i18n[currentLang];
        const listenerRows = OBS_LISTENERS.map(l => {
            const lc = d[l] || {};
            return `
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                <label style="display:flex; align-items:center; gap:8px; min-width:120px; cursor:pointer;">
                    <input type="checkbox" id="obs_${l}_enabled" ${lc.enabled ? 'checked' : ''}>
                    <span style="font-size:13px; text-transform:uppercase;">${l}</span>
                </label>
                <input id="obs_${l}_port" type="number" min="1" max="65535"
                       aria-label="${escapeHtml(l.toUpperCase() + ' ' + tr('lblNetPort'))}"
                       value="${lc.port != null ? lc.port : ''}"
                       placeholder="${lc.default_port}"
                       style="width:100px; padding:6px 10px; border-radius:0; border:1px solid var(--border);
                              background:var(--surface-3); color:var(--text); font-family:var(--font-code); font-size:12px;">
                <span style="font-size:11px; color:var(--text-muted);">UDP · ${L.hintObsDefaultPort || 'porta predefinita'} ${lc.default_port}</span>
            </div>`;
        }).join('');
        box.innerHTML = `
            <label style="display:flex; align-items:center; gap:10px; cursor:pointer; margin-bottom:14px;">
                <input type="checkbox" id="obs_enabled" ${d.enabled ? 'checked' : ''}>
                <span style="font-size:13px; font-weight:700;" data-i18n="lblObsEnabled">Abilita observability</span>
            </label>
            <div class="form-group" style="max-width:280px;">
                <label for="obs_bind" data-i18n="lblObsBind">Indirizzo di ascolto (bind)</label>
                <input id="obs_bind" type="text" value="${escapeHtml(d.bind || '')}" style="padding-left:12px;">
            </div>
            <div class="form-group" style="max-width:200px;">
                <label for="obs_api_poll_s" data-i18n="lblObsApiPoll">Intervallo polling API (s)</label>
                <input id="obs_api_poll_s" type="number" min="1" value="${d.api_poll_s != null ? d.api_poll_s : ''}" style="padding-left:12px;">
            </div>
            <div class="form-group" style="max-width:280px;">
                <label for="obs_snmp_poll_s" data-i18n="lblObsSnmpPoll">Intervallo polling SNMP (s)</label>
                <input id="obs_snmp_poll_s" type="number" min="0" value="${d.snmp_poll_s != null ? d.snmp_poll_s : 0}" style="padding-left:12px;">
                <small style="color:var(--text-muted); font-size:11px;" data-i18n="hintObsSnmpPoll">0 = spento. Interroga solo gli apparati che hanno una community configurata nella loro scheda.</small>
            </div>
            <div class="form-group" style="max-width:280px;">
                <label for="obs_linux_poll_s" data-i18n="lblObsLinuxPoll">Intervallo polling host Linux/Windows (s)</label>
                <input id="obs_linux_poll_s" type="number" min="0" value="${d.linux_poll_s != null ? d.linux_poll_s : 0}" style="padding-left:12px;">
                <small style="color:var(--text-muted); font-size:11px;" data-i18n="hintObsLinuxPoll">0 = spento. Apre una sessione SSH verso gli host con vendor «linux» o «windows» e ne rileva CPU, memoria e disco.</small>
            </div>
            <div style="margin-top:10px; margin-bottom:2px; font-size:12px; color:var(--text-muted); text-transform:uppercase; font-weight:700;" data-i18n="lblObsListeners">Listener</div>
            <div style="margin-bottom:8px; font-size:12px; color:var(--text-muted);">${L.hintObsListeners || "Attiva il listener e indica la porta UDP su cui SentinelNet resta in ascolto, poi configura l'invio syslog dei dispositivi verso questo host su quella porta. Le modifiche ai listener vengono applicate subito, senza riavviare l'applicazione."}</div>
            ${listenerRows}
            <div style="margin-top:12px;">
                <button id="btnSaveObsSettings" class="btn btn-primary btn-small" data-action="save-obs-settings" data-i18n="btnSave">
                    <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(L.btnSave || (tr('uiSave')))}
                </button>
            </div>
            <div id="obsSettingsError" style="margin-top:10px; font-size:12px; color:var(--danger);"></div>
            <div id="obsHealthBox" style="margin-top:18px; padding-top:14px; border-top:1px solid var(--border);"></div>`;
        loadObsHealth();
    }

    // Stato della pipeline: finora esisteva solo come rotta, e per sapere se un
    // listener era davvero in ascolto bisognava chiamarla a mano.
    async function loadObsHealth() {
        const box = document.getElementById('obsHealthBox');
        if (!box) return;
        const L = i18n[currentLang];
        const res = await apiFetch('/api/observability/health');
        if (!res || !res.ok) { box.innerHTML = ''; return; }
        const h = await res.json();
        const listeners = h.listeners || {};
        const badges = Object.keys(listeners).map(name => {
            const active = listeners[name] && listeners[name].active;
            return `<span class="status ${active ? 'ok' : 'warn'}" style="margin-right:6px;">
                        <span class="led ${active ? 'led-success' : 'led-warning'}"></span>${escapeHtml(name)}
                    </span>`;
        }).join('') || `<span style="color:var(--text-muted); font-size:12px;">${escapeHtml(tr('obsNoListener'))}</span>`;
        const mb = (h.db_size_bytes || 0) / (1024 * 1024);
        // WP7: la perdita dati della pipeline e' uno stato dichiarato, non un
        // contatore nascosto: writer fermo (scritture scartate) o scarti per
        // coda piena dall'avvio.
        const dbh = h.db_health || {};
        const writerChip = dbh.writer_dead
            ? `<span class="status error"><span class="led led-danger"></span>${escapeHtml(tr('obsStoppedWritesDiscarded'))}</span>`
            : dbh.degraded
                ? `<span class="status warn"><span class="led led-warning"></span>${escapeHtml(tr('obsDrops'))} (${dbh.writes_dropped_queue_full || 0})</span>`
                : `<span class="status ok"><span class="led led-success"></span>ok</span>`;
        box.innerHTML = `
            <h4 style="margin:0 0 10px; font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted);">
                <i class="fa-solid fa-heart-pulse" style="color:var(--primary);"></i>
                ${escapeHtml(L.obsHealthTitle || (tr('obsPipelineHealth')))}
            </h4>
            <div style="display:flex; gap:16px; flex-wrap:wrap; align-items:center; font-size:12px; margin-bottom:12px;">
                <span>${escapeHtml(tr('obsEnabled'))}:
                    <span class="status ${h.enabled ? 'ok' : 'warn'}">${h.enabled ? (tr('obsYes')) : 'no'}</span></span>
                <span>${escapeHtml(tr('obsListeners'))}: ${badges}</span>
                <span>${escapeHtml(tr('obsWriter'))}: ${writerChip}</span>
                <span>DB: <b>${mb.toFixed(1)} MB</b></span>
                <span>${escapeHtml(tr('obsSchema'))}: <b>${escapeHtml(String(h.schema_version ?? '—'))}</b></span>
            </div>
            <p style="margin:0 0 8px; font-size:12px; color:var(--text-muted);">
                ${escapeHtml(tr('obsABackgroundJobAlready'))}
            </p>
            <div style="display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap;">
                <div class="form-group" style="margin-bottom:0; max-width:170px;">
                    <label for="obsPruneDays">${escapeHtml(L.obsPruneDays || (tr('obsKeepLastDays')))}</label>
                    <input id="obsPruneDays" type="number" min="1" max="3650" value="30" style="padding-left:12px;">
                </div>
                <button id="btnPruneObsLogs" class="btn btn-danger btn-small" style="width:auto; margin:0;" data-action="prune-obs-logs">
                    <i class="fa-solid fa-broom"></i> ${escapeHtml(L.obsPruneRun || (tr('obsPurgeOlderLogs')))}
                </button>
            </div>`;
    }

    // Permanent deletion: syslog_events older than the threshold.
    async function pruneObsLogs() {
        const days = parseInt(document.getElementById('obsPruneDays')?.value, 10);
        if (!days || days < 1) {
            showToast(tr('obsEnterARetentionIn'), 'warning');
            return;
        }
        const question = tr('obsPermanentlyDeleteSyslogEvents', {days: days});
        if (!confirm(question)) return;
        const res = await apiFetch('/api/observability/prune-logs', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ days })
        });
        if (!res || !res.ok) {
            showToast(tr('obsPurgeFailed'), 'error');
            return;
        }
        showToast(tr('obsOldLogsPurged'), 'success');
        loadObsHealth();
    }

    async function saveObsSettings() {
        const errEl = document.getElementById('obsSettingsError');
        if (errEl) errEl.textContent = '';
        const payload = {
            enabled: document.getElementById('obs_enabled').checked,
            bind: document.getElementById('obs_bind').value.trim(),
            api_poll_s: parseInt(document.getElementById('obs_api_poll_s').value, 10),
            snmp_poll_s: parseInt(document.getElementById('obs_snmp_poll_s').value, 10) || 0,
            linux_poll_s: parseInt(document.getElementById('obs_linux_poll_s').value, 10) || 0
        };
        OBS_LISTENERS.forEach(l => {
            payload[`${l}_enabled`] = document.getElementById(`obs_${l}_enabled`).checked;
            const port = parseInt(document.getElementById(`obs_${l}_port`).value, 10);
            if (!isNaN(port)) payload[`${l}_port`] = port;
        });
        const res = await apiFetch('/api/observability/config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            const msg = (e && e.detail) || (tr('uiSaveError'));
            if (errEl) errEl.textContent = msg; else alert(msg);
            return;
        }
        const data = await res.json();
        const banner = document.getElementById('obsRestartBanner');
        if (data && data.restart_required) {
            if (banner) banner.style.display = 'block';
            showToast(tr('msgObsRestartRequired') || 'Riavvio richiesto per applicare le modifiche.', 'warning');
        } else {
            if (banner) banner.style.display = 'none';
            showToast(tr('msgObsApplied') || 'Modifiche applicate.', 'success');
        }
    }

    // --- TRAFFIC TAB ----------------------------------------------------------
    // Autenticazione via cookie HttpOnly (apiFetch): nessun token lato JS.
    let flowsRefreshTimer = null;
    let _flowsSelectedTenants = new Set(Object.keys(globalGroups || {}));

    // Single source of truth for the Traffico tab. Every view reads the window
    // and the tenant from here: the tab used to carry three independent window
    // selects (flows, protocol chart, SIEM), so a 15m top talker could sit next
    // to a 24h chart with nothing on screen saying so.
    const trafState = {
        window: '1h',
        autoRefresh: true,
    };
    let _trafView = 'search';

    // One loader per view: switching pill loads only the view being opened.
    const TRAF_LOADERS = {
        search:    () => loadFlowSiemTab(),
        policies:  () => trafPoliciesShown(),
    };

    // Una lista sola: aggiungere una pill e dimenticare questo array lasciava
    // il pane precedente visibile sotto quello nuovo.
    const TRAF_VIEWS = ['search', 'policies'];

    function trafSwitchView(view) {
        if (!document.getElementById('trafPane-' + view)) return;
        _trafView = view;
        for (const v of TRAF_VIEWS) {
            const pane = document.getElementById('trafPane-' + v);
            const pill = document.getElementById('trafPill-' + v);
            if (pane) pane.style.display = (v === view) ? '' : 'none';
            if (pill) pill.classList.toggle('active', v === view);
        }
        const loader = TRAF_LOADERS[view];
        if (loader) loader();
    }

    // --- VISTA "PER POLICY": i contatori che il firewall tiene da se' --------
    // Non e' telemetria di rete come il resto del tab: byte e sessioni per
    // policy vivono SUL FortiGate e sono cumulativi dall'ultimo azzeramento.
    // La finestra del tab non li filtra, e il pannello lo dice a schermo: 850
    // MB letti sotto un selettore "ultime 6 ore" si leggono come 850 MB in sei
    // ore, che e' sbagliato di un ordine di grandezza.

    let _trafPolicies = [];
    let _trafPolErrors = [];

    function trafPolSelectedDevices() {
        return pickerValues('trafPolDevice');
    }

    function trafPolFilters() {
        const val = id => {
            const el = /** @type {HTMLInputElement|HTMLSelectElement|null} */ (
                document.getElementById(id));
            return el ? el.value : '';
        };
        return { device: trafPolSelectedDevices().join(','),
                 action: val('trafPolAction'), q: val('trafPolSearch') };
    }

    // I firewall scegliibili arrivano dall'inventario, non dalle righe
    // tornate: la lista deve esistere PRIMA di interrogare qualcuno.
    async function loadTrafPolDeviceList() {
        let devices = [];
        try {
            const res = await apiFetch('/api/firewall-traffic/devices');
            if (res && res.ok) devices = (await res.json()).devices || [];
        } catch (e) { devices = []; }
        // Lo scope globale vale anche qui: senza filtro il picker elencava i
        // firewall di tutti i tenant.
        const tenant = window.globalSelectedTenant || 'all';
        if (tenant !== 'all') devices = devices.filter(d => d.group === tenant);
        renderPickerItems('trafPolDevice', devices
            .sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''))
            .map(d => ({ value: d.ip, label: d.hostname || d.ip, hint: d.ip })));
    }

    // Aprire la vista popola la tendina e si ferma li'. Interrogare da soli
    // tutti i firewall gestiti apre una sessione REST per apparato, e i
    // contatori per policy non cambiano abbastanza da giustificarlo.
    async function trafPoliciesShown() {
        await loadTrafPolDeviceList();
        renderTrafPolErrors();
        renderTrafPolicies(null);
    }

    async function loadTrafPolicies() {
        const f = trafPolFilters();
        if (!f.device) {
            _trafPolicies = [];
            _trafPolErrors = [];
            renderTrafPolErrors();
            renderTrafPolicies(null);
            return;
        }
        const url = `/api/firewall-traffic/policies?device=${encodeURIComponent(f.device)}`
            + `&action=${encodeURIComponent(f.action)}&q=${encodeURIComponent(f.q.trim())}`;
        const body = document.getElementById('trafPolBody');
        if (body) {
            body.innerHTML = `<tr><td colspan="8" style="padding:20px; text-align:center;
                color:var(--text-muted);">${escapeHtml(tr('trafPolLoading'))}</td></tr>`;
        }
        let totals = { total_bytes: 0, total_sessions: 0 };
        try {
            const res = await apiFetch(url);
            if (!res || !res.ok) throw new Error('HTTP ' + (res ? res.status : '?'));
            const data = await res.json();
            _trafPolicies = data.rows || [];
            _trafPolErrors = data.errors || [];
            totals = data;
        } catch (e) {
            _trafPolicies = [];
            _trafPolErrors = [{ device_ip: '', error: String(e) }];
        }
        renderTrafPolErrors();
        renderTrafPolicies(totals);
    }

    function renderTrafPolErrors() {
        const box = document.getElementById('trafPolErrors');
        if (!box) return;
        if (!_trafPolErrors.length) { box.style.display = 'none'; box.innerHTML = ''; return; }
        box.style.display = '';
        box.innerHTML = `<div style="border:1px solid var(--warning);
              background:color-mix(in srgb, var(--warning) 8%, transparent); padding:10px 14px; font-size:12px;">
            <strong>${escapeHtml(tr('trafPolPartial', { n: _trafPolErrors.length }))}</strong>
            <ul style="margin:6px 0 0; padding-left:18px;">${
                _trafPolErrors.map(e => `<li><span style="font-family:var(--font-code);">${
                    escapeHtml(e.device_ip || '?')}</span> &mdash; ${escapeHtml(e.error)}</li>`).join('')}</ul>
          </div>`;
    }

    function renderTrafPolicies(totals) {
        const tbody = document.getElementById('trafPolBody');
        const totalsBox = document.getElementById('trafPolTotals');
        if (!tbody) return;
        if (totalsBox) {
            totalsBox.textContent = tr('trafPolTotals', {
                n: _trafPolicies.length,
                bytes: fmtBytes((totals && totals.total_bytes) || 0),
                sessions: (totals && totals.total_sessions) || 0,
            });
        }
        if (!_trafPolicies.length) {
            const msg = trafPolSelectedDevices().length ? tr('trafPolEmpty') : tr('trafPolPickDevices');
            tbody.innerHTML = `<tr><td colspan="8" style="padding:20px; text-align:center;
                color:var(--text-muted);">${escapeHtml(msg)}</td></tr>`;
            return;
        }
        // Barra in scala sulla policy piu' carica della vista: si sta leggendo
        // il confronto fra regole, non la loro quota sul totale.
        const max = Math.max(..._trafPolicies.map(r => r.bytes || 0), 1);
        const dash = '<span style="color:var(--text-muted);">&mdash;</span>';
        tbody.innerHTML = _trafPolicies.map(r => {
            const deny = r.action === 'deny';
            const actionColor = deny ? 'var(--danger)' : 'var(--success)';
            const pct = Math.max(1, Math.round(((r.bytes || 0) / max) * 100));
            // never_hit distingue "contatore a zero" da "nessun contatore":
            // una policy di cui non sappiamo nulla non e' una regola morta.
            const traffic = r.bytes
                ? `<div style="position:relative; height:14px; background:var(--surface-3); overflow:hidden; min-width:120px;">
                     <div style="height:100%; width:${pct}%; background:${actionColor};"></div>
                     <span style="position:absolute; right:4px; top:50%; transform:translateY(-50%);
                           font-size:10px; font-family:var(--font-code); color:var(--text);">${
                               escapeHtml(fmtBytes(r.bytes))}</span>
                   </div>`
                : (r.never_hit
                    ? `<span class="badge" style="border-color:var(--warning); color:var(--warning);">${
                          escapeHtml(tr('trafPolNeverHit'))}</span>`
                    : dash);
            const flow = `${escapeHtml(r.srcaddr || '?')} &rarr; ${escapeHtml(r.dstaddr || '?')}`;
            const ips = [r.srcaddr_ips, r.dstaddr_ips].filter(Boolean).join(' -> ');
            const disabled = r.status && r.status !== 'enable';
            return `<tr style="border-top:1px solid var(--border); font-size:12px; ${
                       disabled ? 'opacity:.55;' : ''}">
                <td style="padding:6px 8px;">${escapeHtml(r.device)}</td>
                <td style="padding:6px 8px; text-align:right; font-family:var(--font-code);">${
                    r.policyid === null || r.policyid === undefined ? dash : escapeHtml(String(r.policyid))}</td>
                <td style="padding:6px 8px;">${r.name ? escapeHtml(r.name) : dash}${
                    disabled ? ` <span class="badge" style="border-color:var(--text-muted); color:var(--text-muted);">${
                        escapeHtml(tr('trafPolDisabled'))}</span>` : ''}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);" ${
                    ips ? `title="${escapeHtml(ips)}"` : ''}>${flow}</td>
                <td style="padding:6px 8px;">${r.service ? escapeHtml(r.service) : dash}</td>
                <td style="padding:6px 8px; font-weight:700; color:${actionColor};">${
                    escapeHtml((r.action || '').toUpperCase() || 'N/D')}</td>
                <td style="padding:6px 8px;">${traffic}</td>
                <td style="padding:6px 8px; text-align:right; font-family:var(--font-code);">${
                    escapeHtml(String(r.active_sessions || 0))}</td>
            </tr>`;
        }).join('');
    }

    function trafSetWindow(value) {
        trafState.window = value;
        trafRefresh();
    }

    function trafRefresh() {
        const loader = TRAF_LOADERS[_trafView];
        if (loader) loader();
    }

    function flowsTabShown() {
        // Header controls mirror trafState, not the other way round.
        const winSel = document.getElementById('trafWindow');
        if (winSel) winSel.value = trafState.window;
        trafSwitchView(_trafView);
        startFlowsAutoRefresh();
        checkObsStatusBanner();
    }

    // Banner di stato: l'assenza di dati era silenziosa quando l'osservabilità
    // era spenta o nessun listener attivo. /health è solo-admin: 403 → nascosto.
    async function checkObsStatusBanner() {
        const banner = document.getElementById('flowsObsBanner');
        if (!banner) return;
        try {
            const res = await apiFetch('/api/observability/health');
            if (!res || !res.ok) { banner.style.display = 'none'; return; }
            const h = await res.json();
            const listeners = h.listeners || {};
            const anyActive = Object.values(listeners).some(l => l && l.active);
            if (!h.enabled) {
                banner.textContent = tr('obsObservabilityDisabledNoListener');
                banner.style.display = 'block';
            } else if (!anyActive) {
                banner.textContent = tr('obsObservabilityEnabledButNo');
                banner.style.display = 'block';
            } else {
                banner.style.display = 'none';
            }
        } catch (e) { banner.style.display = 'none'; }
    }

    function startFlowsAutoRefresh() {
        stopFlowsAutoRefresh();
        flowsRefreshTimer = setInterval(() => {
            const active = document.getElementById('tab-flows')?.classList.contains('active');
            const auto = document.getElementById('trafAutoRefresh')?.checked;
            if (active && auto && !document.hidden) trafRefresh();
        }, 30000);
    }

    function stopFlowsAutoRefresh() {
        if (flowsRefreshTimer) { clearInterval(flowsRefreshTimer); flowsRefreshTimer = null; }
    }

    // Pausa quando la pagina non è visibile; refresh immediato al ritorno.
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden &&
            document.getElementById('tab-flows')?.classList.contains('active')) {
            trafRefresh();
        }
    });

    function fmtBytes(b) {
        if (!b) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), units.length - 1);
        return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + units[i];
    }

    // Expose functions globally for UI
    window.loadObsHealth = loadObsHealth;
    window.pruneObsLogs = pruneObsLogs;
    window.trafSelectedTenants = () => new Set(_flowsSelectedTenants);
    window.trafState = trafState;
    window.trafSwitchView = trafSwitchView;
    window.trafSetWindow = trafSetWindow;
    window.trafRefresh = trafRefresh;

    document.getElementById('obsSettingsBody')?.addEventListener('click', (e) => {
        if (e.target.closest('[data-action="save-obs-settings"]')) saveObsSettings();
        if (e.target.closest('[data-action="prune-obs-logs"]')) pruneObsLogs();
    });

    // Static event listeners for Traffic / Flows / Observability tab
    document.getElementById('trafWindow')?.addEventListener('change', (e) => trafSetWindow(e.target.value));
    document.getElementById('btnTrafRefresh')?.addEventListener('click', trafRefresh);
    document.getElementById('trafPills')?.addEventListener('click', (e) => {
        const pill = e.target.closest('[data-traf-view]');
        if (pill && pill.dataset.trafView) trafSwitchView(pill.dataset.trafView);
    });
    let _trafPolSearchTimer = null;
    document.getElementById('trafPolSearch')?.addEventListener('input', () => {
        clearTimeout(_trafPolSearchTimer);
        _trafPolSearchTimer = setTimeout(loadTrafPolicies, 350);
    });
    // Cambiare la selezione non fa partire la query: si sceglie e si preme
    // Interroga. Ogni firewall in piu' e' una sessione REST in piu'.
    document.getElementById('btnTrafPolRun')?.addEventListener('click', loadTrafPolicies);
    document.getElementById('trafPolAction')?.addEventListener('change', loadTrafPolicies);

    // Listen for global tenant changes and update the traffic filter.
    window.addEventListener('globalTenantChanged', (/** @type {CustomEvent} */ e) => {
        const tenant = e.detail && e.detail.tenant;
        if (tenant && tenant !== 'all') {
            _flowsSelectedTenants = new Set([tenant]);
        } else {
            _flowsSelectedTenants = new Set(Object.keys(globalGroups || {}));
        }
        trafRefresh();
        loadTrafPolDeviceList();
    });
