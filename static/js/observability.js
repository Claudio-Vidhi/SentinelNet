// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
    // --- OBSERVABILITY SETTINGS (§11.5a) ---

    const OBS_LISTENERS = ['ipfix', 'sflow', 'syslog', 'netflow'];
    const OBS_DEFAULT_PORTS = { ipfix: 4739, sflow: 6343, syslog: 5514, netflow: 2055 };

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
                       placeholder="${OBS_DEFAULT_PORTS[l]}"
                       style="width:100px; padding:6px 10px; border-radius:0; border:1px solid var(--border);
                              background:var(--surface-3); color:var(--text); font-family:var(--font-code); font-size:12px;">
                <span style="font-size:11px; color:var(--text-muted);">UDP · ${L.hintObsDefaultPort || 'porta predefinita'} ${OBS_DEFAULT_PORTS[l]}</span>
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
            <div style="margin-bottom:8px; font-size:12px; color:var(--text-muted);">${L.hintObsListeners || "Attiva un protocollo e indica la porta UDP su cui SentinelNet resta in ascolto, poi configura l'export dei dispositivi verso questo host su quella porta. Le modifiche ai listener vengono applicate subito, senza riavviare l'applicazione."}</div>
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

    // Cancellazione definitiva: syslog_events e flow_aggregates oltre la soglia.
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

    // --- FLUSSI LIVE (fase 5): top talker -----------------------------------
    // showToast: MOVED to static/js/core.js

    // Autenticazione via cookie HttpOnly (apiFetch): nessun token lato JS.
    let flowsRefreshTimer = null;
    let flowsFetchInFlight = false;
    let _flowsRawData = [];                           // cache rows from last fetch
    let _flowsSelectedTenants = new Set(Object.keys(globalGroups || {}));
    let _flowsAllTenantsChecked = true;                // "Tutti" checkbox state
    let _deviceContextIp = null;                       // IP from global device context chip
    let _flowPanelFlow = null;                         // flow object currently shown in the detail panel

    // --- Filtro per origine dati + colonne dinamiche (flussi vs syslog) ---
    const FLOWS_SOURCES = ['all', 'netflow', 'ipfix', 'sflow', 'syslog'];
    const FLOWS_SOURCE_LABELS = { netflow: 'NetFlow', ipfix: 'IPFIX', sflow: 'sFlow', syslog: 'Syslog' };
    // Colonne del modo flusso che l'utente può nascondere (id → chiave i18n).
    const FLOW_TOGGLE_COLS = [
        { id: 'tenant',  lbl: 'thFlTenant' },
        { id: 'source',  lbl: 'thFlSource' },
        { id: 'proto',   lbl: 'thFlProto' },
        { id: 'packets', lbl: 'thFlPackets' },
        { id: 'flows',   lbl: 'thFlFlows' },
    ];
    let _flowsSource = 'all';
    let _flowsSyslogData = [];
    let _flowsHiddenCols = new Set(JSON.parse(localStorage.getItem('sentinelnet_flows_hidden_cols') || '[]'));
    // Traffico verso i collector (NetFlow/IPFIX/sFlow/Syslog/SNMP): sono flussi
    // veri ma sono rumore di misura. Default spento: si nasconde solo se lo
    // chiede l'utente, e resta a un click di distanza.
    let _flowsHideTelemetry = localStorage.getItem('sentinelnet_flows_hide_telemetry') === '1';

    // Single source of truth for the Traffico tab. Every view reads the window
    // and the tenant from here: the tab used to carry three independent window
    // selects (flows, protocol chart, SIEM), so a 15m top talker could sit next
    // to a 24h chart with nothing on screen saying so.
    const trafState = {
        window: '1h',
        metric: 'bytes',
        autoRefresh: true,
        hideTelemetry: _flowsHideTelemetry,
    };
    let _trafView = 'search';

    // One loader per view: switching pill loads only the view being opened.
    const TRAF_LOADERS = {
        flows:     () => loadTopTalkers(),
        search:    () => loadFlowSiemTab(),
        policies:  () => trafPoliciesShown(),
    };

    // Una lista sola: aggiungere una pill e dimenticare questo array lasciava
    // il pane precedente visibile sotto quello nuovo.
    const TRAF_VIEWS = ['search', 'flows', 'policies'];

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

    function trafSetMetric(value) {
        trafState.metric = value;
        trafRefresh();
    }

    function trafRefresh() {
        const loader = TRAF_LOADERS[_trafView];
        if (loader) loader();
    }

    function telemetryParam() { return _flowsHideTelemetry ? '&exclude_telemetry=true' : ''; }

    function flowsColHidden(id) { return _flowsHiddenCols.has(id); }

    function renderFlowsSourceChips() {
        const box = document.getElementById('flowsSourceChips');
        if (!box) return;
        const L = i18n[currentLang];
        box.innerHTML = FLOWS_SOURCES.map(s => {
            const active = s === _flowsSource;
            const label = s === 'all' ? (L.chipAllSources || 'Tutte le origini') : FLOWS_SOURCE_LABELS[s];
            return `<button class="btn btn-small" data-action="set-flows-source" data-source="${s}"
                style="padding:5px 14px; border-radius:0; font-size:12px;
                       ${active ? 'background:var(--cta); color:var(--cta-text); border-color:var(--cta);' : ''}">${label}</button>`;
        }).join('');
        const colsBtn = document.getElementById('flowsColsBtn');
        if (colsBtn) colsBtn.style.display = _flowsSource === 'syslog' ? 'none' : '';
    }

    function setFlowsSource(s) {
        _flowsSource = s;
        renderFlowsSourceChips();
        loadTopTalkers();
    }

    function setFlowsHideTelemetry(hide) {
        _flowsHideTelemetry = !!hide;
        trafState.hideTelemetry = _flowsHideTelemetry;
        localStorage.setItem('sentinelnet_flows_hide_telemetry', _flowsHideTelemetry ? '1' : '0');
        trafRefresh();
    }

    function toggleFlowsColsDropdown() {
        const dd = document.getElementById('flowsColsDropdown');
        if (!dd) return;
        if (dd.style.display === 'none') {
            const L = i18n[currentLang];
            dd.innerHTML = FLOW_TOGGLE_COLS.map(c => `
                <label style="display:flex; align-items:center; gap:8px; padding:4px 8px; cursor:pointer; font-size:13px;">
                    <input type="checkbox" class="flows-col-cb" data-col-id="${c.id}" ${flowsColHidden(c.id) ? '' : 'checked'}
                           style="accent-color:var(--primary);">
                    <span>${escapeHtml(L[c.lbl] || c.id)}</span>
                </label>`).join('');
            dd.style.display = 'block';
        } else {
            dd.style.display = 'none';
        }
    }

    function toggleFlowsCol(id, visible) {
        if (visible) _flowsHiddenCols.delete(id); else _flowsHiddenCols.add(id);
        localStorage.setItem('sentinelnet_flows_hidden_cols', JSON.stringify([..._flowsHiddenCols]));
        renderFlowsTable();
    }

    document.addEventListener('click', function(e) {
        const dd = document.getElementById('flowsColsDropdown');
        const btn = document.getElementById('flowsColsBtn');
        if (dd && btn && !dd.contains(e.target) && !btn.contains(e.target)) {
            dd.style.display = 'none';
        }
    });

    function renderFlowsThead() {
        const head = document.getElementById('flowsTableHead');
        if (!head) return;
        const L = i18n[currentLang];
        const th = (txt, style = '') => `<th ${style ? `style="${style}"` : ''}>${txt}</th>`;
        if (_flowsSource === 'syslog') {
            head.innerHTML = `<tr style="font-size:12px; text-align:left;">
                ${th(L.thSlWhen || 'Quando', 'padding:8px;')}${th(L.thFlTenant || 'Sede')}
                ${th(L.thSlDevice || 'Dispositivo')}${th(L.thSlSev || 'Sev')}
                ${th(L.thSlAction || 'Azione')}${th(L.thSlMsg || 'Messaggio')}</tr>`;
            return;
        }
        head.innerHTML = `<tr style="font-size:12px; text-align:left;">
            <th style="padding:8px;">#</th>
            ${flowsColHidden('tenant') ? '' : th(L.thFlTenant || 'Sede')}
            ${th(L.thFlSrc || 'Sorgente')}${th(L.thFlDst || 'Destinazione')}
            ${flowsColHidden('proto') ? '' : th(L.thFlProto || 'Proto/Porta')}
            ${flowsColHidden('source') ? '' : th(L.thFlSource || 'Origine')}
            ${th(L.thFlTraffic || 'Traffico', 'min-width:180px;')}
            ${flowsColHidden('packets') ? '' : th(L.thFlPackets || 'Pacchetti')}
            ${flowsColHidden('flows') ? '' : th(L.thFlFlows || 'Flussi')}</tr>`;
    }

    let _syslogVisibleRows = [];   // righe attualmente renderizzate, per il modale dettaglio

    function syslogTheadHtml() {
        const L = i18n[currentLang];
        const th = (txt, style = '') => `<th ${style ? `style="${style}"` : ''}>${txt}</th>`;
        return `<tr style="font-size:12px; text-align:left;">
            ${th(L.thSlWhen || 'Quando', 'padding:8px;')}${th(L.thFlTenant || 'Sede')}
            ${th(L.thSlDevice || 'Dispositivo')}${th(L.thSlSev || 'Sev')}
            ${th(L.thSlAction || 'Azione')}${th(L.thSlMsg || 'Messaggio')}</tr>`;
    }

    function renderSyslogTable(tbodyId = 'flowsTableBody') {
        const tbody = document.getElementById(tbodyId);
        const L = i18n[currentLang];
        const rows = _flowsSyslogData.filter(e =>
            _flowsSelectedTenants.size > 0 && _flowsSelectedTenants.has(e.tenant));
        _syslogVisibleRows = rows;
        if (rows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--text-muted);">${L.msgNoSyslog || 'Nessun evento syslog nel periodo selezionato.'}</td></tr>`;
            return;
        }
        const sevColor = s => s == null ? 'var(--text-muted)' : s <= 3 ? 'var(--danger)' : s <= 4 ? 'var(--warning)' : 'var(--text-muted)';
        tbody.innerHTML = rows.map((e, i) => `
            <tr style="font-size:12px; border-top:1px solid var(--border); cursor:pointer;" data-action="show-syslog-detail" data-index="${i}" data-i18n-title="titleSyslogRowHint" title="${escapeHtml(L.titleSyslogRowHint || 'Clicca per il dettaglio')}">
                <td style="padding:6px 8px; white-space:nowrap;">${new Date(e.ts * 1000).toLocaleString()}</td>
                <td>${escapeHtml(e.tenant)}</td>
                <td>${escapeHtml(e.device_ip || e.exporter_ip || '—')}</td>
                <td style="color:${sevColor(e.severity)}; font-weight:700;">${e.severity ?? '—'}</td>
                <td>${escapeHtml(e.action || '—')}</td>
                <td style="max-width:520px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(e.message || '')}</td>
            </tr>`).join('');
    }

    // Modale dettaglio: campi key=value del messaggio FortiOS in tabella + raw.
    function showSyslogDetail(idx) {
        const e = _syslogVisibleRows[idx];
        if (!e) return;
        const L = i18n[currentLang];
        const meta = [
            [L.thSlWhen || 'Quando', new Date(e.ts * 1000).toLocaleString()],
            [L.thFlTenant || 'Sede', e.tenant],
            [L.thSlDevice || 'Dispositivo', e.device_ip || e.exporter_ip || '—'],
            [L.thSlSev || 'Sev', e.severity ?? '—'],
            [L.thSlAction || 'Azione', e.action || '—'],
        ];
        const msg = e.message || '';
        // key=value / key="valore con spazi" (formato syslog FortiOS)
        const pairs = [...msg.matchAll(/([A-Za-z0-9_-]+)=("([^"]*)"|\S+)/g)]
            .map(m => [m[1], m[3] !== undefined ? m[3] : m[2]]);
        const kvRow = ([k, v]) => `<tr style="border-top:1px solid var(--border);">
            <td style="padding:4px 10px 4px 0; color:var(--text-muted); white-space:nowrap; vertical-align:top;">${escapeHtml(String(k))}</td>
            <td style="padding:4px 0; word-break:break-all;"><code style="font-family:var(--font-code); font-size:12px;">${escapeHtml(String(v))}</code></td></tr>`;
        document.getElementById('syslogDetailBody').innerHTML = `
            <table style="width:100%; border-collapse:collapse; margin-bottom:14px;">${meta.map(kvRow).join('')}</table>
            ${pairs.length ? `<h4 style="font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); margin:0 0 6px;">${tr('obsParsedFields')}</h4>
            <table style="width:100%; border-collapse:collapse; margin-bottom:14px;">${pairs.map(kvRow).join('')}</table>` : ''}
            <h4 style="font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); margin:0 0 6px;">Raw</h4>
            <pre style="margin:0; padding:10px; background:var(--surface-2); border:1px solid var(--border); border-radius:0; white-space:pre-wrap; word-break:break-all; font-family:var(--font-code); font-size:12px;">${escapeHtml(msg)}</pre>`;
        openModal('syslogDetailModal');
    }

    function closeSyslogDetail() {
        closeModal('syslogDetailModal');
    }

    function flowsTabShown() {
        renderFlowsSourceChips();
        // Header controls mirror trafState, not the other way round.
        const teleCb = document.getElementById('trafHideTelemetry');
        if (teleCb) teleCb.checked = trafState.hideTelemetry;
        const winSel = document.getElementById('trafWindow');
        if (winSel) winSel.value = trafState.window;
        const metricSel = document.getElementById('trafMetric');
        if (metricSel) metricSel.value = trafState.metric;
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

    async function loadTopTalkers() {
        if (flowsFetchInFlight) return;         // niente fetch sovrapposti
        flowsFetchInFlight = true;
        const tbody = document.getElementById('flowsTableBody');
        try {
            const w = trafState.window;
            const m = trafState.metric;
            if (_flowsSource === 'syslog') {
                const res = await apiFetch(`/api/observability/syslog?window=${encodeURIComponent(w)}&limit=200`);
                if (!res || !res.ok) {
                    if (res) tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--danger);">${tr('obsErrorLoadingSyslogEvents')}</td></tr>`;
                    return;
                }
                _flowsSyslogData = (await res.json()).events || [];
                document.getElementById('trafLastUpdate').textContent =
                    (tr('obsUpdated')) + new Date().toLocaleTimeString();
                renderFlowsThead();
                renderSyslogTable();
                renderSyslogAllSection();
                return;
            }
            const srcParam = _flowsSource === 'all' ? '' : `&source=${_flowsSource}`;
            const res = await apiFetch(`/api/observability/top?window=${encodeURIComponent(w)}&metric=${encodeURIComponent(m)}&limit=100${srcParam}${telemetryParam()}`);
            if (!res || !res.ok) {
                if (res) tbody.innerHTML = `<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--danger);">${tr('obsErrorLoadingFlows')}</td></tr>`;
                return;
            }
            const flows = (await res.json()).flows || [];
            _flowsRawData = flows;                     // cache for filtering
            document.getElementById('trafLastUpdate').textContent =
                (tr('obsUpdated')) + new Date().toLocaleTimeString();

            // "Tutte le origini": il syslog non è un flusso, va caricato a parte
            // e mostrato nella sezione dedicata sotto la tabella flussi.
            if (_flowsSource === 'all') {
                const sres = await apiFetch(`/api/observability/syslog?window=${encodeURIComponent(w)}&limit=200`);
                _flowsSyslogData = (sres && sres.ok) ? ((await sres.json()).events || []) : [];
            }

            // Render filtered table
            renderFlowsTable();
        } finally {
            flowsFetchInFlight = false;
        }
    }

    // Row key: the flow tuple, not the row index, so a click still finds its
    // flow after the tenant filter or a periodic refresh re-rendered the table.
    function flowKey(f) {
        return `${f.tenant}|${f.src_ip}|${f.dst_ip}|${f.protocol}|${f.dst_port}|${f.source ?? ''}`;
    }

    // Sezione syslog sotto la tabella flussi, visibile solo in modo "Tutte le origini".
    function renderSyslogAllSection() {
        const sec = document.getElementById('flowsSyslogAllSection');
        if (!sec) return;
        if (_flowsSource !== 'all' || _flowsSyslogData.length === 0) {
            sec.style.display = 'none';
            return;
        }
        sec.style.display = 'block';
        document.getElementById('flowsSyslogAllHead').innerHTML = syslogTheadHtml();
        renderSyslogTable('flowsSyslogAllBody');
        document.getElementById('flowsSyslogAllCount').textContent = `(${_syslogVisibleRows.length})`;
    }

    function renderFlowsTable() {
        renderFlowsThead();
        if (_flowsSource === 'syslog') { renderSyslogTable(); renderSyslogAllSection(); return; }
        renderSyslogAllSection();
        const tbody = document.getElementById('flowsTableBody');
        const m = trafState.metric;
        const L = i18n[currentLang];
        const hlTitle = escapeHtml(L.titleHighlightTopology || 'Evidenzia nella topologia');

        // Filter by selected tenants
        let filtered = _flowsRawData.length === 0 ? []
            : _flowsSelectedTenants.size === 0 ? []
            : _flowsRawData.filter(f => _flowsSelectedTenants.has(f.tenant));

        // Filter by device context chip (exporter IP)
        if (_deviceContextIp) {
            filtered = filtered.filter(f => f.exporter_ip === _deviceContextIp);
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--text-muted);">${tr('msgNoFlows') || 'Nessun flusso nel periodo selezionato.'}</td></tr>`;
            return;
        }

        const maxVal = Math.max(...filtered.map(f => m === 'bytes' ? f.total_bytes : f.total_packets));
        let rowNum = 1;
        tbody.innerHTML = filtered.map((f) => {
            const val = m === 'bytes' ? f.total_bytes : f.total_packets;
            const pct = maxVal ? (val / maxVal * 100).toFixed(1) : 0;
            const proto = ({6: 'TCP', 17: 'UDP', 1: 'ICMP'})[f.protocol] || f.protocol || '—';
            const key = flowKey(f);
            const srcLabel = FLOWS_SOURCE_LABELS[f.source] || '—';
            return `<tr style="font-size:12px; border-top:1px solid var(--border); cursor:pointer;" data-action="open-flow-detail" data-key="${escapeHtml(key)}">
                    <td style="padding:6px 8px;">${rowNum++}</td>
                    ${flowsColHidden('tenant') ? '' : `<td>${escapeHtml(f.tenant)}</td>`}
                    <td><a href="javascript:void(0)" data-action="flow-hl-topo" data-ip="${escapeHtml(f.src_ip)}" title="${hlTitle}">${escapeHtml(f.src_ip)}</a></td>
                    <td><a href="javascript:void(0)" data-action="flow-hl-topo" data-ip="${escapeHtml(f.dst_ip)}" title="${hlTitle}">${escapeHtml(f.dst_ip)}</a></td>
                    ${flowsColHidden('proto') ? '' : `<td>${proto}/${f.dst_port ?? '—'}</td>`}
                    ${flowsColHidden('source') ? '' : `<td><span style="font-size:11px; padding:2px 8px; border-radius:0; background:var(--surface-3);">${srcLabel}</span></td>`}
                    <td><div style="display:flex; align-items:center; gap:8px;">
                        <div style="flex:1; height:7px; background:var(--surface-3); border-radius:0;"><div style="height:100%; width:${pct}%; background:var(--primary); border-radius:0;"></div></div>
                        <span style="min-width:64px;">${fmtBytes(f.total_bytes)}</span></div></td>
                    ${flowsColHidden('packets') ? '' : `<td>${f.total_packets}</td>`}
                    ${flowsColHidden('flows') ? '' : `<td>${f.flow_count}</td>`}
                </tr>`;
        }).join('');
    }

    // --- Pannello dettaglio flusso (slide-in) ---------------------------

    function openFlowDetailPanelByKey(key, evt) {
        if (evt && evt.target && evt.target.closest('input, a')) return; // checkbox/link già gestiti (stopPropagation)
        const f = _flowsRawData.find(row => flowKey(row) === key);
        if (f) openFlowDetailPanel(f);
    }

    function openFlowDetailPanel(f) {
        _flowPanelFlow = f;
        const proto = ({6: 'TCP', 17: 'UDP', 1: 'ICMP'})[f.protocol] || f.protocol || '—';
        const row = (label, value) => `<tr><td style="padding:4px 8px 4px 0; color:var(--text-muted); white-space:nowrap;">${label}</td><td style="padding:4px 0;">${value}</td></tr>`;
        const body = document.getElementById('flowDetailPanelBody');
        const L = i18n[currentLang];
        body.innerHTML = `
            <table style="width:100%; font-size:13px; border-collapse:collapse; margin-bottom:14px;">
                ${row(L.thFlTenant || 'Sede', escapeHtml(f.tenant))}
                ${row(L.thFlSrc || 'Sorgente', `<a href="javascript:void(0)" data-action="detail-hl-topo" data-ip="${escapeHtml(f.src_ip)}">${escapeHtml(f.src_ip)}</a>`)}
                ${row(L.thFlDst || 'Destinazione', `<a href="javascript:void(0)" data-action="detail-hl-topo" data-ip="${escapeHtml(f.dst_ip)}">${escapeHtml(f.dst_ip)}</a>`)}
                ${row(L.thFlProto || 'Proto/Porta', `${proto}/${f.dst_port ?? '—'}`)}
                ${row(L.thFlTraffic || 'Traffico', fmtBytes(f.total_bytes))}
                ${row(L.thFlPackets || 'Pacchetti', f.total_packets)}
                ${row(tr('obsAggregatedFlows'), f.flow_count)}
            </table>
            <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:16px;">
                <button class="btn" style="text-align:left;" data-action="detail-hl-topo" data-ip="${escapeHtml(f.src_ip)}">
                    <i class="fa-solid fa-diagram-project"></i> ${tr('obsShowSourceInTopology')}
                </button>
                <button class="btn" style="text-align:left;" data-action="detail-hl-topo" data-ip="${escapeHtml(f.dst_ip)}">
                    <i class="fa-solid fa-diagram-project"></i> ${tr('obsShowDestinationInTopology')}
                </button>
            </div>
            <h5 style="margin:0 0 8px 0;">${tr('obsClientSource')}</h5>
            <div id="flowPanelClientMap" style="font-size:12px; color:var(--text-muted);">${tr('obsSearching')}</div>
        `;
        document.getElementById('flowDetailPanel').style.display = 'block';
        loadFlowPanelClientMap(f.src_ip);
    }

    function closeFlowDetailPanel() {
        document.getElementById('flowDetailPanel').style.display = 'none';
        _flowPanelFlow = null;
    }

    // Riusa l'endpoint del Client Map (§ tab ARP) — nessun nuovo endpoint backend.
    async function loadFlowPanelClientMap(ip) {
        const box = document.getElementById('flowPanelClientMap');
        if (!box) return;
        try {
            const res = await apiFetch('/api/arp/client-map?' + new URLSearchParams({ ip }).toString());
            if (!res || !res.ok) { box.textContent = tr('obsClientMapLookupUnavailable'); return; }
            const d = await res.json();
            const rows = d.results || [];
            if (rows.length === 0) {
                box.textContent = tr('obsNoKnownMacIp');
                return;
            }
            box.innerHTML = rows.map(r => `
                <div style="padding:8px; border:1px solid var(--border); border-radius:0; margin-bottom:6px;">
                    <div><b>MAC</b>: <code>${escapeHtml(r.mac)}</code></div>
                    <div><b>Gateway</b>: ${escapeHtml(r.source_name || '')} <span style="color:var(--text-muted);">${escapeHtml(r.source_ip || '')}</span></div>
                    <div><b>${tr('uiAccessSwitch')}</b>: ${r.switch_ip ? `${escapeHtml(r.switch_name || '')} ${escapeHtml(r.switch_ip)}` : '—'}</div>
                    <div><b>${tr('obsPort')}</b>: ${escapeHtml(r.switch_port || '—')}</div>
                </div>`).join('');
        } catch (e) {
            box.textContent = tr('obsClientMapLookupUnavailable');
        }
    }

    // Mappatura IP → nodo topologia: i nodi Vis.js usano l'IP del device come
    // id (vedi loadInteractiveMap: n.id confrontato con globalDevices[].IP).
    function highlightInTopology(ip) {
        switchTab('tab-map-interactive',
                  document.querySelector(`.nav-item[onclick*="'tab-map-interactive'"]`));
        const tryFocus = (attempt) => {
            if (networkInstance && networkInstance.body.data.nodes.get(ip)) {
                networkInstance.selectNodes([ip]);
                networkInstance.focus(ip, { scale: 1.3, animation: true });
                return;
            }
            if (attempt < 20) { setTimeout(() => tryFocus(attempt + 1), 250); return; }
            showToast(tr('obsNodeNotPresentIn'), 'warning');
        };
        tryFocus(0);
    }

    // Expose functions globally for UI
    window.loadObsHealth = loadObsHealth;
    window.pruneObsLogs = pruneObsLogs;
    window.trafSelectedTenants = () => new Set(_flowsSelectedTenants);
    window.trafState = trafState;
    window.trafSwitchView = trafSwitchView;
    window.trafSetWindow = trafSetWindow;
    window.trafSetMetric = trafSetMetric;
    window.trafRefresh = trafRefresh;

    // Delegated click and change event listeners
    document.getElementById('flowsSourceChips')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="set-flows-source"]');
        if (btn && btn.dataset.source) setFlowsSource(btn.dataset.source);
    });

    document.getElementById('flowsColsDropdown')?.addEventListener('change', (e) => {
        const cb = e.target.closest('.flows-col-cb');
        if (cb && cb.dataset.colId) toggleFlowsCol(cb.dataset.colId, cb.checked);
    });

    document.getElementById('flowsTableBody')?.addEventListener('click', (e) => {
        const sysRow = e.target.closest('tr[data-action="show-syslog-detail"]');
        if (sysRow && sysRow.dataset.index != null) {
            showSyslogDetail(Number(sysRow.dataset.index));
            return;
        }
        const hlLink = e.target.closest('[data-action="flow-hl-topo"]');
        if (hlLink && hlLink.dataset.ip) {
            e.stopPropagation();
            highlightInTopology(hlLink.dataset.ip);
            return;
        }
        const flowRow = e.target.closest('tr[data-action="open-flow-detail"]');
        if (flowRow && flowRow.dataset.key) {
            openFlowDetailPanelByKey(flowRow.dataset.key, e);
        }
    });

    document.getElementById('flowsSyslogAllBody')?.addEventListener('click', (e) => {
        const sysRow = e.target.closest('tr[data-action="show-syslog-detail"]');
        if (sysRow && sysRow.dataset.index != null) {
            showSyslogDetail(Number(sysRow.dataset.index));
        }
    });

    document.getElementById('flowDetailPanelBody')?.addEventListener('click', (e) => {
        const hl = e.target.closest('[data-action="detail-hl-topo"]');
        if (hl && hl.dataset.ip) {
            highlightInTopology(hl.dataset.ip);
            closeFlowDetailPanel();
            return;
        }
    });

    document.getElementById('obsSettingsBody')?.addEventListener('click', (e) => {
        if (e.target.closest('[data-action="save-obs-settings"]')) saveObsSettings();
        if (e.target.closest('[data-action="prune-obs-logs"]')) pruneObsLogs();
    });

    // Static event listeners for Traffic / Flows / Observability tab
    document.getElementById('trafWindow')?.addEventListener('change', (e) => trafSetWindow(e.target.value));
    document.getElementById('trafMetric')?.addEventListener('change', (e) => trafSetMetric(e.target.value));
    document.getElementById('btnTrafRefresh')?.addEventListener('click', trafRefresh);
    document.getElementById('trafHideTelemetry')?.addEventListener('change', (e) => setFlowsHideTelemetry(e.target.checked));
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

    document.getElementById('flowsColsBtn')?.addEventListener('click', toggleFlowsColsDropdown);
    document.getElementById('btnCloseFlowDetail')?.addEventListener('click', closeFlowDetailPanel);

    document.getElementById('syslogDetailModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'syslogDetailModal' || e.target.closest('#btnCloseSyslogDetail')) {
            closeSyslogDetail();
        }
    });

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

    // Listen for device context changes: filter flows by exporter IP.
    window.addEventListener('globalDeviceContextChanged', (/** @type {CustomEvent} */ e) => {
        _deviceContextIp = (e.detail && e.detail.ip) || null;
        trafRefresh();
    });

