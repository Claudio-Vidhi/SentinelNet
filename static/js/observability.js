    // --- OBSERVABILITY SETTINGS (§11.5a) ---

    const OBS_LISTENERS = ['ipfix', 'sflow', 'syslog', 'netflow'];
    const OBS_DEFAULT_PORTS = { ipfix: 4739, sflow: 6343, syslog: 5514, netflow: 2055 };

    async function loadObsSettings() {
        if (currentRole !== 'admin') return;
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
                <label data-i18n="lblObsBind">Indirizzo di ascolto (bind)</label>
                <input id="obs_bind" type="text" value="${escapeHtml(d.bind || '')}" style="padding-left:12px;">
            </div>
            <div class="form-group" style="max-width:200px;">
                <label data-i18n="lblObsApiPoll">Intervallo polling API (s)</label>
                <input id="obs_api_poll_s" type="number" min="1" value="${d.api_poll_s != null ? d.api_poll_s : ''}" style="padding-left:12px;">
            </div>
            <div class="form-group" style="max-width:280px;">
                <label data-i18n="lblObsSnmpPoll">Intervallo polling SNMP (s)</label>
                <input id="obs_snmp_poll_s" type="number" min="0" value="${d.snmp_poll_s != null ? d.snmp_poll_s : 0}" style="padding-left:12px;">
                <small style="color:var(--text-muted); font-size:11px;" data-i18n="hintObsSnmpPoll">0 = spento. Interroga solo gli apparati che hanno una community configurata nella loro scheda.</small>
            </div>
            <div class="form-group" style="max-width:280px;">
                <label data-i18n="lblObsLinuxPoll">Intervallo polling host Linux (s)</label>
                <input id="obs_linux_poll_s" type="number" min="0" value="${d.linux_poll_s != null ? d.linux_poll_s : 0}" style="padding-left:12px;">
                <small style="color:var(--text-muted); font-size:11px;" data-i18n="hintObsLinuxPoll">0 = spento. Apre una sessione SSH non privilegiata verso gli host con vendor «linux» e ne rileva CPU, memoria e disco.</small>
            </div>
            <div style="margin-top:10px; margin-bottom:2px; font-size:12px; color:var(--text-muted); text-transform:uppercase; font-weight:700;" data-i18n="lblObsListeners">Listener</div>
            <div style="margin-bottom:8px; font-size:12px; color:var(--text-muted);">${L.hintObsListeners || "Attiva un protocollo e indica la porta UDP su cui SentinelNet resta in ascolto, poi configura l'export dei dispositivi verso questo host su quella porta. Le modifiche ai listener vengono applicate subito, senza riavviare l'applicazione."}</div>
            ${listenerRows}
            <div style="margin-top:12px;">
                <button id="btnSaveObsSettings" class="btn btn-primary btn-small" data-action="save-obs-settings" data-i18n="btnSave">
                    <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(L.btnSave || (currentLang === 'en' ? 'Save' : 'Salva'))}
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
        const en = currentLang === 'en';
        const res = await apiFetch('/api/observability/health');
        if (!res || !res.ok) { box.innerHTML = ''; return; }
        const h = await res.json();
        const listeners = h.listeners || {};
        const badges = Object.keys(listeners).map(name => {
            const active = listeners[name] && listeners[name].active;
            return `<span class="status ${active ? 'ok' : 'warn'}" style="margin-right:6px;">
                        <span class="led ${active ? 'led-success' : 'led-warning'}"></span>${escapeHtml(name)}
                    </span>`;
        }).join('') || `<span style="color:var(--text-muted); font-size:12px;">${escapeHtml(en ? 'no listener' : 'nessun listener')}</span>`;
        const mb = (h.db_size_bytes || 0) / (1024 * 1024);
        box.innerHTML = `
            <h4 style="margin:0 0 10px; font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted);">
                <i class="fa-solid fa-heart-pulse" style="color:var(--primary);"></i>
                ${escapeHtml(L.obsHealthTitle || (en ? 'Pipeline health' : 'Stato della pipeline'))}
            </h4>
            <div style="display:flex; gap:16px; flex-wrap:wrap; align-items:center; font-size:12px; margin-bottom:12px;">
                <span>${escapeHtml(en ? 'Enabled' : 'Abilitata')}:
                    <span class="status ${h.enabled ? 'ok' : 'warn'}">${h.enabled ? (en ? 'yes' : 'si') : 'no'}</span></span>
                <span>${escapeHtml(en ? 'Listeners' : 'Listener')}: ${badges}</span>
                <span>DB: <b>${mb.toFixed(1)} MB</b></span>
                <span>${escapeHtml(en ? 'Schema' : 'Schema')}: <b>${escapeHtml(String(h.schema_version ?? '—'))}</b></span>
            </div>
            <p style="margin:0 0 8px; font-size:12px; color:var(--text-muted);">
                ${escapeHtml(en
                    ? 'A background job already prunes by the retention set below, per table. This is a one-off purge with a horizon of your choosing.'
                    : 'Un job in background pota gia’ secondo la retention impostata piu’ sotto, tabella per tabella. Questa e’ una pulizia una-tantum con l’orizzonte che scegli.')}
            </p>
            <div style="display:flex; gap:8px; align-items:flex-end; flex-wrap:wrap;">
                <div class="form-group" style="margin-bottom:0; max-width:170px;">
                    <label for="obsPruneDays">${escapeHtml(L.obsPruneDays || (en ? 'Keep last (days)' : 'Conserva (giorni)'))}</label>
                    <input id="obsPruneDays" type="number" min="1" max="3650" value="30" style="padding-left:12px;">
                </div>
                <button id="btnPruneObsLogs" class="btn btn-danger btn-small" style="width:auto; margin:0;" data-action="prune-obs-logs">
                    <i class="fa-solid fa-broom"></i> ${escapeHtml(L.obsPruneRun || (en ? 'Purge older logs' : 'Elimina i log vecchi'))}
                </button>
            </div>`;
    }

    // Cancellazione definitiva: syslog_events e flow_aggregates oltre la soglia.
    async function pruneObsLogs() {
        const en = currentLang === 'en';
        const days = parseInt(document.getElementById('obsPruneDays')?.value, 10);
        if (!days || days < 1) {
            showToast(en ? 'Enter a retention in days.' : 'Indica una retention in giorni.', 'warning');
            return;
        }
        const question = en
            ? `Permanently delete syslog events and flow aggregates older than ${days} days?`
            : `Eliminare definitivamente eventi syslog e aggregati di flusso piu' vecchi di ${days} giorni?`;
        if (!confirm(question)) return;
        const res = await apiFetch('/api/observability/prune-logs', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ days })
        });
        if (!res || !res.ok) {
            showToast(en ? 'Purge failed.' : 'Eliminazione non riuscita.', 'error');
            return;
        }
        showToast(en ? 'Old logs purged.' : 'Log vecchi eliminati.', 'success');
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
            const msg = (e && e.detail) || (currentLang === 'en' ? 'Save error.' : 'Errore nel salvataggio.');
            if (errEl) errEl.textContent = msg; else alert(msg);
            return;
        }
        const data = await res.json();
        const banner = document.getElementById('obsRestartBanner');
        if (data && data.restart_required) {
            if (banner) banner.style.display = 'block';
            showToast(i18n[currentLang].msgObsRestartRequired || 'Riavvio richiesto per applicare le modifiche.', 'warning');
        } else {
            if (banner) banner.style.display = 'none';
            showToast(i18n[currentLang].msgObsApplied || 'Modifiche applicate.', 'success');
        }
    }

    // --- FLUSSI LIVE (fase 5): top talker + anomalie correlate -------------
    // showToast: MOVED to static/js/core.js

    // Autenticazione via cookie HttpOnly (apiFetch): nessun token lato JS.
    let flowsRefreshTimer = null;
    let flowsFetchInFlight = false;
    let aiAttachTopFlowsOnce = false;
    let aiAttachFlowKeysOnce = null;                  // 11.3: tuple dei flussi selezionati da allegare una sola volta
    let _flowsRawData = [];                           // cache rows from last fetch
    let _flowsSelectedTenants = new Set();             // selected tenant names
    let _flowsAllTenantsChecked = true;                // "Tutti" checkbox state
    let _flowsSelectedKeys = new Set();                // selected flow keys (tuple string, survives filter/refresh)
    let _flowPanelFlow = null;                         // flow object currently shown in the detail panel
    let _anomIpFilter = null;                          // {src, dst} client-side filter for the anomalies table

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
    let _trafView = 'overview';

    // Loader per vista: registrato dal task che porta dentro il contenuto.
    // Cambiare pill carica solo la vista che si apre, non tutte e quattro.
    const TRAF_LOADERS = {
        overview:  () => { loadTopTalkers(); loadObsProtocolDist(); },
        flows:     () => loadTopTalkers(),
        search:    () => loadFlowSiemTab(),
        anomalies: () => loadAnomalies(),
    };

    function trafSwitchView(view) {
        if (!document.getElementById('trafPane-' + view)) return;
        _trafView = view;
        for (const v of ['overview', 'flows', 'search', 'anomalies']) {
            const pane = document.getElementById('trafPane-' + v);
            const pill = document.getElementById('trafPill-' + v);
            if (pane) pane.style.display = (v === view) ? '' : 'none';
            if (pill) pill.classList.toggle('active', v === view);
        }
        const loader = TRAF_LOADERS[view];
        if (loader) loader();
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
        loadTopTalkers();          // ricarica anche il flowgraph e la KPI strip
        loadObsProtocolDist();
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
            <th style="padding:8px;"><input type="checkbox" id="flowsSelectAll" style="accent-color:var(--primary);" title="${escapeHtml(L.lnkSelectAll || 'Seleziona tutti')}"></th>
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
            ${pairs.length ? `<h4 style="font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); margin:0 0 6px;">${currentLang === 'en' ? 'Parsed fields' : 'Campi'}</h4>
            <table style="width:100%; border-collapse:collapse; margin-bottom:14px;">${pairs.map(kvRow).join('')}</table>` : ''}
            <h4 style="font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--text-muted); margin:0 0 6px;">Raw</h4>
            <pre style="margin:0; padding:10px; background:var(--surface-2); border:1px solid var(--border); border-radius:0; white-space:pre-wrap; word-break:break-all; font-family:var(--font-code); font-size:12px;">${escapeHtml(msg)}</pre>`;
        document.getElementById('syslogDetailModal').style.display = 'flex';
    }

    function closeSyslogDetail() {
        document.getElementById('syslogDetailModal').style.display = 'none';
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
                banner.textContent = currentLang === 'en'
                    ? '⚠️ Observability disabled: no listener running. Enable it with SENTINELNET_OBS_ENABLE=1 (or "observability.enabled" in app_settings.json) and restart.'
                    : '⚠️ Osservabilità disabilitata: nessun listener in ascolto. Abilita con SENTINELNET_OBS_ENABLE=1 (o "observability.enabled" in app_settings.json) e riavvia.';
                banner.style.display = 'block';
            } else if (!anyActive) {
                banner.textContent = currentLang === 'en'
                    ? '⚠️ Observability enabled but no active listener (bind failed?). Check /api/observability/health and the startup logs.'
                    : '⚠️ Osservabilità abilitata ma nessun listener attivo (bind fallito?). Controlla /api/observability/health e i log di avvio.';
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
                    if (res) tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--danger);">${currentLang === 'en' ? 'Error loading syslog events.' : 'Errore nel caricamento degli eventi syslog.'}</td></tr>`;
                    return;
                }
                _flowsSyslogData = (await res.json()).events || [];
                document.getElementById('trafLastUpdate').textContent =
                    (currentLang === 'en' ? 'Updated: ' : 'Aggiornato: ') + new Date().toLocaleTimeString();
                rebuildFlowsTenantList(_flowsSyslogData);
                renderFlowsThead();
                renderSyslogTable();
                renderSyslogAllSection();
                return;
            }
            const srcParam = _flowsSource === 'all' ? '' : `&source=${_flowsSource}`;
            const res = await apiFetch(`/api/observability/top?window=${encodeURIComponent(w)}&metric=${encodeURIComponent(m)}&limit=100${srcParam}${telemetryParam()}`);
            if (!res || !res.ok) {
                if (res) tbody.innerHTML = `<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--danger);">${currentLang === 'en' ? 'Error loading flows.' : 'Errore nel caricamento dei flussi.'}</td></tr>`;
                return;
            }
            const flows = (await res.json()).flows || [];
            _flowsRawData = flows;                     // cache for filtering
            document.getElementById('trafLastUpdate').textContent =
                (currentLang === 'en' ? 'Updated: ' : 'Aggiornato: ') + new Date().toLocaleTimeString();

            // "Tutte le origini": il syslog non è un flusso, va caricato a parte
            // e mostrato nella sezione dedicata sotto la tabella flussi.
            if (_flowsSource === 'all') {
                const sres = await apiFetch(`/api/observability/syslog?window=${encodeURIComponent(w)}&limit=200`);
                _flowsSyslogData = (sres && sres.ok) ? ((await sres.json()).events || []) : [];
            }

            // Rebuild tenant checkbox list from distinct tenants in fetched data
            // (in modo "all" include anche i tenant presenti solo nel syslog)
            rebuildFlowsTenantList(_flowsSource === 'all' ? flows.concat(_flowsSyslogData) : flows);

            // Render filtered table
            renderFlowsTable();
            loadFlowGraph(w);
        } finally {
            flowsFetchInFlight = false;
        }
    }

    function fmtRate(bps) {
        if (!bps) return '0 bps';
        if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
        if (bps >= 1e6) return (bps / 1e6).toFixed(2) + ' Mbps';
        if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
        return Math.round(bps) + ' bps';
    }

    function rebuildFlowsTenantList(flows) {
        // Extract distinct tenants from flows, maintaining order of appearance
        const tenants = [...new Set(flows.map(f => f.tenant))].sort();
        const listDiv = document.getElementById('trafTenantList');
        if (!listDiv) return;

        // Preserve checked state for tenants that still exist
        const newSelected = new Set();
        for (const t of tenants) {
            if (_flowsSelectedTenants.has(t) || _flowsAllTenantsChecked) {
                newSelected.add(t);
            }
        }
        _flowsSelectedTenants = newSelected;

        // Update checkbox list
        listDiv.innerHTML = tenants.map(t => `
            <label style="display:flex; align-items:center; gap:8px; padding:6px 8px; cursor:pointer;">
                <input type="checkbox" class="flows-tenant-cb" value="${escapeHtml(t)}"
                       ${newSelected.has(t) ? 'checked' : ''} style="accent-color:var(--primary);">
                <span>${escapeHtml(t)}</span>
            </label>
        `).join('');

        // Update "Tutti" checkbox state
        const allCheckbox = document.getElementById('trafTenantAll');
        if (allCheckbox) {
            allCheckbox.checked = tenants.length > 0 && tenants.every(t => newSelected.has(t));
            _flowsAllTenantsChecked = allCheckbox.checked;
        }

        // Update button label
        updateFlowsTenantButtonLabel(tenants.length);
    }

    function updateFlowsTenantSelection() {
        const checkboxes = Array.from(document.querySelectorAll('#trafTenantList input[type="checkbox"]'));
        const selected = new Set(checkboxes.filter(cb => cb.checked).map(cb => cb.value));
        _flowsSelectedTenants = selected;

        // Update "Tutti" checkbox
        const allCheckbox = document.getElementById('trafTenantAll');
        const totalTenants = checkboxes.length;
        const checkedCount = checkboxes.filter(cb => cb.checked).length;
        if (allCheckbox) {
            allCheckbox.checked = checkedCount === totalTenants;
            _flowsAllTenantsChecked = allCheckbox.checked;
        }

        updateFlowsTenantButtonLabel(totalTenants);
        renderFlowsTable();
    }

    function toggleTrafTenantAll() {
        const allCheckbox = document.getElementById('trafTenantAll');
        const checkboxes = Array.from(document.querySelectorAll('#trafTenantList input[type="checkbox"]'));
        const shouldCheck = allCheckbox.checked;
        checkboxes.forEach(cb => cb.checked = shouldCheck);
        _flowsSelectedTenants = shouldCheck ? new Set(checkboxes.map(cb => cb.value)) : new Set();
        _flowsAllTenantsChecked = shouldCheck;
        updateFlowsTenantButtonLabel(checkboxes.length);
        renderFlowsTable();
    }

    function updateFlowsTenantButtonLabel(totalTenants) {
        const btn = document.getElementById('trafTenantBtn');
        if (!btn) return;
        const L = i18n[currentLang];
        let label = 'Tenants';
        if (totalTenants === 0) {
            label = 'Tenants';
        } else if (_flowsSelectedTenants.size === 0) {
            label = L.lblNoTenant || 'Nessun tenant';
        } else if (_flowsSelectedTenants.size === totalTenants) {
            label = L.optArpAllTenants || 'Tutti i tenant';
        } else {
            label = `${_flowsSelectedTenants.size} tenant`;
        }
        btn.textContent = label;
        // Re-add icon
        btn.innerHTML = `<i class="fa-solid fa-filter"></i> ${label}`;
    }

    // Chiave di selezione del flusso: per tupla, non per indice riga, così la
    // selezione sopravvive al filtro tenant (11.1) e al refresh periodico.
    function flowKey(f) {
        return `${f.tenant}|${f.src_ip}|${f.dst_ip}|${f.protocol}|${f.dst_port}|${f.source ?? ''}`;
    }

    // Input per 11.3 (analisi AI sulle sole righe selezionate).
    function getSelectedFlows() {
        return _flowsRawData.filter(f => _flowsSelectedKeys.has(flowKey(f)));
    }

    // 11.3: tupla identificativa (SOLO identificatori — nessun byte/pacchetto:
    // il server ri-deriva i totali dal DB).
    function flowToKey(f) {
        return {
            src_ip: f.src_ip,
            dst_ip: f.dst_ip,
            protocol: Number(f.protocol),
            dst_port: (f.dst_port === undefined || f.dst_port === null || f.dst_port === '')
                ? null : Number(f.dst_port)
        };
    }

    function toggleFlowRowSelect(key, checked) {
        if (checked) _flowsSelectedKeys.add(key); else _flowsSelectedKeys.delete(key);
        syncFlowsSelectAllCheckbox();
    }

    function toggleFlowsSelectAll(cb) {
        const rowBoxes = Array.from(document.querySelectorAll('#flowsTableBody input.flow-row-check'));
        rowBoxes.forEach(box => {
            box.checked = cb.checked;
            if (cb.checked) _flowsSelectedKeys.add(box.dataset.key);
            else _flowsSelectedKeys.delete(box.dataset.key);
        });
    }

    function syncFlowsSelectAllCheckbox() {
        const all = document.getElementById('flowsSelectAll');
        const rowBoxes = Array.from(document.querySelectorAll('#flowsTableBody input.flow-row-check'));
        if (all) all.checked = rowBoxes.length > 0 && rowBoxes.every(b => b.checked);
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
        const filtered = _flowsRawData.length === 0 ? []
            : _flowsSelectedTenants.size === 0 ? []
            : _flowsRawData.filter(f => _flowsSelectedTenants.has(f.tenant));

        // Selection may reference flows no longer present (e.g. window change); prune lazily.
        const filteredKeys = new Set(filtered.map(flowKey));
        _flowsSelectedKeys.forEach(k => { if (!filteredKeys.has(k) && !_flowsRawData.some(f => flowKey(f) === k)) _flowsSelectedKeys.delete(k); });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--text-muted);">${i18n[currentLang].msgNoFlows || 'Nessun flusso nel periodo selezionato.'}</td></tr>`;
            const all = document.getElementById('flowsSelectAll');
            if (all) all.checked = false;
            return;
        }

        const maxVal = Math.max(...filtered.map(f => m === 'bytes' ? f.total_bytes : f.total_packets));
        let rowNum = 1;
        tbody.innerHTML = filtered.map((f) => {
            const val = m === 'bytes' ? f.total_bytes : f.total_packets;
            const pct = maxVal ? (val / maxVal * 100).toFixed(1) : 0;
            const proto = ({6: 'TCP', 17: 'UDP', 1: 'ICMP'})[f.protocol] || f.protocol || '—';
            const key = flowKey(f);
            const checked = _flowsSelectedKeys.has(key) ? 'checked' : '';
            const srcLabel = FLOWS_SOURCE_LABELS[f.source] || '—';
            return `<tr style="font-size:12px; border-top:1px solid var(--border); cursor:pointer;" data-action="open-flow-detail" data-key="${escapeHtml(key)}">
                    <td style="padding:6px 8px;"><input type="checkbox" class="flow-row-check" data-key="${escapeHtml(key)}" ${checked} style="accent-color:var(--primary);"></td>
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
        syncFlowsSelectAllCheckbox();
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
        const en = currentLang === 'en';
        body.innerHTML = `
            <table style="width:100%; font-size:13px; border-collapse:collapse; margin-bottom:14px;">
                ${row(L.thFlTenant || 'Sede', escapeHtml(f.tenant))}
                ${row(L.thFlSrc || 'Sorgente', `<a href="javascript:void(0)" data-action="detail-hl-topo" data-ip="${escapeHtml(f.src_ip)}">${escapeHtml(f.src_ip)}</a>`)}
                ${row(L.thFlDst || 'Destinazione', `<a href="javascript:void(0)" data-action="detail-hl-topo" data-ip="${escapeHtml(f.dst_ip)}">${escapeHtml(f.dst_ip)}</a>`)}
                ${row(L.thFlProto || 'Proto/Porta', `${proto}/${f.dst_port ?? '—'}`)}
                ${row(L.thFlTraffic || 'Traffico', fmtBytes(f.total_bytes))}
                ${row(L.thFlPackets || 'Pacchetti', f.total_packets)}
                ${row(en ? 'Aggregated flows' : 'Flussi aggregati', f.flow_count)}
            </table>
            <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:16px;">
                <button class="btn" style="text-align:left;" data-action="detail-hl-topo" data-ip="${escapeHtml(f.src_ip)}">
                    <i class="fa-solid fa-diagram-project"></i> ${en ? 'Show source in topology' : 'Mostra sorgente in topologia'}
                </button>
                <button class="btn" style="text-align:left;" data-action="detail-hl-topo" data-ip="${escapeHtml(f.dst_ip)}">
                    <i class="fa-solid fa-diagram-project"></i> ${en ? 'Show destination in topology' : 'Mostra destinazione in topologia'}
                </button>
                <button class="btn" style="text-align:left;" data-action="detail-anomalies">
                    <i class="fa-solid fa-triangle-exclamation"></i> ${en ? 'See anomalies for this flow' : 'Vedi anomalie di questo flusso'}
                </button>
                <button class="btn requires-write" style="text-align:left;" data-action="detail-ai-flow" title="${en ? 'Send ONLY this flow to the AI assistant (identifiers; totals re-derived server-side)' : 'Invia SOLO questo flusso all\'assistente AI (identificatori; totali ri-derivati dal server)'}">
                    <i class="fa-solid fa-robot"></i> ${L.btnAnalyzeAi || 'Analizza con AI'}
                </button>
            </div>
            <h5 style="margin:0 0 8px 0;">${en ? 'Client (source)' : 'Client (sorgente)'}</h5>
            <div id="flowPanelClientMap" style="font-size:12px; color:var(--text-muted);">${en ? 'Searching…' : 'Ricerca in corso…'}</div>
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
            const en = currentLang === 'en';
            const res = await apiFetch('/api/arp/client-map?' + new URLSearchParams({ ip }).toString());
            if (!res || !res.ok) { box.textContent = en ? 'Client-map lookup unavailable.' : 'Ricerca client-map non disponibile.'; return; }
            const d = await res.json();
            const rows = d.results || [];
            if (rows.length === 0) {
                box.textContent = en ? 'No known MAC/IP binding for this source.' : 'Nessun binding MAC/IP noto per questa sorgente.';
                return;
            }
            box.innerHTML = rows.map(r => `
                <div style="padding:8px; border:1px solid var(--border); border-radius:0; margin-bottom:6px;">
                    <div><b>MAC</b>: <code>${escapeHtml(r.mac)}</code></div>
                    <div><b>Gateway</b>: ${escapeHtml(r.source_name || '')} <span style="color:var(--text-muted);">${escapeHtml(r.source_ip || '')}</span></div>
                    <div><b>${en ? 'Access switch' : 'Switch di accesso'}</b>: ${r.switch_ip ? `${escapeHtml(r.switch_name || '')} ${escapeHtml(r.switch_ip)}` : '—'}</div>
                    <div><b>${en ? 'Port' : 'Porta'}</b>: ${escapeHtml(r.switch_port || '—')}</div>
                </div>`).join('');
        } catch (e) {
            box.textContent = currentLang === 'en' ? 'Client-map lookup unavailable.' : 'Ricerca client-map non disponibile.';
        }
    }

    // Salta alla tabella anomalie filtrata per gli IP src/dst del flusso.
    function jumpToAnomaliesForFlow() {
        const f = _flowPanelFlow;
        if (!f) return;
        _anomIpFilter = { src: f.src_ip, dst: f.dst_ip };
        closeFlowDetailPanel();
        const statusSel = document.getElementById('anomStatus');
        if (statusSel) statusSel.value = 'all';
        loadAnomalies();
        // Ancora esplicita: il vecchio selettore '#tab-flows h4' puntava alla prima
        // h4 del tab (il titolo anomalie) e si rompe appena cambia la gerarchia.
        document.getElementById('anomSectionTitle')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function clearAnomIpFilter() {
        _anomIpFilter = null;
        loadAnomalies();
    }

    function toggleTrafTenantDropdown() {
        const dropdown = document.getElementById('trafTenantDropdown');
        if (!dropdown) return;
        dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
    }

    // Close dropdown on outside click
    document.addEventListener('click', function(e) {
        const dropdown = document.getElementById('trafTenantDropdown');
        const btn = document.getElementById('trafTenantBtn');
        if (dropdown && btn && !dropdown.contains(e.target) && !btn.contains(e.target)) {
            dropdown.style.display = 'none';
        }
    });

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
            showToast(currentLang === 'en' ? 'Node not present in the topology.' : 'Nodo non presente nella topologia.', 'warning');
        };
        tryFocus(0);
    }

    // Percorso comune: prepara il chat AI col contesto flussi (server-side).
    // ``flows`` non vuoto → analisi delle sole righe selezionate (attach_flow_keys);
    // altrimenti fallback al riassunto top-N (attach_top_flows).
    async function _prepareFlowAiChat(flows) {
        const selected = flows && flows.length;
        if (selected) {
            aiAttachFlowKeysOnce = flows.map(flowToKey);
            aiAttachTopFlowsOnce = false;
        } else {
            aiAttachFlowKeysOnce = null;
            aiAttachTopFlowsOnce = true;
        }
        let providerName = '';
        try {
            const res = await apiFetch('/api/ai/profiles');
            if (res && res.ok) {
                const data = await res.json();
                const active = (data.profiles || []).find(p => p.id === data.active_profile) || {};
                providerName = active.provider || '';
            }
        } catch (e) { /* nome provider best-effort */ }
        const note = document.getElementById('flowsAiNote');
        note.style.display = 'block';
        // Il contesto è assemblato e REDATTO lato server: il browser invia solo
        // le tuple identificative (mai byte/pacchetti) e la domanda.
        const en = currentLang === 'en';
        note.textContent = en
            ? '⚠️ ' + (selected
                ? `ONLY the ${flows.length} selected flows (identifiers; totals re-derived server-side, secrets redacted)`
                : 'The aggregated flow data (top-N summary, secrets redacted)')
                + ' will be sent to the configured AI provider'
                + (providerName ? ` (${providerName})` : '') + '.'
            : '⚠️ ' + (selected
                ? `Vengono inviati SOLO i ${flows.length} flussi selezionati (identificatori; totali ri-derivati dal server, segreti redatti)`
                : 'I dati aggregati dei flussi (riassunto top-N, con segreti redatti)')
                + ' verranno inviati al provider AI configurato'
                + (providerName ? ` (${providerName})` : '') + '.';
        switchTab('tab-ai', document.querySelector(`.nav-item[onclick*="'tab-ai'"]`));
        const input = document.getElementById('aiChatInput');
        input.value = en
            ? (selected
                ? `Analyze the ${flows.length} selected attached network flows: `
                  + 'spot anomalous top talkers, possible exfiltration or scans, '
                  + 'and correlate with the open anomalies.'
                : 'Analyze the attached network flows: spot anomalous top talkers, '
                  + 'possible exfiltration or scans, and correlate with the open anomalies.')
            : (selected
                ? `Analizza i ${flows.length} flussi di rete selezionati e allegati: `
                  + 'individua top talker anomali, possibili esfiltrazioni o scansioni, '
                  + 'e correla con le anomalie aperte.'
                : 'Analizza i flussi di rete allegati: individua i top talker anomali, '
                  + 'possibili esfiltrazioni o scansioni, e correla con le anomalie aperte.');
        input.focus();
    }

    async function analyzeFlowsWithAi() {
        // Se l'utente ha selezionato righe (11.2), analizza SOLO quelle;
        // altrimenti il percorso legacy top-N (attach_top_flows).
        await _prepareFlowAiChat(getSelectedFlows());
    }

    // 11.3: analisi AI del singolo flusso dal pannello dettaglio.
    async function analyzeSingleFlowWithAi() {
        if (!_flowPanelFlow) return;
        const f = _flowPanelFlow;
        closeFlowDetailPanel();
        await _prepareFlowAiChat([f]);
    }

    async function loadAnomalies() {
        const tbody = document.getElementById('anomTableBody');
        const status = document.getElementById('anomStatus').value;
        // The window comes from the tab header like every other view. It used
        // to be a hardcoded 7d, so this panel silently showed a week while the
        // rest of the tab showed the selected range.
        const res = await apiFetch(`/api/observability/anomalies?status=${encodeURIComponent(status)}&window=${encodeURIComponent(trafState.window)}&limit=100`);
        if (!res || !res.ok) return;
        let rows = (await res.json()).anomalies || [];

        // Filtro client-side per IP src/dst del flusso, impostato dal pannello dettaglio flussi.
        const chip = document.getElementById('anomIpFilterChip');
        if (_anomIpFilter) {
            const { src, dst } = _anomIpFilter;
            rows = rows.filter(a => a.src_ip === src || a.dst_ip === src || a.src_ip === dst || a.dst_ip === dst);
            if (chip) {
                chip.style.display = 'inline-flex';
                chip.querySelector('span').textContent = `${currentLang === 'en' ? 'Filtered by flow' : 'Filtrato per flusso'}: ${src} / ${dst}`;
            }
        } else if (chip) {
            chip.style.display = 'none';
        }

        const en = currentLang === 'en';
        if (rows.length === 0) {
            tbody.innerHTML = `<tr><td colspan="9" style="padding:20px; text-align:center; color:var(--text-muted);">${i18n[currentLang].msgNoAnomalies || 'Nessuna anomalia.'}</td></tr>`;
            return;
        }
        // Severità = severità syslog (0-7, più bassa = più grave), stessa scala
        // usata da renderSyslogTable(): <=3 grave, 4 attenzione, oltre informativa.
        // Mirrors sevColor() in the syslog table: 0-3 critico/alto, 4 warning,
        // 5+ is "medio" (see _SEVERITY_KIND in observability/correlator.py) --
        // neutral, NOT ok/green. A medium anomaly must not read as healthy.
        const sevBadge = s => s == null ? '—'
            : s <= 3 ? `<span class="status bad">${s}</span>`
            : s <= 4 ? `<span class="status warn">${s}</span>`
            : `<span class="chip">${s}</span>`;
        // new = da lavorare, ack = presa in carico, resolved = chiusa.
        const statusBadge = st => st === 'resolved' ? `<span class="status ok">${escapeHtml(st)}</span>`
            : st === 'ack' ? `<span class="chip">${escapeHtml(st)}</span>`
            : `<span class="status warn">${escapeHtml(st)}</span>`;
        tbody.innerHTML = rows.map(a => {
            const when = new Date(a.created_ts * 1000).toLocaleString();
            const actions = [];
            const lblAck = en ? 'Acknowledge' : 'Prendi in carico';
            const lblResolve = en ? 'Resolve' : 'Risolvi';
            if (a.status === 'new') {
                actions.push(`<button class="btn requires-write" style="font-size:11px; padding:3px 8px;" data-action="anom-transition" data-id="${a.id}" data-from="new" data-to="ack">${lblAck}</button>`);
                actions.push(`<button class="btn requires-write" style="font-size:11px; padding:3px 8px;" data-action="anom-transition" data-id="${a.id}" data-from="new" data-to="resolved">${lblResolve}</button>`);
            } else if (a.status === 'ack') {
                actions.push(`<button class="btn requires-write" style="font-size:11px; padding:3px 8px;" data-action="anom-transition" data-id="${a.id}" data-from="ack" data-to="resolved">${lblResolve}</button>`);
            }
            // The id this route returns IS the incident id: /api/observability/
            // anomalies reads FROM incidents. The two surfaces are one queue,
            // so the link costs nothing but the anchor.
            if (a.id != null) {
                actions.push(`<button class="btn" style="font-size:11px; padding:3px 8px;" title="${en ? 'Open the incident' : 'Apri l\'incidente'}" data-action="anom-open-incident" data-id="${Number(a.id)}"><i class="fa-solid fa-arrow-up-right-from-square"></i></button>`);
            }
            return `<tr style="font-size:12px; border-top:1px solid var(--border);">
                <td style="padding:6px 8px;">${when}</td>
                <td>${escapeHtml(a.tenant)}</td>
                <td>${escapeHtml(a.kind || '—')}</td>
                <td>${escapeHtml(a.src_ip || '—')}</td>
                <td>${escapeHtml(a.dst_ip || '—')}</td>
                <td>${escapeHtml(a.switch_port || '—')}</td>
                <td>${sevBadge(a.severity)}</td>
                <td>${statusBadge(a.status)}</td>
                <td style="display:flex; gap:4px;">${actions.join('')}</td>
            </tr>`;
        }).join('');
    }

    // Anomaly row -> the incident it belongs to. The Incidenti tab is
    // admin-only, so a viewer gets told rather than sent to an empty tab.
    async function anomOpenIncident(id) {
        const nav = document.getElementById('navIncidents');
        if (!nav || nav.offsetParent === null) {
            showToast(currentLang === 'en'
                ? 'The Incidents tab is not available for your role.'
                : 'Il tab Incidenti non e\' disponibile per il tuo ruolo.', 'warning');
            return;
        }
        // switchTab is async: it lazy-loads incidents.js and then calls that
        // tab's own loadIncidentsTab(). Calling incidents.js functions before
        // awaiting it hit a ReferenceError whenever the Incidents tab had not
        // been opened yet in this session, so the first click on an anomaly's
        // incident button did nothing at all.
        await switchTab('tab-incidents', nav);
        window.openIncident?.(id);
    }

    // Home counts the anomalies, Traffico shows them. One queue, one table.
    function openTrafficoAnomalies() {
        const nav = document.querySelector('[data-tabs="tab-flows"]');
        switchTab('tab-flows', nav || undefined);
        const status = document.getElementById('anomStatus');
        if (status) status.value = 'new';
        flowsTabShown();
        trafSwitchView('anomalies');
    }

    // L'id di un'anomalia e' l'id del suo incidente: la transizione va sulla
    // rotta degli incidenti. Quella sotto /observability e' un alias deprecato.
    async function anomTransition(id, fromStatus, toStatus) {
        const res = await apiFetch(`/api/incidents/${id}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ from_status: fromStatus, status: toStatus })
        });
        if (res && res.ok) {
            loadAnomalies();
        } else if (res && res.status === 409) {
            const err = await res.json().catch(() => ({}));
            showToast(err.detail || (currentLang === 'en' ? 'Status changed in the meantime: reloading.' : 'Stato cambiato nel frattempo: ricarico.'), 'warning');
            loadAnomalies();
        } else if (res) {
            showToast(currentLang === 'en' ? 'Operation failed.' : 'Operazione non riuscita.', 'error');
        }
    }

    // --- FLOW GRAPH (Task 3: Live Flows — grafo, KPI, riepilogo, tabelle) ---

    let _fgData = null;          // ultima risposta /flowgraph
    let _fgFetchInFlight = false;

    async function loadFlowGraph(window_) {
        if (_fgFetchInFlight) return;
        _fgFetchInFlight = true;
        try {
            const w = window_ || trafState.window;
            const res = await apiFetch(`/api/observability/flowgraph?window=${encodeURIComponent(w)}${telemetryParam()}`);
            if (!res || !res.ok) return;
            _fgData = await res.json();
            // Disclosure: qualunque nodo/arco con VLAN non reale (fallback
            // sintetico, nessun binding ARP noto per l'IP) attiva l'avviso
            // in UI — mai spacciare un valore inventato per un tag 802.1Q reale.
            if (_fgData.tenant) {
                _fgData.tenant.vlan_disclosure =
                    (_fgData.nodes || []).some(n => n.vlan_real === false) ||
                    (_fgData.edges || []).some(e => e.vlan_real === false);
            }
            renderFlowGraphKpis();
            renderFlowGraphTenant();
            renderFlowGraphProtocols();
            renderFlowGraphTalkers();
        } finally {
            _fgFetchInFlight = false;
        }
    }

    function renderFlowGraphKpis() {
        const d = _fgData;
        if (!d) return;
        const L = i18n[currentLang];
        document.getElementById('fgKpiThroughput').textContent = fmtRate(d.kpi.throughput_bps);
        const tp = d.kpi.top_path;
        const topPathEl = document.getElementById('fgKpiTopPath');
        if (topPathEl) {
            if (tp && tp.src) {
                topPathEl.innerHTML = `
                    <div class="kpi-top-path" title="${escapeHtml(tp.src)} → ${escapeHtml(tp.dst)} (${escapeHtml(tp.pct)}%)">
                        <div class="kpi-path-line">
                            <span class="kpi-path-ip">${escapeHtml(tp.src)}</span>
                            <span class="kpi-path-arrow"><i class="fa-solid fa-arrow-right"></i></span>
                            <span class="kpi-path-ip">${escapeHtml(tp.dst)}</span>
                        </div>
                        <div class="kpi-path-sub">
                            <span class="kpi-path-pct">(${escapeHtml(tp.pct)}%)</span>
                        </div>
                    </div>
                `;
            } else {
                topPathEl.textContent = '—';
            }
        }
        document.getElementById('fgKpiTalkers').textContent = d.kpi.talkers;
        document.getElementById('fgKpiSpikes').textContent = d.kpi.spikes;
    }

    function renderFlowGraphTenant() {
        const d = _fgData;
        const box = document.getElementById('fgTenantSummary');
        if (!box) return;
        if (!d || !d.tenant || !d.tenant.name) { box.textContent = '—'; return; }
        const L = i18n[currentLang];
        const t = d.tenant;
        const tt = t.top_talker;
        box.innerHTML = `
            <div><b>${escapeHtml(L.thFlTenant || 'Tenant')}</b>: ${escapeHtml(t.name)}</div>
            <div><b>${escapeHtml(L.thFgVlan || 'VLAN')}</b>: ${escapeHtml((t.vlans || []).join(', ') || '—')}${t.vlan_disclosure ? ` <span title="${escapeHtml(L.hintVlanSynthetic || '')}" style="cursor:help; color:var(--text-muted);">*</span>` : ''}</div>
            <div><b>${escapeHtml(L.lblVisibleVlans || 'Visible VLANs')}</b>: ${(t.vlans || []).length}</div>
            <div><b>${escapeHtml(L.lblFlowsShown || 'Flows shown')}</b>: ${t.flows_shown}</div>
            <div><b>${escapeHtml(L.lblTopTalker || 'Top talker')}</b>: ${tt ? `${escapeHtml(tt.src)} → ${escapeHtml(tt.dst)} (${escapeHtml(fmtRate(tt.rate_bps))})` : '—'}</div>`;
    }

    function _fgVisibleEdges() {
        // Archi visibili nelle due tabelle: l'intera finestra (il grafo
        // click-to-filter è stato rimosso insieme al canvas force-directed).
        return (_fgData && _fgData.edges) || [];
    }

    function _fgVlanMark(realFlag) {
        if (realFlag !== false) return '';
        const L = i18n[currentLang];
        return ` <span title="${escapeHtml(L.hintVlanSynthetic || '')}" style="cursor:help; color:var(--text-muted);">*</span>`;
    }

    function renderFlowGraphProtocols() {
        const tbody = document.getElementById('fgProtoTableBody');
        if (!tbody) return;
        // Intera finestra dei protocolli precalcolata dal backend.
        const rows = (_fgData && _fgData.protocols) || [];
        if (!rows.length) {
            tbody.innerHTML = `<tr><td colspan="3" style="padding:10px; text-align:center; color:var(--text-muted);">—</td></tr>`;
            return;
        }
        tbody.innerHTML = rows.map(p => `
            <tr style="border-top:1px solid var(--border);">
                <td style="padding:4px 6px;">${escapeHtml(String(p.proto).toUpperCase())}</td>
                <td>${escapeHtml(p.port == null ? '—' : String(p.port))}</td>
                <td>${escapeHtml(fmtRate(p.rate_bps))}</td>
            </tr>`).join('');
    }

    function renderFlowGraphTalkers() {
        const tbody = document.getElementById('fgTalkersTableBody');
        if (!tbody) return;
        const edges = _fgVisibleEdges();
        if (!edges.length) {
            const L = i18n[currentLang];
            tbody.innerHTML = `<tr><td colspan="4" style="padding:16px; text-align:center; color:var(--text-muted);">${escapeHtml(L.msgNoFlowGraphData || 'No data.')}</td></tr>`;
            return;
        }
        tbody.innerHTML = edges.map(e => `
            <tr style="border-top:1px solid var(--border);">
                <td style="padding:6px 8px;">${escapeHtml(e.src)}</td>
                <td>${escapeHtml(e.dst)}</td>
                <td>${escapeHtml(String(e.vlan))}${_fgVlanMark(e.vlan_real)}</td>
                <td>${escapeHtml(fmtRate(e.rate_bps))}</td>
            </tr>`).join('');
    }

    // --- PROTOCOL DISTRIBUTION CHART (DONUT, BAR, TREND) ---
    let _obsChartType = 'donut';
    let _obsProtocolData = null;

    function setObsChartType(type) {
        _obsChartType = type;
        ['donut', 'bar', 'trend'].forEach(t => {
            const btn = document.getElementById('btnChartType' + t.charAt(0).toUpperCase() + t.slice(1));
            if (!btn) return;
            if (t === type) {
                btn.style.background = 'var(--cta)';
                btn.style.color = 'var(--cta-text)';
            } else {
                btn.style.background = 'transparent';
                btn.style.color = 'var(--text)';
            }
        });
        renderObsProtocolChart();
    }

    async function loadObsProtocolDist() {
        const card = document.getElementById('obsProtocolCard');
        if (!card) return;
        const win = trafState.window;
        const res = await apiFetch(`/api/observability/protocol-distribution?window=${win}${telemetryParam()}`);
        if (!res || !res.ok) return;
        _obsProtocolData = await res.json();
        renderObsProtocolChart();
    }

    function renderObsProtocolChart() {
        if (!_obsProtocolData) return;
        const canvas = document.getElementById('obsProtocolCanvas');
        const statsBox = document.getElementById('obsProtocolStats');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const d = _obsProtocolData;
        const totals = d.totals || {};

        // Conduttori dello schema: il codice fasi del quadro, risolto in colori
        // veri perche' questi valori finiscono anche in ctx.fillStyle su canvas.
        const PROTO_COLORS = {
            netflow: cssVar('--cond-a', '#5aa9e6'),
            ipfix:   cssVar('--cond-c', '#63c88a'),
            sflow:   cssVar('--cond-d', '#b98a5e'),
            syslog:  cssVar('--cond-b', '#e0a03c')
        };
        const PROTO_LABELS = {
            netflow: 'NetFlow',
            ipfix: 'IPFIX',
            sflow: 'sFlow',
            syslog: 'Syslog'
        };

        if (_obsChartType === 'bar') {
            canvas.style.display = 'none';
            if (statsBox) {
                statsBox.style.display = 'flex';
                let totalBytes = 0;
                let totalEvents = totals.syslog ? (totals.syslog.events || 0) : 0;
                Object.keys(totals).forEach(k => {
                    if (k !== 'syslog') totalBytes += (totals[k].bytes || 0);
                });
                
                const protoKeys = ['netflow', 'ipfix', 'sflow', 'syslog'];
                statsBox.innerHTML = protoKeys.map(k => {
                    const col = PROTO_COLORS[k];
                    const label = PROTO_LABELS[k];
                    const item = totals[k] || {};
                    let valStr = '0 B';
                    let pct = 0;
                    if (k === 'syslog') {
                        valStr = `${item.events || 0} eventi`;
                        pct = totalEvents > 0 ? Math.min(100, Math.round(((item.events || 0) / totalEvents) * 100)) : 0;
                    } else {
                        valStr = typeof fmtBytes === 'function' ? fmtBytes(item.bytes || 0) : `${item.bytes || 0} B`;
                        pct = totalBytes > 0 ? Math.min(100, Math.round(((item.bytes || 0) / totalBytes) * 100)) : 0;
                    }
                    return `
                    <div style="display:flex; flex-direction:column; gap:4px;">
                        <div style="display:flex; align-items:center; justify-content:space-between; font-size:12px;">
                            <span style="font-weight:700; color:${col}; flex:1;">${label}</span>
                            <span style="font-family:var(--font-code); color:var(--text); font-weight:600;">${valStr}</span>
                            <span style="color:var(--text-muted); width:45px; text-align:right;">${pct}%</span>
                        </div>
                        <div style="width:100%; height:8px; background:var(--surface-3); border-radius:0; overflow:hidden;">
                            <div style="width:100%; transform:scaleX(${pct / 100}); transform-origin:left; height:100%; background:${col}; border-radius:0; transition:transform .3s;"></div>
                        </div>
                    </div>`;
                }).join('');
            }
            return;
        }

        canvas.style.display = 'block';
        if (statsBox) statsBox.style.display = 'none';

        // ResizeObserver to automatically adjust canvas resolution when tab becomes visible or resizes
        if (typeof ResizeObserver !== 'undefined' && canvas && !canvas._hasObsResizeObserver) {
            canvas._hasObsResizeObserver = true;
            const ro = new ResizeObserver(() => {
                if (canvas.offsetWidth > 0) {
                    renderObsProtocolChart();
                }
            });
            ro.observe(canvas.parentElement || canvas);
        }

        // Resize canvas to pixel ratio accurately
        const dpr = window.devicePixelRatio || 1;
        const rect = canvas.getBoundingClientRect();
        const parentRect = canvas.parentElement ? canvas.parentElement.getBoundingClientRect() : rect;
        const width = Math.max(300, Math.round(rect.width || parentRect.width || 600));
        const height = Math.max(180, Math.round(rect.height || parentRect.height || 230));

        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.scale(dpr, dpr);

        ctx.clearRect(0, 0, width, height);

        if (_obsChartType === 'donut') {
            let totalVal = 0;
            const items = [];
            Object.keys(totals).forEach(k => {
                const v = k === 'syslog' ? (totals[k].events || 0) : (totals[k].bytes || 0);
                if (v > 0) {
                    items.push({ key: k, val: v, color: PROTO_COLORS[k], label: PROTO_LABELS[k] });
                    totalVal += v;
                }
            });

            const cx = width > 500 ? width * 0.32 : width * 0.3;
            const cy = height / 2;
            const radius = Math.min(width * 0.22, height * 0.38);
            const innerRadius = radius * 0.58;

            if (items.length === 0 || totalVal === 0) {
                ctx.fillStyle = '#888';
                ctx.font = '13px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('Nessun dato di telemetria nel periodo', width / 2, height / 2);
                return;
            }

            let startAngle = -Math.PI / 2;
            items.forEach(item => {
                const sliceAngle = (item.val / totalVal) * (Math.PI * 2);
                ctx.beginPath();
                ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
                ctx.arc(cx, cy, innerRadius, startAngle + sliceAngle, startAngle, true);
                ctx.closePath();
                ctx.fillStyle = item.color;
                ctx.fill();
                startAngle += sliceAngle;
            });

            // Center total text
            ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text') || '#fff';
            ctx.font = 'bold 14px sans-serif';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('Protocolli', cx, cy - 8);
            ctx.font = '11px sans-serif';
            ctx.fillStyle = '#888';
            ctx.fillText(`${items.length} attivi`, cx, cy + 10);

            // Render Legend on the right side
            let lx = Math.max(220, width * 0.52);
            let ly = Math.max(20, (height - (items.length * 28)) / 2);
            items.forEach(item => {
                ctx.fillStyle = item.color;
                ctx.fillRect(lx, ly, 12, 12);
                ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text') || '#fff';
                ctx.font = '12px sans-serif';
                ctx.textAlign = 'left';
                ctx.textBaseline = 'top';
                const pct = Math.round((item.val / totalVal) * 100);
                const valStr = item.key === 'syslog' ? `${item.val} evt` : (typeof fmtBytes === 'function' ? fmtBytes(item.val) : `${item.val} B`);
                ctx.fillText(`${item.label}: ${valStr} (${pct}%)`, lx + 20, ly - 1);
                ly += 28;
            });
        } else if (_obsChartType === 'trend') {
            const trend = d.trend || [];
            if (trend.length === 0) {
                ctx.fillStyle = '#888';
                ctx.font = '13px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('Nessun trend temporale disponibile nel periodo', width / 2, height / 2);
                return;
            }

            const padding = { top: 38, right: 55, bottom: 35, left: 60 };
            const graphW = width - padding.left - padding.right;
            const graphH = height - padding.top - padding.bottom;

            // Render Top Legend
            let legX = padding.left;
            const legY = 12;
            const protoKeys = ['netflow', 'ipfix', 'sflow', 'syslog'];
            protoKeys.forEach(k => {
                ctx.fillStyle = PROTO_COLORS[k];
                ctx.fillRect(legX, legY, 10, 10);
                ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--text') || '#fff';
                ctx.font = '11px sans-serif';
                ctx.textAlign = 'left';
                ctx.textBaseline = 'top';
                const label = k === 'syslog' ? 'Syslog (Eventi)' : PROTO_LABELS[k] + ' (Bytes)';
                ctx.fillText(label, legX + 14, legY - 1);
                legX += ctx.measureText(label).width + 30;
            });

            // Find Max Values
            let maxBytes = 1;
            let maxSyslog = 1;
            trend.forEach(pt => {
                ['netflow', 'ipfix', 'sflow'].forEach(k => {
                    if ((pt[k] || 0) > maxBytes) maxBytes = pt[k];
                });
                if ((pt.syslog || 0) > maxSyslog) maxSyslog = pt.syslog;
            });

            // Draw Background Gridlines & Y-Axis Ticks
            const textColor = getComputedStyle(document.body).getPropertyValue('--text-muted') || '#888';
            const borderColor = getComputedStyle(document.body).getPropertyValue('--border') || '#444';

            ctx.lineWidth = 1;
            ctx.font = '10px sans-serif';

            [0, 0.5, 1.0].forEach(factor => {
                const y = height - padding.bottom - (factor * graphH);
                ctx.strokeStyle = factor === 0 ? borderColor : 'rgba(255,255,255,0.06)';
                ctx.beginPath();
                ctx.moveTo(padding.left, y);
                ctx.lineTo(width - padding.right, y);
                ctx.stroke();

                // Left Y-Axis (Bytes)
                ctx.fillStyle = textColor;
                ctx.textAlign = 'right';
                ctx.textBaseline = 'middle';
                const bytesVal = Math.round(maxBytes * factor);
                const bytesStr = typeof fmtBytes === 'function' ? fmtBytes(bytesVal) : `${bytesVal} B`;
                ctx.fillText(bytesStr, padding.left - 8, y);

                // Right Y-Axis (Syslog Events)
                ctx.textAlign = 'left';
                const evtVal = Math.round(maxSyslog * factor);
                ctx.fillText(`${evtVal} evt`, width - padding.right + 8, y);
            });

            // Draw X-Axis Time Labels
            const labelStep = Math.max(1, Math.floor(trend.length / 5));
            trend.forEach((pt, i) => {
                if (i % labelStep === 0 || i === trend.length - 1) {
                    const x = padding.left + (i / Math.max(1, trend.length - 1)) * graphW;
                    const dateObj = new Date(pt.ts * 1000);
                    const timeStr = dateObj.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    ctx.fillStyle = textColor;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'top';
                    ctx.fillText(timeStr, x, height - padding.bottom + 8);
                }
            });

            // Draw Lines and Points for each protocol
            protoKeys.forEach(k => {
                const col = PROTO_COLORS[k];
                const isSyslog = k === 'syslog';
                const curMax = isSyslog ? maxSyslog : maxBytes;

                ctx.strokeStyle = col;
                ctx.fillStyle = col;
                ctx.lineWidth = 2;
                ctx.beginPath();

                const points = [];
                trend.forEach((pt, i) => {
                    const x = padding.left + (i / Math.max(1, trend.length - 1)) * graphW;
                    const val = pt[k] || 0;
                    const y = height - padding.bottom - ((val / curMax) * graphH);
                    points.push({ x, y, val });
                    if (i === 0) ctx.moveTo(x, y);
                    else ctx.lineTo(x, y);
                });
                ctx.stroke();

                // Draw Dots
                points.forEach(p => {
                    ctx.beginPath();
                    ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
                    ctx.fill();
                });
            });
        }
    }

    // --- INSPECTION MODAL & CLICK DRILL-DOWN ---
    // Markup per la ripartizione telemetria (severità syslog, azioni, top
    // device, breakdown L4 e top porte per protocollo). Riusata sia dal
    // pannello inline "Dettaglio Flussi" sia dal modale di ispezione, così
    // le due viste non divergono.
    const OBS_PROTO_LABELS = { netflow: 'NetFlow', ipfix: 'IPFIX', sflow: 'sFlow', syslog: 'Syslog' };

    function buildFlowTelemetryDetailHtml(protoKey = 'all') {
        const bd = (_obsProtocolData && _obsProtocolData.breakdown) || {};
        const totals = (_obsProtocolData && _obsProtocolData.totals) || {};
        const windowStr = (_obsProtocolData && _obsProtocolData.window) || '24h';
        const PROTO_LABELS = OBS_PROTO_LABELS;

        let html = '';

        if (protoKey === 'syslog' || protoKey === 'all') {
            const slData = bd.syslog || {};
            const sevs = slData.severity || {};
            const actions = slData.actions || {};
            const devices = slData.devices || {};
            const totalSyslogEvts = totals.syslog ? (totals.syslog.events || 0) : 0;

            const SEV_LABELS = {
                '0': 'Emerg (0)', '1': 'Alert (1)', '2': 'Crit (2)', '3': 'Err (3)',
                '4': 'Warn (4)', '5': 'Notice (5)', '6': 'Info (6)', '7': 'Debug (7)'
            };
            const SEV_COLORS = {
                '0': 'var(--danger)', '1': 'var(--danger)', '2': 'var(--danger)', '3': 'var(--danger)',
                '4': 'var(--warning)', '5': 'var(--info)', '6': 'var(--primary)', '7': 'var(--text-muted)'
            };

            let sevHtml = '';
            Object.keys(sevs).sort().forEach(sev => {
                const cnt = sevs[sev] || 0;
                const pct = totalSyslogEvts > 0 ? Math.round((cnt / totalSyslogEvts) * 100) : 0;
                sevHtml += `
                <div style="margin-bottom:8px;">
                    <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:2px;">
                        <span style="color:${SEV_COLORS[sev] || 'var(--text)'}; font-weight:700;">${SEV_LABELS[sev] || ('Sev ' + sev)}</span>
                        <span>${cnt} eventi (${pct}%)</span>
                    </div>
                    <div style="width:100%; height:6px; background:var(--surface-3); border-radius:0; overflow:hidden;">
                        <div style="width:${pct}%; height:100%; background:${SEV_COLORS[sev] || 'var(--primary)'};"></div>
                    </div>
                </div>`;
            });

            let actHtml = '';
            let totalAct = Object.values(actions).reduce((a, b) => a + b, 0);
            Object.keys(actions)
                .sort((a, b) => (actions[b] || 0) - (actions[a] || 0))
                .forEach(act => {
                    const cnt = actions[act];
                    const pct = totalAct > 0 ? Math.round((cnt / totalAct) * 100) : 0;
                    actHtml += `<span class="badge" style="background:var(--surface-3); border:1px solid var(--border); font-size:11px; padding:3px 8px; border-radius:0; white-space:nowrap; display:inline-flex; align-items:center; gap:4px;">${escapeHtml(act)}: <strong>${cnt}</strong> <span style="color:var(--text-muted); font-size:10px;">(${pct}%)</span></span>`;
                });

            let devHtml = '';
            Object.keys(devices)
                .sort((a, b) => (devices[b] || 0) - (devices[a] || 0))
                .forEach(dev => {
                    const cnt = devices[dev];
                    const pct = totalSyslogEvts > 0 ? Math.round((cnt / totalSyslogEvts) * 100) : 0;
                    devHtml += `<li style="margin-bottom:4px;"><code>${escapeHtml(dev)}</code> — ${cnt} log (${pct}%)</li>`;
                });

            html += `
            <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:14px;">
                <h4 style="margin:0 0 10px; font-size:14px; color:var(--warning); display:flex; align-items:center; gap:6px;">
                    <i class="fa-solid fa-list-check"></i> Syslog Event Breakdown (Finestra ${windowStr})
                </h4>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px;">
                    <div>
                        <div style="font-size:12px; font-weight:700; margin-bottom:6px; color:var(--text-muted);">DISTRIBUZIONE SEVERITÀ (%)</div>
                        ${sevHtml || '<div style="color:var(--text-muted); font-size:12px;">Nessun evento</div>'}
                    </div>
                    <div>
                        <div style="font-size:12px; font-weight:700; margin-bottom:6px; color:var(--text-muted);">AZIONI REGISTRATE (ACCEPT/DENY)</div>
                        <div style="display:flex; flex-wrap:wrap; gap:6px; max-height:150px; overflow-y:auto; padding:8px; background:var(--surface-1); border:1px solid var(--border); border-radius:0; margin-bottom:10px;">
                            ${actHtml || '<div style="color:var(--text-muted); font-size:12px;">Nessuna azione</div>'}
                        </div>
                        <div style="font-size:12px; font-weight:700; margin:12px 0 6px; color:var(--text-muted);">TOP SORGENTI DISPOSITIVI</div>
                        <ul style="margin:0; padding-left:16px; font-size:12px; max-height:100px; overflow-y:auto;">${devHtml || '<li>—</li>'}</ul>
                    </div>
                </div>
            </div>`;
        }

        ['netflow', 'ipfix', 'sflow'].forEach(p => {
            if (protoKey === p || protoKey === 'all') {
                const pData = bd[p] || {};
                const l4Map = pData.l4 || {};
                const portsMap = pData.ports || {};
                const pTot = totals[p] || {};
                const totalBytes = pTot.bytes || 0;

                let l4Html = '';
                Object.keys(l4Map).forEach(proto => {
                    const b = l4Map[proto];
                    const pct = totalBytes > 0 ? Math.round((b / totalBytes) * 100) : 0;
                    l4Html += `
                    <div style="margin-bottom:6px;">
                        <div style="display:flex; justify-content:space-between; font-size:12px;">
                            <span style="font-weight:700;">${proto}</span>
                            <span>${typeof fmtBytes === 'function' ? fmtBytes(b) : b + ' B'} (${pct}%)</span>
                        </div>
                        <div style="width:100%; height:6px; background:var(--surface-3); border-radius:0; overflow:hidden;">
                            <div style="width:${pct}%; height:100%; background:var(--primary);"></div>
                        </div>
                    </div>`;
                });

                let portsHtml = '';
                Object.keys(portsMap).slice(0, 5).forEach(port => {
                    const b = portsMap[port];
                    const pct = totalBytes > 0 ? Math.round((b / totalBytes) * 100) : 0;
                    portsHtml += `<div style="display:flex; justify-content:space-between; font-size:12px; padding:3px 0; border-bottom:1px dashed var(--border);">
                        <span>${escapeHtml(port)}</span>
                        <span><strong>${typeof fmtBytes === 'function' ? fmtBytes(b) : b + ' B'}</strong> (${pct}%)</span>
                    </div>`;
                });

                html += `
                <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:14px;">
                    <h4 style="margin:0 0 10px; font-size:14px; color:var(--primary); display:flex; align-items:center; gap:6px;">
                        <i class="fa-solid fa-network-wired"></i> Telemetria ${PROTO_LABELS[p]} (Flussi: ${pTot.flows || 0}, Pacchetti: ${pTot.packets || 0})
                    </h4>
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px;">
                        <div>
                            <div style="font-size:12px; font-weight:700; margin-bottom:6px; color:var(--text-muted);">PROTOCOLLI L4 (PERCENTUALE BYTE)</div>
                            ${l4Html || '<div style="color:var(--text-muted); font-size:12px;">Nessun dato di flusso</div>'}
                        </div>
                        <div>
                            <div style="font-size:12px; font-weight:700; margin-bottom:6px; color:var(--text-muted);">TOP PORTE DI DESTINAZIONE</div>
                            ${portsHtml || '<div style="color:var(--text-muted); font-size:12px;">Nessun dato</div>'}
                        </div>
                    </div>
                </div>`;
            }
        });

        return html;
    }

    async function openObsInspectModal(protoKey = 'all') {
        const modal = document.getElementById('obsInspectModal');
        const title = document.getElementById('obsInspectTitle');
        const body = document.getElementById('obsInspectBody');
        if (!modal || !body) return;

        if (!_obsProtocolData) {
            await loadObsProtocolDist();
        }

        if (title) {
            title.innerHTML = `<i class="fa-solid fa-magnifying-glass-chart" style="color:var(--primary);"></i> Ispezione Dettagliata Telemetria — ${protoKey === 'all' ? 'Tutti i Protocolli' : (OBS_PROTO_LABELS[protoKey] || protoKey)}`;
        }

        const html = buildFlowTelemetryDetailHtml(protoKey);
        body.innerHTML = html || '<div style="padding:20px; text-align:center; color:var(--text-muted);">Nessun dettaglio disponibile per la finestra selezionata.</div>';
        modal.style.display = 'flex';
    }

    function closeObsInspectModal() {
        const modal = document.getElementById('obsInspectModal');
        if (modal) modal.style.display = 'none';
    }

    // Expose functions globally for UI
    window.loadObsHealth = loadObsHealth;
    window.pruneObsLogs = pruneObsLogs;
    window.anomOpenIncident = anomOpenIncident;
    window.openTrafficoAnomalies = openTrafficoAnomalies;
    window.trafSelectedTenants = () => new Set(_flowsSelectedTenants);
    window.trafState = trafState;
    window.trafSwitchView = trafSwitchView;
    window.trafSetWindow = trafSetWindow;
    window.trafSetMetric = trafSetMetric;
    window.trafRefresh = trafRefresh;
    window.toggleTrafTenantDropdown = toggleTrafTenantDropdown;
    window.toggleTrafTenantAll = toggleTrafTenantAll;
    window.setObsChartType = setObsChartType;
    window.loadObsProtocolDist = loadObsProtocolDist;
    window.openObsInspectModal = openObsInspectModal;
    window.closeObsInspectModal = closeObsInspectModal;

    // Delegated click and change event listeners
    document.getElementById('flowsSourceChips')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="set-flows-source"]');
        if (btn && btn.dataset.source) setFlowsSource(btn.dataset.source);
    });

    document.getElementById('flowsColsDropdown')?.addEventListener('change', (e) => {
        const cb = e.target.closest('.flows-col-cb');
        if (cb && cb.dataset.colId) toggleFlowsCol(cb.dataset.colId, cb.checked);
    });

    document.getElementById('flowsTableHead')?.addEventListener('change', (e) => {
        const all = e.target.closest('#flowsSelectAll');
        if (all) toggleFlowsSelectAll(all);
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

    document.getElementById('flowsTableBody')?.addEventListener('change', (e) => {
        const cb = e.target.closest('.flow-row-check');
        if (cb && cb.dataset.key) {
            toggleFlowRowSelect(cb.dataset.key, cb.checked);
        }
    });

    document.getElementById('flowsSyslogAllBody')?.addEventListener('click', (e) => {
        const sysRow = e.target.closest('tr[data-action="show-syslog-detail"]');
        if (sysRow && sysRow.dataset.index != null) {
            showSyslogDetail(Number(sysRow.dataset.index));
        }
    });

    document.getElementById('trafTenantList')?.addEventListener('change', (e) => {
        if (e.target.closest('.flows-tenant-cb')) {
            updateFlowsTenantSelection();
        }
    });

    document.getElementById('flowDetailPanelBody')?.addEventListener('click', (e) => {
        const hl = e.target.closest('[data-action="detail-hl-topo"]');
        if (hl && hl.dataset.ip) {
            highlightInTopology(hl.dataset.ip);
            closeFlowDetailPanel();
            return;
        }
        if (e.target.closest('[data-action="detail-anomalies"]')) {
            jumpToAnomaliesForFlow();
            return;
        }
        if (e.target.closest('[data-action="detail-ai-flow"]')) {
            analyzeSingleFlowWithAi();
            return;
        }
    });

    document.getElementById('anomTableBody')?.addEventListener('click', (e) => {
        const trBtn = e.target.closest('[data-action="anom-transition"]');
        if (trBtn && trBtn.dataset.id) {
            anomTransition(Number(trBtn.dataset.id), trBtn.dataset.from, trBtn.dataset.to);
            return;
        }
        const incBtn = e.target.closest('[data-action="anom-open-incident"]');
        if (incBtn && incBtn.dataset.id) {
            anomOpenIncident(Number(incBtn.dataset.id));
        }
    });

    document.getElementById('obsSettingsBody')?.addEventListener('click', (e) => {
        if (e.target.closest('[data-action="save-obs-settings"]')) saveObsSettings();
        if (e.target.closest('[data-action="prune-obs-logs"]')) pruneObsLogs();
    });

    // Static event listeners for Traffic / Flows / Observability tab
    document.getElementById('trafWindow')?.addEventListener('change', (e) => trafSetWindow(e.target.value));
    document.getElementById('trafMetric')?.addEventListener('change', (e) => trafSetMetric(e.target.value));
    document.getElementById('trafTenantBtn')?.addEventListener('click', toggleTrafTenantDropdown);
    document.getElementById('trafTenantAll')?.addEventListener('change', toggleTrafTenantAll);
    document.getElementById('btnTrafRefresh')?.addEventListener('click', trafRefresh);
    document.getElementById('trafHideTelemetry')?.addEventListener('change', (e) => setFlowsHideTelemetry(e.target.checked));
    document.getElementById('btnAnalyzeFlowsAi')?.addEventListener('click', analyzeFlowsWithAi);
    document.getElementById('trafPills')?.addEventListener('click', (e) => {
        const pill = e.target.closest('[data-traf-view]');
        if (pill && pill.dataset.trafView) trafSwitchView(pill.dataset.trafView);
    });
    document.getElementById('btnChartTypeDonut')?.addEventListener('click', () => setObsChartType('donut'));
    document.getElementById('btnChartTypeBar')?.addEventListener('click', () => setObsChartType('bar'));
    document.getElementById('btnChartTypeTrend')?.addEventListener('click', () => setObsChartType('trend'));
    document.getElementById('btnObsInspectModal')?.addEventListener('click', () => openObsInspectModal('all'));
    document.getElementById('flowsColsBtn')?.addEventListener('click', toggleFlowsColsDropdown);
    document.getElementById('anomStatus')?.addEventListener('change', loadAnomalies);
    document.getElementById('btnRefreshAnomalies')?.addEventListener('click', loadAnomalies);
    document.getElementById('lnkClearAnomIpFilter')?.addEventListener('click', clearAnomIpFilter);
    document.getElementById('btnCloseFlowDetail')?.addEventListener('click', closeFlowDetailPanel);

    document.getElementById('syslogDetailModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'syslogDetailModal' || e.target.closest('#btnCloseSyslogDetail')) {
            closeSyslogDetail();
        }
    });

    document.getElementById('obsInspectModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'obsInspectModal' || e.target.closest('[data-action="close-obs-inspect-modal"]')) {
            closeObsInspectModal();
        }
    });


    // Attach click listener on canvas. Il modulo ora si carica lazy alla
    // prima visita di tab-flows: di solito DOMContentLoaded e' gia' passato,
    // quindi il boot va eseguito subito (stesso pattern di provisioning.js).
    function obsWidgetBoot() {
        setTimeout(() => {
            // Pre-login l'overlay copre l'app: nessuna sessione esiste ancora,
            // e il fetch protetto produrrebbe solo uno 401 inutile.
            const overlay = document.getElementById('authOverlay');
            if (overlay && overlay.style.display !== 'none') return;
            loadObsProtocolDist();
            const canvas = document.getElementById('obsProtocolCanvas');
            if (canvas) {
                canvas.style.cursor = 'pointer';
                canvas.addEventListener('click', () => {
                    openObsInspectModal('all');
                });
            }
        }, 800);
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', obsWidgetBoot);
    } else {
        obsWidgetBoot();
    }

