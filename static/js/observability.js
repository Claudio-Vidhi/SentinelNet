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
                       style="width:100px; padding:6px 10px; border-radius:8px; border:1px solid var(--border);
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
            <div style="margin-top:10px; margin-bottom:2px; font-size:12px; color:var(--text-muted); text-transform:uppercase; font-weight:700;" data-i18n="lblObsListeners">Listener</div>
            <div style="margin-bottom:8px; font-size:12px; color:var(--text-muted);">${L.hintObsListeners || "Attiva un protocollo e indica la porta UDP su cui SentinelNet resta in ascolto, poi configura l'export dei dispositivi verso questo host su quella porta. Le modifiche ai listener vengono applicate subito, senza riavviare l'applicazione."}</div>
            ${listenerRows}
            <div style="margin-top:12px;">
                <button class="btn btn-primary btn-small" onclick="saveObsSettings()" data-i18n="btnSave">
                    <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(L.btnSave || (currentLang === 'en' ? 'Save' : 'Salva'))}
                </button>
            </div>
            <div id="obsSettingsError" style="margin-top:10px; font-size:12px; color:var(--danger);"></div>`;
    }

    async function saveObsSettings() {
        const errEl = document.getElementById('obsSettingsError');
        if (errEl) errEl.textContent = '';
        const payload = {
            enabled: document.getElementById('obs_enabled').checked,
            bind: document.getElementById('obs_bind').value.trim(),
            api_poll_s: parseInt(document.getElementById('obs_api_poll_s').value, 10)
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

    function flowsColHidden(id) { return _flowsHiddenCols.has(id); }

    function renderFlowsSourceChips() {
        const box = document.getElementById('flowsSourceChips');
        if (!box) return;
        const L = i18n[currentLang];
        box.innerHTML = FLOWS_SOURCES.map(s => {
            const active = s === _flowsSource;
            const label = s === 'all' ? (L.chipAllSources || 'Tutte le origini') : FLOWS_SOURCE_LABELS[s];
            return `<button class="btn btn-small" onclick="setFlowsSource('${s}')"
                style="padding:5px 14px; border-radius:16px; font-size:12px;
                       ${active ? 'background:var(--primary); color:#fff; border-color:var(--primary);' : ''}">${label}</button>`;
        }).join('');
        const colsBtn = document.getElementById('flowsColsBtn');
        if (colsBtn) colsBtn.style.display = _flowsSource === 'syslog' ? 'none' : '';
    }

    function setFlowsSource(s) {
        _flowsSource = s;
        renderFlowsSourceChips();
        loadTopTalkers();
    }

    function toggleFlowsColsDropdown() {
        const dd = document.getElementById('flowsColsDropdown');
        if (!dd) return;
        if (dd.style.display === 'none') {
            const L = i18n[currentLang];
            dd.innerHTML = FLOW_TOGGLE_COLS.map(c => `
                <label style="display:flex; align-items:center; gap:8px; padding:4px 8px; cursor:pointer; font-size:13px;">
                    <input type="checkbox" ${flowsColHidden(c.id) ? '' : 'checked'}
                           onchange="toggleFlowsCol('${c.id}', this.checked)" style="accent-color:var(--primary);">
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
            <th style="padding:8px;"><input type="checkbox" id="flowsSelectAll" onclick="toggleFlowsSelectAll(this)" style="accent-color:var(--primary);" title="${escapeHtml(L.lnkSelectAll || 'Seleziona tutti')}"></th>
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
            <tr style="font-size:12px; border-top:1px solid var(--border); cursor:pointer;" onclick="showSyslogDetail(${i})" data-i18n-title="titleSyslogRowHint" title="${escapeHtml(L.titleSyslogRowHint || 'Clicca per il dettaglio')}">
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
            <pre style="margin:0; padding:10px; background:var(--surface-2); border:1px solid var(--border); border-radius:8px; white-space:pre-wrap; word-break:break-all; font-family:var(--font-code); font-size:12px;">${escapeHtml(msg)}</pre>`;
        document.getElementById('syslogDetailModal').style.display = 'flex';
    }

    function closeSyslogDetail() {
        document.getElementById('syslogDetailModal').style.display = 'none';
    }

    function flowsTabShown() {
        renderFlowsSourceChips();
        loadTopTalkers();
        loadAnomalies();
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
            const auto = document.getElementById('flowsAutoRefresh')?.checked;
            if (active && auto && !document.hidden) loadTopTalkers();
        }, 30000);
    }

    function stopFlowsAutoRefresh() {
        if (flowsRefreshTimer) { clearInterval(flowsRefreshTimer); flowsRefreshTimer = null; }
    }

    // Pausa quando la pagina non è visibile; refresh immediato al ritorno.
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden &&
            document.getElementById('tab-flows')?.classList.contains('active')) {
            loadTopTalkers();
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
            const w = document.getElementById('flowsWindow').value;
            const m = document.getElementById('flowsMetric').value;
            if (_flowsSource === 'syslog') {
                const res = await apiFetch(`/api/observability/syslog?window=${encodeURIComponent(w)}&limit=200`);
                if (!res || !res.ok) {
                    if (res) tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--danger, #d9534f);">${currentLang === 'en' ? 'Error loading syslog events.' : 'Errore nel caricamento degli eventi syslog.'}</td></tr>`;
                    return;
                }
                _flowsSyslogData = (await res.json()).events || [];
                document.getElementById('flowsLastUpdate').textContent =
                    (currentLang === 'en' ? 'Updated: ' : 'Aggiornato: ') + new Date().toLocaleTimeString();
                rebuildFlowsTenantList(_flowsSyslogData);
                renderFlowsThead();
                renderSyslogTable();
                renderSyslogAllSection();
                return;
            }
            const srcParam = _flowsSource === 'all' ? '' : `&source=${_flowsSource}`;
            const res = await apiFetch(`/api/observability/top?window=${encodeURIComponent(w)}&metric=${encodeURIComponent(m)}&limit=100${srcParam}`);
            if (!res || !res.ok) {
                if (res) tbody.innerHTML = `<tr><td colspan="10" style="padding:20px; text-align:center; color:var(--danger, #d9534f);">${currentLang === 'en' ? 'Error loading flows.' : 'Errore nel caricamento dei flussi.'}</td></tr>`;
                return;
            }
            const flows = (await res.json()).flows || [];
            _flowsRawData = flows;                     // cache for filtering
            document.getElementById('flowsLastUpdate').textContent =
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
        } finally {
            flowsFetchInFlight = false;
        }
    }

    function rebuildFlowsTenantList(flows) {
        // Extract distinct tenants from flows, maintaining order of appearance
        const tenants = [...new Set(flows.map(f => f.tenant))].sort();
        const listDiv = document.getElementById('flowsTenantList');
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
                <input type="checkbox" value="${escapeHtml(t)}" onchange="updateFlowsTenantSelection()"
                       ${newSelected.has(t) ? 'checked' : ''} style="accent-color:var(--primary);">
                <span>${escapeHtml(t)}</span>
            </label>
        `).join('');

        // Update "Tutti" checkbox state
        const allCheckbox = document.getElementById('flowsTenantAll');
        if (allCheckbox) {
            allCheckbox.checked = tenants.length > 0 && tenants.every(t => newSelected.has(t));
            _flowsAllTenantsChecked = allCheckbox.checked;
        }

        // Update button label
        updateFlowsTenantButtonLabel(tenants.length);
    }

    function updateFlowsTenantSelection() {
        const checkboxes = Array.from(document.querySelectorAll('#flowsTenantList input[type="checkbox"]'));
        const selected = new Set(checkboxes.filter(cb => cb.checked).map(cb => cb.value));
        _flowsSelectedTenants = selected;

        // Update "Tutti" checkbox
        const allCheckbox = document.getElementById('flowsTenantAll');
        const totalTenants = checkboxes.length;
        const checkedCount = checkboxes.filter(cb => cb.checked).length;
        if (allCheckbox) {
            allCheckbox.checked = checkedCount === totalTenants;
            _flowsAllTenantsChecked = allCheckbox.checked;
        }

        updateFlowsTenantButtonLabel(totalTenants);
        renderFlowsTable();
    }

    function toggleFlowsTenantAll() {
        const allCheckbox = document.getElementById('flowsTenantAll');
        const checkboxes = Array.from(document.querySelectorAll('#flowsTenantList input[type="checkbox"]'));
        const shouldCheck = allCheckbox.checked;
        checkboxes.forEach(cb => cb.checked = shouldCheck);
        _flowsSelectedTenants = shouldCheck ? new Set(checkboxes.map(cb => cb.value)) : new Set();
        _flowsAllTenantsChecked = shouldCheck;
        updateFlowsTenantButtonLabel(checkboxes.length);
        renderFlowsTable();
    }

    function updateFlowsTenantButtonLabel(totalTenants) {
        const btn = document.getElementById('flowsTenantBtn');
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
        const m = document.getElementById('flowsMetric').value;
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
            return `<tr style="font-size:12px; border-top:1px solid var(--border); cursor:pointer;" onclick="openFlowDetailPanelByKey('${escapeHtml(key)}', event)">
                    <td style="padding:6px 8px;" onclick="event.stopPropagation();"><input type="checkbox" class="flow-row-check" data-key="${escapeHtml(key)}" ${checked} onchange="toggleFlowRowSelect('${escapeHtml(key)}', this.checked)" style="accent-color:var(--primary);"></td>
                    <td style="padding:6px 8px;">${rowNum++}</td>
                    ${flowsColHidden('tenant') ? '' : `<td>${escapeHtml(f.tenant)}</td>`}
                    <td><a href="javascript:void(0)" onclick="event.stopPropagation(); highlightInTopology('${escapeHtml(f.src_ip)}')" title="${hlTitle}">${escapeHtml(f.src_ip)}</a></td>
                    <td><a href="javascript:void(0)" onclick="event.stopPropagation(); highlightInTopology('${escapeHtml(f.dst_ip)}')" title="${hlTitle}">${escapeHtml(f.dst_ip)}</a></td>
                    ${flowsColHidden('proto') ? '' : `<td>${proto}/${f.dst_port ?? '—'}</td>`}
                    ${flowsColHidden('source') ? '' : `<td><span style="font-size:11px; padding:2px 8px; border-radius:10px; background:var(--surface-3);">${srcLabel}</span></td>`}
                    <td><div style="display:flex; align-items:center; gap:8px;">
                        <div style="flex:1; height:7px; background:var(--surface-3); border-radius:4px;"><div style="height:100%; width:${pct}%; background:var(--primary); border-radius:4px;"></div></div>
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
                ${row(L.thFlSrc || 'Sorgente', `<a href="javascript:void(0)" onclick="highlightInTopology('${escapeHtml(f.src_ip)}'); closeFlowDetailPanel();">${escapeHtml(f.src_ip)}</a>`)}
                ${row(L.thFlDst || 'Destinazione', `<a href="javascript:void(0)" onclick="highlightInTopology('${escapeHtml(f.dst_ip)}'); closeFlowDetailPanel();">${escapeHtml(f.dst_ip)}</a>`)}
                ${row(L.thFlProto || 'Proto/Porta', `${proto}/${f.dst_port ?? '—'}`)}
                ${row(L.thFlTraffic || 'Traffico', fmtBytes(f.total_bytes))}
                ${row(L.thFlPackets || 'Pacchetti', f.total_packets)}
                ${row(en ? 'Aggregated flows' : 'Flussi aggregati', f.flow_count)}
            </table>
            <div style="display:flex; flex-direction:column; gap:8px; margin-bottom:16px;">
                <button class="btn" style="text-align:left;" onclick="highlightInTopology('${escapeHtml(f.src_ip)}'); closeFlowDetailPanel();">
                    <i class="fa-solid fa-diagram-project"></i> ${en ? 'Show source in topology' : 'Mostra sorgente in topologia'}
                </button>
                <button class="btn" style="text-align:left;" onclick="highlightInTopology('${escapeHtml(f.dst_ip)}'); closeFlowDetailPanel();">
                    <i class="fa-solid fa-diagram-project"></i> ${en ? 'Show destination in topology' : 'Mostra destinazione in topologia'}
                </button>
                <button class="btn" style="text-align:left;" onclick="jumpToAnomaliesForFlow()">
                    <i class="fa-solid fa-triangle-exclamation"></i> ${en ? 'See anomalies for this flow' : 'Vedi anomalie di questo flusso'}
                </button>
                <button class="btn requires-write" style="text-align:left;" onclick="analyzeSingleFlowWithAi()" title="${en ? 'Send ONLY this flow to the AI assistant (identifiers; totals re-derived server-side)' : 'Invia SOLO questo flusso all\'assistente AI (identificatori; totali ri-derivati dal server)'}">
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
                <div style="padding:8px; border:1px solid var(--border); border-radius:8px; margin-bottom:6px;">
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

    function toggleFlowsTenantDropdown() {
        const dropdown = document.getElementById('flowsTenantDropdown');
        if (!dropdown) return;
        dropdown.style.display = dropdown.style.display === 'none' ? 'block' : 'none';
    }

    // Close dropdown on outside click
    document.addEventListener('click', function(e) {
        const dropdown = document.getElementById('flowsTenantDropdown');
        const btn = document.getElementById('flowsTenantBtn');
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
        const res = await apiFetch(`/api/observability/anomalies?status=${encodeURIComponent(status)}&window=7d&limit=100`);
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
                actions.push(`<button class="btn requires-write" style="font-size:11px; padding:3px 8px;" onclick="anomTransition(${a.id}, 'new', 'ack')">${lblAck}</button>`);
                actions.push(`<button class="btn requires-write" style="font-size:11px; padding:3px 8px;" onclick="anomTransition(${a.id}, 'new', 'resolved')">${lblResolve}</button>`);
            } else if (a.status === 'ack') {
                actions.push(`<button class="btn requires-write" style="font-size:11px; padding:3px 8px;" onclick="anomTransition(${a.id}, 'ack', 'resolved')">${lblResolve}</button>`);
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

    async function anomTransition(id, fromStatus, toStatus) {
        const res = await apiFetch(`/api/observability/anomalies/${id}/status`, {
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

