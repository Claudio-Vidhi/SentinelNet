// static/js/incidents.js
// ===== Incidenti (PREVIEW) — timeline multi-fonte e ragionamento deterministico =====
// La conclusione mostrata in testa e' SEMPRE quella deterministica del backend
// (causa, confidenza, regole attivate, fonti). La narrativa AI, quando richiesta,
// vive in un blocco separato e dichiaratamente generato: non e' la conclusione.
// Escaping: escapeHtml(x) su ogni valore interpolato (jsStr in mcp-client.js).

(function () {
    let _incidents = [];
    let _selectedId = null;
    let _catalog = {};   // rule_id -> definizione, per mostrare cosa fare
    let _interfaces = [];  // ultima vista interfacce, per l'indice dei checkbox

    // Le etichette si risolvono al RENDER, non alla definizione: un oggetto
    // costante catturerebbe la lingua al caricamento dello script e non si
    // aggiornerebbe piu' al cambio lingua.
    const L = k => ((typeof i18n !== 'undefined' && i18n[currentLang]) || {})[k] || k;
    const metaLabel = m => (m.labelKey ? L(m.labelKey) : (m.label || ''));

    const SOURCE_META = {
        evidence:   { icon: 'fa-scale-balanced', color: 'var(--danger)',   labelKey: 'incSrcEvidence' },
        syslog:     { icon: 'fa-file-lines',     color: 'var(--warning)',  labelKey: 'incSrcSyslog' },
        flow:       { icon: 'fa-chart-area',     color: 'var(--primary)',  labelKey: 'incSrcFlow' },
        api:        { icon: 'fa-satellite-dish', color: 'var(--success)',  labelKey: 'incSrcApi' },
        location:   { icon: 'fa-location-dot',   color: 'var(--text-muted)', labelKey: 'incSrcLocation' },
        endpoint:   { icon: 'fa-address-card',   color: 'var(--text-muted)', labelKey: 'incSrcEndpoint' },
    };

    // Il ruolo causale lo dichiara la regola che ha prodotto l'evidenza: qui si
    // mostra, non si reinterpreta.
    const ROLE_META = {
        trigger:     { color: 'var(--danger)',    labelKey: 'incRoleTrigger' },
        supporting:  { color: 'var(--primary)',   labelKey: 'incRoleSupporting' },
        symptom:     { color: 'var(--warning)',   labelKey: 'incRoleSymptom' },
        consequence: { color: 'var(--text-muted)', labelKey: 'incRoleConsequence' },
    };

    function fmtTime(ts) {
        if (!ts) return '--';
        return new Date(ts * 1000).toLocaleString();
    }

    function sevColor(sev) {
        if (sev === null || sev === undefined) return 'var(--text-muted)';
        if (sev <= 2) return 'var(--danger)';
        if (sev <= 3) return 'var(--warning)';
        if (sev <= 5) return 'var(--primary)';
        return 'var(--text-muted)';
    }

    function confidenceBar(value) {
        const pct = Math.max(0, Math.min(100, Number(value) || 0));
        const color = pct >= 70 ? 'var(--success)' : (pct >= 45 ? 'var(--warning)' : 'var(--text-muted)');
        return `<div style="height:6px; border-radius:0; background:var(--surface-3); overflow:hidden;">
                    <div style="width:${pct}%; height:100%; background:${color};"></div>
                </div>`;
    }

    function loadIncidentsTab() {
        loadIncidentsList();
        loadRuleCatalog();
        loadInterfaceExpectations();
    }

    // Conoscenza dell'OPERATORE, non della rete. Stesso modello per "e' giu'
    // per progetto" e per "e' in manutenzione stanotte": cambia solo se c'e'
    // una scadenza. Tenerli separati darebbe due posti dove cercare perche' un
    // allarme non e' scattato.
    //
    // Raggruppato tenant -> apparato -> interfacce: una tabella piatta con
    // l'IP ripetuto su ogni riga regge tre switch di laboratorio, non venti
    // apparati su quattro sedi.
    async function loadInterfaceExpectations() {
        const box = document.getElementById('incidentInterfaces');
        if (!box) return;
        try {
            const res = await apiFetch('/api/incidents/interfaces');
            if (!res || !res.ok) { box.innerHTML = ''; return; }
            const data = await res.json();
            const rows = data.interfaces || [];
            if (!rows.length) {
                box.innerHTML = `<div style="font-size:12px; color:var(--text-muted);">${L('incNoIfacesYet')}</div>`;
                return;
            }
            _interfaces = rows;
            const soglia = data.min_transitions || 4;
            const ore = Math.round((data.window_s || 86400) / 3600);

            // tenant -> apparato -> righe, conservando l'indice originale
            // perche' i controlli lo usano per risalire alla riga.
            const byTenant = new Map();
            rows.forEach((r, i) => {
                if (!byTenant.has(r.tenant)) byTenant.set(r.tenant, new Map());
                const dev = byTenant.get(r.tenant);
                if (!dev.has(r.device_ip)) dev.set(r.device_ip, []);
                dev.get(r.device_ip).push(Object.assign({}, r, { _i: i }));
            });

            const suppressions = data.suppressions || [];
            const deviceRule = ip => suppressions.find(
                s => s.device_ip === ip && !s.interface && !s.expired);

            const tenants = Array.from(byTenant.keys()).sort();
            box.innerHTML = tenants.map(t => {
                const devices = Array.from(byTenant.get(t).entries())
                    .sort((a, b) => a[0].localeCompare(b[0]));
                // Un solo tenant: l'intestazione di sede sarebbe rumore.
                const head = tenants.length > 1
                    ? `<div style="margin:14px 0 6px; font-size:12px; font-weight:700; color:var(--primary); text-transform:uppercase; letter-spacing:.4px;">
                           <i class="fa-solid fa-building"></i> ${escapeHtml(t)}
                           <span style="font-weight:400; color:var(--text-muted); text-transform:none;">· ${devices.length} ${L('incDevices')}</span>
                       </div>`
                    : '';
                return head + devices.map(entry =>
                    renderDeviceBlock(entry[0], entry[1], deviceRule(entry[0]), soglia, ore)).join('');
            }).join('') + `
                <div id="ifxStatus" style="font-size:11px; color:var(--text-muted); margin-top:8px;"></div>
                ${renderSuppressionList(suppressions)}`;
        } catch (e) { box.innerHTML = ''; }
    }

    function renderDeviceBlock(ip, list, devRule, soglia, ore) {
        const name = list[0].hostname || '';
        const down = list.filter(r => String(r.link).toLowerCase() === 'down').length;
        const unstable = list.filter(r => (r.transitions || 0) > 0).length;
        // Aperto solo se c'e' qualcosa da guardare: con venti apparati, venti
        // tabelle aperte sono un muro. Chiuso non vuol dire nascosto, il
        // riassunto sta nell'intestazione.
        const interesting = down > 0 || unstable > 0 || !!devRule;
        const badge = (txt, col) => `<span style="font-size:10px; color:${col}; border:1px solid ${col}; border-radius:0; padding:1px 6px; margin-left:6px;">${txt}</span>`;

        const sorted = list.slice().sort(
            (a, b) => (b.transitions || 0) - (a.transitions || 0)
                   || String(a.interface).localeCompare(String(b.interface)));

        return `<details ${interesting ? 'open' : ''} style="margin-bottom:8px; border:1px solid var(--border); border-radius:0; background:var(--surface-2);">
            <summary style="cursor:pointer; padding:8px 10px; font-size:13px;">
                <strong style="font-family:var(--font-code);">${escapeHtml(name || ip)}</strong>
                ${name ? `<span style="color:var(--text-muted); font-size:11px; font-family:var(--font-code);"> ${escapeHtml(ip)}</span>` : ''}
                <span style="color:var(--text-muted); font-size:11px;"> · ${list.length} ${L('incIfaces')}</span>
                ${down ? badge(down + ' down', 'var(--danger)') : ''}
                ${unstable ? badge(unstable + ' ' + L('incUnstable'), 'var(--warning)') : ''}
                ${devRule ? badge(L('incDevUnderMaint'), 'var(--text-muted)') : ''}
            </summary>
            <div style="padding:0 10px 10px;">
                ${renderDeviceSuppression(ip, list[0].tenant, devRule)}
                ${renderInterfaceTable(sorted, soglia, ore)}
            </div>
        </details>`;
    }

    // La manutenzione sull'INTERO apparato non aveva un posto in cui essere
    // dichiarata: si poteva sopprimere una porta alla volta, non il nodo.
    function renderDeviceSuppression(ip, tenant, rule) {
        const until = rule && rule.to_ts
            ? new Date((rule.to_ts * 1000) - new Date().getTimezoneOffset() * 60000)
                .toISOString().slice(0, 16) : '';
        return `<div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; padding:6px 0 10px; font-size:11px; color:var(--text-muted);">
            <label style="display:flex; align-items:center; gap:6px; cursor:pointer;">
                <input type="checkbox" id="dvx-${escapeHtml(ip)}" ${rule ? 'checked' : ''}
                       data-action="save-dev-suppression" data-tenant="${escapeHtml(tenant)}" data-ip="${escapeHtml(ip)}"
                       style="accent-color:var(--warning);">
                <span>${L('incDevExpectedDown')}</span>
            </label>
            <input type="datetime-local" id="dvu-${escapeHtml(ip)}" value="${escapeHtml(until)}"
                   data-action="save-dev-suppression" data-tenant="${escapeHtml(tenant)}" data-ip="${escapeHtml(ip)}"
                   title="${L('incUntilHint')}"
                   style="padding:3px 6px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:11px;">
            <input type="text" id="dvn-${escapeHtml(ip)}" value="${escapeHtml((rule || {}).note || '')}" placeholder="${L('incReasonPl')}"
                   style="flex:1; min-width:140px; padding:3px 6px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:11px;">
        </div>`;
    }

    function renderInterfaceTable(list, soglia, ore) {
        const dot = st => {
            const isDown = String(st || '').toLowerCase() === 'down';
            return `<span style="color:${isDown ? 'var(--danger)' : 'var(--success)'}; font-size:11px;">${escapeHtml(st || '?')}</span>`;
        };
        // L'instabilita' va MOSTRATA anche quando non e' diventata un
        // incidente: la regola guarda la finestra di correlazione, questa
        // colonna guarda un giorno.
        const flap = n => {
            if (!n) return '<span style="color:var(--text-muted);">&mdash;</span>';
            const grave = n >= soglia;
            return `<span title="${L('incFlapTitle').replace('{h}', ore)}${grave ? L('incFlapOver') : ''}"
                style="color:${grave ? 'var(--danger)' : 'var(--warning)'}; font-weight:${grave ? '700' : '400'};">${n}${grave ? ' &#9888;' : ''}</span>`;
        };
        const local = ts => {
            if (!ts) return '';
            const d = new Date(ts * 1000);
            return new Date(d.getTime() - d.getTimezoneOffset() * 60000)
                .toISOString().slice(0, 16);
        };
        const th = t => `<th style="text-align:left; padding:5px 8px; font-size:10px; text-transform:uppercase; color:var(--text-muted); border-bottom:1px solid var(--border);">${t}</th>`;
        const cols = [L('incThInterface'), L('incThLink'), L('incThAdmin'),
                      L('incThTransitions') + ' ' + ore + 'h',
                      L('incThExpected'), L('incThUntil'), L('incThNote')];
        return `<table style="width:100%; border-collapse:collapse; font-size:12px;">
            <thead><tr>${cols.map(th).join('')}</tr></thead>
            <tbody>${list.map(r => `<tr${r.scope === 'device' ? ' style="opacity:.55;"' : ''}>
                <td style="padding:5px 8px; border-bottom:1px solid var(--border); font-family:var(--font-code);">${escapeHtml(r.interface)}</td>
                <td style="padding:5px 8px; border-bottom:1px solid var(--border);">${dot(r.link)}</td>
                <td style="padding:5px 8px; border-bottom:1px solid var(--border);">${dot(r.admin_status)}</td>
                <td style="padding:5px 8px; border-bottom:1px solid var(--border);">${flap(r.transitions)}</td>
                <td style="padding:5px 8px; border-bottom:1px solid var(--border);">
                    <input type="checkbox" id="ifx-${r._i}" ${r.suppressed ? 'checked' : ''}
                           ${r.scope === 'device' ? `disabled title="${L('incCoveredByDevice')}"` : ''}
                           data-action="save-if-expectation" data-index="${r._i}" style="accent-color:var(--primary);"></td>
                <td style="padding:5px 8px; border-bottom:1px solid var(--border);">
                    <input type="datetime-local" id="ifu-${r._i}" value="${escapeHtml(local(r.to_ts))}"
                           data-action="save-if-expectation" data-index="${r._i}"
                           style="padding:3px 6px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:11px;"></td>
                <td style="padding:5px 8px; border-bottom:1px solid var(--border);">
                    <input type="text" id="ifn-${r._i}" value="${escapeHtml(r.note || '')}" placeholder="${L('incReasonPl')}"
                           style="width:100%; padding:3px 6px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:11px;"></td>
            </tr>`).join('')}</tbody></table>`;
    }

    async function saveDeviceSuppression(tenant, ip) {
        const until = document.getElementById('dvu-' + ip).value;
        const res = await apiFetch('/api/incidents/interfaces/expected', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tenant: tenant, device_ip: ip, interface: null,
                suppressed: document.getElementById('dvx-' + ip).checked,
                to_ts: until ? Math.floor(new Date(until).getTime() / 1000) : null,
                note: document.getElementById('dvn-' + ip).value
            })
        });
        if (!res) return;
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            const st = document.getElementById('ifxStatus');
            if (st) st.textContent = err.detail || L('incErrGeneric');
            return;
        }
        await loadInterfaceExpectations();
    }

    // Anche quelle scadute: mostrarle spente e' cio' che rende leggibile
    // perche' un incidente di ieri non e' mai nato.
    function renderSuppressionList(list) {
        if (!list.length) return '';
        const when = r => r.to_ts
            ? `${L('incSuppUntil')} ${new Date(r.to_ts * 1000).toLocaleString()}`
            : L('incSuppNoExpiry');
        return `<div style="margin-top:12px; font-size:11px;">
            <div style="color:var(--text-muted); text-transform:uppercase; font-weight:700; margin-bottom:6px;">${L('incSuppDeclared')}</div>
            ${list.map(r => `<div style="padding:4px 0; border-bottom:1px solid var(--border); ${r.expired ? 'opacity:.45; text-decoration:line-through;' : ''}">
                <code>${escapeHtml(r.device_ip || '')}</code>${r.interface ? ':' + escapeHtml(r.interface) : ` <em>${L('incSuppWholeDevice')}</em>`}
                — ${escapeHtml(when(r))}
                ${r.note ? ' · ' + escapeHtml(r.note) : ''}
                <span style="color:var(--text-muted);">· ${escapeHtml(r.by || '')}</span>
            </div>`).join('')}
        </div>`;
    }

    async function saveInterfaceExpectation(index) {
        const row = _interfaces[index];
        if (!row) return;
        const st = document.getElementById('ifxStatus');
        const until = document.getElementById(`ifu-${index}`).value;
        const res = await apiFetch('/api/incidents/interfaces/expected', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tenant: row.tenant, device_ip: row.device_ip,
                interface: row.interface,
                suppressed: document.getElementById(`ifx-${index}`).checked,
                to_ts: until ? Math.floor(new Date(until).getTime() / 1000) : null,
                note: document.getElementById(`ifn-${index}`).value
            })
        });
        if (!res) return;
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            if (st) st.textContent = err.detail || L('incErrGeneric');
            return;
        }
        await loadInterfaceExpectations();
        const box = document.getElementById('ifxStatus');
        if (box) box.textContent = `${row.device_ip}:${row.interface} aggiornata.`;
    }

    async function loadRuleCatalog() {
        const box = document.getElementById('incidentRules');
        if (!box) return;
        try {
            const res = await apiFetch('/api/incidents/rules');
            if (!res || !res.ok) { box.innerHTML = ''; return; }
            const data = await res.json();
            _catalog = {};
            (data.rules || []).forEach(r => { _catalog[r.id] = r; });
            box.innerHTML = (data.rules || []).map(r => `
                <div style="padding:10px; border:1px solid var(--border); border-radius:0; margin-bottom:8px; background:var(--surface-2);">
                    <div style="display:flex; justify-content:space-between; gap:12px; align-items:baseline;">
                        <strong style="font-size:13px;">${escapeHtml(r.title)}</strong>
                        <span style="font-size:11px; color:var(--text-muted); font-family:var(--font-code);">${escapeHtml(r.id)} v${escapeHtml(r.version)}</span>
                    </div>
                    <div style="font-size:12px; color:var(--text-muted); margin:4px 0 6px;">${escapeHtml(r.description)}</div>
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
                        consuma: ${escapeHtml((r.inputs || []).join(', '))} ·
                        produce: ${escapeHtml((r.outputs || []).join(', '))}
                    </div>
                    ${r.investigation ? `<div style="font-size:12px; margin-bottom:4px;">
                        <strong>${L('incInvestigate')}</strong> ${escapeHtml(r.investigation)}</div>` : ''}
                    ${r.remediation ? `<div style="font-size:12px; margin-bottom:8px;">
                        <strong>${L('incRemediation')}</strong> ${escapeHtml(r.remediation)}</div>` : ''}
                    ${(r.parameters || []).length ? `<div style="display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end;">
                        ${r.parameters.map(p => `<div>
                            <label style="font-size:11px; color:var(--text-muted); display:block;" title="${escapeHtml(p.description || '')}">
                                ${escapeHtml(p.name)} (${escapeHtml(p.min)}–${escapeHtml(p.max)})
                            </label>
                            <input type="number" id="rp-${escapeHtml(r.id)}-${escapeHtml(p.name)}"
                                   value="${escapeHtml((r.effective || {})[p.name] ?? p.default)}"
                                   min="${escapeHtml(p.min)}" max="${escapeHtml(p.max)}"
                                   style="width:110px; padding:5px 8px; border-radius:0; border:1px solid var(--border);
                                          background:var(--surface-2); color:var(--text); font-size:12px;">
                        </div>`).join('')}
                        <button class="btn btn-secondary btn-small" style="width:auto;"
                                data-action="save-rule-params" data-rule-id="${escapeHtml(r.id)}">${L('incSaveThresholds')}</button>
                        <span id="rp-status-${escapeHtml(r.id)}" style="font-size:11px; color:var(--text-muted);"></span>
                    </div>` : `<div style="font-size:11px; color:var(--text-muted);">${L('incNoThresholds')}</div>`}
                </div>`).join('');
        } catch (e) { box.innerHTML = ''; }
    }

    async function saveRuleParameters(ruleId) {
        const st = document.getElementById(`rp-status-${ruleId}`);
        const payload = {};
        document.querySelectorAll(`[id^="rp-${ruleId}-"]`).forEach(input => {
            payload[input.id.slice(`rp-${ruleId}-`.length)] = Number(input.value);
        });
        try {
            const res = await apiFetch(`/api/incidents/rules/${encodeURIComponent(ruleId)}/parameters`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!res) return;
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                if (st) st.textContent = err.detail || L('incErrGeneric');
                return;
            }
            if (st) st.textContent = L('incSaved');
        } catch (e) {
            if (st) st.textContent = L('incErrGeneric');
        }
    }

    async function loadIncidentsList() {
        const box = document.getElementById('incidentsList');
        if (!box) return;
        const status = (document.getElementById('incStatusFilter') || {}).value || 'new';
        const window_ = (document.getElementById('incWindowFilter') || {}).value || '24h';
        box.innerHTML = '<div style="text-align:center; padding:16px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i></div>';
        try {
            const res = await apiFetch(`/api/incidents?status=${encodeURIComponent(status)}&window=${encodeURIComponent(window_)}`);
            if (!res || !res.ok) { box.innerHTML = `<div style="color:var(--danger); font-size:12px;">${L('incErrLoad')}</div>`; return; }
            const data = await res.json();
            _incidents = data.incidents || [];
            // Il pannello di destra viene scritto solo da openIncident(): senza
            // questo, cambiando filtro la lista si svuota ma il dettaglio resta
            // su un incidente che non e' piu' in elenco.
            if (_selectedId !== null && !_incidents.some(i => i.id === _selectedId)) {
                _selectedId = null;
                const detail = document.getElementById('incidentDetail');
                if (detail) detail.innerHTML = `<div style="color:var(--text-muted); font-size:12px; padding:12px;">${L('incSelectOne')}</div>`;
            }
            renderIncidentsList();
        } catch (e) {
            box.innerHTML = `<div style="color:var(--danger); font-size:12px;">${L('incErrLoad')}</div>`;
        }
    }

    function renderIncidentsList() {
        const box = document.getElementById('incidentsList');
        if (!box) return;
        if (!_incidents.length) {
            box.innerHTML = `<div style="color:var(--text-muted); font-size:12px; padding:12px;">${L('incNoIncidents')}</div>`;
            return;
        }
        box.innerHTML = _incidents.map(inc => {
            const active = inc.id === _selectedId;
            return `<div class="incident-list-item" data-id="${Number(inc.id)}" style="cursor:pointer; padding:10px; border-radius:0; margin-bottom:8px;
                        border:1px solid ${active ? 'var(--primary)' : 'var(--border)'}; background:var(--surface-2);">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                    <span style="width:8px; height:8px; border-radius:50%; background:${sevColor(inc.severity)};"></span>
                    <strong style="font-size:13px;">${escapeHtml(inc.title || inc.entity_key)}</strong>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">
                    ${escapeHtml(inc.event_count)} eventi · ${escapeHtml(inc.status)}
                    ${inc.closed_ts ? '· chiuso' : '· aperto'} · ${escapeHtml(fmtTime(inc.last_event_ts))}
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:11px; color:var(--text-muted); min-width:70px;">${escapeHtml(inc.confidence ?? '--')}% conf.</span>
                    <div style="flex:1;">${confidenceBar(inc.confidence)}</div>
                </div>
            </div>`;
        }).join('');
    }

    async function openIncident(id) {
        _selectedId = id;
        renderIncidentsList();
        if (!Object.keys(_catalog).length) await loadRuleCatalog();
        const box = document.getElementById('incidentDetail');
        if (!box) return;
        box.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i></div>';
        try {
            const res = await apiFetch(`/api/incidents/${Number(id)}`);
            if (!res || !res.ok) { box.innerHTML = `<div style="color:var(--danger); font-size:12px;">${L('incNotAvailable')}</div>`; return; }
            const data = await res.json();
            renderIncidentDetail(data.incident || {}, data.timeline || [],
                                 data.previous_conclusions || [],
                                 data.flow_path || null);
        } catch (e) {
            box.innerHTML = `<div style="color:var(--danger); font-size:12px;">${L('incNotAvailable')}</div>`;
        }
    }

    function renderReasoning(inc) {
        const r = inc.reasoning || {};
        const rules = (r.rules_fired || []).map(x =>
            `<span class="badge" style="font-size:11px;">${escapeHtml(x)}</span>`).join(' ') || `<span style="color:var(--text-muted);">${L('incNone')}</span>`;
        const sources = (r.sources_used || []).map(x =>
            `<span class="badge" style="font-size:11px;">${escapeHtml(x)}</span>`).join(' ') || `<span style="color:var(--text-muted);">${L('incNone')}</span>`;
        const byRole = r.evidence_by_role || {};
        const roleCounts = Object.keys(byRole).map(role => {
            const meta = ROLE_META[role] || { color: 'var(--text-muted)', label: role };
            const roleLabel = metaLabel(meta);
            return `<span style="padding:1px 6px; border-radius:0; font-size:10px; font-weight:700;
                        color:${meta.color}; border:1px solid ${meta.color};">${escapeHtml(roleLabel)} ${byRole[role].length}</span>`;
        }).join(' ') || `<span style="color:var(--text-muted);">${L('incNone')}</span>`;
        return `<div style="padding:12px; border-radius:0; background:var(--surface-2); border:1px solid var(--border); margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:10px;">
                <div>
                    <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700;">${L('incCauseTitle')}</div>
                    <div style="font-size:17px; font-family:var(--font-display);">${escapeHtml(inc.cause_kind || '--')}</div>
                </div>
                <div style="min-width:160px;">
                    <div style="font-size:11px; color:var(--text-muted); text-align:right;">Confidenza ${escapeHtml(inc.confidence ?? '--')}%</div>
                    ${confidenceBar(inc.confidence)}
                </div>
            </div>
            <div style="font-size:12px; margin-bottom:6px;"><strong>${L('incRulesFired')}</strong> ${rules}</div>
            <div style="font-size:12px; margin-bottom:6px;"><strong>${L('incSourcesCorrob')}</strong> ${sources}</div>
            <div style="font-size:12px; margin-bottom:6px;"><strong>${L('incEvidenceByRole')}</strong> ${roleCounts}</div>
            <div style="font-size:11px; color:var(--text-muted);">
                ${L('incConfBasis').replace('{b}', escapeHtml(r.base_confidence ?? '--')).replace('{s}', escapeHtml(r.confidence_step ?? '--'))}
                ${L('incRuleRef')} ${escapeHtml(r.rule_id || '--')} v${escapeHtml(r.rule_version || '--')}
                ${r.rule_params && Object.keys(r.rule_params).length
                    ? '· soglie ' + escapeHtml(JSON.stringify(r.rule_params)) : ''}
            </div>
            ${renderGuidance(r.rule_id)}
        </div>`;
    }

    // "Cosa dovrebbe indagare l'ingegnere dopo": non un testo scritto a parte,
    // ma i campi che la regola stessa dichiara nel catalogo.
    function renderGuidance(ruleId) {
        const rule = _catalog[ruleId];
        if (!rule || (!rule.investigation && !rule.remediation)) return '';
        return `<div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border);">
            ${rule.investigation ? `<div style="font-size:12px; margin-bottom:4px;">
                <i class="fa-solid fa-magnifying-glass" style="color:var(--primary);"></i>
                <strong>${L('incInvestigate')}</strong> ${escapeHtml(rule.investigation)}</div>` : ''}
            ${rule.remediation ? `<div style="font-size:12px;">
                <i class="fa-solid fa-screwdriver-wrench" style="color:var(--success);"></i>
                <strong>${L('incRemediation')}</strong> ${escapeHtml(rule.remediation)}</div>` : ''}
        </div>`;
    }

    function renderTimeline(entries) {
        if (!entries.length) {
            return `<div style="color:var(--text-muted); font-size:12px;">${L('incNoTimeline')}</div>`;
        }
        return `<div style="border-left:2px solid var(--border); margin-left:8px; padding-left:16px;">` +
            entries.map(e => {
                const meta = SOURCE_META[e.source] || { icon: 'fa-circle', color: 'var(--text-muted)', label: e.source };
                const role = e.role ? ROLE_META[e.role] : null;
                const dotColor = role ? role.color : meta.color;
                const prov = (e.ref && e.ref.rule_id)
                    ? `${e.ref.rule_id} v${e.ref.rule_version}` + (e.ref.rule_params && Object.keys(e.ref.rule_params).length
                        ? ' · ' + JSON.stringify(e.ref.rule_params) : '')
                    : '';
                const attrs = (e.ref && e.ref.attrs && Object.keys(e.ref.attrs).length)
                    ? JSON.stringify(e.ref.attrs) : '';
                // Un'evidenza ritrattata resta visibile, barrata: la timeline
                // racconta anche cosa si era concluso e perché non regge più.
                const retracted = e.status === 'retracted';
                const why = retracted && e.ref
                    ? `${e.ref.retracted_reason || L('incRetractedDefault')}${e.ref.retracted_by_rule_id ? ' — ' + e.ref.retracted_by_rule_id : ''}`
                    : '';
                return `<div style="position:relative; margin-bottom:12px; ${retracted ? 'opacity:0.65;' : ''}">
                    <span style="position:absolute; left:-23px; top:2px; width:12px; height:12px; border-radius:50%;
                                 background:${retracted ? 'var(--surface-3)' : 'var(--surface)'}; border:2px solid ${dotColor};"></span>
                    <div style="font-size:11px; color:var(--text-muted);">
                        ${escapeHtml(fmtTime(e.ts))} ·
                        <i class="fa-solid ${meta.icon}" style="color:${meta.color};"></i> ${escapeHtml(metaLabel(meta))}
                        ${role ? `<span style="margin-left:6px; padding:1px 6px; border-radius:0; font-weight:700;
                                     font-size:10px; color:${role.color}; border:1px solid ${role.color};">${escapeHtml(metaLabel(role))}</span>` : ''}
                        ${retracted ? `<span style="margin-left:6px; padding:1px 6px; border-radius:0; font-weight:700;
                                     font-size:10px; color:var(--text-muted); border:1px solid var(--text-muted);">${L('incRetractedBadge')}</span>` : ''}
                    </div>
                    <div style="font-size:13px; ${retracted ? 'text-decoration:line-through;' : ''}
                                color:${e.severity !== null && e.severity !== undefined ? sevColor(e.severity) : 'var(--text)'};">
                        ${escapeHtml(e.text)}
                    </div>
                    ${why ? `<div style="font-size:11px; color:var(--warning); margin-top:2px;">
                                <i class="fa-solid fa-rotate-left"></i> ${escapeHtml(why)}</div>` : ''}
                    ${prov ? `<div style="font-size:11px; color:var(--text-muted); margin-top:2px;" title="${L('incProvTitle')}">
                                <i class="fa-solid fa-fingerprint"></i> ${escapeHtml(prov)}</div>` : ''}
                    ${attrs ? `<div style="font-family:var(--font-code); font-size:11px; color:var(--text-muted); margin-top:2px; word-break:break-all;">${escapeHtml(attrs)}</div>` : ''}
                </div>`;
            }).join('') + '</div>';
    }

    function renderAiBlock(inc) {
        const body = inc.ai_narrative
            ? `<div style="font-size:13px; white-space:pre-wrap;">${escapeHtml(inc.ai_narrative)}</div>
               <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Generato il ${escapeHtml(fmtTime(inc.ai_narrative_ts))}</div>`
            : `<div style="font-size:12px; color:var(--text-muted);">${L('incNoNarrative')}</div>`;
        return `<div style="margin-top:18px; padding:12px; border-radius:0; border:1px dashed var(--primary); background:color-mix(in srgb, var(--primary) 6%, transparent);">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:8px;">
                <span style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--primary);">
                    <i class="fa-solid fa-robot"></i> ${L('incAiRestated')}
                </span>
                <button class="btn btn-secondary btn-small" style="width:auto;" data-action="explain-incident" data-id="${Number(inc.id)}">
                    <i class="fa-solid fa-wand-magic-sparkles"></i> ${inc.ai_narrative ? L('incRegenerate') : L('incExplainAi')}
                </button>
            </div>
            <div id="incidentAiBody">${body}</div>
        </div>`;
    }

    function renderConclusionHistory(history) {
        if (!history.length) return '';
        return `<div style="margin-top:12px; padding:10px; border-radius:0; background:var(--surface-3);">
            <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--text-muted); margin-bottom:6px;">
                <i class="fa-solid fa-clock-rotate-left"></i> Conclusioni precedenti (superate)
            </div>
            ${history.map(h => `<div style="font-size:12px; color:var(--text-muted); text-decoration:line-through;">
                ${escapeHtml(fmtTime(h.concluded_ts))} — ${escapeHtml(h.cause_kind)}
                (${escapeHtml(h.confidence)}%)
            </div>`).join('')}
        </div>`;
    }

    // Percorso logico della conversazione. Un salto sconosciuto va MOSTRATO
    // come tale: l'ingegnere decide dove guardare in base a questo, e un buco
    // taciuto lo manda a cercare nel posto sbagliato.
    const DIRECTION_KEY = {
        east_west: 'incDirEastWest',
        north_south: 'incDirNorthSouth',
        control_plane: 'incDirControlPlane',
        local: 'incDirLocal'
    };

    function renderFlowPath(path) {
        if (!path || !(path.hops || []).length) return '';
        const hops = path.hops.map(h => {
            const unknown = h.known === false;
            const color = unknown ? 'var(--text-muted)' : 'var(--text)';
            const icon = unknown ? 'fa-circle-question' : ({
                endpoint: 'fa-desktop', access: 'fa-ethernet',
                gateway: 'fa-route', perimeter: 'fa-shield-halved'
            }[h.kind] || 'fa-circle-dot');
            return `<div style="display:flex; align-items:center; gap:8px; padding:6px 10px; background:var(--surface-2); border:1px solid var(--border); border-radius:0; font-size:12px; color:${color}; ${unknown ? 'border-style:dashed;' : ''}">
                <i class="fa-solid ${icon}"></i>
                <span>${escapeHtml(h.label || h.kind)}</span>
            </div>`;
        }).join('<i class="fa-solid fa-angle-right" style="color:var(--text-muted); align-self:center;"></i>');
        const warn = path.complete ? '' :
            `<div style="font-size:11px; color:var(--warning); margin-top:6px;"><i class="fa-solid fa-triangle-exclamation"></i> ${L('incPathPartial')}</div>`;
        return `<h4 style="margin:12px 0 10px; font-size:14px; color:var(--primary);"><i class="fa-solid fa-diagram-project"></i> ${L('incPathTitle')}
                    <span style="font-weight:normal; font-size:12px; color:var(--text-muted);">${escapeHtml(DIRECTION_KEY[path.direction] ? L(DIRECTION_KEY[path.direction]) : (path.direction || ''))}</span></h4>
                <div style="display:flex; flex-wrap:wrap; gap:6px; align-items:center;">${hops}</div>${warn}`;
    }

    function renderIncidentDetail(inc, entries, history, flowPath) {
        const box = document.getElementById('incidentDetail');
        if (!box) return;
        const next = inc.status === 'new'
            ? `<button class="btn btn-secondary btn-small" style="width:auto;" data-action="set-incident-status" data-id="${Number(inc.id)}" data-from="new" data-to="ack">${L('incBtnAck')}</button>
               <button class="btn btn-secondary btn-small" style="width:auto;" data-action="set-incident-status" data-id="${Number(inc.id)}" data-from="new" data-to="resolved">${L('incBtnResolve')}</button>`
            : (inc.status === 'ack'
                ? `<button class="btn btn-secondary btn-small" style="width:auto;" data-action="set-incident-status" data-id="${Number(inc.id)}" data-from="ack" data-to="resolved">${L('incBtnResolve')}</button>`
                : '');
        box.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:14px;">
                <div>
                    <h3 style="margin:0; font-family:var(--font-display); font-size:21px;">${escapeHtml(inc.title || inc.entity_key)}</h3>
                    <div style="font-size:12px; color:var(--text-muted);">
                        ${escapeHtml(inc.entity_key)} · tenant ${escapeHtml(inc.tenant)} ·
                        ${L('incFromTo').replace('{a}', escapeHtml(fmtTime(inc.opened_ts))).replace('{b}', escapeHtml(fmtTime(inc.last_event_ts)))}
                    </div>
                </div>
                <div style="display:flex; gap:8px;">${next}</div>
            </div>
            ${renderReasoning(inc)}
            ${renderConclusionHistory(history || [])}
            ${renderFlowPath(flowPath)}
            <h4 style="margin:12px 0 10px; font-size:14px; color:var(--primary);"><i class="fa-solid fa-timeline"></i> ${L('incTimeline')}</h4>
            ${renderTimeline(entries)}
            ${renderAiBlock(inc)}`;
    }

    async function setIncidentStatus(id, from, to) {
        try {
            const res = await apiFetch(`/api/incidents/${Number(id)}/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ from_status: from, status: to })
            });
            if (!res) return;
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                alert(err.detail || L('incErrTransition'));
                return;
            }
            await loadIncidentsList();
            // Con il filtro su "Nuovi", prendere in carico un incidente lo toglie
            // dalla lista: riaprirlo comunque rimetterebbe il dettaglio stantio.
            if (_incidents.some(i => i.id === id)) await openIncident(id);
        } catch (e) {}
    }

    async function explainIncident(id) {
        const body = document.getElementById('incidentAiBody');
        if (body) body.innerHTML = `<div style="color:var(--text-muted); font-size:12px;"><i class="fa-solid fa-circle-notch fa-spin"></i> ${L('incGenerating')}</div>`;
        try {
            const res = await apiFetch(`/api/incidents/${Number(id)}/explain`, { method: 'POST' });
            if (!res) return;
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                if (body) body.innerHTML = `<div style="color:var(--danger); font-size:12px;">${escapeHtml(err.detail || L('incErrGeneration'))}</div>`;
                return;
            }
            const data = await res.json();
            if (body) {
                body.innerHTML = `<div style="font-size:13px; white-space:pre-wrap;">${escapeHtml(data.ai_narrative)}</div>
                                  <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Generato il ${escapeHtml(fmtTime(data.ai_narrative_ts))}</div>`;
            }
        } catch (e) {
            if (body) body.innerHTML = `<div style="color:var(--danger); font-size:12px;">${L('incErrGeneration')}</div>`;
        }
    }

    // Delegated and static event listeners
    document.getElementById('incStatusFilter')?.addEventListener('change', loadIncidentsList);
    document.getElementById('incWindowFilter')?.addEventListener('change', loadIncidentsList);

    document.getElementById('incidentsList')?.addEventListener('click', (e) => {
        const item = e.target.closest('.incident-list-item[data-id]');
        if (item && item.dataset.id) {
            openIncident(Number(item.dataset.id));
        }
    });

    document.getElementById('incidentDetail')?.addEventListener('click', (e) => {
        const expBtn = e.target.closest('[data-action="explain-incident"]');
        if (expBtn && expBtn.dataset.id) {
            explainIncident(Number(expBtn.dataset.id));
            return;
        }
        const stBtn = e.target.closest('[data-action="set-incident-status"]');
        if (stBtn && stBtn.dataset.id && stBtn.dataset.from && stBtn.dataset.to) {
            setIncidentStatus(Number(stBtn.dataset.id), stBtn.dataset.from, stBtn.dataset.to);
            return;
        }
    });

    document.getElementById('incidentRules')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="save-rule-params"]');
        if (btn && btn.dataset.ruleId) {
            saveRuleParameters(btn.dataset.ruleId);
        }
    });

    document.getElementById('incidentInterfaces')?.addEventListener('change', (e) => {
        const devEl = e.target.closest('[data-action="save-dev-suppression"]');
        if (devEl && devEl.dataset.tenant && devEl.dataset.ip) {
            saveDeviceSuppression(devEl.dataset.tenant, devEl.dataset.ip);
            return;
        }
        const ifEl = e.target.closest('[data-action="save-if-expectation"]');
        if (ifEl && ifEl.dataset.index != null) {
            saveInterfaceExpectation(Number(ifEl.dataset.index));
            return;
        }
    });

    window.loadIncidentsTab = loadIncidentsTab;
    window.loadIncidentsList = loadIncidentsList;
    window.openIncident = openIncident;
    window.setIncidentStatus = setIncidentStatus;
    window.explainIncident = explainIncident;
    window.saveRuleParameters = saveRuleParameters;
    window.saveInterfaceExpectation = saveInterfaceExpectation;
    window.saveDeviceSuppression = saveDeviceSuppression;
})();
