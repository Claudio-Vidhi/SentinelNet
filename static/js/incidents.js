// static/js/incidents.js
// ===== Incidenti (PREVIEW) — timeline multi-fonte e ragionamento deterministico =====
// La conclusione mostrata in testa e' SEMPRE quella deterministica del backend
// (causa, confidenza, regole attivate, fonti). La narrativa AI, quando richiesta,
// vive in un blocco separato e dichiaratamente generato: non e' la conclusione.
// Escaping: escapeHtml(jsStr(x)) su ogni valore interpolato (jsStr in mcp-client.js).

(function () {
    let _incidents = [];
    let _selectedId = null;
    let _catalog = {};   // rule_id -> definizione, per mostrare cosa fare
    let _interfaces = [];  // ultima vista interfacce, per l'indice dei checkbox

    const SOURCE_META = {
        evidence:   { icon: 'fa-scale-balanced', color: 'var(--danger)',   label: 'Evidenza' },
        syslog:     { icon: 'fa-file-lines',     color: 'var(--warning)',  label: 'Syslog' },
        flow:       { icon: 'fa-chart-area',     color: 'var(--primary)',  label: 'Flussi' },
        api:        { icon: 'fa-satellite-dish', color: 'var(--success)',  label: 'Stato apparato' },
        location:   { icon: 'fa-location-dot',   color: 'var(--text-muted)', label: 'Posizione' },
        endpoint:   { icon: 'fa-address-card',   color: 'var(--text-muted)', label: 'Indirizzo noto' },
    };

    // Il ruolo causale lo dichiara la regola che ha prodotto l'evidenza: qui si
    // mostra, non si reinterpreta.
    const ROLE_META = {
        trigger:     { color: 'var(--danger)',    label: 'INNESCO' },
        supporting:  { color: 'var(--primary)',   label: 'SUPPORTO' },
        symptom:     { color: 'var(--warning)',   label: 'SINTOMO' },
        consequence: { color: 'var(--text-muted)', label: 'CONSEGUENZA' },
    };

    async function applyIncidentsGating() {
        try {
            const res = await apiFetch('/api/settings/incidents');
            if (!res || !res.ok) return;
            const data = await res.json();
            const nav = document.getElementById('navIncidents');
            if (nav) nav.style.display = data.incidents_preview ? '' : 'none';
            const toggle = document.getElementById('incidentsToggle');
            if (toggle) toggle.checked = !!data.incidents_preview;
        } catch (e) {}
    }

    async function setIncidentsPreview(enabled) {
        const st = document.getElementById('incidentsStatus');
        try {
            const res = await apiFetch('/api/settings/incidents', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !!enabled })
            });
            if (res && res.ok) {
                if (st) st.textContent = currentLang === 'en' ? 'Saved.' : 'Salvato.';
                await applyIncidentsGating();
            }
        } catch (e) {
            if (st) st.textContent = currentLang === 'en' ? 'Error.' : 'Errore.';
        }
    }

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
        return `<div style="height:6px; border-radius:3px; background:var(--surface-3); overflow:hidden;">
                    <div style="width:${pct}%; height:100%; background:${color};"></div>
                </div>`;
    }

    function loadIncidentsTab() {
        loadIncidentsList();
        loadRuleCatalog();
        loadInterfaceExpectations();
    }

    // Conoscenza dell'OPERATORE, non della rete: una porta giù per progetto
    // resta giù, e senza un posto in cui dirlo ogni sua transizione diventa
    // rumore che nasconde quello vero.
    async function loadInterfaceExpectations() {
        const box = document.getElementById('incidentInterfaces');
        if (!box) return;
        try {
            const res = await apiFetch('/api/incidents/interfaces');
            if (!res || !res.ok) { box.innerHTML = ''; return; }
            const rows = (await res.json()).interfaces || [];
            if (!rows.length) {
                box.innerHTML = '<div style="font-size:12px; color:var(--text-muted);">Nessuna interfaccia ancora osservata. Serve almeno un giro di polling (REST o SNMP).</div>';
                return;
            }
            const dot = s => {
                const down = String(s || '').toLowerCase() === 'down';
                return `<span style="color:${down ? 'var(--danger)' : 'var(--success)'}; font-size:11px;">${escapeHtml(jsStr(s || '?'))}</span>`;
            };
            box.innerHTML = `<table style="width:100%; border-collapse:collapse; font-size:12px;">
                <thead><tr>${['Apparato','Interfaccia','Link','Admin','Atteso giù','Nota']
                    .map(h => `<th style="text-align:left; padding:6px 8px; font-size:11px; text-transform:uppercase; color:var(--text-muted); border-bottom:1px solid var(--border);">${h}</th>`).join('')}</tr></thead>
                <tbody>${rows.map((r, i) => `<tr>
                    <td style="padding:6px 8px; border-bottom:1px solid var(--border); font-family:var(--font-code);">${escapeHtml(jsStr(r.device_ip))}</td>
                    <td style="padding:6px 8px; border-bottom:1px solid var(--border); font-family:var(--font-code);">${escapeHtml(jsStr(r.interface))}</td>
                    <td style="padding:6px 8px; border-bottom:1px solid var(--border);">${dot(r.link)}</td>
                    <td style="padding:6px 8px; border-bottom:1px solid var(--border);">${dot(r.admin_status)}</td>
                    <td style="padding:6px 8px; border-bottom:1px solid var(--border);">
                        <input type="checkbox" id="ifx-${i}" ${r.expected_down ? 'checked' : ''}
                               onchange="saveInterfaceExpectation(${i})" style="accent-color:var(--primary);"></td>
                    <td style="padding:6px 8px; border-bottom:1px solid var(--border);">
                        <input type="text" id="ifn-${i}" value="${escapeHtml(jsStr(r.note || ''))}" placeholder="perché"
                               style="width:100%; padding:4px 6px; border-radius:6px; border:1px solid var(--border); background:var(--surface-2); color:var(--text); font-size:11px;"></td>
                </tr>`).join('')}</tbody></table>
                <div id="ifxStatus" style="font-size:11px; color:var(--text-muted); margin-top:6px;"></div>`;
            _interfaces = rows;
        } catch (e) { box.innerHTML = ''; }
    }

    async function saveInterfaceExpectation(index) {
        const row = _interfaces[index];
        if (!row) return;
        const st = document.getElementById('ifxStatus');
        const res = await apiFetch('/api/incidents/interfaces/expected', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                tenant: row.tenant, device_ip: row.device_ip,
                interface: row.interface,
                expected_down: document.getElementById(`ifx-${index}`).checked,
                note: document.getElementById(`ifn-${index}`).value
            })
        });
        if (!res) return;
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            if (st) st.textContent = err.detail || 'Errore.';
            return;
        }
        row.expected_down = (await res.json()).expected_down;
        if (st) st.textContent = `${row.device_ip}:${row.interface} aggiornata.`;
    }

    // Il pannello non conosce le regole: le legge dal catalogo, che è generato
    // dal codice del motore. Aggiungere una regola non richiede toccare la UI.
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
                <div style="padding:10px; border:1px solid var(--border); border-radius:8px; margin-bottom:8px; background:var(--surface-2);">
                    <div style="display:flex; justify-content:space-between; gap:12px; align-items:baseline;">
                        <strong style="font-size:13px;">${escapeHtml(jsStr(r.title))}</strong>
                        <span style="font-size:11px; color:var(--text-muted); font-family:var(--font-code);">${escapeHtml(jsStr(r.id))} v${escapeHtml(jsStr(r.version))}</span>
                    </div>
                    <div style="font-size:12px; color:var(--text-muted); margin:4px 0 6px;">${escapeHtml(jsStr(r.description))}</div>
                    <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
                        consuma: ${escapeHtml(jsStr((r.inputs || []).join(', ')))} ·
                        produce: ${escapeHtml(jsStr((r.outputs || []).join(', ')))}
                    </div>
                    ${r.investigation ? `<div style="font-size:12px; margin-bottom:4px;">
                        <strong>Da verificare:</strong> ${escapeHtml(jsStr(r.investigation))}</div>` : ''}
                    ${r.remediation ? `<div style="font-size:12px; margin-bottom:8px;">
                        <strong>Rimedio:</strong> ${escapeHtml(jsStr(r.remediation))}</div>` : ''}
                    ${(r.parameters || []).length ? `<div style="display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end;">
                        ${r.parameters.map(p => `<div>
                            <label style="font-size:11px; color:var(--text-muted); display:block;" title="${escapeHtml(jsStr(p.description || ''))}">
                                ${escapeHtml(jsStr(p.name))} (${escapeHtml(jsStr(p.min))}–${escapeHtml(jsStr(p.max))})
                            </label>
                            <input type="number" id="rp-${escapeHtml(jsStr(r.id))}-${escapeHtml(jsStr(p.name))}"
                                   value="${escapeHtml(jsStr((r.effective || {})[p.name] ?? p.default))}"
                                   min="${escapeHtml(jsStr(p.min))}" max="${escapeHtml(jsStr(p.max))}"
                                   style="width:110px; padding:5px 8px; border-radius:6px; border:1px solid var(--border);
                                          background:var(--surface-2); color:var(--text); font-size:12px;">
                        </div>`).join('')}
                        <button class="btn btn-secondary btn-small" style="width:auto;"
                                onclick="saveRuleParameters('${jsStr(r.id)}')">Salva soglie</button>
                        <span id="rp-status-${escapeHtml(jsStr(r.id))}" style="font-size:11px; color:var(--text-muted);"></span>
                    </div>` : '<div style="font-size:11px; color:var(--text-muted);">Nessuna soglia configurabile.</div>'}
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
                if (st) st.textContent = err.detail || 'Errore.';
                return;
            }
            if (st) st.textContent = 'Salvato.';
        } catch (e) {
            if (st) st.textContent = 'Errore.';
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
            if (!res || !res.ok) { box.innerHTML = '<div style="color:var(--danger); font-size:12px;">Errore nel caricamento.</div>'; return; }
            const data = await res.json();
            _incidents = data.incidents || [];
            renderIncidentsList();
        } catch (e) {
            box.innerHTML = '<div style="color:var(--danger); font-size:12px;">Errore nel caricamento.</div>';
        }
    }

    function renderIncidentsList() {
        const box = document.getElementById('incidentsList');
        if (!box) return;
        if (!_incidents.length) {
            box.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:12px;">Nessun incidente nella finestra selezionata.</div>';
            return;
        }
        box.innerHTML = _incidents.map(inc => {
            const active = inc.id === _selectedId;
            return `<div onclick="openIncident(${Number(inc.id)})" style="cursor:pointer; padding:10px; border-radius:8px; margin-bottom:8px;
                        border:1px solid ${active ? 'var(--primary)' : 'var(--border)'}; background:var(--surface-2);">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                    <span style="width:8px; height:8px; border-radius:50%; background:${sevColor(inc.severity)};"></span>
                    <strong style="font-size:13px;">${escapeHtml(jsStr(inc.title || inc.entity_key))}</strong>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-bottom:6px;">
                    ${escapeHtml(jsStr(inc.event_count))} eventi · ${escapeHtml(jsStr(inc.status))}
                    ${inc.closed_ts ? '· chiuso' : '· aperto'} · ${escapeHtml(fmtTime(inc.last_event_ts))}
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:11px; color:var(--text-muted); min-width:70px;">${escapeHtml(jsStr(inc.confidence ?? '--'))}% conf.</span>
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
            if (!res || !res.ok) { box.innerHTML = '<div style="color:var(--danger); font-size:12px;">Incidente non disponibile.</div>'; return; }
            const data = await res.json();
            renderIncidentDetail(data.incident || {}, data.timeline || [],
                                 data.previous_conclusions || [],
                                 data.flow_path || null);
        } catch (e) {
            box.innerHTML = '<div style="color:var(--danger); font-size:12px;">Incidente non disponibile.</div>';
        }
    }

    function renderReasoning(inc) {
        const r = inc.reasoning || {};
        const rules = (r.rules_fired || []).map(x =>
            `<span class="badge" style="font-size:11px;">${escapeHtml(jsStr(x))}</span>`).join(' ') || '<span style="color:var(--text-muted);">nessuna</span>';
        const sources = (r.sources_used || []).map(x =>
            `<span class="badge" style="font-size:11px;">${escapeHtml(jsStr(x))}</span>`).join(' ') || '<span style="color:var(--text-muted);">nessuna</span>';
        const byRole = r.evidence_by_role || {};
        const roleCounts = Object.keys(byRole).map(role => {
            const meta = ROLE_META[role] || { color: 'var(--text-muted)', label: role };
            return `<span style="padding:1px 6px; border-radius:4px; font-size:10px; font-weight:700;
                        color:${meta.color}; border:1px solid ${meta.color};">${escapeHtml(meta.label)} ${byRole[role].length}</span>`;
        }).join(' ') || '<span style="color:var(--text-muted);">nessuna</span>';
        return `<div style="padding:12px; border-radius:8px; background:var(--surface-2); border:1px solid var(--border); margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:10px;">
                <div>
                    <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700;">Causa più probabile (deterministica)</div>
                    <div style="font-size:18px; font-family:var(--font-display);">${escapeHtml(jsStr(inc.cause_kind || '--'))}</div>
                </div>
                <div style="min-width:160px;">
                    <div style="font-size:11px; color:var(--text-muted); text-align:right;">Confidenza ${escapeHtml(jsStr(inc.confidence ?? '--'))}%</div>
                    ${confidenceBar(inc.confidence)}
                </div>
            </div>
            <div style="font-size:12px; margin-bottom:6px;"><strong>Regole attivate:</strong> ${rules}</div>
            <div style="font-size:12px; margin-bottom:6px;"><strong>Fonti corroboranti:</strong> ${sources}</div>
            <div style="font-size:12px; margin-bottom:6px;"><strong>Evidenze per ruolo:</strong> ${roleCounts}</div>
            <div style="font-size:11px; color:var(--text-muted);">
                Base ${escapeHtml(jsStr(r.base_confidence ?? '--'))}% + ${escapeHtml(jsStr(r.confidence_step ?? '--'))}% per fonte corroborante.
                Regola: ${escapeHtml(jsStr(r.rule_id || '--'))} v${escapeHtml(jsStr(r.rule_version || '--'))}
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
                <strong>Da verificare:</strong> ${escapeHtml(jsStr(rule.investigation))}</div>` : ''}
            ${rule.remediation ? `<div style="font-size:12px;">
                <i class="fa-solid fa-screwdriver-wrench" style="color:var(--success);"></i>
                <strong>Rimedio:</strong> ${escapeHtml(jsStr(rule.remediation))}</div>` : ''}
        </div>`;
    }

    function renderTimeline(entries) {
        if (!entries.length) {
            return '<div style="color:var(--text-muted); font-size:12px;">Nessuna voce di timeline.</div>';
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
                    ? `${e.ref.retracted_reason || 'invalidata'}${e.ref.retracted_by_rule_id ? ' — ' + e.ref.retracted_by_rule_id : ''}`
                    : '';
                return `<div style="position:relative; margin-bottom:12px; ${retracted ? 'opacity:0.65;' : ''}">
                    <span style="position:absolute; left:-23px; top:2px; width:12px; height:12px; border-radius:50%;
                                 background:${retracted ? 'var(--surface-3)' : 'var(--surface)'}; border:2px solid ${dotColor};"></span>
                    <div style="font-size:11px; color:var(--text-muted);">
                        ${escapeHtml(fmtTime(e.ts))} ·
                        <i class="fa-solid ${meta.icon}" style="color:${meta.color};"></i> ${escapeHtml(meta.label)}
                        ${role ? `<span style="margin-left:6px; padding:1px 6px; border-radius:4px; font-weight:700;
                                     font-size:10px; color:${role.color}; border:1px solid ${role.color};">${escapeHtml(role.label)}</span>` : ''}
                        ${retracted ? `<span style="margin-left:6px; padding:1px 6px; border-radius:4px; font-weight:700;
                                     font-size:10px; color:var(--text-muted); border:1px solid var(--text-muted);">RITRATTATA</span>` : ''}
                    </div>
                    <div style="font-size:13px; ${retracted ? 'text-decoration:line-through;' : ''}
                                color:${e.severity !== null && e.severity !== undefined ? sevColor(e.severity) : 'var(--text)'};">
                        ${escapeHtml(jsStr(e.text))}
                    </div>
                    ${why ? `<div style="font-size:11px; color:var(--warning); margin-top:2px;">
                                <i class="fa-solid fa-rotate-left"></i> ${escapeHtml(jsStr(why))}</div>` : ''}
                    ${prov ? `<div style="font-size:11px; color:var(--text-muted); margin-top:2px;" title="Regola che ha prodotto questa evidenza e soglie usate">
                                <i class="fa-solid fa-fingerprint"></i> ${escapeHtml(prov)}</div>` : ''}
                    ${attrs ? `<div style="font-family:var(--font-code); font-size:11px; color:var(--text-muted); margin-top:2px; word-break:break-all;">${escapeHtml(attrs)}</div>` : ''}
                </div>`;
            }).join('') + '</div>';
    }

    function renderAiBlock(inc) {
        const body = inc.ai_narrative
            ? `<div style="font-size:13px; white-space:pre-wrap;">${escapeHtml(jsStr(inc.ai_narrative))}</div>
               <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Generato il ${escapeHtml(fmtTime(inc.ai_narrative_ts))}</div>`
            : '<div style="font-size:12px; color:var(--text-muted);">Nessuna narrativa generata. La conclusione qui sopra resta valida senza AI.</div>';
        return `<div style="margin-top:18px; padding:12px; border-radius:8px; border:1px dashed var(--primary); background:rgba(99,102,241,0.06);">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:8px;">
                <span style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--primary);">
                    <i class="fa-solid fa-robot"></i> Riformulazione generata da AI — non è la conclusione
                </span>
                <button class="btn btn-secondary btn-small" style="width:auto;" onclick="explainIncident(${Number(inc.id)})">
                    <i class="fa-solid fa-wand-magic-sparkles"></i> ${inc.ai_narrative ? 'Rigenera' : 'Spiega con AI'}
                </button>
            </div>
            <div id="incidentAiBody">${body}</div>
        </div>`;
    }

    function renderConclusionHistory(history) {
        if (!history.length) return '';
        return `<div style="margin-top:12px; padding:10px; border-radius:8px; background:var(--surface-3);">
            <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--text-muted); margin-bottom:6px;">
                <i class="fa-solid fa-clock-rotate-left"></i> Conclusioni precedenti (superate)
            </div>
            ${history.map(h => `<div style="font-size:12px; color:var(--text-muted); text-decoration:line-through;">
                ${escapeHtml(fmtTime(h.concluded_ts))} — ${escapeHtml(jsStr(h.cause_kind))}
                (${escapeHtml(jsStr(h.confidence))}%)
            </div>`).join('')}
        </div>`;
    }

    // Percorso logico della conversazione. Un salto sconosciuto va MOSTRATO
    // come tale: l'ingegnere decide dove guardare in base a questo, e un buco
    // taciuto lo manda a cercare nel posto sbagliato.
    const DIRECTION_LABEL = {
        east_west: 'East-West (interno ↔ interno)',
        north_south: 'North-South (attraversa il perimetro)',
        control_plane: 'Control plane (scoperta e routing)',
        local: 'Locale'
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
            return `<div style="display:flex; align-items:center; gap:8px; padding:6px 10px; background:var(--surface-2); border:1px solid var(--border); border-radius:8px; font-size:12px; color:${color}; ${unknown ? 'border-style:dashed;' : ''}">
                <i class="fa-solid ${icon}"></i>
                <span>${escapeHtml(jsStr(h.label || h.kind))}</span>
            </div>`;
        }).join('<i class="fa-solid fa-angle-right" style="color:var(--text-muted); align-self:center;"></i>');
        const warn = path.complete ? '' :
            `<div style="font-size:11px; color:var(--warning); margin-top:6px;"><i class="fa-solid fa-triangle-exclamation"></i> Percorso parziale: i salti tratteggiati non sono noti.</div>`;
        return `<h4 style="margin:12px 0 10px; font-size:14px; color:var(--primary);"><i class="fa-solid fa-diagram-project"></i> Percorso
                    <span style="font-weight:normal; font-size:12px; color:var(--text-muted);">${escapeHtml(jsStr(DIRECTION_LABEL[path.direction] || path.direction || ''))}</span></h4>
                <div style="display:flex; flex-wrap:wrap; gap:6px; align-items:center;">${hops}</div>${warn}`;
    }

    function renderIncidentDetail(inc, entries, history, flowPath) {
        const box = document.getElementById('incidentDetail');
        if (!box) return;
        const next = inc.status === 'new'
            ? `<button class="btn btn-secondary btn-small" style="width:auto;" onclick="setIncidentStatus(${Number(inc.id)}, 'new', 'ack')">Prendi in carico</button>
               <button class="btn btn-secondary btn-small" style="width:auto;" onclick="setIncidentStatus(${Number(inc.id)}, 'new', 'resolved')">Risolvi</button>`
            : (inc.status === 'ack'
                ? `<button class="btn btn-secondary btn-small" style="width:auto;" onclick="setIncidentStatus(${Number(inc.id)}, 'ack', 'resolved')">Risolvi</button>`
                : '');
        box.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:14px;">
                <div>
                    <h3 style="margin:0; font-family:var(--font-display); font-size:20px;">${escapeHtml(jsStr(inc.title || inc.entity_key))}</h3>
                    <div style="font-size:12px; color:var(--text-muted);">
                        ${escapeHtml(jsStr(inc.entity_key))} · tenant ${escapeHtml(jsStr(inc.tenant))} ·
                        dal ${escapeHtml(fmtTime(inc.opened_ts))} al ${escapeHtml(fmtTime(inc.last_event_ts))}
                    </div>
                </div>
                <div style="display:flex; gap:8px;">${next}</div>
            </div>
            ${renderReasoning(inc)}
            ${renderConclusionHistory(history || [])}
            ${renderFlowPath(flowPath)}
            <h4 style="margin:12px 0 10px; font-size:14px; color:var(--primary);"><i class="fa-solid fa-timeline"></i> Timeline</h4>
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
                alert(err.detail || 'Transizione non riuscita.');
                return;
            }
            await loadIncidentsList();
            await openIncident(id);
        } catch (e) {}
    }

    async function explainIncident(id) {
        const body = document.getElementById('incidentAiBody');
        if (body) body.innerHTML = '<div style="color:var(--text-muted); font-size:12px;"><i class="fa-solid fa-circle-notch fa-spin"></i> Generazione in corso…</div>';
        try {
            const res = await apiFetch(`/api/incidents/${Number(id)}/explain`, { method: 'POST' });
            if (!res) return;
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                if (body) body.innerHTML = `<div style="color:var(--danger); font-size:12px;">${escapeHtml(jsStr(err.detail || 'Generazione non riuscita.'))}</div>`;
                return;
            }
            const data = await res.json();
            if (body) {
                body.innerHTML = `<div style="font-size:13px; white-space:pre-wrap;">${escapeHtml(jsStr(data.ai_narrative))}</div>
                                  <div style="font-size:11px; color:var(--text-muted); margin-top:6px;">Generato il ${escapeHtml(fmtTime(data.ai_narrative_ts))}</div>`;
            }
        } catch (e) {
            if (body) body.innerHTML = '<div style="color:var(--danger); font-size:12px;">Generazione non riuscita.</div>';
        }
    }

    window.applyIncidentsGating = applyIncidentsGating;
    window.setIncidentsPreview = setIncidentsPreview;
    window.loadIncidentsTab = loadIncidentsTab;
    window.loadIncidentsList = loadIncidentsList;
    window.openIncident = openIncident;
    window.setIncidentStatus = setIncidentStatus;
    window.explainIncident = explainIncident;
    window.saveRuleParameters = saveRuleParameters;
    window.saveInterfaceExpectation = saveInterfaceExpectation;
})();
