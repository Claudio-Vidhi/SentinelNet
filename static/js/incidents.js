// static/js/incidents.js
// ===== Incidenti (PREVIEW) — timeline multi-fonte e ragionamento deterministico =====
// La conclusione mostrata in testa e' SEMPRE quella deterministica del backend
// (causa, confidenza, regole attivate, fonti). La narrativa AI, quando richiesta,
// vive in un blocco separato e dichiaratamente generato: non e' la conclusione.
// Escaping: escapeHtml(jsStr(x)) su ogni valore interpolato (jsStr in mcp-client.js).

(function () {
    let _incidents = [];
    let _selectedId = null;

    const SOURCE_META = {
        evidence:   { icon: 'fa-scale-balanced', color: 'var(--danger)',   label: 'Evidenza' },
        syslog:     { icon: 'fa-file-lines',     color: 'var(--warning)',  label: 'Syslog' },
        flow:       { icon: 'fa-chart-area',     color: 'var(--primary)',  label: 'Flussi' },
        api:        { icon: 'fa-satellite-dish', color: 'var(--success)',  label: 'Stato apparato' },
        location:   { icon: 'fa-location-dot',   color: 'var(--text-muted)', label: 'Posizione' },
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
        const box = document.getElementById('incidentDetail');
        if (!box) return;
        box.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i></div>';
        try {
            const res = await apiFetch(`/api/incidents/${Number(id)}`);
            if (!res || !res.ok) { box.innerHTML = '<div style="color:var(--danger); font-size:12px;">Incidente non disponibile.</div>'; return; }
            const data = await res.json();
            renderIncidentDetail(data.incident || {}, data.timeline || []);
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
                return `<div style="position:relative; margin-bottom:12px;">
                    <span style="position:absolute; left:-23px; top:2px; width:12px; height:12px; border-radius:50%;
                                 background:var(--surface); border:2px solid ${dotColor};"></span>
                    <div style="font-size:11px; color:var(--text-muted);">
                        ${escapeHtml(fmtTime(e.ts))} ·
                        <i class="fa-solid ${meta.icon}" style="color:${meta.color};"></i> ${escapeHtml(meta.label)}
                        ${role ? `<span style="margin-left:6px; padding:1px 6px; border-radius:4px; font-weight:700;
                                     font-size:10px; color:${role.color}; border:1px solid ${role.color};">${escapeHtml(role.label)}</span>` : ''}
                    </div>
                    <div style="font-size:13px; color:${e.severity !== null && e.severity !== undefined ? sevColor(e.severity) : 'var(--text)'};">
                        ${escapeHtml(jsStr(e.text))}
                    </div>
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

    function renderIncidentDetail(inc, entries) {
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
            <h4 style="margin:0 0 10px; font-size:14px; color:var(--primary);"><i class="fa-solid fa-timeline"></i> Timeline</h4>
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
})();
