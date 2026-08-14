// static/js/flow-analytics.js
// ===== Flow SIEM Analytics (PREVIEW) — Wazuh & Splunk inspired Network Traffic Analytics =====

(function () {
    let _flowSiemData = [];
    let _flowSiemFacets = null;
    let _flowSiemHistogram = [];
    let _isStreaming = true;
    let _activeQuery = '';
    let _streamTimer = null;
    let _selectedEventId = null;

    // The header lets several tenants be ticked, but /api/flow-siem/* scopes to
    // one tenant server-side, and facets/histogram are aggregated there — they
    // cannot be narrowed client-side afterwards. One tenant selected: filter.
    // More than one: show the caller's whole scope and say so on screen.
    function siemTenantParam() {
        const picked = window.trafSelectedTenants ? [...window.trafSelectedTenants()] : [];
        const note = document.getElementById('flowSiemScopeNote');
        const scoped = picked.length === 1;
        if (note) {
            note.style.display = picked.length > 1 ? '' : 'none';
            note.textContent = picked.length > 1
                ? (currentLang === 'en'
                    ? `Showing every tenant in your scope: this view filters one tenant at a time (${picked.length} selected).`
                    : `Mostra tutti i tenant del tuo profilo: questa vista ne filtra uno alla volta (${picked.length} selezionati).`)
                : '';
        }
        return scoped ? `&tenant=${encodeURIComponent(picked[0])}` : '';
    }

    async function loadFlowSiemTab() {
        const windowVal = window.trafState ? window.trafState.window : '1h';
        const qParam = _activeQuery ? `&q=${encodeURIComponent(_activeQuery)}` : '';
        const tenantParam = siemTenantParam();

        try {
            const [eventsRes, histRes, facetsRes] = await Promise.all([
                apiFetch(`/api/flow-siem/events?window=${windowVal}&limit=100${qParam}${tenantParam}`),
                apiFetch(`/api/flow-siem/histogram?window=${windowVal}&buckets=30${tenantParam}`),
                apiFetch(`/api/flow-siem/facets?window=${windowVal}${tenantParam}`)
            ]);

            if (eventsRes && eventsRes.ok) {
                const data = await eventsRes.json();
                _flowSiemData = data.events || [];
            }
            if (histRes && histRes.ok) {
                const data = await histRes.json();
                _flowSiemHistogram = data.buckets || [];
            }
            if (facetsRes && facetsRes.ok) {
                _flowSiemFacets = await facetsRes.json();
            }
        } catch (e) {
            console.error("Errore durante il caricamento della telemetria Flow SIEM:", e);
        }

        renderSiemHistogram();
        renderSiemFacets();
        renderSiemTable();
        startSiemStreamTimer();
    }

    function startSiemStreamTimer() {
        if (_streamTimer) clearInterval(_streamTimer);
        _streamTimer = setInterval(async () => {
            const tabOn = document.getElementById('tab-flows')?.classList.contains('active');
            const paneOn = document.getElementById('trafPane-search')?.style.display !== 'none';
            if (!_isStreaming || !tabOn || !paneOn) return;

            // Con un dettaglio aperto NON si aggiorna la tabella: il refresh la
            // ricostruisce e sposta la riga che l'utente sta leggendo. Lo
            // streaming riprende alla chiusura del dettaglio.
            if (_selectedEventId !== null && _selectedEventId !== undefined) return;

            const windowVal = window.trafState ? window.trafState.window : '1h';
            const qParam = _activeQuery ? `&q=${encodeURIComponent(_activeQuery)}` : '';
            const tenantParam = siemTenantParam();

            try {
                const res = await apiFetch(`/api/flow-siem/events?window=${windowVal}&limit=20${qParam}${tenantParam}`);
                if (res && res.ok) {
                    const data = await res.json();
                    if (data.events && data.events.length) {
                        // Deduplica per id. Il polling richiede sempre gli
                        // ultimi 20 eventi, quindi senza questo gli stessi
                        // eventi venivano riaccodati ogni 5s: la tabella si
                        // riempiva di duplicati e un id selezionato compariva
                        // piu' volte, aprendo piu' dettagli identici.
                        const seen = new Set(_flowSiemData.map(e => e.id));
                        const fresh = data.events.filter(e => !seen.has(e.id));
                        if (!fresh.length) return;
                        _flowSiemData = fresh.concat(_flowSiemData).slice(0, 150);
                        renderSiemHistogram();
                        renderSiemTable();
                    }
                }
            } catch (e) {}
        }, 5000);
    }

    function toggleSiemStream() {
        _isStreaming = !_isStreaming;
        const btn = document.getElementById('btnFlowSiemStream');
        if (btn) {
            btn.className = `btn btn-sm ${_isStreaming ? 'btn-secondary' : 'btn-primary'}`;
            btn.innerHTML = `<i class="fa-solid ${_isStreaming ? 'fa-pause' : 'fa-play'}"></i> ${
                _isStreaming 
                    ? (currentLang === 'en' ? 'Pause Stream' : 'Pausa Streaming') 
                    : (currentLang === 'en' ? 'Resume Stream' : 'Riprendi Streaming')
            }`;
        }
        const badge = document.getElementById('flowSiemStreamBadge');
        if (badge) {
            badge.className = `status ${_isStreaming ? 'ok' : 'warn'}`;
            badge.innerHTML = `<span class="led ${_isStreaming ? 'led-success' : 'led-warning'}"></span>${_isStreaming ? 'LIVE TAIL' : 'PAUSED'}`;
        }
    }

    function filterSiemEvents() {
        const input = document.getElementById('flowSiemQueryInput');
        _activeQuery = input ? input.value.trim() : '';
        loadFlowSiemTab();
    }

    function renderSiemHistogram() {
        const canvas = document.getElementById('flowSiemHistCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.clientWidth || 800;
        const height = canvas.height = 100;
        ctx.clearRect(0, 0, width, height);

        // Il fallback precedente disegnava una rampa finta (count: 20+i) quando
        // non c'erano dati: un database vuoto sembrava traffico reale. Ora si
        // dichiara l'assenza di dati.
        const buckets = _flowSiemHistogram;
        const style = getComputedStyle(document.body);
        if (!buckets.length) {
            ctx.fillStyle = style.getPropertyValue('--text-muted').trim() || '#888';
            ctx.font = `12px ${style.getPropertyValue('--font-main').trim() || 'sans-serif'}`;
            ctx.fillText(currentLang === 'en'
                ? 'No events in the selected window.'
                : 'Nessun evento nella finestra selezionata.', 20, height / 2);
            return;
        }

        const bars = buckets.length;
        const barWidth = (width - 40) / bars;
        const maxVal = Math.max(...buckets.map(b => b.count || 0), 1);

        for (let i = 0; i < bars; i++) {
            const b = buckets[i];
            const val = b.count || 0;
            const x = 20 + i * barWidth;
            const h = (val / maxVal) * (height - 28);
            const y = height - 20 - h;

            const isDeny = (b.deny_count || 0) > 0;
            ctx.fillStyle = isDeny ? 'rgba(239, 68, 68, 0.6)' : 'rgba(106, 95, 193, 0.5)';
            ctx.fillRect(x + 1, y, barWidth - 2, h);
        }

        // Draw baseline axis
        ctx.beginPath();
        ctx.strokeStyle = 'rgba(255,255,255,0.1)';
        ctx.moveTo(10, height - 20);
        ctx.lineTo(width - 10, height - 20);
        ctx.stroke();
    }

    function renderSiemFacets() {
        const facetBox = document.getElementById('flowSiemFacets');
        if (!facetBox) return;

        if (!_flowSiemFacets) {
            facetBox.innerHTML = `<div style="font-size:12px; color:var(--text-muted);">${currentLang==='en'?'Loading facets...':'Caricamento faccette...'}</div>`;
            return;
        }

        // Ogni sezione filtra sul PROPRIO campo: senza, cliccare un IP fra le
        // sorgenti cercava quell'IP ovunque e restituiva soprattutto le righe
        // in cui e' la destinazione.
        const renderSection = (title, items, icon, field) => `
            <div style="margin-bottom:14px;">
                <h5 style="margin:0 0 6px; font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:.05em;">
                    <i class="fa-solid ${icon}"></i> ${title}
                </h5>
                ${(items || []).map(item => `
                    <div class="siem-facet-item" data-term="${escapeHtml(item.value)}" data-field="${escapeHtml(field)}" style="display:flex; align-items:center; justify-content:space-between; font-size:11px; padding:3px 6px; border-radius:0; cursor:pointer; background:var(--surface-3); margin-bottom:4px;" title="${escapeHtml(field)}:${escapeHtml(item.value)}">
                        <span style="font-family:var(--font-code); text-overflow:ellipsis; overflow:hidden; white-space:nowrap; max-width:130px;">${escapeHtml(item.value)}</span>
                        <span class="badge" style="font-size:10px;">${item.count}</span>
                    </div>
                `).join('')}
            </div>
        `;

        facetBox.innerHTML =
            renderSection('Top Sorgenti IP', _flowSiemFacets.top_src_ips, 'fa-network-wired', 'src_ip') +
            renderSection('Top Destinazioni IP', _flowSiemFacets.top_dst_ips, 'fa-server', 'dst_ip') +
            renderSection('Threat Flags SIEM', _flowSiemFacets.threat_flags, 'fa-triangle-exclamation', 'threat_flag') +
            renderSection('Stato Azione', _flowSiemFacets.actions, 'fa-shield-halved', 'action');
    }

    function applySiemFilter(term, field) {
        const input = document.getElementById('flowSiemQueryInput');
        if (input) {
            // Il filtro resta visibile e modificabile nella casella di ricerca:
            // "src_ip:10.0.1.2" e' la stessa sintassi che l'utente puo' digitare.
            input.value = field ? `${field}:${term}` : term;
            filterSiemEvents();
        }
    }

    function renderSiemTable() {
        const tbody = document.getElementById('flowSiemTableBody');
        if (!tbody) return;

        if (!_flowSiemData.length) {
            tbody.innerHTML = `<tr><td colspan="7" style="padding:20px; text-align:center; color:var(--text-muted);">${currentLang==='en'?'No matching flow events.':'Nessun evento di flusso corrispondente.'}</td></tr>`;
            return;
        }

        // La tabella viene ricostruita interamente: senza salvare e ripristinare
        // lo scroll del contenitore, ogni refresh riporta l'utente in cima.
        const scroller = tbody.closest('.table-container');
        const prevScroll = scroller ? scroller.scrollTop : 0;

        // Un campo assente nel messaggio syslog resta vuoto: si mostra un
        // trattino, non un valore inventato.
        const dash = '<span style="color:var(--text-muted);">—</span>';
        const endpoint = (ip, port) => ip
            ? `<strong>${escapeHtml(ip)}</strong>${port ? ':' + escapeHtml(String(port)) : ''}`
            : dash;

        tbody.innerHTML = _flowSiemData.map(e => {
            const isDeny = !!e.is_deny;
            const actionCol = isDeny ? 'var(--danger)' : 'var(--success)';
            const timeStr = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—';
            const isSelected = _selectedEventId === e.id;
            const volume = (e.bytes === null || e.bytes === undefined)
                ? dash
                : `${(e.bytes / 1024).toFixed(1)} KB`;

            return `<tr class="siem-event-row" data-id="${escapeHtml(String(e.id))}" style="font-size:12px; border-top:1px solid var(--border); cursor:pointer; ${isSelected ? 'background:var(--surface-3);' : ''}">
                <td style="padding:6px 8px; font-family:var(--font-code); color:var(--text-muted);">${timeStr}</td>
                <td style="padding:6px 8px; font-family:var(--font-code); color:var(--primary);">${endpoint(e.src_ip, e.src_port)}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);">${endpoint(e.dst_ip, e.dst_port)}</td>
                <td style="padding:6px 8px;">${e.proto ? `<span class="badge">${escapeHtml(e.proto)}</span>` : dash}</td>
                <td style="padding:6px 8px; font-weight:700; color:${actionCol};">${escapeHtml(e.action || 'N/D')}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);">${volume}</td>
                <td style="padding:6px 8px;"><span class="badge" style="background:${isDeny ? 'color-mix(in srgb, var(--danger) 15%, transparent)' : 'var(--surface-3)'}; color:${isDeny ? 'var(--danger)' : 'var(--text)'};">${escapeHtml(e.threat_flag)}</span></td>
            </tr>
            ${isSelected ? `<tr style="background:var(--surface-2);"><td colspan="7" style="padding:12px;">
                <div style="font-family:var(--font-code); font-size:11px; background:var(--surface); padding:10px; border-radius:0; border:1px solid var(--border); margin-bottom:8px;">
                    <strong>Raw SIEM Flow Event Payload (JSON):</strong>
                    <pre style="margin:4px 0 0; white-space:pre-wrap;">${escapeHtml(JSON.stringify(e, null, 2))}</pre>
                    ${isDeny ? `<div style="margin-top:8px; padding:8px 12px; border-radius:0; background:color-mix(in srgb, var(--primary) 10%, transparent); border:1px solid color-mix(in srgb, var(--primary) 25%, transparent); color:var(--text); font-size:11px; font-family:var(--font-main, sans-serif);">
                        <i class="fa-solid fa-circle-info" style="color:var(--primary); margin-right:4px;"></i>
                        <strong>Nota sull'Azione DENY / BLOCKED:</strong> SentinelNet è una piattaforma di osservabilità passiva (raccoglie telemetria). L'azione <code>DENY</code> indica che il <strong>firewall/router apparato di rete</strong> di origine ha bloccato il pacchetto ed emesso il relativo log.
                    </div>` : ''}
                </div>
                <div style="display:flex; justify-content:flex-end;">
                    <button class="btn btn-sm btn-secondary" data-action="suppress-alert" data-id="${escapeHtml(String(e.id))}"><i class="fa-solid fa-bell-slash"></i> Sopprimi Allerta Threat</button>
                </div>
            </td></tr>` : ''}`;
        }).join('');

        if (scroller) scroller.scrollTop = prevScroll;
    }

    function toggleEventDrawer(id) {
        _selectedEventId = (_selectedEventId === id) ? null : id;
        renderSiemTable();
    }

    async function suppressSiemAlert(id, evt) {
        if (evt) evt.stopPropagation();
        try {
            const res = await apiFetch('/api/flow-siem/alerts/suppress', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ event_id: id })
            });
            if (res && res.ok) {
                // La soppressione ora e' persistita e l'evento viene escluso
                // dalle query successive, quindi il dettaglio aperto va chiuso:
                // punterebbe a una riga che non esiste piu'.
                _selectedEventId = null;
                showToast(currentLang === 'en'
                    ? `Alert for event ${id} suppressed.`
                    : `Allerta per l'evento ${id} soppressa.`, 'info');
                loadFlowSiemTab();
            } else {
                let detail = '';
                try { const d = await res.json(); detail = d && d.detail; } catch (e2) {}
                showToast(detail || (currentLang === 'en'
                    ? 'Could not suppress the alert.'
                    : 'Impossibile sopprimere l\'allerta.'), 'error');
            }
        } catch (e) {
            showToast(currentLang === 'en'
                ? 'Error while suppressing the alert.'
                : 'Errore durante la soppressione dell\'allerta.', 'error');
        }
    }

    // Delegated click listeners
    document.getElementById('flowSiemFacets')?.addEventListener('click', (e) => {
        const item = e.target.closest('.siem-facet-item');
        if (item && item.dataset.term) {
            applySiemFilter(item.dataset.term, item.dataset.field || '');
        }
    });

    document.getElementById('flowSiemTableBody')?.addEventListener('click', (e) => {
        const suppressBtn = e.target.closest('[data-action="suppress-alert"]');
        if (suppressBtn) {
            e.stopPropagation();
            suppressSiemAlert(suppressBtn.dataset.id, e);
            return;
        }
        const row = e.target.closest('.siem-event-row');
        if (row && row.dataset.id) {
            toggleEventDrawer(row.dataset.id);
        }
    });

    // Static event listeners
    document.getElementById('btnFlowSiemStream')?.addEventListener('click', toggleSiemStream);
    document.getElementById('btnFilterSiem')?.addEventListener('click', filterSiemEvents);
    document.getElementById('flowSiemQueryInput')?.addEventListener('keyup', (e) => {
        if (e.key === 'Enter' || e.target.value.length === 0) filterSiemEvents();
    });

    // Expose functions globally
    window.loadFlowSiemTab = loadFlowSiemTab;
    window.siemTenantParam = siemTenantParam;
    window.toggleSiemStream = toggleSiemStream;
    window.filterSiemEvents = filterSiemEvents;
    window.applySiemFilter = applySiemFilter;
    window.toggleEventDrawer = toggleEventDrawer;
    window.suppressSiemAlert = suppressSiemAlert;
})();
