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

    async function applyFlowSiemPreviewGating() {
        try {
            const res = await apiFetch('/api/settings/flow-siem-preview');
            if (!res || !res.ok) return;
            const data = await res.json();
            const nav = document.getElementById('navFlowSiemPreview');
            if (nav) nav.style.display = data.flow_siem_preview ? '' : 'none';
            const toggle = document.getElementById('flowSiemPreviewToggle');
            if (toggle) toggle.checked = !!data.flow_siem_preview;
        } catch (e) {}
    }

    async function setFlowSiemPreview(enabled) {
        const st = document.getElementById('flowSiemPreviewStatus');
        try {
            const res = await apiFetch('/api/settings/flow-siem-preview', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !!enabled })
            });
            if (res && res.ok) {
                if (st) st.textContent = currentLang === 'en' ? 'Saved.' : 'Salvato.';
                await applyFlowSiemPreviewGating();
            }
        } catch (e) {
            if (st) st.textContent = currentLang === 'en' ? 'Error.' : 'Errore.';
        }
    }

    async function loadFlowSiemTab() {
        const windowVal = document.getElementById('flowSiemWindow') ? document.getElementById('flowSiemWindow').value : '24h';
        const qParam = _activeQuery ? `&q=${encodeURIComponent(_activeQuery)}` : '';

        try {
            const [eventsRes, histRes, facetsRes] = await Promise.all([
                apiFetch(`/api/flow-siem/events?window=${windowVal}&limit=100${qParam}`),
                apiFetch(`/api/flow-siem/histogram?window=${windowVal}&buckets=30`),
                apiFetch(`/api/flow-siem/facets?window=${windowVal}`)
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
            if (!_isStreaming || !document.getElementById('tab-flow-siem')?.classList.contains('active')) return;
            
            const windowVal = document.getElementById('flowSiemWindow') ? document.getElementById('flowSiemWindow').value : '24h';
            const qParam = _activeQuery ? `&q=${encodeURIComponent(_activeQuery)}` : '';
            
            try {
                const res = await apiFetch(`/api/flow-siem/events?window=${windowVal}&limit=20${qParam}`);
                if (res && res.ok) {
                    const data = await res.json();
                    if (data.events && data.events.length) {
                        _flowSiemData = data.events.concat(_flowSiemData).slice(0, 150);
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

        const buckets = _flowSiemHistogram.length ? _flowSiemHistogram : Array.from({length:30}, (_,i)=>({count:20+i}));
        const bars = buckets.length;
        const barWidth = (width - 40) / bars;
        const maxVal = Math.max(...buckets.map(b => b.count || 10), 1);

        for (let i = 0; i < bars; i++) {
            const b = buckets[i];
            const val = b.count || 0;
            const x = 20 + i * barWidth;
            const h = (val / maxVal) * (height - 28);
            const y = height - 20 - h;
            
            const isDeny = b.deny_count > 0;
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

        const renderSection = (title, items, icon) => `
            <div style="margin-bottom:14px;">
                <h5 style="margin:0 0 6px; font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:.05em;">
                    <i class="fa-solid ${icon}"></i> ${title}
                </h5>
                ${(items || []).map(item => `
                    <div style="display:flex; align-items:center; justify-content:space-between; font-size:11px; padding:3px 6px; border-radius:4px; cursor:pointer; background:var(--surface-3); margin-bottom:4px;" onclick="applySiemFilter('${escapeHtml(item.value)}')">
                        <span style="font-family:var(--font-code); text-overflow:ellipsis; overflow:hidden; white-space:nowrap; max-width:130px;">${escapeHtml(item.value)}</span>
                        <span class="badge" style="font-size:10px;">${item.count}</span>
                    </div>
                `).join('')}
            </div>
        `;

        facetBox.innerHTML = 
            renderSection('Top Sorgenti IP', _flowSiemFacets.top_src_ips, 'fa-network-wired') +
            renderSection('Top Destinazioni IP', _flowSiemFacets.top_dst_ips, 'fa-server') +
            renderSection('Threat Flags SIEM', _flowSiemFacets.threat_flags, 'fa-triangle-exclamation') +
            renderSection('Stato Azione', _flowSiemFacets.actions, 'fa-shield-halved');
    }

    function applySiemFilter(term) {
        const input = document.getElementById('flowSiemQueryInput');
        if (input) {
            input.value = term;
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

        tbody.innerHTML = _flowSiemData.map(e => {
            const isDeny = e.action === 'DENY';
            const actionCol = isDeny ? 'var(--danger)' : 'var(--success)';
            const timeStr = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—';
            const isSelected = _selectedEventId === e.id;

            return `<tr style="font-size:12px; border-top:1px solid var(--border); cursor:pointer; ${isSelected ? 'background:var(--surface-3);' : ''}" onclick="toggleEventDrawer('${escapeHtml(e.id)}')">
                <td style="padding:6px 8px; font-family:var(--font-code); color:var(--text-muted);">${timeStr}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);"><strong style="color:var(--primary);">${escapeHtml(e.src_ip)}</strong>:${e.src_port}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);"><strong>${escapeHtml(e.dst_ip)}</strong>:${e.dst_port}</td>
                <td style="padding:6px 8px;"><span class="badge">${escapeHtml(e.proto)}</span></td>
                <td style="padding:6px 8px; font-weight:700; color:${actionCol};">${escapeHtml(e.action)}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);">${(e.bytes / 1024).toFixed(1)} KB</td>
                <td style="padding:6px 8px;"><span class="badge" style="background:${isDeny ? 'rgba(239, 68, 68, 0.15)' : 'var(--surface-3)'}; color:${isDeny ? 'var(--danger)' : 'var(--text)'};">${escapeHtml(e.threat_flag)}</span></td>
            </tr>
            ${isSelected ? `<tr style="background:var(--surface-2);"><td colspan="7" style="padding:12px;">
                <div style="font-family:var(--font-code); font-size:11px; background:var(--surface); padding:10px; border-radius:6px; border:1px solid var(--border); margin-bottom:8px;">
                    <strong>Raw SIEM Flow Event Payload (JSON):</strong>
                    <pre style="margin:4px 0 0; white-space:pre-wrap;">${escapeHtml(JSON.stringify(e, null, 2))}</pre>
                    ${isDeny ? `<div style="margin-top:8px; padding:8px 12px; border-radius:6px; background:rgba(59, 130, 246, 0.1); border:1px solid rgba(59, 130, 246, 0.25); color:var(--text); font-size:11px; font-family:var(--font-main, sans-serif);">
                        <i class="fa-solid fa-circle-info" style="color:var(--primary); margin-right:4px;"></i>
                        <strong>Nota sull'Azione DENY / BLOCKED:</strong> SentinelNet è una piattaforma di osservabilità passiva (raccoglie telemetria). L'azione <code>DENY</code> indica che il <strong>firewall/router apparato di rete</strong> di origine ha bloccato il pacchetto ed emesso il relativo log.
                    </div>` : ''}
                </div>
                <div style="display:flex; justify-content:flex-end;">
                    <button class="btn btn-sm btn-secondary" onclick="suppressSiemAlert('${escapeHtml(e.id)}', event)"><i class="fa-solid fa-bell-slash"></i> Sopprimi Allerta Threat</button>
                </div>
            </td></tr>` : ''}`;
        }).join('');
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
                alert(`Allerta Threat per evento '${id}' soppressa con successo.`);
                loadFlowSiemTab();
            }
        } catch (e) {
            alert('Errore durante la soppressione dell\'allerta.');
        }
    }

    // Expose functions globally
    window.loadFlowSiemTab = loadFlowSiemTab;
    window.applyFlowSiemPreviewGating = applyFlowSiemPreviewGating;
    window.setFlowSiemPreview = setFlowSiemPreview;
    window.toggleSiemStream = toggleSiemStream;
    window.filterSiemEvents = filterSiemEvents;
    window.applySiemFilter = applySiemFilter;
    window.toggleEventDrawer = toggleEventDrawer;
    window.suppressSiemAlert = suppressSiemAlert;
})();
