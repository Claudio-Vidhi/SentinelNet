// static/js/flow-analytics.js
// ===== Flow SIEM Analytics (PREVIEW) — Wazuh & Splunk inspired Network Traffic Analytics =====

(function () {
    let _flowSiemData = [];
    let _isStreaming = true;
    let _activeQuery = '';
    let _streamTimer = null;

    // Default mock/sample flow SIEM logs for rich interactive preview
    const MOCK_FLOW_EVENTS = [
        { id: "fl-101", timestamp: new Date(Date.now() - 30000).toISOString(), src_ip: "10.0.1.45", dst_ip: "192.168.10.5", src_port: 54120, dst_port: 443, proto: "TCP", bytes: 14280, packets: 18, action: "ALLOW", vlan: "VLAN 10", site: "Milano Core", threat_flag: "NORMAL" },
        { id: "fl-102", timestamp: new Date(Date.now() - 60000).toISOString(), src_ip: "10.0.2.110", dst_ip: "185.220.101.5", src_port: 49102, dst_port: 80, proto: "TCP", bytes: 85200, packets: 120, action: "DENY", vlan: "VLAN 20", site: "Roma Branch", threat_flag: "TOR_EXIT_NODE" },
        { id: "fl-103", timestamp: new Date(Date.now() - 90000).toISOString(), src_ip: "10.0.1.5", dst_ip: "8.8.8.8", src_port: 53112, dst_port: 53, proto: "UDP", bytes: 512, packets: 4, action: "ALLOW", vlan: "VLAN 10", site: "Milano Core", threat_flag: "NORMAL" },
        { id: "fl-104", timestamp: new Date(Date.now() - 120000).toISOString(), src_ip: "172.16.50.12", dst_ip: "10.0.1.1", src_port: 3389, dst_port: 3389, proto: "TCP", bytes: 245000, packets: 340, action: "ALLOW", vlan: "VLAN 50", site: "Torino Plant", threat_flag: "HIGH_RDP_VOL" },
        { id: "fl-105", timestamp: new Date(Date.now() - 150000).toISOString(), src_ip: "10.0.3.88", dst_ip: "10.0.1.200", src_port: 445, dst_port: 445, proto: "TCP", bytes: 1048576, packets: 980, action: "ALLOW", vlan: "VLAN 30", site: "Bologna Hub", threat_flag: "SMB_TRANSFER" },
        { id: "fl-106", timestamp: new Date(Date.now() - 180000).toISOString(), src_ip: "192.168.1.99", dst_ip: "10.0.1.1", src_port: 22, dst_port: 22, proto: "TCP", bytes: 4200, packets: 14, action: "DENY", vlan: "VLAN 1", site: "Milano Core", threat_flag: "SSH_BRUTE" }
    ];

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
        try {
            const res = await apiFetch(`/api/observability/top?window=${windowVal}&limit=100`);
            if (res && res.ok) {
                const apiData = await res.json();
                if (apiData.flows && apiData.flows.length) {
                    _flowSiemData = apiData.flows.map((f, idx) => ({
                        id: `flow-live-${idx}`,
                        timestamp: new Date().toISOString(),
                        src_ip: f.src_ip || '10.0.0.1',
                        dst_ip: f.dst_ip || '10.0.0.2',
                        src_port: f.src_port || 1024 + idx,
                        dst_port: f.dst_port || 80,
                        proto: ({6:'TCP', 17:'UDP', 1:'ICMP'})[f.protocol] || String(f.protocol || 'TCP'),
                        bytes: f.total_bytes || 1000,
                        packets: f.total_packets || 10,
                        action: idx % 4 === 0 ? 'DENY' : 'ALLOW',
                        vlan: f.vlan ? `VLAN ${f.vlan}` : 'VLAN 10',
                        site: f.tenant || 'Central',
                        threat_flag: f.action === 'DENY' ? 'SUSPICIOUS' : 'NORMAL'
                    }));
                } else {
                    _flowSiemData = MOCK_FLOW_EVENTS;
                }
            } else {
                _flowSiemData = MOCK_FLOW_EVENTS;
            }
        } catch (e) {
            _flowSiemData = MOCK_FLOW_EVENTS;
        }

        renderSiemHistogram();
        renderSiemFacets();
        renderSiemTable();
        startSiemStreamTimer();
    }

    function startSiemStreamTimer() {
        if (_streamTimer) clearInterval(_streamTimer);
        _streamTimer = setInterval(() => {
            if (!_isStreaming || !document.getElementById('tab-flow-siem')?.classList.contains('active')) return;
            // Generate synthetic stream heartbeat event
            const randomSrc = ["10.0.1.45", "10.0.2.110", "172.16.50.12", "192.168.10.88"][Math.floor(Math.random() * 4)];
            const randomDst = ["8.8.8.8", "1.1.1.1", "192.168.10.5", "10.0.1.200"][Math.floor(Math.random() * 4)];
            const randomProto = Math.random() > 0.3 ? "TCP" : "UDP";
            const randomAction = Math.random() > 0.85 ? "DENY" : "ALLOW";
            const newEvt = {
                id: `fl-live-${Date.now().toString().slice(-4)}`,
                timestamp: new Date().toISOString(),
                src_ip: randomSrc,
                dst_ip: randomDst,
                src_port: Math.floor(Math.random() * 50000) + 1024,
                dst_port: randomProto === "TCP" ? (Math.random() > 0.5 ? 443 : 80) : 53,
                proto: randomProto,
                bytes: Math.floor(Math.random() * 50000) + 200,
                packets: Math.floor(Math.random() * 50) + 1,
                action: randomAction,
                vlan: "VLAN 10",
                site: "Milano Core",
                threat_flag: randomAction === "DENY" ? "BLOCKED_FLOW" : "NORMAL"
            };
            _flowSiemData.unshift(newEvt);
            if (_flowSiemData.length > 200) _flowSiemData.pop();
            renderSiemHistogram();
            renderSiemFacets();
            renderSiemTable();
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
        _activeQuery = input ? input.value.trim().toLowerCase() : '';
        renderSiemTable();
    }

    function renderSiemHistogram() {
        const canvas = document.getElementById('flowSiemHistCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.clientWidth || 800;
        const height = canvas.height = 100;
        ctx.clearRect(0, 0, width, height);

        const bars = 30;
        const barWidth = (width - 40) / bars;
        ctx.fillStyle = 'rgba(106, 95, 193, 0.15)';
        ctx.strokeStyle = 'var(--primary, #6a5fc1)';
        ctx.lineWidth = 1.5;

        // Draw histogram bars
        for (let i = 0; i < bars; i++) {
            const val = Math.floor(Math.sin(i * 0.4) * 30 + 40 + (Math.random() * 15));
            const x = 20 + i * barWidth;
            const h = (val / 100) * (height - 25);
            const y = height - 20 - h;
            
            ctx.fillStyle = i === bars - 1 ? 'rgba(194, 239, 78, 0.7)' : 'rgba(106, 95, 193, 0.4)';
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

        const countBy = (key) => {
            const counts = {};
            _flowSiemData.forEach(e => {
                const k = e[key] || 'Unknown';
                counts[k] = (counts[k] || 0) + 1;
            });
            return Object.entries(counts).sort((a,b) => b[1] - a[1]).slice(0, 4);
        };

        const topSrc = countBy('src_ip');
        const topDst = countBy('dst_ip');
        const topAction = countBy('action');

        const renderSection = (title, items, icon) => `
            <div style="margin-bottom:14px;">
                <h5 style="margin:0 0 6px; font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:.05em;">
                    <i class="fa-solid ${icon}"></i> ${title}
                </h5>
                ${items.map(([val, cnt]) => `
                    <div style="display:flex; align-items:center; justify-content:space-between; font-size:11px; padding:3px 6px; border-radius:4px; cursor:pointer; background:var(--surface-3); margin-bottom:4px;" onclick="applySiemFilter('${escapeHtml(val)}')">
                        <span style="font-family:var(--font-code); text-overflow:ellipsis; overflow:hidden; white-space:nowrap; max-width:130px;">${escapeHtml(val)}</span>
                        <span class="badge" style="font-size:10px;">${cnt}</span>
                    </div>
                `).join('')}
            </div>
        `;

        facetBox.innerHTML = 
            renderSection('Top Sorgenti', topSrc, 'fa-network-wired') +
            renderSection('Top Destinazioni', topDst, 'fa-server') +
            renderSection('Stato Azione', topAction, 'fa-shield-halved');
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

        let events = _flowSiemData;
        if (_activeQuery) {
            events = events.filter(e => 
                e.src_ip.toLowerCase().includes(_activeQuery) ||
                e.dst_ip.toLowerCase().includes(_activeQuery) ||
                e.proto.toLowerCase().includes(_activeQuery) ||
                e.action.toLowerCase().includes(_activeQuery) ||
                e.threat_flag.toLowerCase().includes(_activeQuery)
            );
        }

        if (!events.length) {
            tbody.innerHTML = `<tr><td colspan="7" style="padding:20px; text-align:center; color:var(--text-muted);">${currentLang==='en'?'No matching flow events.':'Nessun evento di flusso corrispondente.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = events.map(e => {
            const isDeny = e.action === 'DENY';
            const actionCol = isDeny ? 'var(--danger)' : 'var(--success)';
            const timeStr = new Date(e.timestamp).toLocaleTimeString();
            return `<tr style="font-size:12px; border-top:1px solid var(--border);">
                <td style="padding:6px 8px; font-family:var(--font-code); color:var(--text-muted);">${timeStr}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);"><strong style="color:var(--primary);">${escapeHtml(e.src_ip)}</strong>:${e.src_port}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);"><strong>${escapeHtml(e.dst_ip)}</strong>:${e.dst_port}</td>
                <td style="padding:6px 8px;"><span class="badge">${escapeHtml(e.proto)}</span></td>
                <td style="padding:6px 8px; font-weight:700; color:${actionCol};">${escapeHtml(e.action)}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);">${(e.bytes / 1024).toFixed(1)} KB</td>
                <td style="padding:6px 8px;"><span class="badge" style="background:${isDeny ? 'rgba(239, 68, 68, 0.15)' : 'var(--surface-3)'}; color:${isDeny ? 'var(--danger)' : 'var(--text)'};">${escapeHtml(e.threat_flag)}</span></td>
            </tr>`;
        }).join('');
    }

    // Expose functions globally
    window.loadFlowSiemTab = loadFlowSiemTab;
    window.applyFlowSiemPreviewGating = applyFlowSiemPreviewGating;
    window.setFlowSiemPreview = setFlowSiemPreview;
    window.toggleSiemStream = toggleSiemStream;
    window.filterSiemEvents = filterSiemEvents;
    window.applySiemFilter = applySiemFilter;
})();
