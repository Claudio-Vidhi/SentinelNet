// -*- coding: utf-8 -*-
// WLC Live Observability module for SentinelNet

let currentWlcIp = '';

async function loadWlcTab() {
    const select = document.getElementById('wlcTargetSelect');
    if (!select) return;

    try {
        // /api/local-devices, non /api/devices: quest'ultima non e' mai
        // esistita, la fetch tornava 404 e la select restava vuota. La risposta
        // e' una busta {devices, detected_versions, groups}, non un array.
        const res = await apiFetch('/api/local-devices');
        if (!res || !res.ok) return;
        const data = await res.json();
        const devices = data.devices || [];

        select.innerHTML = '<option value="">-- Seleziona Cisco WLC --</option>';
        const wlcVendors = ['cisco_wlc', 'cisco_9800', 'cisco'];
        
        const wlcDevices = devices.filter(d => 
            wlcVendors.includes((d.Vendor || '').toLowerCase()) ||
            (d.Hostname || '').toLowerCase().includes('wlc')
        );

        const listToUse = wlcDevices.length > 0 ? wlcDevices : devices;
        listToUse.forEach(d => {
            const opt = document.createElement('option');
            opt.value = d.IP;
            opt.textContent = `${d.Hostname || d.IP} (${d.IP}) - ${d.Vendor || 'Cisco'}`;
            select.appendChild(opt);
        });

        if (select.options.length > 1) {
            select.selectedIndex = 1;
            onWlcTargetChanged();
        }
    } catch (e) {
        console.error('Errore caricamento lista WLC:', e);
    }
}

function onWlcTargetChanged() {
    const select = document.getElementById('wlcTargetSelect');
    if (!select) return;
    currentWlcIp = select.value;
    if (currentWlcIp) {
        refreshWlcData();
    }
}

async function refreshWlcData() {
    if (!currentWlcIp) return;
    
    const statusBox = document.getElementById('wlcStatusBox');
    if (statusBox) statusBox.innerHTML = '<div class="spinner"></div> Caricamento stato WLC...';
    
    try {
        // Una sola chiamata: il backend apre una sola sessione SSH e risponde
        // con aps/clients/wlans/rogues gia' strutturati. Le cinque fetch
        // parallele di prima aprivano cinque login SSH (AireOS ne accetta 5 in
        // tutto) e tornavano testo CLI grezzo, che nessuna tabella sapeva
        // leggere: il tab restava vuoto su qualunque piattaforma.
        const res = await apiFetch(`/api/wlc/${currentWlcIp}/overview`);
        if (!res || !res.ok) {
            let msg = 'Impossibile connettersi al WLC.';
            try {
                const err = await res.json();
                if (err.detail) msg = escapeHtml(err.detail);
            } catch (_) { /* risposta non JSON: resta il messaggio generico */ }
            if (statusBox) statusBox.innerHTML = `<span style="color:var(--danger)">${msg}</span>`;
            return;
        }
        const data = await res.json();
        renderWlcStatus(data);
        renderWlcAps(data);
        renderWlcClients(data);
        renderWlcWlans(data);
        renderWlcRogues(data);

    } catch (e) {
        console.error('Errore refresh WLC:', e);
        showToast('Errore durante il recupero dei dati dal WLC: ' + e.message, 'error');
    }
}

function renderWlcStatus(d) {
    const box = document.getElementById('wlcStatusBox');
    if (!box) return;
    
    box.innerHTML = `
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:12px;">
            <div class="kpi-card">
                <div class="kpi-label">Controller IP</div>
                <div class="kpi-value" style="font-size:15px;">${escapeHtml(currentWlcIp)}</div>
                <div class="kpi-label">${escapeHtml(d.platform === 'aireos' ? 'AireOS' : (d.platform === 'iosxe' ? 'IOS-XE / 9800' : ''))}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Versione / Uptime</div>
                <div class="kpi-value" style="font-size:14px;">${escapeHtml(d.version || 'N/A')}</div>
                <div class="kpi-label">${escapeHtml(d.uptime || '')}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">AP Collegati</div>
                <div class="kpi-value" style="color:var(--accent);">${d.ap_count != null ? d.ap_count : (d.aps ? d.aps.length : '0')}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Clienti Wireless Attivi</div>
                <div class="kpi-value" style="color:var(--success);">${d.client_count != null ? d.client_count : (d.clients ? d.clients.length : '0')}</div>
            </div>
        </div>
    `;
}

function renderWlcAps(apData) {
    const tbody = document.getElementById('wlcApTableBody');
    if (!tbody) return;
    const aps = Array.isArray(apData) ? apData : (apData.aps || []);
    
    if (aps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Nessun Access Point rilevato</td></tr>';
        return;
    }

    tbody.innerHTML = aps.map(ap => `
        <tr>
            <td style="font-weight:700;">${escapeHtml(ap.name || ap.ap_name || '-')}</td>
            <td>${escapeHtml(ap.ip || ap.ip_address || '-')}</td>
            <td>${escapeHtml(ap.mac || ap.ethernet_mac || '-')}</td>
            <td><span class="badge ${ap.status === 'UP' || ap.joined ? 'badge-success' : 'badge-danger'}">${escapeHtml(ap.status || 'JOINED')}</span></td>
            <td>${escapeHtml(ap.clients || ap.client_count || '0')}</td>
            <td>${escapeHtml(ap.model || '-')}</td>
        </tr>
    `).join('');
}

function renderWlcClients(clientData) {
    const tbody = document.getElementById('wlcClientTableBody');
    if (!tbody) return;
    const clients = Array.isArray(clientData) ? clientData : (clientData.clients || []);
    
    if (clients.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Nessun client associato</td></tr>';
        return;
    }

    tbody.innerHTML = clients.slice(0, 100).map(c => `
        <tr>
            <td style="font-family:var(--font-code); font-weight:700;">${escapeHtml(c.mac || c.mac_address || '-')}</td>
            <td>${escapeHtml(c.ip || c.ip_address || '-')}</td>
            <td>${escapeHtml(c.ap_name || c.ap || '-')}</td>
            <td>${escapeHtml(c.wlan || c.ssid || '-')}</td>
            <td>${escapeHtml(c.rssi || '-')} dBm / ${escapeHtml(c.snr || '-')} dB</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="wlcDiagnoseClient('${escapeHtml(c.mac || c.mac_address)}')">
                    <i class="fa-solid fa-stethoscope"></i> Diagnostica
                </button>
            </td>
        </tr>
    `).join('');
}

function renderWlcWlans(wlanData) {
    const tbody = document.getElementById('wlcWlanTableBody');
    if (!tbody) return;
    const wlans = Array.isArray(wlanData) ? wlanData : (wlanData.wlans || []);

    if (wlans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">Nessun WLAN/SSID configurato</td></tr>';
        return;
    }

    tbody.innerHTML = wlans.map(w => `
        <tr>
            <td>${escapeHtml(String(w.id || w.wlan_id || '-'))}</td>
            <td style="font-weight:700;">${escapeHtml(w.ssid || w.name || '-')}</td>
            <td><span class="badge ${w.status === 'UP' || w.enabled ? 'badge-success' : 'badge-secondary'}">${escapeHtml(w.status || 'ENABLED')}</span></td>
            <td>${escapeHtml(w.security || w.auth || 'WPA2/WPA3')}</td>
        </tr>
    `).join('');
}

function renderWlcRogues(rogueData) {
    const tbody = document.getElementById('wlcRogueTableBody');
    if (!tbody) return;
    const rogues = Array.isArray(rogueData) ? rogueData : (rogueData.rogues || []);

    if (rogues.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);"><i class="fa-solid fa-shield-cat"></i> Nessun Rogue AP rilevato nelle vicinanze</td></tr>';
        return;
    }

    tbody.innerHTML = rogues.map(r => `
        <tr>
            <td style="font-family:var(--font-code); font-weight:700; color:var(--danger);">${escapeHtml(r.mac || r.bssid || '-')}</td>
            <td>${escapeHtml(r.ssid || 'N/A (Nascosto)')}</td>
            <td>${escapeHtml(String(r.channel || '-'))}</td>
            <td>${escapeHtml(r.rssi || '-')} dBm</td>
            <td><span class="badge badge-warning">${escapeHtml(r.status || 'UNCLASSIFIED')}</span></td>
        </tr>
    `).join('');
}

async function wlcDiagnoseClient(mac) {
    if (!currentWlcIp || !mac) return;
    
    showToast(`Diagnostica in corso per client ${mac}...`, 'info');
    try {
        const res = await apiFetch(`/api/wlc/${currentWlcIp}/diagnose-client/${encodeURIComponent(mac)}`);
        if (!res || !res.ok) {
            showToast('Errore durante l\'esecuzione della diagnostica', 'error');
            return;
        }
        const diag = await res.json();

        // Il modal si apriva con openModal(), che non esiste in nessun file:
        // il ReferenceError finiva nel catch e la finestra non compariva mai.
        // Il resto della UI apre i modal cosi'.
        const sections = diag.sections || {};
        const labels = [['client_detail', 'Dettaglio client'],
                        ['ap_summary', 'Access Point'],
                        ['wlan_summary', 'WLAN'],
                        ['rogue_aps', 'Rogue AP vicini']];
        document.getElementById('wlcDiagModalBody').innerHTML = labels.map(([key, label]) => {
            const s = sections[key] || {};
            const body = s.error ? `Errore: ${s.error}` : (s.data || '(nessun output)');
            return `
                <div style="margin-bottom:16px;">
                    <div style="font-weight:700; margin-bottom:6px;">${escapeHtml(label)}
                        <span style="font-weight:400; font-family:var(--font-code); font-size:11px; color:var(--text-muted); margin-left:8px;">${escapeHtml(s.command || '')}</span>
                    </div>
                    <pre style="font-family:var(--font-code); background:var(--surface-3); padding:12px; margin:0; max-height:260px; overflow:auto; font-size:12px; white-space:pre;">${escapeHtml(body)}</pre>
                </div>`;
        }).join('');
        document.getElementById('wlcDiagModal').style.display = 'flex';
    } catch (e) {
        console.error('Errore diagnostica client WLC:', e);
        showToast('Errore diagnostica: ' + e.message, 'error');
    }
}
