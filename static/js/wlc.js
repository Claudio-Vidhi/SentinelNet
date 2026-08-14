// -*- coding: utf-8 -*-
// WLC Live Observability module for SentinelNet

let currentWlcIp = '';
// Only inventory controllers: the vendor is the sole reliable recognition
// (the SSH driver to use depends on it). A hostname containing "wlc" is not a
// WLC, and the old "if nothing matches show everything" fallback let the user
// pick switches that the backend then rejected with 400.
const WLC_VENDORS = ['cisco_wlc', 'cisco_9800'];
let wlcInventory = [];

async function loadWlcTab() {
    const tenantSel = document.getElementById('wlcTenantSelect');
    const select = document.getElementById('wlcTargetSelect');
    if (!tenantSel || !select) return;

    try {
        // /api/local-devices, non /api/devices: quest'ultima non e' mai
        // esistita, la fetch tornava 404 e la select restava vuota. La risposta
        // e' una busta {devices, detected_versions, groups}, non un array.
        const res = await apiFetch('/api/local-devices');
        if (!res || !res.ok) return;
        const data = await res.json();
        const devices = data.devices || [];

        wlcInventory = devices.filter(d => WLC_VENDORS.includes((d.Vendor || '').toLowerCase()));

        // Only tenants that own at least one WLC: picking an empty one would be
        // a dead end.
        const tenants = [...new Set(wlcInventory.map(d => d.Group || 'Generale'))].sort();
        const curTenant = tenantSel.value;
        tenantSel.innerHTML = '<option value="">-- Seleziona tenant --</option>' +
            tenants.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
        tenantSel.value = tenants.includes(curTenant) ? curTenant : '';
        onWlcTenantChanged();
    } catch (e) {
        console.error('Errore caricamento lista WLC:', e);
    }
}

// The device is chosen inside a tenant: with no tenant the select stays empty
// and disabled.
function onWlcTenantChanged() {
    const tenantSel = document.getElementById('wlcTenantSelect');
    const select = document.getElementById('wlcTargetSelect');
    if (!tenantSel || !select) return;

    const tenant = tenantSel.value;
    const devs = tenant ? wlcInventory.filter(d => (d.Group || 'Generale') === tenant) : [];
    select.disabled = !tenant;
    select.innerHTML = `<option value="">${tenant ? '-- Seleziona Cisco WLC --' : '-- Scegli prima un tenant --'}</option>` +
        devs.map(d => `<option value="${escapeHtml(d.IP)}">${escapeHtml(d.Hostname || d.IP)} (${escapeHtml(d.IP)}) - ${escapeHtml(d.Vendor)}</option>`).join('');
    select.value = '';
    onWlcTargetChanged();
}

function onWlcTargetChanged() {
    const select = document.getElementById('wlcTargetSelect');
    if (!select) return;
    currentWlcIp = select.value;
    if (currentWlcIp) {
        refreshWlcData();
        return;
    }
    const statusBox = document.getElementById('wlcStatusBox');
    if (statusBox) statusBox.innerHTML = '';
    wlcClients = [];
    const searchBox = document.getElementById('wlcClientSearch');
    if (searchBox) searchBox.value = '';
    const countBox = document.getElementById('wlcClientCount');
    if (countBox) countBox.textContent = '';
    ['wlcApTableBody', 'wlcClientTableBody', 'wlcWlanTableBody', 'wlcRogueTableBody'].forEach(id => {
        const tb = document.getElementById(id);
        if (tb) tb.innerHTML = '';
    });
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
            ${renderWlcQualityKpi(d.clients || [])}
        </div>
    `;
}

// Quadro d'insieme della qualita' radio: solo i client di cui il controller ha
// dato RSSI/SNR (il dettaglio si raccoglie fino a un tetto per non allungare il
// refresh oltre la validita' del dato).
function renderWlcQualityKpi(clients) {
    const rated = clients.map(c => wlcQuality(c.rssi, c.snr)).filter(Boolean);
    if (rated.length === 0) return '';
    const count = label => rated.filter(q => q.label === label).length;
    const weak = count('Sufficiente') + count('Scarsa');
    const color = count('Scarsa') ? 'var(--danger)' : (weak ? 'var(--warning)' : 'var(--success)');
    return `
            <div class="kpi-card">
                <div class="kpi-label">Qualita' Wi-Fi (${rated.length} client misurati)</div>
                <div class="kpi-value" style="font-size:15px; color:${color};">${weak
                    ? `${weak} sotto soglia`
                    : 'Nessun client critico'}</div>
                <div class="kpi-label">${count('Ottima')} ottima &middot; ${count('Buona')} buona &middot; ${count('Sufficiente')} sufficiente &middot; ${count('Scarsa')} scarsa</div>
            </div>`;
}

function renderWlcAps(apData) {
    const tbody = document.getElementById('wlcApTableBody');
    if (!tbody) return;
    const aps = Array.isArray(apData) ? apData : (apData.aps || []);
    
    if (aps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">Nessun Access Point rilevato</td></tr>';
        return;
    }

    // Canale, larghezza e utilizzo arrivano dall'auto-RF (solo AireOS), una
    // colonna per radio: dove il controller non li da', la cella resta un
    // trattino. Le chiavi con suffisso _24 sono la radio 2.4 GHz.
    tbody.innerHTML = aps.map(ap => `
        <tr>
            <td style="font-weight:700;">${escapeHtml(ap.name || ap.ap_name || '-')}</td>
            <td>${escapeHtml(ap.ip || ap.ip_address || '-')}</td>
            <td>${escapeHtml(ap.mac || ap.ethernet_mac || '-')}</td>
            <td><span class="badge ${ap.status === 'UP' || ap.joined ? 'badge-success' : 'badge-danger'}">${escapeHtml(ap.status || 'JOINED')}</span></td>
            <td>${escapeHtml(ap.clients || ap.client_count || '0')}</td>
            <td title="${escapeHtml(ap.channel_utilization ? 'Utilizzo canale ' + ap.channel_utilization : '')}">${
                escapeHtml(ap.channel || '-')}${ap.channel_width ? ' @ ' + escapeHtml(ap.channel_width) : ''}</td>
            <td title="${escapeHtml(ap.channel_utilization_24 ? 'Utilizzo canale ' + ap.channel_utilization_24 : '')}">${
                escapeHtml(ap.channel_24 || '-')}${ap.channel_width_24 ? ' @ ' + escapeHtml(ap.channel_width_24) : ''}</td>
            <td>${escapeHtml(ap.model || '-')}</td>
        </tr>
    `).join('');
}

// Wi-Fi quality from the client's own radio figures. Thresholds are the usual
// design targets: -67 dBm / 25 dB SNR is what voice and seamless roaming need,
// below -80 dBm / 15 dB the link survives but retransmits. A level counts only
// when BOTH figures clear it: a good SNR does not make up for a weak signal,
// nor the other way round. A missing figure does not block the other one.
const WLC_QUALITY_LEVELS = [
    { label: 'Ottima',      cls: 'badge-success', rssi: -65, snr: 25 },
    { label: 'Buona',       cls: 'badge-success', rssi: -72, snr: 20 },
    { label: 'Sufficiente', cls: 'badge-warning', rssi: -80, snr: 15 },
];
const WLC_QUALITY_POOR = { label: 'Scarsa', cls: 'badge-danger' };

function wlcQuality(rssi, snr) {
    const r = parseFloat(rssi), s = parseFloat(snr);
    if (!isFinite(r) && !isFinite(s)) return null;
    return WLC_QUALITY_LEVELS.find(l => (!isFinite(r) || r >= l.rssi) && (!isFinite(s) || s >= l.snr))
        || WLC_QUALITY_POOR;
}

// Ultimi client ricevuti dall'overview: la ricerca filtra questi, non le sole
// righe gia' disegnate (la tabella e' troncata a 100).
let wlcClients = [];

function renderWlcClients(clientData) {
    wlcClients = Array.isArray(clientData) ? clientData : (clientData.clients || []);
    renderWlcClientRows();
}

function onWlcClientSearch() {
    renderWlcClientRows();
}

function renderWlcClientRows() {
    const tbody = document.getElementById('wlcClientTableBody');
    if (!tbody) return;
    const q = (document.getElementById('wlcClientSearch')?.value || '').trim().toLowerCase();
    const clients = q
        ? wlcClients.filter(c => [c.mac, c.mac_address, c.ip, c.ip_address, c.ap_name, c.ap,
                                  c.wlan, c.ssid, c.status].some(v => (v || '').toLowerCase().includes(q)))
        : wlcClients;

    const countBox = document.getElementById('wlcClientCount');
    if (countBox) countBox.textContent = `${clients.length} / ${wlcClients.length}`;

    if (clients.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">${
            q ? 'Nessun client corrisponde alla ricerca' : 'Nessun client associato'}</td></tr>`;
        return;
    }

    tbody.innerHTML = clients.slice(0, 100).map(c => {
        const qual = wlcQuality(c.rssi, c.snr);
        const badge = qual
            ? `<span class="badge ${qual.cls}" title="RSSI ${escapeHtml(c.rssi || 'n/d')} dBm / SNR ${escapeHtml(c.snr || 'n/d')} dB">${qual.label}</span>`
            : '<span style="color:var(--text-muted);" title="Dettaglio radio non raccolto per questo client: usa Diagnostica">n/d</span>';
        return `
        <tr>
            <td style="font-family:var(--font-code); font-weight:700;">${escapeHtml(c.mac || c.mac_address || '-')}</td>
            <td>${escapeHtml(c.ip || c.ip_address || '-')}</td>
            <td>${escapeHtml(c.ap_name || c.ap || '-')}</td>
            <td>${escapeHtml(c.wlan || c.ssid || '-')}</td>
            <td>${escapeHtml(c.rssi || '-')} dBm / ${escapeHtml(c.snr || '-')} dB</td>
            <td>${badge}</td>
            <td>
                <button class="btn btn-sm btn-secondary" data-action="wlc-diagnose" data-mac="${escapeHtml(c.mac || c.mac_address)}">
                    <i class="fa-solid fa-stethoscope"></i> Diagnostica
                </button>
            </td>
        </tr>`;
    }).join('');
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

// Delegated and static event listeners for WLC tab
document.getElementById('wlcTenantSelect')?.addEventListener('change', onWlcTenantChanged);
document.getElementById('wlcTargetSelect')?.addEventListener('change', onWlcTargetChanged);
document.getElementById('btnRefreshWlcData')?.addEventListener('click', refreshWlcData);
document.getElementById('wlcClientSearch')?.addEventListener('input', onWlcClientSearch);
document.getElementById('btnCloseWlcDiagModal')?.addEventListener('click', () => {
    const m = document.getElementById('wlcDiagModal');
    if (m) m.style.display = 'none';
});
document.getElementById('btnFooterCloseWlcDiagModal')?.addEventListener('click', () => {
    const m = document.getElementById('wlcDiagModal');
    if (m) m.style.display = 'none';
});
document.getElementById('wlcClientTableBody')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="wlc-diagnose"]');
    if (btn && btn.dataset.mac) {
        wlcDiagnoseClient(btn.dataset.mac);
    }
});
