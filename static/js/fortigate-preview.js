// ===== FortiGate LIVE (PREVIEW) tab — token API + oggetti firewall live =====
// Gating: la tab e il flag sono admin-only (mirror del pattern MCP Client,
// vedi mcp-client.js). Questa è l'unica proprietaria della UI token/oggetti
// FortiGate: il duplicato che viveva in tab-provisioner (provisioning.js) è
// stato rimosso. Le stringhe derivate dal FortiGate passano sempre da
// escapeHtml(jsStr(x)) (jsStr definito in mcp-client.js).

const FGT_OBJ_COLUMNS = {
    'addresses': [
        ['name', 'colFgtAddrName'], ['type', 'colFgtAddrType'],
        ['subnet', 'colFgtAddrSubnet'], ['fqdn', 'colFgtAddrFqdn'],
        ['comment', 'colFgtAddrComment'],
    ],
    'policy-objects': [
        ['policyid', 'colFgtPolId'], ['name', 'colFgtPolName'],
        ['srcintf', 'colFgtPolSrcIntf'], ['dstintf', 'colFgtPolDstIntf'],
        ['srcaddr', 'colFgtPolSrcAddr'], ['dstaddr', 'colFgtPolDstAddr'],
        ['service', 'colFgtPolService'], ['action', 'colFgtPolAction'],
        ['status', 'colFgtPolStatus'], ['logtraffic', 'colFgtPolLog'],
    ],
    'services': [
        ['name', 'colFgtSvcName'], ['tcp-portrange', 'colFgtSvcTcp'],
        ['udp-portrange', 'colFgtSvcUdp'], ['comment', 'colFgtSvcComment'],
    ],
};
const FGT_OBJ_ENDPOINT = {
    'addresses': 'addresses', 'policy-objects': 'policy-objects', 'services': 'services',
};

// --- Gating: mostra la tab solo se il flag preview e' attivo (chiamata in appInit) ---
async function applyFgtPreviewGating() {
    const res = await apiFetch('/api/settings/fortigate-preview');
    if (!res || !res.ok) return;
    const data = await res.json();
    const nav = document.getElementById('navFortigatePreview');
    if (nav) nav.style.display = data.fortigate_preview ? '' : 'none';
    const toggle = document.getElementById('fgtPreviewToggle');
    if (toggle) toggle.checked = !!data.fortigate_preview;
}

// --- Toggle preview (nella tab MCP Server) ---
async function setFgtPreview(enabled) {
    const st = document.getElementById('fgtPreviewStatus');
    const res = await apiFetch('/api/settings/fortigate-preview', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !!enabled })
    });
    const L = i18n[currentLang];
    if (res && res.ok) {
        if (st) st.textContent = L.mcpPreviewSaved || 'Salvato.';
        await applyFgtPreviewGating();
    } else {
        const e = res ? await res.json().catch(() => ({})) : {};
        if (st) st.textContent = (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || '');
    }
}

// --- Caricamento tab ---
function loadFgtPreviewTab() {
    populateFgtPrevDeviceSelects();
    loadFgtPrevTokens();
    fgtPrevObjRows = [];
    renderFgtPrevObjTable();
}

function populateFgtPrevDeviceSelects() {
    const fgtDevices = (typeof globalDevices !== 'undefined' ? globalDevices : []).filter(dev =>
        (dev.Vendor || '').toLowerCase() === 'fortinet'
    );
    const opts = '<option value="" data-i18n="optFgtSelectDevice">-- seleziona dispositivo --</option>' +
        fgtDevices.map(dev =>
            `<option value="${escapeHtml(dev.IP)}" title="${escapeHtml(dev.Hostname || dev.IP)}">${escapeHtml(dev.IP)} (${escapeHtml(dev.Hostname || 'unknown')})</option>`
        ).join('');
    ['fgtPrevTokenDevice', 'fgtPrevObjDevice'].forEach(id => {
        const select = document.getElementById(id);
        if (!select) return;
        const currentValue = select.value;
        select.innerHTML = opts;
        if (currentValue) select.value = currentValue;
    });
}

// --- Token API (admin-only) ---

async function loadFgtPrevTokens() {
    try {
        const res = await apiFetch('/api/fortigate/tokens');
        if (!res || !res.ok) {
            document.getElementById('fgtPrevTokensEmpty').style.display = '';
            document.getElementById('fgtPrevTokensTable').style.display = 'none';
            return;
        }
        renderFgtPrevTokensTable(await res.json());
    } catch (e) {
        console.error('Errore caricamento token FortiGate (preview):', e);
    }
}

function renderFgtPrevTokensTable(tokens) {
    const tbody = document.getElementById('fgtPrevTokensTableBody');
    const emptyMsg = document.getElementById('fgtPrevTokensEmpty');
    const table = document.getElementById('fgtPrevTokensTable');
    if (!tbody) return;

    const entries = Object.entries(tokens || {});
    if (!entries.length) {
        tbody.innerHTML = '';
        table.style.display = 'none';
        emptyMsg.style.display = '';
        return;
    }

    table.style.display = '';
    emptyMsg.style.display = 'none';
    tbody.innerHTML = entries.map(([ip, conf]) => {
        const port = conf.port || 443;
        const verifyTls = conf.verify_tls !== false ? 'Sì' : 'No';
        const status = '<span class="status ok"><i class="fa-solid fa-check"></i> Configurato</span>';
        return `<tr style="border-bottom:1px solid var(--border);">
            <td style="padding:8px 12px;">${escapeHtml(jsStr(ip))}</td>
            <td style="padding:8px 12px;">${port}</td>
            <td style="padding:8px 12px;">${verifyTls}</td>
            <td style="padding:8px 12px;">${status}</td>
        </tr>`;
    }).join('');
}

async function saveFgtPrevToken() {
    const ip = document.getElementById('fgtPrevTokenDevice').value.trim();
    const token = document.getElementById('fgtPrevTokenValue').value;
    const port = parseInt(document.getElementById('fgtPrevTokenPort').value) || 443;
    const verifyTls = document.getElementById('fgtPrevTokenVerifyTls').checked;
    const st = document.getElementById('fgtPrevTokenStatus');

    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }
    if (port < 1 || port > 65535) { showToast(currentLang === 'en' ? 'Invalid port (1-65535)' : 'Porta non valida (1-65535)', 'error'); return; }
    if (!token) { showToast(currentLang === 'en' ? 'Enter a token' : 'Inserire un token', 'warning'); return; }

    const res = await apiFetch('/api/fortigate/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, token, port, verify_tls: verifyTls })
    });
    if (res && res.ok) {
        showToast(currentLang === 'en' ? 'Token saved successfully (encrypted)' : 'Token salvato con successo (cifrato)', 'success');
        document.getElementById('fgtPrevTokenValue').value = '';
        document.getElementById('fgtPrevTokenPort').value = '443';
        document.getElementById('fgtPrevTokenVerifyTls').checked = false;
        document.getElementById('fgtPrevTokenDevice').value = '';
        if (st) st.textContent = '';
        await loadFgtPrevTokens();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || (currentLang === 'en' ? 'Token save failed' : 'Salvataggio token fallito')}`, 'error');
    }
}

async function removeFgtPrevToken() {
    const ip = document.getElementById('fgtPrevTokenDevice').value.trim();
    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }
    if (!confirm(currentLang === 'en' ? `Remove the API token for ${ip}?` : `Rimuovere il token API per ${ip}?`)) return;

    const res = await apiFetch('/api/fortigate/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, token: "", port: 443, verify_tls: false })
    });
    if (res && res.ok) {
        showToast(currentLang === 'en' ? 'Token removed successfully' : 'Token rimosso con successo', 'success');
        document.getElementById('fgtPrevTokenDevice').value = '';
        await loadFgtPrevTokens();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || (currentLang === 'en' ? 'Token removal failed' : 'Rimozione token fallita')}`, 'error');
    }
}

async function testFgtPrevToken() {
    const ip = document.getElementById('fgtPrevTokenDevice').value.trim();
    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }

    const statusDiv = document.getElementById('fgtPrevTokenStatus');
    statusDiv.textContent = currentLang === 'en' ? 'Testing...' : 'Test in corso...';
    statusDiv.style.color = 'var(--text-muted)';

    const res = await apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/status`);
    if (res && res.ok) {
        const data = await res.json();
        const source = data.source || 'unknown';
        const results = data.data || {};
        let hostname = results.hostname || results.host || 'Unknown';
        let version = results.version || results.FortiOS_version || 'Unknown';
        if (results.results) {
            hostname = results.results.hostname || hostname;
            version = results.results.version || version;
        }
        let msg = `Test OK (${source}): ${hostname} v${version}`;
        if (source === 'ssh' && data.api_error) {
            msg += currentLang === 'en' ? ` — REST API failed: ${data.api_error}` : ` — REST API fallita: ${data.api_error}`;
        }
        showToast(msg, 'success');
        statusDiv.textContent = msg;
        statusDiv.style.color = 'var(--success)';
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        const msg = `${currentLang === 'en' ? 'Test failed: ' : 'Test fallito: '}${err.detail || (currentLang === 'en' ? 'Device unreachable' : 'Dispositivo non raggiungibile')}`;
        showToast(msg, 'error');
        statusDiv.textContent = msg;
        statusDiv.style.color = 'var(--danger)';
    }
}

// --- Oggetti Firewall FortiGate (live, sola lettura) ---
// Usa FGT_OBJ_COLUMNS/FGT_OBJ_ENDPOINT definiti in cima a questo file.

let fgtPrevObjView = 'addresses';   // 'addresses' | 'policy-objects' | 'services'
let fgtPrevObjRows = [];

function switchFgtPrevObjView(view) {
    fgtPrevObjView = view;
    ['addresses', 'policy-objects', 'services'].forEach(v => {
        const id = v === 'addresses' ? 'fgtPrevObjTabAddresses' : v === 'policy-objects' ? 'fgtPrevObjTabPolicies' : 'fgtPrevObjTabServices';
        const el = document.getElementById(id);
        if (el) el.classList.toggle('active', v === view);
    });
    loadFgtPrevObjects();
}

async function loadFgtPrevObjects() {
    const ip = document.getElementById('fgtPrevObjDevice')?.value.trim();
    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }
    try {
        const res = await apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/firewall/${FGT_OBJ_ENDPOINT[fgtPrevObjView]}`);
        if (res && res.ok) {
            const body = await res.json();
            const data = body && body.data;
            fgtPrevObjRows = Array.isArray(data) ? data : (data ? [data] : []);
        } else {
            const err = res ? await res.json().catch(() => ({})) : {};
            showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || (currentLang === 'en' ? 'Load failed' : 'Caricamento fallito')}`, 'error');
            fgtPrevObjRows = [];
        }
    } catch (e) {
        console.error('Errore loadFgtPrevObjects:', e);
        showToast(currentLang === 'en' ? 'Network error' : 'Errore di rete', 'error');
        fgtPrevObjRows = [];
    }
    renderFgtPrevObjTable();
}

function renderFgtPrevObjTable() {
    const table = document.getElementById('fgtPrevObjTable');
    const thead = document.getElementById('fgtPrevObjTableHead');
    const tbody = document.getElementById('fgtPrevObjTableBody');
    const emptyMsg = document.getElementById('fgtPrevObjEmpty');
    if (!table || !thead || !tbody) return;

    const cols = FGT_OBJ_COLUMNS[fgtPrevObjView] || [];
    const filterVal = (document.getElementById('fgtPrevObjFilter')?.value || '').trim().toLowerCase();

    const rowText = row => cols.map(([key]) => {
        const v = row ? row[key] : undefined;
        return Array.isArray(v) ? v.map(x => (x && x.name) || x).join(' ') : (v == null ? '' : String(v));
    }).join(' ').toLowerCase();

    const rows = filterVal ? fgtPrevObjRows.filter(r => rowText(r).includes(filterVal)) : fgtPrevObjRows;

    if (!rows.length) {
        table.style.display = 'none';
        emptyMsg.style.display = '';
        thead.innerHTML = '';
        tbody.innerHTML = '';
        return;
    }

    table.style.display = '';
    emptyMsg.style.display = 'none';
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    thead.innerHTML = '<tr style="border-bottom:1px solid var(--border); background:var(--surface-3);">' +
        cols.map(([, labelKey]) => `<th style="padding:8px 12px; text-align:left;">${escapeHtml(L[labelKey] || labelKey)}</th>`).join('') +
        '</tr>';
    tbody.innerHTML = rows.map(row => {
        const tds = cols.map(([key]) => {
            let v = row ? row[key] : undefined;
            if (Array.isArray(v)) v = v.map(x => (x && x.name) || x).join(', ');
            if (v === null || v === undefined || v === '') v = '—';
            return `<td style="padding:8px 12px; font-family:var(--font-code); font-size:12px;">${escapeHtml(jsStr(v))}</td>`;
        }).join('');
        return `<tr style="border-bottom:1px solid var(--border);">${tds}</tr>`;
    }).join('');
}
