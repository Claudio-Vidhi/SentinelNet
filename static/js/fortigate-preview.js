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
    loadFgtTargets();
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

// --- Multi-target FortiGate: selettore + modale di gestione ---------------
// Ogni FortiGate configurato (services/fortigate_service.py, JSON con
// "_active" per il target corrente) può avere un nome descrittivo. Il
// selettore in testa alla tab imposta il target attivo lato server; il
// modale "Gestisci FortiGate" elenca/aggiunge/modifica/rimuove i target e
// ne testa la connessione. Stringhe derivate dal FortiGate/inventario
// passano sempre da escapeHtml(jsStr(x)).

let fgtTargetsCache = [];

async function loadFgtTargets() {
    try {
        const res = await apiFetch('/api/fortigate/targets');
        fgtTargetsCache = (res && res.ok) ? await res.json() : [];
    } catch (e) {
        console.error('Errore caricamento target FortiGate:', e);
        fgtTargetsCache = [];
    }
    renderFgtTargetSelect();
}

function renderFgtTargetSelect() {
    const sel = document.getElementById('fgtTargetSelect');
    if (!sel) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (!fgtTargetsCache.length) {
        sel.innerHTML = `<option value="">${escapeHtml(L.optFgtNoTargets || '-- nessun target configurato --')}</option>`;
        return;
    }
    sel.innerHTML = fgtTargetsCache.map(t => {
        const label = `${t.name ? jsStr(t.name) : jsStr(t.ip)} (${jsStr(t.ip)})`;
        return `<option value="${escapeHtml(jsStr(t.ip))}" ${t.active ? 'selected' : ''}>${escapeHtml(label)}</option>`;
    }).join('');
}

async function onFgtTargetSelectChange() {
    const ip = document.getElementById('fgtTargetSelect')?.value;
    if (!ip) return;
    const res = await apiFetch('/api/fortigate/targets/active', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (res && res.ok) {
        showToast(L.msgFgtTargetActivated || 'Target FortiGate attivo aggiornato.', 'success');
        await loadFgtTargets();
        // Allinea i selettori "dispositivo" del pannello token/oggetti e ricarica gli oggetti live.
        const objSel = document.getElementById('fgtPrevObjDevice');
        if (objSel) { objSel.value = ip; loadFgtPrevObjects(); }
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || ''}`, 'error');
    }
}

function openFgtManageModal() {
    populateFgtMgrDeviceSelect();
    resetFgtMgrForm();
    renderFgtMgrTable();
    document.getElementById('fgtManageModal').style.display = 'flex';
}

function closeFgtManageModal() {
    document.getElementById('fgtManageModal').style.display = 'none';
}

function populateFgtMgrDeviceSelect() {
    const fgtDevices = (typeof globalDevices !== 'undefined' ? globalDevices : []).filter(dev =>
        (dev.Vendor || '').toLowerCase() === 'fortinet'
    );
    const sel = document.getElementById('fgtMgrIp');
    if (!sel) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    const current = sel.value;
    sel.innerHTML = `<option value="">${escapeHtml(L.optFgtSelectDevice || '-- seleziona dispositivo --')}</option>` +
        fgtDevices.map(dev =>
            `<option value="${escapeHtml(dev.IP)}">${escapeHtml(dev.IP)} (${escapeHtml(dev.Hostname || 'unknown')})</option>`
        ).join('');
    if (current) sel.value = current;
}

function renderFgtMgrTable() {
    const tbody = document.getElementById('fgtMgrTableBody');
    const table = document.getElementById('fgtMgrTable');
    const emptyMsg = document.getElementById('fgtMgrEmpty');
    if (!tbody) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};

    if (!fgtTargetsCache.length) {
        tbody.innerHTML = '';
        table.style.display = 'none';
        emptyMsg.style.display = '';
        return;
    }
    table.style.display = '';
    emptyMsg.style.display = 'none';

    tbody.innerHTML = fgtTargetsCache.map(t => {
        const ip = escapeHtml(jsStr(t.ip));
        const name = escapeHtml(jsStr(t.name || ''));
        const tlsBadge = t.verify_tls
            ? `<span class="status ok">${escapeHtml(L.badgeFgtTestOk || 'OK')}</span>`
            : `<span class="status warn">off</span>`;
        return `<tr style="border-bottom:1px solid var(--border);" data-ip="${ip}">
            <td style="padding:8px 12px;">${name || '—'}</td>
            <td style="padding:8px 12px; font-family:var(--font-code);">${ip}</td>
            <td style="padding:8px 12px;">${t.port}</td>
            <td style="padding:8px 12px;">${tlsBadge}</td>
            <td style="padding:8px 12px; text-align:center;">
                <input type="radio" name="fgtMgrActiveRadio" ${t.active ? 'checked' : ''} onclick="activateFgtMgrTarget('${ip}')">
            </td>
            <td style="padding:8px 12px; text-align:center;">
                <button type="button" class="btn btn-secondary btn-small" style="width:auto; margin:0;" onclick="testFgtMgrTarget('${ip}', this)">${L.btnFgtMgrTest || '<i class="fa-solid fa-plug"></i>'}</button>
                <span class="fgt-mgr-test-result" style="margin-left:6px; font-size:11px;"></span>
            </td>
            <td style="padding:8px 12px; text-align:right; white-space:nowrap;">
                <button type="button" class="btn btn-secondary btn-small" style="width:auto; margin:0;" onclick="editFgtMgrTarget('${ip}')" title="${currentLang === 'en' ? 'Edit' : 'Modifica'}"><i class="fa-solid fa-pen"></i></button>
                <button type="button" class="btn btn-danger btn-small" style="width:auto; margin:0;" onclick="deleteFgtMgrTarget('${ip}')">${L.btnFgtMgrDelete || '<i class="fa-solid fa-trash"></i>'}</button>
            </td>
        </tr>`;
    }).join('');
}

function resetFgtMgrForm() {
    document.getElementById('fgtMgrEditIp').value = '';
    document.getElementById('fgtMgrName').value = '';
    const ipSel = document.getElementById('fgtMgrIp');
    if (ipSel) { ipSel.value = ''; ipSel.disabled = false; }
    document.getElementById('fgtMgrPort').value = '443';
    document.getElementById('fgtMgrVerifyTls').checked = false;
    const tokenInput = document.getElementById('fgtMgrToken');
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    tokenInput.value = '';
    tokenInput.placeholder = L.phFgtMgrTokenNew || 'token API';
    const st = document.getElementById('fgtMgrStatus');
    if (st) st.textContent = '';
}

function editFgtMgrTarget(ip) {
    const t = fgtTargetsCache.find(x => x.ip === ip);
    if (!t) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    document.getElementById('fgtMgrEditIp').value = t.ip;
    document.getElementById('fgtMgrName').value = t.name || '';
    const ipSel = document.getElementById('fgtMgrIp');
    if (ipSel) { ipSel.value = t.ip; ipSel.disabled = true; }
    document.getElementById('fgtMgrPort').value = t.port || 443;
    document.getElementById('fgtMgrVerifyTls').checked = !!t.verify_tls;
    const tokenInput = document.getElementById('fgtMgrToken');
    tokenInput.value = '';
    tokenInput.placeholder = L.phFgtMgrTokenEdit || '•••• invariato';
}

async function saveFgtMgrTarget() {
    const editIp = document.getElementById('fgtMgrEditIp').value.trim();
    const ip = editIp || document.getElementById('fgtMgrIp').value.trim();
    const name = document.getElementById('fgtMgrName').value.trim();
    const port = parseInt(document.getElementById('fgtMgrPort').value) || 443;
    const verifyTls = document.getElementById('fgtMgrVerifyTls').checked;
    const token = document.getElementById('fgtMgrToken').value;
    const st = document.getElementById('fgtMgrStatus');
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};

    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }
    if (port < 1 || port > 65535) { showToast(currentLang === 'en' ? 'Invalid port (1-65535)' : 'Porta non valida (1-65535)', 'error'); return; }
    if (!token) {
        // Come per le altre credenziali dell'app (v. devices.js), il backend
        // non conserva il token "invariato se vuoto": va sempre reinserito,
        // anche in modifica, per aggiornare porta/TLS/nome.
        showToast(currentLang === 'en' ? 'Enter the API token to save (re-enter it even when only editing name/port/TLS)' : 'Inserire il token API per salvare (va reinserito anche modificando solo nome/porta/TLS)', 'warning');
        return;
    }

    const res = await apiFetch('/api/fortigate/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, token: token || '', port, verify_tls: verifyTls, name })
    });
    if (res && res.ok) {
        showToast(L.msgFgtTargetSaved || 'Target FortiGate salvato.', 'success');
        if (st) st.textContent = '';
        resetFgtMgrForm();
        await loadFgtTargets();
        renderFgtMgrTable();
        populateFgtPrevDeviceSelects();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || ''}`, 'error');
    }
}

async function activateFgtMgrTarget(ip) {
    const res = await apiFetch('/api/fortigate/targets/active', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (res && res.ok) {
        showToast(L.msgFgtTargetActivated || 'Target FortiGate attivo aggiornato.', 'success');
        await loadFgtTargets();
        renderFgtMgrTable();
    }
}

async function testFgtMgrTarget(ip, btn) {
    const row = btn.closest('tr');
    const resultSpan = row ? row.querySelector('.fgt-mgr-test-result') : null;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (resultSpan) resultSpan.textContent = currentLang === 'en' ? 'Testing...' : 'Test in corso...';
    const res = await apiFetch(`/api/fortigate/targets/${encodeURIComponent(ip)}/test`, { method: 'POST' });
    const data = res ? await res.json().catch(() => ({ ok: false })) : { ok: false };
    if (resultSpan) {
        if (data.ok) {
            resultSpan.innerHTML = `<span class="status ok">${escapeHtml(L.badgeFgtTestOk || 'OK')}${data.version ? ' v' + escapeHtml(jsStr(data.version)) : ''}</span>`;
        } else {
            resultSpan.innerHTML = `<span class="status bad" title="${escapeHtml(jsStr(data.error || ''))}">${escapeHtml(L.badgeFgtTestFail || 'Fallito')}</span>`;
        }
    }
}

async function deleteFgtMgrTarget(ip) {
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (!confirm(L.confirmFgtTargetDelete || 'Rimuovere questo target FortiGate?')) return;
    const res = await apiFetch('/api/fortigate/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, token: '', port: 443, verify_tls: false })
    });
    if (res && res.ok) {
        showToast(L.msgFgtTargetDeleted || 'Target FortiGate rimosso.', 'success');
        resetFgtMgrForm();
        await loadFgtTargets();
        renderFgtMgrTable();
        populateFgtPrevDeviceSelects();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || ''}`, 'error');
    }
}
