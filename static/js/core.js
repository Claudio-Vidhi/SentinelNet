// --- SIDEBAR RAIL (collasso a icone) ---

const SIDEBAR_COLLAPSED_KEY = 'sidebarCollapsed';

// Con la rail collassata restano solo le icone: il tooltip nativo è l'unica
// etichetta disponibile. Il testo viene DERIVATO dal label già tradotto, così
// non esiste una seconda copia della stringa da tenere allineata: basta
// richiamare questa funzione dopo ogni cambio lingua.
function syncNavTooltips() {
    const collapsed = document.body.classList.contains('sidebar-collapsed');
    document.querySelectorAll('.sidenav .nav-item').forEach(btn => {
        const label = btn.querySelector('.nav-left');
        if (!label) return;
        const text = label.textContent.trim();
        if (collapsed && text) btn.setAttribute('title', text);
        else btn.removeAttribute('title');
    });
}

function applySidebarCollapsed(collapsed) {
    document.body.classList.toggle('sidebar-collapsed', collapsed);
    const btn = document.getElementById('sidebarToggle');
    if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    syncNavTooltips();
}

function toggleSidebar() {
    const collapsed = !document.body.classList.contains('sidebar-collapsed');
    try { localStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? '1' : '0'); } catch (e) {}
    applySidebarCollapsed(collapsed);
}

let globalDevices = [];
let globalGroups = {};
let globalVendors = {};
let globalVersions = {}; // Cache globale per lo stato delle scansioni (ottimizzazione UI)
let currentRole = 'viewer';   // ruolo dell'utente loggato (admin/operator/viewer)
let currentUsername = '';
let appLoading = false;

// --- AUTENTICAZIONE E UTILITY ---

// Escaping HTML per tutti i valori dinamici (hostname dai config, nomi gruppo/vendor,
// descrizioni EUVD): previene markup rotto e stored XSS nelle tabelle e nei tooltip.
function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, c =>
        ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ===== Ordinamento generico colonne per TUTTE le tabelle =====
// Click sull'intestazione: ordina crescente/decrescente. Le celle editabili
// (input/select) ordinano per valore del campo
function _cellSortValue(td) {
    if (!td) return '';
    const sv = td.getAttribute('data-sort-value');
    if (sv !== null && sv !== undefined) return String(sv).trim();
    const f = td.querySelector('input, select');
    return f ? String(f.value || '').trim() : td.textContent.trim();
}
function sortTableByColumn(table, colIdx, th) {
    const tbody = table.tBodies[0];
    if (!tbody) return;
    const asc = th.getAttribute('data-sort-asc') !== 'true';
    Array.from(table.tHead.rows[0].cells).forEach(c => {
        c.removeAttribute('data-sort-asc');
        const i = c.querySelector('.sort-ind');
        if (i) { i.textContent = ' ⇅'; i.style.opacity = '0.35'; }
    });
    th.setAttribute('data-sort-asc', asc ? 'true' : 'false');
    const ind = th.querySelector('.sort-ind');
    if (ind) { ind.textContent = asc ? ' ▲' : ' ▼'; ind.style.opacity = '1'; }
    const rows = Array.from(tbody.rows);
    rows.sort((a, b) => {
        const x = _cellSortValue(a.cells[colIdx]);
        const y = _cellSortValue(b.cells[colIdx]);
        const c = x.localeCompare(y, undefined, { numeric: true, sensitivity: 'base' });
        return asc ? c : -c;
    });
    rows.forEach(r => tbody.appendChild(r));
}
function makeTableSortable(table) {
    if (!table || table.dataset.sortable === '1') return;
    if (!table.tHead || !table.tHead.rows.length) return;
    table.dataset.sortable = '1';
    Array.from(table.tHead.rows[0].cells).forEach((th, idx) => {
        if (th.dataset.noSort === '1') return;
        th.style.cursor = 'pointer';
        th.style.userSelect = 'none';
        if (!th.querySelector('.sort-ind')) {
            const s = document.createElement('span');
            s.className = 'sort-ind';
            s.textContent = ' ⇅';
            s.style.opacity = '0.35';
            s.style.fontSize = '10px';
            th.appendChild(s);
        }
        th.addEventListener('click', () => sortTableByColumn(table, idx, th));
    });
}
function enhanceAllTables(root) {
    (root || document).querySelectorAll('table').forEach(makeTableSortable);
}
function initSortableTables() {
    enhanceAllTables(document);
    const obs = new MutationObserver(muts => {
        for (const m of muts) {
            for (const node of m.addedNodes) {
                if (node.nodeType === 1) {
                    if (node.tagName === 'TABLE') makeTableSortable(node);
                    enhanceAllTables(node);
                }
            }
        }
    });
    obs.observe(document.body, { childList: true, subtree: true });
}
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSortableTables);
} else {
    initSortableTables();
}

// ===== Port Config Modal (promosso da static/js/topology.js: usato anche
// dal tab MAC-tracker/ARP inline e da static/js/config-analyzer.js) =====
// Espande le abbreviazioni comuni delle interfacce ('Gi1/0/5' -> 'GigabitEthernet1/0/5').
// Speculare a expand_iface() di mac_collector.py: tenerli allineati.
function expandIface(name) {
    if (!name) return '';
    name = String(name).trim();
    const abbr = [
        [/^(?:GigabitEthernet|Gi)(?=\d)/i, 'GigabitEthernet'],
        [/^(?:TenGigabitEthernet|TenGigE|Te|XGi|10Ge)(?=\d)/i, 'TenGigabitEthernet'],
        [/^(?:TwentyFiveGigE|Twe|25Ge)(?=\d)/i, 'TwentyFiveGigE'],
        [/^(?:FortyGigabitEthernet|FortyGigE|Fo|40Ge)(?=\d)/i, 'FortyGigE'],
        [/^(?:HundredGigE|Hu|100Ge)(?=\d)/i, 'HundredGigE'],
        [/^(?:FastEthernet|Fa|fe)(?=\d)/i, 'FastEthernet'],
        [/^(?:Ethernet|Eth|Et|e)(?=\d)/i, 'Ethernet'],
        [/^(?:Port-channel|Port-Channel|Po)(?=\d)/i, 'Port-channel'],
    ];
    for (const [pat, full] of abbr) {
        if (pat.test(name)) return name.replace(pat, full);
    }
    return name;
}

function getAuthHeaders() {
    // Autenticazione via cookie HttpOnly (impostato dal server al login).
    // L'header custom è la prova anti-CSRF sulle richieste che modificano stato.
    return { "X-Requested-With": "SentinelNet" };
}

// Funzione centralizzata per iniettare e controllare gli header di autenticazione ed evitare disallineamenti della UI
async function apiFetch(url, options = {}) {
    options.headers = options.headers || {};
    Object.assign(options.headers, getAuthHeaders());

    try {
        const res = await fetch(url, options);
        if (res.status === 401) {
            console.warn("[AUTH] Sessione scaduta o non valida (401). Forzatura Logout.");
            logout();
            return null;
        }
        return res;
    } catch (err) {
        console.error(`[ApiFetch Error] ${url}:`, err);
        return null;
    }
}

async function checkAuthRequirements() {
    // Interroga lo stato del setup/utenti nel sistema
    const res = await fetch('/api/auth/status');
    const data = await res.json();

    const overlay = document.getElementById('authOverlay');
    // Il pannello di cambio password è transitorio: lo nascondiamo sempre qui.
    document.getElementById('changePwSection').style.display = 'none';

    if (!data.has_users) {
        // Nessun utente su disco: mostriamo la procedura guidata di primo setup
        document.getElementById('wizardSection').style.display = 'block';
        document.getElementById('loginSection').style.display = 'none';
        overlay.style.display = 'flex';
        return false;
    } else {
        // Esiste già un amministratore: mostriamo la maschera di login standard
        document.getElementById('wizardSection').style.display = 'none';
        document.getElementById('loginSection').style.display = 'block';
        // La sessione vive nel cookie HttpOnly: la verifichiamo lato server.
        const me = await fetch('/api/auth/me');
        if (!me.ok) {
            overlay.style.display = 'flex';
            return false;
        }
        overlay.style.display = 'none';
        return true;
    }
}

// Evento per la registrazione guidata del primo utente amministratore
document.getElementById('btnRegisterAdmin').addEventListener('click', async () => {
    const user = document.getElementById('wizUser').value.trim();
    const pass = document.getElementById('wizPass').value.trim();

    if(!user || !pass) { alert(i18n[currentLang].alertFirstSetupFill); return; }
    if(pass.length < 8) { alert(i18n[currentLang].alertPassTooShort); return; }

    const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });

    if (res.ok) {
        // Login automatico con le credenziali appena create: evita di
        // dover ridigitare la stessa password nel form di login.
        const loginRes = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        if (loginRes.ok) {
            // La sessione è nel cookie HttpOnly impostato dal server.
            document.getElementById('authOverlay').style.display = 'none';
            appInit();
        } else {
            // Fallback improbabile: account creato ma login fallito.
            alert(i18n[currentLang].alertFirstSetupSuccess);
            checkAuthRequirements();
        }
    } else {
        const err = await res.json();
        alert(i18n[currentLang].alertFirstSetupError + (err.detail || "Impossibile creare l'account."));
    }
});

// Evento per il Login Standard
document.getElementById('btnLogin').addEventListener('click', async () => {
    const user = document.getElementById('loginUser').value.trim();
    const pass = document.getElementById('loginPass').value.trim();
    const errDiv = document.getElementById('loginError');

    if(!user || !pass) { errDiv.innerText = i18n[currentLang].alertLoginFill; errDiv.style.display = 'block'; return; }
    errDiv.style.display = 'none';

    const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
    });

    if (res.ok) {
        const data = await res.json();
        // La sessione è nel cookie HttpOnly impostato dal server: nessun
        // token conservato lato JavaScript (finding L-1).
        if (data.must_change_password) {
            // Account creato da un amministratore: forziamo il cambio password.
            pendingOldPass = pass;
            document.getElementById('loginSection').style.display = 'none';
            document.getElementById('changePwSection').style.display = 'block';
            document.getElementById('cpwNewPass').value = '';
            document.getElementById('cpwConfirmPass').value = '';
            document.getElementById('cpwNewPass').focus();
            return;
        }
        // Sblocca la UI nascondendo la schermata oscurante
        document.getElementById('authOverlay').style.display = 'none';
        appInit(); // Avvia il caricamento dei dispositivi di rete
    } else {
        errDiv.innerText = i18n[currentLang].alertLoginDenied;
        errDiv.style.display = 'block';
    }
});

// Password nota all'utente al momento del cambio obbligatorio (usata come
// vecchia password per l'endpoint /api/auth/change-password).
let pendingOldPass = '';

// Cambio password obbligatorio al primo accesso
document.getElementById('btnChangePass').addEventListener('click', async () => {
    const np = document.getElementById('cpwNewPass').value.trim();
    const cp = document.getElementById('cpwConfirmPass').value.trim();
    const errDiv = document.getElementById('loginError');
    errDiv.style.display = 'none';

    if (np.length < 8) { errDiv.innerText = i18n[currentLang].alertPassTooShort; errDiv.style.display = 'block'; return; }
    if (np !== cp)     { errDiv.innerText = i18n[currentLang].alertPassMismatch; errDiv.style.display = 'block'; return; }

    const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'SentinelNet'
        },
        body: JSON.stringify({ old_password: pendingOldPass, new_password: np })
    });

    if (res.ok) {
        pendingOldPass = '';
        document.getElementById('changePwSection').style.display = 'none';
        document.getElementById('loginSection').style.display = 'block';
        document.getElementById('authOverlay').style.display = 'none';
        appInit();
    } else {
        errDiv.innerText = i18n[currentLang].alertPassChangeErr;
        errDiv.style.display = 'block';
    }
});

async function logout() {
    // Cancella il cookie di sessione lato server (best-effort).
    try {
        await fetch('/api/auth/logout', { method: 'POST',
            headers: { 'X-Requested-With': 'SentinelNet' } });
    } catch (e) { /* sessione già scaduta: ignora */ }
    currentRole = 'viewer';
    currentUsername = '';
    document.body.classList.remove('role-admin','role-operator','role-viewer');
    checkAuthRequirements();
}

// --- RUOLI / PRIVILEGI ---

function roleLabel(role) {
    if (role === 'admin')    return currentLang === 'en' ? 'Administrator' : 'Amministratore';
    if (role === 'operator') return currentLang === 'en' ? 'Operator' : 'Operatore';
    return currentLang === 'en' ? 'Viewer' : 'Visualizzatore';
}

function applyRoleUI(username, role, allowedTabs) {
    currentUsername = username || '';
    currentRole = role || 'viewer';
    document.body.classList.remove('role-admin','role-operator','role-viewer');
    document.body.classList.add('role-' + currentRole);
    const badge = document.getElementById('userBadgeLabel');
    if (badge) {
        const icon = currentRole === 'admin' ? 'fa-user-shield'
                   : currentRole === 'operator' ? 'fa-user-gear' : 'fa-user';
        badge.innerHTML = `<i class="fa-solid ${icon}"></i> ${escapeHtml(currentUsername)} · ` +
            `<span class="role-pill role-pill-${currentRole}">${roleLabel(currentRole)}</span>`;
    }
    // ponytail: restrizione solo lato frontend (nasconde i pulsanti); vuoto = tutte le tab.
    if (Array.isArray(allowedTabs) && allowedTabs.length > 0) {
        document.querySelectorAll('.nav-item').forEach(btn => {
            const m = btn.getAttribute('onclick').match(/switchTab\('([^']+)'/);
            const tabId = m && m[1];
            if (tabId && !allowedTabs.includes(tabId)) btn.style.display = 'none';
        });
    }
}

// Invio rapido con tasto Enter su login, setup wizard e creazione gruppo
function bindEnterKey(inputIds, buttonId) {
    inputIds.forEach(id => {
        document.getElementById(id).addEventListener('keydown', e => {
            if (e.key === 'Enter') document.getElementById(buttonId).click();
        });
    });
}
bindEnterKey(['loginUser', 'loginPass'], 'btnLogin');
bindEnterKey(['wizUser', 'wizPass'], 'btnRegisterAdmin');
bindEnterKey(['newGroupName'], 'btnCreateGroup');
bindEnterKey(['scanNetworkInput'], 'btnAvviaScan');

// Chiusura modali: click sullo sfondo oppure tasto Escape.
// Il modale CLI non si chiude con Escape: il tasto serve dentro al terminale SSH.
document.getElementById('subnetScanModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeSubnetScanModal();
});
document.getElementById('cliModalOverlay').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeCliModal();
});
document.getElementById('triageScopeModal').addEventListener('click', e => {
    if (e.target === e.currentTarget) closeTriageScopeModal();
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && document.getElementById('triageScopeModal').style.display === 'flex') {
        closeTriageScopeModal();
    }
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' &&
        document.getElementById('subnetScanModal').style.display === 'flex') {
        closeSubnetScanModal();
    }
});

// --- INITIALIZATION ---

async function appInit() {
    appLoading = true;
    initLanguageSelector();
    const isAuth = await checkAuthRequirements();
    if (!isAuth) {
        appLoading = false;
        return;
    }

    // Determina ruolo/privilegi dell'utente corrente e adatta la UI
    try {
        const meRes = await apiFetch('/api/auth/me');
        if (meRes && meRes.ok) {
            const me = await meRes.json();
            currentRole = me.role || 'viewer';
            applyRoleUI(me.username, currentRole, me.allowed_tabs || []);
        }
    } catch (e) { /* non bloccante */ }

    // Gating tab MCP Client (preview): visibile solo ad admin col flag attivo.
    if (currentRole === 'admin' && typeof applyMcpClientGating === 'function') {
        try { await applyMcpClientGating(); } catch (e) { /* non bloccante */ }
    }

    // Gating tab FortiGate LIVE (preview): visibile solo ad admin col flag attivo.
    if (currentRole === 'admin' && typeof applyFgtPreviewGating === 'function') {
        try { await applyFgtPreviewGating(); } catch (e) { /* non bloccante */ }
    }

    try {
        const res = await apiFetch('/api/local-devices');
        if (!res) {
            appLoading = false;
            return;
        }
        const data = await res.json();

        globalDevices = data.devices;
        globalGroups = data.groups;
        globalVersions = data.detected_versions; // Cache globale delle versioni rilevate

        const vRes = await apiFetch('/api/vendors');
        if (vRes && vRes.ok) globalVendors = await vRes.json();

        // Popola tendine Vendor + tendina Gruppi del form di provisioning
        // (estratto in populateProvisioningFormSelects: riusato anche da loadProvisioningTab).
        populateProvisioningFormSelects();

        // Memorizza la selezione corrente del filtro se esiste
        const filterSelect = document.getElementById('filterGroupSelect');
        const prevFilter = filterSelect ? filterSelect.value : 'all';

        // Popola tendina Filtro Gruppi nella tabella dell'inventario
        if (filterSelect) {
            filterSelect.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
                Object.keys(globalGroups).map(g =>
                    `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            filterSelect.value = prevFilter;
            if (filterSelect.selectedIndex === -1) filterSelect.value = 'all';
        }

        // Popola tendina Filtro Gruppi in TAB 3
        const topoSelect = document.getElementById('topologyGroupSelect');
        if (topoSelect) {
            const prevTopoFilter = topoSelect.value || 'all';
            topoSelect.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
                Object.keys(globalGroups).map(g =>
                    `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            topoSelect.value = prevTopoFilter;
            if (topoSelect.selectedIndex === -1) topoSelect.value = 'all';
        }

        // Popola tendina Filtro Gruppi in TAB 4
        const interSelect = document.getElementById('interactiveGroupSelect');
        if (interSelect) {
            const prevInterFilter = interSelect.value || 'all';
            interSelect.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
                Object.keys(globalGroups).map(g =>
                    `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            interSelect.value = prevInterFilter;
            if (interSelect.selectedIndex === -1) interSelect.value = 'all';
        }

        // Popola Tabella Dispositivi tramite la nuova funzione autonoma filtrabile
        renderDeviceTable();

        // Popola la Home operativa (tab di default al login) coi globals appena caricati
        loadHome();

        // Popola Tabella Gestione Gruppi
        renderGroupsTable();

    // Forza il reload delle mappe se le tab sono attive
    const activeTabId = document.querySelector('.tab-content.active')?.id;
    if (activeTabId === 'tab-map') {
        await loadTopology();
    } else if (activeTabId === 'tab-map-interactive') {
        await loadInteractiveMap();
    } else if (activeTabId === 'tab-security') {
        loadThreatIntel();
    }

    startTriageStatusPolling();

    } catch (err) {
        console.error(err);
    } finally {
        appLoading = false;
    }
}

function switchTab(tabId, clickedBtn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    // Se chiamato senza pulsante (es. dopo import CSV) evidenzia comunque la tab corretta
    const btn = clickedBtn || document.querySelector(`.nav-item[onclick*="'${tabId}'"]`);
    if (btn) {
        btn.classList.add('active');
    }

    if (tabId === 'tab-home') {
        loadHome();
    } else if (tabId === 'tab-devices') {
        renderDeviceTable();
    } else if (tabId === 'tab-provisioning') {
        loadProvisioningTab();
    } else if(tabId === 'tab-map') loadTopology();
    else if(tabId === 'tab-map-interactive') loadInteractiveMap();
    else if(tabId === 'tab-categories') loadCategoriesData();
    else if(tabId === 'tab-security' && !appLoading) {
        loadThreatIntel();
    }
    else if(tabId === 'tab-mac') loadMacTracker();
    else if(tabId === 'tab-config') loadConfigAnalyzer();
    else if(tabId === 'tab-ai') loadAiTab();
    else if(tabId === 'tab-users') loadUsers();
    else if(tabId === 'tab-sites') loadSites();
    else if(tabId === 'tab-mcp') loadMcpTab();
    else if(tabId === 'tab-mcp-client') loadMcpClientTab();
    else if(tabId === 'tab-fortigate-preview') loadFgtPreviewTab();
    else if(tabId === 'tab-settings') loadAppSettings();
}

// --- FLUSSI LIVE (fase 5): top talker + anomalie correlate -------------
// Toast minimale non bloccante (il resto della dashboard usa alert()).
function showToast(msg, kind) {
    const el = document.createElement('div');
    el.textContent = msg;
    el.style.cssText = 'position:fixed; bottom:24px; right:24px; z-index:9999;'
        + 'padding:10px 16px; border-radius:10px; font-size:13px; color:#fff;'
        + 'box-shadow:0 4px 16px rgba(0,0,0,0.35); background:'
        + (kind === 'error' ? '#c0392b' : kind === 'warning' ? '#b9770e' : '#2c3e50') + ';';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 4000);
}

// --- Shared across tabs (promoted from templates/dashboard.html during
// static/js/provisioning.js extraction): renderVendorTable/buildVendorOptions
// are used by the Provisioning tab (populateProvisioningFormSelects) AND by
// the still-inline Groups tab (loadVendors) AND by changeLanguage() in
// static/js/i18n.js. refreshIdentityOptions/renderIdentitiesPanel are used by
// the Provisioning tab AND by the still-inline Devices tab's editDevice() AND
// by the still-inline Groups tab's btnCreateGroup handler. ---

function buildVendorOptions(selected) {
    const builtins = ["cisco","hpe"];
    const all = [...new Set([...builtins, ...Object.keys(globalVendors)])];
    return all.map(v =>
        `<option value="${escapeHtml(v)}" ${v===selected?"selected":""}>${escapeHtml(v.toUpperCase())}</option>`
    ).join("");
}

function renderVendorTable() {
    const body = document.getElementById('vendorTableBody');
    if (!body) return;
    body.innerHTML = '';
    Object.entries(globalVendors).forEach(([name, meta]) => {
        const isSystem = name === 'cisco' || name === 'hpe';
        const systemText = currentLang === 'en' ? 'System' : 'Sistema';
        const deleteText = currentLang === 'en' ? 'Delete' : 'Elimina';
        body.innerHTML += `<tr>
            <td><strong>${escapeHtml(name)}</strong></td>
            <td><span style="font-family:var(--font-code); font-size:12px; color:var(--primary);">${escapeHtml(meta.euvd_term) || '—'}</span></td>
            <td><span style="font-family:var(--font-code); font-size:12px; color:var(--text-muted);">${escapeHtml(meta.driver) || '—'}</span></td>
            <td>${currentRole === 'viewer'
                ? '<span style="color:var(--text-muted); font-size:12px;">—</span>'
                : (isSystem
                    ? `<span style="color:var(--text-muted); font-size:12px;">${systemText}</span>`
                    : `<button onclick="deleteVendor(this.dataset.v)" data-v="${escapeHtml(name)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${deleteText}</button>`)
            }</td>
        </tr>`;
    });
}

// Carica le identita' del tenant selezionato nella select devProfile,
// preservando default/custom. Chiamata al load della tab e al cambio tenant.
async function refreshIdentityOptions(preserve) {
    const tenant = document.getElementById('devGroupSelect').value;
    const sel = document.getElementById('devProfile');
    const keep = preserve || sel.value;
    const res = await apiFetch('/api/identities?tenant=' + encodeURIComponent(tenant));
    const idents = res && res.ok ? (await res.json()).identities : [];
    sel.innerHTML = `<option value="default">${i18n[currentLang].optProfileDefault.replace(/<[^>]*>/g,'')}</option>` +
        idents.map(i => `<option value="identity:${i.id}">${escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('') +
        `<option value="custom">${i18n[currentLang].optProfileCustom.replace(/<[^>]*>/g,'')}</option>`;
    sel.value = Array.from(sel.options).some(o => o.value === keep) ? keep : 'default';
    document.getElementById('customCredsForm').style.display = sel.value === 'custom' ? 'block' : 'none';
    window._tenantIdentities = idents;
}

function renderIdentitiesPanel() {
    const body = document.getElementById('identitiesTableBody');
    const idents = window._tenantIdentities || [];
    body.innerHTML = idents.length ? idents.map(i => `<tr>
        <td>${escapeHtml(i.name)}</td>
        <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(i.username)}</td>
        <td>${i.devices_using}</td>
        <td>
          <button class="btn-icon" onclick="editIdentity('${i.id}')" title="Edit"><i class="fa-solid fa-pen"></i></button>
          <button class="btn-icon danger" onclick="deleteIdentity('${i.id}')" title="Delete"><i class="fa-solid fa-trash-can"></i></button>
        </td></tr>`).join('')
      : `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px; font-size:13px;">${i18n[currentLang].emptyIdentities}</td></tr>`;
}

// ===== Port Config Modal (promosso da static/js/topology.js: usato anche
// dal tab MAC-tracker/ARP inline e da static/js/config-analyzer.js) =====
    // Espande le abbreviazioni comuni delle interfacce ('Gi1/0/5' -> 'GigabitEthernet1/0/5').
    // Speculare a expand_iface() di mac_collector.py: tenerli allineati.
    function expandIface(name) {
        if (!name) return '';
        name = String(name).trim();
        const abbr = [
            [/^Gi(?=\d)/, 'GigabitEthernet'], [/^Te(?=\d)/, 'TenGigabitEthernet'],
            [/^Fo(?=\d)/, 'FortyGigE'], [/^Twe(?=\d)/, 'TwentyFiveGigE'],
            [/^Hu(?=\d)/, 'HundredGigE'], [/^Fa(?=\d)/, 'FastEthernet'],
            [/^Eth(?=\d)/, 'Ethernet'], [/^Et(?=\d)/, 'Ethernet'], [/^Po(?=\d)/, 'Port-channel'],
        ];
        for (const [pat, full] of abbr) {
            if (pat.test(name)) return name.replace(pat, full);
        }
        return name;
    }

    // Deep-link verso il Config Analyzer (impostati da showPortConfig, letti da renderCaResults).
    let caFocusIp = null;
    let caFocusPort = null;

    function closePortConfigModal() {
        const m = document.getElementById('portConfigModal');
        if (m) m.remove();
    }

    async function showPortConfig(switchIp, port, switchName) {
        const L = i18n[currentLang];
        let iface = null;
        try {
            const res = await apiFetch('/api/config-analyzer/' + encodeURIComponent(switchIp));
            if (res && res.ok) {
                const d = await res.json();
                const want = expandIface(port).toLowerCase();
                iface = (d.interfaces || []).find(i => expandIface(i.name).toLowerCase() === want) || null;
            }
        } catch (e) { /* trattato come non trovato */ }

        closePortConfigModal();
        const body = iface
            ? `<pre style="font-family:var(--font-code); background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:12px; margin:0; white-space:pre-wrap; font-size:12px;">${escapeHtml(iface.raw || '—')}</pre>`
            : `<div style="font-size:13px; color:var(--text-muted); padding:10px 0;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.portConfigNotFound)}</div>`;
        const ov = document.createElement('div');
        ov.id = 'portConfigModal';
        ov.style.cssText = 'position:fixed; inset:0; z-index:10050; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(4px);';
        ov.innerHTML = `
            <div style="background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:22px; width:min(560px,94vw); max-height:86vh; overflow:auto; box-shadow:0 20px 60px rgba(0,0,0,0.6);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <h3 style="font-size:16px;"><i class="fa-solid fa-ethernet" style="color:var(--primary);"></i> ${escapeHtml(L.portConfigTitle)}</h3>
                    <i class="fa-solid fa-xmark" onclick="closePortConfigModal()" style="cursor:pointer; color:var(--text-muted); font-size:18px;"></i>
                </div>
                <div style="font-family:var(--font-code); font-size:13px; color:var(--primary); margin-bottom:16px;">${escapeHtml(switchName || switchIp)} — ${escapeHtml(port)}</div>
                ${body}
                <div style="display:flex; justify-content:flex-end; align-items:center; gap:10px; margin-top:16px;">
                    <button onclick="openPortInAnalyzer('${escapeHtml(switchIp)}','${escapeHtml(port)}')" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-up-right-from-square"></i> ${escapeHtml(L.openInAnalyzer)}</button>
                    <button onclick="closePortConfigModal()" class="btn btn-secondary btn-small" style="width:auto; margin:0;">${currentLang==='en'?'Close':'Chiudi'}</button>
                </div>
            </div>`;
        ov.addEventListener('click', e => { if (e.target === ov) closePortConfigModal(); });
        document.body.appendChild(ov);
    }

    function openPortInAnalyzer(switchIp, port) {
        caFocusIp = switchIp;
        caFocusPort = port;
        closePortConfigModal();
        switchTab('tab-config');
    }
