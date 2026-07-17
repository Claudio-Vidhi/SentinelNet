    // ===== Settings tab (Users, Sites, MCP Server, App/Network/CLI Settings) =====

    // --- SEDI MULTI-SITO (admin) ---
    async function loadSites() {
        if (currentRole !== 'admin') return;
        const res = await apiFetch('/api/sites');
        if (!res || !res.ok) return;
        const data = await res.json();
        renderSitesTable(data.sites || []);
    }

    function renderSitesTable(sites) {
        const body = document.getElementById('sitesTableBody');
        if (!body) return;
        const L = i18n[currentLang];
        body.innerHTML = sites.map(s => {
            const isCentral = s.id === 'central';
            const modeBadge = s.mode === 'agent'
                ? '<span class="chip">SITE AGENT</span>'
                : '<span class="status ok"><span class="led led-success"></span>CENTRAL POLL</span>';
            const last = s.last_seen ? new Date(s.last_seen * 1000).toLocaleString() : '—';
            const subnets = (s.subnets || []).map(escapeHtml).join(', ') || '—';
            let actions = '';
            if (s.mode === 'agent') {
                actions += `<button data-s="${escapeHtml(s.id)}" onclick="regenSiteToken(this.dataset.s)" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-key"></i> ${L.btnRegenSiteToken}</button>`;
            }
            if (!isCentral) {
                actions += `<button data-s="${escapeHtml(s.id)}" onclick="deleteSite(this.dataset.s)" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${L.btnDeleteSite}</button>`;
            } else {
                actions = `<span class="chip">${L.lblSiteDefault}</span>`;
            }
            return `<tr>
                <td><strong>${escapeHtml(s.id)}</strong></td>
                <td>${escapeHtml(s.name)}</td>
                <td>${modeBadge}</td>
                <td style="font-size:12px;">${subnets}</td>
                <td style="font-size:12px; color:var(--text-muted);">${last}</td>
                <td style="white-space:nowrap;">${actions}</td>
            </tr>`;
        }).join('');
    }

    async function createSite() {
        const name = document.getElementById('newSiteName').value.trim();
        const mode = document.getElementById('newSiteMode').value;
        const subnets = document.getElementById('newSiteSubnets').value
            .split(',').map(x => x.trim()).filter(Boolean);
        if (!name) { alert(currentLang==='en' ? 'Site name required.' : 'Nome sede obbligatorio.'); return; }
        const res = await apiFetch('/api/sites', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, mode, subnets })
        });
        if (res && res.ok) {
            const data = await res.json();
            document.getElementById('newSiteName').value = '';
            document.getElementById('newSiteSubnets').value = '';
            if (data.token) {
                prompt(currentLang==='en' ? 'Site token (shown ONLY ONCE — copy it now and configure it in the agent):' : 'Token della sede (mostrato UNA SOLA VOLTA — copialo ora e configuralo nell\'agente):', data.token);
            }
            loadSites();
        } else if (res) {
            const e = await res.json(); alert((currentLang==='en' ? 'Error: ' : 'Errore: ') + (e.detail || ''));
        }
    }

    async function regenSiteToken(id) {
        if (!confirm(currentLang==='en' ? `Regenerate the token for site "${id}"? The old token will stop working.` : `Rigenerare il token della sede "${id}"? Il vecchio token smetterà di funzionare.`)) return;
        const res = await apiFetch('/api/sites/regenerate-token', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (res && res.ok) {
            const data = await res.json();
            prompt(currentLang==='en' ? 'New token (shown ONLY ONCE):' : 'Nuovo token (mostrato UNA SOLA VOLTA):', data.token);
            loadSites();
        } else if (res) { const e = await res.json(); alert((currentLang==='en' ? 'Error: ' : 'Errore: ') + (e.detail || '')); }
    }

    async function deleteSite(id) {
        if (!confirm(currentLang==='en' ? `Delete site "${id}"?` : `Eliminare la sede "${id}"?`)) return;
        const res = await apiFetch('/api/sites/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (res && res.ok) loadSites();
        else if (res) { const e = await res.json(); alert((currentLang==='en' ? 'Error: ' : 'Errore: ') + (e.detail || '')); }
    }

    // --- TAB MCP SERVER (guida + selezione tool esposti ai client LLM) ---

    function mcpConfigSnippetText() {
        return JSON.stringify({
            mcpServers: {
                sentinelnet: {
                    command: "python",
                    args: ["/percorso/SentinelNet/mcp_server.py"],
                    env: {
                        SENTINELNET_URL: window.location.origin,
                        SENTINELNET_USERNAME: "<utente-dedicato>",
                        SENTINELNET_PASSWORD: "<password>"
                    }
                }
            }
        }, null, 2);
    }

    async function loadMcpTab() {
        const pre = document.getElementById('mcpConfigSnippet');
        if (pre) pre.textContent = mcpConfigSnippetText();
        const list = document.getElementById('mcpToolList');
        if (!list) return;
        const res = await apiFetch('/api/mcp/settings');
        if (!res || !res.ok) { list.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">Impossibile caricare le impostazioni MCP.</span>'; return; }
        const data = await res.json();
        const disabled = new Set(data.disabled_tools || []);
        const L = i18n[currentLang];
        list.innerHTML = (data.tools || []).map(t => {
            const isEnabled = !disabled.has(t.name);
            const stKey = isEnabled ? 'mcpStEnabled' : 'mcpStDisabled';
            return `
            <label style="display:flex; align-items:flex-start; gap:8px; font-size:13px; padding:8px 10px; border:1px solid var(--border); border-radius:8px; background:var(--surface); cursor:pointer;">
              <input type="checkbox" class="mcp-tool-toggle" value="${escapeHtml(t.name)}" ${isEnabled ? 'checked' : ''} style="margin-top:2px;">
              <span style="flex:1;">
                <span style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                  <code style="font-size:12px;">${escapeHtml(t.name)}</code>
                  <span class="status ${isEnabled ? 'ok' : 'bad'}"><span class="led ${isEnabled ? 'led-success' : 'led-danger'}"></span><span data-i18n="${stKey}">${escapeHtml(L[stKey])}</span></span>
                </span>
                <span style="color:var(--text-muted); font-size:11px;">${escapeHtml(t.description || '')}</span>
              </span>
            </label>`;
        }).join('');
    }

    async function saveMcpSettings() {
        const statusEl = document.getElementById('mcpSettingsStatus');
        const disabled = [...document.querySelectorAll('.mcp-tool-toggle')]
            .filter(cb => !cb.checked).map(cb => cb.value);
        const res = await apiFetch('/api/mcp/settings', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ disabled_tools: disabled })
        });
        if (res && res.ok) {
            if (statusEl) statusEl.textContent = 'Impostazioni salvate.';
        } else {
            const e = res ? await res.json().catch(() => ({})) : {};
            if (statusEl) statusEl.textContent = 'Errore: ' + (e.detail || 'salvataggio fallito.');
        }
    }

    function copyMcpConfig() {
        navigator.clipboard.writeText(mcpConfigSnippetText());
    }

    // --- GESTIONE UTENTI (solo admin) ---

    // Tab assegnabili ai ruoli non-admin (le tab requires-admin restano sempre escluse).
    const ASSIGNABLE_TABS = [
        { id: 'tab-devices', key: 'tabInventory' },
        { id: 'tab-groups', key: 'tabGroups' },
        { id: 'tab-map', key: 'tabMap' },
        { id: 'tab-map-interactive', key: 'tabInteractive' },
        { id: 'tab-categories', key: 'tabCategories' },
        { id: 'tab-security', key: 'tabSecurity' },
        { id: 'tab-mac', key: 'tabMacTracker' },
        { id: 'tab-flows', key: 'tabFlows' },
        { id: 'tab-config', key: 'tabConfigAnalyzer' },
        { id: 'tab-ai', key: 'tabAiAssistant' },
        { id: 'tab-provisioning', key: 'tabProvisioning' },
        { id: 'tab-provisioner', key: 'tabProvisioner' },
        { id: 'tab-import', key: 'tabImport' },
    ];

    async function loadUsers() {
        if (currentRole !== 'admin') return;
        const res = await apiFetch('/api/users');
        if (!res || !res.ok) return;
        renderUsersTable(await res.json());
    }

    function renderUsersTable(users) {
        const body = document.getElementById('usersTableBody');
        if (!body) return;
        const delText = currentLang === 'en' ? 'Delete' : 'Elimina';
        const allGroups = Object.keys(globalGroups);
        body.innerHTML = users.map(u => {
            const roleOptions = ['viewer', 'operator', 'admin'].map(r =>
                `<option value="${r}" ${r === u.role ? 'selected' : ''}>${roleLabel(r)}</option>`).join('');
            const isSelf = u.username === currentUsername;
            const scope = Array.isArray(u.groups) ? u.groups : [];

            // Editor sedi: gli admin vedono tutto; per gli altri checkbox per sede (nessuna = tutte)
            let scopeCell;
            if (u.role === 'admin') {
                scopeCell = `<span style="color:var(--text-muted); font-size:12px;">${currentLang === 'en' ? 'All tenants (admin)' : 'Tutti i tenant (admin)'}</span>`;
            } else {
                const summary = scope.length === 0
                    ? `<span style="color:var(--success);">${currentLang === 'en' ? 'All tenants' : 'Tutti i tenant'}</span>`
                    : `<span style="color:var(--primary);">${scope.map(escapeHtml).join(', ')}</span>`;
                const checks = allGroups.map(g =>
                    `<label style="display:flex; align-items:center; gap:6px; padding:3px 4px; font-size:12px; cursor:pointer;">
                       <input type="checkbox" class="scope-box" value="${escapeHtml(g)}" ${scope.includes(g) ? 'checked' : ''}
                              onchange="saveUserGroups(this.closest('details').dataset.u)"
                              style="accent-color:var(--primary); cursor:pointer;">
                       ${escapeHtml(g)}
                     </label>`).join('');
                scopeCell = `<details data-u="${escapeHtml(u.username)}" style="position:relative;">
                    <summary style="cursor:pointer; list-style:none; font-size:12px; padding:2px 0;">
                      <i class="fa-solid fa-location-dot" style="color:var(--text-muted); margin-right:4px;"></i>${summary}
                    </summary>
                    <div style="margin-top:6px; padding:6px; border:1px solid var(--border); border-radius:8px; background:var(--surface-3); max-height:160px; overflow:auto;">
                      <div style="font-size:10px; color:var(--text-muted); margin-bottom:4px;">${currentLang === 'en' ? 'None checked = all tenants' : 'Nessuno spuntato = tutti i tenant'}</div>
                      ${checks || `<span style="color:var(--text-muted); font-size:12px;">${currentLang === 'en' ? 'No tenants' : 'Nessun tenant'}</span>`}
                    </div>
                  </details>`;
            }

            // Editor tab: gli admin vedono sempre tutto; per gli altri checkbox per tab
            // (nessuna spuntata = tutte), con salvataggio esplicito (staged, no auto-save).
            let tabsCell;
            if (u.role === 'admin') {
                tabsCell = `<span style="color:var(--text-muted); font-size:12px;">${currentLang === 'en' ? 'All tabs (admin)' : 'Tutte le tab (admin)'}</span>`;
            } else {
                const allowed = Array.isArray(u.allowed_tabs) ? u.allowed_tabs : [];
                const tabsSummary = allowed.length === 0
                    ? `<span style="color:var(--success);">${currentLang === 'en' ? 'All tabs' : 'Tutte le tab'}</span>`
                    : `<span style="color:var(--primary);">${allowed.length} ${currentLang === 'en' ? 'tab(s)' : 'tab'}</span>`;
                const tabChecks = ASSIGNABLE_TABS.map(t =>
                    `<label style="display:flex; align-items:center; gap:6px; padding:3px 4px; font-size:12px; cursor:pointer;">
                       <input type="checkbox" class="tabs-box" value="${t.id}" ${allowed.includes(t.id) ? 'checked' : ''}
                              onchange="markTabsDirty(this)"
                              style="accent-color:var(--primary); cursor:pointer;">
                       ${i18n[currentLang][t.key] || t.id}
                     </label>`).join('');
                tabsCell = `<details data-u="${escapeHtml(u.username)}" data-orig='${JSON.stringify(allowed)}' style="position:relative;">
                    <summary style="cursor:pointer; list-style:none; font-size:12px; padding:2px 0;">
                      <i class="fa-solid fa-table-columns" style="color:var(--text-muted); margin-right:4px;"></i>${tabsSummary}
                    </summary>
                    <div style="margin-top:6px; padding:6px; border:1px solid var(--border); border-radius:8px; background:var(--surface-3); max-height:200px; overflow:auto;">
                      <div style="font-size:10px; color:var(--text-muted); margin-bottom:4px;">${currentLang === 'en' ? 'None checked = all tabs' : 'Nessuna spuntata = tutte le tab'}</div>
                      ${tabChecks}
                      <div style="margin-top:8px; display:flex; align-items:center; gap:8px;">
                        <button type="button" class="btn btn-primary btn-small tabs-save-btn" style="display:none; width:auto; margin:0; padding:4px 10px; font-size:12px;" onclick="saveUserTabs(this)">
                          <i class="fa-solid fa-floppy-disk"></i> ${currentLang === 'en' ? 'Save' : 'Salva'}
                        </button>
                        <span class="tabs-dirty-label" style="display:none; color:var(--warning); font-size:11px;">${currentLang === 'en' ? 'Unsaved changes' : 'Modifiche non salvate'}</span>
                      </div>
                    </div>
                  </details>`;
            }

            const disabled = !!u.disabled;
            const disabledBadge = disabled
                ? ` <span class="role-pill" style="background:rgba(255,107,124,0.15); color:var(--danger); border:1px solid rgba(255,107,124,0.35);">${currentLang === 'en' ? 'DISABLED' : 'DISABILITATO'}</span>`
                : '';
            const toggleText = disabled
                ? (currentLang === 'en' ? 'Enable' : 'Abilita')
                : (currentLang === 'en' ? 'Disable' : 'Disabilita');
            const toggleIcon = disabled ? 'fa-circle-check' : 'fa-ban';
            const toggleColor = disabled ? 'var(--success)' : 'var(--warning)';
            const toggleBtn = isSelf ? '' :
                `<button data-u="${escapeHtml(u.username)}" data-d="${disabled ? '1' : '0'}"
                    onclick="toggleUserDisabled(this.dataset.u, this.dataset.d === '1')"
                    style="color:${toggleColor}; background:none; border:none; cursor:pointer; margin-right:10px;">
                    <i class="fa-solid ${toggleIcon}"></i> ${toggleText}</button>`;

            return `<tr style="${disabled ? 'opacity:0.55;' : ''}">
                <td><strong>${escapeHtml(u.username)}</strong>${isSelf ? ` <span style="color:var(--text-muted); font-size:11px;">(${currentLang === 'en' ? 'you' : 'tu'})</span>` : ''}${disabledBadge}</td>
                <td><select data-u="${escapeHtml(u.username)}" onchange="changeUserRole(this.dataset.u, this.value)"
                       style="font-size:12px; padding:4px 8px; border-radius:6px; border:1px solid var(--border); background:var(--surface-3); color:var(--text); cursor:pointer; outline:none;">
                    ${roleOptions}
                  </select></td>
                <td>${scopeCell}</td>
                <td>${tabsCell}</td>
                <td style="white-space:nowrap;">${toggleBtn}${isSelf
                    ? '<span style="color:var(--text-muted); font-size:12px;">—</span>'
                    : `<button data-u="${escapeHtml(u.username)}" onclick="deleteUser(this.dataset.u)" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${delText}</button>`}</td>
            </tr>`;
        }).join('');
    }

    async function saveUserGroups(username) {
        const details = document.querySelector(`#usersTableBody details[data-u="${CSS.escape(username)}"]`);
        if (!details) return;
        const groups = [...details.querySelectorAll('.scope-box:checked')].map(cb => cb.value);
        const res = await apiFetch('/api/users/groups', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, groups })
        });
        if (res && res.ok) {
            loadUsers();   // aggiorna il riepilogo
        } else if (res) {
            const e = await res.json();
            alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || ''));
        }
    }

    // Staged: il toggle di una checkbox non chiama l'API, mostra solo il pulsante Salva
    // se lo stato differisce da quello originale caricato dal server.
    function markTabsDirty(checkboxEl) {
        const details = checkboxEl.closest('details');
        if (!details) return;
        const original = JSON.parse(details.dataset.orig || '[]').slice().sort();
        const current = [...details.querySelectorAll('.tabs-box:checked')].map(cb => cb.value).sort();
        const dirty = JSON.stringify(original) !== JSON.stringify(current);
        const btn = details.querySelector('.tabs-save-btn');
        const label = details.querySelector('.tabs-dirty-label');
        if (btn) btn.style.display = dirty ? 'inline-flex' : 'none';
        if (label) label.style.display = dirty ? 'inline' : 'none';
    }

    async function saveUserTabs(btnEl) {
        const details = btnEl.closest('details');
        if (!details) return;
        const username = details.dataset.u;
        const allowed_tabs = [...details.querySelectorAll('.tabs-box:checked')].map(cb => cb.value);
        const res = await apiFetch('/api/users/tabs', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, allowed_tabs })
        });
        if (res && res.ok) {
            loadUsers();
        } else if (res) {
            const e = await res.json();
            alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || ''));
        }
    }

    async function createUser() {
        const username = document.getElementById('newUserName').value.trim();
        const password = document.getElementById('newUserPass').value;
        const role     = document.getElementById('newUserRole').value;
        if (!username || !password) {
            alert(currentLang === 'en' ? 'Username and password are required.' : 'Username e password obbligatori.');
            return;
        }
        const res = await apiFetch('/api/users', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role })
        });
        if (res && res.ok) {
            document.getElementById('newUserName').value = '';
            document.getElementById('newUserPass').value = '';
            loadUsers();
        } else if (res) {
            const e = await res.json();
            alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || ''));
        }
    }

    async function deleteUser(username) {
        const msg = currentLang === 'en' ? `Delete user "${username}"?` : `Eliminare l'utente "${username}"?`;
        if (!confirm(msg)) return;
        const res = await apiFetch('/api/users/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        if (res && res.ok) loadUsers();
        else if (res) { const e = await res.json(); alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || '')); }
    }

    async function toggleUserDisabled(username, currentlyDisabled) {
        const res = await apiFetch('/api/users/disable', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, disabled: !currentlyDisabled })
        });
        if (res && res.ok) loadUsers();
        else if (res) { const e = await res.json(); alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || '')); }
    }

    async function changeUserRole(username, role) {
        const res = await apiFetch('/api/users/role', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, role })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + ((e && e.detail) || ''));
            loadUsers(); // ripristina la selezione corretta
        }
    }

    // --- IMPOSTAZIONI: esposizione in rete (solo admin) ---

    async function loadAppSettings() {
        if (currentRole !== 'admin') return;
        const box = document.getElementById('netSettingsBody');
        if (!box) return;
        const res = await apiFetch('/api/settings/network');
        if (!res || !res.ok) { box.innerHTML = ''; return; }
        const d = await res.json();
        renderAppSettings(d);
        loadCliBlacklistSetting();
        loadObsSettings();
        loadAppAdvSettings();
    }

    // --- IMPOSTAZIONI AVANZATE (sezione 'app', solo admin) ---

    // 'grp' raggruppa i campi per ambito dentro la card generale (solo
    // presentazione: il salvataggio resta un unico POST /api/settings/app).
    const APP_ADV_FIELDS = [
        { key: 'port',                  type: 'number', lbl: 'lblAppPort',      grp: 'appAdvGrpServer' },
        { key: 'ssl_certfile',          type: 'text',   lbl: 'lblAppSslCert',   grp: 'appAdvGrpServer' },
        { key: 'ssl_keyfile',           type: 'text',   lbl: 'lblAppSslKey',    grp: 'appAdvGrpServer' },
        { key: 'cors_origins',          type: 'text',   lbl: 'lblAppCors',      grp: 'appAdvGrpServer' },
        { key: 'retention_flows_days',  type: 'number', lbl: 'lblAppRetFlows',  grp: 'appAdvGrpRetention' },
        { key: 'retention_syslog_days', type: 'number', lbl: 'lblAppRetSyslog', grp: 'appAdvGrpRetention' },
        { key: 'retention_events_days', type: 'number', lbl: 'lblAppRetEvents', grp: 'appAdvGrpRetention' },
    ];

    async function loadAppAdvSettings() {
        if (currentRole !== 'admin') return;
        const box = document.getElementById('appAdvBody');
        if (!box) return;
        const res = await apiFetch('/api/settings/app');
        if (!res || !res.ok) { box.innerHTML = ''; return; }
        renderAppAdvSettings(await res.json());
    }

    function renderAppAdvSettings(d) {
        const box = document.getElementById('appAdvBody');
        if (!box) return;
        const L = i18n[currentLang];
        const s = d.settings || {}, env = d.env_overrides || {}, def = d.defaults || {};
        const subhead = (key, fallback) =>
            `<div style="margin-top:10px; margin-bottom:6px; font-size:12px; color:var(--text-muted); text-transform:uppercase; font-weight:700;" data-i18n="${key}">${escapeHtml(L[key] || fallback)}</div>`;
        let lastGrp = null;
        const rows = APP_ADV_FIELDS.map(f => {
            const over = env[f.key];
            const envNote = over ? `<span style="font-size:11px; color:var(--warning);"> ${escapeHtml(L.msgEnvOverride || 'Sovrascritto da variabile d\'ambiente')}</span>` : '';
            let hdr = '';
            if (f.grp !== lastGrp) { hdr = subhead(f.grp, f.grp); lastGrp = f.grp; }
            return `${hdr}
            <div class="form-group" style="max-width:420px;">
                <label data-i18n="${f.lbl}">${escapeHtml(L[f.lbl] || f.key)}</label>${envNote}
                <input id="appadv_${f.key}" type="${f.type}" ${f.type === 'number' ? 'min="1"' : ''} ${over ? 'disabled' : ''}
                       value="${s[f.key] != null ? escapeHtml(String(s[f.key])) : ''}"
                       placeholder="${def[f.key] != null ? def[f.key] : ''}" style="padding-left:12px;">
            </div>`;
        }).join('');
        box.innerHTML = `
            ${rows}
            ${subhead('appAdvGrpStartup', 'Avvio')}
            <label style="display:flex; align-items:center; gap:10px; cursor:pointer; margin-bottom:14px;">
                <input type="checkbox" id="appadv_no_browser" ${s.no_browser ? 'checked' : ''} ${env.no_browser ? 'disabled' : ''}>
                <span style="font-size:13px;" data-i18n="lblAppNoBrowser">${escapeHtml(L.lblAppNoBrowser || 'Non aprire il browser all\'avvio')}</span>
            </label>
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
                ${escapeHtml(L.lblAppDataDir || 'Cartella dati (solo env SENTINELNET_DATA_DIR)')}: <code>${escapeHtml(d.data_dir || '')}</code>
            </div>
            <button class="btn btn-primary btn-small" onclick="saveAppAdvSettings()">
                <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(L.btnSave || 'Salva')}
            </button>
            <div id="appAdvError" style="margin-top:10px; font-size:12px; color:var(--danger);"></div>`;
    }

    async function saveAppAdvSettings() {
        const errEl = document.getElementById('appAdvError');
        if (errEl) errEl.textContent = '';
        const payload = {};
        APP_ADV_FIELDS.forEach(f => {
            const el = document.getElementById(`appadv_${f.key}`);
            if (!el || el.disabled) return;
            payload[f.key] = el.value.trim() === '' ? null : el.value.trim();
        });
        const nb = document.getElementById('appadv_no_browser');
        if (nb && !nb.disabled) payload.no_browser = nb.checked;
        const res = await apiFetch('/api/settings/app', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            const msg = (e && e.detail) || (currentLang === 'en' ? 'Save error.' : 'Errore nel salvataggio.');
            if (errEl) errEl.textContent = msg; else alert(msg);
            return;
        }
        const banner = document.getElementById('appAdvRestartBanner');
        if (banner) banner.style.display = 'block';
        showToast(i18n[currentLang].msgObsRestartRequired || 'Riavvio richiesto per applicare le modifiche.', 'warning');
    }

    async function loadCliBlacklistSetting() {
        const cb = document.getElementById('cliBlacklistToggle');
        if (!cb) return;
        const res = await apiFetch('/api/settings/cli-blacklist');
        if (!res || !res.ok) return;
        const d = await res.json();
        cb.checked = !!d.cli_blacklist_operators;
    }

    async function saveCliBlacklistSetting() {
        const cb = document.getElementById('cliBlacklistToggle');
        const statusEl = document.getElementById('cliBlacklistStatus');
        const res = await apiFetch('/api/settings/cli-blacklist', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cli_blacklist_operators: cb.checked })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + ((e && e.detail) || ''));
            cb.checked = !cb.checked; // ripristina lo stato precedente
            return;
        }
        if (statusEl) statusEl.textContent = i18n[currentLang].msgCliBlacklistSaved;
    }

    function renderAppSettings(d) {
        const box = document.getElementById('netSettingsBody');
        if (!box) return;
        const L = i18n[currentLang];
        const localIps = d.local_ips || [];
        const options = ['0.0.0.0', '127.0.0.1', ...localIps.filter(ip => ip !== '0.0.0.0' && ip !== '127.0.0.1')];
        const current = d.configured_host || d.effective_host || '0.0.0.0';
        const optHtml = options.map(ip => {
            const hint = ip === '0.0.0.0' ? ` ${escapeHtml(L.optAllIfaces)}` : ip === '127.0.0.1' ? ` ${escapeHtml(L.optLocalOnly)}` : '';
            return `<option value="${escapeHtml(ip)}" ${ip === current ? 'selected' : ''}>${escapeHtml(ip)}${hint}</option>`;
        }).join('');
        const envNote = d.env_override
            ? `<div style="margin-top:10px; padding:8px 10px; border:1px solid var(--warning); border-radius:8px; color:var(--warning); font-size:12px;"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(L.msgEnvOverride)}</div>`
            : '';
        box.innerHTML = `
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                <span style="font-size:12px; color:var(--text-muted);">${escapeHtml(L.lblNetHost)}:</span>
                <span class="badge" style="font-size:11px; color:var(--primary); border:1px solid var(--primary); font-family:var(--font-code);">${escapeHtml(d.effective_host || '—')}</span>
                <span style="font-size:12px; color:var(--text-muted); margin-left:16px;">${escapeHtml(L.lblNetPort)}:</span>
                <span style="font-family:var(--font-code); font-size:12px;">${escapeHtml(d.port != null ? String(d.port) : '—')}</span>
            </div>
            <div class="form-group" style="max-width:360px;">
                <select id="netHostSelect" ${d.env_override ? 'disabled' : ''} style="padding-left:12px;">${optHtml}</select>
            </div>
            ${envNote}
            <div style="margin-top:12px;">
                <button class="btn btn-primary btn-small" onclick="saveAppSettings()" ${d.env_override ? 'disabled' : ''} data-i18n="btnSave">
                    <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(L.btnSave || (currentLang === 'en' ? 'Save' : 'Salva'))}
                </button>
            </div>
            <div id="netSettingsNotice" style="margin-top:10px; font-size:12px; color:var(--warning);"></div>`;
    }

    async function saveAppSettings() {
        const sel = document.getElementById('netHostSelect');
        if (!sel) return;
        const L = i18n[currentLang];
        const res = await apiFetch('/api/settings/network', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: sel.value })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + ((e && e.detail) || ''));
            return;
        }
        const notice = document.getElementById('netSettingsNotice');
        if (notice) notice.textContent = L.msgRestartRequired;
    }
