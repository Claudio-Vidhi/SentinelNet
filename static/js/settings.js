    // ===== Settings tab (Users, Sites, MCP Server, App/Network/CLI Settings) =====

    // --- SEDI MULTI-SITO (admin) ---
    async function loadSites() {
        if (currentRole !== 'admin') return;
        const res = await apiFetch('/api/sites');
        if (!res || !res.ok) return;
        const data = await res.json();
        await renderSitesTable(data.sites || []);
    }

    async function renderSitesTable(sites) {
        const body = document.getElementById('sitesTableBody');
        if (!body) return;
        const L = i18n[currentLang];
        // A jump row carries its device-default identity inline: the bastion
        // login and the login used on the devices behind it are two different
        // credentials, and there is no other screen to change the second one.
        const identities = sites.some(s => s.mode === 'jump') ? await getIdentities() : [];
        body.innerHTML = sites.map(s => {
            const isCentral = s.id === 'central';
            const modeBadge = s.mode === 'agent'
                ? '<span class="chip">SITE AGENT</span>'
                : s.mode === 'jump'
                ? '<span class="chip">JUMP (BASTION)</span>'
                : '<span class="status ok"><span class="led led-success"></span>CENTRAL POLL</span>';
            const last = s.last_seen ? new Date(s.last_seen * 1000).toLocaleString() : '—';
            const subnets = (s.subnets || []).map(escapeHtml).join(', ') || '—';
            // Solo una sede con agente puo' essere offline: il central poll non
            // ha un processo remoto che riporta heartbeat. Soglia legata
            // all'intervallo configurato dell'agente, non fissa: con un
            // intervallo lungo un agente sano risulterebbe sempre offline.
            let statusCell = '<span style="color:var(--text-muted);">—</span>';
            if (s.mode === 'agent') {
                const staleAfter = Math.max(120, (s.interval || 60) * 2);
                const online = s.last_seen && (Date.now() / 1000 - s.last_seen) < staleAfter;
                statusCell = online
                    ? `<span class="status ok"><span class="led led-success"></span>${L.lblAgentOnline}</span>`
                    : `<span class="status bad"><span class="led led-danger"></span>${L.lblAgentOffline}</span>`;
            }
            let actions = '';
            if (s.mode === 'agent') {
                actions += `<button data-action="open-agent-control" data-site-id="${escapeHtml(s.id)}" style="color:var(--warning); background:none; border:none; cursor:pointer; margin-right:10px;" title="Pannello di controllo ed aggiornamento agente remoti"><i class="fa-solid fa-gears"></i> Gestione Agente</button>`;
                actions += `<button data-action="regen-site-token" data-site-id="${escapeHtml(s.id)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-key"></i> ${L.btnRegenSiteToken}</button>`;
            }
            if (s.mode === 'jump') {
                // Two identities, two selects. One unlabelled dropdown next to
                // "Test bastion" read as the bastion credential while it set
                // the DEVICE one, so an operator could fix the login the test
                // does not use and see the same refusal again — with no way to
                // reach the bastion identity at all after site creation.
                actions += `<span style="font-size:10px; color:var(--text-muted); margin-right:3px;">${escapeHtml(L.lblIdentityBastionShort)}</span>`;
                // A select whose stored value matches no option silently
                // displays the FIRST one, which reads as "configured" while
                // the site still points at an identity that no longer exists.
                const jumpKnown = identities.some(i => i.id === s.jump_identity);
                const jumpMissing = jumpKnown ? '' : `<option value="" selected>${escapeHtml(L.optMissingIdentity)}</option>`;
                actions += `<select data-action="set-site-jump-identity" data-site-id="${escapeHtml(s.id)}" title="${escapeHtml(L.lblJumpIdentity)}" style="margin-right:10px; padding:2px 6px; font-size:12px;">${jumpMissing}${identityOptions(identities, s.jump_identity || '')}</select>`;
                actions += `<span style="font-size:10px; color:var(--text-muted); margin-right:3px;">${escapeHtml(L.lblIdentityDeviceShort)}</span>`;
                actions += `<select data-action="set-site-device-identity" data-site-id="${escapeHtml(s.id)}" title="${escapeHtml(L.lblDeviceIdentity)}" style="margin-right:10px; padding:2px 6px; font-size:12px;"><option value="">${escapeHtml(L.optNoDeviceIdentity)}</option>${identityOptions(identities, s.device_identity || '')}</select>`;
                actions += `<button data-action="test-bastion" data-site-id="${escapeHtml(s.id)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-plug-circle-check"></i> ${L.btnTestBastion}</button>`;
            }
            if (!isCentral) {
                actions += `<button data-action="delete-site" data-site-id="${escapeHtml(s.id)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${L.btnDeleteSite}</button>`;
            } else {
                actions = `<span class="chip">${L.lblSiteDefault}</span>`;
            }
            return `<tr>
                <td><strong>${escapeHtml(s.id)}</strong></td>
                <td>${escapeHtml(s.name)}</td>
                <td>${modeBadge}</td>
                <td>${statusCell}</td>
                <td style="font-size:12px;">${subnets}</td>
                <td style="font-size:12px; color:var(--text-muted);">${last}</td>
                <td style="white-space:nowrap;">${actions}</td>
            </tr>`;
        }).join('');
    }

    // Toggles the bastion fields + limitation notice for the 'jump' mode, and
    // (re)populates the identity select the first time it becomes visible.
    async function onNewSiteModeChange() {
        const mode = document.getElementById('newSiteMode').value;
        const isJump = mode === 'jump';
        const fields = document.getElementById('jumpFields');
        const limits = document.getElementById('jumpLimits');
        if (fields) fields.style.display = isJump ? 'grid' : 'none';
        if (limits) limits.style.display = isJump ? 'block' : 'none';
        if (isJump) await populateJumpIdentitySelect();
    }

    let identitiesCache = null;

    async function getIdentities() {
        if (identitiesCache) return identitiesCache;
        const res = await apiFetch('/api/identities');
        identitiesCache = (res && res.ok) ? (await res.json()).identities || [] : [];
        return identitiesCache;
    }

    function identityOptions(identities, selected) {
        return identities.map(i => `<option value="${escapeHtml(i.id)}"${
            i.id === selected ? ' selected' : ''}>${escapeHtml(i.name)} (${
            escapeHtml(i.username)})</option>`).join('');
    }

    async function populateJumpIdentitySelect() {
        const sel = document.getElementById('newSiteJumpIdentity');
        const dev = document.getElementById('newSiteDeviceIdentity');
        if (!sel || sel.dataset.loaded) return;
        const identities = await getIdentities();
        sel.innerHTML = identityOptions(identities, null);
        // The device default is optional: without it the devices behind the
        // bastion fall back to the global admin credentials.
        if (dev) {
            const L = i18n[currentLang];
            dev.innerHTML = `<option value="">${escapeHtml(L.optNoDeviceIdentity)}</option>`
                + identityOptions(identities, null);
        }
        sel.dataset.loaded = '1';
    }

    async function createSite() {
        const name = document.getElementById('newSiteName').value.trim();
        const mode = document.getElementById('newSiteMode').value;
        const subnets = document.getElementById('newSiteSubnets').value
            .split(',').map(x => x.trim()).filter(Boolean);
        if (!name) { alert(currentLang==='en' ? 'Site name required.' : 'Nome sede obbligatorio.'); return; }
        const payload = { name, mode, subnets };
        if (mode === 'jump') {
            payload.jump_host = document.getElementById('newSiteJumpHost').value.trim();
            payload.jump_port = parseInt(document.getElementById('newSiteJumpPort').value, 10) || 22;
            payload.jump_identity = document.getElementById('newSiteJumpIdentity').value;
            payload.device_identity = document.getElementById('newSiteDeviceIdentity').value;
        }
        const res = await apiFetch('/api/sites', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res && res.ok) {
            const data = await res.json();
            document.getElementById('newSiteName').value = '';
            document.getElementById('newSiteSubnets').value = '';
            if (mode === 'jump') {
                document.getElementById('newSiteJumpHost').value = '';
                document.getElementById('newSiteJumpPort').value = '22';
            }
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

    async function testBastion(id) {
        const L = i18n[currentLang];
        const res = await apiFetch('/api/sites/test-bastion', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (!res) return;
        const data = await res.json();
        if (!res.ok) { alert((L.lblError || 'Errore') + ': ' + (data.detail || '')); return; }
        if (data.status === 'success') alert(L.msgBastionOk);
        else if (data.status === 'auth_failed') alert(L.msgBastionAuthFailed + '\n\n' + (data.message || ''));
        else alert(L.msgBastionUnreachable + '\n\n' + (data.message || ''));
    }

    async function setSiteJumpIdentity(id, identityId) {
        // A jump site cannot exist without a bastion identity, so there is no
        // empty option to send.
        if (!identityId) { loadSites(); return; }
        const res = await apiFetch('/api/sites/update', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, jump_identity: identityId })
        });
        if (res && !res.ok) {
            const e = await res.json();
            alert((currentLang==='en' ? 'Error: ' : 'Errore: ') + (e.detail || ''));
        }
        loadSites();
    }

    async function setSiteDeviceIdentity(id, identityId) {
        const res = await apiFetch('/api/sites/update', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, device_identity: identityId })
        });
        if (res && !res.ok) {
            const e = await res.json();
            alert((currentLang==='en' ? 'Error: ' : 'Errore: ') + (e.detail || ''));
            loadSites();
        }
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
                    // Il modulo sta in ai/, non nella radice: lo snippet è
                    // fatto per essere incollato, quindi il percorso deve
                    // essere quello vero.
                    args: ["/percorso/SentinelNet/ai/mcp_server.py"],
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
            <label style="display:flex; align-items:flex-start; gap:8px; font-size:13px; padding:8px 10px; border:1px solid var(--border); border-radius:0; background:var(--surface); cursor:pointer;">
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
        { id: 'tab-endpoint', key: 'tabEndpointLoc' },
        { id: 'tab-flows', key: 'tabFlows' },
        { id: 'tab-config', key: 'tabConfigAnalyzer' },
        { id: 'tab-netsec-audit', key: 'tabNetSecAudit' },
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
                              data-action="save-user-groups" data-username="${escapeHtml(u.username)}"
                              style="accent-color:var(--primary); cursor:pointer;">
                       ${escapeHtml(g)}
                     </label>`).join('');
                scopeCell = `<details data-u="${escapeHtml(u.username)}" style="position:relative;">
                    <summary style="cursor:pointer; list-style:none; font-size:12px; padding:2px 0;">
                      <i class="fa-solid fa-location-dot" style="color:var(--text-muted); margin-right:4px;"></i>${summary}
                    </summary>
                    <div style="margin-top:6px; padding:6px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); max-height:160px; overflow:auto;">
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
                const allowed = normalizeAllowedTabs(u.allowed_tabs);
                const tabsSummary = allowed.length === 0
                    ? `<span style="color:var(--success);">${currentLang === 'en' ? 'All tabs' : 'Tutte le tab'}</span>`
                    : `<span style="color:var(--primary);">${allowed.length} ${currentLang === 'en' ? 'tab(s)' : 'tab'}</span>`;
                const tabChecks = ASSIGNABLE_TABS.map(t =>
                    `<label style="display:flex; align-items:center; gap:6px; padding:3px 4px; font-size:12px; cursor:pointer;">
                       <input type="checkbox" class="tabs-box" value="${t.id}" ${allowed.includes(t.id) ? 'checked' : ''}
                              data-action="mark-tabs-dirty"
                              style="accent-color:var(--primary); cursor:pointer;">
                       ${i18n[currentLang][t.key] || t.id}
                     </label>`).join('');
                tabsCell = `<details data-u="${escapeHtml(u.username)}" data-orig='${JSON.stringify(allowed)}' style="position:relative;">
                    <summary style="cursor:pointer; list-style:none; font-size:12px; padding:2px 0;">
                      <i class="fa-solid fa-table-columns" style="color:var(--text-muted); margin-right:4px;"></i>${tabsSummary}
                    </summary>
                    <div style="margin-top:6px; padding:6px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); max-height:200px; overflow:auto;">
                      <div style="font-size:10px; color:var(--text-muted); margin-bottom:4px;">${currentLang === 'en' ? 'None checked = all tabs' : 'Nessuna spuntata = tutte le tab'}</div>
                      ${tabChecks}
                      <div style="margin-top:8px; display:flex; align-items:center; gap:8px;">
                        <button type="button" class="btn btn-primary btn-small tabs-save-btn" data-action="save-user-tabs" style="display:none; width:auto; margin:0; padding:4px 10px; font-size:12px;">
                          <i class="fa-solid fa-floppy-disk"></i> ${currentLang === 'en' ? 'Save' : 'Salva'}
                        </button>
                        <span class="tabs-dirty-label" style="display:none; color:var(--warning); font-size:11px;">${currentLang === 'en' ? 'Unsaved changes' : 'Modifiche non salvate'}</span>
                      </div>
                    </div>
                  </details>`;
            }

            const disabled = !!u.disabled;
            const disabledBadge = disabled
                ? ` <span class="role-pill" style="background:color-mix(in srgb, var(--danger) 15%, transparent); color:var(--danger); border:1px solid color-mix(in srgb, var(--danger) 35%, transparent);">${currentLang === 'en' ? 'DISABLED' : 'DISABILITATO'}</span>`
                : '';
            const toggleText = disabled
                ? (currentLang === 'en' ? 'Enable' : 'Abilita')
                : (currentLang === 'en' ? 'Disable' : 'Disabilita');
            const toggleIcon = disabled ? 'fa-circle-check' : 'fa-ban';
            const toggleColor = disabled ? 'var(--success)' : 'var(--warning)';
            const toggleBtn = isSelf ? '' :
                `<button data-action="toggle-user-disabled" data-username="${escapeHtml(u.username)}" data-disabled="${disabled ? '1' : '0'}"
                    style="color:${toggleColor}; background:none; border:none; cursor:pointer; margin-right:10px;">
                    <i class="fa-solid ${toggleIcon}"></i> ${toggleText}</button>`;

            return `<tr style="${disabled ? 'opacity:0.55;' : ''}">
                <td><strong>${escapeHtml(u.username)}</strong>${isSelf ? ` <span style="color:var(--text-muted); font-size:11px;">(${currentLang === 'en' ? 'you' : 'tu'})</span>` : ''}${disabledBadge}</td>
                <td><select data-action="change-user-role" data-username="${escapeHtml(u.username)}"
                       style="font-size:12px; padding:4px 8px; border-radius:0; border:1px solid var(--border); background:var(--surface-3); color:var(--text); cursor:pointer; outline:none;">
                    ${roleOptions}
                  </select></td>
                <td>${scopeCell}</td>
                <td>${tabsCell}</td>
                <td style="white-space:nowrap;">${toggleBtn}<button data-action="delete-user" data-username="${escapeHtml(u.username)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${delText}</button></td>
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
        const isSelf = username === currentUsername;
        const msg = isSelf
            ? (currentLang === 'en'
                ? `Delete YOUR OWN account "${username}"? You will be signed out and cannot sign back in.`
                : `Eliminare il TUO account "${username}"? Verrai disconnesso e non potrai più accedere.`)
            : (currentLang === 'en' ? `Delete user "${username}"?` : `Eliminare l'utente "${username}"?`);
        if (!confirm(msg)) return;
        const res = await apiFetch('/api/users/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        // Cancellato il proprio account la sessione non vale più: si esce subito,
        // invece di lasciare che sia la prima chiamata a fallire con un 401.
        if (res && res.ok) { if (isSelf) logout(); else loadUsers(); }
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
        loadPingMonitorSettings();
        if (typeof loadObsSettings === 'function') {
            loadObsSettings();
        }
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
        { key: 'audit_history_days',   type: 'number', lbl: 'lblAppRetAuditHist', grp: 'appAdvGrpRetention' },
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
            <button id="btnSaveAppAdv" class="btn btn-primary btn-small">
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
            ? `<div style="margin-top:10px; padding:8px 10px; border:1px solid var(--warning); border-radius:0; color:var(--warning); font-size:12px;"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(L.msgEnvOverride)}</div>`
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
                <button id="btnSaveAppSettings" class="btn btn-primary btn-small" ${d.env_override ? 'disabled' : ''} data-i18n="btnSave">
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
        const notice = document.getElementById('netSettingsNotice');
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            if (notice) notice.textContent = (currentLang === 'en' ? 'Error: ' : 'Errore: ') + ((e && e.detail) || '');
            return;
        }
        if (notice) notice.textContent = L.msgRestartRequired;
    }

    // --- MONITOR PING CONTINUO (solo admin) ---

    async function loadPingMonitorSettings() {
        if (currentRole !== 'admin') return;
        const toggle = document.getElementById('pingMonitorToggle');
        const intervalEl = document.getElementById('pingMonitorInterval');
        if (!toggle || !intervalEl) return;
        const res = await apiFetch('/api/settings/ping-monitor');
        if (!res || !res.ok) return;
        const cfg = await res.json();
        toggle.checked = !!cfg.enabled;
        intervalEl.value = cfg.interval_seconds || 60;
        loadPingMonitorStatus();
    }

    async function savePingMonitorSettings() {
        const toggle = document.getElementById('pingMonitorToggle');
        const intervalEl = document.getElementById('pingMonitorInterval');
        const statusEl = document.getElementById('pingMonitorStatus');
        if (!toggle || !intervalEl) return;
        const L = i18n[currentLang];
        const interval = parseInt(intervalEl.value, 10);
        if (!Number.isFinite(interval) || interval < 5 || interval > 86400) {
            if (statusEl) statusEl.textContent = L.msgPingMonitorIntervalInvalid || 'Intervallo non valido (5–86400 secondi).';
            return;
        }
        const res = await apiFetch('/api/settings/ping-monitor', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: toggle.checked, interval_seconds: interval })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            if (statusEl) statusEl.textContent = (currentLang === 'en' ? 'Error: ' : 'Errore: ') + ((e && e.detail) || '');
            return;
        }
        if (statusEl) statusEl.textContent = L.msgPingMonitorSaved || 'Impostazioni monitor ping salvate.';
        loadPingMonitorStatus();
    }

    async function loadPingMonitorStatus() {
        const summaryEl = document.getElementById('pingMonitorSummary');
        const statusEl = document.getElementById('pingMonitorStatus');
        if (!summaryEl) return;
        const L = i18n[currentLang];
        const res = await apiFetch('/api/ping-monitor/status');
        if (!res || !res.ok) { summaryEl.innerHTML = ''; return; }
        const st = await res.json();
        const lastRun = st.last_run ? new Date(st.last_run * 1000).toLocaleString() : '—';
        if (statusEl) {
            statusEl.textContent = st.enabled
                ? `${L.lblPingMonitorLastRun || 'Ultimo ciclo'}: ${lastRun}`
                : (L.msgPingMonitorDisabled || 'Monitor ping disattivato.');
        }
        // Three buckets, not two: a jump-site device is never pinged (the
        // bastion tunnel carries no ICMP), so the backend reports it under
        // summary.unknown. Rendering only up/down made those devices vanish
        // from the panel with no explanation. Same vocabulary and lamp as the
        // inventory KPI row for the state (invKpiUnknownLabel / led-discovered).
        const s = st.summary || { total: 0, up: 0, down: 0, unknown: 0 };
        summaryEl.innerHTML = `
            <span class="chip">${escapeHtml(L.lblPingMonitorTotal || 'Dispositivi')}: ${s.total}</span>
            <span class="status ok"><span class="led led-success"></span>${escapeHtml(L.lblPingMonitorUp || 'Up')}: ${s.up}</span>
            <span class="status bad"><span class="led led-danger"></span>${escapeHtml(L.lblPingMonitorDown || 'Down')}: ${s.down}</span>
            <span class="status idle"><span class="led led-discovered"></span>${escapeHtml(L.invKpiUnknownLabel || 'Non misurabile')}: ${s.unknown || 0}</span>`;
    }

    // Delegated and static event listeners
    document.getElementById('uiVariantSelect')?.addEventListener('change', (e) => {
        if (typeof applyUiVariant === 'function') applyUiVariant(e.target.value, true);
    });

    document.getElementById('uiVariantCardsGrid')?.addEventListener('click', (e) => {
        const card = e.target.closest('[data-action="apply-ui-variant"]');
        if (card && card.dataset.variant && typeof applyUiVariant === 'function') {
            applyUiVariant(card.dataset.variant, true);
        }
    });

    document.getElementById('cliBlacklistToggle')?.addEventListener('change', saveCliBlacklistSetting);
    document.getElementById('btnSavePingMonitor')?.addEventListener('click', savePingMonitorSettings);

    document.getElementById('appAdvBody')?.addEventListener('click', (e) => {
        if (e.target.closest('#btnSaveAppAdv')) saveAppAdvSettings();
    });

    document.getElementById('netSettingsBody')?.addEventListener('click', (e) => {
        if (e.target.closest('#btnSaveAppSettings')) saveAppSettings();
    });

    document.getElementById('sitesTableBody')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn || !btn.dataset.siteId) return;
        const act = btn.dataset.action;
        const siteId = btn.dataset.siteId;
        if (act === 'open-agent-control' && typeof openAgentControlModal === 'function') openAgentControlModal(siteId);
        else if (act === 'regen-site-token') regenSiteToken(siteId);
        else if (act === 'delete-site') deleteSite(siteId);
        else if (act === 'test-bastion') testBastion(siteId);
    });

    document.getElementById('sitesTableBody')?.addEventListener('change', (e) => {
        const sel = e.target.closest('[data-action="set-site-device-identity"]');
        if (sel && sel.dataset.siteId) setSiteDeviceIdentity(sel.dataset.siteId, sel.value);
        const jump = e.target.closest('[data-action="set-site-jump-identity"]');
        if (jump && jump.dataset.siteId) setSiteJumpIdentity(jump.dataset.siteId, jump.value);
    });

    document.getElementById('usersTableBody')?.addEventListener('change', (e) => {
        const grp = e.target.closest('[data-action="save-user-groups"]');
        if (grp && grp.dataset.username) {
            saveUserGroups(grp.dataset.username);
            return;
        }
        const dirty = e.target.closest('[data-action="mark-tabs-dirty"]');
        if (dirty) {
            markTabsDirty(dirty);
            return;
        }
        const role = e.target.closest('[data-action="change-user-role"]');
        if (role && role.dataset.username) {
            changeUserRole(role.dataset.username, role.value);
            return;
        }
    });

    document.getElementById('usersTableBody')?.addEventListener('click', (e) => {
        const saveTabs = e.target.closest('[data-action="save-user-tabs"]');
        if (saveTabs) {
            saveUserTabs(saveTabs);
            return;
        }
        const toggleDis = e.target.closest('[data-action="toggle-user-disabled"]');
        if (toggleDis && toggleDis.dataset.username) {
            toggleUserDisabled(toggleDis.dataset.username, toggleDis.dataset.disabled === '1');
            return;
        }
        const delUser = e.target.closest('[data-action="delete-user"]');
        if (delUser && delUser.dataset.username) {
            deleteUser(delUser.dataset.username);
            return;
        }
    });

    document.getElementById('btnCreateUser')?.addEventListener('click', createUser);
    document.getElementById('btnCreateSite')?.addEventListener('click', createSite);
    document.getElementById('newSiteMode')?.addEventListener('change', onNewSiteModeChange);
    document.getElementById('btnCopyMcpConfig')?.addEventListener('click', copyMcpConfig);
    document.getElementById('btnSaveMcpSettings')?.addEventListener('click', saveMcpSettings);
    document.getElementById('mcpPreviewToggle')?.addEventListener('change', (e) => {
        if (typeof setMcpPreview === 'function') setMcpPreview(e.target.checked);
    });

