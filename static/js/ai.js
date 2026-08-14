    // ===== AI Assistant =====
    let aiHistory = [];  // {role, content} inviato al backend (senza system: aggiunto server-side)
    let aiProfilesCache = [];   // ultima lista di profili (mascherati) caricata dal server
    let aiActiveProfileId = ''; // id del profilo attivo lato server
    let aiConversations = [];   // elenco (senza messaggi) delle conversazioni salvate
    let aiConvId = null;        // id della conversazione aperta (null = non ancora salvata)
    let aiConvTitle = '';       // titolo della conversazione aperta

    // Popola la select dei dispositivi allegabili, filtrata per il tenant
    // selezionato: la config allegata deve appartenere al tenant scelto.
    function populateAiAttachDevices() {
        const box = document.getElementById('aiAttachDeviceList');
        if (!box) return;
        const tenant = document.getElementById('aiAttachTenant')?.value || '';
        // Multi-selezione: preserva gli IP già selezionati che restano visibili.
        const cur = new Set(getAiAttachDeviceIps());
        const devices = (globalDevices || []).filter(d =>
            !tenant || (d.Group || 'Generale') === tenant);
        box.innerHTML = devices.length ? devices.map(d =>
            `<label style="display:flex; align-items:center; gap:6px; cursor:pointer; padding:4px 8px;">
                <input type="checkbox" class="ai-attach-device" value="${escapeHtml(d.IP)}"${cur.has(d.IP) ? ' checked' : ''} style="accent-color:var(--primary);">
                <span>${escapeHtml(d.Hostname || d.IP)} (${escapeHtml(d.IP)})</span>
            </label>`
        ).join('') : `<span style="color:var(--text-muted); padding:4px 8px; display:block;">${i18n[currentLang].msgAiNoDevices || 'Nessun dispositivo'}</span>`;
        updateAiDeviceBtnLabel();
    }

    function getAiAttachDeviceIps() {
        return [...document.querySelectorAll('#aiAttachDeviceList .ai-attach-device:checked')]
            .map(cb => cb.value);
    }

    function setAllAiAttachDevices(checked) {
        document.querySelectorAll('#aiAttachDeviceList .ai-attach-device')
            .forEach(cb => { cb.checked = checked; });
        updateAiDeviceBtnLabel();
    }

    function updateAiDeviceBtnLabel() {
        const el = document.getElementById('aiAttachDeviceBtnLabel');
        if (!el) return;
        const L = i18n[currentLang];
        const n = getAiAttachDeviceIps().length;
        el.textContent = n > 0
            ? `${n} ${L.lblAiDevSelected || 'selezionati'}`
            : (L.lblAiAttachDevices || 'Dispositivi');
    }

    function toggleAiDeviceDropdown() {
        const dd = document.getElementById('aiAttachDeviceDropdown');
        if (dd) dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
    }

    document.addEventListener('click', function(e) {
        const dd = document.getElementById('aiAttachDeviceDropdown');
        const btn = document.getElementById('aiAttachDeviceBtn');
        if (dd && btn && !dd.contains(e.target) && !btn.contains(e.target)) {
            dd.style.display = 'none';
        }
    });

    function loadAiTab() {
        populateAiAttachDevices();
        // Popola la select dei tenant/sedi per allegare il contesto completo al chat
        const tenantSel = document.getElementById('aiAttachTenant');
        if (tenantSel) {
            const curTenant = tenantSel.value;
            const tenantOpts = Object.keys(globalGroups || {}).map(g =>
                `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`
            ).join('');
            tenantSel.innerHTML = `<option value="">${i18n[currentLang].optAiNoTenant}</option>` + tenantOpts;
            tenantSel.value = [...tenantSel.options].some(o => o.value === curTenant) ? curTenant : '';
            if (tenantSel.value !== curTenant) populateAiAttachDevices();
        }
        if (document.body.classList.contains('role-admin')) {
            loadAiProfiles();
        }
        loadAiConversations();
        populateGenCfgTenants();
    }

    // ===== Conversazioni salvate =====
    // La chat viveva solo in `aiHistory`: cambiare tab la buttava via. Ora ogni
    // scambio viene persistito lato server (POST alla prima risposta, PUT alle
    // successive) e la sidebar elenca le conversazioni dell'utente.

    function fmtAiConvTime(ts) {
        const d = new Date((ts || 0) * 1000);
        const days = Math.floor((Date.now() - d.getTime()) / 86400000);
        if (days <= 0) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        if (days === 1) return i18n[currentLang].lblAiYesterday || 'ieri';
        return d.toLocaleDateString();
    }

    function renderAiConvList() {
        const box = document.getElementById('aiConvList');
        if (!box) return;
        if (!aiConversations.length) {
            box.innerHTML = `<div class="ai-conv-empty">${escapeHtml(i18n[currentLang].msgAiNoConversations || 'Nessuna conversazione salvata.')}</div>`;
            return;
        }
        const untitled = i18n[currentLang].lblAiUntitledChat || 'Nuova conversazione';
        box.innerHTML = aiConversations.map(c => `
            <div class="ai-conv-item${c.id === aiConvId ? ' active' : ''}" data-action="open-conv" data-conv-id="${Number(c.id)}">
                <i class="fa-regular fa-comment" style="font-size:11px;"></i>
                <span class="ai-conv-title" title="${escapeHtml(c.title || untitled)}">${escapeHtml(c.title || untitled)}</span>
                <span style="font-size:10px; color:var(--text-muted);">${escapeHtml(fmtAiConvTime(c.updated_ts))}</span>
                <button class="ai-conv-del" data-action="delete-conv" data-conv-id="${Number(c.id)}"
                        title="${escapeHtml(i18n[currentLang].btnAiDeleteChat || 'Elimina conversazione')}">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            </div>`).join('');
    }

    function setAiChatTitle(title) {
        aiConvTitle = title || '';
        const el = document.getElementById('aiChatTitle');
        if (el) el.textContent = aiConvTitle
            || (aiConvId !== null ? (i18n[currentLang].lblAiUntitledChat || 'Nuova conversazione')
                                  : (i18n[currentLang].titleAiChat || 'Conversazione'));
    }

    async function loadAiConversations() {
        try {
            const res = await apiFetch('/api/ai/conversations');
            if (!res || !res.ok) return;
            aiConversations = (await res.json()).conversations || [];
            // Il titolo di una conversazione creata vuota lo deriva il server
            // dal primo messaggio: qui l'intestazione si riallinea.
            const open = aiConversations.find(c => c.id === aiConvId);
            if (open) setAiChatTitle(open.title);
            renderAiConvList();
        } catch (e) { /* silenzioso: la chat resta usabile senza cronologia */ }
    }

    async function openAiConversation(id) {
        try {
            const res = await apiFetch(`/api/ai/conversations/${Number(id)}`);
            if (!res || !res.ok) return;
            const data = await res.json();
            aiConvId = data.id;
            aiHistory = data.messages || [];
            const box = document.getElementById('aiChatMessages');
            if (box) box.innerHTML = '';
            aiHistory.forEach(m => appendAiMessage(m.role, m.content));
            setAiChatTitle(data.title);
            renderAiConvList();
        } catch (e) { /* silenzioso */ }
    }

    // Il "+" crea subito la riga lato server, così la conversazione compare in
    // elenco appena la si apre invece che solo dopo la prima risposta.
    async function newAiConversation() {
        // Se quella aperta è già nuova e vuota non serve un doppione.
        if (aiConvId !== null && !aiHistory.length) return;
        clearAiChat();
        try {
            const res = await apiFetch('/api/ai/conversations', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ messages: [] })
            });
            if (!res || !res.ok) return;
            aiConvId = (await res.json()).id;
            setAiChatTitle('');
            await loadAiConversations();
        } catch (e) { /* silenzioso: la chat resta usabile senza cronologia */ }
    }

    async function deleteAiConversation(id) {
        if (!confirm(i18n[currentLang].confirmAiDeleteChat || 'Eliminare questa conversazione?')) return;
        try {
            const res = await apiFetch(`/api/ai/conversations/${Number(id)}`, { method: 'DELETE' });
            if (!res || !res.ok) return;
            if (id === aiConvId) clearAiChat();
            await loadAiConversations();
        } catch (e) { /* silenzioso */ }
    }

    function deleteCurrentAiConversation() {
        if (aiConvId !== null) deleteAiConversation(aiConvId);
    }

    async function renameAiConversation() {
        if (aiConvId === null) return;
        const next = prompt(i18n[currentLang].promptAiRenameChat || 'Nuovo titolo:', aiConvTitle);
        if (next === null) return;
        const title = next.trim();
        if (!title) return;
        try {
            const res = await apiFetch(`/api/ai/conversations/${Number(aiConvId)}`, {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title })
            });
            if (!res || !res.ok) return;
            setAiChatTitle(title);
            await loadAiConversations();
        } catch (e) { /* silenzioso */ }
    }

    // Persiste la conversazione corrente. Alla prima risposta crea la riga e
    // ne memorizza l'id, poi aggiorna sempre la stessa.
    async function persistAiConversation() {
        if (!aiHistory.length) return;
        try {
            if (aiConvId === null) {
                const res = await apiFetch('/api/ai/conversations', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ messages: aiHistory })
                });
                if (!res || !res.ok) return;
                const data = await res.json();
                aiConvId = data.id;
                setAiChatTitle(data.title);
            } else {
                await apiFetch(`/api/ai/conversations/${Number(aiConvId)}`, {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ messages: aiHistory })
                });
            }
            await loadAiConversations();
        } catch (e) { /* silenzioso: la chat non deve rompersi se il salvataggio fallisce */ }
    }

    // ===== Generazione config nuovo switch (AI) =====
    function populateGenCfgProfiles() {
        const sel = document.getElementById('genCfgProfileSelect');
        if (!sel) return;
        const cur = sel.value;
        const profiles = aiProfilesCache || [];
        sel.innerHTML = `<option value="">${i18n[currentLang].optGenCfgActiveProfile || '-- usa profilo AI attivo --'}</option>` +
            profiles.map(p =>
                `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name || 'Senza nome')} (${escapeHtml(p.provider || 'auto')}${p.model ? ' - ' + escapeHtml(p.model) : ''})</option>`
            ).join('');
        if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
    }

    function populateGenCfgTenants() {
        const sel = document.getElementById('genCfgTenant');
        if (!sel) return;
        const cur = sel.value;
        const fromGlobal = Object.keys(window.globalGroups || {});
        const fromDevs = (window.globalDevices || []).map(d => d.Group).filter(Boolean);
        const allTenants = [...new Set(['Generale', ...fromGlobal, ...fromDevs])].sort();

        sel.innerHTML = allTenants.map(g =>
            `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`
        ).join('');
        if (cur && [...sel.options].some(o => o.value === cur)) {
            sel.value = cur;
        } else if (sel.options.length > 0) {
            sel.selectedIndex = 0;
        }
        populateGenCfgTemplates();
        populateGenCfgProfiles();
    }

    function populateGenCfgTemplates() {
        const sel = document.getElementById('genCfgTemplate');
        if (!sel) return;
        const tenant = document.getElementById('genCfgTenant')?.value || '';
        const cur = sel.value;
        const devices = (globalDevices || []).filter(d => (d.Group || 'Generale') === tenant);
        sel.innerHTML = `<option value="">${i18n[currentLang].optGenCfgNoTemplate || '-- usa parametri comuni del tenant --'}</option>` +
            devices.map(d =>
                `<option value="${escapeHtml(d.IP)}">${escapeHtml(d.Hostname || d.IP)} (${escapeHtml(d.IP)})</option>`
            ).join('');
        if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
    }

    async function generateSwitchConfig() {
        const L = i18n[currentLang];
        const statusEl = document.getElementById('genCfgStatus');
        const btn = document.getElementById('btnGenCfg');
        const tenant = document.getElementById('genCfgTenant')?.value || '';
        const hostname = (document.getElementById('genCfgHostname')?.value || '').trim();
        if (!tenant) { if (statusEl) statusEl.textContent = L.errGenCfgTenantRequired || 'Seleziona un tenant.'; return; }
        if (!hostname) { if (statusEl) statusEl.textContent = L.errGenCfgHostnameRequired || "Inserisci l'hostname del nuovo switch."; return; }
        const body = {
            tenant,
            hostname,
            mgmt_ip: (document.getElementById('genCfgMgmtIp')?.value || '').trim(),
            template_ip: document.getElementById('genCfgTemplate')?.value || null,
            notes: (document.getElementById('genCfgNotes')?.value || '').trim(),
            profile_id: document.getElementById('genCfgProfileSelect')?.value || null,
        };
        if (btn) btn.disabled = true;
        if (statusEl) statusEl.textContent = L.msgGenCfgWorking || 'Generazione in corso…';
        try {
            const res = await apiFetch('/api/ai/generate-config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (res && res.ok) {
                const data = await res.json();
                const out = document.getElementById('genCfgOutput');
                const box = document.getElementById('genCfgResult');
                if (out) out.textContent = data.reply || '';
                if (box) box.style.display = '';
                if (statusEl) statusEl.textContent = [data.profile_name, data.model].filter(Boolean).join(' · ');
            } else if (res && res.status === 429) {
                const err = await res.json().catch(() => ({}));
                if (statusEl) statusEl.textContent = '⏳ ' + (err.detail || L.errAiRateLimited || 'Quota AI superata, riprova più tardi.');
            } else {
                const err = res ? await res.json().catch(() => ({})) : {};
                if (statusEl) statusEl.textContent = (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (err.detail || res?.status || 'richiesta fallita.');
            }
        } catch (e) {
            if (statusEl) statusEl.textContent = (currentLang === 'en' ? 'Network error: ' : 'Errore di rete: ') + e;
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function copyGenCfgOutput() {
        const out = document.getElementById('genCfgOutput');
        const statusEl = document.getElementById('genCfgStatus');
        if (!out || !out.textContent) return;
        try {
            await navigator.clipboard.writeText(out.textContent);
            if (statusEl) statusEl.textContent = i18n[currentLang].msgGenCfgCopied || 'Configurazione copiata negli appunti.';
        } catch (e) {
            if (statusEl) statusEl.textContent = (currentLang === 'en' ? 'Copy failed: ' : 'Copia fallita: ') + e;
        }
    }

    // Ricarica la lista dei profili AI dal server e ripopola sia la select
    // "profilo attivo" (in cima alla chat) sia quella "profilo in modifica"
    // (nel pannello di configurazione admin).
    async function loadAiProfiles() {
        const statusEl = document.getElementById('aiSettingsStatus');
        try {
            const res = await apiFetch('/api/ai/profiles');
            if (!res || !res.ok) return;
            const data = await res.json();
            aiProfilesCache = data.profiles || [];
            aiActiveProfileId = data.active_profile || '';

            const activeSel = document.getElementById('aiProfileSelect');
            if (activeSel) {
                const opts = aiProfilesCache.map(p =>
                    `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)} (${escapeHtml(p.provider)})</option>`
                ).join('');
                activeSel.innerHTML = (aiProfilesCache.length
                    ? opts
                    : `<option value="">${i18n[currentLang].optAiNoProfile}</option>`);
                activeSel.value = aiActiveProfileId;
            }
            populateGenCfgProfiles();
            const badge = document.getElementById('aiActiveProfileBadge');
            if (badge) {
                const active = aiProfilesCache.find(p => p.id === aiActiveProfileId);
                badge.textContent = active ? `${active.name} · ${active.model || i18n[currentLang].optAiModelCustom}` : '';
            }

            const editSel = document.getElementById('aiProfileEditSelect');
            if (editSel) {
                const curEdit = editSel.value;
                const editOpts = aiProfilesCache.map(p =>
                    `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`
                ).join('');
                editSel.innerHTML = `<option value="__new__" data-i18n="optAiNewProfile">${i18n[currentLang].optAiNewProfile}</option>` + editOpts;
                editSel.value = [...editSel.options].some(o => o.value === curEdit) ? curEdit : '__new__';
                onAiProfileEditSelectChange();
            }
            renderAiProfileCards();
            if (statusEl) statusEl.textContent = '';
        } catch (e) { /* silenzioso: pannello opzionale per admin */ }
    }

    // Le card sono una VISTA sulle due <select> nascoste: cliccarne una scrive
    // nella select e lascia partire l'onchange esistente. Nessuna logica di
    // profilo duplicata qui.
    const AI_PROVIDER_ICONS = {
        anthropic: 'fa-solid fa-a', openai: 'fa-solid fa-o',
        gemini: 'fa-solid fa-gem', ollama: 'fa-solid fa-server',
    };

    function renderAiProfileCards() {
        const box = document.getElementById('aiProfileCards');
        if (!box) return;
        const L = i18n[currentLang];
        const editing = document.getElementById('aiProfileEditSelect')?.value || '__new__';
        if (!aiProfilesCache.length) {
            box.innerHTML = `<div style="font-size:12px; color:var(--text-muted); padding:6px 2px;">${escapeHtml(L.optAiNoProfile || 'Nessun profilo')}</div>`;
            return;
        }
        box.innerHTML = aiProfilesCache.map(p => {
            const active = p.id === aiActiveProfileId;
            // Ollama gira in locale e non usa chiave: segnalarla "mancante"
            // sarebbe un falso allarme.
            const needsKey = p.provider !== 'ollama';
            const keyChip = !needsKey
                ? `<span title="${escapeHtml(L.lblAiLocalLlm || 'LLM locale')}"><i class="fa-solid fa-house-laptop"></i></span>`
                : (p.api_key_set
                    ? `<span style="color:var(--success);" title="${escapeHtml(L.lblAiKeySet || 'API key impostata')}"><i class="fa-solid fa-key"></i></span>`
                    : `<span style="color:var(--warning, var(--lamp-warn));" title="${escapeHtml(L.lblAiKeyMissing || 'API key mancante')}"><i class="fa-solid fa-triangle-exclamation"></i></span>`);
            return `<div class="ai-profile-card${p.id === editing ? ' editing' : ''}" data-action="select-profile" data-profile-id="${escapeHtml(p.id)}">
                <div class="ai-prof-top">
                    <i class="${AI_PROVIDER_ICONS[p.provider] || 'fa-solid fa-robot'}" style="color:var(--primary); width:14px;"></i>
                    <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(p.name)}</span>
                    ${active ? `<span class="chip" style="font-size:9px; padding:2px 6px;">${escapeHtml(L.lblAiProfileActive || 'ATTIVO')}</span>` : ''}
                </div>
                <div class="ai-prof-meta">
                    ${keyChip}
                    <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(p.model || L.optAiModelCustom || '—')}</span>
                </div>
                ${active ? '' : `<button type="button" class="ai-prof-activate" data-action="activate-profile" data-profile-id="${escapeHtml(p.id)}">${escapeHtml(L.btnAiActivateProfile || 'Rendi attivo')}</button>`}
            </div>`;
        }).join('');
    }

    function selectAiProfileCard(id) {
        const editSel = document.getElementById('aiProfileEditSelect');
        if (!editSel) return;
        editSel.value = id;
        onAiProfileEditSelectChange();   // rirenderizza anche le card
    }

    async function activateAiProfileCard(id) {
        const activeSel = document.getElementById('aiProfileSelect');
        if (!activeSel) return;
        activeSel.value = id;
        await onAiProfileSelectChange();
        renderAiProfileCards();
    }

    // L'utente ha cambiato il "profilo attivo" in cima alla chat: attiva
    // subito quel profilo lato server, cosi' la chat lo usa istantaneamente.
    async function onAiProfileSelectChange() {
        const sel = document.getElementById('aiProfileSelect');
        const profileId = sel ? sel.value : '';
        if (!profileId) return;
        try {
            const res = await apiFetch(`/api/ai/profiles/${encodeURIComponent(profileId)}/activate`, { method: 'POST' });
            if (res && res.ok) {
                aiActiveProfileId = profileId;
                const badge = document.getElementById('aiActiveProfileBadge');
                const active = aiProfilesCache.find(p => p.id === profileId);
                if (badge) badge.textContent = active ? `${active.name} · ${active.model || i18n[currentLang].optAiModelCustom}` : '';
            }
        } catch (e) { /* silenzioso */ }
    }

    // L'utente ha selezionato un profilo diverso nel pannello di modifica:
    // ripopola i campi del form con i dati di quel profilo (chiave API mai
    // precompilata, solo il placeholder indica se e' gia' impostata).
    function onAiProfileEditSelectChange() {
        const editSel = document.getElementById('aiProfileEditSelect');
        const id = editSel ? editSel.value : '__new__';
        const apiKeyInput = document.getElementById('aiApiKey');
        if (id === '__new__') {
            document.getElementById('aiProfileName').value = '';
            // Nessun provider preselezionato: la scelta è esplicita dell'utente.
            document.getElementById('aiProvider').value = '';
            document.getElementById('aiModel').value = '';
            document.getElementById('aiBaseUrl').value = '';
            document.getElementById('aiRateLimitRpm').value = 0;
            document.getElementById('aiContextBudget').value = 0;
            document.getElementById('aiAllowUnredacted').checked = false;
            apiKeyInput.value = '';
            apiKeyInput.placeholder = i18n[currentLang].phAiApiKeyEmpty || 'Inserisci una API key';
            document.getElementById('btnAiDeleteProfile').style.display = 'none';
        } else {
            const p = aiProfilesCache.find(x => x.id === id);
            if (!p) return;
            document.getElementById('aiProfileName').value = p.name || '';
            document.getElementById('aiProvider').value = p.provider || '';
            document.getElementById('aiModel').value = p.model || '';
            document.getElementById('aiBaseUrl').value = p.base_url || '';
            document.getElementById('aiRateLimitRpm').value = p.rate_limit_rpm || 0;
            document.getElementById('aiContextBudget').value = p.context_budget_chars || 0;
            document.getElementById('aiAllowUnredacted').checked = !!p.allow_unredacted;
            apiKeyInput.value = '';
            apiKeyInput.placeholder = p.api_key_set
                ? (i18n[currentLang].phAiApiKeySet || '•••••• (già impostata, lascia vuoto per non modificare)')
                : (i18n[currentLang].phAiApiKeyEmpty || 'Inserisci una API key');
            document.getElementById('btnAiDeleteProfile').style.display = '';
        }
        // NESSUNA chiamata API automatica: l'elenco modelli si aggiorna solo
        // col pulsante dedicato. Qui si svuota soltanto la lista locale, che
        // altrimenti mostrerebbe i modelli di un altro provider/profilo.
        resetAiModelList();
        renderAiProfileCards();   // sposta l'evidenziazione sulla card in modifica
    }

    // Svuota la select dei modelli (nessuna chiamata di rete). Usata quando
    // cambia provider o profilo in modifica: i modelli elencati devono sempre
    // appartenere al provider correntemente selezionato.
    function resetAiModelList() {
        const sel = document.getElementById('aiModelSelect');
        if (sel) sel.innerHTML = `<option value="" data-i18n="optAiModelCustom">${i18n[currentLang].optAiModelCustom || '-- modello personalizzato --'}</option>`;
    }

    async function refreshAiModels(silent) {
        const statusEl = document.getElementById('aiSettingsStatus');
        const sel = document.getElementById('aiModelSelect');
        if (!sel) return;
        const provider = document.getElementById('aiProvider').value;
        if (!provider) {
            if (statusEl) statusEl.textContent = i18n[currentLang].errAiProviderRequired || 'Seleziona prima un provider.';
            return;
        }
        const editSel = document.getElementById('aiProfileEditSelect');
        const profileId = (editSel && editSel.value !== '__new__') ? editSel.value : '';
        const qs = new URLSearchParams();
        if (provider) qs.set('provider', provider);
        if (profileId) qs.set('profile_id', profileId);
        try {
            const res = await apiFetch('/api/ai/models?' + qs.toString());
            if (!res || !res.ok) {
                if (!silent) {
                    const err = res ? await res.json().catch(() => ({})) : {};
                    if (statusEl) statusEl.textContent = (currentLang==='en' ? 'Model list error: ' : 'Errore elenco modelli: ') + (err.detail || res?.status);
                }
                return;
            }
            const data = await res.json();
            const current = document.getElementById('aiModel').value.trim();
            const opts = (data.models || []).map(m =>
                `<option value="${escapeHtml(m)}">${escapeHtml(m)}</option>`
            ).join('');
            sel.innerHTML = `<option value="" data-i18n="optAiModelCustom">-- modello personalizzato --</option>` + opts;
            if (current && (data.models || []).includes(current)) sel.value = current;
            sel.onchange = () => {
                if (sel.value) document.getElementById('aiModel').value = sel.value;
            };
            if (!silent && statusEl) statusEl.textContent = currentLang==='en' ? `Found ${(data.models || []).length} models.` : `Trovati ${(data.models || []).length} modelli.`;
        } catch (e) {
            if (!silent && statusEl) statusEl.textContent = (currentLang==='en' ? 'Network error: ' : 'Errore di rete: ') + e;
        }
    }

    async function saveAiSettings() {
        const statusEl = document.getElementById('aiSettingsStatus');
        const editSel = document.getElementById('aiProfileEditSelect');
        const editingId = (editSel && editSel.value !== '__new__') ? editSel.value : null;
        const name = document.getElementById('aiProfileName').value.trim();
        if (!name) {
            if (statusEl) statusEl.textContent = i18n[currentLang].errAiProfileNameRequired || 'Il nome del profilo è obbligatorio.';
            return;
        }
        if (!document.getElementById('aiProvider').value) {
            if (statusEl) statusEl.textContent = i18n[currentLang].errAiProviderRequired || 'Seleziona prima un provider.';
            return;
        }
        const body = {
            name,
            provider: document.getElementById('aiProvider').value,
            model: document.getElementById('aiModel').value.trim(),
            base_url: document.getElementById('aiBaseUrl').value.trim(),
            rate_limit_rpm: parseInt(document.getElementById('aiRateLimitRpm').value, 10) || 0,
            context_budget_chars: parseInt(document.getElementById('aiContextBudget').value, 10) || 0,
            allow_unredacted: document.getElementById('aiAllowUnredacted').checked,
        };
        const key = document.getElementById('aiApiKey').value;
        if (key) body.api_key = key;
        try {
            const res = editingId
                ? await apiFetch(`/api/ai/profiles/${encodeURIComponent(editingId)}`, {
                    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
                })
                : await apiFetch('/api/ai/profiles', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
                });
            if (res && res.ok) {
                const saved = await res.json();
                if (statusEl) statusEl.textContent = i18n[currentLang].msgAiProfileSaved || 'Profilo salvato.';
                await loadAiProfiles();
                const editSel2 = document.getElementById('aiProfileEditSelect');
                if (editSel2 && saved.id) { editSel2.value = saved.id; onAiProfileEditSelectChange(); }
            } else {
                const err = res ? await res.json().catch(() => ({})) : {};
                if (statusEl) statusEl.textContent = (currentLang==='en' ? 'Error: ' : 'Errore: ') + (err.detail || res?.status);
            }
        } catch (e) {
            if (statusEl) statusEl.textContent = (currentLang==='en' ? 'Network error: ' : 'Errore di rete: ') + e;
        }
    }

    async function deleteAiProfile() {
        const editSel = document.getElementById('aiProfileEditSelect');
        const id = editSel ? editSel.value : '';
        if (!id || id === '__new__') return;
        const statusEl = document.getElementById('aiSettingsStatus');
        try {
            const res = await apiFetch(`/api/ai/profiles/${encodeURIComponent(id)}`, { method: 'DELETE' });
            if (res && res.ok) {
                if (statusEl) statusEl.textContent = i18n[currentLang].msgAiProfileDeleted || 'Profilo eliminato.';
                await loadAiProfiles();
            } else {
                const err = res ? await res.json().catch(() => ({})) : {};
                if (statusEl) statusEl.textContent = (currentLang==='en' ? 'Error: ' : 'Errore: ') + (err.detail || res?.status);
            }
        } catch (e) {
            if (statusEl) statusEl.textContent = (currentLang==='en' ? 'Network error: ' : 'Errore di rete: ') + e;
        }
    }

    // Non cancella nulla lato server: chiude la conversazione corrente e ne
    // apre una nuova. Quella di prima resta nella sidebar.
    function clearAiChat() {
        aiHistory = [];
        aiConvId = null;
        const box = document.getElementById('aiChatMessages');
        if (box) box.innerHTML = '';
        setAiChatTitle('');
        renderAiConvList();
    }

    // --- Config push proposto dall'AI (§10.2): il modello PROPONE in un blocco
    // ```sentinelnet-config {...}```; l'utente CONFERMA in un modale; solo allora
    // il browser chiama /api/bulk-command (operator+blacklist+audit lato server).
    function parseAiConfigProposal(reply) {
        const m = (reply || '').match(/```sentinelnet-config\s*\n?([\s\S]*?)```/);
        if (!m) return null;
        try {
            const p = JSON.parse(m[1].trim());
            if (!p.device_ip || !Array.isArray(p.commands) || !p.commands.length) return null;
            return p;
        } catch (e) { return null; }
    }

    function renderAiConfigProposal(p, attachedIps) {
        if (!p) return;
        const box = document.getElementById('aiChatMessages');
        if (!box) return;
        const card = document.createElement('div');
        card.style.cssText = 'border:1px solid var(--warning, var(--lamp-warn)); border-radius:0; padding:12px; margin:8px 0; font-size:13px;';
        if (!(attachedIps || []).includes(p.device_ip)) {
            card.innerHTML = currentLang==='en' ? `⚠️ The AI proposed a change for <code>${escapeHtml(p.device_ip)}</code>, which is not among the attached devices. Proposal ignored for safety.` : `⚠️ L'AI ha proposto una modifica per <code>${escapeHtml(p.device_ip)}</code>, che non è tra i dispositivi allegati. Proposta ignorata per sicurezza.`;
            box.appendChild(card);
            box.scrollTop = box.scrollHeight;
            return;
        }
        card.innerHTML = `
            <div style="font-weight:600; margin-bottom:6px;"><i class="fa-solid fa-screwdriver-wrench"></i> ${currentLang==='en' ? 'Proposed configuration change' : 'Modifica di configurazione proposta'} — <code>${escapeHtml(p.device_ip)}</code></div>
            <pre style="background:var(--surface-2); border-radius:0; padding:10px; overflow:auto; margin:0 0 8px 0;">${escapeHtml(p.commands.join('\n'))}</pre>
            <div style="display:flex; gap:8px; align-items:center;">
                <button class="btn btn-primary btn-small requires-write" style="width:auto;"><i class="fa-solid fa-play"></i> ${currentLang==='en' ? 'Apply…' : 'Applica…'}</button>
                <button class="btn btn-secondary btn-small" style="width:auto;">${currentLang==='en' ? 'Cancel' : 'Annulla'}</button>
                <span class="ai-cfg-status" style="font-size:12px; color:var(--text-muted);"></span>
            </div>`;
        const [applyBtn, cancelBtn] = card.querySelectorAll('button');
        cancelBtn.onclick = () => card.remove();
        applyBtn.onclick = () => showAiConfigConfirmModal(p, card);
        box.appendChild(card);
        box.scrollTop = box.scrollHeight;
    }

    function showAiConfigConfirmModal(p, card) {
        const overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed; inset:0; background:var(--scrim); z-index:10000; display:flex; align-items:center; justify-content:center;';
        overlay.innerHTML = `
            <div style="background:var(--surface); color:var(--text); border:1px solid var(--border); border-radius:0; max-width:560px; width:92%; padding:18px;">
                <h4 style="margin:0 0 10px 0;">${currentLang==='en' ? 'Confirm configuration push' : 'Conferma invio configurazione'}</h4>
                <p style="font-size:13px; margin:0 0 8px 0;">${currentLang==='en' ? `You are about to send <b>${p.commands.length}</b> commands in configuration mode to <code>${escapeHtml(p.device_ip)}</code>. The operation is audited and blacklisted commands are blocked server-side.` : `Stai per inviare <b>${p.commands.length}</b> comandi in modalità configurazione a <code>${escapeHtml(p.device_ip)}</code>. L'operazione viene auditata e i comandi in blacklist vengono bloccati dal server.`}</p>
                <pre style="background:var(--surface-2); border-radius:0; padding:10px; max-height:220px; overflow:auto; font-size:12px;">${escapeHtml(p.commands.join('\n'))}</pre>
                <label style="display:flex; align-items:center; gap:6px; font-size:13px; margin:8px 0;">
                    <input type="checkbox" id="aiCfgSaveAfter"${p.save_after ? ' checked' : ''}> ${currentLang==='en' ? 'Save startup configuration after the push' : "Salva configurazione di avvio dopo l'invio"}
                </label>
                <div style="display:flex; gap:8px; justify-content:flex-end;">
                    <button class="btn btn-secondary btn-small" style="width:auto;">${currentLang==='en' ? 'Cancel' : 'Annulla'}</button>
                    <button class="btn btn-primary btn-small" style="width:auto;"><i class="fa-solid fa-play"></i> ${currentLang==='en' ? 'Confirm and apply' : 'Conferma e applica'}</button>
                </div>
            </div>`;
        const [cancelBtn, confirmBtn] = overlay.querySelectorAll('button');
        cancelBtn.onclick = () => overlay.remove();
        confirmBtn.onclick = async () => {
            const save = overlay.querySelector('#aiCfgSaveAfter').checked;
            overlay.remove();
            await applyAiConfigProposal(p, save, card);
        };
        document.body.appendChild(overlay);
    }

    async function applyAiConfigProposal(p, save, card) {
        const statusEl = card.querySelector('.ai-cfg-status');
        const setStatus = (t, err) => { if (statusEl) { statusEl.textContent = t; statusEl.style.color = err ? 'var(--danger, #d9534f)' : 'var(--text-muted)'; } };
        card.querySelectorAll('button').forEach(b => b.disabled = true);
        setStatus(currentLang==='en' ? 'Sending…' : 'Invio in corso…');
        try {
            const res = await apiFetch('/api/bulk-command', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ips: [p.device_ip],
                    commands: p.commands.join('\n'),
                    mode: p.config_mode === false ? 'exec' : 'config',
                    save: !!save
                })
            });
            if (!res || !res.ok) {
                const err = res ? await res.json().catch(() => ({})) : {};
                setStatus((currentLang==='en' ? 'Error: ' : 'Errore: ') + (err.detail || (currentLang==='en' ? 'request rejected.' : 'richiesta rifiutata.')), true);
                card.querySelectorAll('button').forEach(b => b.disabled = false);
                return;
            }
            const jobId = (await res.json()).job_id;
            // Poll dello stato del job (max ~120s).
            for (let i = 0; i < 60; i++) {
                await new Promise(r => setTimeout(r, 2000));
                const jr = await apiFetch(`/api/bulk-command/${encodeURIComponent(jobId)}`);
                if (!jr || !jr.ok) continue;
                const job = await jr.json();
                if (job.status !== 'running') {
                    const entry = (job.results || [])[0];
                    const result = entry ? (entry.result || {}) : { status: 'error', message: currentLang==='en' ? 'device not found in inventory.' : 'dispositivo non trovato in inventario.' };
                    const ok = result.status === 'success';
                    setStatus(ok ? (currentLang==='en' ? '✅ Configuration applied.' : '✅ Configurazione applicata.') : (currentLang==='en' ? 'Error: ' : 'Errore: ') + (result.message || (currentLang==='en' ? 'push failed.' : 'invio fallito.')), !ok);
                    appendAiMessage('assistant', (ok ? (currentLang==='en' ? '✅ Configuration applied to ' : '✅ Configurazione applicata a ') : (currentLang==='en' ? '❌ Push failed to ' : '❌ Invio fallito a ')) + p.device_ip + (result.output ? '\n\n' + result.output : (result.message ? '\n\n' + result.message : '')));
                    return;
                }
                setStatus(currentLang==='en' ? 'Running…' : 'In esecuzione…');
            }
            setStatus(currentLang==='en' ? 'Timeout waiting for the result: check the bulk command job.' : 'Timeout in attesa del risultato: controlla il job dei comandi bulk.', true);
        } catch (e) {
            setStatus((currentLang==='en' ? 'Network error: ' : 'Errore di rete: ') + e, true);
            card.querySelectorAll('button').forEach(b => b.disabled = false);
        }
    }

    function appendAiMessage(role, text, meta) {
        const box = document.getElementById('aiChatMessages');
        if (!box) return null;
        const div = document.createElement('div');
        const isUser = role === 'user';
        div.style.marginBottom = '12px';
        div.style.display = 'flex';
        div.style.flexDirection = 'column';
        div.style.alignItems = isUser ? 'flex-end' : 'flex-start';
        const label = isUser ? (i18n[currentLang].lblAiChatYou || 'Tu') : (meta || (i18n[currentLang].lblAiChatAssistant || 'AI'));
        div.innerHTML = `<div style="font-size:11px; color:var(--text-muted); margin-bottom:3px;">${escapeHtml(label)}</div>
            <div style="white-space:pre-wrap; max-width:85%; background:${isUser ? 'var(--primary)' : 'var(--surface-3)'}; color:${isUser ? 'var(--on-lamp)' : 'inherit'}; border-radius:0; ${isUser ? 'border-bottom-right-radius:2px;' : 'border-bottom-left-radius:2px;'} padding:8px 12px; font-size:13px;">${escapeHtml(text)}</div>`;
        box.appendChild(div);
        box.scrollTop = box.scrollHeight;
        return div;
    }

    async function sendAiChat() {
        const input = document.getElementById('aiChatInput');
        const sendBtn = document.getElementById('btnAiSend');
        const text = (input.value || '').trim();
        if (!text) return;
        input.value = '';
        if (sendBtn) sendBtn.disabled = true;
        aiHistory.push({ role: 'user', content: text });
        appendAiMessage('user', text);

        const attachInventory = document.getElementById('aiAttachInventory').checked;
        const attachDeviceIps = getAiAttachDeviceIps();
        const attachTenant = document.getElementById('aiAttachTenant')?.value || null;
        const wasTopFlows = aiAttachTopFlowsOnce;
        const wasFlowKeys = aiAttachFlowKeysOnce;

        const placeholder = appendAiMessage('assistant', '...');

        try {
            const body = {
                messages: aiHistory,
                attach_inventory: attachInventory,
                attach_device_ips: attachDeviceIps,
                attach_tenant: attachTenant,
                attach_top_flows: aiAttachTopFlowsOnce
            };
            // 11.3: se sono state selezionate righe flusso specifiche, invia le
            // sole tuple identificative (mai byte/pacchetti — li ri-deriva il server).
            if (aiAttachFlowKeysOnce && aiAttachFlowKeysOnce.length) {
                body.attach_flow_keys = aiAttachFlowKeysOnce;
            }
            const res = await apiFetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (placeholder) placeholder.remove();
            if (res && res.ok) {
                const data = await res.json();
                aiHistory.push({ role: 'assistant', content: data.reply });
                const meta = [data.profile_name, data.model].filter(Boolean).join(' · ');
                appendAiMessage('assistant', data.reply, meta);
                renderAiConfigProposal(parseAiConfigProposal(data.reply), attachDeviceIps);
            } else if (res && res.status === 429) {
                const err = await res.json().catch(() => ({}));
                appendAiMessage('assistant', '⏳ ' + (i18n[currentLang].errAiRateLimited || 'Troppe richieste: limite di frequenza superato. Riprova tra qualche secondo.') + (err.detail ? ' (' + err.detail + ')' : ''));
            } else {
                const err = res ? await res.json().catch(() => ({})) : {};
                appendAiMessage('assistant', 'Errore: ' + (err.detail || 'richiesta fallita.'));
            }
        } catch (e) {
            if (placeholder) placeholder.remove();
            appendAiMessage('assistant', 'Errore di rete: ' + e);
        } finally {
            if (sendBtn) sendBtn.disabled = false;
            if (wasTopFlows) aiAttachTopFlowsOnce = false; // allegato una sola volta
            if (wasFlowKeys) aiAttachFlowKeysOnce = null;  // allegato una sola volta
            await persistAiConversation();
        }
    }

    window.populateGenCfgProfiles = populateGenCfgProfiles;
    window.populateGenCfgTenants = populateGenCfgTenants;
    window.populateGenCfgTemplates = populateGenCfgTemplates;
    window.generateSwitchConfig = generateSwitchConfig;
    window.copyGenCfgOutput = copyGenCfgOutput;

    // Delegated event listeners for AI tab
    document.getElementById('aiAttachDeviceList')?.addEventListener('change', (e) => {
        if (e.target.classList.contains('ai-attach-device')) {
            updateAiDeviceBtnLabel();
        }
    });

    document.getElementById('aiConvList')?.addEventListener('click', (e) => {
        const delBtn = e.target.closest('[data-action="delete-conv"]');
        if (delBtn && delBtn.dataset.convId) {
            e.stopPropagation();
            deleteAiConversation(Number(delBtn.dataset.convId));
            return;
        }
        const openItem = e.target.closest('[data-action="open-conv"]');
        if (openItem && openItem.dataset.convId) {
            openAiConversation(Number(openItem.dataset.convId));
            return;
        }
    });

    document.getElementById('aiProfileCards')?.addEventListener('click', (e) => {
        const actBtn = e.target.closest('[data-action="activate-profile"]');
        if (actBtn && actBtn.dataset.profileId) {
            e.stopPropagation();
            activateAiProfileCard(actBtn.dataset.profileId);
            return;
        }
        const selCard = e.target.closest('[data-action="select-profile"]');
        if (selCard && selCard.dataset.profileId) {
            selectAiProfileCard(selCard.dataset.profileId);
            return;
        }
    });

    document.getElementById('aiProfileSelect')?.addEventListener('change', onAiProfileSelectChange);
    document.getElementById('aiProfileEditSelect')?.addEventListener('change', onAiProfileEditSelectChange);
    document.getElementById('aiProvider')?.addEventListener('change', resetAiModelList);
    document.getElementById('btnAiRefreshModels')?.addEventListener('click', refreshAiModels);
    document.getElementById('btnAiSaveSettings')?.addEventListener('click', saveAiSettings);
    document.getElementById('btnAiDeleteProfile')?.addEventListener('click', deleteAiProfile);
    document.getElementById('btnAiNewChat')?.addEventListener('click', newAiConversation);
    document.getElementById('btnAiRenameChat')?.addEventListener('click', renameAiConversation);
    document.getElementById('btnAiDeleteChat')?.addEventListener('click', deleteCurrentAiConversation);
    document.getElementById('aiAttachTenant')?.addEventListener('change', populateAiAttachDevices);
    document.getElementById('aiAttachDeviceBtn')?.addEventListener('click', toggleAiDeviceDropdown);

    document.getElementById('aiChatInput')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendAiChat();
        }
    });
    document.getElementById('btnAiSend')?.addEventListener('click', sendAiChat);

    document.getElementById('tab-ai')?.addEventListener('click', (e) => {
        if (e.target.closest('[data-action="ai-select-all-devices"]')) {
            setAllAiAttachDevices(true);
            return;
        }
        if (e.target.closest('[data-action="ai-deselect-all-devices"]')) {
            setAllAiAttachDevices(false);
            return;
        }
        const newProf = e.target.closest('[data-action="select-profile"][data-profile-id="__new__"]');
        if (newProf) {
            selectAiProfileCard('__new__');
            return;
        }
    });

    document.getElementById('genCfgTenant')?.addEventListener('change', populateGenCfgTemplates);
    document.getElementById('btnGenCfg')?.addEventListener('click', generateSwitchConfig);
    document.getElementById('btnGenCfgCopy')?.addEventListener('click', copyGenCfgOutput);

