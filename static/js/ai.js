// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
    let aiProfilesCache = [];   // ultima lista di profili (mascherati) caricata dal server
    let aiActiveProfileId = ''; // id del profilo attivo lato server

    // ===== Generazione config nuovo switch (AI) =====
    function populateGenCfgProfiles() {
        const sel = document.getElementById('genCfgProfileSelect');
        if (!sel) return;
        const cur = sel.value;
        const profiles = aiProfilesCache || [];
        sel.innerHTML = `<option value="">${tr('optGenCfgActiveProfile') || '-- usa profilo AI attivo --'}</option>` +
            profiles.map(p =>
                `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name || 'Senza nome')} (${escapeHtml(p.provider || 'auto')}${p.model ? ' - ' + escapeHtml(p.model) : ''})</option>`
            ).join('');
        if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
    }

    function populateGenCfgTenants() {
        const sel = document.getElementById('genCfgTenant');
        if (!sel) return;
        const cur = sel.value;
        const fromGlobal = Object.keys(globalGroups || {});
        const fromDevs = (globalDevices || []).map(d => d.Group).filter(Boolean);
        const allTenants = [...new Set([...fromGlobal, ...fromDevs])].sort();

        sel.innerHTML = allTenants.map(g =>
            `<option value="${escapeHtml(g)}">${escapeHtml(orgLabel(g))}</option>`
        ).join('');
        if (cur && [...sel.options].some(o => o.value === cur)) {
            sel.value = cur;
        } else if (sel.options.length > 0) {
            sel.value = tenantSelectSeed('', allTenants, allTenants[0]);
        }
        populateGenCfgTemplates();
        populateGenCfgProfiles();
    }

    function populateGenCfgTemplates() {
        const sel = document.getElementById('genCfgTemplate');
        if (!sel) return;
        const tenant = document.getElementById('genCfgTenant')?.value || '';
        const cur = sel.value;
        const devices = (globalDevices || []).filter(d => (d.Group || '') === tenant);
        sel.innerHTML = `<option value="">${tr('optGenCfgNoTemplate') || '-- usa parametri comuni del tenant --'}</option>` +
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
                if (statusEl) statusEl.textContent = (tr('uiError')) + (err.detail || res?.status || 'richiesta fallita.');
            }
        } catch (e) {
            if (statusEl) statusEl.textContent = (tr('aiNetworkError')) + e;
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
            if (statusEl) statusEl.textContent = tr('msgGenCfgCopied') || 'Configurazione copiata negli appunti.';
        } catch (e) {
            if (statusEl) statusEl.textContent = (tr('aiCopyFailed')) + e;
        }
    }

    // Ricarica la lista dei profili AI dal server e ripopola sia la select
    // "profilo attivo" sia quella "profilo in modifica" (entrambe nascoste,
    // pannello Profili AI delle Impostazioni).
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
                    : `<option value="">${tr('optAiNoProfile')}</option>`);
                activeSel.value = aiActiveProfileId;
            }
            populateGenCfgProfiles();
            const badge = document.getElementById('aiActiveProfileBadge');
            if (badge) {
                const active = aiProfilesCache.find(p => p.id === aiActiveProfileId);
                badge.textContent = active ? `${active.name} · ${active.model || tr('optAiModelCustom')}` : '';
            }

            const editSel = document.getElementById('aiProfileEditSelect');
            if (editSel) {
                const curEdit = editSel.value;
                const editOpts = aiProfilesCache.map(p =>
                    `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`
                ).join('');
                editSel.innerHTML = `<option value="__new__" data-i18n="optAiNewProfile">${tr('optAiNewProfile')}</option>` + editOpts;
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

    // Una card ha chiesto di diventare il profilo attivo: lo attiva lato server.
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
                if (badge) badge.textContent = active ? `${active.name} · ${active.model || tr('optAiModelCustom')}` : '';
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
            apiKeyInput.placeholder = tr('phAiApiKeyEmpty') || 'Inserisci una API key';
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
                ? (tr('phAiApiKeySet') || '•••••• (già impostata, lascia vuoto per non modificare)')
                : (tr('phAiApiKeyEmpty') || 'Inserisci una API key');
            document.getElementById('btnAiDeleteProfile').style.display = '';
        }
        // NESSUNA chiamata API automatica: l'elenco modelli si aggiorna solo
        // col pulsante dedicato. Qui si svuota soltanto la lista locale, che
        // altrimenti mostrerebbe i modelli di un altro provider/profilo.
        resetAiModelList();
        syncAiProviderUi();
        renderAiProfileCards();   // sposta l'evidenziazione sulla card in modifica
    }

    // Svuota la select dei modelli (nessuna chiamata di rete). Usata quando
    // cambia provider o profilo in modifica: i modelli elencati devono sempre
    // appartenere al provider correntemente selezionato.
    // Le tessere provider e i campi che dipendono dal provider (API key,
    // endpoint) seguono il valore di #aiProvider, scritto anche via codice.
    function syncAiProviderUi() {
        const v = document.getElementById('aiProvider').value;
        const form = document.getElementById('aiProfileForm');
        if (form) form.dataset.provider = v;
        document.querySelectorAll('#aiProfileForm .ai-provider-tile').forEach(t =>
            t.setAttribute('aria-checked', String(t.dataset.provider === v)));
    }

    function resetAiModelList() {
        const sel = document.getElementById('aiModelSelect');
        if (sel) sel.innerHTML = `<option value="" data-i18n="optAiModelCustom">${tr('optAiModelCustom') || '-- modello personalizzato --'}</option>`;
    }

    async function refreshAiModels(silent) {
        const statusEl = document.getElementById('aiSettingsStatus');
        const sel = document.getElementById('aiModelSelect');
        if (!sel) return;
        const provider = document.getElementById('aiProvider').value;
        if (!provider) {
            if (statusEl) statusEl.textContent = tr('errAiProviderRequired') || 'Seleziona prima un provider.';
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
                    if (statusEl) statusEl.textContent = (tr('aiModelListError')) + (err.detail || res?.status);
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
            if (!silent && statusEl) statusEl.textContent = tr('aiFoundModels', {length: (data.models || []).length});
        } catch (e) {
            if (!silent && statusEl) statusEl.textContent = (tr('aiNetworkError')) + e;
        }
    }

    async function saveAiSettings() {
        const statusEl = document.getElementById('aiSettingsStatus');
        const editSel = document.getElementById('aiProfileEditSelect');
        const editingId = (editSel && editSel.value !== '__new__') ? editSel.value : null;
        const name = document.getElementById('aiProfileName').value.trim();
        if (!name) {
            if (statusEl) statusEl.textContent = tr('errAiProfileNameRequired') || 'Il nome del profilo è obbligatorio.';
            return;
        }
        if (!document.getElementById('aiProvider').value) {
            if (statusEl) statusEl.textContent = tr('errAiProviderRequired') || 'Seleziona prima un provider.';
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
                if (statusEl) statusEl.textContent = tr('msgAiProfileSaved') || 'Profilo salvato.';
                await loadAiProfiles();
                const editSel2 = document.getElementById('aiProfileEditSelect');
                if (editSel2 && saved.id) { editSel2.value = saved.id; onAiProfileEditSelectChange(); }
            } else {
                const err = res ? await res.json().catch(() => ({})) : {};
                if (statusEl) statusEl.textContent = (tr('uiError')) + (err.detail || res?.status);
            }
        } catch (e) {
            if (statusEl) statusEl.textContent = (tr('aiNetworkError')) + e;
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
                if (statusEl) statusEl.textContent = tr('msgAiProfileDeleted') || 'Profilo eliminato.';
                await loadAiProfiles();
            } else {
                const err = res ? await res.json().catch(() => ({})) : {};
                if (statusEl) statusEl.textContent = (tr('uiError')) + (err.detail || res?.status);
            }
        } catch (e) {
            if (statusEl) statusEl.textContent = (tr('aiNetworkError')) + e;
        }
    }

    window.populateGenCfgProfiles = populateGenCfgProfiles;
    window.populateGenCfgTenants = populateGenCfgTenants;
    window.populateGenCfgTemplates = populateGenCfgTemplates;
    window.generateSwitchConfig = generateSwitchConfig;
    window.copyGenCfgOutput = copyGenCfgOutput;

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
    document.getElementById('aiProvider')?.addEventListener('change', () => { resetAiModelList(); syncAiProviderUi(); });
    document.getElementById('btnAiRefreshModels')?.addEventListener('click', refreshAiModels);
    document.getElementById('btnAiSaveSettings')?.addEventListener('click', saveAiSettings);
    document.getElementById('btnAiDeleteProfile')?.addEventListener('click', deleteAiProfile);
    // core.js seeds the tenant field without a change event (a form's side
    // effects must not fire): redraw its device list here.
    window.addEventListener('globalTenantChanged', populateGenCfgTemplates);

    document.getElementById('aiSettingsPanel')?.addEventListener('click', (e) => {
        const tile = e.target.closest('[data-action="ai-pick-provider"]');
        if (tile) {
            const sel = document.getElementById('aiProvider');
            sel.value = tile.dataset.provider;
            sel.dispatchEvent(new Event('change'));
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

