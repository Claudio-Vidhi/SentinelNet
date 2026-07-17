    // ===== AI Assistant =====
    let aiHistory = [];  // {role, content} inviato al backend (senza system: aggiunto server-side)
    let aiProfilesCache = [];   // ultima lista di profili (mascherati) caricata dal server
    let aiActiveProfileId = ''; // id del profilo attivo lato server

    // Popola la select dei dispositivi allegabili, filtrata per il tenant/sede
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
                <input type="checkbox" class="ai-attach-device" value="${escapeHtml(d.IP)}"${cur.has(d.IP) ? ' checked' : ''} onchange="updateAiDeviceBtnLabel()" style="accent-color:var(--primary);">
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
            const badge = document.getElementById('aiActiveProfileBadge');
            if (badge) {
                const active = aiProfilesCache.find(p => p.id === aiActiveProfileId);
                badge.textContent = active ? `${active.model || i18n[currentLang].optAiModelCustom}` : '';
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
            if (statusEl) statusEl.textContent = '';
        } catch (e) { /* silenzioso: pannello opzionale per admin */ }
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
                if (badge) badge.textContent = active ? `${active.model || i18n[currentLang].optAiModelCustom}` : '';
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

    function clearAiChat() {
        aiHistory = [];
        const box = document.getElementById('aiChatMessages');
        if (box) box.innerHTML = '';
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
        card.style.cssText = 'border:1px solid var(--warning, #e0a800); border-radius:10px; padding:12px; margin:8px 0; font-size:13px;';
        if (!(attachedIps || []).includes(p.device_ip)) {
            card.innerHTML = currentLang==='en' ? `⚠️ The AI proposed a change for <code>${escapeHtml(p.device_ip)}</code>, which is not among the attached devices. Proposal ignored for safety.` : `⚠️ L'AI ha proposto una modifica per <code>${escapeHtml(p.device_ip)}</code>, che non è tra i dispositivi allegati. Proposta ignorata per sicurezza.`;
            box.appendChild(card);
            box.scrollTop = box.scrollHeight;
            return;
        }
        card.innerHTML = `
            <div style="font-weight:600; margin-bottom:6px;"><i class="fa-solid fa-screwdriver-wrench"></i> ${currentLang==='en' ? 'Proposed configuration change' : 'Modifica di configurazione proposta'} — <code>${escapeHtml(p.device_ip)}</code></div>
            <pre style="background:var(--surface-2); border-radius:8px; padding:10px; overflow:auto; margin:0 0 8px 0;">${escapeHtml(p.commands.join('\n'))}</pre>
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
        overlay.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,0.55); z-index:10000; display:flex; align-items:center; justify-content:center;';
        overlay.innerHTML = `
            <div style="background:var(--surface); color:var(--text); border:1px solid var(--border); border-radius:12px; max-width:560px; width:92%; padding:18px;">
                <h4 style="margin:0 0 10px 0;">${currentLang==='en' ? 'Confirm configuration push' : 'Conferma invio configurazione'}</h4>
                <p style="font-size:13px; margin:0 0 8px 0;">${currentLang==='en' ? `You are about to send <b>${p.commands.length}</b> commands in configuration mode to <code>${escapeHtml(p.device_ip)}</code>. The operation is audited and blacklisted commands are blocked server-side.` : `Stai per inviare <b>${p.commands.length}</b> comandi in modalità configurazione a <code>${escapeHtml(p.device_ip)}</code>. L'operazione viene auditata e i comandi in blacklist vengono bloccati dal server.`}</p>
                <pre style="background:var(--surface-2); border-radius:8px; padding:10px; max-height:220px; overflow:auto; font-size:12px;">${escapeHtml(p.commands.join('\n'))}</pre>
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
            <div style="white-space:pre-wrap; max-width:85%; background:${isUser ? 'var(--accent, #3b82f6)' : 'var(--surface-3)'}; color:${isUser ? '#fff' : 'inherit'}; border-radius:12px; ${isUser ? 'border-bottom-right-radius:2px;' : 'border-bottom-left-radius:2px;'} padding:8px 12px; font-size:13px;">${escapeHtml(text)}</div>`;
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
        }
    }
