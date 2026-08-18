// static/js/site-agent.js
// Remote Site Agent Control Plane & RPC Management (Checkmk Style)

(function () {
    let _activeAgentSiteId = null;

    async function openAgentControlModal(siteId) {
        _activeAgentSiteId = siteId;
        const modal = document.getElementById('agentControlModal');
        const title = document.getElementById('agentControlTitle');
        const body = document.getElementById('agentControlBody');
        if (!modal || !body) return;

        if (title) title.innerHTML = `<i class="fa-solid fa-gears" style="color:var(--primary);"></i> Gestione Remota Agente Sede: <strong>${escapeHtml(siteId)}</strong>`;

        body.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin fa-2x"></i><br><br>Caricamento telemetria agente...</div>`;
        modal.style.display = 'flex';

        // Load jobs history and site details
        const [jobsRes, sitesRes] = await Promise.all([
            apiFetch(`/api/sites/${siteId}/command-jobs`),
            apiFetch(`/api/sites`)
        ]);

        let site = null;
        if (sitesRes && sitesRes.ok) {
            const sData = await sitesRes.json();
            site = (sData.sites || []).find(x => x.id === siteId);
        }

        let jobs = [];
        if (jobsRes && jobsRes.ok) {
            const jData = await jobsRes.json();
            jobs = jData.jobs || [];
        }

        const lastSeen = site && site.last_seen ? new Date(site.last_seen * 1000).toLocaleString() : 'Mai / Offline';
        const isOnline = site && site.last_seen && (Date.now() / 1000 - site.last_seen < 120);

        // Valori APPLICATI: sempre e solo da site.* (autoritativo, riportato
        // dall'agente ad ogni heartbeat — vedi routers/agent.py). NON vanno
        // sovrascritti con quanto richiesto via job, perché un job può essere
        // ancora in coda, fallito, o mai eseguito: mostrare il richiesto come
        // se fosse applicato inganna l'admin facendogli credere che la modifica
        // abbia già avuto effetto.
        let curPort = (site && site.syslog_port) || 5514;
        let curInterval = (site && site.interval) || 60;

        // jobs arriva già ordinato dal più recente al più vecchio (site_manager.list_jobs
        // usa ORDER BY created DESC), quindi il primo match è già l'ultimo richiesto.
        const lastCfgJob = jobs.find(j => j.command && j.command.startsWith('_agent_config'));
        let pendingCfg = null;
        if (lastCfgJob && lastCfgJob.status !== 'done') {
            let reqPort = null, reqInterval = null;
            try {
                const argStr = lastCfgJob.command.replace('_agent_config', '').trim();
                const p = JSON.parse(argStr);
                if (p.syslog_port != null) reqPort = p.syslog_port;
                if (p.interval != null) reqInterval = p.interval;
            } catch (err) {}
            pendingCfg = { job: lastCfgJob, reqPort: reqPort, reqInterval: reqInterval };
        }

        let pendingCfgHtml = '';
        if (pendingCfg) {
            const j = pendingCfg.job;
            const reqBits = [
                pendingCfg.reqPort != null ? `Porta: ${escapeHtml(String(pendingCfg.reqPort))}` : null,
                pendingCfg.reqInterval != null ? `Intervallo: ${escapeHtml(String(pendingCfg.reqInterval))}s` : null
            ].filter(Boolean).join(', ');
            if (j.status === 'error') {
                pendingCfgHtml = `<div style="margin-top:10px; padding:8px 10px; border-radius:0; background:color-mix(in srgb, var(--danger) 12%, transparent); border:1px solid var(--danger); font-size:11px; color:var(--danger);">
                    <i class="fa-solid fa-triangle-exclamation"></i> <strong>Ultima richiesta di configurazione FALLITA</strong>${reqBits ? ` (${reqBits})` : ''}.
                    <div style="margin-top:4px; font-family:var(--font-code); white-space:pre-wrap;">${escapeHtml(j.result || 'Errore sconosciuto')}</div>
                </div>`;
            } else {
                pendingCfgHtml = `<div style="margin-top:10px; padding:8px 10px; border-radius:0; background:color-mix(in srgb, var(--warning) 12%, transparent); border:1px solid var(--warning); font-size:11px; color:var(--warning);">
                    <i class="fa-solid fa-hourglass-half"></i> <strong>Modifica in attesa di applicazione dall'agente</strong>${reqBits ? ` (${reqBits})` : ''}.
                    Verrà applicata al prossimo ciclo di polling dell'agente (ritardo massimo atteso: ~${escapeHtml(String(curInterval))}s, in base all'intervallo attualmente applicato).
                </div>`;
            }
        }

        const isFlowActive = site && site.flow_active !== false;

        // jobs arriva ORDER BY created DESC (piu' recente per primo): i 10 job
        // da mostrare sono quindi i PRIMI 10, gia' nell'ordine giusto. Il
        // precedente slice(-10).reverse() prendeva gli ULTIMI 10 dell'array,
        // cioe' i 10 piu' VECCHI: un job appena accodato non compariva mai
        // nello storico, facendo sembrare che la richiesta non fosse partita.
        let jobsHtml = jobs.slice(0, 10).map(j => {
            const statusCol = j.status === 'done' ? 'var(--success)' : j.status === 'error' ? 'var(--danger)' : 'var(--warning)';
            const jobTime = j.created ? new Date(j.created * 1000).toLocaleString() : 'N/D';
            return `<div style="padding:6px 8px; border-bottom:1px solid var(--border); font-size:12px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
                <span>
                    <code>${escapeHtml(j.command)}</code>
                    <span style="font-size:11px; color:var(--text-muted); margin-left:6px;">
                        <i class="fa-regular fa-clock"></i> ${jobTime} — (${escapeHtml(j.requested_by || 'admin')})
                    </span>
                </span>
                <span style="color:${statusCol}; font-weight:700; font-size:11px; text-transform:uppercase;">${escapeHtml(j.status)}</span>
            </div>
            ${j.result ? `<pre style="margin:2px 0 8px; padding:6px; background:var(--surface); font-size:11px; max-height:100px; overflow:auto;">${escapeHtml(j.result)}</pre>` : ''}`;
        }).join('');

        body.innerHTML = `
        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:16px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:10px; flex-wrap:wrap; gap:8px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <span style="font-weight:700; font-size:14px;">Stato Agente Remoto</span>
                    <span class="status ${isOnline ? 'ok' : 'err'}"><span class="led ${isOnline ? 'led-success' : 'led-danger'}"></span>${isOnline ? 'ONLINE' : 'OFFLINE / UNREACHABLE'}</span>
                </div>
                <div style="display:flex; align-items:center; gap:10px;">
                    <span class="status ${isFlowActive ? 'ok' : 'warn'}" style="font-size:11px;">
                        <span class="led ${isFlowActive ? 'led-success' : 'led-warning'}"></span>
                        ${isFlowActive ? 'FLUSSO ATTIVO' : 'FLUSSO PAUSATO'}
                    </span>
                    <button class="btn btn-sm ${isFlowActive ? 'btn-secondary' : 'btn-primary'}" data-action="toggle-flow" data-site-id="${escapeHtml(siteId)}" data-active="${!isFlowActive}" style="padding:4px 10px; font-size:11px;">
                        <i class="fa-solid ${isFlowActive ? 'fa-pause' : 'fa-play'}"></i> ${isFlowActive ? 'Interrompi Flusso Dati' : 'Riavvia Flusso Dati'}
                    </button>
                </div>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:12px;">
                <div><strong>Ultimo contatto:</strong> ${lastSeen}</div>
                <div><strong>Modalità:</strong> Site Agent (Outbound HTTPS)</div>
                <div><strong>Syslog UDP Listener:</strong> Attivo su porta ${curPort}</div>
                <div><strong>Intervallo Sync:</strong> ${curInterval}s (Syslog streaming 2s)</div>
            </div>
        </div>

        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:16px;">
            <h4 style="margin:0 0 10px; font-size:13px; color:var(--primary);"><i class="fa-solid fa-sliders"></i> Configurazione Porta Syslog & Timing Polling</h4>
            <div style="display:grid; grid-template-columns:1fr 1fr auto; gap:10px; align-items:end;">
                <div>
                    <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Porta Syslog UDP Listener</label>
                    <input id="agentCfgSyslogPort" type="number" value="${curPort}" style="width:100%; padding:6px 10px; font-size:12px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); color:var(--text);">
                </div>
                <div>
                    <label style="font-size:11px; color:var(--text-muted); display:block; margin-bottom:4px;">Intervallo Polling Inventario (sec)</label>
                    <input id="agentCfgInterval" type="number" value="${curInterval}" style="width:100%; padding:6px 10px; font-size:12px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); color:var(--text);">
                </div>
                <button class="btn btn-sm" data-action="save-config" data-site-id="${escapeHtml(siteId)}" style="padding:6px 14px; background:var(--cta); color:var(--cta-text);">
                    <i class="fa-solid fa-floppy-disk"></i> Salva Config
                </button>
            </div>
            ${pendingCfgHtml}
        </div>

        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:16px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                <h4 style="margin:0; font-size:13px; color:var(--warning);"><i class="fa-solid fa-file-csv"></i> Editor Inventario Locale Sede (network_hosts.csv)</h4>
                <button class="btn btn-sm btn-secondary" data-action="fetch-inv" data-site-id="${escapeHtml(siteId)}" style="padding:4px 10px; font-size:11px;">
                    <i class="fa-solid fa-download"></i> Leggi da Agente
                </button>
            </div>
            <textarea id="agentInventoryTextarea" placeholder="IP,Vendor,Profile,Username,Password,Enable Secret,Group,Hostname,Site,SSH Port,Transports,SNMP Community&#10;192.0.2.1,fortigate,custom,admin,,,Tenant_Milano,fw-01,milano,22,,&#10;192.0.2.2,cisco,custom,admin,,,Tenant_Milano,switch-01,milano,22,," style="width:100%; height:100px; font-family:var(--font-code); font-size:11px; padding:8px; border:1px solid var(--border); border-radius:0; background:var(--surface); color:var(--text); resize:vertical;"></textarea>
            <div style="margin-top:6px; font-size:11px; color:var(--text-muted); line-height:1.5;">
                Serve almeno la colonna <code>IP</code>; il separatore può essere <code>,</code> o <code>;</code> e le altre
                colonne sono opzionali. Il tenant è la colonna <strong>Group</strong> (non "Tenant"): con un nome diverso
                l'apparato finisce in "Generale". Al salvataggio il file viene riscritto nelle colonne canoniche qui sopra,
                quindi eventuali colonne aggiuntive vengono scartate.
                <br><strong style="color:var(--warning);">Password e Enable Secret</strong> vengono scritte così come sono:
                l'agente le attende cifrate con la propria chiave Fernet, e un valore in chiaro viene ignorato in favore
                delle credenziali di default. Per impostare credenziali reali usa l'inventario locale sull'agente.
            </div>
            <div style="margin-top:8px; display:flex; justify-content:flex-end;">
                <button class="btn btn-sm" data-action="save-inv" data-site-id="${escapeHtml(siteId)}" style="padding:6px 14px; background:var(--warning); color:var(--on-lamp); font-weight:700;">
                    <i class="fa-solid fa-upload"></i> Salva Inventario Remoto
                </button>
            </div>
        </div>

        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:16px;">
            <h4 style="margin:0 0 10px; font-size:13px; color:var(--primary);"><i class="fa-solid fa-screwdriver-wrench"></i> Azioni di Gestione Remota (Checkmk Style)</h4>
            <div style="display:flex; flex-wrap:wrap; gap:10px;">
                <button class="btn btn-sm" data-action="self-update" data-site-id="${escapeHtml(siteId)}" style="background:var(--primary); color:#fff; padding:8px 14px;">
                    <i class="fa-solid fa-rotate"></i> Aggiorna Agente da Git (git pull)
                </button>
                <button class="btn btn-sm btn-secondary" data-action="restart-agent" data-site-id="${escapeHtml(siteId)}" style="padding:8px 14px;">
                    <i class="fa-solid fa-power-off" style="color:var(--warning);"></i> Riavvia Agente
                </button>
            </div>
        </div>

        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px;">
            <h4 style="margin:0 0 8px; font-size:13px; color:var(--text-muted);"><i class="fa-solid fa-list-check"></i> Cronologia Comandi & RPC Accodati</h4>
            <div style="max-height:160px; overflow-y:auto; border:1px solid var(--border); border-radius:0; background:var(--surface-3); padding:4px;">
                ${jobsHtml || '<div style="padding:10px; color:var(--text-muted); font-size:12px;">Nessun comando in cronologia.</div>'}
            </div>
        </div>`;

        // Check if last job was an inventory fetch result to auto-populate textarea.
        // jobs e' DESC (piu' recente per primo), quindi il primo match e' gia'
        // il fetch piu' recente. Il precedente .reverse().find() restituiva il
        // piu' VECCHIO: la textarea veniva precompilata con un inventario
        // obsoleto e un salvataggio avrebbe sovrascritto quello corrente.
        const lastInvJob = jobs.find(j => j.command === '_agent_get_inventory' && j.status === 'done');
        if (lastInvJob && lastInvJob.result) {
            const ta = document.getElementById('agentInventoryTextarea');
            if (ta) ta.value = lastInvJob.result;
        }
    }

    async function triggerAgentSelfUpdate(siteId) {
        if (!confirm(`Confermi di voler inviare il comando 'git pull' per aggiornare l'agente della sede '${siteId}'?`)) return;
        const res = await apiFetch(`/api/sites/${siteId}/agent/update`, { method: 'POST' });
        if (res && res.ok) {
            alert(`Comando di aggiornamento 'git pull' accodato con successo per la sede '${siteId}'. L'agente eseguirà l'aggiornamento al prossimo polling.`);
            openAgentControlModal(siteId);
        } else {
            const err = res ? await res.json() : null;
            alert(`Errore accodamento aggiornamento: ${err ? err.detail : 'Errore sconosciuto'}`);
        }
    }

    async function triggerAgentRestart(siteId) {
        if (!confirm(`Confermi di voler riavviare l'agente della sede '${siteId}'?`)) return;
        const res = await apiFetch(`/api/sites/${siteId}/agent/restart`, { method: 'POST' });
        if (res && res.ok) {
            alert(`Comando di riavvio accodato per la sede '${siteId}'. Systemd riavvierà il servizio in 2 secondi.`);
            openAgentControlModal(siteId);
        } else {
            const err = res ? await res.json() : null;
            alert(`Errore accodamento riavvio: ${err ? err.detail : 'Errore sconosciuto'}`);
        }
    }

    async function triggerAgentConfigSave(siteId) {
        const port = parseInt(document.getElementById('agentCfgSyslogPort').value, 10) || 514;
        const interval = parseInt(document.getElementById('agentCfgInterval').value, 10) || 60;
        const res = await apiFetch(`/api/sites/${siteId}/agent/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ syslog_port: port, interval: interval })
        });
        if (res && res.ok) {
            alert(`Configurazione accodata per la sede '${siteId}' (Syslog Port: ${port}, Interval: ${interval}s).`);
            openAgentControlModal(siteId);
        } else {
            const err = res ? await res.json() : null;
            alert(`Errore salvataggio config: ${err ? err.detail : 'Errore sconosciuto'}`);
        }
    }

    async function fetchAgentInventory(siteId) {
        const res = await apiFetch(`/api/sites/${siteId}/agent/inventory/get`, { method: 'POST' });
        if (res && res.ok) {
            alert(`Comando di lettura inventario network_hosts.csv accodato per '${siteId}'. Aggiorna il modale tra qualche secondo per vedere il contenuto.`);
            openAgentControlModal(siteId);
        } else {
            const err = res ? await res.json() : null;
            alert(`Errore lettura inventario: ${err ? err.detail : 'Errore sconosciuto'}`);
        }
    }

    async function saveAgentInventory(siteId) {
        const content = document.getElementById('agentInventoryTextarea').value;
        if (!content.trim()) { alert('Inserisci il contenuto CSV dell\'inventario.'); return; }
        const res = await apiFetch(`/api/sites/${siteId}/agent/inventory/save`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content: content })
        });
        if (res && res.ok) {
            alert(`Salvataggio inventario locale accodato per la sede '${siteId}'. L'agente applicherà le modifiche al prossimo ciclo.`);
            openAgentControlModal(siteId);
        } else {
            const err = res ? await res.json() : null;
            alert(`Errore salvataggio inventario: ${err ? err.detail : 'Errore sconosciuto'}`);
        }
    }

    function closeAgentControlModal() {
        const modal = document.getElementById('agentControlModal');
        if (modal) modal.style.display = 'none';
    }

    async function toggleAgentDataFlow(siteId, newActiveState) {
        const actionName = newActiveState ? 'riavviare' : 'interrompere';
        if (!confirm(`Confermi di voler ${actionName} il flusso dati per la sede '${siteId}'?`)) return;
        const res = await apiFetch(`/api/sites/${siteId}/agent/flow-control`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ active: newActiveState })
        });
        if (res && res.ok) {
            openAgentControlModal(siteId);
        } else {
            const err = res ? await res.json() : null;
            alert(`Errore gestione flusso: ${err ? err.detail : 'Errore sconosciuto'}`);
        }
    }

    // Delegated click listener for agent control modal
    document.getElementById('agentControlModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'agentControlModal' || e.target.closest('[data-action="close-agent-control-modal"]')) {
            closeAgentControlModal();
        }
    });

    // Same id openAgentControlModal() fills: the delegated listener belongs on
    // the real container, not on a wrapper that does not exist.
    document.getElementById('agentControlBody')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn || !btn.dataset.siteId) return;
        const action = btn.dataset.action;
        const siteId = btn.dataset.siteId;
        if (action === 'toggle-flow') toggleAgentDataFlow(siteId, btn.dataset.active === 'true');
        else if (action === 'save-config') triggerAgentConfigSave(siteId);
        else if (action === 'fetch-inv') fetchAgentInventory(siteId);
        else if (action === 'save-inv') saveAgentInventory(siteId);
        else if (action === 'self-update') triggerAgentSelfUpdate(siteId);
        else if (action === 'restart-agent') triggerAgentRestart(siteId);
    });

    // Expose functions globally for UI buttons
    window.openAgentControlModal = openAgentControlModal;
    window.closeAgentControlModal = closeAgentControlModal;
    window.triggerAgentSelfUpdate = triggerAgentSelfUpdate;
    window.triggerAgentRestart = triggerAgentRestart;
    window.triggerAgentConfigSave = triggerAgentConfigSave;
    window.fetchAgentInventory = fetchAgentInventory;
    window.saveAgentInventory = saveAgentInventory;
    window.toggleAgentDataFlow = toggleAgentDataFlow;
})();
