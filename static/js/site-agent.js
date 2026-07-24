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

        let jobsHtml = jobs.slice(-5).reverse().map(j => {
            const statusCol = j.status === 'done' ? 'var(--success)' : j.status === 'error' ? 'var(--danger)' : 'var(--warning)';
            return `<div style="padding:6px 8px; border-bottom:1px solid var(--border); font-size:12px; display:flex; justify-content:space-between;">
                <span><code>${escapeHtml(j.command)}</code> (Richiesto da: ${escapeHtml(j.requested_by || 'admin')})</span>
                <span style="color:${statusCol}; font-weight:700;">${escapeHtml(j.status)}</span>
            </div>
            ${j.result ? `<pre style="margin:2px 0 8px; padding:6px; background:var(--surface); font-size:11px; max-height:100px; overflow:auto;">${escapeHtml(j.result)}</pre>` : ''}`;
        }).join('');

        body.innerHTML = `
        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:16px;">
            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:10px;">
                <span style="font-weight:700; font-size:14px;">Stato Agente Remoto</span>
                <span class="status ${isOnline ? 'ok' : 'err'}"><span class="led ${isOnline ? 'led-success' : 'led-danger'}"></span>${isOnline ? 'ONLINE' : 'OFFLINE / UNREACHABLE'}</span>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:12px;">
                <div><strong>Ultimo contatto:</strong> ${lastSeen}</div>
                <div><strong>Modalità:</strong> Site Agent (Outbound HTTPS)</div>
                <div><strong>Syslog UDP Listener:</strong> Attivo su porta 514</div>
                <div><strong>Intervallo Sync:</strong> 60s (Syslog streaming 2s)</div>
            </div>
        </div>

        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:16px;">
            <h4 style="margin:0 0 10px; font-size:13px; color:var(--primary);"><i class="fa-solid fa-screwdriver-wrench"></i> Azioni di Gestione Remota (Checkmk Style)</h4>
            <div style="display:flex; flex-wrap:wrap; gap:10px;">
                <button class="btn btn-sm" onclick="triggerAgentSelfUpdate('${escapeHtml(siteId)}')" style="background:var(--primary); color:#fff; padding:8px 14px;">
                    <i class="fa-solid fa-rotate"></i> Aggiorna Agente da Git (git pull)
                </button>
                <button class="btn btn-sm btn-secondary" onclick="triggerAgentRestart('${escapeHtml(siteId)}')" style="padding:8px 14px;">
                    <i class="fa-solid fa-power-off" style="color:var(--warning);"></i> Riavvia Agente
                </button>
            </div>
        </div>

        <div style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:14px;">
            <h4 style="margin:0 0 8px; font-size:13px; color:var(--text-muted);"><i class="fa-solid fa-list-check"></i> Cronologia Comandi & RPC Accodati</h4>
            <div style="max-height:160px; overflow-y:auto; border:1px solid var(--border); border-radius:6px; background:var(--surface-3); padding:4px;">
                ${jobsHtml || '<div style="padding:10px; color:var(--text-muted); font-size:12px;">Nessun comando in cronologia.</div>'}
            </div>
        </div>`;
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

    function closeAgentControlModal() {
        const modal = document.getElementById('agentControlModal');
        if (modal) modal.style.display = 'none';
    }

    // Expose functions globally for UI buttons
    window.openAgentControlModal = openAgentControlModal;
    window.closeAgentControlModal = closeAgentControlModal;
    window.triggerAgentSelfUpdate = triggerAgentSelfUpdate;
    window.triggerAgentRestart = triggerAgentRestart;
})();
