// static/js/redundancy.js
// ===== High Availability & Redundancy Groups (HA) =====

(function () {
    // Every group carries the tenant that owns it, and the API already scopes
    // the list to what the user may see. The full list is kept here so the
    // tenant filter never has to hit the network again.
    let allRedundancyGroups = [];

    const tenantOf = (g) => g.group_name || 'default';

    function healthBucket(g) {
        const h = (g.health || '').toLowerCase();
        if (h === 'healthy' || h === 'ok') return 'healthy';
        if (h === 'degraded' || h === 'warning') return 'degraded';
        return 'critical';
    }

    async function loadRedundancyTab() {
        const container = document.getElementById('redundancyGroupsContainer');
        if (!container) return;
        container.innerHTML = `<div style="text-align:center; padding:30px;"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><p style="margin-top:10px; color:var(--text-muted); font-size:13px;">Caricamento gruppi di ridondanza e cluster HA...</p></div>`;

        try {
            const res = await apiFetch('/api/redundancy/groups');
            if (!res || !res.ok) {
                container.innerHTML = `<div class="alert-box alert-danger">Impossibile caricare i gruppi di ridondanza.</div>`;
                return;
            }
            const data = await res.json();
            allRedundancyGroups = data.results || [];
            populateTenantFilter(allRedundancyGroups);
            applyRedundancyFilter();
        } catch (e) {
            container.innerHTML = `<div class="alert-box alert-danger">${escapeHtml(e.message)}</div>`;
        }
    }

    function populateTenantFilter(groups) {
        const sel = document.getElementById('haTenantFilter');
        if (!sel) return;
        const previous = sel.value;
        const tenants = Array.from(new Set(groups.map(tenantOf))).sort();
        // Option 0 ("all tenants") lives in the template and carries its
        // data-i18n: rebuilding it here would drop its translation.
        sel.length = 1;
        tenants.forEach(t => sel.add(new Option(t, t)));
        // A refresh must not silently widen the view back to every tenant, but
        // a tenant whose last group just disappeared has no option left.
        sel.value = tenants.includes(previous) ? previous : '';
    }

    function applyRedundancyFilter() {
        const sel = document.getElementById('haTenantFilter');
        const tenant = sel ? sel.value : '';
        const groups = tenant
            ? allRedundancyGroups.filter(g => tenantOf(g) === tenant)
            : allRedundancyGroups;
        renderRedundancyGroups(groups, tenant);
        // The KPIs describe what is on screen: leaving them on the whole fleet
        // while the list shows one tenant is how a degraded cluster gets
        // attributed to the wrong customer.
        updateRedundancyKpis(groups);
    }

    function updateRedundancyKpis(groups) {
        let healthy = 0, degraded = 0, critical = 0;
        groups.forEach(g => {
            const bucket = healthBucket(g);
            if (bucket === 'healthy') healthy++;
            else if (bucket === 'degraded') degraded++;
            else critical++;
        });
        const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        setText('haKpiTotal', groups.length);
        setText('haKpiHealthy', healthy);
        setText('haKpiDegraded', degraded);
        setText('haKpiCritical', critical);
    }

    function renderRedundancyGroups(groups, activeTenant) {
        const container = document.getElementById('redundancyGroupsContainer');
        if (!container) return;

        if (groups.length === 0) {
            // An empty tenant is not an empty install: offering "create your
            // first group" to someone who just filtered would read as data loss.
            container.innerHTML = activeTenant ? `
                <div class="panel" style="text-align:center; padding:40px;">
                    <i class="fa-solid fa-filter-circle-xmark" style="font-size:36px; color:var(--text-muted); margin-bottom:12px;"></i>
                    <h3 style="margin-bottom:8px; font-size:16px;">Nessun gruppo di ridondanza per il tenant «${escapeHtml(activeTenant)}»</h3>
                    <p style="color:var(--text-muted); font-size:13px; max-width:500px; margin:0 auto;">
                        Scegli «Tutti i tenant» per vedere gli altri cluster.
                    </p>
                </div>
            ` : `
                <div class="panel" style="text-align:center; padding:40px;">
                    <i class="fa-solid fa-layer-group" style="font-size:36px; color:var(--text-muted); margin-bottom:12px;"></i>
                    <h3 style="margin-bottom:8px; font-size:16px;">Nessun gruppo di ridondanza registrato</h3>
                    <p style="color:var(--text-muted); font-size:13px; max-width:500px; margin:0 auto 16px;">
                        Crea un gruppo per monitorare cluster HSRP, VRRP, FortiGate HA (FGCP), Cisco StackWise o coppie VPC/MLAG.
                    </p>
                    ${typeof currentRole !== 'undefined' && currentRole === 'admin' ? `
                    <button class="btn btn-primary" data-action="open-create-redundancy" style="width:auto; margin:0 auto;">
                        <i class="fa-solid fa-plus"></i> Crea Gruppo HA
                    </button>` : ''}
                </div>
            `;
            return;
        }

        const byTenant = new Map();
        groups.forEach(g => {
            const t = tenantOf(g);
            if (!byTenant.has(t)) byTenant.set(t, []);
            byTenant.get(t).push(g);
        });

        container.innerHTML = Array.from(byTenant.keys()).sort()
            .map(t => renderTenantSection(t, byTenant.get(t))).join('');
    }

    function renderTenantSection(tenant, groups) {
        const unhealthy = groups.filter(g => healthBucket(g) !== 'healthy').length;
        const alertChip = unhealthy ? `
            <span class="chip" style="font-size:10px; color:var(--warning); border-color:var(--warning);">
                <i class="fa-solid fa-triangle-exclamation" style="margin-right:4px;"></i>${unhealthy} da verificare
            </span>` : '';

        return `
            <section style="margin-bottom:24px;">
                <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:12px; padding-bottom:6px; border-bottom:1px solid var(--border);">
                    <i class="fa-solid fa-building" style="color:var(--text-muted); font-size:12px;"></i>
                    <h4 style="margin:0; font-size:13px; text-transform:uppercase; letter-spacing:.06em;">${escapeHtml(tenant)}</h4>
                    <span class="chip" style="font-size:10px;">${groups.length} cluster</span>
                    ${alertChip}
                </div>
                <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(340px, 1fr)); gap:18px;">
                    ${groups.map(g => renderRedundancyCard(g)).join('')}
                </div>
            </section>
        `;
    }

    function renderRedundancyCard(g) {
        const health = (g.health || 'unknown').toLowerCase();
        const isHealthy = health === 'healthy' || health === 'ok';
        const isDegraded = health === 'degraded' || health === 'warning';
        const healthBadge = isHealthy ?
            `<span class="status ok"><span class="led led-success"></span>HEALTHY</span>` :
            (isDegraded ? `<span class="status warn"><span class="led led-warning"></span>DEGRADED</span>` : `<span class="status bad"><span class="led led-danger"></span>CRITICAL</span>`);

        const isStack = g.group_type === 'stack' || (g.protocol || '').toLowerCase().includes('stack');
        const protoLabel = g.protocol || (isStack ? 'Cisco StackWise'
            : g.group_type === 'ha_pair' ? 'HA Pair'
            : g.group_type === 'sso' ? 'Cisco HA SSO'
            : (g.group_type || 'HA'));

        const members = (g.members || []).map((m, idx) => {
            const isMaster = (m.role || '').toLowerCase().includes('master') || (m.role || '').toLowerCase().includes('active') || (m.state || '').toLowerCase().includes('active') || (m.role || '').toLowerCase().includes('primary');
            const roleIcon = isMaster ? '<i class="fa-solid fa-crown" style="color:var(--warning); margin-right:5px;" title="Master / Active"></i>' : '<i class="fa-solid fa-shield" style="color:var(--text-muted); margin-right:5px;" title="Member / Standby"></i>';

            let memberLabel = '';
            if (isStack || (m.member_index !== null && m.member_index !== undefined)) {
                const unitNum = (m.member_index !== null && m.member_index !== undefined) ? m.member_index : (idx + 1);
                memberLabel = `Switch #${unitNum}`;
                if (m.device_ip && m.device_ip !== g.logical_device_ip) {
                    memberLabel += ` (${m.device_ip})`;
                }
            } else {
                memberLabel = m.device_ip || m.mgmt_ip || `Membro #${idx + 1}`;
            }

            const modelBadge = m.model ? `<span style="color:var(--text-muted); font-size:11px; font-weight:normal; margin-left:4px;">${escapeHtml(m.model)}</span>` : '';
            const ifaceBadge = m.interface ? `<span style="color:var(--text-muted); font-size:11px; margin-left:4px;">(${escapeHtml(m.interface)})</span>` : '';

            const serialBadge = m.serial ? `
                <div style="display:inline-flex; align-items:center; gap:4px; font-size:11px; margin-top:2px;">
                    <span style="color:var(--text-muted); font-size:10px; text-transform:uppercase; letter-spacing:.03em;"><i class="fa-solid fa-barcode" style="margin-right:2px; font-size:10px; opacity:0.8;"></i>S/N:</span>
                    <code style="font-family:var(--font-code); font-size:11px; color:var(--text); background:var(--surface-2); padding:1px 5px; border-radius:3px; border:1px solid var(--border);">${escapeHtml(m.serial)}</code>
                </div>
            ` : (isStack ? `
                <div style="display:inline-flex; align-items:center; gap:4px; font-size:11px; margin-top:2px; color:var(--text-muted);">
                    <span style="font-size:10px; text-transform:uppercase; letter-spacing:.03em;"><i class="fa-solid fa-barcode" style="margin-right:2px; font-size:10px; opacity:0.6;"></i>S/N:</span>
                    <span style="font-size:10px; font-style:italic;">Non rilevato</span>
                </div>
            ` : '');

            return `<div style="display:flex; justify-content:space-between; align-items:flex-start; padding:8px 0; border-bottom:1px solid var(--border); font-size:12px; gap:8px;">
                <div style="display:flex; flex-direction:column; gap:2px; min-width:0;">
                    <div style="display:flex; align-items:center; flex-wrap:wrap; gap:4px;">
                        ${roleIcon}<strong>${escapeHtml(memberLabel)}</strong>
                        ${modelBadge}
                        ${ifaceBadge}
                    </div>
                    ${serialBadge}
                </div>
                <div style="display:flex; gap:6px; align-items:center; flex-shrink:0; margin-top:2px;">
                    <span class="chip" style="font-size:10px; font-family:var(--font-code);">${escapeHtml(m.role || m.state || 'member')}</span>
                    ${m.priority !== undefined && m.priority !== null ? `<span style="font-size:11px; color:var(--text-muted); font-family:var(--font-code);">Prio: ${m.priority}</span>` : ''}
                    ${m.state && m.state !== 'ready' && m.state !== 'active' ? `<span class="chip" style="font-size:10px; font-family:var(--font-code); color:var(--danger); border-color:var(--danger);">${escapeHtml(m.state)}</span>` : ''}
                </div>
            </div>`;
        }).join('') || `<div style="color:var(--text-muted); font-size:12px; padding:6px 0;">Nessun membro associato.</div>`;

        return `
            <div class="panel" style="display:flex; flex-direction:column; justify-content:space-between;">
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
                        <div>
                            <h4 style="margin:0 0 4px; font-size:15px; color:var(--text);">${escapeHtml(g.name || g.group_name || 'Gruppo HA')}</h4>
                            <span style="font-size:11px; color:var(--text-muted);">${escapeHtml(protoLabel)} | Tenant: <strong>${escapeHtml(g.group_name || 'default')}</strong></span>
                        </div>
                        ${healthBadge}
                    </div>

                    ${g.virtual_ip ? `
                    <div style="background:var(--surface-2); border:1px solid var(--border); padding:6px 10px; margin-bottom:12px; font-size:12px;">
                        <span style="color:var(--text-muted);">VIP:</span> <code style="color:var(--primary); font-weight:700; font-family:var(--font-code);">${escapeHtml(g.virtual_ip)}</code>
                    </div>` : ''}

                    ${g.logical_device_ip ? `
                    <div style="background:var(--surface-2); border:1px solid var(--border); padding:6px 10px; margin-bottom:12px; font-size:12px;">
                        <span style="color:var(--text-muted);">IP Switch / Stack:</span> <code style="color:var(--primary); font-weight:700; font-family:var(--font-code);">${escapeHtml(g.logical_device_ip)}</code>
                    </div>` : ''}

                    <div style="margin-bottom:14px;">
                        <h5 style="margin:0 0 6px; font-size:11px; text-transform:uppercase; color:var(--text-muted); letter-spacing:.05em;">Membri del Cluster</h5>
                        ${members}
                    </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid var(--border); padding-top:10px; margin-top:8px;">
                    <span style="font-size:10px; color:var(--text-muted);">${g.detection_source ? `Fonte: ${escapeHtml(g.detection_source)}` : ''}</span>
                    ${typeof currentRole !== 'undefined' && currentRole === 'admin' ? `
                    <button class="btn btn-secondary btn-small" data-action="delete-redundancy" data-group-id="${g.id}" style="color:var(--danger); width:auto;" title="Elimina gruppo">
                        <i class="fa-solid fa-trash"></i>
                    </button>` : ''}
                </div>
            </div>
        `;
    }

    function openCreateRedundancyModal() {
        const modal = document.getElementById('createRedundancyModal');
        if (modal) modal.style.display = 'flex';
    }

    function closeCreateRedundancyModal() {
        const modal = document.getElementById('createRedundancyModal');
        if (modal) modal.style.display = 'none';
    }

    async function submitCreateRedundancyGroup() {
        const nameEl = document.getElementById('haGroupName');
        const protoEl = document.getElementById('haProtocol');
        const vipEl = document.getElementById('haVirtualIp');
        const tenantEl = document.getElementById('haTenant');

        const name = nameEl ? nameEl.value.trim() : '';
        const protocol = protoEl ? protoEl.value : 'HSRP';
        const vip = vipEl ? vipEl.value.trim() : '';
        const tenant = tenantEl ? tenantEl.value.trim() || 'default' : 'default';

        if (!name) {
            showToast('Inserisci un nome per il gruppo di ridondanza', 'warning');
            return;
        }

        const groupType = (protocol === 'StackWise') ? 'stack' : (protocol === 'SSO' ? 'sso' : 'ha_pair');

        try {
            const res = await apiFetch('/api/redundancy/groups', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: name,
                    group_name: tenant,
                    group_type: groupType,
                    virtual_ip: groupType === 'ha_pair' ? (vip || null) : null,
                    logical_device_ip: groupType === 'stack' ? (vip || null) : null,
                    detection_source: 'manual',
                    members: []
                })
            });
            if (!res || !res.ok) {
                const errData = res ? await res.json().catch(() => ({})) : {};
                showToast(errData.detail || 'Errore durante la creazione del gruppo HA', 'error');
                return;
            }
            showToast('Gruppo HA creato con successo!', 'ok');
            if (nameEl) nameEl.value = '';
            if (vipEl) vipEl.value = '';
            closeCreateRedundancyModal();
            loadRedundancyTab();
        } catch (e) {
            showToast('Errore: ' + e.message, 'error');
        }
    }

    async function deleteRedundancyGroup(id) {
        if (!confirm(`Sei sicuro di voler eliminare il gruppo di ridondanza #${id}?`)) return;

        try {
            const res = await apiFetch(`/api/redundancy/groups/${id}`, { method: 'DELETE' });
            if (!res || !res.ok) {
                showToast('Impossibile eliminare il gruppo HA', 'error');
                return;
            }
            showToast('Gruppo HA eliminato con successo.', 'ok');
            loadRedundancyTab();
        } catch (e) {
            showToast('Errore: ' + e.message, 'error');
        }
    }

    // Delegated click handler for tab actions
    document.addEventListener('click', (e) => {
        const btnOpen = e.target.closest('[data-action="open-create-redundancy"]');
        if (btnOpen) {
            e.preventDefault();
            openCreateRedundancyModal();
            return;
        }

        const btnClose = e.target.closest('[data-action="close-create-redundancy"]');
        if (btnClose) {
            e.preventDefault();
            closeCreateRedundancyModal();
            return;
        }

        const btnRefresh = e.target.closest('[data-action="refresh-redundancy"]');
        if (btnRefresh) {
            e.preventDefault();
            loadRedundancyTab();
            return;
        }

        const btnDel = e.target.closest('[data-action="delete-redundancy"]');
        if (btnDel) {
            e.preventDefault();
            const id = btnDel.getAttribute('data-group-id');
            if (id) deleteRedundancyGroup(id);
            return;
        }

        const btnSubmit = e.target.closest('#btnSubmitCreateRedundancy');
        if (btnSubmit) {
            e.preventDefault();
            submitCreateRedundancyGroup();
            return;
        }

        const modalBackdrop = document.getElementById('createRedundancyModal');
        if (modalBackdrop && e.target === modalBackdrop) {
            closeCreateRedundancyModal();
        }
    });

    document.addEventListener('change', (e) => {
        if (e.target && e.target.id === 'haTenantFilter') applyRedundancyFilter();
    });

    window.loadRedundancyTab = loadRedundancyTab;
    window.openCreateRedundancyModal = openCreateRedundancyModal;
    window.closeCreateRedundancyModal = closeCreateRedundancyModal;
    window.submitCreateRedundancyGroup = submitCreateRedundancyGroup;
    window.deleteRedundancyGroup = deleteRedundancyGroup;
})();
