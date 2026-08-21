// static/js/devices.js
// Estratto da templates/dashboard.html: tab-devices (Inventario dispositivi),
// tab-groups (Gruppi/Tenant), Vendor CRUD, triage on-demand/di gruppo, subnet
// scanner in background e CSV import/export. Globals di stato scoping
// triage/scan/device-edit (isTriagePolling, editingDeviceIp, wasTriageRunning,
// _scanJobInterval, pingInProgress) vivono qui perche' usati solo da questo
// modulo.
//
// updateTopologyMapNodeStatus (Visio overlay) belongs to topology.js, which
// core.js lazy-loads only for the map and categories tabs. Calling it bare
// from here is a ReferenceError whenever the user has not opened one of those
// tabs first, so every call goes through setMapNodeStatus below, which treats
// the map overlay as optional. Do not "simplify" it back to a direct call.

    // Globals di stato per triage/scan/device-edit, scoped a questo modulo.
    let isTriagePolling = false;
    let editingDeviceIp = null;   // §11.5b: IP del dispositivo in modifica (null = modalità aggiunta)
    let wasTriageRunning = false;
    let _scanJobInterval = null;

    // Solo i NOMI dei tenant con un default: la community non arriva mai al
    // browser, quindi la tabella puo' dire "configurata" e nient'altro.
    let snmpDefaultTenants = [];

    async function loadSnmpDefaults() {
        const res = await apiFetch('/api/settings/snmp-defaults');
        if (!res || !res.ok) return;
        snmpDefaultTenants = (await res.json()).tenants || [];
        renderGroupsTable();
    }

    async function setTenantSnmp(tenant) {
        const L = i18n[currentLang];
        const value = prompt(L.promptTenantSnmp, '');
        if (value === null) return;               // annullato: non toccare nulla
        const res = await apiFetch('/api/settings/snmp-defaults', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant: tenant, community: value })
        });
        if (res && res.ok) loadSnmpDefaults();
    }

    function renderGroupsTable() {
        const groupBody = document.getElementById('groupsTableBody');
        if (!groupBody) return;
        groupBody.innerHTML = '';
        Object.keys(globalGroups).forEach(g => {
            let desc = globalGroups[g].description || "Tenant";
            if (desc === "Sede Principale predefinita") {
                desc = currentLang === 'en' ? "Default Main Tenant" : "Tenant principale";
            } else if (desc.startsWith("Sede secondaria ")) {
                const nm = desc.slice("Sede secondaria ".length);
                desc = (currentLang === 'en' ? "Secondary Tenant " : "Tenant secondario ") + nm;
            }
            const btnText = currentLang === 'en' ? '<i class="fa-solid fa-trash-can"></i> Delete Tenant' : '<i class="fa-solid fa-trash-can"></i> Elimina Tenant';
            const renameText = currentLang === 'en' ? '<i class="fa-solid fa-pen"></i> Rename' : '<i class="fa-solid fa-pen"></i> Rinomina';
            const reservedText = currentLang === 'en' ? 'System Reserved' : 'System Reserved';
            const renameBtn = (g !== 'Generale')
                ? `<button data-action="rename-group" data-g="${escapeHtml(g)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:12px;">${renameText}</button>` : '';

            const hasSnmp = snmpDefaultTenants.includes(g);
            const snmpCell = `<td>
                <span style="font-size:11px; color:${hasSnmp ? 'var(--success)' : 'var(--text-muted)'}; border:1px solid ${hasSnmp ? 'var(--success)' : 'var(--border)'}; border-radius:0; padding:1px 6px;">
                    ${hasSnmp ? (currentLang === 'en' ? 'configured' : 'configurata')
                              : (currentLang === 'en' ? 'not set' : 'non impostata')}</span>
                ${currentRole === 'admin'
                    ? `<button data-action="set-tenant-snmp" data-g="${escapeHtml(g)}" style="margin-left:8px; color:var(--primary); background:none; border:none; cursor:pointer;">${i18n[currentLang].btnSetTenantSnmp}</button>`
                    : ''}</td>`;

            groupBody.innerHTML += `<tr>
                <td><strong>${escapeHtml(g)}</strong></td>
                <td><span style="color:var(--text-muted); font-size:13px;">${escapeHtml(desc)}</span></td>
                ${snmpCell}
                <td>${currentRole === 'viewer'
                    ? '<span style="color:var(--text-muted)">—</span>'
                    : (g !== 'Generale' ? `${renameBtn}<button data-action="delete-group" data-g="${escapeHtml(g)}" style="color:var(--danger); background:none; border:none; cursor:pointer;">${btnText}</button>` : reservedText)}</td>
            </tr>`;
        });
    }

    document.getElementById('groupsTableBody')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;
        const g = btn.dataset.g;
        if (action === 'rename-group') renameGroup(g);
        else if (action === 'set-tenant-snmp') setTenantSnmp(g);
        else if (action === 'delete-group') deleteGroup(g);
    });

    // KPI row sopra la tabella inventario: conteggi sull'intera flotta (non filtrati
    // da ricerca/tenant), stessa mappatura stato->led usata per le righe della tabella.
    // A jump-site device has no ICMP, but the SSH triage does reach it through
    // the bastion and its outcome is persisted (detected_versions, written by
    // update_version_inventory). So "not measurable" applies only until that
    // outcome exists: showing the em dash regardless threw the triage result
    // away on every re-render, and the ONLINE the triage had just painted
    // vanished as soon as the user left the tab and came back.
    function jumpStatusIsUnmeasurable(d) {
        if (d.icmp_reachable !== false) return false;
        const st = (globalVersions[d.IP] || {}).status;
        return !st || st === 'unknown';
    }

    function updateInventoryKpis() {
        let online = 0, offline = 0, authFailed = 0, unknown = 0;
        (globalDevices || []).forEach(d => {
            // Jump site: same "not measurable" bucket as the row's em dash
            // (icmp_reachable is set per-device by /api/local-devices, Task 4's
            // has_direct_path). Without this branch a jump-site device
            // that has never been triaged falls into `else offline++` and the
            // "Offline: N" tile contradicts the row directly below it.
            if (jumpStatusIsUnmeasurable(d)) { unknown++; return; }
            const scan = globalVersions[d.IP] || {};
            if (scan.status === 'online') online++;
            else if (scan.status === 'auth_failed') authFailed++;
            else offline++;
        });
        const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
        setText('invKpiOnline', online);
        setText('invKpiOffline', offline);
        setText('invKpiAuthFailed', authFailed);
        setText('invKpiUnknown', unknown);
    }

    function renderDeviceTable() {
        updateInventoryKpis();

        // The Sede column needs the site list, and every caller of this
        // function is synchronous. Fetch it once in the background and repaint
        // when it lands; until then each row offers only its own site, so the
        // table is never blocked on the request.
        if (_sitesCache === null) loadDeviceSites().then(renderDeviceTable);

        const filterSelect  = document.getElementById('filterGroupSelect');
        const selectedGroup = filterSelect ? filterSelect.value : 'all';

        const devBody = document.getElementById('deviceTableBody');
        if (!devBody) return;

        const term = (document.getElementById('deviceSearch')?.value || '').trim().toLowerCase();
        const isViewer = currentRole === 'viewer';

        devBody.innerHTML = '';
        globalDevices.forEach(d => {
            if (selectedGroup !== 'all' && d.Group !== selectedGroup) return;

            const scan = globalVersions[d.IP] || { version: currentLang === 'en' ? "Not Scanned" : "Non Scansionato", status: "unknown" };

            // Barra di ricerca: filtra su IP, hostname, vendor, gruppo, versione, stato
            if (term) {
                const haystack = [d.IP, d.Hostname, d.Vendor, d.Group, d.Site, scan.version, scan.status]
                    .map(x => (x || '').toString().toLowerCase()).join(' ');
                if (!haystack.includes(term)) return;
            }

            let ledClass = "led-offline";
            if (scan.status === "online")           ledClass = "led-online";
            else if (scan.status === "auth_failed") ledClass = "led-auth_failed";

            // Jump site: ICMP cannot cross the bastion tunnel, so any "offline"
            // here would be a ping that never ran, not a real down (Task 4's
            // has_direct_path, surfaced per-device as icmp_reachable by
            // /api/local-devices). Show the same "not measurable" em dash used
            // elsewhere instead of a misleading led.
            const isJumpUnmeasurable = jumpStatusIsUnmeasurable(d);

            const siteOptions = (current) => (_sitesCache || []).map(st => {
                const mode = st.mode === 'jump' ? ' [bastion]' : (st.mode === 'agent' ? ' [agent]' : '');
                return `<option value="${escapeHtml(st.id)}" ${st.id === current ? 'selected' : ''}>${
                    escapeHtml(st.name || st.id)}${escapeHtml(mode)}</option>`;
            }).join('') || `<option value="${escapeHtml(current)}" selected>${escapeHtml(current)}</option>`;

            const groupOptions = Object.keys(globalGroups).map(g =>
                `<option value="${escapeHtml(g)}" ${g === d.Group ? "selected" : ""}>${escapeHtml(g)}</option>`
            ).join("");
            const safeIp = d.IP.replace(/\./g, "_");

            let versionText = scan.version;
            if (currentLang === 'en') {
                if (versionText === 'Non Scansionato') versionText = 'Not Scanned';
                if (versionText === 'Non Rilevata') versionText = 'Not Detected';
            }

            const deleteText = currentLang === 'en' ? 'Delete' : 'Elimina';

            devBody.innerHTML += `<tr>
                <td>
                  ${isJumpUnmeasurable
                    ? `<span class="led-container" title="${escapeHtml(i18n[currentLang].jumpLimitsPing)}">—</span>`
                    : `<span class="led-container">
                    <span class="led ${ledClass}"></span>
                    ${scan.status.toUpperCase()}
                  </span>`}
                </td>
                <td>
                  <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
                    ${/* Il badge duplicava la select: chi puo' cambiare tenant lo
                          legge gia' dalla select, al viewer resta il solo badge. */''}
                    ${isViewer ? `<span class="badge" id="badge_${safeIp}">${escapeHtml(d.Group)}</span>` : ''}
                    ${isViewer ? '' : `<select
                      id="grpsel_${safeIp}"
                      data-action="reassign-device"
                      data-ip="${escapeHtml(d.IP)}"
                      title="${currentLang==='en'?'Move to another tenant without deleting':'Sposta in un altro tenant senza eliminare'}"
                      style="font-size:11px; padding:3px 6px; border-radius:0;
                             border:1px solid var(--border); background:var(--surface-3);
                             color:var(--text-muted); cursor:pointer; outline:none;
                             max-width:120px; transition:var(--transition);">
                      ${groupOptions}
                    </select>`}
                  </div>
                </td>
                <td>${isViewer
                  ? `<span class="badge" style="background:var(--surface-3); color:var(--text-muted);">${escapeHtml(d.Site || 'central')}</span>`
                  : `<select
                      data-action="reassign-device-site"
                      data-ip="${escapeHtml(d.IP)}"
                      title="${currentLang==='en'?'Move to another site (changes how the device is reached)':"Sposta in un'altra sede (cambia come si raggiunge l'apparato)"}"
                      style="font-size:11px; padding:3px 6px; border-radius:0;
                             border:1px solid var(--border); background:var(--surface-3);
                             color:var(--text-muted); cursor:pointer; outline:none;
                             max-width:130px; transition:var(--transition);">
                      ${siteOptions(d.Site || 'central')}
                    </select>`}</td>
                <td style="font-family:monospace; font-size:12px; white-space:nowrap;">
                  ${d.Hostname ? escapeHtml(d.Hostname) : '<span style="color:var(--text-muted)">—</span>'}
                  ${isViewer ? '' : `<button data-action="rename-device" data-ip="${escapeHtml(d.IP)}"
                      title="${currentLang==='en'?'Rename device':'Rinomina dispositivo'}"
                      style="margin-left:6px; font-size:11px; cursor:pointer; border:none; background:none;
                             color:var(--text-muted); padding:0;">
                      <i class="fa-solid fa-pen"></i></button>`}
                </td>
                <td><strong>${d.IP}</strong></td>
                <td>${d.Vendor
                    ? escapeHtml(d.Vendor.toUpperCase())
                    : `<span style="color:var(--warning); font-style:italic;" title="${
                        escapeHtml(currentLang === 'en'
                            ? 'No vendor set: backup and triage will fail until you edit this device.'
                            : "Vendor non impostato: backup e triage falliranno finche' non modifichi il dispositivo.")
                      }">${escapeHtml(currentLang === 'en' ? 'not set' : 'non impostato')}</span>`}</td>
                <td style="white-space:nowrap;"><code>${escapeHtml(versionText)}</code></td>
                <td class="actions-cell">
                    ${isViewer ? '<span style="color:var(--text-muted)">—</span>' : `
                    <button class="btn btn-secondary btn-small"
                        style="margin:0; padding:4px 8px;"
                        data-action="ping-device"
                        data-ip="${escapeHtml(d.IP)}"
                        title="${currentLang==='en'?'Ping device':'Ping dispositivo'}">
                      <i class="fa-solid fa-wifi"></i>
                    </button>
                    <button class="btn btn-secondary btn-small"
                        style="margin:0; padding:4px 8px; color:var(--warning);"
                        data-action="triage-device"
                        data-ip="${escapeHtml(d.IP)}"
                        title="${currentLang==='en'?'Triage device':'Triage dispositivo'}">
                      <i class="fa-solid fa-bolt-lightning"></i>
                    </button>
                    <button class="btn btn-secondary btn-small" style="margin:0; padding:4px 8px;"
                        data-action="open-cli"
                        data-ip="${escapeHtml(d.IP)}">
                        <i class="fa-solid fa-terminal"></i> CLI
                    </button>
                    <button class="btn btn-secondary btn-small" style="margin:0; padding:4px 8px;"
                        data-action="edit-device"
                        data-ip="${escapeHtml(d.IP)}"
                        title="${currentLang==='en'?'Edit device':'Modifica dispositivo'}">
                        <i class="fa-solid fa-pen"></i> ${currentLang==='en'?'Edit':'Modifica'}
                    </button>
                    <button class="btn btn-primary btn-small"
                        style="margin:0; width:auto; background:var(--cta); color:var(--cta-text); padding:4px 8px;"
                        data-action="download-backup"
                        data-ip="${escapeHtml(d.IP)}">
                        <i class="fa-solid fa-download"></i>
                    </button>
                    <button class="btn btn-danger btn-small"
                        style="margin:0; padding:4px 8px; background:none; border:none;
                               color:var(--danger); cursor:pointer;"
                        data-action="delete-device"
                        data-ip="${escapeHtml(d.IP)}">
                        <i class="fa-solid fa-trash-can"></i> ${deleteText}
                    </button>`}
                </td>
            </tr>`;
        });

        // Stato vuoto: guida l'utente invece di mostrare una tabella nuda
        if (!devBody.children.length) {
            const msg = globalDevices.length === 0
                ? i18n[currentLang].emptyInventory
                : i18n[currentLang].emptyInventoryFiltered;
            devBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:32px; color:var(--text-muted); font-size:13px;">
                <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${msg}
            </td></tr>`;
        }
    }

    document.getElementById('deviceTableBody')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;
        const ip = btn.dataset.ip;
        if (action === 'open-cli') openCliModal(ip);
        else if (action === 'edit-device') editDevice(ip);
        else if (action === 'delete-device') deleteDevice(ip);
        else if (action === 'ping-device') pingSingleDevice(ip, btn);
        else if (action === 'triage-device') triageSingleDevice(ip, btn);
        else if (action === 'rename-device') renameDevice(ip);
        else if (action === 'download-backup') downloadBackup(ip);
    });

    document.getElementById('deviceTableBody')?.addEventListener('change', (e) => {
        const siteSel = e.target.closest('select[data-action="reassign-device-site"]');
        if (siteSel && siteSel.dataset.ip) {
            reassignDeviceSite(siteSel.dataset.ip, siteSel.value, siteSel);
            return;
        }
        const sel = e.target.closest('select[data-action="reassign-device"]');
        if (sel && sel.dataset.ip) {
            reassignDevice(sel.dataset.ip, sel.value, sel);
        }
    });

    // --- DEVICE CRUD ---

    document.getElementById('devProfile').addEventListener('change', (e) => {
        document.getElementById('customCredsForm').style.display = e.target.value === 'custom' ? 'block' : 'none';
    });

    // Toggle inline "+ nuovo tenant" row accanto a devGroupSelect.
    document.getElementById('btnInlineNewTenant').addEventListener('click', () => {
        const row = document.getElementById('inlineNewTenantRow');
        row.style.display = row.style.display === 'flex' ? 'none' : 'flex';
    });

    // Validazione IP inline + hint duplicato con link rapido a modifica.
    document.getElementById('devIp').addEventListener('input', () => {
        const v = document.getElementById('devIp').value.trim();
        const hint = document.getElementById('devIpHint');
        const ipRe = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!v) { hint.style.display = 'none'; return; }
        if (!ipRe.test(v) || v.split('.').some(o => +o > 255)) {
            hint.style.display = 'block'; hint.style.color = 'var(--danger)';
            hint.innerHTML = i18n[currentLang].hintIpInvalid;
            return;
        }
        const existing = (globalDevices || []).find(d => d.IP === v);
        if (existing && !editingDeviceIp) {
            hint.style.display = 'block'; hint.style.color = 'var(--warning)';
            hint.innerHTML = `${i18n[currentLang].hintIpExists} <a href="#" data-action="edit-device-hint" data-ip="${escapeHtml(v)}">${i18n[currentLang].hintIpEditLink}</a>`;
        } else { hint.style.display = 'none'; }
    });

    document.getElementById('devIpHint')?.addEventListener('click', (e) => {
        const a = e.target.closest('[data-action="edit-device-hint"]');
        if (a && a.dataset.ip) {
            e.preventDefault();
            editDevice(a.dataset.ip);
        }
    });

    // devGroupSelect change listener + IDENTITIES CRUD (renderIdentitiesPanel/
    // editIdentity/deleteIdentity/btnNewIdentity/btnCancelIdentity/btnSaveIdentity):
    // MOVED to static/js/provisioning.js.
    // refreshIdentityOptions/renderIdentitiesPanel: MOVED to static/js/core.js
    // (shared with editDevice below and with the Groups tab's btnCreateGroup handler).

    // §11.6: gestione trasporti per-device (checkbox + porta per protocollo).
    const TRANSPORT_PROTOS = ['ssh', 'telnet', 'netconf', 'restconf', 'tcp', 'udp'];
    const TRANSPORT_LABELS = { ssh: 'SSH', telnet: 'Telnet', netconf: 'NETCONF', restconf: 'RESTCONF', tcp: 'TCP', udp: 'UDP' };
    const _trCap = (p) => p.charAt(0).toUpperCase() + p.slice(1);

    function updateTelnetWarn() {
        const on = document.getElementById('trTelnetEnabled').checked;
        document.getElementById('trTelnetWarn').style.display = on ? 'block' : 'none';
    }

    // Riepilogo mostrato nel <summary> del pannello collassabile #devTransports
    // (es. "SSH:22, NETCONF:830"), tenuto allineato ad ogni modifica di
    // checkbox/porta. Nessun data-i18n qui dentro: i nomi dei protocolli non
    // si traducono, quindi changeLanguage() non deve toccare questo nodo.
    function updateTransportsSummary() {
        const parts = [];
        for (const p of TRANSPORT_PROTOS) {
            if (!document.getElementById('tr' + _trCap(p) + 'Enabled').checked) continue;
            const port = document.getElementById('tr' + _trCap(p) + 'Port').value.trim();
            parts.push(TRANSPORT_LABELS[p] + (port ? ':' + port : ''));
        }
        document.getElementById('devTransportsSummary').textContent =
            parts.length ? parts.join(', ') : i18n[currentLang].lblTransportsNone;
    }

    document.getElementById('trTelnetEnabled').addEventListener('change', updateTelnetWarn);
    for (const p of TRANSPORT_PROTOS) {
        document.getElementById('tr' + _trCap(p) + 'Enabled').addEventListener('change', updateTransportsSummary);
        document.getElementById('tr' + _trCap(p) + 'Port').addEventListener('input', updateTransportsSummary);
    }

    // Legge il form in una mappa {protocollo: porta|null} coi soli protocolli abilitati.
    function readTransportsForm() {
        const out = {};
        for (const p of TRANSPORT_PROTOS) {
            if (!document.getElementById('tr' + _trCap(p) + 'Enabled').checked) continue;
            const raw = document.getElementById('tr' + _trCap(p) + 'Port').value.trim();
            out[p] = raw ? (parseInt(raw, 10) || null) : null;
        }
        return out;
    }

    // Popola il form dai trasporti del device (mappa {proto: porta|null}).
    // Assenza => default ssh-only sulla porta indicata.
    function setTransportsForm(transports, fallbackSshPort) {
        let map = transports;
        if (!map || typeof map !== 'object' || !Object.keys(map).length) {
            map = { ssh: parseInt(fallbackSshPort, 10) || 22 };
        }
        // tcp/udp non hanno una porta di default: l'utente deve inserirla.
        const defaults = { ssh: 22, telnet: 23, netconf: 830, restconf: 443 };
        for (const p of TRANSPORT_PROTOS) {
            const enabled = Object.prototype.hasOwnProperty.call(map, p);
            document.getElementById('tr' + _trCap(p) + 'Enabled').checked = enabled;
            document.getElementById('tr' + _trCap(p) + 'Port').value =
                (enabled && map[p]) ? map[p] : (defaults[p] ?? '');
        }
        updateTelnetWarn();
        updateTransportsSummary();
        // Auto-espandi il pannello se il device non usa i default (solo SSH:22):
        // mai nascondere uno stato non-standard all'utente.
        const isDefaultState = document.getElementById('trSshEnabled').checked
            && document.getElementById('trSshPort').value === '22'
            && !document.getElementById('trTelnetEnabled').checked
            && !document.getElementById('trNetconfEnabled').checked
            && !document.getElementById('trRestconfEnabled').checked;
        document.getElementById('devTransports').open = !isDefaultState;
    }

    document.getElementById('btnSaveDevice').addEventListener('click', async () => {
        const siteSel = document.getElementById('devSiteSelect');
        const payload = {
            ip: document.getElementById('devIp').value.trim(),
            vendor: document.getElementById('devVendor').value,
            profile: document.getElementById('devProfile').value,
            username: document.getElementById('devUser').value,
            password: document.getElementById('devPass').value,
            enable_secret: document.getElementById('devSecret').value,
            group: document.getElementById('devGroupSelect').value,
            site: (siteSel && siteSel.value) ? siteSel.value : 'central',
            transports: readTransportsForm()
        };

        // La community non viene mai rimandata indietro dal server: campo vuoto
        // significa "lasciala com'è", non "cancellala". Per rimuoverla serve la
        // spunta esplicita, così un salvataggio distratto non spegne il polling.
        const snmp = document.getElementById('devSnmp');
        const snmpClear = document.getElementById('devSnmpClear');
        if (snmpClear && snmpClear.checked) payload.snmp_community = '';
        else if (snmp && snmp.value) payload.snmp_community = snmp.value;
        const snmpDisabled = document.getElementById('devSnmpDisabled');
        if (snmpDisabled) payload.snmp_disabled = snmpDisabled.checked;

        if(!payload.ip) { alert(i18n[currentLang].alertEnterIp); return; }

        // In modifica i campi credenziali vuoti significano "invariate":
        // add_or_update_device preserva quelle già salvate. Si compilano solo
        // per cambiarle.
        const res = await apiFetch('/api/add-device', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if(res && res.ok) {
            resetDeviceForm();
            appInit();
        } else if (res) {
            const err = await res.json();
            alert(`${i18n[currentLang].alertFirstSetupError}${err.detail || i18n[currentLang].alertSaveDeviceError}`);
        }
    });

    // Pre-compila il form di provisioning con i dati del dispositivo esistente
    // per la modifica (§11.5b). Password/secret restano vuoti perché il server
    // non li restituisce mai: lasciarli vuoti ora vuol dire "invariate", si
    // compilano solo per cambiarle. Stessa regola della community SNMP.
    async function editDevice(ip) {
        const dev = globalDevices.find(d => d.IP === ip);
        if (!dev) return;
        editingDeviceIp = ip;

        // La form di provisioning ora vive nella sua tab dedicata: prima di
        // precompilarla assicurati che sia quella visibile.
        switchTab('tab-provisioning');

        document.getElementById('devGroupSelect').value = dev.Group || 'Generale';
        const siteSel = document.getElementById('devSiteSelect');
        if (siteSel) {
            if (typeof populateSiteOptions === 'function') {
                await populateSiteOptions(dev.Site || 'central');
            } else {
                siteSel.value = dev.Site || 'central';
            }
        }
        const ipInput = document.getElementById('devIp');
        ipInput.value = dev.IP;
        ipInput.readOnly = true;
        ipInput.style.opacity = '0.7';
        let devTransports = null;
        try { devTransports = dev.Transports ? JSON.parse(dev.Transports) : null; } catch (e) { devTransports = null; }
        setTransportsForm(devTransports, dev['SSH Port']);
        document.getElementById('devVendor').value = (dev.Vendor || '').toLowerCase();
        updateDevSecretField();
        // Il segreto non torna dal server: il placeholder dice solo SE c'è.
        document.getElementById('devSnmp').value = '';
        document.getElementById('devSnmp').placeholder = dev.snmp_inherited
            ? i18n[currentLang].hintSnmpInherited
            : (dev.snmp_enabled
                ? (currentLang === 'en' ? 'configured — leave blank to keep'
                                        : 'configurata — lascia vuoto per non cambiarla')
                : '—');
        document.getElementById('devSnmpClear').checked = false;
        const dsd = document.getElementById('devSnmpDisabled');
        if (dsd) dsd.checked = !!dev['SNMP Disabled'];

        // switchTab('tab-provisioning') ha già ricaricato le identità per il
        // tenant precedentemente selezionato (loadProvisioningTab chiama
        // refreshIdentityOptions/renderIdentitiesPanel): devGroupSelect.value
        // è stato appena riassegnato sopra ma senza far scattare 'change',
        // quindi il pannello identità è ancora sul tenant sbagliato -- va
        // ricaricato esplicitamente per il tenant del device in modifica.
        const profileIsIdentity = (dev.Profile || '').startsWith('identity:');
        // Il profilo desiderato va esplicitato come "preserve": 'default' non
        // può contare sul valore residuo della select (potrebbe restare
        // 'custom' da una modifica precedente), quindi si passa sempre un
        // valore concreto invece di fare affidamento sul fallback di keep.
        const desiredProfile = profileIsIdentity ? dev.Profile
            : (dev.Profile === 'custom' ? 'custom' : 'default');
        await refreshIdentityOptions(desiredProfile);
        renderIdentitiesPanel();
        document.getElementById('customCredsForm').style.display =
            document.getElementById('devProfile').value === 'custom' ? 'block' : 'none';
        document.getElementById('devUser').value = dev.Username || '';
        // Il server non restituisce mai password e secret: il placeholder dice
        // che restano quelle salvate, come già fa la community SNMP.
        const keepPh = currentLang === 'en' ? 'unchanged — fill in only to change it'
                                            : 'invariata — compila solo per cambiarla';
        for (const id of ['devPass', 'devSecret']) {
            const el = document.getElementById(id);
            el.value = '';
            el.placeholder = keepPh;
        }

        document.getElementById('devFormTitle').innerHTML = i18n[currentLang].titleEditDevice;
        document.getElementById('devEditNotice').style.display = 'block';
        document.getElementById('btnSaveDevice').innerHTML = i18n[currentLang].btnUpdateDevice;
        document.getElementById('btnCancelEditDevice').style.display = 'block';

        document.getElementById('devFormTitle').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Riporta il form di provisioning in modalità "aggiunta" (§11.5b).
    function resetDeviceForm() {
        editingDeviceIp = null;
        const ipInput = document.getElementById('devIp');
        ipInput.value = '';
        ipInput.readOnly = false;
        ipInput.style.opacity = '';
        document.getElementById('devProfile').value = 'default';
        const siteSelReset = document.getElementById('devSiteSelect');
        if (siteSelReset) siteSelReset.value = 'central';
        setTransportsForm(null, 22);
        document.getElementById('customCredsForm').style.display = 'none';
        document.getElementById('devUser').value = '';
        for (const id of ['devPass', 'devSecret']) {
            const el = document.getElementById(id);
            el.value = '';
            el.placeholder = '';
        }
        document.getElementById('devSnmp').value = '';
        document.getElementById('devSnmp').placeholder = '—';
        document.getElementById('devSnmpClear').checked = false;
        const dsdReset = document.getElementById('devSnmpDisabled');
        if (dsdReset) dsdReset.checked = false;
        document.getElementById('devFormTitle').innerHTML = i18n[currentLang].titleProvisioning;
        document.getElementById('devEditNotice').style.display = 'none';
        document.getElementById('btnSaveDevice').innerHTML = i18n[currentLang].btnSaveDevice;
        document.getElementById('btnCancelEditDevice').style.display = 'none';
    }

    async function deleteDevice(ip) {
        if(confirm(i18n[currentLang].confirmDeleteDevice.replace("{ip}", ip))) {
            const res = await apiFetch('/api/delete-device', { 
                method: 'POST', 
                headers: {'Content-Type': 'application/json'}, 
                body: JSON.stringify({ ip: ip }) 
            });
            if (res && res.ok) {
                appInit();
            }
        }
    }

    // Rinomina un dispositivo gestito (imposta manualmente l'hostname mostrato).
    async function renameDevice(ip) {
        const dev = globalDevices.find(d => d.IP === ip);
        const current = dev ? (dev.Hostname || '') : '';
        const label = i18n[currentLang].promptRenameDevice.replace("{ip}", ip);
        const name = prompt(label, current);
        if (name === null) return;                 // annullato
        if (name.trim() === (current || '').trim()) return;  // nessuna modifica
        const res = await apiFetch('/api/rename-device', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip: ip, hostname: name.trim() })
        });
        if (res && res.ok) {
            appInit();
        } else if (res) {
            alert(i18n[currentLang].alertRenameDeviceError);
        }
    }

    // --- GRUPPI CRUD ---

    document.getElementById('btnCreateGroup').addEventListener('click', async () => {
        const name = document.getElementById('newGroupName').value.trim();
        if(!name) return;
        
        // Descrizione canonica in forma IT: renderGroupsTable la traduce per lingua.
        const description = `Sede secondaria ${name}`;
        const res = await apiFetch('/api/groups', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({ name: name, description: description }) 
        });
        if(res && res.ok) {
            document.getElementById('newGroupName').value = '';
            document.getElementById('inlineNewTenantRow').style.display = 'none';
            await appInit();
            // Seleziona il tenant appena creato nella select del form di provisioning.
            const groupSelect = document.getElementById('devGroupSelect');
            if (groupSelect && Array.from(groupSelect.options).some(o => o.value === name)) {
                groupSelect.value = name;
            }
            await refreshIdentityOptions();
            renderIdentitiesPanel();
        } else if (res) {
            alert(i18n[currentLang].alertGroupCreateError);
        }
    });

    async function deleteGroup(name) {
        if(confirm(i18n[currentLang].confirmDeleteGroup.replace("{name}", name))) {
            const res = await apiFetch('/api/groups/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ name: name })
            });
            if(res && res.ok) {
                appInit();
            } else if (res) {
                alert(i18n[currentLang].alertGroupDeleteError);
            }
        }
    }

    async function renameGroup(oldName) {
        const newName = prompt(currentLang==='en'
            ? `New name for tenant "${oldName}":`
            : `Nuovo nome per il tenant "${oldName}":`, oldName);
        if (newName === null) return;
        const trimmed = newName.trim();
        if (!trimmed || trimmed === oldName) return;
        const res = await apiFetch('/api/groups/rename', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ old_name: oldName, new_name: trimmed })
        });
        if (res && res.ok) {
            appInit();
        } else {
            const e = res ? await res.json().catch(()=>({})) : {};
            alert(e.detail || (currentLang==='en'?'Rename failed.':'Rinomina non riuscita.'));
        }
    }

    // --- VENDOR CRUD ---

    // buildVendorOptions/renderVendorTable: MOVED to static/js/core.js
    // (shared with static/js/provisioning.js's populateProvisioningFormSelects
    // and with static/js/i18n.js's changeLanguage).

    async function loadVendors() {
        const res = await apiFetch('/api/vendors');
        if (!res || !res.ok) return;
        globalVendors = await res.json();
        renderVendorTable();
        const devVendorSel = document.getElementById('devVendor');
        if (devVendorSel) devVendorSel.innerHTML = buildVendorOptions(devVendorSel.value || 'cisco');
        const scanVendorSel = document.getElementById('scanVerifyVendorSelect');
        if (scanVendorSel) scanVendorSel.innerHTML = buildScanVendorOptions(scanVendorSel.value);
    }

    async function addVendor() {
        const name = document.getElementById('newVendorName').value.trim().toLowerCase();
        const term = document.getElementById('newVendorTerm').value.trim();
        const drv  = document.getElementById('newVendorDriver').value.trim() || null;
        if (!name || !term) { alert(i18n[currentLang].alertVendorRequired); return; }
        const res = await apiFetch('/api/vendors', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({name, euvd_term: term, driver: drv})
        });
        if (res && res.ok) {
            document.getElementById('newVendorName').value = '';
            document.getElementById('newVendorTerm').value = '';
            document.getElementById('newVendorDriver').value = '';
            await loadVendors();
        }
    }

    async function deleteVendor(name) {
        if (!confirm(i18n[currentLang].confirmDeleteVendor.replace("{name}", name))) return;
        const res = await apiFetch('/api/vendors/delete', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({name})
        });
        if (res && res.ok) { await loadVendors(); }
    }

    // --- BACKGROUND JOBS (polling triage in background) ---

    // Triage globale: con una sola sede parte subito, con più sedi apre il selettore
    document.getElementById("btnRunTriage").addEventListener("click", () => {
        const groups = Object.keys(globalGroups);
        if (groups.length <= 1) {
            startGroupTriage(groups[0] || 'all');
        } else {
            openTriageScopeModal();
        }
    });

    // Triage Sede: analizza la sede attualmente filtrata; se "tutte", apre il selettore
    function triageCurrentSite() {
        const g = document.getElementById('filterGroupSelect')?.value || 'all';
        if (g === 'all') {
            const groups = Object.keys(globalGroups);
            if (groups.length <= 1) { startGroupTriage(groups[0] || 'all'); }
            else { openTriageScopeModal(); }
        } else {
            startGroupTriage(g);
        }
    }

    function openTriageScopeModal() {
        const list = document.getElementById('triageScopeList');
        list.innerHTML = Object.keys(globalGroups).map(g =>
            `<button class="btn btn-secondary" data-action="triage-scope-group" data-g="${escapeHtml(g)}"
                 style="justify-content:flex-start; gap:10px;">
               <i class="fa-solid fa-location-dot" style="color:var(--primary);"></i> ${escapeHtml(g)}
             </button>`).join('');
        document.getElementById('triageScopeModal').style.display = 'flex';
    }

    document.getElementById('triageScopeList')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="triage-scope-group"]');
        if (btn && btn.dataset.g) {
            startGroupTriage(btn.dataset.g);
        }
    });

    function closeTriageScopeModal() {
        document.getElementById('triageScopeModal').style.display = 'none';
    }

    async function startGroupTriage(group) {
        const res = await apiFetch("/api/run-triage", {
            method: "POST",
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ group })
        });
        if (res && res.ok) {
            closeTriageScopeModal();
            startTriageStatusPolling();
        }
    }

    function startTriageStatusPolling() {
        if (isTriagePolling) return;
        isTriagePolling = true;
        pollTriageStatus();
    }

    async function pollTriageStatus() {
        try {
            const res = await apiFetch("/api/triage-status");
            if (!res || !res.ok) { isTriagePolling = false; return; }
            const statusData = await res.json();
            
            const pbox = document.getElementById("triageProgressBox");
            if (statusData.status === "running") {
                wasTriageRunning = true;
                pbox.style.display = "flex";
                const total = statusData.total || 1;
                const progress = statusData.progress || 0;
                const pct = Math.round((progress / total) * 100);
                
                document.getElementById("triageProgressPct").innerText = `${pct}%`;
                const processingText = currentLang === 'en' ? 'Processing' : 'Elaborazione';
                document.getElementById("triageProgressMsg").innerText = `${processingText}: ${statusData.current_device} (${progress}/${total})`;
                document.getElementById("triageProgressBarFill").style.transform = `scaleX(${pct / 100})`;
                
                setTimeout(pollTriageStatus, 1500);
            } else {
                pbox.style.display = "none";
                isTriagePolling = false;
                if (wasTriageRunning) {
                    wasTriageRunning = false;
                    appInit();
                }
            }
        } catch {
            isTriagePolling = false;
        }
    }

    // --- SUBNET SCANNER ---

    // Discovery rows currently on screen. verify is null until the user runs
    // the optional verify step (see verifySelectedScanRows).
    let _scanRows = [];

    // --- SUB-SCAN BACKGROUND JOB & ALERTING STATE ---
    window._activeSubnetScanJob = window._activeSubnetScanJob || {
        jobId: null,
        type: 'scan',
        network: '',
        ports: '22',
        total: 0,
        progress: 0,
        status: 'idle',
        results: [],
        isVerify: false,
    };

    function playNotificationChime() {
        try {
            const AudioCtx = window.AudioContext || window.webkitAudioContext;
            if (!AudioCtx) return;
            const ctx = new AudioCtx();
            const now = ctx.currentTime;

            const osc1 = ctx.createOscillator();
            const gain1 = ctx.createGain();
            osc1.type = 'sine';
            osc1.frequency.setValueAtTime(587.33, now); // D5
            gain1.gain.setValueAtTime(0.12, now);
            gain1.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
            osc1.connect(gain1);
            gain1.connect(ctx.destination);
            osc1.start(now);
            osc1.stop(now + 0.3);

            const osc2 = ctx.createOscillator();
            const gain2 = ctx.createGain();
            osc2.type = 'sine';
            osc2.frequency.setValueAtTime(880, now + 0.12); // A5
            gain2.gain.setValueAtTime(0.12, now + 0.12);
            gain2.gain.exponentialRampToValueAtTime(0.001, now + 0.55);
            osc2.connect(gain2);
            gain2.connect(ctx.destination);
            osc2.start(now + 0.12);
            osc2.stop(now + 0.55);
        } catch (e) {
            // AudioContext blocked
        }
    }

    function sendDesktopNotification(title, body) {
        if (!('Notification' in window)) return;
        if (Notification.permission === 'granted') {
            try {
                const n = new Notification(title, { body });
                n.onclick = () => {
                    window.focus();
                    switchToDevicesAndOpenScan();
                };
            } catch (e) {}
        } else if (Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    function switchToDevicesAndOpenScan() {
        if (typeof switchTab === 'function') {
            switchTab('tab-devices');
        }
        openSubnetScanModal();
    }

    function updateFloatingScanWidget() {
        const widget = document.getElementById('floatingScanWidget');
        if (!widget) return;
        const job = window._activeSubnetScanJob;
        const modal = document.getElementById('subnetScanModal');
        const isModalOpen = modal && modal.style.display !== 'none' && modal.style.display !== '';

        if (!job || job.status !== 'running' || isModalOpen) {
            widget.style.display = 'none';
            return;
        }

        const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
        const titleEl = document.getElementById('floatingScanTitle');
        const subEl = document.getElementById('floatingScanSubtitle');
        if (titleEl) {
            titleEl.textContent = job.isVerify
                ? (L.lblScanVerifyRunningShort || (currentLang === 'en' ? 'Verifying credentials...' : 'Verifica credenziali...'))
                : (L.lblScanRunningShort ? L.lblScanRunningShort.replace('{net}', job.network) : (currentLang === 'en' ? `Scanning: ${job.network}` : `Scansione: ${job.network}`));
        }
        if (subEl) {
            const pct = job.total > 0 ? Math.round((job.progress / job.total) * 100) : 0;
            subEl.textContent = `${job.progress}/${job.total} host (${pct}%)`;
        }
        widget.style.display = 'flex';
    }

    function showScanCompletionAlert(msg, onAction) {
        const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
        const old = document.querySelector('.scan-complete-toast');
        if (old) old.remove();

        const el = document.createElement('div');
        el.className = 'scan-complete-toast';
        el.style.cssText = 'position:fixed; bottom:24px; right:24px; z-index:10070;'
            + 'padding:12px 18px; border-radius:0; font-size:13px;'
            + 'font-family:var(--font-prose); color:var(--text);'
            + 'background:var(--surface-3); box-shadow:var(--shadow-float);'
            + 'border:1px solid var(--success, #10b981);'
            + 'display:flex; align-items:center; gap:12px; max-width:520px;';

        const icon = document.createElement('i');
        icon.className = 'fa-solid fa-circle-check';
        icon.style.cssText = 'color:var(--success, #10b981); font-size:16px; flex-shrink:0;';
        el.appendChild(icon);

        const text = document.createElement('span');
        text.style.flex = '1';
        text.textContent = msg;
        el.appendChild(text);

        const btn = document.createElement('button');
        btn.className = 'btn btn-primary btn-small';
        btn.style.cssText = 'width:auto; margin:0; padding:4px 10px; font-size:12px; flex-shrink:0; cursor:pointer;';
        btn.textContent = L.btnViewResults || (currentLang === 'en' ? 'View Results' : 'Mostra Risultati');
        btn.onclick = () => {
            el.remove();
            if (onAction) onAction();
        };
        el.appendChild(btn);

        const closeBtn = document.createElement('i');
        closeBtn.className = 'fa-solid fa-xmark';
        closeBtn.style.cssText = 'color:var(--text-muted); cursor:pointer; font-size:14px; margin-left:4px;';
        closeBtn.onclick = () => el.remove();
        el.appendChild(closeBtn);

        document.body.appendChild(el);
        setTimeout(() => { if (el.parentNode) el.remove(); }, 14000);
    }

    function addScanPort(port) {
        const input = document.getElementById('scanPortsInput');
        const ports = input.value.split(',').map(s => s.trim()).filter(Boolean);
        if (!ports.includes(String(port))) ports.push(String(port));
        input.value = ports.join(',');
    }

    function openSubnetScanModal() {
        // Populate group select from current globalGroups cache
        const sel = document.getElementById('scanGroupSelect');
        if (sel) {
            sel.innerHTML = '';
            Object.keys(globalGroups).forEach(g => {
                const opt = document.createElement('option');
                opt.value = g;
                opt.textContent = g;
                if (g === 'Generale') opt.selected = true;
                sel.appendChild(opt);
            });
        }

        const job = window._activeSubnetScanJob;
        const bgBtn = document.getElementById('btnScanRunBackground');

        if (job && job.status === 'running') {
            // Restore active running scan state
            if (job.network) document.getElementById('scanNetworkInput').value = job.network;
            if (job.ports) document.getElementById('scanPortsInput').value = job.ports;
            document.getElementById('subnetScanResults').style.display = 'block';
            const pct = job.total > 0 ? Math.round((job.progress / job.total) * 100) : 0;
            document.getElementById('subnetScanProgressBar').style.transform = `scaleX(${pct / 100})`;
            document.getElementById('subnetScanStatus').textContent = currentLang === 'en'
                ? `Scanning — ${job.progress}/${job.total} hosts processed...`
                : `Scansione in corso — ${job.progress}/${job.total} host elaborati...`;

            const btn = document.getElementById('btnAvviaScan');
            btn.disabled = true;
            btn.innerHTML = currentLang === 'en'
                ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...'
                : '<i class="fa-solid fa-circle-notch fa-spin"></i> Scansione in corso...';
            if (bgBtn) bgBtn.style.display = 'inline-flex';
        } else if (job && job.status === 'done' && _scanRows.length > 0) {
            // Restore finished results
            if (job.network) document.getElementById('scanNetworkInput').value = job.network;
            if (job.ports) document.getElementById('scanPortsInput').value = job.ports;
            document.getElementById('subnetScanResults').style.display = 'block';
            document.getElementById('subnetScanProgressBar').style.transform = 'scaleX(1)';
            scanStartButtonIdle();
            if (bgBtn) bgBtn.style.display = 'none';
            renderScanResults(_scanRows);
        } else {
            _scanRows = [];
            document.getElementById('subnetScanResults').style.display = 'none';
            document.getElementById('scanActionsBar').style.display = 'none';
            document.getElementById('subnetScanResultsTable').innerHTML = '';
            document.getElementById('subnetScanStatus').textContent = '';
            document.getElementById('scanNetworkInput').value = '';
            document.getElementById('scanPortsInput').value = '22';
            document.getElementById('scanVerifyVendorSelect').innerHTML = buildScanVendorOptions('');
            scanStartButtonIdle();
            if (bgBtn) bgBtn.style.display = 'none';
        }

        document.getElementById('subnetScanModal').style.display = 'flex';
        updateFloatingScanWidget();
    }

    function closeSubnetScanModal() {
        // Leaving scan running in background: do not cancel interval if running!
        const modal = document.getElementById('subnetScanModal');
        if (modal) modal.style.display = 'none';
        updateFloatingScanWidget();
    }

    function scanStartButtonIdle() {
        const b = document.getElementById('btnAvviaScan');
        if (!b) return;
        b.disabled = false;
        b.innerHTML = currentLang === 'en'
            ? '<i class="fa-solid fa-satellite-dish"></i> Start Scan'
            : '<i class="fa-solid fa-satellite-dish"></i> Avvia Scansione';
    }

    async function startSubnetScan() {
        if (_scanJobInterval) { clearInterval(_scanJobInterval); _scanJobInterval = null; }

        const network = document.getElementById('scanNetworkInput').value.trim();
        if (!network) { document.getElementById('scanNetworkInput').focus(); return; }
        const ports = document.getElementById('scanPortsInput').value
            .split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));

        const btn = document.getElementById('btnAvviaScan');
        btn.disabled = true;
        btn.innerHTML = currentLang === 'en'
            ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Starting...'
            : '<i class="fa-solid fa-circle-notch fa-spin"></i> Avvio...';
        _scanRows = [];
        document.getElementById('subnetScanResults').style.display = 'block';
        document.getElementById('scanActionsBar').style.display = 'none';
        document.getElementById('subnetScanResultsTable').innerHTML = '';
        document.getElementById('subnetScanProgressBar').style.transform = 'scaleX(0)';
        document.getElementById('subnetScanStatus').textContent =
            currentLang === 'en' ? 'Starting scan...' : 'Avvio scansione...';

        const bgBtn = document.getElementById('btnScanRunBackground');
        if (bgBtn) bgBtn.style.display = 'inline-flex';

        // Request browser notification permission if not yet decided
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }

        const res = await apiFetch('/api/scan-subnet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ network, ports }),
        });
        if (!res || !res.ok) {
            const err = res ? await res.json() : { detail: currentLang === 'en' ? 'Network error' : 'Errore di rete' };
            document.getElementById('subnetScanStatus').textContent =
                (currentLang === 'en' ? 'Error: ' : 'Errore: ') +
                (err.detail || (currentLang === 'en' ? 'unable to start scan.' : 'impossibile avviare la scansione.'));
            if (bgBtn) bgBtn.style.display = 'none';
            scanStartButtonIdle();
            return;
        }
        const { job_id, total_hosts } = await res.json();
        document.getElementById('subnetScanStatus').textContent = currentLang === 'en'
            ? `Scan started — ${total_hosts} hosts to check...`
            : `Scansione avviata — ${total_hosts} host da verificare...`;
        btn.innerHTML = currentLang === 'en'
            ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...'
            : '<i class="fa-solid fa-circle-notch fa-spin"></i> Scansione in corso...';
        pollScanJob(job_id, total_hosts, network, ports.join(','));
    }

    function pollScanJob(jobId, totalHosts, network, portsStr) {
        window._activeSubnetScanJob = {
            jobId,
            type: 'scan',
            network: network || '',
            ports: portsStr || '22',
            total: totalHosts,
            progress: 0,
            status: 'running',
            results: [],
            isVerify: false,
            startTime: Date.now()
        };
        updateFloatingScanWidget();

        _scanJobInterval = setInterval(async () => {
            const res = await apiFetch(`/api/scan-subnet/${jobId}`);
            if (!res || !res.ok) {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                window._activeSubnetScanJob.status = 'error';
                updateFloatingScanWidget();
                const bgBtn = document.getElementById('btnScanRunBackground');
                if (bgBtn) bgBtn.style.display = 'none';
                const st = document.getElementById('subnetScanStatus');
                if (st) st.textContent = currentLang === 'en' ? 'Error during polling.' : 'Errore durante il polling.';
                scanStartButtonIdle();
                return;
            }
            const data = await res.json();
            const total = data.total || totalHosts;
            const pct = total > 0 ? Math.round((data.progress / total) * 100) : 0;

            window._activeSubnetScanJob.progress = data.progress;
            window._activeSubnetScanJob.total = total;
            updateFloatingScanWidget();

            const pBar = document.getElementById('subnetScanProgressBar');
            if (pBar) pBar.style.transform = `scaleX(${pct / 100})`;
            const st = document.getElementById('subnetScanStatus');
            if (st) {
                st.textContent = currentLang === 'en'
                    ? `Scanning — ${data.progress}/${total} hosts processed...`
                    : `Scansione in corso — ${data.progress}/${total} host elaborati...`;
            }

            if (data.status !== 'running') {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                window._activeSubnetScanJob.status = data.status;
                window._activeSubnetScanJob.results = data.results || [];
                updateFloatingScanWidget();
                scanStartButtonIdle();
                const bgBtn = document.getElementById('btnScanRunBackground');
                if (bgBtn) bgBtn.style.display = 'none';
                if (pBar) pBar.style.transform = 'scaleX(1)';

                if (data.status === 'error') {
                    if (st) st.textContent = currentLang === 'en' ? 'Scan finished with error.' : 'Scansione terminata con errore.';
                    return;
                }
                _scanRows = (data.results || []).map(r => ({ ...r, verify: null }));
                renderScanResults(_scanRows);

                // Multi-channel completion alert
                const count = _scanRows.length;
                const netStr = window._activeSubnetScanJob.network || network || 'subnet';
                const alertMsg = currentLang === 'en'
                    ? `Subnet scan completed! Found ${count} active host(s) on ${netStr}.`
                    : `Scansione Subnet completata! Trovati ${count} host attivi su ${netStr}.`;

                playNotificationChime();
                sendDesktopNotification('SentinelNet', alertMsg);

                const modal = document.getElementById('subnetScanModal');
                const isModalOpen = modal && modal.style.display !== 'none' && modal.style.display !== '';
                if (!isModalOpen || document.hidden) {
                    showScanCompletionAlert(alertMsg, () => {
                        switchToDevicesAndOpenScan();
                    });
                } else {
                    showToast(alertMsg, 'success');
                }
            }
        }, 2000);
    }

    function selectedScanIps() {
        return Array.from(document.querySelectorAll('.scan-row-cb:checked'))
            .map(cb => cb.dataset.ip);
    }

    function refreshScanActionButtons() {
        const n = selectedScanIps().length;
        const L = i18n[currentLang] || {};
        const identity = document.getElementById('scanIdentitySelect')?.value;
        const vendor = document.getElementById('scanVerifyVendorSelect')?.value;
        const verifyBtn = document.getElementById('btnScanVerify');
        const addBtn = document.getElementById('btnScanAddSelected');
        if (verifyBtn) {
            verifyBtn.textContent = (L.btnScanVerify || 'Verifica selezionati ({n})').replace('{n}', n);
            verifyBtn.disabled = n === 0 || !identity || !vendor;
        }
        if (addBtn) {
            addBtn.textContent = (L.btnScanAddSelected || 'Aggiungi selezionati ({n})').replace('{n}', n);
            addBtn.disabled = n === 0;
        }
    }

    function renderScanResults(rows) {
        const L = i18n[currentLang] || {};
        const st = document.getElementById('subnetScanStatus');
        if (st) {
            st.textContent = (L.scanFoundCount || 'Trovati {n} host').replace('{n}', rows.length);
        }

        const tableEl = document.getElementById('subnetScanResultsTable');
        const actionsBar = document.getElementById('scanActionsBar');
        if (!tableEl) return;

        if (rows.length === 0) {
            tableEl.innerHTML = `<div style="padding:14px; color:var(--text-muted); font-size:13px;">${
                escapeHtml(L.scanNoHosts || 'Nessun host ha risposto.')}</div>`;
            if (actionsBar) actionsBar.style.display = 'none';
            return;
        }

        const header = `<div style="display:grid; grid-template-columns:28px 130px 48px 1fr 1fr;
                    align-items:center; gap:8px; padding:8px 12px; position:sticky; top:0;
                    background:var(--surface-3); border-bottom:1px solid var(--border);
                    font-size:11px; text-transform:uppercase; color:var(--text-muted);">
            <input type="checkbox" id="scanSelectAll" data-action="toggle-all-scan-rows"
                   style="width:14px; height:14px; accent-color:var(--primary); cursor:pointer;">
            <span>IP</span>
            <span>${escapeHtml(L.scanColPing || 'Ping')}</span>
            <span>${escapeHtml(L.scanColPorts || 'Porte aperte')}</span>
            <span>${escapeHtml(L.scanColVerify || 'Verifica')}</span>
          </div>`;

        const body = rows.map(r => {
            const ports = (r.open_ports && r.open_ports.length)
                ? escapeHtml(r.open_ports.join(', '))
                : '<span style="color:var(--text-muted)">—</span>';
            let verifyCell = '<span style="color:var(--text-muted)">—</span>';
            if (r.verify && r.verify.ok) {
                verifyCell = `<span style="color:var(--primary)">✓ ${
                    escapeHtml(r.verify.hostname || '')}</span>`;
            } else if (r.verify) {
                verifyCell = `<span style="color:var(--danger)" title="${
                    escapeHtml(r.verify.error || '')}">✗ ${
                    escapeHtml((r.verify.error || '').slice(0, 40))}</span>`;
            }
            return `<div style="display:grid; grid-template-columns:28px 130px 48px 1fr 1fr;
                        align-items:center; gap:8px; padding:8px 12px;
                        border-bottom:1px solid var(--border); font-size:12px;">
                <input type="checkbox" class="scan-row-cb" data-ip="${escapeHtml(r.ip)}"
                       data-action="refresh-scan-action-buttons"
                       style="width:14px; height:14px; accent-color:var(--primary); cursor:pointer;">
                <span style="font-family:var(--font-code); color:var(--primary);">${escapeHtml(r.ip)}</span>
                <span style="color:${r.alive ? 'var(--primary)' : 'var(--text-muted)'};">${r.alive ? '✓' : '✗'}</span>
                <span style="font-family:var(--font-code);">${ports}</span>
                <span>${verifyCell}</span>
              </div>`;
        }).join('');

        tableEl.innerHTML = header + body;
        if (actionsBar) actionsBar.style.display = 'flex';
        populateScanIdentitySelect();
        const vendorSel = document.getElementById('scanVerifyVendorSelect');
        if (vendorSel) {
            vendorSel.innerHTML = buildScanVendorOptions(vendorSel.value);
            vendorSel.onchange = refreshScanActionButtons;
        }
        refreshScanActionButtons();
    }

    document.getElementById('subnetScanResultsTable')?.addEventListener('change', (e) => {
        const master = e.target.closest('#scanSelectAll');
        if (master) {
            toggleAllScanRows(master);
            return;
        }
        if (e.target.closest('.scan-row-cb')) {
            refreshScanActionButtons();
        }
    });

    function toggleAllScanRows(master) {
        document.querySelectorAll('.scan-row-cb').forEach(cb => { cb.checked = master.checked; });
        refreshScanActionButtons();
    }

    async function populateScanIdentitySelect() {
        const sel = document.getElementById('scanIdentitySelect');
        if (!sel) return;
        const L = i18n[currentLang] || {};
        const res = await apiFetch('/api/identities');
        const identities = (res && res.ok) ? (await res.json()).identities || [] : [];
        sel.innerHTML = `<option value="">${
            escapeHtml(L.optScanNoIdentity || '— nessuna (solo scoperta) —')}</option>` +
            identities.map(i => `<option value="${escapeHtml(i.id)}">${
                escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('');
        sel.onchange = refreshScanActionButtons;
    }

    async function verifySelectedScanRows() {
        const ips = selectedScanIps();
        const identityId = document.getElementById('scanIdentitySelect')?.value;
        const vendor = document.getElementById('scanVerifyVendorSelect')?.value;
        if (!ips.length || !identityId) return;

        const L = i18n[currentLang] || {};
        const verifyBtn = document.getElementById('btnScanVerify');
        if (verifyBtn) verifyBtn.disabled = true;

        const bgBtn = document.getElementById('btnScanRunBackground');
        if (bgBtn) bgBtn.style.display = 'inline-flex';

        const res = await apiFetch('/api/scan-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips, vendor, identity_id: identityId }),
        });
        if (!res || !res.ok) {
            const err = res ? await res.json() : { detail: currentLang === 'en' ? 'Network error' : 'Errore di rete' };
            const st = document.getElementById('subnetScanStatus');
            if (st) st.textContent = (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (err.detail || '');
            if (bgBtn) bgBtn.style.display = 'none';
            refreshScanActionButtons();
            return;
        }
        const { job_id } = await res.json();

        window._activeSubnetScanJob = {
            jobId: job_id,
            type: 'verify',
            network: '',
            ports: '',
            total: ips.length,
            progress: 0,
            status: 'running',
            results: [],
            isVerify: true,
            startTime: Date.now()
        };
        updateFloatingScanWidget();

        const interval = setInterval(async () => {
            const poll = await apiFetch(`/api/scan-subnet/${job_id}`);
            if (!poll || !poll.ok) {
                clearInterval(interval);
                window._activeSubnetScanJob.status = 'error';
                updateFloatingScanWidget();
                if (bgBtn) bgBtn.style.display = 'none';
                const st = document.getElementById('subnetScanStatus');
                if (st) st.textContent = currentLang === 'en' ? 'Error during polling.' : 'Errore durante il polling.';
                refreshScanActionButtons();
                return;
            }
            const data = await poll.json();
            window._activeSubnetScanJob.progress = data.progress;
            window._activeSubnetScanJob.total = data.total;
            updateFloatingScanWidget();

            const st = document.getElementById('subnetScanStatus');
            if (st) {
                st.textContent = (L.scanVerifyRunning || 'Verifica in corso — {done}/{total}...')
                    .replace('{done}', data.progress).replace('{total}', data.total);
            }

            if (data.status !== 'running') {
                clearInterval(interval);
                window._activeSubnetScanJob.status = data.status;
                updateFloatingScanWidget();
                if (bgBtn) bgBtn.style.display = 'none';

                if (data.status === 'error') {
                    if (st) st.textContent = currentLang === 'en' ? 'Verify finished with error.' : 'Verifica terminata con errore.';
                    refreshScanActionButtons();
                    return;
                }
                const selected = new Set(ips);
                (data.results || []).forEach(v => {
                    const row = _scanRows.find(r => r.ip === v.ip);
                    if (row) row.verify = v;
                });
                renderScanResults(_scanRows);
                document.querySelectorAll('.scan-row-cb').forEach(cb => {
                    cb.checked = selected.has(cb.dataset.ip);
                });
                refreshScanActionButtons();

                const okCount = (data.results || []).filter(r => r.ok).length;
                const alertMsg = currentLang === 'en'
                    ? `Credential verification completed: ${okCount}/${ips.length} succeeded.`
                    : `Verifica credenziali completata: ${okCount}/${ips.length} con successo.`;

                playNotificationChime();
                sendDesktopNotification('SentinelNet', alertMsg);

                const modal = document.getElementById('subnetScanModal');
                const isModalOpen = modal && modal.style.display !== 'none' && modal.style.display !== '';
                if (!isModalOpen || document.hidden) {
                    showScanCompletionAlert(alertMsg, () => {
                        switchToDevicesAndOpenScan();
                    });
                } else {
                    showToast(alertMsg, 'success');
                }
            }
        }, 2000);
    }

    async function addSelectedScanRows() {
        const group = document.getElementById('scanGroupSelect').value;
        const vendorSel = document.getElementById('scanVerifyVendorSelect').value;
        const identityId = document.getElementById('scanIdentitySelect').value;
        const ips = selectedScanIps();

        for (const ip of ips) {
            const row = _scanRows.find(r => r.ip === ip);
            // Il vendor e' quello scelto nella finestra, verifica o no: sceglierlo
            // e' l'utente che lo dice, non il programma che lo indovina. Vuoto
            // resta vuoto — la select ha la voce apposta.
            // L'identita' invece si scrive solo se ha davvero aperto la sessione:
            // legarla a un dispositivo su cui non ha fatto login sarebbe una
            // credenziale dichiarata e mai provata.
            const verified = row && row.verify && row.verify.ok;
            const body = {
                ip,
                vendor: vendorSel,
                profile: (verified && identityId) ? `identity:${identityId}` : 'default',
                username: '', password: '', enable_secret: '', group,
            };
            await apiFetch('/api/add-device', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
        }
        appInit();
        closeSubnetScanModal();
    }

    async function downloadBackup(ip) {
        try {
            const res = await apiFetch(`/api/download-backup/${ip}`);
            if (!res || !res.ok) {
                alert(i18n[currentLang].alertDownloadError);
                return;
            }
            const blob = await res.blob();
            const disposition = res.headers.get('content-disposition');
            let filename = `${ip}.txt`;
            if (disposition && disposition.indexOf('attachment') !== -1) {
                const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
                const matches = filenameRegex.exec(disposition);
                if (matches != null && matches[1]) { 
                    filename = matches[1].replace(/['"]/g, '');
                }
            }
            
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (err) {
            alert(i18n[currentLang].alertNetworkDownloadError);
        }
    }

    // --- CUSTOMIZABLE CSV EXPORT ---

    // Columns come from /api/export/devices/columns: the registry lives in the
    // backend, so no second copy here that could drift away from it.
    let exportColumns = [];
    const EXPORT_PREFS_KEY = 'sentinelnet.exportPrefs';

    function readExportPrefs() {
        try { return JSON.parse(localStorage.getItem(EXPORT_PREFS_KEY)) || {}; }
        catch (e) { return {}; }
    }

    function checkedValues(containerId) {
        return Array.from(document.querySelectorAll(`#${containerId} input:checked`))
            .map(el => el.value);
    }

    function renderCheckList(containerId, values, checked) {
        const box = document.getElementById(containerId);
        const want = new Set(checked || []);
        box.innerHTML = values.map(v => `
            <label style="display:flex; align-items:center; gap:6px; font-size:12px; padding:2px 0; cursor:pointer;">
              <input type="checkbox" value="${escapeHtml(v.value)}" ${want.has(v.value) ? 'checked' : ''}
                     style="width:14px; height:14px; accent-color:var(--primary); cursor:pointer;">
              <span>${escapeHtml(v.label)}</span>
            </label>`).join('');
    }

    function updateMemberHint() {
        const perMember = new Set(exportColumns.filter(c => c.per_member).map(c => c.key));
        const hit = checkedValues('exportColumnList').some(k => perMember.has(k));
        document.getElementById('exportMemberHint').style.display = hit ? 'block' : 'none';
    }

    async function openDeviceExportModal() {
        if (!exportColumns.length) {
            const res = await apiFetch("/api/export/devices/columns");
            if (!res || !res.ok) {
                alert(i18n[currentLang].alertExportError);
                return;
            }
            const data = await res.json();
            exportColumns = data.columns;
            const prefs = readExportPrefs();
            if (!prefs.columns) prefs.columns = data.default;
            localStorage.setItem(EXPORT_PREFS_KEY, JSON.stringify(prefs));
        }
        const prefs = readExportPrefs();
        const uniq = (key) => Array.from(new Set(globalDevices.map(d => d[key]).filter(Boolean)))
            .sort().map(v => ({ value: v, label: v }));

        renderCheckList('exportFilterGroups', uniq('Group'), prefs.groups);
        renderCheckList('exportFilterSites', uniq('Site'), prefs.sites);
        renderCheckList('exportFilterVendors', uniq('Vendor'), prefs.vendors);
        renderCheckList('exportFilterRedundancy', [
            { value: 'standalone', label: 'standalone' },
            { value: 'stack', label: 'stack' },
            { value: 'ha_pair', label: 'ha_pair' },
            { value: 'sso', label: 'sso' },
        ], prefs.redundancy);
        renderCheckList('exportColumnList',
            exportColumns.map(c => ({ value: c.key, label: c.header + (c.per_member ? ' *' : '') })),
            prefs.columns);
        updateMemberHint();
        document.getElementById('deviceExportModal').style.display = 'flex';
    }

    async function exportDeviceCsv() {
        const prefs = {
            groups: checkedValues('exportFilterGroups'),
            sites: checkedValues('exportFilterSites'),
            vendors: checkedValues('exportFilterVendors'),
            redundancy: checkedValues('exportFilterRedundancy'),
            columns: checkedValues('exportColumnList'),
        };
        if (!prefs.columns.length) {
            alert(i18n[currentLang].alertExportNoColumns);
            return;
        }
        localStorage.setItem(EXPORT_PREFS_KEY, JSON.stringify(prefs));
        const qs = new URLSearchParams();
        for (const [k, v] of Object.entries(prefs)) if (v.length) qs.set(k, v.join(','));

        const res = await apiFetch("/api/export/devices?" + qs.toString());
        if (!res || !res.ok) {
            alert(i18n[currentLang].alertExportError);
            return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "sentinelnet-devices-" + new Date().toISOString().slice(0,10) + ".csv";
        a.click();
        URL.revokeObjectURL(url);
        document.getElementById('deviceExportModal').style.display = 'none';
    }

    // --- CSV UPLOAD ---

    // Modello scaricabile: il riquadro di esempio andava ricopiato a mano, ed
    // e' li' che nascevano le intestazioni sbagliate.
    // 'Site' e' nel modello anche se opzionale: Group (tenant) e Site (sede
    // fisica) sono due cose diverse, e vederle affiancate con valori diversi
    // le distingue meglio di qualunque nota. Omessa, Site vale 'central'.
    const CSV_TEMPLATE = [
        'IP,Username,Password,Enable Secret,Hostname,Group,Site,Vendor',
        '192.0.2.1,admin,Mypass123!,enablepass,switch-01,Tenant_Milano,central,cisco',
        '198.51.100.1,manager,Pwd456!,secret,switch-02,Tenant_Roma,sede-roma,hpe',
        ''
    ].join('\n');

    // The Site column has to carry the site id, not its name, and that id is a
    // slug the operator never typed. Showing the real ones next to the rule
    // saves a trip to the Sites tab. If the call fails the row stays hidden and
    // the written rule above still stands.
    async function loadImportSiteIds() {
        const box = document.getElementById('importSiteIds');
        const list = document.getElementById('importSiteIdsList');
        if (!box || !list) return;
        const res = await apiFetch('/api/sites');
        if (!res || !res.ok) return;
        const sites = (await res.json()).sites || [];
        if (!sites.length) return;
        list.innerHTML = sites.map(s =>
            `<code style="margin-right:6px;">${escapeHtml(s.id)}</code>`).join('');
        box.style.display = 'block';
    }
    window.loadImportSiteIds = loadImportSiteIds;

    const btnTemplate = document.getElementById('btnDownloadCsvTemplate');
    if (btnTemplate) {
        btnTemplate.addEventListener('click', () => {
            // BOM in testa: senza, Excel apre il file interpretandolo in ANSI e
            // storpia gli accenti dei nomi di sede.
            const blob = new Blob(['﻿' + CSV_TEMPLATE],
                                  { type: 'text/csv;charset=utf-8' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'sentinelnet-inventario-modello.csv';
            a.click();
            URL.revokeObjectURL(a.href);
        });
    }

    const csvZone = document.getElementById('csvDropZone');
    const csvInput = document.getElementById('csvFileInput');
    const csvDropText = document.getElementById('csvDropText');

    function showCsvFile(file) {
        if (!csvDropText) return;
        csvDropText.innerHTML = `<i class="fa-solid fa-file-circle-check fa-2x" style="color:var(--success); margin-bottom:8px;"></i><br>
            <strong>${escapeHtml(file.name)}</strong>
            <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">${Math.max(1, Math.round(file.size / 1024))} KB</div>`;
    }

    if (csvZone && csvInput) {
        csvZone.onclick = () => csvInput.click();
        csvZone.ondragover = e => { e.preventDefault(); csvZone.style.borderColor = 'var(--primary)'; };
        csvZone.ondragleave = () => { csvZone.style.borderColor = 'var(--border)'; };
        csvZone.ondrop = e => {
            e.preventDefault();
            csvZone.style.borderColor = 'var(--border)';
            if (e.dataTransfer.files.length) {
                csvInput.files = e.dataTransfer.files;
                showCsvFile(e.dataTransfer.files[0]);
            }
        };
        csvInput.onchange = () => {
            if (csvInput.files.length) showCsvFile(csvInput.files[0]);
        };
    }

    function renderCsvImportResult(result, errorDetail) {
        const box = document.getElementById('csvImportResult');
        if (!box) return;
        const en = currentLang === 'en';
        box.style.display = '';
        if (errorDetail) {
            box.innerHTML = `<div style="padding:12px 14px; border-radius:0; border:1px solid var(--danger); background:color-mix(in srgb, var(--danger) 10%, transparent); font-size:13px; color:var(--danger);">
                <i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(errorDetail)}</div>`;
            return;
        }
        const ok = (result.imported || []).length;
        const failed = result.failed || [];
        const rowsHtml = failed.map(f => `
            <tr style="border-top:1px solid var(--border);">
                <td style="padding:5px 8px; color:var(--text-muted);">${escapeHtml(String(f.row))}</td>
                <td style="padding:5px 8px; font-family:var(--font-code);">${escapeHtml(String(f.ip))}</td>
                <td style="padding:5px 8px; color:var(--danger);">${escapeHtml(String(f.error))}</td>
            </tr>`).join('');
        box.innerHTML = `
            <div style="padding:12px 14px; border-radius:0; border:1px solid ${failed.length ? 'var(--warning)' : 'var(--success)'}; background:${failed.length ? 'color-mix(in srgb, var(--warning) 10%, transparent)' : 'color-mix(in srgb, var(--success) 10%, transparent)'}; font-size:13px;">
                <strong>${ok}</strong> ${en ? 'devices imported' : 'dispositivi importati'}${failed.length ? ` · <strong>${failed.length}</strong> ${en ? 'rows skipped' : 'righe scartate'}` : ''}
            </div>
            ${failed.length ? `
            <div class="table-container" style="margin-top:10px;">
                <table style="font-size:12px;">
                    <thead><tr>
                        <th>${en ? 'Row' : 'Riga'}</th><th>IP</th><th>${en ? 'Reason' : 'Motivo'}</th>
                    </tr></thead>
                    <tbody>${rowsHtml}</tbody>
                </table>
            </div>` : ''}`;
    }

    document.getElementById('btnUploadCsv').addEventListener('click', async () => {
        const fileInput = document.getElementById('csvFileInput');
        if (fileInput.files.length === 0) { alert(i18n[currentLang].alertSelectCsv); return; }

        const file = fileInput.files[0];
        const reader = new FileReader();
        reader.onload = async function(e) {
            const text = e.target.result;
            try {
                const res = await apiFetch('/api/import-csv', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ csv_data: text })
                });
                if (res && res.ok) {
                    const result = await res.json();
                    renderCsvImportResult(result, null);
                    fileInput.value = "";
                    appInit();
                    // Non si cambia piu' tab automaticamente: l'elenco delle
                    // righe scartate e' proprio qui, e passare all'inventario
                    // lo faceva sparire prima che qualcuno lo leggesse.
                } else if (res) {
                    let detail = '';
                    try { const err = await res.json(); detail = err && err.detail; } catch (e2) {}
                    renderCsvImportResult(null, detail || i18n[currentLang].alertImportCsvError);
                }
            } catch (err) {
                renderCsvImportResult(null, `${i18n[currentLang].alertError}${err}`);
            }
        };
        reader.readAsText(file);
    });

    // Sites for the inventory's Sede column. Cached: the list changes only when
    // an admin edits it in the Sedi tab, and renderDevices runs on every poll.
    let _sitesCache = null;

    async function loadDeviceSites() {
        if (_sitesCache) return _sitesCache;
        const res = await apiFetch('/api/sites');
        _sitesCache = (res && res.ok) ? (await res.json()).sites || [] : [];
        return _sitesCache;
    }

    async function reassignDeviceSite(ip, newSite, selectEl) {
        const dev = globalDevices.find(d => d.IP === ip);
        if (!dev || newSite === (dev.Site || 'central')) return;
        const previous = dev.Site || 'central';
        selectEl.disabled = true;
        try {
            const res = await apiFetch('/api/reassign-device-site', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, new_site: newSite })
            });
            if (res && res.ok) {
                dev.Site = newSite;
                // The site decides HOW the device is reached, so the row's
                // reachability semantics change with it: a jump site has no
                // ICMP. Re-fetch rather than guess the new state here.
                appInit();
            } else {
                selectEl.value = previous;
                const e = res ? await res.json() : {};
                alert((currentLang === 'en' ? 'Error: ' : 'Errore: ') + (e.detail || ''));
            }
        } finally {
            selectEl.disabled = false;
        }
    }

    async function reassignDevice(ip, newGroup, selectEl) {
        const dev = globalDevices.find(d => d.IP === ip);
        const originalGroup = dev?.Group;
        if (!dev || newGroup === originalGroup) return;

        selectEl.disabled = true;
        const safeIp = ip.replace(/\./g, "_");

        try {
            const res = await apiFetch("/api/reassign-device", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ip, new_group: newGroup })
            });

            if (res && res.ok) {
                dev.Group = newGroup;
                const badge = document.getElementById(`badge_${safeIp}`);
                if (badge) badge.textContent = newGroup;
                const filterSelect = document.getElementById("filterGroupSelect");
                const selectedGroup = filterSelect ? filterSelect.value : "all";
                if (selectedGroup !== "all" && newGroup !== selectedGroup) {
                    const row = selectEl.closest("tr");
                    if (row) {
                        row.style.transition = "opacity 0.4s";
                        row.style.opacity = "0";
                        setTimeout(() => row.remove(), 400);
                    }
                }
            } else {
                const err = res ? await res.json() : null;
                const errDetail = err?.detail || (currentLang === 'en' ? "Unknown error" : "Errore sconosciuto");
                alert(`${i18n[currentLang].alertReassignmentError}${errDetail}`);
                selectEl.value = originalGroup;
            }
        } catch (err) {
            alert(i18n[currentLang].alertNetworkReassignmentError);
            selectEl.value = originalGroup;
        }
        selectEl.disabled = false;
    }

    // topology.js is lazy-loaded only for the map/categories tabs (see
    // LAZY_TAB_SCRIPTS in core.js), so on the devices tab the identifier is
    // simply not there. Calling it bare threw a ReferenceError that aborted
    // the caller mid-way: a successful triage was repainted OFFLINE by its own
    // catch, and the button was left spinning forever.
    function setMapNodeStatus(ip, status) {
        window.updateTopologyMapNodeStatus?.(ip, status);
    }

    let pingInProgress = false;

    async function pingSingleDevice(ip, btnEl) {
        const row = btnEl?.closest("tr");
        const led = row?.cells[0]?.querySelector(".led");
        const ledContainer = row?.cells[0]?.querySelector(".led-container");

        btnEl.disabled = true;
        btnEl.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
        if (led) { led.className = "led led-auth_failed"; }

        try {
            const res = await apiFetch(`/api/ping/${ip}`);
            if (res && res.ok) {
                const data = await res.json();
                // null = not measurable (jump site: ICMP cannot cross the
                // bastion tunnel, see routers/triage.py's ping_single). Show
                // the same em dash the row already uses on load, not a false
                // "OFFLINE" from a ping that never ran.
                if (data.reachable === null) {
                    if (led) led.className = "led";
                    if (ledContainer) {
                        ledContainer.title = i18n[currentLang].jumpLimitsPing;
                        Array.from(ledContainer.childNodes)
                            .filter(n => n.nodeType === Node.TEXT_NODE)
                            .forEach(n => n.remove());
                        ledContainer.appendChild(document.createTextNode('—'));
                    }
                    if (globalVersions[ip]) globalVersions[ip].status = "unknown";
                    setMapNodeStatus(ip, "unknown");
                } else {
                    const statusTxt = data.reachable ? "ONLINE" : "OFFLINE";
                    if (led) {
                        led.className = data.reachable ? "led led-online" : "led led-offline";
                    }
                    if (ledContainer) {
                        Array.from(ledContainer.childNodes)
                            .filter(n => n.nodeType === Node.TEXT_NODE)
                            .forEach(n => n.remove());
                        ledContainer.appendChild(document.createTextNode(` ${statusTxt}`));
                    }

                    // Update globalVersions cache
                    if (!globalVersions[ip]) {
                        globalVersions[ip] = {
                            version: currentLang === 'en' ? "Not Scanned" : "Non Scansionato",
                            vendor: "cisco"
                        };
                    }
                    globalVersions[ip].status = data.reachable ? "online" : "offline";

                    // Update map node status
                    setMapNodeStatus(ip, data.reachable ? "online" : "offline");
                }
            }
        } catch(e) {}

        btnEl.disabled = false;
        btnEl.innerHTML = '<i class="fa-solid fa-wifi"></i>';
    }

    async function triageSingleDevice(ip, btnEl) {
        const row = btnEl?.closest("tr");
        const led          = row?.cells[0]?.querySelector(".led");
        const ledContainer = row?.cells[0]?.querySelector(".led-container");
        const hostnameCell = row?.cells[3];                    // Hostname column (was cells[2])
        const verCell      = row?.cells[6]?.querySelector("code"); // Firmware column (was cells[5] — off by one after Hostname added)

        btnEl.disabled = true;
        btnEl.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
        if (led) led.className = "led led-auth_failed";

        try {
            const res = await apiFetch(`/api/triage/${ip}`, { method: "POST" });
            if (res && res.ok) {
                const data = await res.json();
                if (data.status === "success") {
                    if (led) led.className = "led led-online";
                    if (ledContainer) {
                        Array.from(ledContainer.childNodes)
                            .filter(n => n.nodeType === Node.TEXT_NODE)
                            .forEach(n => n.remove());
                        ledContainer.appendChild(document.createTextNode(" ONLINE"));
                    }

                    if (verCell && data.version) verCell.textContent = data.version;

                    if (hostnameCell && data.hostname) {
                        hostnameCell.style.fontFamily = "monospace";
                        hostnameCell.style.fontSize   = "12px";
                        hostnameCell.textContent      = data.hostname;
                    }

                    if (globalVersions[ip]) {
                        globalVersions[ip].version = data.version || globalVersions[ip].version;
                        globalVersions[ip].status  = "online";
                    }
                    const dev = globalDevices.find(d => d.IP === ip);
                    if (dev && data.hostname) dev.Hostname = data.hostname;

                    setMapNodeStatus(ip, "online");

                } else {
                    if (led) led.className = "led led-offline";
                    if (ledContainer) {
                        Array.from(ledContainer.childNodes)
                            .filter(n => n.nodeType === Node.TEXT_NODE)
                            .forEach(n => n.remove());
                        ledContainer.appendChild(document.createTextNode(" OFFLINE"));
                    }
                    if (globalVersions[ip]) {
                        globalVersions[ip].status = "offline";
                    }
                    setMapNodeStatus(ip, "offline");
                    const msgDetail = data.message || (currentLang === 'en' ? "Unknown error" : "Errore sconosciuto");
                    alert(`${i18n[currentLang].alertTriageFailed}${msgDetail}`);
                }
            }
        } catch(e) {
            if (led) led.className = "led led-offline";
            if (ledContainer) {
                Array.from(ledContainer.childNodes)
                    .filter(n => n.nodeType === Node.TEXT_NODE)
                    .forEach(n => n.remove());
                ledContainer.appendChild(document.createTextNode(" OFFLINE"));
            }
            if (globalVersions[ip]) {
                globalVersions[ip].status = "offline";
            }
            setMapNodeStatus(ip, "offline");
        } finally {
            btnEl.disabled = false;
            btnEl.innerHTML = '<i class="fa-solid fa-bolt-lightning"></i>';
        }
    }

    async function runPingCheck() {
        if (pingInProgress) return;
        pingInProgress = true;

        const btn = document.getElementById("btnPingCheck");
        const filterSelect = document.getElementById("filterGroupSelect");
        const group = filterSelect ? filterSelect.value : "all";
        const groupLabel = group === "all" ? i18n[currentLang].allSites : group;

        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${i18n[currentLang].pingingBtnText.replace("{group}", groupLabel)}`;

        try {
            const res = await apiFetch("/api/ping-check", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ group })
            });
            if (res && res.ok) {
                const data = await res.json();
                applyPingResultsToTable(data.results);
            } else {
                alert(i18n[currentLang].alertPingError);
            }
        } catch (err) {
            console.error("Ping check error:", err);
        }

        btn.innerHTML = i18n[currentLang].btnPingCheck;
        btn.disabled = false;
        pingInProgress = false;
    }

    function applyPingResultsToTable(results) {
        const rows = document.querySelectorAll("#deviceTableBody tr");
        rows.forEach(row => {
            const ip = row.querySelector("strong")?.textContent?.trim();
            if (!ip || !(ip in results)) return;

            const ledContainer = row.cells[0].querySelector(".led-container");
            if (!ledContainer) return;

            const alive = results[ip];
            const led = ledContainer.querySelector(".led");

            // null = not measurable (jump site: ICMP cannot cross the bastion
            // tunnel, see routers/triage.py's ping_check) — same em dash the
            // row already uses on load, not a false "OFFLINE".
            if (alive === null) {
                if (led) led.className = "led";
                ledContainer.title = i18n[currentLang].jumpLimitsPing;
                Array.from(ledContainer.childNodes)
                    .filter(n => n.nodeType === Node.TEXT_NODE)
                    .forEach(n => n.remove());
                ledContainer.appendChild(document.createTextNode('—'));
                if (globalVersions[ip]) globalVersions[ip].status = "unknown";
                setMapNodeStatus(ip, "unknown");
                return;
            }

            const ledClass  = alive ? "led-online" : "led-offline";
            const statusTxt = alive ? "ONLINE" : "OFFLINE";

            if (led) led.className = `led ${ledClass}`;

            Array.from(ledContainer.childNodes)
                .filter(n => n.nodeType === Node.TEXT_NODE)
                .forEach(n => n.remove());
            ledContainer.appendChild(document.createTextNode(` ${statusTxt}`));

            // Update globalVersions cache
            if (!globalVersions[ip]) {
                globalVersions[ip] = {
                    version: currentLang === 'en' ? "Not Scanned" : "Non Scansionato",
                    vendor: "cisco"
                };
            }
            globalVersions[ip].status = alive ? "online" : "offline";

            // Update map node status
            setMapNodeStatus(ip, alive ? "online" : "offline");
        });
    }

    async function loadRedundancyGroups() {
        try {
            const res = await apiFetch('/api/redundancy/groups');
            if (!res || !res.ok) return [];
            const data = await res.json();
            return data.results || [];
        } catch (e) {
            return [];
        }
    }
    window.loadRedundancyGroups = loadRedundancyGroups;

    document.getElementById('filterGroupSelect')?.addEventListener('change', renderDeviceTable);
    document.getElementById('deviceSearch')?.addEventListener('input', renderDeviceTable);
    document.getElementById('btnTriageSite')?.addEventListener('click', triageCurrentSite);
    document.getElementById('btnPingCheck')?.addEventListener('click', runPingCheck);
    document.getElementById('btnSubnetScan')?.addEventListener('click', openSubnetScanModal);
    document.getElementById('btnBulkCommand')?.addEventListener('click', () => {
        if (typeof openBulkCommandModal === 'function') openBulkCommandModal();
    });
    document.getElementById('btnExportDevices')?.addEventListener('click', openDeviceExportModal);
    document.getElementById('btnRunDeviceExport')?.addEventListener('click', exportDeviceCsv);
    document.getElementById('exportColumnList')?.addEventListener('change', updateMemberHint);
    document.getElementById('btnExportColsToggle')?.addEventListener('click', () => {
        const boxes = Array.from(document.querySelectorAll('#exportColumnList input'));
        const turnOn = boxes.some(b => !b.checked);
        boxes.forEach(b => { b.checked = turnOn; });
        updateMemberHint();
    });
    document.getElementById('deviceExportModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'deviceExportModal' || e.target.closest('#btnCloseDeviceExport')) {
            document.getElementById('deviceExportModal').style.display = 'none';
        }
    });
    document.getElementById('btnCancelEditDevice')?.addEventListener('click', resetDeviceForm);
    document.getElementById('btnAddVendor')?.addEventListener('click', addVendor);

    // Subnet Scan modal listeners
    document.getElementById('btnCloseSubnetScan')?.addEventListener('click', closeSubnetScanModal);
    document.getElementById('btnScanRunBackground')?.addEventListener('click', () => {
        closeSubnetScanModal();
        const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
        showToast(L.msgScanRunningBackground || (currentLang === 'en' ? 'Scan is continuing in the background.' : 'La scansione continua in background.'), 'info');
    });
    document.getElementById('floatingScanWidget')?.addEventListener('click', () => {
        switchToDevicesAndOpenScan();
    });
    document.getElementById('subnetScanModal')?.addEventListener('click', (e) => {
        const portBtn = e.target.closest('[data-action="add-scan-port"]');
        if (portBtn && portBtn.dataset.port) {
            addScanPort(Number(portBtn.dataset.port));
        }
    });
    document.getElementById('btnAvviaScan')?.addEventListener('click', startSubnetScan);
    document.getElementById('btnScanVerify')?.addEventListener('click', verifySelectedScanRows);
    document.getElementById('btnScanAddSelected')?.addEventListener('click', addSelectedScanRows);

    // Triage Scope modal listeners
    document.getElementById('btnCloseTriageScope')?.addEventListener('click', closeTriageScopeModal);
    document.getElementById('btnStartGroupTriageAll')?.addEventListener('click', () => startGroupTriage('all'));

