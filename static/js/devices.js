// static/js/devices.js
// Estratto da templates/dashboard.html: tab-devices (Inventario dispositivi),
// tab-groups (Gruppi/Tenant), Vendor CRUD, triage on-demand/di gruppo, subnet
// scanner in background e CSV import/export. Globals di stato scoping
// triage/scan/device-edit (isTriagePolling, editingDeviceIp, wasTriageRunning,
// _scanJobInterval, pingInProgress) vivono qui perche' usati solo da questo
// modulo.
//
// promoteDevice (Pannello Dispositivi & Categorie / mappa di rete) e
// updateTopologyMapNodeStatus (overlay Visio) restano inline in dashboard.html:
// appartengono alla tab di mappa/topologia, non ancora estratta -- vengono
// richiamati da qui via riferimento cross-modulo a runtime (funzione-corpo),
// il che e' consentito dalla regola di caricamento.

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
    function updateInventoryKpis() {
        let online = 0, offline = 0, authFailed = 0;
        (globalDevices || []).forEach(d => {
            const scan = globalVersions[d.IP] || {};
            if (scan.status === 'online') online++;
            else if (scan.status === 'auth_failed') authFailed++;
            else offline++;
        });
        const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
        setText('invKpiOnline', online);
        setText('invKpiOffline', offline);
        setText('invKpiAuthFailed', authFailed);
    }

    function renderDeviceTable() {
        updateInventoryKpis();

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
                  <span class="led-container">
                    <span class="led ${ledClass}"></span>
                    ${scan.status.toUpperCase()}
                  </span>
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
                <td><span class="badge" style="background:var(--surface-3); color:var(--text-muted);">${escapeHtml(d.Site || 'central')}</span></td>
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
        const payload = {
            ip: document.getElementById('devIp').value.trim(),
            vendor: document.getElementById('devVendor').value,
            profile: document.getElementById('devProfile').value,
            username: document.getElementById('devUser').value,
            password: document.getElementById('devPass').value,
            enable_secret: document.getElementById('devSecret').value,
            group: document.getElementById('devGroupSelect').value,
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

    function addScanPort(port) {
        const input = document.getElementById('scanPortsInput');
        const ports = input.value.split(',').map(s => s.trim()).filter(Boolean);
        if (!ports.includes(String(port))) ports.push(String(port));
        input.value = ports.join(',');
    }

    function openSubnetScanModal() {
        // Populate group select from current globalGroups cache
        const sel = document.getElementById('scanGroupSelect');
        sel.innerHTML = '';
        Object.keys(globalGroups).forEach(g => {
            const opt = document.createElement('option');
            opt.value = g;
            opt.textContent = g;
            if (g === 'Generale') opt.selected = true;
            sel.appendChild(opt);
        });

        _scanRows = [];
        document.getElementById('subnetScanResults').style.display = 'none';
        document.getElementById('scanActionsBar').style.display = 'none';
        document.getElementById('subnetScanResultsTable').innerHTML = '';
        document.getElementById('subnetScanStatus').textContent = '';
        document.getElementById('scanNetworkInput').value = '';
        document.getElementById('scanPortsInput').value = '22';
        // Il vendor torna "non impostato" a ogni apertura, come rete e porte.
        // renderScanResults invece conserva la scelta (le serve per sopravvivere
        // al ridisegno dopo la verifica): senza questo azzeramento il vendor
        // dell'ultima scansione si applicherebbe da solo alla successiva, che e'
        // di nuovo un vendor che l'utente non ha scelto.
        document.getElementById('scanVerifyVendorSelect').innerHTML = buildScanVendorOptions('');
        document.getElementById('btnAvviaScan').disabled = false;
        document.getElementById('subnetScanModal').style.display = 'flex';
    }

    function closeSubnetScanModal() {
        if (_scanJobInterval) { clearInterval(_scanJobInterval); _scanJobInterval = null; }
        document.getElementById('subnetScanModal').style.display = 'none';
    }

    function scanStartButtonIdle() {
        const b = document.getElementById('btnAvviaScan');
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
        pollScanJob(job_id, total_hosts);
    }

    function pollScanJob(jobId, totalHosts) {
        _scanJobInterval = setInterval(async () => {
            const res = await apiFetch(`/api/scan-subnet/${jobId}`);
            if (!res || !res.ok) {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                document.getElementById('subnetScanStatus').textContent =
                    currentLang === 'en' ? 'Error during polling.' : 'Errore durante il polling.';
                scanStartButtonIdle();
                return;
            }
            const data = await res.json();
            const total = data.total || totalHosts;
            const pct = total > 0 ? Math.round((data.progress / total) * 100) : 0;
            document.getElementById('subnetScanProgressBar').style.transform = `scaleX(${pct / 100})`;
            document.getElementById('subnetScanStatus').textContent = currentLang === 'en'
                ? `Scanning — ${data.progress}/${total} hosts processed...`
                : `Scansione in corso — ${data.progress}/${total} host elaborati...`;

            if (data.status !== 'running') {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                scanStartButtonIdle();
                document.getElementById('subnetScanProgressBar').style.transform = 'scaleX(1)';
                if (data.status === 'error') {
                    document.getElementById('subnetScanStatus').textContent =
                        currentLang === 'en' ? 'Scan finished with error.' : 'Scansione terminata con errore.';
                    return;
                }
                _scanRows = (data.results || []).map(r => ({ ...r, verify: null }));
                renderScanResults(_scanRows);
            }
        }, 2000);
    }

    function selectedScanIps() {
        return Array.from(document.querySelectorAll('.scan-row-cb:checked'))
            .map(cb => cb.dataset.ip);
    }

    function refreshScanActionButtons() {
        const n = selectedScanIps().length;
        const L = i18n[currentLang];
        const identity = document.getElementById('scanIdentitySelect').value;
        const vendor = document.getElementById('scanVerifyVendorSelect').value;
        const verifyBtn = document.getElementById('btnScanVerify');
        const addBtn = document.getElementById('btnScanAddSelected');
        verifyBtn.textContent = (L.btnScanVerify || 'Verifica selezionati ({n})').replace('{n}', n);
        addBtn.textContent = (L.btnScanAddSelected || 'Aggiungi selezionati ({n})').replace('{n}', n);
        // Verify authenticates: it needs a selection, an identity AND a vendor
        // (probe_device resolves the driver from it — there is no sane default).
        verifyBtn.disabled = n === 0 || !identity || !vendor;
        addBtn.disabled = n === 0;
    }

    function renderScanResults(rows) {
        const L = i18n[currentLang];
        document.getElementById('subnetScanStatus').textContent =
            (L.scanFoundCount || 'Trovati {n} host').replace('{n}', rows.length);

        if (rows.length === 0) {
            document.getElementById('subnetScanResultsTable').innerHTML =
                `<div style="padding:14px; color:var(--text-muted); font-size:13px;">${
                    escapeHtml(L.scanNoHosts || 'Nessun host ha risposto.')}</div>`;
            document.getElementById('scanActionsBar').style.display = 'none';
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
            const ports = r.open_ports.length
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

        document.getElementById('subnetScanResultsTable').innerHTML = header + body;
        document.getElementById('scanActionsBar').style.display = 'flex';
        populateScanIdentitySelect();
        const vendorSel = document.getElementById('scanVerifyVendorSelect');
        vendorSel.innerHTML = buildScanVendorOptions(vendorSel.value);
        vendorSel.onchange = refreshScanActionButtons;
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
        const L = i18n[currentLang];
        const res = await apiFetch('/api/identities');
        const identities = (res && res.ok) ? (await res.json()).identities || [] : [];
        // Empty value = no identity chosen: verify stays disabled, add still works.
        sel.innerHTML = `<option value="">${
            escapeHtml(L.optScanNoIdentity || '— nessuna (solo scoperta) —')}</option>` +
            identities.map(i => `<option value="${escapeHtml(i.id)}">${
                escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('');
        sel.onchange = refreshScanActionButtons;
    }

    async function verifySelectedScanRows() {
        const ips = selectedScanIps();
        const identityId = document.getElementById('scanIdentitySelect').value;
        const vendor = document.getElementById('scanVerifyVendorSelect').value;
        if (!ips.length || !identityId) return;

        const L = i18n[currentLang];
        document.getElementById('btnScanVerify').disabled = true;

        const res = await apiFetch('/api/scan-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ips, vendor, identity_id: identityId }),
        });
        if (!res || !res.ok) {
            const err = res ? await res.json() : { detail: currentLang === 'en' ? 'Network error' : 'Errore di rete' };
            document.getElementById('subnetScanStatus').textContent =
                (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (err.detail || '');
            refreshScanActionButtons();
            return;
        }
        const { job_id } = await res.json();

        // Same job machinery and same polling endpoint as the scan, but a job
        // of its own: the discovery job may already have been collected.
        const interval = setInterval(async () => {
            const poll = await apiFetch(`/api/scan-subnet/${job_id}`);
            if (!poll || !poll.ok) {
                clearInterval(interval);
                document.getElementById('subnetScanStatus').textContent =
                    currentLang === 'en' ? 'Error during polling.' : 'Errore durante il polling.';
                refreshScanActionButtons();
                return;
            }
            const data = await poll.json();
            document.getElementById('subnetScanStatus').textContent =
                (L.scanVerifyRunning || 'Verifica in corso — {done}/{total}...')
                    .replace('{done}', data.progress).replace('{total}', data.total);

            if (data.status !== 'running') {
                clearInterval(interval);
                if (data.status === 'error') {
                    document.getElementById('subnetScanStatus').textContent =
                        currentLang === 'en' ? 'Verify finished with error.' : 'Verifica terminata con errore.';
                    refreshScanActionButtons();
                    return;
                }
                // Merge by IP into the rows already on screen.
                const selected = new Set(ips);
                (data.results || []).forEach(v => {
                    const row = _scanRows.find(r => r.ip === v.ip);
                    if (row) row.verify = v;
                });
                renderScanResults(_scanRows);
                // renderScanResults rebuilds the table, so restore the selection.
                document.querySelectorAll('.scan-row-cb').forEach(cb => {
                    cb.checked = selected.has(cb.dataset.ip);
                });
                refreshScanActionButtons();
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

    async function exportDeviceCsv() {
        const res = await apiFetch("/api/export/devices");
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
                updateTopologyMapNodeStatus(ip, data.reachable ? "online" : "offline");
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

                    updateTopologyMapNodeStatus(ip, "online");

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
                    updateTopologyMapNodeStatus(ip, "offline");
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
            updateTopologyMapNodeStatus(ip, "offline");
        }

        btnEl.disabled = false;
        btnEl.innerHTML = '<i class="fa-solid fa-bolt-lightning"></i>';
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

            const alive     = results[ip];
            const ledClass  = alive ? "led-online" : "led-offline";
            const statusTxt = alive ? "ONLINE" : "OFFLINE";

            const led = ledContainer.querySelector(".led");
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
            updateTopologyMapNodeStatus(ip, alive ? "online" : "offline");
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
    document.getElementById('btnExportDevices')?.addEventListener('click', exportDeviceCsv);
    document.getElementById('btnCancelEditDevice')?.addEventListener('click', resetDeviceForm);
    document.getElementById('btnAddVendor')?.addEventListener('click', addVendor);

    // Subnet Scan modal listeners
    document.getElementById('btnCloseSubnetScan')?.addEventListener('click', closeSubnetScanModal);
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

