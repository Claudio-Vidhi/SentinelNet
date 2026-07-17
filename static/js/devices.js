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
                ? `<button onclick="renameGroup(this.dataset.g)" data-g="${escapeHtml(g)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:12px;">${renameText}</button>` : '';

            groupBody.innerHTML += `<tr>
                <td><strong>${escapeHtml(g)}</strong></td>
                <td><span style="color:var(--text-muted); font-size:13px;">${escapeHtml(desc)}</span></td>
                <td>${currentRole === 'viewer'
                    ? '<span style="color:var(--text-muted)">—</span>'
                    : (g !== 'Generale' ? `${renameBtn}<button onclick="deleteGroup(this.dataset.g)" data-g="${escapeHtml(g)}" style="color:var(--danger); background:none; border:none; cursor:pointer;">${btnText}</button>` : reservedText)}</td>
            </tr>`;
        });
    }

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
                    <span class="badge" id="badge_${safeIp}">${escapeHtml(d.Group)}</span>
                    ${isViewer ? '' : `<select
                      id="grpsel_${safeIp}"
                      onchange="reassignDevice('${d.IP}', this.value, this)"
                      title="${currentLang==='en'?'Move to another tenant without deleting':'Sposta in un altro tenant senza eliminare'}"
                      style="font-size:11px; padding:3px 6px; border-radius:6px;
                             border:1px solid var(--border); background:var(--surface-3);
                             color:var(--text-muted); cursor:pointer; outline:none;
                             max-width:120px; transition:var(--transition);">
                      ${groupOptions}
                    </select>`}
                  </div>
                </td>
                <td><span class="badge" style="background:var(--surface-3); color:var(--text-muted);">${escapeHtml(d.Site || 'central')}</span></td>
                <td style="font-family:monospace; font-size:12px;">
                  ${d.Hostname ? escapeHtml(d.Hostname) : '<span style="color:var(--text-muted)">—</span>'}
                  ${isViewer ? '' : `<button onclick="renameDevice('${d.IP}')"
                      title="${currentLang==='en'?'Rename device':'Rinomina dispositivo'}"
                      style="margin-left:6px; font-size:11px; cursor:pointer; border:none; background:none;
                             color:var(--text-muted); padding:0;">
                      <i class="fa-solid fa-pen"></i></button>`}
                </td>
                <td><strong>${d.IP}</strong></td>
                <td>${escapeHtml(d.Vendor.toUpperCase())}</td>
                <td><code>${escapeHtml(versionText)}</code></td>
                <td class="actions-cell">
                    ${isViewer ? '<span style="color:var(--text-muted)">—</span>' : `
                    <button class="btn btn-secondary btn-small"
                        style="margin:0; padding:4px 8px;"
                        onclick="pingSingleDevice('${d.IP}', this)"
                        title="${currentLang==='en'?'Ping device':'Ping dispositivo'}">
                      <i class="fa-solid fa-wifi"></i>
                    </button>
                    <button class="btn btn-secondary btn-small"
                        style="margin:0; padding:4px 8px; color:var(--warning);"
                        onclick="triageSingleDevice('${d.IP}', this)"
                        title="${currentLang==='en'?'Triage device':'Triage dispositivo'}">
                      <i class="fa-solid fa-bolt-lightning"></i>
                    </button>
                    <button class="btn btn-secondary btn-small" style="margin:0; padding:4px 8px;"
                        onclick="openCliModal('${d.IP}')">
                        <i class="fa-solid fa-terminal"></i> CLI
                    </button>
                    <button class="btn btn-secondary btn-small" style="margin:0; padding:4px 8px;"
                        onclick="editDevice('${d.IP}')"
                        title="${currentLang==='en'?'Edit device':'Modifica dispositivo'}">
                        <i class="fa-solid fa-pen"></i> ${currentLang==='en'?'Edit':'Modifica'}
                    </button>
                    <button class="btn btn-primary btn-small"
                        style="margin:0; width:auto; background:var(--cta); color:var(--cta-text); padding:4px 8px;"
                        onclick="downloadBackup('${d.IP}')">
                        <i class="fa-solid fa-download"></i>
                    </button>
                    <button class="btn btn-danger btn-small"
                        style="margin:0; padding:4px 8px; background:none; border:none;
                               color:var(--danger); cursor:pointer;"
                        onclick="deleteDevice('${d.IP}')">
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
            hint.innerHTML = `${i18n[currentLang].hintIpExists} <a href="#" onclick="editDevice('${v}'); return false;">${i18n[currentLang].hintIpEditLink}</a>`;
        } else { hint.style.display = 'none'; }
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

        if(!payload.ip) { alert(i18n[currentLang].alertEnterIp); return; }

        // §11.5b: la password non è preservata se vuota (add_or_update_device la
        // sovrascrive sempre), quindi in modifica va reinserita per intero --
        // ma solo per il profilo 'custom': con un profilo 'default'/'identity:<id>'
        // le credenziali vivono altrove (rete standard o identità salvata) e non
        // vanno reinserite qui.
        if (editingDeviceIp && payload.profile === 'custom' && (!payload.password || !payload.enable_secret)) {
            alert(i18n[currentLang].alertCredsRequiredOnEdit);
            return;
        }

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
    // per la modifica (§11.5b). Password/secret restano vuoti: vanno reinseriti,
    // perché add_or_update_device sovrascrive sempre le credenziali (nessun
    // "invariato se vuoto" lato backend).
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
        document.getElementById('devPass').value = '';
        document.getElementById('devSecret').value = '';

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
        document.getElementById('devPass').value = '';
        document.getElementById('devSecret').value = '';
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
        const scanVendorSel = document.getElementById('scanVendorSelect');
        if (scanVendorSel) scanVendorSel.innerHTML = buildVendorOptions(scanVendorSel.value || 'cisco');
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
            `<button class="btn btn-secondary" data-g="${escapeHtml(g)}" onclick="startGroupTriage(this.dataset.g)"
                 style="justify-content:flex-start; gap:10px;">
               <i class="fa-solid fa-location-dot" style="color:var(--primary);"></i> ${escapeHtml(g)}
             </button>`).join('');
        document.getElementById('triageScopeModal').style.display = 'flex';
    }

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
                document.getElementById("triageProgressBarFill").style.width = `${pct}%`;
                
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

        document.getElementById('subnetScanResults').style.display = 'none';
        document.getElementById('subnetScanResultsTable').innerHTML = '';
        document.getElementById('subnetScanStatus').textContent = '';
        document.getElementById('scanNetworkInput').value = '';
        document.getElementById('scanAutoAdd').checked = false;
        document.getElementById('btnAvviaScan').disabled = false;
        document.getElementById('subnetScanModal').style.display = 'flex';
    }

    function closeSubnetScanModal() {
        if (_scanJobInterval) { clearInterval(_scanJobInterval); _scanJobInterval = null; }
        document.getElementById('subnetScanModal').style.display = 'none';
    }

    async function startSubnetScan() {
        if (_scanJobInterval) { clearInterval(_scanJobInterval); _scanJobInterval = null; }

        const network = document.getElementById('scanNetworkInput').value.trim();
        const vendor  = document.getElementById('scanVendorSelect').value;
        const group   = document.getElementById('scanGroupSelect').value;
        const autoAdd = document.getElementById('scanAutoAdd').checked;
        if (!network) { document.getElementById('scanNetworkInput').focus(); return; }

        const btn = document.getElementById('btnAvviaScan');
        btn.disabled = true;
        btn.innerHTML = currentLang === 'en' ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Starting...' : '<i class="fa-solid fa-circle-notch fa-spin"></i> Avvio...';
        document.getElementById('subnetScanResults').style.display = 'block';
        document.getElementById('subnetScanStatus').textContent = currentLang === 'en' ? 'Starting scan...' : 'Avvio scansione...';
        document.getElementById('subnetScanResultsTable').innerHTML = '';
        document.getElementById('subnetScanProgressBar').style.width = '0%';

        const res = await apiFetch('/api/scan-subnet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ network, vendor, group, auto_add: autoAdd, use_default_creds: true }),
        });
        if (!res || !res.ok) {
            const err = res ? await res.json() : { detail: currentLang === 'en' ? 'Network error' : 'Errore di rete' };
            document.getElementById('subnetScanStatus').textContent =
                (currentLang === 'en' ? 'Error: ' : 'Errore: ') + (err.detail || (currentLang === 'en' ? 'unable to start scan.' : 'impossibile avviare la scansione.'));
            btn.disabled = false;
            btn.innerHTML = currentLang === 'en' ? '<i class="fa-solid fa-satellite-dish"></i> Start Scan' : '<i class="fa-solid fa-satellite-dish"></i> Avvia Scansione';
            return;
        }
        const { job_id, total_hosts } = await res.json();
        document.getElementById('subnetScanStatus').textContent =
            currentLang === 'en' ? `Scan started — ${total_hosts} hosts to verify...` : `Scansione avviata — ${total_hosts} host da verificare...`;
        btn.innerHTML = currentLang === 'en' ? '<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning...' : '<i class="fa-solid fa-circle-notch fa-spin"></i> Scansione in corso...';
        pollScanJob(job_id, total_hosts);
    }

    function pollScanJob(jobId, totalHosts) {
        _scanJobInterval = setInterval(async () => {
            const res = await apiFetch(`/api/scan-subnet/${jobId}`);
            if (!res || !res.ok) {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                document.getElementById('subnetScanStatus').textContent = currentLang === 'en' ? 'Error during polling.' : 'Errore durante il polling.';
                const b = document.getElementById('btnAvviaScan');
                b.disabled = false;
                b.innerHTML = currentLang === 'en' ? '<i class="fa-solid fa-satellite-dish"></i> Start Scan' : '<i class="fa-solid fa-satellite-dish"></i> Avvia Scansione';
                return;
            }
            const data = await res.json();
            const pct  = totalHosts > 0 ? Math.round((data.progress / totalHosts) * 100) : 0;
            document.getElementById('subnetScanProgressBar').style.width = `${pct}%`;
            document.getElementById('subnetScanStatus').textContent =
                currentLang === 'en' ? `Scanning in progress — ${data.progress}/${totalHosts} hosts processed...` : `Scansione in corso — ${data.progress}/${totalHosts} host elaborati...`;

            if (data.status !== 'running') {
                clearInterval(_scanJobInterval); _scanJobInterval = null;
                const b = document.getElementById('btnAvviaScan');
                b.disabled = false;
                b.innerHTML = currentLang === 'en' ? '<i class="fa-solid fa-satellite-dish"></i> Start Scan' : '<i class="fa-solid fa-satellite-dish"></i> Avvia Scansione';
                document.getElementById('subnetScanProgressBar').style.width = '100%';
                if (data.status === 'error') {
                    document.getElementById('subnetScanStatus').textContent = currentLang === 'en' ? 'Scan finished with error.' : 'Scansione terminata con errore.';
                    return;
                }
                renderScanResults(data.results || []);
            }
        }, 2000);
    }

    function renderScanResults(results) {
        const reachable = results.filter(r => r.reachable);
        const sshOk     = results.filter(r => r.ssh_ok);
        const added     = results.filter(r => r.added);
        document.getElementById('subnetScanStatus').textContent =
            currentLang === 'en'
                ? `Completed — ${reachable.length} reachable, ${sshOk.length} SSH ok, ${added.length} added to inventory.`
                : `Completata — ${reachable.length} raggiungibili, ${sshOk.length} SSH ok, ${added.length} aggiunti all'inventario.`;

        if (sshOk.length === 0) {
            const noHostText = currentLang === 'en' ? 'No hosts responding via SSH.' : 'Nessun host risponde via SSH.';
            document.getElementById('subnetScanResultsTable').innerHTML =
                `<div style="padding:14px; color:var(--text-muted); font-size:13px;">${noHostText}</div>`;
            return;
        }
        const rows = sshOk.map(r => {
            const addText = currentLang === 'en' ? 'Add' : 'Aggiungi';
            const inInventoryText = currentLang === 'en' ? 'In inventory' : 'In inventario';
            const addCell = (!r.added)
                ? `<button class="btn btn-primary btn-small"
                       style="margin:0; padding:3px 8px; width:auto;"
                       data-ip="${escapeHtml(r.ip)}" data-hn="${escapeHtml(r.hostname || '')}" data-vendor="${escapeHtml(r.vendor)}"
                       onclick="addDiscoveredDevice(this.dataset.ip, this.dataset.hn, this.dataset.vendor, this)">
                       ${addText}
                   </button>`
                : `<span style="color:var(--text-muted); font-size:11px;">${inInventoryText}</span>`;
            return `<div style="display:grid; grid-template-columns:130px 1fr 56px 24px 90px;
                        align-items:center; gap:8px; padding:8px 12px;
                        border-bottom:1px solid var(--border); font-size:12px;">
                <span style="font-family:Menlo,monospace; color:var(--primary);">${escapeHtml(r.ip)}</span>
                <span>${r.hostname ? escapeHtml(r.hostname) : '<span style="color:var(--text-muted)">—</span>'}</span>
                <span style="text-transform:uppercase; color:var(--text-muted);">${escapeHtml(r.vendor)}</span>
                <span style="text-align:center; color:${r.ssh_ok ? 'var(--primary)' : 'var(--danger)'};">${r.ssh_ok ? '✓' : '✗'}</span>
                ${addCell}
              </div>`;
        }).join('');
        document.getElementById('subnetScanResultsTable').innerHTML = rows;
        if (added.length > 0) appInit();
    }

    async function addDiscoveredDevice(ip, hostname, vendor, btnEl) {
        const group = document.getElementById('scanGroupSelect').value;
        const res = await apiFetch('/api/add-device', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, vendor, profile: 'default', username: '', password: '', enable_secret: '', group }),
        });
        if (!res || !res.ok) return;
        const inInventoryText = currentLang === 'en' ? 'In inventory' : 'In inventario';
        if (btnEl) {
            btnEl.outerHTML = `<span style="color:var(--text-muted); font-size:11px;">${inInventoryText}</span>`;
        }
        appInit();
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
                if(res && res.ok) {
                    const result = await res.json();
                    const importedCount = result.imported ? result.imported.length : 0;
                    const failedCount = result.failed ? result.failed.length : 0;
                    
                    let msg = i18n[currentLang].csvImportSuccess.replace("{importedCount}", importedCount);
                    if (failedCount > 0) {
                        msg += i18n[currentLang].csvImportFailedRows.replace("{failedCount}", failedCount);
                        result.failed.forEach(f => {
                            msg += i18n[currentLang].csvImportRowDetail
                                .replace("{row}", f.row)
                                .replace("{ip}", f.ip)
                                .replace("{error}", f.error);
                        });
                    }
                    alert(msg);
                    fileInput.value = "";
                    appInit();
                    switchTab('tab-devices');
                } else if (res) {
                    alert(i18n[currentLang].alertImportCsvError);
                }
            } catch (err) {
                alert(`${i18n[currentLang].alertError}${err}`);
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
        const safeIp = ip.replace(/\./g, "_");
        const row = document.querySelector(`#grpsel_${safeIp}`)?.closest("tr");
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
        const safeIp = ip.replace(/\./g, "_");
        const row = document.querySelector(`#grpsel_${safeIp}`)?.closest("tr");
        const led          = row?.cells[0]?.querySelector(".led");
        const ledContainer = row?.cells[0]?.querySelector(".led-container");
        const hostnameCell = row?.cells[2];                    // Hostname column
        const verCell      = row?.cells[5]?.querySelector("code"); // Firmware column (was cells[4] — off by one after Hostname added)

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
            const ipCell = row.cells[3]; // IP is at index 3 — Hostname column shifted it right
            if (!ipCell) return;
            const ip = ipCell.querySelector("strong")?.textContent?.trim();
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
