// static/js/provisioning.js
// Estratto da templates/dashboard.html: tab-provisioning (form di provisioning
// apparato + pannello Identità, parte tab-owned) e tab-provisioner (wizard ZTP
// switch/FortiGate). La gestione del token API FortiGate e la vista live degli
// oggetti firewall sono state rimosse da qui: erano un duplicato della tab
// Fortigate Management (static/js/fortigate-management.js), che ora è
// l'unica proprietaria di quella UI.
//
// refreshIdentityOptions/renderIdentitiesPanel e buildVendorOptions/
// renderVendorTable sono stati promossi a static/js/core.js perché usati anche
// dalla tab Devices (editDevice) e dalla tab Groups (btnCreateGroup,
// loadVendors), ancora inline in dashboard.html.

document.getElementById('devGroupSelect').addEventListener('change', async () => { await refreshIdentityOptions(); renderIdentitiesPanel(); });

// --- IDENTITIES CRUD (pannello destro della tab Provisioning) ---

async function populateIdentTenantOptions(selected) {
    const sel = document.getElementById('identTenant');
    if (!sel) return;
    try {
        const res = await apiFetch('/api/groups');
        if (res && res.ok) {
            const data = await res.json();
            globalGroups = (data && data.groups) ? data.groups : (data || {});
        }
    } catch (e) { /* fallback */ }
    const fromGlobal = Object.keys(globalGroups || {});
    const fromDevs = (globalDevices || []).map(d => d.Group).filter(Boolean);
    const allTenants = [...new Set(['Generale', ...fromGlobal, ...fromDevs])].sort();
    if (typeof window.populateGenCfgTenants === 'function') window.populateGenCfgTenants();

    // Single select options
    const options = [`<option value="all">${escapeHtml(i18n[currentLang].optTenantAll || 'Tutti i tenant (Globale)')}</option>`]
        .concat(allTenants.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`));
    sel.innerHTML = options.join('');

    // Multi-tenant checkboxes
    const cbContainer = document.getElementById('identTenantCheckboxes');
    if (cbContainer) {
        cbContainer.innerHTML = allTenants.map(t => `
          <label style="font-size:12px; font-weight:normal; cursor:pointer; display:flex; align-items:center; gap:8px;">
            <input type="checkbox" class="identTenantCb" value="${escapeHtml(t)}" style="width:auto; margin:0;">
            <span>${escapeHtml(t)}</span>
          </label>
        `).join('');
    }

    // Wire checkbox toggle listener
    const chkSpecific = document.getElementById('chkIdentSpecificTenant');
    const singleWrap = document.getElementById('identTenantSingleWrap');
    const multiWrap = document.getElementById('identTenantMultiWrap');

    if (chkSpecific && !chkSpecific._wired) {
        chkSpecific._wired = true;
        chkSpecific.addEventListener('change', () => {
            if (chkSpecific.checked) {
                if (singleWrap) singleWrap.style.display = 'none';
                if (multiWrap) multiWrap.style.display = 'block';
            } else {
                if (singleWrap) singleWrap.style.display = 'block';
                if (multiWrap) multiWrap.style.display = 'none';
                if (sel) sel.value = 'all';
            }
        });
    }

    // Initialize state from 'selected'
    const isGlobal = !selected || selected === 'all' || (Array.isArray(selected) && (selected.length === 0 || selected.includes('all')));
    if (chkSpecific) chkSpecific.checked = !isGlobal;
    if (singleWrap) singleWrap.style.display = isGlobal ? 'block' : 'none';
    if (multiWrap) multiWrap.style.display = isGlobal ? 'none' : 'block';

    if (isGlobal) {
        sel.value = 'all';
    } else {
        const selArray = Array.isArray(selected) ? selected : String(selected).split(',').map(s => s.trim());
        document.querySelectorAll('.identTenantCb').forEach(cb => {
            cb.checked = selArray.includes(cb.value);
        });
        if (selArray.length === 1) sel.value = selArray[0];
    }
}

async function editIdentity(id) {
    const i = (window._tenantIdentities || []).find(x => x.id === id);
    if (!i) return;
    document.getElementById('identEditId').value = id;
    document.getElementById('identName').value = i.name;
    await populateIdentTenantOptions(i.tenant || 'all');
    document.getElementById('identUser').value = i.username;
    document.getElementById('identPass').value = '';
    document.getElementById('identSecret').value = '';
    document.getElementById('identityForm').style.display = 'block';
}

async function deleteIdentity(id) {
    if (!confirm(i18n[currentLang].confirmDeleteIdentity)) return;
    const res = await apiFetch('/api/identities/' + id, { method: 'DELETE' });
    if (res && res.status === 409) {
        const err = await res.json();
        alert(i18n[currentLang].alertIdentityInUse + '\n' + (err.detail.devices || []).join(', '));
        return;
    }
    await refreshIdentityOptions(); renderIdentitiesPanel();
}

document.getElementById('btnNewIdentity').addEventListener('click', async () => {
    document.getElementById('identEditId').value = '';
    ['identName', 'identUser', 'identPass', 'identSecret'].forEach(i => document.getElementById(i).value = '');
    await populateIdentTenantOptions(document.getElementById('devGroupSelect').value || 'all');
    document.getElementById('identityForm').style.display = 'block';
});
document.getElementById('btnCancelIdentity').addEventListener('click', () => {
    ['identPass', 'identSecret'].forEach(i => { const el = document.getElementById(i); if (el) el.value = ''; });
    document.getElementById('identityForm').style.display = 'none';
});
document.getElementById('btnSaveIdentity').addEventListener('click', async () => {
    const id = document.getElementById('identEditId').value;
    const chkSpecific = document.getElementById('chkIdentSpecificTenant');
    let tenantPayload = 'all';

    if (chkSpecific && chkSpecific.checked) {
        const selectedCbs = Array.from(document.querySelectorAll('.identTenantCb:checked')).map(cb => cb.value);
        if (!selectedCbs.length) {
            alert(i18n[currentLang].alertSelectTenant || 'Seleziona almeno un tenant.');
            return;
        }
        tenantPayload = selectedCbs.length === 1 ? selectedCbs[0] : selectedCbs;
    } else {
        tenantPayload = 'all';
    }

    const passEl = document.getElementById('identPass');
    const secretEl = document.getElementById('identSecret');
    const payload = {
        name: document.getElementById('identName').value.trim(),
        tenant: tenantPayload,
        username: document.getElementById('identUser').value.trim(),
        password: passEl ? passEl.value : '',
        enable_secret: secretEl ? secretEl.value : '',
    };
    if (!payload.name || !payload.username || (!id && !payload.password)) {
        alert(i18n[currentLang].alertIdentityFields); return;
    }
    const res = await apiFetch(id ? '/api/identities/' + id : '/api/identities', {
        method: id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (res && res.ok) {
        if (passEl) passEl.value = '';
        if (secretEl) secretEl.value = '';
        document.getElementById('identityForm').style.display = 'none';
        await refreshIdentityOptions(); renderIdentitiesPanel();
    } else if (res) {
        const err = await res.json();
        alert(err.detail || 'Errore');
    }
});

// --- SWITCH PROVISIONER ("Switch da Zero") ---

function provParseVlans(text) {
    // "10:DATA, 20:VOICE" -> [{id:10, name:'DATA'}, ...]
    return (text || '').split(',').map(s => s.trim()).filter(Boolean).map(chunk => {
        const [id, name] = chunk.split(':').map(p => (p || '').trim());
        return { id: parseInt(id, 10), name: name || `VLAN${id}` };
    }).filter(v => !isNaN(v.id));
}

function provParseSvis(text) {
    // "10:10.1.10.1:255.255.255.0" -> [{vlan:10, ip:'10.1.10.1', mask:'255.255.255.0'}]
    return (text || '').split(',').map(s => s.trim()).filter(Boolean).map(chunk => {
        const [vlan, ip, mask] = chunk.split(':').map(p => (p || '').trim());
        return { vlan: parseInt(vlan, 10), ip, mask };
    }).filter(s => !isNaN(s.vlan) && s.ip && s.mask);
}

function provParseRanges(text) {
    return (text || '').split(',').map(s => s.trim()).filter(Boolean);
}

function provCollectPayload() {
    const aaaProtocol = document.getElementById('provAaaProtocol')?.value || 'none';
    const payload = {
        hostname: document.getElementById('provHostname').value.trim() || 'Switch',
        role: document.getElementById('provRole').value,
        domain: document.getElementById('provDomain').value.trim(),
        mgmt_vlan: parseInt(document.getElementById('provMgmtVlan').value, 10) || null,
        mgmt_ip: document.getElementById('provMgmtIp').value.trim(),
        mgmt_mask: document.getElementById('provMgmtMask').value.trim(),
        mgmt_gw: document.getElementById('provMgmtGw').value.trim(),
        admin_user: document.getElementById('provAdminUser').value.trim(),
        admin_password: document.getElementById('provAdminPass').value,
        enable_secret: document.getElementById('provEnableSecret').value,
        ssh_only: document.getElementById('provSshOnly').checked,
        banner: document.getElementById('provBanner').value.trim(),
        ntp_servers: document.getElementById('provNtp').value.split(',').map(s => s.trim()).filter(Boolean),
        syslog_server: document.getElementById('provSyslog').value.trim(),
        snmpv3: document.getElementById('provSnmpUser').value.trim() ? {
            user: document.getElementById('provSnmpUser').value.trim(),
            auth_pass: document.getElementById('provSnmpAuth').value,
            priv_pass: document.getElementById('provSnmpPriv').value,
        } : {},
        vlans: provParseVlans(document.getElementById('provVlans').value),
        vtp_mode: 'transparent',
        stp_mode: 'rapid-pvst',
        bpduguard: document.getElementById('provBpduguard').checked,
        port_security: document.getElementById('provPortSecurity').checked,
        dhcp_snooping: document.getElementById('provDhcpSnooping').checked,
        dhcp_snooping_vlans: document.getElementById('provTrunkVlans').value.trim(),
        cdp_enabled: document.getElementById('provCdp').checked,
        lldp_enabled: document.getElementById('provLldp').checked,
        access_ports: provParseRanges(document.getElementById('provAccessPorts').value),
        access_vlan: parseInt(document.getElementById('provAccessVlan').value, 10) || null,
        trunk_ports: provParseRanges(document.getElementById('provTrunkPorts').value),
        trunk_allowed_vlans: document.getElementById('provTrunkVlans').value.trim(),
        uplink_pc_id: parseInt(document.getElementById('provUplinkPc').value, 10) || null,
        login_block: document.getElementById('provLoginBlock').checked,
        storm_control: document.getElementById('provStormControl').checked,
        errdisable_recovery: document.getElementById('provErrdisable').checked,
        no_vstack: document.getElementById('provNoVstack').checked,
        svis: provParseSvis(document.getElementById('provSvis').value),
        enable_routing: true,
        default_route_gw: document.getElementById('provDefRouteGw').value.trim(),
        aaa_protocol: aaaProtocol,
    };
    if (aaaProtocol !== 'none') {
        const ip = document.getElementById('provAaaServerIp').value.trim();
        const key = document.getElementById('provAaaKey').value;
        if (ip) payload.aaa_servers = [{ ip, key }];
    }
    return payload;
}

// Raccolta parametri del wizard ZTP FortiGate (vedi fortigate_provisioner.py).
function fgtCollectPayload() {
    const v = id => (document.getElementById(id)?.value || '').trim();
    const aaaProtocol = document.getElementById('fgtAaaProtocol')?.value || 'none';
    const payload = {
        hostname: v('fgtHostname') || 'FortiGate',
        timezone: v('fgtTimezone') || 'Europe/Rome',
        admin_user: v('fgtAdminUser'),
        admin_password: document.getElementById('fgtAdminPass').value,
        lockout: document.getElementById('fgtLockout').checked,
        strong_crypto: document.getElementById('fgtStrongCrypto').checked,
        mgmt_interface: v('fgtMgmtIf'),
        mgmt_ip: v('fgtMgmtIp'),
        mgmt_mask: v('fgtMgmtMask'),
        wan_interface: v('fgtWanIf'),
        wan_mode: document.getElementById('fgtWanMode').value,
        wan_ip: v('fgtWanIp'),
        wan_mask: v('fgtWanMask'),
        wan_gw: v('fgtWanGw'),
        lan_interface: v('fgtLanIf'),
        lan_ip: v('fgtLanIp'),
        lan_mask: v('fgtLanMask'),
        dhcp_server: document.getElementById('fgtDhcpServer').checked,
        dhcp_start: v('fgtDhcpStart'),
        dhcp_end: v('fgtDhcpEnd'),
        dns_primary: v('fgtDns1'),
        dns_secondary: v('fgtDns2'),
        ntp_servers: v('fgtNtp').split(',').map(s => s.trim()).filter(Boolean),
        syslog_server: v('fgtSyslog'),
        snmpv3: v('fgtSnmpUser') ? {
            user: v('fgtSnmpUser'),
            auth_pass: document.getElementById('fgtSnmpAuth').value,
            priv_pass: document.getElementById('fgtSnmpPriv').value,
        } : {},
        lan_to_wan_policy: document.getElementById('fgtLanToWan').checked,
        disable_wan_admin: document.getElementById('fgtNoWanAdmin').checked,
        banner: v('fgtBanner'),
        aaa_protocol: aaaProtocol,
    };
    if (aaaProtocol !== 'none') {
        payload.aaa_server_ip = v('fgtAaaServerIp');
        payload.aaa_key = document.getElementById('fgtAaaKey').value;
    }
    return payload;
}
function provVendorIsFgt() { return document.getElementById('provVendor')?.value === 'fortigate'; }
function provPayloadAndBase() {
    return provVendorIsFgt()
        ? { payload: fgtCollectPayload(), base: '/api/provisioner/fgt' }
        : { payload: provCollectPayload(), base: '/api/provisioner' };
}

// I chip "Tipo apparato" sono solo una skin del <select id="provVendor">, che
// resta la fonte di verità: qui li riallineiamo al value corrente del select.
function provSyncVendorChips() {
    const sel = document.getElementById('provVendor');
    if (!sel) return;
    document.querySelectorAll('#provVendorChips .chip-choice').forEach(chip => {
        chip.setAttribute('aria-pressed', String(chip.dataset.vendor === sel.value));
    });
}

function provInitVendorChips() {
    const sel = document.getElementById('provVendor');
    if (!sel) return;
    document.querySelectorAll('#provVendorChips .chip-choice').forEach(chip => {
        chip.addEventListener('click', () => {
            if (sel.value === chip.dataset.vendor) return;
            sel.value = chip.dataset.vendor;
            // Evento 'change' reale: rieffettua tutto il wiring vendor esistente
            // (sezioni Cisco/FGT, campi console, token inline) senza duplicarlo.
            sel.dispatchEvent(new Event('change'));
        });
    });
    provSyncVendorChips();
}

function provInitToggles() {
    const roleSel = document.getElementById('provRole');
    if (!roleSel) return;
    document.getElementById('provVendor').addEventListener('change', () => {
        const fgt = provVendorIsFgt();
        document.getElementById('provCiscoSection').style.display = fgt ? 'none' : '';
        document.getElementById('provFgtSection').style.display = fgt ? '' : 'none';
        // Campi login console: servono solo al push seriale FortiGate.
        document.getElementById('fgtConsoleUserGroup').style.display = fgt ? 'block' : 'none';
        document.getElementById('fgtConsolePassGroup').style.display = fgt ? 'block' : 'none';
        const ciscoHint = document.getElementById('provCiscoTokenHint');
        if (ciscoHint) ciscoHint.style.display = fgt ? 'none' : 'flex';
        provSyncVendorChips();
    });
    provInitVendorChips();

    // Toggle AAA server/key fields quando il protocollo AAA non è "none",
    // sia per il wizard switch (Cisco) sia per quello FortiGate.
    function wireAaaToggle(selectId, serverGroupId, keyGroupId, hintId) {
        const sel = document.getElementById(selectId);
        if (!sel) return;
        const sync = () => {
            const show = sel.value !== 'none';
            const serverGroup = document.getElementById(serverGroupId);
            const keyGroup = document.getElementById(keyGroupId);
            const hint = document.getElementById(hintId);
            if (serverGroup) serverGroup.style.display = show ? '' : 'none';
            if (keyGroup) keyGroup.style.display = show ? '' : 'none';
            if (hint) hint.style.display = show ? '' : 'none';
        };
        sel.addEventListener('change', sync);
        sync();
    }
    wireAaaToggle('provAaaProtocol', 'provAaaServerGroup', 'provAaaKeyGroup', 'provAaaHint');
    wireAaaToggle('fgtAaaProtocol', 'fgtAaaServerGroup', 'fgtAaaKeyGroup', 'fgtAaaHint');

    const devVendorSel = document.getElementById('devVendor');
    if (devVendorSel) devVendorSel.addEventListener('change', updateDevSecretField);

    roleSel.addEventListener('change', () => {
        const isDist = roleSel.value === 'distribution';
        document.getElementById('provSvisGroup').style.display = isDist ? 'block' : 'none';
        document.getElementById('provDefRouteGroup').style.display = isDist ? 'block' : 'none';
    });
    document.getElementById('provDeliveryMode').addEventListener('change', (e) => {
        document.getElementById('provSshFields').style.display = e.target.value === 'ssh' ? 'grid' : 'none';
        document.getElementById('provSerialFields').style.display = e.target.value === 'serial' ? 'grid' : 'none';
        if (e.target.value === 'ssh') populateProvSiteSelect();
    });

    // A day-0 device is not in the inventory yet, so the server cannot resolve
    // its site from the target IP: inside a jump site the push would be dialled
    // directly instead of through the bastion. The operator names the site here.
    async function populateProvSiteSelect() {
        const sel = document.getElementById('provSshSite');
        if (!sel || sel.dataset.loaded) return;
        const res = await apiFetch('/api/sites');
        if (!res || !res.ok) return;
        const sites = (await res.json()).sites || [];
        sel.insertAdjacentHTML('beforeend', sites.map(st =>
            `<option value="${escapeHtml(st.id)}">${escapeHtml(st.name)}</option>`).join(''));
        sel.dataset.loaded = '1';
    }
    document.getElementById('btnProvGenerate').addEventListener('click', async () => {
        const { payload, base } = provPayloadAndBase();
        const res = await apiFetch(`${base}/generate`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res && res.ok) {
            const data = await res.json();
            document.getElementById('provOutput').value = data.config;
        }
    });
    document.getElementById('btnProvDownload').addEventListener('click', async () => {
        const { payload, base } = provPayloadAndBase();
        const res = await apiFetch(`${base}/download`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res && res.ok) {
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${(payload.hostname || 'device')}-day0.txt`;
            a.click();
            URL.revokeObjectURL(url);
        }
    });
    document.getElementById('btnProvPushSsh').addEventListener('click', async () => {
        const { payload, base } = provPayloadAndBase();
        Object.assign(payload, {
            ssh_host: document.getElementById('provSshHost').value.trim(),
            ssh_port: parseInt(document.getElementById('provSshPort').value, 10) || 22,
            ssh_username: document.getElementById('provSshUser').value.trim(),
            ssh_password: document.getElementById('provSshPass').value,
            ssh_site: document.getElementById('provSshSite').value,
        });
        if (!provVendorIsFgt()) {
            payload.ssh_secret = document.getElementById('provSshSecret').value;
            payload.save_after = true;
        }
        document.getElementById('provOutput').value = 'Invio in corso via SSH...';
        const res = await apiFetch(`${base}/push-ssh`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res) {
            const data = await res.json();
            // 'method' (api|ssh) è valorizzato solo dal push FortiGate; 'api_error'
            // spiega l'eventuale fallback da REST a SSH.
            const method = data.method ? ` via ${data.method}` : '';
            const apiErr = data.api_error ? `\n(REST API fallita: ${data.api_error})` : '';
            document.getElementById('provOutput').value =
                `[${data.status}${method}]${apiErr}\n${data.message || data.output || ''}`;
        }
    });
    document.getElementById('btnProvPushSerial').addEventListener('click', async () => {
        const { payload, base } = provPayloadAndBase();
        Object.assign(payload, {
            com_port: document.getElementById('provComPort').value.trim(),
            baudrate: parseInt(document.getElementById('provBaudrate').value, 10) || 9600,
        });
        if (provVendorIsFgt()) {
            payload.console_user = document.getElementById('fgtConsoleUser').value.trim() || 'admin';
            payload.console_password = document.getElementById('fgtConsolePass').value;
        }
        document.getElementById('provOutput').value = 'Invio in corso via console/seriale...';
        const res = await apiFetch(`${base}/push-serial`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res) {
            const data = await res.json();
            document.getElementById('provOutput').value =
                `[${data.status}]\n${data.message || data.output || ''}`;
        }
    });
    document.getElementById('btnProvRefreshPorts').addEventListener('click', async () => {
        const res = await apiFetch('/api/provisioner/serial-ports');
        if (res && res.ok) {
            const data = await res.json();
            if (data.ports && data.ports.length) {
                document.getElementById('provComPort').value = data.ports[0].device;
                alert(data.ports.map(p => `${p.device} — ${p.description}`).join('\n'));
            } else {
                alert(currentLang === 'en' ? 'No serial port detected on the server.' : 'Nessuna porta seriale rilevata sul server.');
            }
        }
    });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', provInitToggles);
else provInitToggles();

// "Enable Secret" non vuol dire la stessa cosa su ogni piattaforma: su Linux è
// la password sudo, e su FortiOS, JunOS e PAN-OS non esiste proprio un livello
// privilegiato da sbloccare (netmiko le marca NoEnable). Un campo che chiede
// una cosa che l'apparato non ha è un invito a inventarsi un valore, quindi lì
// sparisce invece di restare vuoto e ambiguo.
const DEV_SECRET_LABELS = { linux: 'lblSecretSudo' };
const DEV_SECRET_NOT_APPLICABLE = ['fortinet', 'juniper', 'paloalto'];

function updateDevSecretField() {
    const group = document.getElementById('devSecretGroup');
    const label = document.getElementById('devSecretLabel');
    const input = document.getElementById('devSecret');
    const hint = document.getElementById('devSecretHint');
    const vendorSel = document.getElementById('devVendor');
    if (!group || !label || !input || !vendorSel) return;

    const vendor = vendorSel.value;
    // Vendor sconosciuto (custom da vendors.json): il campo resta, è il verso
    // sicuro dell'errore.
    const applicable = !DEV_SECRET_NOT_APPLICABLE.includes(vendor);
    group.style.display = applicable ? '' : 'none';
    if (!applicable) input.value = '';

    // Si riscrive l'attributo, non solo il testo: al cambio di lingua è
    // applyI18n a rileggerlo, e con la chiave vecchia rimetterebbe l'etichetta
    // sbagliata.
    const key = DEV_SECRET_LABELS[vendor] || 'lblSecret';
    label.setAttribute('data-i18n', key);
    if (i18n[currentLang] && i18n[currentLang][key]) label.textContent = i18n[currentLang][key];
    if (hint) hint.style.display = vendor === 'linux' ? 'block' : 'none';
}

async function populateSiteOptions(preserve) {
    const siteSelect = document.getElementById('devSiteSelect');
    if (!siteSelect) return;
    const current = preserve || siteSelect.value || 'central';
    let sites = [];
    try {
        const res = await apiFetch('/api/sites');
        if (res && res.ok) {
            sites = (await res.json()).sites || [];
        }
    } catch (e) {}
    if (!sites.length) {
        sites = [{ id: 'central', name: 'Central', mode: 'central' }];
    }
    siteSelect.innerHTML = sites.map(s => {
        const modeLabel = s.mode === 'jump' ? ' [Jump/Bastion]' : (s.mode === 'agent' ? ' [Agent]' : '');
        return `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name || s.id)}${escapeHtml(modeLabel)} (${escapeHtml(s.id)})</option>`;
    }).join('');
    siteSelect.value = Array.from(siteSelect.options).some(o => o.value === current) ? current : 'central';
}
window.populateSiteOptions = populateSiteOptions;

// Popola le select del form di Provisioning Apparato (devVendor,
// scanVerifyVendorSelect, devGroupSelect, devSiteSelect). Estratto da appInit() perché ora
// serve anche quando si apre la tab dedicata tab-provisioning senza passare da
// un reload completo.
function populateProvisioningFormSelects() {
    const devVendorSel = document.getElementById('devVendor');
    if (devVendorSel) devVendorSel.innerHTML = buildVendorOptions(devVendorSel.value || 'cisco');
    const scanVendorSel = document.getElementById('scanVerifyVendorSelect');
    if (scanVendorSel) scanVendorSel.innerHTML = buildScanVendorOptions(scanVendorSel.value);
    updateDevSecretField();
    renderVendorTable();

    const groupSelect = document.getElementById('devGroupSelect');
    if (groupSelect) {
        groupSelect.innerHTML = Object.keys(globalGroups).map(g =>
            `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`
        ).join('');
    }
    populateSiteOptions();
    if (typeof window.populateGenCfgTenants === 'function') {
        window.populateGenCfgTenants();
    }
}

async function loadProvisioningTab() {
    try {
        const res = await apiFetch('/api/groups');
        if (res && res.ok) {
            const data = await res.json();
            globalGroups = (data && data.groups) ? data.groups : (data || {});
        }
    } catch (e) {}
    populateProvisioningFormSelects();
    await populateSiteOptions();
    await refreshIdentityOptions();
    renderIdentitiesPanel();
}

// --- BULK ASSIGN IDENTITY TO DEVICES ---
// Apre un modale che elenca i dispositivi del tenant dell'identità (o del tenant
// corrente se l'identità è globale) e permette di assegnare l'identità.
function assignIdentityToDevices(identityId) {
    const ident = (window._tenantIdentities || []).find(x => x.id === identityId);
    if (!ident) return;
    const currentTenant = document.getElementById('devGroupSelect')?.value || 'Generale';
    const L = i18n[currentLang];

    // Se l'identità è legata a tenant specifici, vengono elencati SOLO i device di quei tenant.
    // Se è globale ('all'), vengono elencati i device del tenant corrente (o tutti se devGroupSelect è 'all').
    let allowedTenants = null;
    if (ident.tenant && ident.tenant !== 'all') {
        allowedTenants = Array.isArray(ident.tenant)
            ? ident.tenant
            : String(ident.tenant).split(',').map(s => s.trim()).filter(Boolean);
        if (allowedTenants.includes('all')) allowedTenants = null;
    }

    // globalDevices is a 'let' in core.js: it lives in the global lexical
    // scope, not on window. Reading it as window.globalDevices always returned
    // undefined and left the device list empty for every tenant.
    const devices = (globalDevices || []).filter(d => {
        if (allowedTenants && allowedTenants.length) return allowedTenants.includes(d.Group);
        return currentTenant === 'all' || d.Group === currentTenant;
    });

    const scopeNotice = (allowedTenants && allowedTenants.length)
        ? (L.assignIdentityScopeSpecific || 'Identità riservata ai tenant <strong>{tenant}</strong>. Vengono elencati solo i dispositivi di queste sedi.').replace('{tenant}', escapeHtml(allowedTenants.join(', ')))
        : (L.assignIdentityScopeGlobal || 'Identità globale: selezionabili i dispositivi del tenant corrente.');

    const ov = document.createElement('div');
    ov.id = 'assignIdentityModal';
    ov.style.cssText = 'position:fixed; inset:0; z-index:10060; background:color-mix(in srgb, var(--bg) 82%, transparent); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(4px);';
    const rows = devices.length
        ? devices.map(d => `<tr>
            <td style="padding:4px 8px;"><input type="checkbox" class="assignDevCb" value="${escapeHtml(d.IP)}" style="width:auto;"></td>
            <td style="padding:4px 8px; font-family:var(--font-code); font-size:12px;">${escapeHtml(d.IP)}</td>
            <td style="padding:4px 8px;">${escapeHtml(d.Hostname || '—')}</td>
            <td style="padding:4px 8px;">${escapeHtml(d.Vendor || '')}</td>
          </tr>`).join('')
        : `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">${L.noDevicesInTenant || 'Nessun dispositivo in questo tenant.'}</td></tr>`;
    ov.innerHTML = `
      <div style="background:var(--surface); border:1px solid var(--border); border-radius:0; padding:22px; width:min(620px,94vw); max-height:86vh; overflow:auto; box-shadow:var(--shadow-float);">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <h3 style="font-size:17px;"><i class="fa-solid fa-users-rectangle" style="color:var(--primary);"></i> ${escapeHtml(L.assignIdentityTitle || 'Assegna identità')}</h3>
          <i class="fa-solid fa-xmark" data-action="close-assign-identity-modal" style="cursor:pointer; color:var(--text-muted); font-size:17px;"></i>
        </div>
        <p style="font-size:13px; color:var(--text-muted); margin-bottom:4px;">
          ${escapeHtml((L.assignIdentityDesc || 'Seleziona i dispositivi a cui assegnare l\'identità:')).replace('{name}', escapeHtml(ident.name))}
          <strong>${escapeHtml(ident.name)}</strong> (${escapeHtml(ident.username)})
        </p>
        <p style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">${scopeNotice}</p>
        <div style="max-height:320px; overflow:auto; border:1px solid var(--border); margin-bottom:16px;">
          <table style="width:100%; border-collapse:collapse; font-size:13px;">
            <thead><tr style="background:var(--surface-2);">
              <th style="padding:6px 8px; width:32px;"><input type="checkbox" id="assignSelectAll" style="width:auto;"></th>
              <th style="padding:6px 8px; text-align:left;">IP</th>
              <th style="padding:6px 8px; text-align:left;">Hostname</th>
              <th style="padding:6px 8px; text-align:left;">Vendor</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
        <div style="display:flex; justify-content:flex-end; gap:10px;">
          <button class="btn btn-secondary" data-action="close-assign-identity-modal">${L.btnCancelIdentity || '<i class="fa-solid fa-xmark"></i> Annulla'}</button>
          <button class="btn btn-primary" id="btnConfirmAssignIdentity"><i class="fa-solid fa-check"></i> ${escapeHtml(L.btnConfirmAssign || 'Assegna')}</button>
        </div>
      </div>`;
    document.body.appendChild(ov);
    ov.addEventListener('click', e => {
      if (e.target === ov || e.target.closest('[data-action="close-assign-identity-modal"]')) closeAssignIdentityModal();
    });
    // Select-all checkbox
    const selAll = document.getElementById('assignSelectAll');
    if (selAll) selAll.addEventListener('change', () => {
        document.querySelectorAll('.assignDevCb').forEach(cb => cb.checked = selAll.checked);
    });
    document.getElementById('btnConfirmAssignIdentity').addEventListener('click', async () => {
        const ips = Array.from(document.querySelectorAll('.assignDevCb:checked')).map(cb => cb.value);
        if (!ips.length) { alert(L.alertSelectDevices || 'Seleziona almeno un dispositivo.'); return; }
        const res = await apiFetch(`/api/identities/${identityId}/assign`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ identity_id: identityId, ips })
        });
        if (res && res.ok) {
            const data = await res.json();
            closeAssignIdentityModal();
            await refreshIdentityOptions();
            renderIdentitiesPanel();
            alert((L.assignSuccess || 'Identità assegnata a {n} dispositivi.').replace('{n}', data.assigned.length));
        } else if (res) {
            const err = await res.json();
            alert(err.detail || 'Errore');
        }
    });
}

function closeAssignIdentityModal() {
    const m = document.getElementById('assignIdentityModal');
    if (m) m.remove();
}
