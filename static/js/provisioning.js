// static/js/provisioning.js
// Estratto da templates/dashboard.html: tab-provisioning (form di provisioning
// apparato + pannello Identità, parte tab-owned) e tab-provisioner (wizard ZTP
// switch/FortiGate). La gestione del token API FortiGate e la vista live degli
// oggetti firewall sono state rimosse da qui: erano un duplicato della tab
// "FortiGate LIVE (preview)" (static/js/fortigate-preview.js), che ora è
// l'unica proprietaria di quella UI.
//
// refreshIdentityOptions/renderIdentitiesPanel e buildVendorOptions/
// renderVendorTable sono stati promossi a static/js/core.js perché usati anche
// dalla tab Devices (editDevice) e dalla tab Groups (btnCreateGroup,
// loadVendors), ancora inline in dashboard.html.

document.getElementById('devGroupSelect').addEventListener('change', () => { refreshIdentityOptions(); renderIdentitiesPanel(); });

// --- IDENTITIES CRUD (pannello destro della tab Provisioning) ---

function editIdentity(id) {
    const i = (window._tenantIdentities || []).find(x => x.id === id);
    if (!i) return;
    document.getElementById('identEditId').value = id;
    document.getElementById('identName').value = i.name;
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

document.getElementById('btnNewIdentity').addEventListener('click', () => {
    document.getElementById('identEditId').value = '';
    ['identName','identUser','identPass','identSecret'].forEach(i => document.getElementById(i).value = '');
    document.getElementById('identityForm').style.display = 'block';
});
document.getElementById('btnCancelIdentity').addEventListener('click', () =>
    document.getElementById('identityForm').style.display = 'none');
document.getElementById('btnSaveIdentity').addEventListener('click', async () => {
    const id = document.getElementById('identEditId').value;
    const payload = {
        name: document.getElementById('identName').value.trim(),
        tenant: document.getElementById('devGroupSelect').value,
        username: document.getElementById('identUser').value.trim(),
        password: document.getElementById('identPass').value,
        enable_secret: document.getElementById('identSecret').value,
    };
    if (!payload.name || !payload.username || !payload.password) {
        alert(i18n[currentLang].alertIdentityFields); return;
    }
    const res = await apiFetch(id ? '/api/identities/' + id : '/api/identities', {
        method: id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (res && res.ok) {
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

    roleSel.addEventListener('change', () => {
        const isDist = roleSel.value === 'distribution';
        document.getElementById('provSvisGroup').style.display = isDist ? 'block' : 'none';
        document.getElementById('provDefRouteGroup').style.display = isDist ? 'block' : 'none';
    });
    document.getElementById('provDeliveryMode').addEventListener('change', (e) => {
        document.getElementById('provSshFields').style.display = e.target.value === 'ssh' ? 'grid' : 'none';
        document.getElementById('provSerialFields').style.display = e.target.value === 'serial' ? 'grid' : 'none';
    });
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
                alert(currentLang==='en' ? 'No serial port detected on the server.' : 'Nessuna porta seriale rilevata sul server.');
            }
        }
    });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', provInitToggles);
else provInitToggles();

// Popola le select del form di Provisioning Apparato (devVendor, scanVendorSelect,
// devGroupSelect). Estratto da appInit() perché ora serve anche quando si apre
// la tab dedicata tab-provisioning senza passare da un reload completo.
function populateProvisioningFormSelects() {
    const devVendorSel = document.getElementById('devVendor');
    if (devVendorSel) devVendorSel.innerHTML = buildVendorOptions(devVendorSel.value || 'cisco');
    const scanVendorSel = document.getElementById('scanVendorSelect');
    if (scanVendorSel) scanVendorSel.innerHTML = buildVendorOptions(scanVendorSel.value || 'cisco');
    renderVendorTable();

    const groupSelect = document.getElementById('devGroupSelect');
    if (groupSelect) {
        groupSelect.innerHTML = Object.keys(globalGroups).map(g =>
            `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`
        ).join('');
    }
}

function loadProvisioningTab() {
    populateProvisioningFormSelects();
    refreshIdentityOptions();
    renderIdentitiesPanel();
}
