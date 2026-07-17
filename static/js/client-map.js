// static/js/client-map.js
// Estratto da templates/dashboard.html: tab-mac (MAC Address Tracker) e
// tab-clientmap (Client Map MAC <-> IP dalle ARP dei gateway L3). Le due
// sezioni erano contigue nell'inline script originale e condividono lo
// stesso pattern (multi-selezione device via checkbox, filtro tenant,
// tabelle raggruppate). showPortConfig/closePortConfigModal (usati dai
// bottoni di riga) vivono in core.js: chiamata cross-modulo a runtime,
// nessun cambio di comportamento.

    // --- MAC ADDRESS TRACKER (storico MAC -> switch/porta/vlan) ---

    function loadMacTracker() {
        const sel = document.getElementById('macScanGroup');
        if (sel) {
            const cur = sel.value;
            const groups = Object.keys(globalGroups || {});
            sel.innerHTML = `<option value="all">${currentLang==='en'?'Filter by Tenant: All':'Filtra per Tenant: Tutti'}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            sel.value = groups.includes(cur) ? cur : 'all';
        }
        populateMacScanDevices();
        loadMacOverrides();
        refreshMacStats(true);
        macSearch();
    }

    // Comandi ad-hoc per apparati non ordinari (override CLI per singolo switch).
    async function loadMacOverrides() {
        fillMacDeviceSelect(document.getElementById('macOvDevice'), false);
        try {
            const r = await apiFetch('/api/mac/overrides');
            if (r && r.ok) renderMacOverrides((await r.json()).overrides || []);
        } catch (e) {}
    }

    function renderMacOverrides(list) {
        const box = document.getElementById('macOverridesList');
        if (!box) return;
        if (!list.length) {
            box.innerHTML = `<div style="font-size:12px; color:var(--text-muted);">${currentLang==='en'?'No ad-hoc commands configured.':'Nessun comando ad-hoc configurato.'}</div>`;
            return;
        }
        box.innerHTML = list.map(o => `<div style="display:flex; align-items:center; gap:10px; padding:6px 0; border-bottom:1px solid var(--border); font-size:12px;">
            <span style="font-family:var(--font-code); color:var(--primary); min-width:120px;">${escapeHtml(o.switch_ip)}</span>
            <span style="font-family:var(--font-code); flex:1;">${escapeHtml(o.command)}</span>
            <span class="badge" style="font-size:10px;">${escapeHtml(o.fmt)}</span>
            <button onclick="removeMacOverride('${escapeHtml(o.switch_ip)}')" title="${currentLang==='en'?'Remove':'Rimuovi'}" style="border:none; background:none; color:var(--danger); cursor:pointer;"><i class="fa-solid fa-trash-can"></i></button>
        </div>`).join('');
    }

    async function saveMacOverride() {
        const val = id => { const el = document.getElementById(id); return el ? el.value : ''; };
        const ip = val('macOvDevice');
        const command = (val('macOvCommand') || '').trim();
        const fmt = val('macOvFmt') || 'generic';
        if (!ip || !command) { alert(currentLang==='en'?'Select a device and enter a command.':'Seleziona un apparato e inserisci un comando.'); return; }
        const res = await apiFetch('/api/mac/overrides', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ ip, command, fmt })
        });
        if (res && res.ok) {
            const c = document.getElementById('macOvCommand'); if (c) c.value = '';
            loadMacOverrides();
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            alert((currentLang==='en'?'Error: ':'Errore: ') + (e.detail || ''));
        }
    }

    async function removeMacOverride(ip) {
        const res = await apiFetch('/api/mac/overrides/delete', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ ip })
        });
        if (res && res.ok) loadMacOverrides();
    }

    // Dispositivi filtrati per il tenant selezionato (globalDevices è già scoped
    // per utente lato server; qui si applica solo il filtro del tenant scelto).
    function macFilteredDevices() {
        const g = document.getElementById('macScanGroup');
        const group = g ? g.value : 'all';
        let devs = globalDevices || [];
        if (group && group !== 'all') devs = devs.filter(d => d.Group === group);
        return devs;
    }

    function fillMacDeviceSelect(sel, includeAll) {
        if (!sel) return;
        const cur = sel.value;
        const opts = macFilteredDevices().map(d => {
            const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
            return `<option value="${escapeHtml(d.IP)}">${escapeHtml(d.IP)}${name}</option>`;
        }).join('');
        const allLabel = (i18n[currentLang] && i18n[currentLang].optMacAllDevices) || 'All devices';
        sel.innerHTML = (includeAll ? `<option value="all">${allLabel}</option>` : '') + opts;
        if ([...sel.options].some(o => o.value === cur)) sel.value = cur;
    }

    // Popola i selettori dispositivo (scan e ad-hoc) in base al tenant scelto:
    // così scegliendo un tenant si vedono SOLO i suoi switch, non tutti.
    // Lo scan usa una multi-selezione a checkbox (più device in un'unica scansione).
    function populateMacScanDevices() {
        const box = document.getElementById('macDeviceList');
        if (box) {
            const devs = macFilteredDevices();
            const head = `<label style="display:flex; align-items:center; gap:8px; padding:5px 6px; font-size:12px; cursor:pointer; border-bottom:1px solid var(--border); margin-bottom:4px;">
                <input type="checkbox" id="macDevAll" onchange="toggleAllMacDevices(this.checked)" style="accent-color:var(--primary);">
                <strong>${currentLang==='en'?'All devices':'Tutti i dispositivi'}</strong></label>`;
            const items = devs.map(d => {
                const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
                return `<label style="display:flex; align-items:center; gap:8px; padding:4px 6px; font-size:12px; cursor:pointer;">
                    <input type="checkbox" class="mac-dev-cb" value="${escapeHtml(d.IP)}" onchange="updateMacDeviceSummary()" style="accent-color:var(--primary);">
                    <span style="font-family:var(--font-code);">${escapeHtml(d.IP)}</span>
                    <span style="color:var(--text-muted);">${name}</span></label>`;
            }).join('');
            box.innerHTML = head + (items ||
                `<div style="font-size:12px; color:var(--text-muted); padding:6px;">${currentLang==='en'?'No devices':'Nessun dispositivo'}</div>`);
        }
        updateMacDeviceSummary();
        fillMacDeviceSelect(document.getElementById('macOvDevice'), false);
    }

    function selectedMacDevices() {
        return [...document.querySelectorAll('#macDeviceList .mac-dev-cb:checked')].map(cb => cb.value);
    }

    function toggleAllMacDevices(on) {
        document.querySelectorAll('#macDeviceList .mac-dev-cb').forEach(cb => cb.checked = on);
        updateMacDeviceSummary();
    }

    function updateMacDeviceSummary() {
        const total = document.querySelectorAll('#macDeviceList .mac-dev-cb').length;
        const sel = selectedMacDevices().length;
        const all = document.getElementById('macDevAll');
        if (all) all.checked = (total > 0 && sel === total);
        const sum = document.getElementById('macDeviceSummary');
        if (sum) sum.textContent = (sel === 0)
            ? (currentLang==='en' ? 'All devices' : 'Tutti i dispositivi')
            : `${sel} ${currentLang==='en' ? 'selected' : 'selezionati'}`;
    }

    async function refreshMacStats(fillRetention) {
        try {
            const g = document.getElementById('macScanGroup');
            const grp = g ? g.value : 'all';
            const qs = (grp && grp !== 'all') ? ('?tenant=' + encodeURIComponent(grp)) : '';
            const r = await apiFetch('/api/mac/stats' + qs);
            if (!r || !r.ok) return;
            const s = await r.json();
            const el = document.getElementById('macStats');
            if (el) el.textContent = currentLang==='en'
                ? `${s.sightings} sightings · ${s.unique_macs} MAC · ${s.switches} switches · retention ${s.retention_days}d`
                : `${s.sightings} avvistamenti · ${s.unique_macs} MAC · ${s.switches} switch · retention ${s.retention_days}g`;
            // KPI tiles nella hero card: stessa risposta, nessuna chiamata aggiuntiva.
            const kSight = document.getElementById('kpiMacSightings'); if (kSight) kSight.textContent = s.sightings;
            const kUniq = document.getElementById('kpiMacUniqueMacs'); if (kUniq) kUniq.textContent = s.unique_macs;
            const kSw = document.getElementById('kpiMacSwitches'); if (kSw) kSw.textContent = s.switches;
            const kRet = document.getElementById('kpiMacRetention'); if (kRet) kRet.textContent = s.retention_days;
            const rin = document.getElementById('macRetentionDays');
            if (rin && (fillRetention || !rin.value)) rin.value = s.retention_days;
        } catch (e) {}
    }

    async function runMacScan() {
        const btn = document.getElementById('btnMacScan');
        const val = id => { const el = document.getElementById(id); return el ? el.value : ''; };
        const group = val('macScanGroup') || 'all';
        const transport = val('macScanTransport') || '';
        const ips = selectedMacDevices();
        const payload = { group, transport };
        if (ips.length) payload.ips = ips;   // device specifici (multi-selezione)
        const orig = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${currentLang==='en'?'Scanning...':'Scansione...'}`;
        try {
            const res = await apiFetch('/api/mac/scan', {
                method: 'POST', headers: {'Content-Type':'application/json'},
                body: JSON.stringify(payload)
            });
            if (res && res.ok) {
                const d = await res.json();
                const okc = d.results.filter(r => !r.error).length;
                const errc = d.results.filter(r => r.error).length;
                alert(currentLang==='en'
                    ? `MAC scan done: ${d.scanned} devices (${okc} ok, ${errc} errors), pruned ${d.pruned}.`
                    : `MAC scan completata: ${d.scanned} apparati (${okc} ok, ${errc} errori), rimossi ${d.pruned}.`);
                macSearch();
                refreshMacStats(false);
            } else if (res) {
                const e = await res.json().catch(() => ({}));
                alert((currentLang==='en'?'Error: ':'Errore: ') + (e.detail || ''));
            }
        } finally {
            btn.disabled = false;
            btn.innerHTML = orig;
        }
    }

    async function macSearch() {
        const params = new URLSearchParams();
        const g = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
        if (g('macSearchMac'))    params.set('mac', g('macSearchMac'));
        if (g('macSearchVlan'))   params.set('vlan', g('macSearchVlan'));
        if (g('macSearchIface'))  params.set('interface', g('macSearchIface'));
        if (g('macSearchSwitch')) params.set('switch', g('macSearchSwitch'));
        const grp = g('macScanGroup');
        if (grp && grp !== 'all') params.set('tenant', grp);
        const res = await apiFetch('/api/mac/search?' + params.toString());
        if (!res || !res.ok) return;
        const d = await res.json();
        renderMacResults(d.results || []);
    }

    function macSearchReset() {
        ['macSearchMac','macSearchVlan','macSearchIface','macSearchSwitch'].forEach(id => {
            const el = document.getElementById(id); if (el) el.value = '';
        });
        macSearch();
    }

    function fmtMacTime(iso) {
        if (!iso) return '—';
        try { return new Date(iso).toLocaleString(currentLang==='en' ? 'en-US' : 'it-IT'); }
        catch (e) { return iso; }
    }

    // --- CLIENT MAP: MAC <-> IP dalle ARP dei gateway L3 ---

    function loadClientMapTab() {
        const L = i18n[currentLang];
        const groups = Object.keys(globalGroups || {});
        const fillGroupSel = (id, allLabel) => {
            const sel = document.getElementById(id);
            if (!sel) return;
            const cur = sel.value;
            sel.innerHTML = `<option value="all">${allLabel}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            sel.value = groups.includes(cur) ? cur : 'all';
        };
        fillGroupSel('arpScanGroup', L.optFilterAll || 'Filtra per Tenant: Tutti');
        populateArpTenantFilter();
        populateArpScanDevices();
        populateArpGatewayFilter();
        arpClientSearch();
    }

    // Dispositivi filtrati per il tenant scelto nel selettore di scansione.
    function arpFilteredDevices(groupSelId) {
        const g = document.getElementById(groupSelId);
        const group = g ? g.value : 'all';
        let devs = globalDevices || [];
        if (group && group !== 'all') devs = devs.filter(d => (d.Group || 'Generale') === group);
        return devs;
    }

    // Multi-selezione dei gateway da interrogare (stesso pattern del MAC Tracker).
    function populateArpScanDevices() {
        const box = document.getElementById('arpDeviceList');
        if (box) {
            const L = i18n[currentLang];
            const devs = arpFilteredDevices('arpScanGroup');
            const head = `<label style="display:flex; align-items:center; gap:8px; padding:5px 6px; font-size:12px; cursor:pointer; border-bottom:1px solid var(--border); margin-bottom:4px;">
                <input type="checkbox" id="arpDevAll" onchange="toggleAllArpDevices(this.checked)" style="accent-color:var(--primary);">
                <strong>${L.optMacAllDevices || 'Tutti i dispositivi'}</strong></label>`;
            const items = devs.map(d => {
                const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
                return `<label style="display:flex; align-items:center; gap:8px; padding:4px 6px; font-size:12px; cursor:pointer;">
                    <input type="checkbox" class="arp-dev-cb" value="${escapeHtml(d.IP)}" onchange="updateArpDeviceSummary()" style="accent-color:var(--primary);">
                    <span style="font-family:var(--font-code);">${escapeHtml(d.IP)}</span>
                    <span style="color:var(--text-muted);">${name}</span></label>`;
            }).join('');
            box.innerHTML = head + (items ||
                `<div style="font-size:12px; color:var(--text-muted); padding:6px;">${L.msgAiNoDevices || 'Nessun dispositivo'}</div>`);
        }
        updateArpDeviceSummary();
    }

    function selectedArpDevices() {
        return [...document.querySelectorAll('#arpDeviceList .arp-dev-cb:checked')].map(cb => cb.value);
    }

    function toggleAllArpDevices(on) {
        document.querySelectorAll('#arpDeviceList .arp-dev-cb').forEach(cb => cb.checked = on);
        updateArpDeviceSummary();
    }

    function updateArpDeviceSummary() {
        const total = document.querySelectorAll('#arpDeviceList .arp-dev-cb').length;
        const sel = selectedArpDevices().length;
        const all = document.getElementById('arpDevAll');
        if (all) all.checked = (total > 0 && sel === total);
        const sum = document.getElementById('arpDeviceSummary');
        if (sum) sum.textContent = (sel === 0)
            ? (i18n[currentLang].optMacAllDevices || 'Tutti i dispositivi')
            : `${sel} ${i18n[currentLang].lblAiDevSelected || 'selezionati'}`;
    }

    // Multi-selezione tenant per la ricerca binding: nessuno selezionato di default,
    // ordine di selezione mantenuto per renderizzare le tabelle nello stesso ordine.
    let arpSelectedTenantOrder = [];

    function populateArpTenantFilter() {
        const box = document.getElementById('arpTenantList');
        if (!box) return;
        const groups = Object.keys(globalGroups || {});
        // Scarta selezioni di tenant non più esistenti.
        arpSelectedTenantOrder = arpSelectedTenantOrder.filter(t => groups.includes(t));
        const L = i18n[currentLang];
        box.innerHTML = groups.map(g => `<label style="display:flex; align-items:center; gap:8px; padding:4px 6px; font-size:12px; cursor:pointer;">
            <input type="checkbox" class="arp-tenant-cb" value="${escapeHtml(g)}" onchange="onArpTenantToggle(this)" ${arpSelectedTenantOrder.includes(g) ? 'checked' : ''} style="accent-color:var(--primary);">
            <span>${escapeHtml(g)}</span></label>`).join('') ||
            `<div style="font-size:12px; color:var(--text-muted); padding:6px;">${L.msgAiNoDevices || 'Nessun tenant'}</div>`;
        updateArpTenantSummary();
    }

    function selectedArpTenants() {
        return arpSelectedTenantOrder.slice();
    }

    function onArpTenantToggle(cb) {
        const name = cb.value;
        if (cb.checked) {
            if (!arpSelectedTenantOrder.includes(name)) arpSelectedTenantOrder.push(name);
        } else {
            arpSelectedTenantOrder = arpSelectedTenantOrder.filter(t => t !== name);
        }
        updateArpTenantSummary();
        populateArpGatewayFilter();
        arpClientSearch();
    }

    function updateArpTenantSummary() {
        const sum = document.getElementById('arpTenantSummary');
        if (!sum) return;
        sum.textContent = arpSelectedTenantOrder.length === 0
            ? (i18n[currentLang].arpPickTenantHint || 'Seleziona un tenant per visualizzare i binding')
            : arpSelectedTenantOrder.join(', ');
    }

    // Dispositivi filtrati per i tenant selezionati nel filtro di ricerca.
    function arpFilteredDevicesByTenants(tenants) {
        let devs = globalDevices || [];
        if (tenants && tenants.length) devs = devs.filter(d => tenants.includes(d.Group || 'Generale'));
        return devs;
    }

    // Il filtro gateway elenca i device dei tenant scelti nel filtro di vista.
    function populateArpGatewayFilter() {
        const sel = document.getElementById('arpFilterGateway');
        if (!sel) return;
        const cur = sel.value;
        const L = i18n[currentLang];
        const devs = arpFilteredDevicesByTenants(selectedArpTenants());
        sel.innerHTML = `<option value="">${L.optArpAllGateways || 'Tutti i gateway'}</option>` +
            devs.map(d => {
                const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
                return `<option value="${escapeHtml(d.IP)}">${escapeHtml(d.IP)}${name}</option>`;
            }).join('');
        sel.value = [...sel.options].some(o => o.value === cur) ? cur : '';
    }

    async function runArpScan() {
        const btn = document.getElementById('btnArpScan');
        btn.disabled = true;
        const oldHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ...';
        try {
            const groupSel = document.getElementById('arpScanGroup');
            const payload = { group: groupSel ? groupSel.value : 'all' };
            const ips = selectedArpDevices();
            if (ips.length) payload.ips = ips;
            const res = await apiFetch('/api/arp/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!res) return;
            const box = document.getElementById('arpScanSummary');
            const en = currentLang === 'en';
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                box.style.display = 'block';
                box.innerHTML = `<span style="color:var(--danger);">${escapeHtml(err.detail || (en ? 'ARP scan error' : 'Errore scansione ARP'))}</span>`;
                return;
            }
            const d = await res.json();
            const rows = Object.entries(d.devices || {}).map(([ip, r]) => {
                const color = r.status === 'success' ? 'var(--success, #7bd88f)'
                            : r.status === 'empty' ? 'var(--text-muted)' : 'var(--danger)';
                const detail = r.status === 'success'
                    ? (en ? `${r.entries} entries (${r.new} new, ${r.updated} updated)`
                          : `${r.entries} entry (nuove ${r.new}, aggiornate ${r.updated})`)
                    : escapeHtml(r.message || r.status);
                return `<div>• <b>${escapeHtml(ip)}</b> — <span style="color:${color};">${r.status}</span>: ${detail}</div>`;
            }).join('');
            box.style.display = 'block';
            box.innerHTML = `<b>${i18n[currentLang].titleArpScanSummary || 'Esito raccolta ARP'}</b>` +
                `<div style="margin-top:6px;">${rows || '—'}</div>`;
            arpClientSearch();
        } finally {
            btn.disabled = false;
            btn.innerHTML = oldHtml;
        }
    }

    // KPI e riepilogo calcolati lato client dai risultati già filtrati per tenant
    // selezionati (nessuna chiamata separata a /api/arp/stats, che non è scopabile
    // per tenant): "KPI contano solo i tenant selezionati".
    function updateArpKpisFromResults(tenants, byTenant) {
        let bindings = 0;
        const macs = new Set();
        const gws = new Set();
        tenants.forEach(t => (byTenant[t] || []).forEach(r => {
            bindings++;
            if (r.mac) macs.add(String(r.mac).toLowerCase());
            if (r.source_ip) gws.add(r.source_ip);
        }));
        const kB = document.getElementById('kpiArpBindings'); if (kB) kB.textContent = bindings;
        const kM = document.getElementById('kpiArpUniqueMacs'); if (kM) kM.textContent = macs.size;
        const kG = document.getElementById('kpiArpGateways'); if (kG) kG.textContent = gws.size;
        const el = document.getElementById('arpStats');
        if (el) el.innerText = (currentLang === 'en'
            ? `${bindings} bindings · ${macs.size} MACs · ${gws.size} gateways`
            : `${bindings} binding · ${macs.size} MAC · ${gws.size} gateway`);
    }

    function clearArpKpis() {
        ['kpiArpBindings', 'kpiArpUniqueMacs', 'kpiArpGateways'].forEach(id => {
            const el = document.getElementById(id); if (el) el.textContent = '—';
        });
        const stats = document.getElementById('arpStats'); if (stats) stats.innerText = '';
    }

    async function arpClientSearch() {
        const mac = document.getElementById('arpSearchMac').value.trim();
        const ip = document.getElementById('arpSearchIp').value.trim();
        const tenants = selectedArpTenants();
        const gw = document.getElementById('arpFilterGateway')?.value || '';
        const box = document.getElementById('arpResults');
        if (!tenants.length) {
            // Nessun tenant scelto: nessuna fetch, solo il placeholder e KPI vuoti.
            if (box) box.innerHTML = `<p style="color:var(--text-muted); font-size:13px;">${escapeHtml(i18n[currentLang].arpPickTenantHint || 'Seleziona un tenant per visualizzare i binding')}</p>`;
            clearArpKpis();
            return;
        }
        const byTenant = {};
        for (const t of tenants) {
            const params = new URLSearchParams();
            if (mac) params.set('mac', mac);
            if (ip) params.set('ip', ip);
            params.set('tenant', t);
            if (gw) params.set('source_ip', gw);
            const res = await apiFetch('/api/arp/client-map?' + params.toString());
            byTenant[t] = (res && res.ok) ? (await res.json()).results || [] : [];
        }
        renderArpResults(tenants, byTenant);
        updateArpKpisFromResults(tenants, byTenant);
    }

    function arpSearchReset() {
        ['arpSearchMac', 'arpSearchIp'].forEach(id => {
            const el = document.getElementById(id); if (el) el.value = '';
        });
        const g = document.getElementById('arpFilterGateway'); if (g) { populateArpGatewayFilter(); g.value = ''; }
        arpClientSearch();
    }

    // Una tabella separata per tenant, nell'ordine di selezione: mai unite in
    // un'unica tabella, ognuna con la propria intestazione.
    function renderArpResults(tenants, byTenant) {
        const en = currentLang === 'en';
        const box = document.getElementById('arpResults');
        const totalRows = tenants.reduce((n, t) => n + (byTenant[t] || []).length, 0);
        if (!totalRows) {
            box.innerHTML = `<p style="color:var(--text-muted); font-size:13px;">${en
                ? 'No MAC ↔ IP bindings. Run an ARP collection (and a MAC scan for port matching).'
                : 'Nessun binding MAC ↔ IP. Esegui una raccolta ARP (e una MAC scan per il match della porta).'}</p>`;
            return;
        }
        const th = (t) => `<th style="text-align:left; padding:8px 10px; font-size:11px; text-transform:uppercase; color:var(--text-muted); border-bottom:1px solid var(--border); white-space:nowrap;">${t}</th>`;
        const td = (t) => `<td style="padding:8px 10px; font-size:13px; border-bottom:1px solid var(--border); white-space:nowrap;">${t}</td>`;
        const header = en
            ? [th('MAC'), th('IP'), th('VLAN'), th('Gateway (routes VLAN)'), th('Type'), th('Access switch'), th('Port'), th('Last seen')]
            : [th('MAC'), th('IP'), th('VLAN'), th('Gateway (ruota la VLAN)'), th('Tipo'), th('Switch di accesso'), th('Porta'), th('Ultimo avvistamento')];
        const rowHtml = r => '<tr>' + [
            td(`<code>${escapeHtml(r.mac)}</code>`),
            td(`<code>${escapeHtml(r.ip)}</code>`),
            td(escapeHtml(r.vlan || '—')),
            td(`<span title="${escapeHtml(r.source_type || '')}">${escapeHtml(r.source_name || '')} <span style="color:var(--text-muted);">${escapeHtml(r.source_ip)}</span></span>`),
            td(escapeHtml(r.client_type || 'client')),
            td(r.switch_ip ? `${escapeHtml(r.switch_name || '')} <span style="color:var(--text-muted);">${escapeHtml(r.switch_ip)}</span>` : '—'),
            td(escapeHtml(r.switch_port || '—') + (r.switch_ip && r.switch_port
                ? `<button onclick="showPortConfig('${escapeHtml(r.switch_ip)}','${escapeHtml(r.switch_port)}','${escapeHtml(r.switch_name || '')}')" title="${escapeHtml(i18n[currentLang].btnPortConfig)}" style="margin-left:6px; border:none; background:none; color:var(--primary); cursor:pointer; font-size:12px;"><i class="fa-solid fa-file-lines"></i></button>`
                : '')),
            td(fmtMacTime(r.last_seen)),
        ].join('') + '</tr>';
        const table = body => `<table style="width:100%; border-collapse:collapse; background:var(--surface-2); border:1px solid var(--border); border-radius:12px; overflow:hidden;">` +
            `<thead><tr>${header.join('')}</tr></thead><tbody>${body}</tbody></table>`;
        box.innerHTML = tenants.map(t => {
            const rows = byTenant[t] || [];
            const body = rows.length
                ? table(rows.map(rowHtml).join(''))
                : `<p style="color:var(--text-muted); font-size:12px;">${en ? 'No bindings for this tenant.' : 'Nessun binding per questo tenant.'}</p>`;
            return `
            <div style="margin-bottom:18px;">
                <h4 style="margin:0 0 8px 0; font-size:13px; display:flex; align-items:center; gap:8px;">
                    <i class="fa-solid fa-building" style="color:var(--primary);"></i> ${escapeHtml(t)}
                    <span style="color:var(--text-muted); font-weight:400; font-size:12px;">(${rows.length})</span>
                </h4>
                ${body}
            </div>`;
        }).join('');
    }

    // Risultati raggruppati per switch: ogni host è un accordion collassato;
    // si clicca sull'host per mostrare i MAC (UX più pulita di righe piatte).
    function renderMacResults(rows) {
        const box = document.getElementById('macResults');
        if (!box) return;
        if (!rows.length) {
            box.innerHTML = `<div style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;">
                <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${currentLang==='en'?'No MAC sightings. Run a MAC Scan to populate the history.':'Nessun avvistamento MAC. Avvia una MAC Scan per popolare lo storico.'}</div>`;
            return;
        }
        const groups = {};
        rows.forEach(r => {
            const key = r.switch_ip || '?';
            if (!groups[key]) groups[key] = { ip: r.switch_ip, name: r.switch_name, tenant: r.tenant, rows: [] };
            groups[key].rows.push(r);
        });
        const keys = Object.keys(groups).sort();
        const openAll = keys.length === 1;   // un solo switch: aperto di default
        const L = i18n[currentLang];
        const colHead = `<thead><tr>
            <th>${L.thMacAddr}</th><th>${L.thMacPort}</th>
            <th>${L.thMacVlan}</th><th>${L.thMacOrigin}</th><th>${L.thMacFirst}</th><th>${L.thMacLast}</th></tr></thead>`;
        box.innerHTML = keys.map(k => {
            const g = groups[k];
            const title = g.name
                ? `${escapeHtml(g.name)} <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(g.ip)}</span>`
                : escapeHtml(g.ip || '—');
            const tenant = g.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(g.tenant)}</span>` : '';
            const body = g.rows.map(r => {
                const port = r.port_channel
                    ? `${escapeHtml(r.interface||'—')} <span class="badge" style="font-size:10px;">${escapeHtml(r.port_channel)}</span>`
                    : escapeHtml(r.interface || '—');
                const uplink = r.is_uplink
                    ? ` <span title="${currentLang==='en'?'Seen on a trunk/uplink (transit, not the access location)':'Visto su trunk/uplink (transito, non posizione di accesso)'}" style="font-size:10px; color:var(--warning); border:1px solid var(--warning); border-radius:4px; padding:0 4px;">uplink</span>`
                    : '';
                const originCell = r.is_uplink
                    ? `<span title="${currentLang==='en'?'In transit on an uplink':'In transito su un uplink'}" style="font-size:10px; color:var(--warning); border:1px solid var(--warning); border-radius:4px; padding:1px 5px;"><i class="fa-solid fa-arrow-right-arrow-left"></i> ${currentLang==='en'?'transit':'transito'}${r.uplink_to?` → ${escapeHtml(r.uplink_to)}`:''}</span>`
                    : `<span title="${currentLang==='en'?'Access port – device attached here':'Porta di accesso – dispositivo collegato qui'}" style="font-size:10px; color:var(--success); border:1px solid var(--success); border-radius:4px; padding:1px 5px;"><i class="fa-solid fa-location-crosshairs"></i> ${currentLang==='en'?'access':'accesso'}</span>`;
                const portCfgBtn = (g.ip && r.interface)
                    ? `<button onclick="showPortConfig('${escapeHtml(g.ip)}','${escapeHtml(r.interface)}','${escapeHtml(g.name || '')}')" title="${escapeHtml(i18n[currentLang].btnPortConfig)}" style="margin-left:6px; border:none; background:none; color:var(--primary); cursor:pointer; font-size:12px;"><i class="fa-solid fa-file-lines"></i></button>`
                    : '';
                const locateBtn = `<button onclick="macLocate('${escapeHtml(r.mac)}')" title="${currentLang==='en'?'Locate origin across switches':'Localizza origine tra gli switch'}" style="margin-left:6px; border:none; background:none; color:var(--primary); cursor:pointer; font-size:12px;"><i class="fa-solid fa-magnifying-glass-location"></i></button>`;
                // MAC di un'interfaccia propria dello switch: infrastruttura, non endpoint.
                const isSwitchIf = (r.origin_type || r.device_type) === 'switch-interface';
                const swName = r.origin_switch || r.switch_name || r.switch_ip;
                const swIf = r.origin_interface || '';
                const switchBadge = isSwitchIf
                    ? ` <span title="${currentLang==='en'?`Interface of ${swName}${swIf?` (${swIf})`:''}`:`Interfaccia di ${swName}${swIf?` (${swIf})`:''}`}" style="font-size:10px; color:var(--text-muted); border:1px solid var(--border); border-radius:4px; padding:0 4px;"><i class="fa-solid fa-microchip"></i> SWITCH</span>`
                    : '';
                const rowStyle = isSwitchIf ? ' style="color:var(--text-muted);"' : '';
                return `<tr${rowStyle}>
                    <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(r.mac)}${switchBadge}</td>
                    <td>${port}${uplink}${portCfgBtn}</td>
                    <td>${escapeHtml(r.vlan || '—')}</td>
                    <td style="white-space:nowrap;">${originCell}${locateBtn}</td>
                    <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(fmtMacTime(r.first_seen))}</td>
                    <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(fmtMacTime(r.last_seen))}</td>
                </tr>`;
            }).join('');
            const macWord = currentLang==='en' ? (g.rows.length===1?'MAC':'MACs') : 'MAC';
            return `<details class="mac-switch" ${openAll?'open':''} style="margin-bottom:10px; border:1px solid var(--border); border-radius:10px; background:var(--surface-2); overflow:hidden;">
                <summary style="cursor:pointer; padding:12px 14px; font-weight:700; display:flex; align-items:center; gap:8px;">
                    <i class="fa-solid fa-chevron-right mac-chev"></i>
                    <i class="fa-solid fa-network-wired" style="color:var(--primary);"></i>
                    <span>${title}${tenant}</span>
                    <span style="margin-left:auto; font-size:12px; color:var(--text-muted); font-weight:600;">${g.rows.length} ${macWord}</span>
                </summary>
                <div class="table-container" style="border-top:1px solid var(--border);">
                    <table>${colHead}<tbody>${body}</tbody></table>
                </div>
            </details>`;
        }).join('');
    }

    function closeMacLocateModal() {
        const m = document.getElementById('macLocateModal');
        if (m) m.remove();
    }

    async function macLocate(mac) {
        const res = await apiFetch('/api/mac/locate?mac=' + encodeURIComponent(mac));
        if (!res || !res.ok) { alert(currentLang==='en'?'Locate failed.':'Localizzazione non riuscita.'); return; }
        const d = await res.json();
        const en = currentLang === 'en';

        // Se la ricerca ha colpito più MAC distinti, localizza il primo del gruppo.
        const g = (d.results && d.results.length && !d.origin) ? d.results[0] : d;
        const status = g.status || d.status || 'resolved';
        const origin = g.origin || [];
        const transit = g.transit || [];
        const macStr = g.mac || d.mac || mac;

        // rank: la porta d'accesso più recente è la più probabile (primo elemento).
        const sightRow = (s, accent, badge) => `
            <div style="display:flex; align-items:center; gap:10px; padding:8px 10px; border:1px solid var(--border); border-left:3px solid ${accent}; border-radius:8px; margin-bottom:6px; background:var(--surface-2);">
                <i class="fa-solid fa-network-wired" style="color:var(--primary);"></i>
                <div style="flex:1;">
                    <div style="font-weight:700; font-size:13px;">${escapeHtml(s.switch_name || s.switch_ip)}
                        <span style="color:var(--text-muted); font-family:var(--font-code); font-size:11px;">${escapeHtml(s.switch_ip)}</span>${badge||''}</div>
                    <div style="font-size:11px; color:var(--text-muted);">
                        <i class="fa-solid fa-ethernet"></i> ${escapeHtml(s.interface || '—')}${s.port_channel?` (${escapeHtml(s.port_channel)})`:''}
                        • VLAN ${escapeHtml(s.vlan || '—')}${s.uplink_to?` • <span style="color:var(--warning);">→ ${escapeHtml(s.uplink_to)}</span>`:''}
                    </div>
                </div>
                <span style="font-size:11px; color:var(--text-muted);">${escapeHtml(fmtMacTime(s.last_seen))}</span>
            </div>`;

        const mostRecent = ` <span class="role-pill" style="background:rgba(59,225,136,0.15); color:var(--success); border:1px solid rgba(59,225,136,0.35);">${en?'most recent':'più recente'}</span>`;
        const originHtml = origin.length
            ? origin.map((s, i) => sightRow(s, 'var(--success)', (status==='ambiguous' && i===0) ? mostRecent : '')).join('')
            : `<div style="font-size:12px; color:var(--text-muted); padding:6px 2px;">${en?'No access port found – the device may be behind an unmanaged switch. Scan more switches.':'Nessuna porta di accesso trovata – il dispositivo potrebbe essere dietro uno switch non gestito. Scansiona altri switch.'}</div>`;
        const transitHtml = transit.length
            ? transit.map(s => sightRow(s, 'var(--warning)')).join('')
            : `<div style="font-size:12px; color:var(--text-muted); padding:6px 2px;">${en?'Not seen in transit elsewhere.':'Non visto in transito altrove.'}</div>`;

        // Banner di stato: chiarisce all'utente quanto è affidabile l'origine.
        let banner = '';
        // MAC di un'interfaccia propria di uno switch: infrastruttura, non endpoint.
        const isSwitchIf = (g.origin_type || g.device_type || d.origin_type) === 'switch-interface';
        if (isSwitchIf) {
            const swName = g.origin_switch || d.origin_switch || '';
            const swIf = g.origin_interface || d.origin_interface || '';
            banner = `<div style="display:flex; gap:8px; align-items:flex-start; padding:10px 12px; border-radius:8px; background:rgba(139,124,255,0.12); border:1px solid rgba(139,124,255,0.35); color:var(--primary); font-size:12px; margin-bottom:14px;">
                <i class="fa-solid fa-microchip" style="margin-top:2px;"></i>
                <span>${en?`This MAC belongs to interface ${swIf} of ${swName}`:`Questo MAC appartiene all'interfaccia ${swIf} di ${swName}`}</span></div>`;
        } else if (status === 'ambiguous') {
            banner = `<div style="display:flex; gap:8px; align-items:flex-start; padding:10px 12px; border-radius:8px; background:rgba(255,184,77,0.12); border:1px solid rgba(255,184,77,0.35); color:var(--warning); font-size:12px; margin-bottom:14px;">
                <i class="fa-solid fa-triangle-exclamation" style="margin-top:2px;"></i>
                <span>${en?`Multiple possible access ports (${g.access_count}). The most recent is the likeliest; run a fresh MAC Scan to disambiguate.`:`Più porte d'accesso possibili (${g.access_count}). La più recente è la più probabile; esegui una MAC Scan aggiornata per disambiguare.`}</span></div>`;
        } else if (status === 'transit_only') {
            banner = `<div style="display:flex; gap:8px; align-items:flex-start; padding:10px 12px; border-radius:8px; background:rgba(255,184,77,0.12); border:1px solid rgba(255,184,77,0.35); color:var(--warning); font-size:12px; margin-bottom:14px;">
                <i class="fa-solid fa-circle-info" style="margin-top:2px;"></i>
                <span>${en?'Only seen in transit on uplinks – the device is behind an unmanaged/unscanned switch. Scan more switches to find the access port.':'Visto solo in transito sugli uplink – il dispositivo è dietro uno switch non gestito/non scansionato. Scansiona altri switch per trovare la porta di accesso.'}</span></div>`;
        } else if (status === 'resolved' && origin.length) {
            banner = `<div style="display:flex; gap:8px; align-items:center; padding:10px 12px; border-radius:8px; background:rgba(59,225,136,0.12); border:1px solid rgba(59,225,136,0.35); color:var(--success); font-size:12px; margin-bottom:14px;">
                <i class="fa-solid fa-circle-check"></i>
                <span>${en?'Single access port resolved.':'Porta di accesso univoca risolta.'}</span></div>`;
        }

        const ov = document.createElement('div');
        ov.id = 'macLocateModal';
        ov.style.cssText = 'position:fixed; inset:0; z-index:10050; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(4px);';
        ov.innerHTML = `
            <div style="background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:22px; width:min(560px,94vw); max-height:86vh; overflow:auto; box-shadow:0 20px 60px rgba(0,0,0,0.6);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <h3 style="font-size:16px;"><i class="fa-solid fa-magnifying-glass-location" style="color:var(--primary);"></i> ${en?'MAC origin':'Origine MAC'}</h3>
                    <i class="fa-solid fa-xmark" onclick="closeMacLocateModal()" style="cursor:pointer; color:var(--text-muted); font-size:18px;"></i>
                </div>
                <div style="font-family:var(--font-code); font-size:13px; color:var(--primary); margin-bottom:16px;">${escapeHtml(macStr)}</div>

                ${banner}

                <h4 style="font-size:13px; margin-bottom:8px; color:var(--success);"><i class="fa-solid fa-location-crosshairs"></i> ${en?'Access location (origin)':'Posizione di accesso (origine)'}</h4>
                ${originHtml}

                <h4 style="font-size:13px; margin:16px 0 8px; color:var(--warning);"><i class="fa-solid fa-arrow-right-arrow-left"></i> ${en?'Seen in transit (uplinks)':'Visto in transito (uplink)'}</h4>
                ${transitHtml}

                <div style="display:flex; justify-content:flex-end; align-items:center; gap:10px; margin-top:16px;">
                    <button onclick="closeMacLocateModal()" class="btn btn-secondary btn-small" style="width:auto; margin:0;">${en?'Close':'Chiudi'}</button>
                </div>
            </div>`;
        ov.addEventListener('click', e => { if (e.target === ov) closeMacLocateModal(); });
        document.body.appendChild(ov);
    }

    // MOVED to static/js/core.js (showPortConfig / closePortConfigModal / openPortInAnalyzer / expandIface / caFocusIp / caFocusPort)

    async function saveMacRetention() {
        const days = parseInt(document.getElementById('macRetentionDays') ? document.getElementById('macRetentionDays').value : '', 10);
        if (!days || days < 1) { alert(currentLang==='en'?'Enter a valid number of days.':'Inserisci un numero di giorni valido.'); return; }
        const res = await apiFetch('/api/mac/settings', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ days })
        });
        if (res && res.ok) {
            const d = await res.json();
            alert((currentLang==='en'?'Retention set to ':'Retention impostata a ') + d.retention_days + (currentLang==='en'?' days.':' giorni.'));
            refreshMacStats(false);
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            alert((currentLang==='en'?'Error: ':'Errore: ') + (e.detail || ''));
        }
    }
