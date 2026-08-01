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

    // Popola il filtro "Switch" della ricerca con i soli switch del tenant scelto
    // (dropdown al posto del vecchio campo IP libero). Voce vuota = tutti gli switch.
    function fillMacSwitchFilter() {
        const sel = document.getElementById('macSearchSwitch');
        if (!sel || sel.tagName !== 'SELECT') return;
        const cur = sel.value;
        const allLabel = currentLang==='en' ? 'All switches' : 'Tutti gli switch';
        sel.innerHTML = `<option value="">${allLabel}</option>` +
            macFilteredDevices().map(d => {
                const name = d.Hostname ? ` — ${escapeHtml(d.Hostname)}` : '';
                return `<option value="${escapeHtml(d.IP)}">${escapeHtml(d.IP)}${name}</option>`;
            }).join('');
        sel.value = [...sel.options].some(o => o.value === cur) ? cur : '';
    }

    // Porta l'utente alla tabella dei MAC (clic sul KPI "MAC Univoci"), applicando
    // i filtri correnti e scorrendo la vista fino ai risultati.
    function focusMacResults() {
        macSearch();
        const el = document.getElementById('macResults');
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
        fillMacSwitchFilter();
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
            ? [th('MAC'), th('IP'), th('VLAN'), th('Gateway (routes VLAN)'), th('Type'), th('Access switch'), th('Port'), th('Last seen'), th('')]
            : [th('MAC'), th('IP'), th('VLAN'), th('Gateway (ruota la VLAN)'), th('Tipo'), th('Switch di accesso'), th('Porta'), th('Ultimo avvistamento'), th('')];
        // Un MAC amministrato localmente e non riconducibile a un OUI di
        // virtualizzazione può cambiare alla sessione successiva: il binding
        // vale adesso, non identifica il dispositivo. Chi legge la tabella deve
        // saperlo, altrimenti costruisce uno storico su un'identità che non c'è.
        const macBadge = r => {
            const info = r.mac_info;
            if (!info) return '';
            if (info.vendor_kind) return ` <span class="badge" style="font-size:9px;" title="${escapeHtml(info.oui)}">${escapeHtml(info.vendor_kind)}</span>`;
            if (r.stable_identity === false) return ` <span class="badge" style="font-size:9px; color:var(--warning);" title="${en ? 'Locally administered: may change between sessions' : 'Amministrato localmente: può cambiare fra le sessioni'}">${en ? 'not stable' : 'non stabile'}</span>`;
            return '';
        };
        const rowHtml = r => '<tr>' + [
            td(`<code>${escapeHtml(r.mac)}</code>${macBadge(r)}`),
            td(`<code>${escapeHtml(r.ip)}</code>`),
            td(escapeHtml(r.vlan || '—')),
            td(`<span title="${escapeHtml(r.source_type || '')}">${escapeHtml(r.source_name || '')} <span style="color:var(--text-muted);">${escapeHtml(r.source_ip)}</span></span>`),
            td(escapeHtml(r.client_type || 'client')),
            td(r.switch_ip ? `${escapeHtml(r.switch_name || '')} <span style="color:var(--text-muted);">${escapeHtml(r.switch_ip)}</span>` : '—'),
            td(escapeHtml(r.switch_port || '—') + (r.switch_ip && r.switch_port
                ? `<button onclick="showPortConfig('${escapeHtml(r.switch_ip)}','${escapeHtml(r.switch_port)}','${escapeHtml(r.switch_name || '')}')" title="${escapeHtml(i18n[currentLang].btnPortConfig)}" style="margin-left:6px; border:none; background:none; color:var(--primary); cursor:pointer; font-size:12px;"><i class="fa-solid fa-file-lines"></i></button>`
                : '')),
            td(fmtMacTime(r.last_seen)),
            // Diagnosi: la riga ha già IP e MAC, cioè tutto l'ingresso
            // dell'endpoint. Si passa l'IP quando c'è (più preciso del MAC,
            // che il servizio dovrebbe comunque risolvere).
            td(`<button onclick="diagnoseClient('${escapeHtml(jsStr(r.ip || r.mac))}','')" title="${escapeHtml(i18n[currentLang].btnDiagnose)}" style="border:none; background:none; color:var(--primary); cursor:pointer; font-size:13px;"><i class="fa-solid fa-stethoscope"></i></button>`),
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

    // --- DIAGNOSI CLIENT (L2 + L3 in un referto solo) ---
    // Il bottone sta sulla riga della Client Map e non in una scheda nuova:
    // quella riga ha già tutto ciò che serve all'endpoint (MAC e IP), e chi
    // sta guardando un client è già qui.
    //
    // Regola di rendering, ereditata dal referto: una sezione che non sa DICE
    // perché. Non viene mai nascosta — un buco taciuto manda l'ingegnere a
    // cercare nel posto sbagliato.

    let _diagClient = null;   // client del referto a schermo, per il "rilancia"

    function closeDiagnosisModal() {
        const el = document.getElementById('clientDiagnosisModal');
        if (el) el.remove();
    }

    function _diagShell(inner) {
        const en = currentLang === 'en';
        closeDiagnosisModal();
        const ov = document.createElement('div');
        ov.id = 'clientDiagnosisModal';
        ov.style.cssText = 'position:fixed; inset:0; z-index:10050; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; backdrop-filter:blur(4px);';
        ov.innerHTML = `
            <div style="background:var(--surface); border:1px solid var(--border); border-radius:14px; padding:22px; width:min(840px,95vw); max-height:88vh; overflow:auto; box-shadow:0 20px 60px rgba(0,0,0,0.6);">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                    <h3 style="font-size:16px;"><i class="fa-solid fa-stethoscope" style="color:var(--primary);"></i> ${en ? 'Client diagnosis' : 'Diagnosi client'}</h3>
                    <i class="fa-solid fa-xmark" onclick="closeDiagnosisModal()" style="cursor:pointer; color:var(--text-muted); font-size:18px;"></i>
                </div>
                ${inner}
            </div>`;
        ov.addEventListener('click', e => { if (e.target === ov) closeDiagnosisModal(); });
        document.body.appendChild(ov);
    }

    async function diagnoseClient(client, dest) {
        const en = currentLang === 'en';
        _diagClient = client;
        _diagShell(`<div style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
            <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>
            ${en ? 'Querying switch and firewall…' : 'Interrogazione di switch e firewall…'}
        </div>`);

        const body = { client };
        if (dest) body.dest = dest;
        const res = await apiFetch('/api/diagnose/client', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body)
        });
        if (!res || !res.ok) {
            const e = res ? await res.json().catch(() => ({})) : {};
            _diagShell(`<div style="color:var(--danger); font-size:13px;">${escapeHtml(e.detail || (en ? 'Diagnosis failed.' : 'Diagnosi fallita.'))}</div>`);
            return;
        }
        renderDiagnosis(await res.json(), dest);
    }

    function rerunDiagnosis() {
        const el = document.getElementById('diagDest');
        diagnoseClient(_diagClient, el ? el.value.trim() : '');
    }

    // Una sezione: pallino di stato, titolo, corpo. Se non è nota, il corpo è
    // il motivo — che è l'informazione utile, non un ripiego.
    // ``extra`` viene reso in OGNI caso, anche quando la sezione non è nota:
    // una sede agent ha firewall.known=false e proprio lì sta la risposta che
    // conta (la policy in arrivo dal relay).
    function _diagCard(icon, title, section, bodyFn, extra) {
        const en = currentLang === 'en';
        const known = section && section.known;
        const err = section && section.error;
        const color = err ? 'var(--danger)' : (known ? 'var(--success)' : 'var(--warning)');
        let body;
        if (err) {
            body = `<div style="color:var(--danger); font-size:12px;">${escapeHtml(err)}</div>`;
        } else if (!known) {
            body = `<div style="color:var(--text-muted); font-size:12px;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml((section && section.reason) || (en ? 'not known' : 'non noto'))}</div>`;
        } else {
            body = bodyFn(section);
        }
        return `<div style="background:var(--surface-2); border:1px solid var(--border); border-radius:10px; padding:12px 14px; margin-bottom:10px;">
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:13px; font-weight:600;">
                <span style="width:8px; height:8px; border-radius:50%; background:${color}; flex:none;"></span>
                <i class="fa-solid ${icon}" style="color:var(--text-muted);"></i> ${escapeHtml(title)}
            </div>${body}${extra || ''}</div>`;
    }

    const _kv = (k, v) => `<div style="display:flex; gap:8px; font-size:12px; padding:2px 0;">
        <span style="color:var(--text-muted); min-width:150px;">${escapeHtml(k)}</span>
        <span style="font-family:var(--font-code);">${escapeHtml(v === null || v === undefined || v === '' ? '—' : String(v))}</span></div>`;

    function renderDiagnosis(d, dest) {
        const en = currentLang === 'en';
        const s = d.sections || {};

        const badge = d.complete
            ? `<span class="badge" style="color:var(--success);">${en ? 'complete' : 'completo'}</span>`
            : `<span class="badge" style="color:var(--warning);" title="${en ? 'Some sections could not be answered — see below' : 'Alcune sezioni non hanno risposta — vedi sotto'}">${en ? 'partial' : 'parziale'}</span>`;

        const position = _diagCard('fa-location-dot', en ? 'Position' : 'Posizione', s.position, p =>
            _kv('MAC', p.mac) + _kv('IP', p.ip) +
            _kv(en ? 'Tenant / site' : 'Tenant / sede', `${p.tenant || '—'} / ${p.site || '—'}`) +
            _kv(en ? 'Access switch' : 'Switch di accesso', `${p.switch_name || ''} ${p.switch_ip || ''}`.trim()) +
            _kv(en ? 'Port / VLAN' : 'Porta / VLAN', `${p.switch_port || '—'} / ${p.port_vlan || '—'}`) +
            _kv('Gateway', `${p.gateway_name || ''} ${p.gateway_ip || ''} (${p.gateway_type || '—'})`.trim()) +
            // Le date non sono decorazione: la raccolta ARP/MAC è manuale, e
            // una porta vista tre settimane fa si legge come una vista adesso.
            _kv(en ? 'Binding seen' : 'Binding visto', fmtMacTime(p.binding_last_seen)) +
            _kv(en ? 'Port seen' : 'Porta vista', fmtMacTime(p.port_last_seen)) +
            (p.port_known === false ? `<div style="color:var(--warning); font-size:12px; margin-top:6px;">${escapeHtml(p.port_reason || '')}</div>` : '') +
            (p.ambiguous ? `<div style="color:var(--warning); font-size:12px; margin-top:6px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${en ? 'Other bindings for this address' : 'Altri binding per questo indirizzo'}: ${p.ambiguous.map(a => escapeHtml(a.mac)).join(', ')}</div>` : '')
        );

        const l2 = _diagCard('fa-ethernet', en ? 'L2 link health' : 'Salute del collegamento L2', s.l2_health, h => {
            const i = h.interface || {};
            let out = '';
            if (i.known) {
                const d1 = i.error_delta || {};
                out += _kv('Link', `${i.link || '—'} (admin ${i.admin_status || '—'})`);
                out += _kv(en ? 'Errors in/out' : 'Errori in/out',
                    i.error_delta === null
                        ? (en ? 'single sample: cannot tell' : 'un solo campione: non si può dire')
                        : `${d1.in_errors === null ? '?' : d1.in_errors} / ${d1.out_errors === null ? '?' : d1.out_errors}` +
                          (i.error_window_s ? ` (${i.error_window_s}s)` : ''));
                if (i.erroring) out += `<div style="color:var(--danger); font-size:12px; margin-top:6px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${en ? 'Error counters are rising: suspect cabling, transceiver or duplex mismatch.' : 'I contatori di errore stanno salendo: sospetta cablaggio, transceiver o duplex mismatch.'}</div>`;
            } else {
                out += `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(i.reason || i.error || '')}</div>`;
            }
            const t = h.trunk || {};
            out += `<div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border);"></div>`;
            if (t.known) {
                out += _kv(en ? 'VLAN on trunks' : 'VLAN sui trunk',
                    t.ok ? (en ? 'allowed on all trunks' : 'ammessa su tutti i trunk')
                         : (en ? 'MISSING' : 'MANCANTE'));
                if (!t.ok) out += `<div style="color:var(--danger); font-size:12px; margin-top:6px;">${en ? 'VLAN' : 'VLAN'} ${escapeHtml(t.vlan)} ${en ? 'is not allowed on' : 'non è ammessa su'}: ${t.missing.map(m => escapeHtml(m.interface)).join(', ')}</div>`;
                out += `<div style="color:var(--text-muted); font-size:11px; margin-top:4px;">${escapeHtml(t.scope || '')}</div>`;
            } else {
                out += `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(t.reason || t.error || '')}</div>`;
            }
            return out;
        });

        const path = _diagCard('fa-route', en ? 'Traffic path' : 'Percorso del traffico', s.path, p =>
            (p.hops || []).map(h => `<div style="font-size:12px; padding:3px 0; ${h.known ? '' : 'color:var(--warning);'}">
                <i class="fa-solid ${h.known ? 'fa-circle-check' : 'fa-circle-question'}" style="margin-right:8px;"></i>${escapeHtml(h.label || h.kind)}</div>`).join('')
        );

        // Sede agent: il centrale non raggiunge l'apparato, la policy arriva
        // dal relay al prossimo poll. Va detto, altrimenti "nessuna policy"
        // si legge come "nessuna policy esiste".
        const relay = s.firewall && s.firewall.policy_lookup;
        const relayNote = relay ? `<div style="margin-top:8px; padding-top:8px; border-top:1px solid var(--border);">
            ${relay.known
                ? `<div style="font-size:12px; font-weight:600; margin-bottom:4px;">${en ? 'Matching policy (via relay)' : 'Policy che matcherebbe (via relay)'}</div>
                   <pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:10px; margin:0; white-space:pre-wrap; font-size:11px; max-height:180px; overflow:auto;">${escapeHtml(JSON.stringify(relay.data, null, 2))}</pre>`
                : `<div style="color:${relay.pending ? 'var(--warning)' : 'var(--text-muted)'}; font-size:12px;">
                     <i class="fa-solid ${relay.pending ? 'fa-hourglass-half' : 'fa-circle-info'}" style="margin-right:6px;"></i>${escapeHtml(relay.reason || '')}</div>`}
        </div>` : '';

        const fw = _diagCard('fa-shield-halved', 'Firewall', s.firewall, f => {
            let out = _kv('FortiGate', f.fortigate) + _kv(en ? 'Chosen by' : 'Scelto per', f.resolved_by);
            const sub = f.sections || {};
            const pl = sub.policy_lookup;
            if (pl && pl.data) {
                out += `<div style="margin-top:8px; padding-top:8px; border-top:1px solid var(--border); font-size:12px; font-weight:600;">${en ? 'Matching policy' : 'Policy che matcherebbe'}</div>`;
                out += `<pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:180px; overflow:auto;">${escapeHtml(JSON.stringify(pl.data, null, 2))}</pre>`;
            }
            const failed = Object.keys(sub).filter(k => sub[k] && sub[k].error);
            if (failed.length) out += `<div style="color:var(--text-muted); font-size:11px; margin-top:8px;">${en ? 'Sections unavailable' : 'Sezioni non disponibili'}: ${escapeHtml(failed.join(', '))}</div>`;
            out += `<details style="margin-top:8px;"><summary style="cursor:pointer; font-size:11px; color:var(--text-muted);">${en ? 'Raw FortiGate output' : 'Output grezzo del FortiGate'}</summary>
                <pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:260px; overflow:auto;">${escapeHtml(JSON.stringify(sub, null, 2))}</pre></details>`;
            return out;
        }, relayNote);

        // Fra sedi diverse il flusso attraversa DUE firewall, e basta che uno
        // neghi. Più ciò che sta in mezzo: tunnel e rotta.
        const across = !s.across_sites ? '' : _diagCard('fa-tower-broadcast',
            en ? 'Across sites' : 'Fra sedi', s.across_sites, a => {
            if (a.same_site === null) return `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(a.note || '')}</div>`;
            let out = _kv(en ? 'Source site' : 'Sede sorgente', a.source.site) +
                      _kv(en ? 'Destination site' : 'Sede destinazione', `${a.destination.site || '—'}${a.destination.derived === 'declared-subnet' ? (en ? ' (declared)' : ' (dichiarata)') : ''}`);
            if (a.same_site) {
                out += `<div style="color:var(--text-muted); font-size:12px; margin-top:6px;">${escapeHtml(a.note || '')}</div>`;
                return out;
            }
            const fe = a.far_end_policy || {};
            out += `<div style="margin-top:8px; font-size:12px; font-weight:600;">${en ? 'Far-end firewall policy' : 'Policy del firewall remoto'}</div>`;
            out += fe.data
                ? `<pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:160px; overflow:auto;">${escapeHtml(JSON.stringify(fe.data, null, 2))}</pre>`
                : `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(fe.reason || fe.error || '')}</div>`;
            if (a.tunnels) out += _kv(en ? 'IPsec tunnels' : 'Tunnel IPsec',
                a.tunnels.error ? a.tunnels.error : (en ? 'see raw output' : 'vedi output grezzo'));
            if (a.route) {
                const rd = a.route.data || {};
                out += _kv(en ? 'Route to destination' : 'Rotta verso la destinazione',
                    a.route.error ? a.route.error
                        : (rd.matched ? `${rd.destination} → ${rd.gateway || '—'} (${rd.interface || '—'})`
                                      : (en ? 'NO ROUTE' : 'NESSUNA ROTTA')));
                if (rd.matched === false) out += `<div style="color:var(--danger); font-size:12px; margin-top:6px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${en ? 'The firewall has no route to that address: a permitted policy would not help.' : 'Il firewall non ha una rotta verso questo indirizzo: una policy che permette non basterebbe.'}</div>`;
            }
            out += `<details style="margin-top:8px;"><summary style="cursor:pointer; font-size:11px; color:var(--text-muted);">${en ? 'Raw output' : 'Output grezzo'}</summary>
                <pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:260px; overflow:auto;">${escapeHtml(JSON.stringify({tunnels: a.tunnels, route: a.route}, null, 2))}</pre></details>`;
            return out;
        });

        const denies = _diagCard('fa-ban', en ? 'Blocks (last hour)' : 'Blocchi (ultima ora)', s.denies, b => {
            let out = _kv(en ? 'Total' : 'Totale', b.total);
            if (b.total && b.by_policy.length) {
                out += `<div style="margin-top:8px; font-size:12px;">` + b.by_policy.map(p =>
                    `<div style="padding:2px 0;"><span class="badge" style="font-size:10px;">policy ${escapeHtml(p.policy_id)}</span>
                     <span style="color:var(--text-muted);">${escapeHtml(p.subtype)}</span> — ${p.count}</div>`).join('') + `</div>`;
            }
            if (b.truncated) out += `<div style="color:var(--warning); font-size:11px; margin-top:6px;">${en ? 'Scan capped: this is a minimum, not a total.' : 'Scansione troncata: è un minimo, non un totale.'}</div>`;
            return out;
        });

        _diagShell(`
            <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:14px;">
                <span style="font-family:var(--font-code); font-size:14px; color:var(--primary);">${escapeHtml(d.client)}</span>
                ${badge}
                <div style="flex:1;"></div>
                <input id="diagDest" value="${escapeHtml(dest || '')}" placeholder="${en ? 'destination IP/FQDN' : 'IP/FQDN destinazione'}"
                       style="background:var(--surface-2); border:1px solid var(--border); border-radius:8px; padding:6px 10px; font-size:12px; color:var(--text); width:210px;">
                <button onclick="rerunDiagnosis()" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-rotate"></i> ${en ? 'Re-run' : 'Rilancia'}</button>
            </div>
            ${position}${l2}${path}${fw}${across}${denies}
            <div style="display:flex; justify-content:flex-end; margin-top:6px;">
                <button onclick="closeDiagnosisModal()" class="btn btn-secondary btn-small" style="width:auto; margin:0;">${en ? 'Close' : 'Chiudi'}</button>
            </div>`);
    }

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
