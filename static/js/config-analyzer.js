    // ===== Config Analyzer =====
    // Dati cache lato client: un solo fetch per tenant selezionato, i pill di
    // vista ri-renderizzano senza richiamare l'API (come richiesto).
    let caData = null;
    let caView = 'home';
    let caFwView = null; // sub-menu del pill "Firewall": id sezione vendor-driven (fw_analyzers envelope), auto-inizializzato al primo render
    let caSrvView = null; // idem per il pill "Server" (envelope ai/linux_analyzer)
    let caRouteGroupMode = 'flat'; // 'flat' | 'byhop' — ricordato per la sessione
    let caNetworks = {};   // ip -> vis.Network istanza mappa route (lazy, per device aperto)
    // Lista EFFETTIVAMENTE renderizzata negli accordion per-apparato. Non e'
    // caData: le viste VLAN/Routing/ACL/Interfacce escludono firewall e server,
    // e ``data-ca-idx`` e' l'indice in QUESTA lista. Cercare quell'indice in
    // caData restituisce un altro apparato ogni volta che un firewall o un
    // server lo precede — la mappa route finiva sul device sbagliato.
    // ponytail: indice posizionale, non chiave. Se un giorno una vista ordina
    // o filtra la lista dopo il render, si passa a data-ca-ip.
    let caList = [];

    function loadConfigAnalyzer(forceRefresh) {
        const sel = document.getElementById('configGroupSelect');
        if (sel) {
            const cur = sel.value;
            const groups = Object.keys(globalGroups || {});
            sel.innerHTML = `<option value="all">${i18n[currentLang].optFilterAll}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            sel.value = groups.includes(cur) ? cur : 'all';
        }
        fetchConfigAnalyzer();
    }

    async function fetchConfigAnalyzer() {
        const box = document.getElementById('caResults');
        if (box) box.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i></div>`;
        destroyCaNetworks();
        const sel = document.getElementById('configGroupSelect');
        const group = sel ? sel.value : 'all';
        try {
            const res = await apiFetch('/api/config-analyzer?group=' + encodeURIComponent(group || 'all'));
            if (!res || !res.ok) { if (box) box.innerHTML = ''; return; }
            const d = await res.json();
            caData = d.devices || [];
        } catch (e) {
            caData = [];
        }
        renderCaResults();
    }

    function caSwitchView(view) {
        caView = view;
        document.querySelectorAll('#caPills .ca-pill').forEach(p => p.classList.toggle('active', p.dataset.view === view));
        destroyCaNetworks();
        renderCaResults();
    }

    // Triage per-apparato dalla scheda del Config Analyzer. Il bottone e' lo
    // stesso dell'inventario (icona, colore, endpoint): e' la stessa azione, e
    // due controlli diversi per la stessa cosa si imparano due volte.
    // L'eta' del backup sta accanto al bottone perche' e' cio' che rende il
    // bottone una decisione: e' il dato vecchio che si vuole rinfrescare.
    // 'requires-write' e' il gancio gia' in uso (body.role-viewer lo nasconde):
    // il triage e' operator-only e a un viewer il bottone non serve.
    function caTriageButton(dev, L) {
        return `<span style="display:inline-flex; align-items:center; gap:8px; margin-left:8px;">
            ${backupAgeLabel(dev.backup_ts)}
            <button type="button" class="btn btn-secondary btn-small requires-write"
                style="margin:0; padding:4px 8px; color:var(--warning);"
                title="${escapeHtml(L.titleCaTriage)}"
                data-action="ca-triage" data-ip="${escapeHtml(dev.ip)}"><i class="fa-solid fa-bolt-lightning"></i></button>
        </span>`;
    }

    // Il bottone vive dentro <summary>: senza preventDefault il click aprirebbe
    // e chiuderebbe anche l'accordion.
    async function caTriageDevice(ip, btnEl, ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        // triageSingleDevice() e' quello dell'inventario. Fuori da una tabella
        // le sue letture di riga sono tutte opzionali e protette, quindi gira
        // qui senza modifiche: disabilita il bottone, gira, e lo ripristina con
        // la stessa icona che questo bottone usa.
        await triageSingleDevice(ip, btnEl);
        // Il triage ha riscritto il backup: quello a schermo e' il vecchio.
        await fetchConfigAnalyzer();
        // caView e' stato di modulo e sopravvive al refetch: si riapre solo la
        // scheda su cui si stava lavorando.
        const card = document.querySelector(`details[data-ca-ip="${CSS.escape(ip)}"]`);
        if (card) {
            card.open = true;
            card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    function destroyCaNetworks() {
        Object.keys(caNetworks).forEach(k => { try { caNetworks[k].destroy(); } catch (e) {} });
        caNetworks = {};
    }

    function caDeviceCount(dev) {
        if (dev.config_type === 'linux') {
            const secs = ((dev.server || {}).sections) || [];
            return secs.reduce((n, s) => n + ((s.rows || []).length), 0);
        }
        if (dev.config_type === 'fortios') return (dev.policies || []).length;
        if (dev.config_type === 'wlc-aireos') return (dev.wlans || []).length;
        if (caView === 'vlan') return (dev.vlans || []).length;
        if (caView === 'routing') return (dev.routing && dev.routing.static ? dev.routing.static.length : 0) + (dev.routing && dev.routing.protocols ? dev.routing.protocols.length : 0);
        if (caView === 'acl') return (dev.acls || []).length;
        if (caView === 'iface') return (dev.interfaces || []).length;
        return 0;
    }

    // Applica il filtro di ricerca alle righe della tabella nel #caResults
    function caApplySearch() {
        const inp = document.getElementById('caSearch');
        if (!inp) return;
        // Home e Converti non hanno tabelle dati: input nascosto e filtro no-op.
        const searchable = !['home', 'convert'].includes(caView);
        inp.style.display = searchable ? '' : 'none';
        if (!searchable) return;
        const q = inp.value.trim().toLowerCase();
        document.querySelectorAll('#caResults tbody tr').forEach(tr => {
            tr.style.display = (!q || tr.textContent.toLowerCase().includes(q)) ? '' : 'none';
        });
        document.querySelectorAll('#caResults details.mac-switch').forEach(det => {
            const rows = det.querySelectorAll('tbody tr');
            const anyVisible = !q || !rows.length ||
                Array.from(rows).some(r => r.style.display !== 'none');
            det.style.display = anyVisible ? '' : 'none';
            if (q && anyVisible && rows.length) det.open = true;
        });
    }

    function isFirewallDevice(dev) {
        if (!dev) return false;
        const ct = (dev.config_type || '').toLowerCase();
        const vendor = (dev.vendor || '').toLowerCase();
        const cat = (dev.category || '').toLowerCase();
        return !!(dev.is_firewall || ct === 'fortios' || ct === 'panos' || vendor === 'fortigate' || vendor === 'paloalto' || vendor === 'fortinet' || cat === 'firewall');
    }

    // Un host Linux non ha VLAN, ACL o interfacce in senso Cisco: sta solo nel
    // pill "Server", e viene escluso dalle viste che descrivono uno switch.
    function isServerDevice(dev) {
        return !!(dev && (dev.config_type || '').toLowerCase() === 'linux');
    }

    function caRenderResultsInner() {
        const box = document.getElementById('caResults');
        if (!box) return;
        const L = i18n[currentLang];
        const en = currentLang === 'en';
        if (caView === 'home') {
            if (caFocusIp && caData && caData.length) {
                caApplyFocus();
                if (caView !== 'home') return;
            }
            box.innerHTML = caRenderHome(L);
            return;
        }
        if (caView === 'convert') { box.innerHTML = caRenderConvert(L); return; }
        if (caView === 'firewall') { box.innerHTML = caRenderFirewallView(L, en); return; }
        if (caView === 'server') { box.innerHTML = caRenderServerView(L, en); return; }
        if (!caData || !caData.length) {
            box.innerHTML = `<div style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.msgCaNoDevices)}</div>`;
            return;
        }
        let list = caData;
        if (['vlan', 'routing', 'acl', 'iface'].includes(caView)) {
            list = caData.filter(dev => !isFirewallDevice(dev) && !isServerDevice(dev));
        }
        caList = list;
        if (!list.length) {
            box.innerHTML = `<div style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.msgCaNoDevices)}</div>`;
            return;
        }
        if (caView === 'validation') {
            box.innerHTML = list.map(dev => caRenderValidation(dev, L, en)).join('');
            caApplyFocus();
            return;
        }
        const openAll = list.length === 1;
        box.innerHTML = list.map((dev, idx) => {
            const count = caDeviceCount(dev);
            const tenant = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
            const body = caView === 'vlan' ? caRenderVlans(dev, L, en)
                       : caView === 'routing' ? caRenderRouting(dev, L, en, idx)
                       : caView === 'acl' ? caRenderAcls(dev, L, en)
                       : caRenderIfaces(dev, L, en);
            return `<details class="mac-switch" data-ca-idx="${idx}" data-ca-ip="${escapeHtml(dev.ip)}" style="border:1px solid var(--border); border-radius:0; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" ${openAll ? 'open' : ''} ontoggle="caOnToggle(this, ${idx})">
                <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                    <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                    <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                    <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                    ${tenant}
                    <span style="margin-left:auto; color:var(--text-muted); font-size:12px;">${count}</span>
                    ${caTriageButton(dev, L)}
                </summary>
                <div style="padding:0 14px 14px;">${body}</div>
            </details>`;
        }).join('');
        caApplyFocus();
    }

    function renderCaResults() {
        caRenderResultsInner();
        caApplySearch();
    }

    // Deep-link dal modale "Config porta": apre il device e evidenzia l'interfaccia.
    function caApplyFocus() {
        if (!caFocusIp || !caData || !caData.length) return;
        // Esistenza nel dataset COMPLETO: decide solo se vale la pena cambiare
        // vista, e va cercata prima che caList sia stata popolata.
        if (!caData.some(d => d.ip === caFocusIp)) { caFocusIp = caFocusPort = null; return; }
        if (caView !== 'iface') {
            // caSwitchView richiama renderCaResults, che a sua volta rientra qui con la vista giusta.
            caSwitchView('iface');
            return;
        }
        // L'indice del DOM e' quello della lista renderizzata, non di caData.
        const idx = caList.findIndex(d => d.ip === caFocusIp);
        const port = caFocusPort;
        caFocusIp = caFocusPort = null;
        if (idx === -1) return;
        const detailsEl = document.querySelector(`details[data-ca-idx="${idx}"]`);
        if (!detailsEl) return;
        detailsEl.open = true;
        const want = expandIface(port || '').toLowerCase();
        const row = detailsEl.querySelector(`tr[data-ca-iface="${CSS.escape(want)}"]`);
        const target = row || detailsEl;
        setTimeout(() => {
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            if (row) {
                row.style.outline = '2px solid var(--primary)';
                row.style.outlineOffset = '-2px';
                setTimeout(() => { row.style.outline = ''; row.style.outlineOffset = ''; }, 2500);
            }
        }, 50);
    }

    // ===== Config Analyzer: Home / Firewall / Converti =====

    function caDeviceOptions(L, pickKey) {
        const opts = (caData || []).map(d =>
            `<option value="${escapeHtml(d.ip)}">${escapeHtml(d.hostname || d.ip)} — ${escapeHtml(d.ip)} (${escapeHtml(d.config_type || 'ios')})</option>`).join('');
        return `<option value="">${escapeHtml(L[pickKey])}</option>` + opts;
    }

    function caRenderHome(L) {
        const card = (view, icon, title, desc) => `
            <div class="hero-card" data-action="ca-switch-view" data-view="${view}" style="cursor:pointer; flex:1; min-width:220px; border:1px solid var(--border); border-radius:0; background:var(--surface-2); padding:22px 18px; transition:var(--transition);">
                <div style="font-size:var(--font-size-3xl); color:var(--primary); margin-bottom:10px;"><i class="fa-solid ${icon}"></i></div>
                <div style="font-weight:600; font-size:15px; margin-bottom:6px;">${escapeHtml(title)}</div>
                <div style="font-size:12px; color:var(--text-muted); line-height:1.5;">${escapeHtml(desc)}</div>
            </div>`;
        return `<div style="display:flex; gap:14px; flex-wrap:wrap; padding:8px 2px;">
            ${card('vlan', 'fa-magnifying-glass-chart', L.caHomeAnalyzeTitle, L.caHomeAnalyzeDesc)}
            ${card('convert', 'fa-right-left', L.pillCaConvert, L.caHomeConvertDesc)}
        </div>`;
    }

    let caConvLastPreview = '';

    function caRenderConvert(L) {
        const vendorOpts = (sel) => ['fortios', 'panos'].map(v =>
            `<option value="${v}" ${v === sel ? 'selected' : ''}>${v === 'fortios' ? 'FortiGate (FortiOS)' : 'Palo Alto (PAN-OS)'}</option>`).join('');
        return `<div style="border:1px solid var(--border); border-radius:0; background:var(--surface-2); padding:16px;">
            <div style="font-weight:600; margin-bottom:12px;"><i class="fa-solid fa-right-left" style="color:var(--primary); margin-right:8px;"></i>${escapeHtml(L.caConvertTitle)}</div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:10px;">
                <select id="caConvDevice" style="padding:6px 12px; border-radius:0; border:1px solid var(--border); background:var(--surface-3); color:var(--text); font-size:13px; min-width:240px;">
                    ${caDeviceOptions(L, 'caConvDevicePick')}
                </select>
                <label style="font-size:12px; color:var(--text-muted);">${escapeHtml(L.caConvSource)}</label>
                <select id="caConvSource" style="padding:6px 10px; border-radius:0; border:1px solid var(--border); background:var(--surface-3); color:var(--text); font-size:13px;">${vendorOpts('fortios')}</select>
                <label style="font-size:12px; color:var(--text-muted);">${escapeHtml(L.caConvTarget)}</label>
                <select id="caConvTarget" style="padding:6px 10px; border-radius:0; border:1px solid var(--border); background:var(--surface-3); color:var(--text); font-size:13px;">${vendorOpts('panos')}</select>
                <button class="btn btn-primary btn-small" style="width:auto; margin:0;" data-action="ca-convert-preview"><i class="fa-solid fa-eye"></i> ${escapeHtml(L.caConvPreviewBtn)}</button>
            </div>
            <textarea id="caConvText" rows="8" placeholder="${escapeHtml(L.caConvTextPh)}" style="width:100%; font-family:var(--font-code); font-size:12px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); color:var(--text); padding:10px; resize:vertical;"></textarea>
            <div id="caConvResult" style="margin-top:12px;"></div>
        </div>`;
    }

    function caConvPickDevice() {
        // Selezione device: usa la conversione con {ip} per farsi restituire
        // anche il testo sorgente (source_text) e riempire la textarea.
        const sel = document.getElementById('caConvDevice');
        if (!sel || !sel.value) return;
        const dev = (caData || []).find(d => d.ip === sel.value);
        const srcSel = document.getElementById('caConvSource');
        const tgtSel = document.getElementById('caConvTarget');
        if (dev && srcSel && tgtSel) {
            const src = dev.config_type === 'panos' ? 'panos' : 'fortios';
            srcSel.value = src;
            tgtSel.value = src === 'fortios' ? 'panos' : 'fortios';
        }
        caConvertPreview(true);
    }

    async function caConvertPreview(useIp) {
        const L = i18n[currentLang];
        const out = document.getElementById('caConvResult');
        const ta = document.getElementById('caConvText');
        const devSel = document.getElementById('caConvDevice');
        if (!out || !ta) return;
        const text = ta.value.trim();
        const body = { source: document.getElementById('caConvSource').value,
                       target: document.getElementById('caConvTarget').value };
        if (useIp === true || (!text && devSel && devSel.value)) body.ip = devSel.value;
        else body.text = text;
        if (!body.ip && !body.text) return;
        out.innerHTML = `<div style="color:var(--text-muted); font-size:13px;"><i class="fa-solid fa-circle-notch fa-spin"></i></div>`;
        try {
            const res = await apiFetch('/api/config-analyzer/convert', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            const d = res ? await res.json() : null;
            if (!res || !res.ok) throw new Error((d && d.detail) || 'HTTP error');
            if (d.source_text) ta.value = d.source_text;
            caConvLastPreview = d.preview_text || '';
            const rows = (d.mapped || []).map(m => `<tr>
                <td style="white-space:pre-wrap; font-family:var(--font-code); font-size:11px; vertical-align:top;">${escapeHtml(m.source)}</td>
                <td style="white-space:pre-wrap; font-family:var(--font-code); font-size:11px; vertical-align:top;">${escapeHtml(m.target)}</td>
                <td style="font-size:11px; color:var(--text-muted); vertical-align:top;">${escapeHtml(m.note || '')}</td></tr>`).join('');
            const unmapped = (d.unmapped || []);
            out.innerHTML = `
                <div style="font-weight:600; font-size:13px; margin:8px 0;">${escapeHtml(L.caConvMapped)} (${(d.mapped || []).length})</div>
                <div style="max-height:320px; overflow:auto; border:1px solid var(--border); border-radius:0;">
                <table class="data-table" style="width:100%;"><thead><tr>
                    <th>${escapeHtml(L.thCaConvSource)}</th><th>${escapeHtml(L.thCaConvTarget)}</th><th>${escapeHtml(L.thCaConvNote)}</th>
                </tr></thead><tbody>${rows || `<tr><td colspan="3" style="color:var(--text-muted); font-size:12px;">—</td></tr>`}</tbody></table></div>
                <details style="margin-top:10px;">
                    <summary style="cursor:pointer; font-weight:600; font-size:13px;">${escapeHtml(L.caConvUnmapped)} (${unmapped.length})</summary>
                    <pre style="white-space:pre-wrap; font-size:11px; background:var(--surface-3); border:1px solid var(--border); border-radius:0; padding:10px; margin-top:8px; max-height:240px; overflow:auto;">${escapeHtml(unmapped.join('\n\n'))}</pre>
                </details>
                <div style="display:flex; align-items:center; gap:10px; margin-top:12px;">
                    <div style="font-weight:600; font-size:13px;">Preview</div>
                    <button class="btn btn-secondary btn-small" style="width:auto; margin:0;" data-action="ca-conv-download"><i class="fa-solid fa-download"></i> ${escapeHtml(L.caConvDownload)}</button>
                </div>
                <pre style="white-space:pre-wrap; font-size:11px; background:var(--surface-3); border:1px solid var(--border); border-radius:0; padding:10px; margin-top:8px; max-height:320px; overflow:auto;">${escapeHtml(caConvLastPreview)}</pre>`;
        } catch (e) {
            out.innerHTML = `<div style="color:var(--danger); font-size:13px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(e.message || 'Error')}</div>`;
        }
    }

    function caConvDownload() {
        if (!caConvLastPreview) return;
        const tgt = document.getElementById('caConvTarget');
        const blob = new Blob([caConvLastPreview], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `converted-${tgt ? tgt.value : 'config'}.txt`;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 100);
    }

    // Le mappe route (vis.js) si creano solo quando l'accordion del device viene
    // aperto e vengono distrutte alla chiusura, per evitare leak di canvas.
    function caOnToggle(detailsEl, idx) {
        if (caView !== 'routing') return;
        const dev = caList[idx];
        if (!dev) return;
        if (detailsEl.open) {
            caBuildRouteMap(dev, idx);
        } else if (caNetworks[idx]) {
            caNetworks[idx].destroy();
            delete caNetworks[idx];
        }
    }

    function caRenderVtpTag(dev, L) {
        const vtp = dev.vtp || {};
        const mode = (vtp.mode || '').trim();
        if (!mode) return '';
        const modeLower = mode.toLowerCase();
        const color = modeLower === 'server' ? 'var(--success)'
                    : modeLower === 'client' ? 'var(--primary)'
                    : 'var(--text-muted)';
        const label = `${escapeHtml(L.lblCaVtp)}: ${escapeHtml(mode.toUpperCase())}${vtp.domain ? ` &middot; ${escapeHtml(vtp.domain)}` : ''}`;
        return `<span class="badge" style="font-size:10px; color:${color}; border:1px solid ${color}; margin-bottom:8px; display:inline-block;">${label}</span>`;
    }

    function caRenderVlans(dev, L, en) {
        const vlans = dev.vlans || [];
        const vtpTag = caRenderVtpTag(dev, L);
        const vtpHtml = vtpTag ? `<div>${vtpTag}</div>` : '';
        if (!vlans.length) return `${vtpHtml}<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">—</div>`;
        const rows = vlans.map(v => {
            const svi = v.svi
                ? `${escapeHtml(v.svi.ip || '—')}${v.svi.shutdown ? ` <span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">${escapeHtml(L.lblCaShutdown)}</span>` : ''}`
                : '—';
            const access = v.access_ifaces || [];
            const trunk = v.trunk_ifaces || [];
            const accessCell = access.length
                ? `<details><summary style="cursor:pointer; color:var(--text);">${access.length}</summary><div style="font-family:var(--font-code); font-size:11px; color:var(--text-muted); margin-top:4px;">${access.map(escapeHtml).join(', ')}</div></details>`
                : '0';
            const trunkCell = trunk.length ? String(trunk.length) : '0';
            return `<tr><td>${escapeHtml(v.id)}</td><td>${escapeHtml(v.name || '—')}</td><td>${svi}</td><td>${accessCell}</td><td>${trunkCell}</td></tr>`;
        }).join('');
        return `${vtpHtml}<div class="table-container"><table><thead><tr>
            <th>${L.thCaVlanId}</th><th>${L.thCaVlanName}</th><th>${L.thCaSvi}</th><th>${L.thCaAccessPorts}</th><th>${L.thCaTrunkPorts}</th>
            </tr></thead><tbody>${rows}</tbody></table></div>`;
    }

    // Cambia modalità (elenco piatto / raggruppato per next-hop) senza ricostruire
    // l'intero accordion (per non toccare la mappa vis.js già aperta).
    function caSwitchRouteGroupMode(mode, idx) {
        caRouteGroupMode = mode;
        renderCaResults();
        const detailsEl = document.querySelector(`details[data-ca-idx="${idx}"]`);
        if (detailsEl) {
            detailsEl.open = true;
            caOnToggle(detailsEl, idx);
        }
    }

    // Bottone icona che mostra la/le riga/righe raw di config da cui deriva
    // la route (data-* per evitare problemi di escaping in onclick inline).
    function caRawRouteButton(r, L) {
        const lines = (r && r.raw_lines) || [];
        if (!lines.length) return '';
        const encoded = btoa(unescape(encodeURIComponent(JSON.stringify(lines))));
        return `<button type="button" class="ca-pill" title="${escapeHtml(L.lblCaShowRawRoute)}" data-i18n-title="lblCaShowRawRoute"
            data-raw="${encoded}" data-action="ca-show-raw-route" style="padding:2px 8px;">
            <i class="fa-solid fa-code"></i>
        </button>`;
    }

    function caShowRawRoute(btn) {
        let lines = [];
        try { lines = JSON.parse(decodeURIComponent(escape(atob(btn.dataset.raw)))); } catch (e) { lines = []; }
        document.getElementById('caRawRouteContent').textContent = lines.join('\n');
        document.getElementById('caRawRouteModal').style.display = 'flex';
    }

    function caCloseRawRouteModal() {
        document.getElementById('caRawRouteModal').style.display = 'none';
    }

    function caRenderRouting(dev, L, en, idx) {
        const routing = dev.routing || {};
        const statics = routing.static || [];
        const protocols = routing.protocols || [];
        const vrfs = routing.vrfs || [];
        const staticRows = statics.length ? statics.map(r => `<tr>
            <td style="font-family:var(--font-code);">${escapeHtml(r.prefix)}</td>
            <td style="font-family:var(--font-code);">${escapeHtml(r.next_hop || '—')}</td>
            <td>${escapeHtml(r.ad != null ? String(r.ad) : '—')}</td>
            <td>${escapeHtml(r.vrf || '—')}</td>
            <td>${escapeHtml(r.name || '—')}</td>
            <td>${caRawRouteButton(r, L)}</td>
            </tr>`).join('') : '';
        const staticTable = staticRows
            ? `<div class="table-container"><table><thead><tr><th>${L.lblCaPrefix}</th><th>${L.lblCaNextHop}</th><th>${L.lblCaAd}</th><th>${L.lblCaVrf}</th><th>${L.lblCaName}</th><th></th></tr></thead><tbody>${staticRows}</tbody></table></div>`
            : `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">—</div>`;
        const groups = {};
        statics.forEach(r => {
            const hop = r.next_hop || '—';
            if (!groups[hop]) groups[hop] = { hop, hasDefault: false, rows: [] };
            groups[hop].rows.push(r);
            if ((r.prefix || '').indexOf('0.0.0.0/0') === 0) groups[hop].hasDefault = true;
        });
        const groupKeys = Object.keys(groups).sort();
        const groupedHtml = groupKeys.length ? groupKeys.map(hop => {
            const g = groups[hop];
            const rows = g.rows.map(r => `<tr>
                <td style="font-family:var(--font-code);">${escapeHtml(r.prefix)}</td>
                <td>${escapeHtml(r.ad != null ? String(r.ad) : '—')}</td>
                <td>${escapeHtml(r.vrf || '—')}</td>
                <td>${escapeHtml(r.name || '—')}</td>
                <td>${caRawRouteButton(r, L)}</td>
                </tr>`).join('');
            const defaultBadge = g.hasDefault ? ` <span class="badge" style="font-size:10px; color:var(--warning); border:1px solid var(--warning);">${escapeHtml(L.lblCaDefaultRoute)}</span>` : '';
            return `<details style="border:1px solid var(--border); border-radius:0; margin-bottom:8px; background:var(--surface);">
                <summary style="cursor:pointer; padding:8px 10px; font-size:12px; font-weight:700; display:flex; align-items:center; gap:8px;">
                    <span style="font-family:var(--font-code);">${escapeHtml(hop)}</span>
                    <span class="badge" style="font-size:10px;">${g.rows.length}</span>
                    ${defaultBadge}
                </summary>
                <div class="table-container" style="border-top:1px solid var(--border);"><table><thead><tr>
                    <th>${L.lblCaPrefix}</th><th>${L.lblCaAd}</th><th>${L.lblCaVrf}</th><th>${L.lblCaName}</th><th></th>
                    </tr></thead><tbody>${rows}</tbody></table></div>
            </details>`;
        }).join('') : `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">—</div>`;
        const routeToggle = `<div style="display:flex; gap:6px; margin-bottom:8px;">
            <button type="button" class="ca-pill ${caRouteGroupMode === 'flat' ? 'active' : ''}" data-action="ca-switch-route-group" data-mode="flat" data-idx="${idx}">${escapeHtml(L.lblCaRouteFlat)}</button>
            <button type="button" class="ca-pill ${caRouteGroupMode === 'byhop' ? 'active' : ''}" data-action="ca-switch-route-group" data-mode="byhop" data-idx="${idx}">${escapeHtml(L.lblCaRouteByHop)}</button>
        </div>`;
        const staticSection = `${routeToggle}${caRouteGroupMode === 'byhop' ? groupedHtml : staticTable}`;
        const protoCards = protocols.length ? protocols.map(p => `
            <details style="border:1px solid var(--border); border-radius:0; margin-top:8px; background:var(--surface);">
                <summary style="cursor:pointer; padding:8px 10px; font-size:12px; font-weight:700;">${escapeHtml(p.proto)}${p.id ? ' ' + escapeHtml(p.id) : ''}</summary>
                <div style="padding:8px 10px; border-top:1px solid var(--border);">
                    ${(p.details || []).length ? `<pre style="font-family:var(--font-code); font-size:11px; background:var(--surface); margin:0 0 6px; white-space:pre-wrap;">${escapeHtml((p.details || []).join('\\n'))}</pre>` : ''}
                    ${p.raw ? `<details><summary style="cursor:pointer; font-size:11px; color:var(--text-muted);">raw</summary><pre style="font-family:var(--font-code); font-size:11px; background:var(--surface); margin-top:4px; white-space:pre-wrap;">${escapeHtml(p.raw)}</pre></details>` : ''}
                </div>
            </details>`).join('') : '';
        const vrfChips = vrfs.length ? `<div style="margin-top:8px;">${vrfs.map(v => `<span class="ca-chip">${escapeHtml(v.name)}${v.rd ? ' · ' + escapeHtml(v.rd) : ''}</span>`).join('')}</div>` : '';
        const mapId = `caRouteMap_${idx}`;
        return `${staticSection}
            ${protocols.length ? `<h4 style="font-size:12px; margin:12px 0 4px; color:var(--text-muted);">${L.lblCaProtocols}</h4>${protoCards}` : ''}
            ${vrfs.length ? `<h4 style="font-size:12px; margin:12px 0 4px; color:var(--text-muted);">${L.lblCaVrfs}</h4>${vrfChips}` : ''}
            <h4 style="font-size:12px; margin:12px 0 4px; color:var(--text-muted);">${L.lblCaRouteMap}</h4>
            <div id="${mapId}" class="ca-route-map"></div>`;
    }

    // Mappa minimale: nodo centrale = device, un nodo per next-hop distinto,
    // archi etichettati col numero di prefissi che passano per quel next-hop.
    // La rotta di default (0.0.0.0/0) viene evidenziata in var(--warning).
    function caBuildRouteMap(dev, idx) {
        const mapId = `caRouteMap_${idx}`;
        const container = document.getElementById(mapId);
        if (!container || typeof vis === 'undefined') return;
        const statics = (dev.routing && dev.routing.static) || [];
        const hostname = dev.hostname || dev.ip;
        // Nodi e testo seguono la resa attiva: in chiara l'etichetta e' inchiostro
        // su targa, in scura e' chiara su ardesia. vis.js vuole colori veri.
        const nodeInk = cssVar('--text', '#e8ebe6');
        const nodeFont = { color: nodeInk, size: 13, face: 'Saira Condensed, sans-serif' };
        const hopFont = { color: nodeInk, size: 12, face: 'Saira Condensed, sans-serif' };
        // Senza un 'highlight' esplicito vis.js usa il proprio: sfondo #D2E5FF,
        // quasi bianco, e in resa scura l'etichetta chiara ci sparisce sopra. Il
        // selezionato tiene quindi una superficie del sistema — e' li' che sta il
        // contrasto col testo — e si distingue con l'anello di selezione.
        const centerColor = {
            background: cssVar('--surface-3', '#2a333a'), border: nodeInk,
            highlight: { background: cssVar('--surface-3', '#2a333a'), border: nodeInk }
        };
        const hopColor = {
            background: cssVar('--surface-2', '#181e23'), border: cssVar('--border-strong', '#46535c'),
            highlight: { background: cssVar('--surface-2', '#181e23'), border: nodeInk }
        };
        /** @type {any[]} */ // vis.js nodes: shape differs between center and hop
        const nodes = [{
            id: 'center', label: hostname, shape: 'box',
            color: centerColor,
            font: nodeFont, borderWidth: 2, borderWidthSelected: 4, margin: 8
        }];
        const edges = [];
        const hopCounts = {};
        const hopHasDefault = {};
        statics.forEach(r => {
            const hop = r.next_hop || '—';
            hopCounts[hop] = (hopCounts[hop] || 0) + 1;
            if ((r.prefix || '').indexOf('0.0.0.0/0') === 0) hopHasDefault[hop] = true;
        });
        Object.keys(hopCounts).forEach(hop => {
            const nid = 'hop_' + hop;
            nodes.push({
                id: nid, label: hop, shape: 'ellipse',
                color: hopColor,
                font: hopFont, borderWidth: 1.5, borderWidthSelected: 3
            });
            edges.push({
                from: 'center', to: nid,
                label: `${hopCounts[hop]} ${i18n[currentLang].lblCaRouteMapEdge}`,
                // Anche l'arco selezionato ha un default vis.js fuori palette
                // (#2B7CE9): si tiene la tinta dell'arco, schiarita.
                color: hopHasDefault[hop]
                    ? { color: cssVar('--lamp-warn', '#e0a03c'),
                        highlight: cssVar('--lamp-warn-ink', '#e8b055') }
                    : { color: cssVar('--cond-trace', '#7b3fb5'),
                        highlight: cssVar('--text', '#e8ebe6') },
                width: hopHasDefault[hop] ? 3 : 2,
                font: { color: nodeInk, size: 12, strokeWidth: 0, background: cssVar('--surface-2', '#181e23') }
            });
        });
        if (caNetworks[idx]) { try { caNetworks[idx].destroy(); } catch (e) {} }
        const network = new vis.Network(container, { nodes, edges }, {
            physics: { stabilization: { iterations: 100 } },
            interaction: { dragView: true, zoomView: true },
            edges: { font: { color: nodeInk, size: 12, strokeWidth: 0, background: cssVar('--surface-2', '#181e23') } }
        });
        let frozen = false;
        const freeze = () => { if (!frozen) { frozen = true; network.setOptions({ physics: false }); } };
        network.once('stabilizationIterationsDone', freeze);
        network.once('afterDrawing', () => setTimeout(freeze, 3000));
        caNetworks[idx] = network;
    }

    function caRenderAcls(dev, L, en) {
        const acls = dev.acls || [];
        if (!acls.length) return `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">—</div>`;
        const refs = (dev.validation && dev.validation.route_acl_refs) || [];
        const referencedNames = new Set(refs.map(r => r.acl));
        return acls.map(acl => {
            const applied = (acl.applied || []).map(a => `<span class="ca-chip">${escapeHtml([a.target, a.direction].filter(Boolean).join(' '))}${a.where ? ' · ' + escapeHtml(a.where) : ''}</span>`).join('');
            const note = referencedNames.has(acl.name) ? `<span class="ca-chip" style="color:var(--primary); border-color:var(--primary);">${escapeHtml(L.lblCaReferencedByRouting)}</span>` : '';
            const rows = (acl.entries || []).map(e => {
                const act = (e.action || '').toLowerCase();
                const color = act === 'permit' ? 'var(--success)' : act === 'deny' ? 'var(--danger)' : 'var(--text-muted)';
                return `<tr><td>${escapeHtml(e.seq != null ? String(e.seq) : '—')}</td><td style="color:${color}; font-weight:700;">${escapeHtml(e.action || '—')}</td><td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(e.text || '—')}</td></tr>`;
            }).join('');
            return `<details style="border:1px solid var(--border); border-radius:0; margin-bottom:8px; background:var(--surface);">
                <summary style="cursor:pointer; padding:10px 12px; display:flex; align-items:center; gap:8px; flex-wrap:wrap; list-style:none;">
                    <strong>${escapeHtml(acl.name)}</strong>
                    <span class="badge" style="font-size:10px;">${escapeHtml(acl.kind || '—')}</span>
                    ${applied}${note}
                </summary>
                <div style="padding:0 12px 12px;">
                    <div class="table-container"><table><thead><tr><th>${L.thCaAclSeq}</th><th>${L.thCaAclAction}</th><th>${L.thCaAclRule}</th></tr></thead><tbody>${rows}</tbody></table></div>
                </div>
            </details>`;
        }).join('');
    }

    function caRenderIfaces(dev, L, en) {
        const ifaces = dev.interfaces || [];
        if (!ifaces.length) return `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">—</div>`;
        const rows = ifaces.map((i, ii) => {
            const mode = i.mode || (i.ip ? 'routed' : '—');
            const vlanCol = i.mode === 'trunk' ? (i.trunk_allowed || '—') : (i.access_vlan != null ? String(i.access_vlan) : '—');
            const aclChips = [i.acl_in ? `<span class="ca-chip">in: ${escapeHtml(i.acl_in)}</span>` : '', i.acl_out ? `<span class="ca-chip">out: ${escapeHtml(i.acl_out)}</span>` : ''].join('');
            const state = i.shutdown
                ? `<span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">shutdown</span>`
                : `<span class="ca-chip" style="color:var(--success); border-color:var(--success);">${escapeHtml(L.lblCaActive)}</span>`;
            const rowId = `caIfaceRaw_${dev.ip || ''}_${ii}`.replace(/[^a-zA-Z0-9_]/g, '_');
            return `<tr style="cursor:pointer;" data-ca-iface="${escapeHtml(expandIface(i.name).toLowerCase())}" data-action="ca-toggle-iface-raw" data-target="${rowId}">
                    <td>${escapeHtml(i.name)}</td><td>${escapeHtml(i.description || '—')}</td><td><span class="badge" style="font-size:10px;">${escapeHtml(mode)}</span></td>
                    <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(String(vlanCol))}</td>
                    <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(i.ip || '—')}</td>
                    <td>${aclChips || '—'}</td><td>${state}</td>
                </tr>
                <tr id="${rowId}" style="display:none;"><td colspan="7"><pre style="font-family:var(--font-code); background:var(--surface); border-radius:0; padding:8px; margin:0; white-space:pre-wrap; font-size:11px;">${escapeHtml(i.raw || '—')}</pre></td></tr>`;
        }).join('');
        return `<div class="table-container"><table><thead><tr>
            <th>${L.thCaIface}</th><th>${L.thCaDesc}</th><th>${L.thCaMode}</th><th>${L.thCaVlanCol}</th><th>${L.thCaIp}</th><th>${L.thCaAclInOut}</th><th>${L.thCaState}</th>
            </tr></thead><tbody>${rows}</tbody></table></div>`;
    }

    function caToggleIfaceRaw(rowId) {
        const row = document.getElementById(rowId);
        if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
    }

    // Etichette it/en per le categorie di validazione multivendor (FortiOS / WLC).
    const caMvValLabels = {
        any_any_policies:        { it: 'Policy any-any',                    en: 'Any-any policies' },
        disabled_policies:       { it: 'Policy disabilitate',               en: 'Disabled policies' },
        unlogged_policies:       { it: 'Policy senza logging',              en: 'Policies without logging' },
        unused_addresses:        { it: 'Indirizzi non usati',               en: 'Unused addresses' },
        unused_addr_groups:      { it: 'Gruppi indirizzi non usati',        en: 'Unused address groups' },
        unused_services:         { it: 'Servizi non usati',                 en: 'Unused services' },
        insecure_mgmt_interfaces:{ it: 'Interfacce mgmt non sicure',        en: 'Insecure mgmt interfaces' },
        admins_without_trusthost:{ it: 'Admin senza trusthost',             en: 'Admins without trusthost' },
        logging_disabled:        { it: 'Logging disabilitato',              en: 'Logging disabled' },
        open_wlans:              { it: 'WLAN aperte (senza sicurezza)',     en: 'Open WLANs (no security)' },
        legacy_tkip_wlans:       { it: 'WLAN con TKIP legacy',              en: 'Legacy TKIP WLANs' },
        disabled_wlans:          { it: 'WLAN disabilitate',                 en: 'Disabled WLANs' },
        broadcast_ssid_off:      { it: 'Broadcast SSID disattivato',        en: 'Broadcast SSID off' },
        management_http:         { it: 'Management HTTP abilitato',         en: 'Management HTTP enabled' }
    };

    // Rende una voce di validazione (stringa o oggetto) in testo leggibile.
    function caMvValItemText(x) {
        if (x == null) return '—';
        if (typeof x !== 'object') return String(x);
        const nm = x.name || x.ssid || x.id || x.profile || '';
        const extra = Array.isArray(x.allowaccess) ? ` (${x.allowaccess.join(', ')})` : '';
        return nm ? `${nm}${extra}` : JSON.stringify(x);
    }

    // Pannello Validazione generico: array → chip warning, boolean true → chip danger.
    function caRenderMvValidationBody(dev, L, en) {
        const v = dev.validation || {};
        const sections = [];
        let total = 0;
        Object.keys(v).forEach(key => {
            const lbl = caMvValLabels[key] ? caMvValLabels[key][en ? 'en' : 'it'] : key;
            const val = v[key];
            if (Array.isArray(val) && val.length) {
                total += val.length;
                const chips = val.map(x => `<span class="ca-chip" style="color:var(--warning); border-color:var(--warning);">${escapeHtml(caMvValItemText(x))}</span>`).join('');
                sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--warning);">${escapeHtml(lbl)}</h4><div>${chips}</div>`);
            } else if (val === true) {
                total += 1;
                sections.push(`<div style="margin:10px 0 4px;"><span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">${escapeHtml(lbl)}</span></div>`);
            }
        });
        if (total === 0) {
            return { total: 0, body: `<div style="display:flex; align-items:center; gap:8px; padding:10px 12px; border-radius:0; background:var(--lamp-up-wash); border:1px solid var(--success); color:var(--success); font-size:12px;">
                <i class="fa-solid fa-circle-check"></i><span>${escapeHtml(L.msgCaNoIssues)}</span></div>` };
        }
        return { total, body: sections.join('') };
    }

    // Severity -> the lamp token for that state. Colour means state here, as
    // everywhere else in this interface; it is never decoration.
    const CA_DEFECT_LAMP = {
        high: { color: 'var(--danger)', wash: 'var(--lamp-fault-wash)', icon: 'fa-circle-xmark' },
        medium: { color: 'var(--warning)', wash: 'var(--lamp-warn-wash)', icon: 'fa-triangle-exclamation' },
        low: { color: 'var(--text-muted)', wash: 'var(--surface-2)', icon: 'fa-circle-info' },
        info: { color: 'var(--text-muted)', wash: 'var(--surface-2)', icon: 'fa-circle-info' },
    };

    function caDefectLine(f, L) {
        const p = f.params || {};
        const acl = f.acl_name || p.acl || '';
        const rule = f.rule_id || p.rule_id || '';
        switch (f.key) {
            case 'shadowed':
                return L.msgCaDefectShadowed
                    .replace('{rule}', rule).replace('{by}', p.shadowed_by || '?').replace('{acl}', acl);
            case 'unreachable':
                return L.msgCaDefectUnreachable
                    .replace('{rule}', rule).replace('{by}', p.blocked_by || '?').replace('{acl}', acl);
            case 'any_any':
                return L.msgCaDefectAnyAny.replace('{rule}', rule).replace('{acl}', acl);
            case 'unresolved_object':
                return L.msgCaDefectUnresolved
                    .replace('{rule}', rule).replace('{acl}', acl)
                    .replace('{objects}', (p.objects || []).join(', '));
            case 'route_to_nowhere':
                return L.msgCaDefectRouteNowhere
                    .replace('{prefix}', p.prefix || '?').replace('{next_hop}', p.next_hop || '?');
            default:
                return `${f.key} - ${acl} ${rule}`.trim();
        }
    }

    function caPolicyDefectsSection(defects, L) {
        const order = { high: 0, medium: 1, low: 2, info: 3 };
        const sorted = defects.slice().sort(
            (a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
        const rows = sorted.map(f => {
            const lamp = CA_DEFECT_LAMP[f.severity] || CA_DEFECT_LAMP.info;
            return `<div style="display:flex; align-items:flex-start; gap:8px; padding:7px 10px; background:${lamp.wash}; border-left:1px solid ${lamp.color}; margin-bottom:4px; font-size:12px;">
                <i class="fa-solid ${lamp.icon}" style="color:${lamp.color}; margin-top:2px;"></i>
                <span>${escapeHtml(caDefectLine(f, L))}</span>
            </div>`;
        }).join('');
        return `<h4 style="font-size:12px; margin:10px 0 4px; color:var(--danger);">${L.titleCaPolicyDefects}</h4><div>${rows}</div>`;
    }

    function caRenderValidation(dev, L, en) {
        if (dev.config_type === 'fortios' || dev.config_type === 'wlc-aireos') {
            const mv = caRenderMvValidationBody(dev, L, en);
            const tenantMv = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
            return `<details class="mac-switch" data-ca-ip="${escapeHtml(dev.ip)}" style="border:1px solid var(--border); border-radius:0; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" open>
                <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                    <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                    <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                    <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                    ${tenantMv}
                    <span style="margin-left:auto; color:var(--text-muted); font-size:12px;">${mv.total}</span>
                    ${caTriageButton(dev, L)}
                </summary>
                <div style="padding:0 14px 14px;">${mv.body}</div>
            </details>`;
        }
        const v = dev.validation || {};
        const unusedAcls = v.unused_acls || [];
        const missingAcls = v.missing_acls || [];
        const unusedVlans = v.unused_vlans || [];
        const undefinedVlans = v.undefined_vlans || [];
        const routeAclRefs = v.route_acl_refs || [];
        const policyDefects = v.policy_findings || [];
        const total = unusedAcls.length + missingAcls.length + unusedVlans.length + undefinedVlans.length + routeAclRefs.length + policyDefects.length;
        const tenant = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
        const chips = arr => arr.map(x => `<span class="ca-chip" style="color:var(--warning); border-color:var(--warning);">${escapeHtml(x)}</span>`).join('');
        let body;
        if (total === 0) {
            body = `<div style="display:flex; align-items:center; gap:8px; padding:10px 12px; border-radius:0; background:var(--lamp-up-wash); border:1px solid var(--success); color:var(--success); font-size:12px;">
                <i class="fa-solid fa-circle-check"></i><span>${escapeHtml(L.msgCaNoIssues)}</span></div>`;
        } else {
            const sections = [];
            // First, not last: a rule that can never fire is the worst defect
            // in this list. An unused ACL does nothing and was never applied;
            // a shadowed ACE is applied, states an intent, and silently does
            // nothing anyway.
            if (policyDefects.length) sections.push(caPolicyDefectsSection(policyDefects, L));
            if (unusedAcls.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--warning);">${L.titleCaUnusedAcls}</h4><div>${chips(unusedAcls)}</div>`);
            if (missingAcls.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--danger);">${L.titleCaMissingAcls}</h4><div>${missingAcls.map(m => `<span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">${escapeHtml(m.name)} (${L.lblCaReferencedIn}: ${escapeHtml(m.referenced_in || '—')})</span>`).join('')}</div>`);
            if (unusedVlans.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--warning);">${L.titleCaUnusedVlans}</h4><div>${chips(unusedVlans)}</div>`);
            if (undefinedVlans.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--warning);">${L.titleCaUndefinedVlans}</h4><div>${undefinedVlans.map(u => `<span class="ca-chip" style="color:var(--warning); border-color:var(--warning);">${escapeHtml(u.vlan)} (${L.lblCaReferencedIn}: ${escapeHtml(u.referenced_in || '—')})</span>`).join('')}</div>`);
            if (routeAclRefs.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--primary);">${L.titleCaRouteAclRefs}</h4><div>${routeAclRefs.map(r => `<span class="ca-chip">${escapeHtml(r.context)} → ${escapeHtml(r.acl)}</span>`).join('')}</div>`);
            body = sections.join('');
        }
        return `<details class="mac-switch" data-ca-ip="${escapeHtml(dev.ip)}" style="border:1px solid var(--border); border-radius:0; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" open>
            <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                ${tenant}
                <span style="margin-left:auto; color:var(--text-muted); font-size:12px;">${total}</span>
                ${caTriageButton(dev, L)}
            </summary>
            <div style="padding:0 14px 14px;">${body}</div>
        </details>`;
    }

    // ===== Config Analyzer: rendering multivendor (FortiOS / Cisco WLC) =====

    function caMvSectionTitle(txt) {
        return `<h4 style="font-size:12px; margin:12px 0 4px; color:var(--text-muted);">${txt}</h4>`;
    }

    function caMvEmpty() {
        return `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">—</div>`;
    }

    // Lista collassabile di oggetti (indirizzi/servizi/gruppi/VIP FortiOS).
    function caMvObjList(label, arr) {
        const items = arr || [];
        if (!items.length) return `<span class="ca-chip">${escapeHtml(label)}: 0</span>`;
        const names = items.map(x => escapeHtml(caMvValItemText(x))).join(', ');
        return `<details style="display:inline-block; margin-right:8px; vertical-align:top;">
            <summary style="cursor:pointer; font-size:12px;"><span class="ca-chip">${escapeHtml(label)}: ${items.length}</span></summary>
            <div style="font-family:var(--font-code); font-size:11px; color:var(--text-muted); margin:4px 0 8px; max-width:520px;">${names}</div>
        </details>`;
    }

    function caRenderFortios(dev, L, en) {
        // Interfacce
        const ifaces = dev.interfaces || [];
        const ifaceRows = ifaces.map(i => {
            const st = (i.status || '').toLowerCase();
            const state = st === 'down' || st === 'disable'
                ? `<span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">${escapeHtml(i.status)}</span>`
                : `<span class="ca-chip" style="color:var(--success); border-color:var(--success);">${escapeHtml(i.status || L.lblCaActive)}</span>`;
            return `<tr>
                <td>${escapeHtml(i.name)}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(i.ip || '—')}</td>
                <td>${escapeHtml(i.vlanid != null ? String(i.vlanid) : '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${caMultiCell(i.allowaccess || [])}</td>
                <td>${state}</td>
            </tr>`;
        }).join('');
        const ifaceTable = ifaces.length
            ? `<div class="table-container"><table><thead><tr>
                <th>${L.thCaIface}</th><th>${L.thCaIp}</th><th>${L.thCaVlanCol}</th><th>${L.thCaFgAllowaccess}</th><th>${L.thCaState}</th>
                </tr></thead><tbody>${ifaceRows}</tbody></table></div>`
            : caMvEmpty();

        // Policy firewall
        const policies = dev.policies || [];
        const polRows = policies.map(p => {
            const act = (p.action || '').toLowerCase();
            const actColor = act === 'accept' ? 'var(--success)' : act === 'deny' ? 'var(--danger)' : 'var(--text-muted)';
            // Stessa resa del pill Firewall: la riga disattivata si attenua e
            // prende una barra neutra a sinistra, senza il rosso che in questa
            // stessa tabella significa gia' azione "deny".
            return `<tr${caRowIsDisabled(p) ? ' class="ca-row-off"' : ''}>
                <td>${escapeHtml(p.id != null ? String(p.id) : '—')}</td>
                <td>${escapeHtml(p.name || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${caMultiCell(p.srcintf || [])}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${caMultiCell(p.dstintf || [])}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${caMultiCell(p.srcaddr || [])}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${caMultiCell(p.dstaddr || [])}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${caMultiCell(p.service || [])}</td>
                <td style="color:${actColor}; font-weight:700;">${escapeHtml(p.action || '—')}</td>
                <td>${escapeHtml(p.nat || '—')}</td>
                <td>${escapeHtml(p.logtraffic || '—')}</td>
            </tr>`;
        }).join('');
        const polTable = policies.length
            ? `<div class="table-container"><table><thead><tr>
                <th>ID</th><th>${L.lblCaName}</th><th>${L.thCaFgSrcIntf}</th><th>${L.thCaFgDstIntf}</th><th>${L.thCaFgSrcAddr}</th><th>${L.thCaFgDstAddr}</th><th>${L.thCaFgService}</th><th>${L.thCaFgAction}</th><th>NAT</th><th>Log</th>
                </tr></thead><tbody>${polRows}</tbody></table></div>`
            : caMvEmpty();

        // Oggetti
        const objects = `<div>
            ${caMvObjList(L.lblCaFgAddresses, dev.addresses)}
            ${caMvObjList(L.lblCaFgAddrGroups, dev.addr_groups)}
            ${caMvObjList(L.lblCaFgServices, dev.services)}
            ${caMvObjList(L.lblCaFgSvcGroups, dev.service_groups)}
            ${caMvObjList(L.lblCaFgVips, dev.vips)}
        </div>`;

        // Routing statico + VPN
        const statics = (dev.routing && dev.routing.static) || [];
        const routeRows = statics.map(r => `<tr>
            <td>${escapeHtml(r.seq != null ? String(r.seq) : '—')}</td>
            <td style="font-family:var(--font-code);">${escapeHtml(r.prefix || '—')}</td>
            <td style="font-family:var(--font-code);">${escapeHtml(r.next_hop || '—')}</td>
            <td>${escapeHtml(r.device || '—')}</td>
            <td>${escapeHtml(r.distance != null ? String(r.distance) : '—')}</td>
            </tr>`).join('');
        const routeTable = statics.length
            ? `<div class="table-container"><table><thead><tr>
                <th>${L.thCaAclSeq}</th><th>${L.lblCaPrefix}</th><th>${L.lblCaNextHop}</th><th>${L.thCaFgDevice}</th><th>${L.thCaFgDistance}</th>
                </tr></thead><tbody>${routeRows}</tbody></table></div>`
            : caMvEmpty();
        const vpn = dev.vpn || {};
        const p1 = vpn.phase1 || [];
        const p2 = vpn.phase2 || [];
        const vpnChips = list => list.map(x => `<span class="ca-chip">${escapeHtml(caMvValItemText(x))}</span>`).join('');
        const vpnHtml = (p1.length || p2.length)
            ? `${p1.length ? `${caMvSectionTitle(L.titleCaVpnP1)}<div>${vpnChips(p1)}</div>` : ''}
               ${p2.length ? `${caMvSectionTitle(L.titleCaVpnP2)}<div>${vpnChips(p2)}</div>` : ''}`
            : '';

        const val = caRenderMvValidationBody(dev, L, en);

        return `${caMvSectionTitle(L.titleCaFgIfaces)}${ifaceTable}
            ${caMvSectionTitle(L.titleCaFgPolicies)}${polTable}
            ${caMvSectionTitle(L.titleCaFgObjects)}${objects}
            ${caMvSectionTitle(L.titleCaFgRouting)}${routeTable}${vpnHtml}
            ${caMvSectionTitle(L.titleCaValidation)}${val.body}`;
    }

    // ===== Config Analyzer: sub-tab Firewall (FortiGate) =====

    function caSwitchFwView(view) {
        caFwView = view;
        renderCaResults();
    }

    function caSwitchSrvView(view) {
        caSrvView = view;
        renderCaResults();
    }

    // Valori mostrati in chiaro prima di collassare il resto dietro un "+N".
    const CA_CELL_PREVIEW = 2;

    // Cella multi-valore: una policy puo' citare decine di oggetti indirizzo, e
    // stamparli tutti rende la colonna piu' larga dello schermo. L'elenco intero
    // resta nel DOM (ricerca del browser, copia-incolla), solo nascosto.
    function caMultiCell(values) {
        const all = values.map(v => escapeHtml(v));
        if (!all.length) return '—';
        // Nascondere un solo valore non fa guadagnare spazio: costa un clic e basta.
        if (all.length <= CA_CELL_PREVIEW + 1) return all.join(', ');
        const head = all.slice(0, CA_CELL_PREVIEW).join(', ');
        return `<span class="ca-cell-short">${head}<button type="button" class="ca-more" data-action="ca-toggle-cell">+${all.length - CA_CELL_PREVIEW}</button></span>`
             + `<span class="ca-cell-full" style="display:none;">${all.join(', ')}<button type="button" class="ca-more" data-action="ca-toggle-cell">&minus;</button></span>`;
    }

    function caToggleCell(btn) {
        const td = btn.closest('td');
        if (!td) return;
        const short = td.querySelector('.ca-cell-short');
        const full = td.querySelector('.ca-cell-full');
        if (!short || !full) return;
        const expanded = full.style.display !== 'none';
        short.style.display = expanded ? '' : 'none';
        full.style.display = expanded ? 'none' : '';
    }

    // Una regola disattivata è ancora scritta nella configurazione ma non filtra
    // niente: leggerla come attiva è il modo più facile di sbagliare una analisi.
    function caRowIsDisabled(r) {
        const status = String(r.status == null ? '' : r.status).toLowerCase();
        if (status === 'disable' || status === 'disabled' || status === 'off') return true;
        return r.disabled === true || String(r.disabled || '').toLowerCase() === 'yes';
    }

    // Renderer generico di una sezione firewall/server (envelope vendor-driven:
    // {id, label_key, columns, rows}).
    function caRenderFwSection(sec, L) {
        const cols = sec.columns || [];
        const rows = sec.rows || [];
        if (!rows.length) return caMvEmpty();
        const thead = cols.map(c => `<th>${escapeHtml(L[c.label_key] || c.label_key)}</th>`).join('');
        const trs = rows.map(r => {
            const tds = cols.map(c => {
                const v = r[c.key];
                let cell;
                if (Array.isArray(v)) {
                    // trusthost vuoto non è "nessuno": è "da qualunque IP".
                    cell = (!v.length && c.key === 'trusthost')
                        ? escapeHtml(L.lblCaTrusthostAny) : caMultiCell(v);
                } else if (c.key === 'trusthost' && (v === null || v === undefined || v === '')) {
                    cell = escapeHtml(L.lblCaTrusthostAny);
                } else {
                    cell = (v === null || v === undefined || v === '') ? '—' : escapeHtml(v);
                }
                return `<td style="font-family:var(--font-code); font-size:12px;">${cell}</td>`;
            }).join('');
            return `<tr${caRowIsDisabled(r) ? ' class="ca-row-off"' : ''}>${tds}</tr>`;
        }).join('');
        return `<div class="table-container"><table><thead><tr>${thead}</tr></thead><tbody>${trs}</tbody></table></div>`;
    }

    // Vista a sotto-pill guidata dall'envelope. Firewall e Server condividono
    // la stessa forma dei dati ({vendor, sections}), quindi anche il renderer:
    // cambia solo dove sta l'envelope sul device e quale variabile ricorda il
    // sotto-pill attivo.
    function caRenderEnvelopeView(devices, envelopeKey, activeId, switchFn,
                                  unsupportedMsg, L) {
        const sectionMap = {};
        devices.forEach(dev => {
            (((dev[envelopeKey] || {}).sections) || []).forEach(s => {
                if (!(s.id in sectionMap)) sectionMap[s.id] = s.label_key;
            });
        });
        const sectionIds = Object.keys(sectionMap);
        if (!sectionIds.length) {
            return { view: activeId, html: `<div style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.msgCaNoDevices)}</div>` };
        }
        if (!sectionIds.includes(activeId)) activeId = sectionIds[0];
        const subPills = sectionIds.map(id => {
            const lbl = L[sectionMap[id]] || sectionMap[id];
            return `<button class="ca-pill${activeId === id ? ' active' : ''}" data-action="ca-switch-envelope-section" data-fn="${escapeHtml(switchFn)}" data-id="${escapeHtml(id)}">${escapeHtml(lbl)}</button>`;
        }).join('');
        const subBar = `<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px;">${subPills}</div>`;
        // Riga di aiuto della sezione attiva. La chiave si ricava da quella
        // dell'etichetta (srv.sec.X -> srv.help.X): le sezioni che non hanno un
        // testo non mostrano niente, quindi l'envelope firewall resta invariato
        // finche' non gli si scrivono le sue.
        const helpText = L[(sectionMap[activeId] || '').replace('.sec.', '.help.')] || '';
        const helpBar = helpText
            ? `<div style="margin:-6px 0 14px; padding:9px 12px; border-left:2px solid var(--primary); background:var(--surface-2); border-radius:var(--radius); font-size:12px; line-height:1.5; color:var(--text-muted);">${escapeHtml(helpText)}</div>`
            : '';

        const openAll = devices.length === 1;
        const body = devices.map(dev => {
            const tenant = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
            const envelope = dev[envelopeKey] || {};
            const sections = envelope.sections || [];
            let inner;
            if (envelope.error) {
                // Un envelope vuoto per crash del parser non e' un apparato
                // pulito: dirlo "vendor non supportato" farebbe leggere
                // un'analisi fallita come "nessuna policy".
                inner = `<div style="font-size:12px; color:var(--danger); padding:8px 0;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(L.msgCaAnalyzeFailed)}</div>`;
            } else if (!sections.length) {
                inner = `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">${escapeHtml(unsupportedMsg)}</div>`;
            } else {
                const sec = sections.find(s => s.id === activeId);
                inner = sec ? caRenderFwSection(sec, L) : caMvEmpty();
            }
            return `<details class="mac-switch" data-ca-ip="${escapeHtml(dev.ip)}" style="border:1px solid var(--border); border-radius:0; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" ${openAll ? 'open' : ''}>
                <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                    <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                    <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                    <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                    ${tenant}
                    <span style="margin-left:auto;">${caTriageButton(dev, L)}</span>
                </summary>
                <div style="padding:0 14px 14px;">${inner}</div>
            </details>`;
        }).join('');
        return { view: activeId, html: subBar + helpBar + body };
    }

    function caRenderFirewallView(L, en) {
        const res = caRenderEnvelopeView((caData || []).filter(isFirewallDevice),
            'firewall', caFwView, 'caSwitchFwView', L.msgCaFwUnsupportedVendor, L);
        caFwView = res.view;
        return res.html;
    }

    function caRenderServerView(L, en) {
        const res = caRenderEnvelopeView((caData || []).filter(isServerDevice),
            'server', caSrvView, 'caSwitchSrvView', L.msgCaSrvNoBackup, L);
        caSrvView = res.view;
        return res.html;
    }

    function caRenderWlc(dev, L, en) {
        // WLAN
        const wlans = dev.wlans || [];
        const wlanRows = wlans.map(w => {
            const state = w.enabled
                ? `<span class="ca-chip" style="color:var(--success); border-color:var(--success);">${escapeHtml(L.lblCaActive)}</span>`
                : `<span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">disabled</span>`;
            const bcast = w.broadcast_ssid === false ? 'off' : 'on';
            return `<tr>
                <td>${escapeHtml(w.id != null ? String(w.id) : '—')}</td>
                <td>${escapeHtml(w.ssid || '—')}</td>
                <td>${escapeHtml(w.profile || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(w.security || '—')}${w.tkip ? ` <span class="ca-chip" style="color:var(--warning); border-color:var(--warning);">TKIP</span>` : ''}</td>
                <td>${state}</td>
                <td>${escapeHtml(w.interface || '—')}</td>
                <td>${escapeHtml(bcast)}</td>
            </tr>`;
        }).join('');
        const wlanTable = wlans.length
            ? `<div class="table-container"><table><thead><tr>
                <th>ID</th><th>${L.thCaSsid}</th><th>${L.thCaProfile}</th><th>${L.thCaSecurity}</th><th>${L.thCaState}</th><th>${L.thCaIface}</th><th>${L.thCaBroadcast}</th>
                </tr></thead><tbody>${wlanRows}</tbody></table></div>`
            : caMvEmpty();

        // Interfacce dinamiche
        const dyns = dev.dynamic_interfaces || [];
        const dynRows = dyns.map(d => `<tr>
            <td>${escapeHtml(d.name || '—')}</td>
            <td>${escapeHtml(d.vlan != null ? String(d.vlan) : '—')}</td>
            <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(d.ip || '—')}</td>
            </tr>`).join('');
        const dynTable = dyns.length
            ? `<div class="table-container"><table><thead><tr>
                <th>${L.lblCaName}</th><th>${L.thCaVlanCol}</th><th>${L.thCaIp}</th>
                </tr></thead><tbody>${dynRows}</tbody></table></div>`
            : caMvEmpty();

        // RADIUS + mobility group
        const radius = dev.radius_servers || [];
        const radiusChips = radius.length
            ? `<div>${radius.map(r => `<span class="ca-chip">${escapeHtml([r.kind, r.index != null ? '#' + r.index : '', r.ip + (r.port ? ':' + r.port : '')].filter(Boolean).join(' '))}</span>`).join('')}</div>`
            : caMvEmpty();
        const mobility = dev.mobility_group
            ? `<div><span class="ca-chip">${escapeHtml(L.lblCaMobility)}: ${escapeHtml(dev.mobility_group)}</span></div>`
            : '';

        const val = caRenderMvValidationBody(dev, L, en);

        // Fallback IOS-XE: riusa il rendering IOS esistente su ios_base.
        let iosHtml = '';
        if (dev.platform === 'iosxe' && dev.ios_base) {
            const iosDev = Object.assign({ ip: dev.ip }, dev.ios_base);
            iosHtml = `${caMvSectionTitle(L.thCaIface)}${caRenderIfaces(iosDev, L, en)}
                ${caMvSectionTitle('VLAN')}${caRenderVlans(iosDev, L, en)}`;
        }

        return `${caMvSectionTitle(L.titleCaWlans)}${wlanTable}
            ${caMvSectionTitle(L.titleCaDynIfaces)}${dynTable}
            ${caMvSectionTitle(L.titleCaRadius)}${radiusChips}${mobility}
            ${iosHtml}
            ${caMvSectionTitle(L.titleCaValidation)}${val.body}`;
    }

    // Delegated event listeners for Config Analyzer
    document.getElementById('caPills')?.addEventListener('click', (e) => {
        const pill = e.target.closest('.ca-pill[data-view]');
        if (pill && pill.dataset.view) {
            caSwitchView(pill.dataset.view);
        }
    });

    document.getElementById('caResults')?.addEventListener('change', (e) => {
        if (e.target.id === 'caConvDevice') {
            caConvPickDevice();
        }
    });

    document.getElementById('caResults')?.addEventListener('click', (e) => {
        const triageBtn = e.target.closest('[data-action="ca-triage"]');
        if (triageBtn && triageBtn.dataset.ip) {
            caTriageDevice(triageBtn.dataset.ip, triageBtn, e);
            return;
        }
        const switchViewCard = e.target.closest('[data-action="ca-switch-view"]');
        if (switchViewCard && switchViewCard.dataset.view) {
            caSwitchView(switchViewCard.dataset.view);
            return;
        }
        const convPrevBtn = e.target.closest('[data-action="ca-convert-preview"]');
        if (convPrevBtn) {
            caConvertPreview();
            return;
        }
        const convDlBtn = e.target.closest('[data-action="ca-conv-download"]');
        if (convDlBtn) {
            caConvDownload();
            return;
        }
        const rawRouteBtn = e.target.closest('[data-action="ca-show-raw-route"]');
        if (rawRouteBtn) {
            caShowRawRoute(rawRouteBtn);
            return;
        }
        const switchRouteGrpBtn = e.target.closest('[data-action="ca-switch-route-group"]');
        if (switchRouteGrpBtn && switchRouteGrpBtn.dataset.mode) {
            caSwitchRouteGroupMode(switchRouteGrpBtn.dataset.mode, Number(switchRouteGrpBtn.dataset.idx));
            return;
        }
        const toggleIfaceRow = e.target.closest('[data-action="ca-toggle-iface-raw"]');
        if (toggleIfaceRow && toggleIfaceRow.dataset.target) {
            caToggleIfaceRaw(toggleIfaceRow.dataset.target);
            return;
        }
        const toggleCellBtn = e.target.closest('[data-action="ca-toggle-cell"]');
        if (toggleCellBtn) {
            caToggleCell(toggleCellBtn);
            return;
        }
        const switchEnvPill = e.target.closest('[data-action="ca-switch-envelope-section"]');
        if (switchEnvPill && switchEnvPill.dataset.fn && switchEnvPill.dataset.id) {
            const fn = switchEnvPill.dataset.fn;
            if (fn === 'caSwitchFwView') caSwitchFwView(switchEnvPill.dataset.id);
            else if (fn === 'caSwitchSrvView') caSwitchSrvView(switchEnvPill.dataset.id);
            return;
        }
    });

    document.getElementById('caRawRouteModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'caRawRouteModal' || e.target.closest('#btnCaCloseRawRouteModal')) {
            caCloseRawRouteModal();
        }
    });

    document.getElementById('caSearch')?.addEventListener('input', () => {
        if (typeof caApplySearch === 'function') caApplySearch();
    });

    document.getElementById('configGroupSelect')?.addEventListener('change', () => {
        if (typeof loadConfigAnalyzer === 'function') loadConfigAnalyzer();
    });

    document.getElementById('btnCaRefresh')?.addEventListener('click', () => {
        if (typeof loadConfigAnalyzer === 'function') loadConfigAnalyzer(true);
    });


