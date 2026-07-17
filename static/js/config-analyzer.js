    // ===== Config Analyzer =====
    // Dati cache lato client: un solo fetch per tenant selezionato, i pill di
    // vista ri-renderizzano senza richiamare l'API (come richiesto).
    let caData = null;
    let caView = 'home';
    let caFwView = 'policy'; // sub-menu del pill "Firewall": policy | iface | nat | objects
    let caRouteGroupMode = 'flat'; // 'flat' | 'byhop' — ricordato per la sessione
    let caNetworks = {};   // ip -> vis.Network istanza mappa route (lazy, per device aperto)

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

    function destroyCaNetworks() {
        Object.keys(caNetworks).forEach(k => { try { caNetworks[k].destroy(); } catch (e) {} });
        caNetworks = {};
    }

    function caDeviceCount(dev) {
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

    function caRenderResultsInner() {
        const box = document.getElementById('caResults');
        if (!box) return;
        const L = i18n[currentLang];
        const en = currentLang === 'en';
        if (caView === 'home') {
            // Il deep-link (caApplyFocus) deve poter scavalcare la home:
            // se c'è un focus pendente si passa subito alla vista interfacce.
            if (caFocusIp && caData && caData.length) {
                caApplyFocus();
                if (caView !== 'home') return; // ha commutato su 'iface'
            }
            box.innerHTML = caRenderHome(L);
            return;
        }
        if (caView === 'convert') { box.innerHTML = caRenderConvert(L); return; }
        if (caView === 'firewall') { box.innerHTML = caRenderFirewallView(L, en); return; }
        if (!caData || !caData.length) {
            box.innerHTML = `<div style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.msgCaNoDevices)}</div>`;
            return;
        }
        if (caView === 'validation') {
            box.innerHTML = caData.map(dev => caRenderValidation(dev, L, en)).join('');
            caApplyFocus();
            return;
        }
        const openAll = caData.length === 1;
        box.innerHTML = caData.map((dev, idx) => {
            const count = caDeviceCount(dev);
            const tenant = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
            const body = dev.config_type === 'fortios' ? caRenderFortios(dev, L, en)
                       : dev.config_type === 'wlc-aireos' ? caRenderWlc(dev, L, en)
                       : caView === 'vlan' ? caRenderVlans(dev, L, en)
                       : caView === 'routing' ? caRenderRouting(dev, L, en, idx)
                       : caView === 'acl' ? caRenderAcls(dev, L, en)
                       : caRenderIfaces(dev, L, en);
            return `<details class="mac-switch" data-ca-idx="${idx}" style="border:1px solid var(--border); border-radius:12px; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" ${openAll ? 'open' : ''} ontoggle="caOnToggle(this, ${idx})">
                <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                    <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                    <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                    <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                    ${tenant}
                    <span style="margin-left:auto; color:var(--text-muted); font-size:12px;">${count}</span>
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
        const idx = caData.findIndex(d => d.ip === caFocusIp);
        if (idx === -1) { caFocusIp = caFocusPort = null; return; }
        if (caView !== 'iface') {
            // caSwitchView richiama renderCaResults, che a sua volta rientra qui con la vista giusta.
            caSwitchView('iface');
            return;
        }
        const port = caFocusPort;
        caFocusIp = caFocusPort = null;
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
            <div class="hero-card" onclick="caSwitchView('${view}')" style="cursor:pointer; flex:1; min-width:220px; border:1px solid var(--border); border-radius:12px; background:var(--surface-2); padding:22px 18px; transition:var(--transition);"
                 onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
                <div style="font-size:26px; color:var(--primary); margin-bottom:10px;"><i class="fa-solid ${icon}"></i></div>
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
        return `<div style="border:1px solid var(--border); border-radius:12px; background:var(--surface-2); padding:16px;">
            <div style="font-weight:600; margin-bottom:12px;"><i class="fa-solid fa-right-left" style="color:var(--primary); margin-right:8px;"></i>${escapeHtml(L.caConvertTitle)}</div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:10px;">
                <select id="caConvDevice" onchange="caConvPickDevice()" style="padding:6px 12px; border-radius:8px; border:1px solid var(--border); background:var(--surface-3); color:var(--text); font-size:13px; min-width:240px;">
                    ${caDeviceOptions(L, 'caConvDevicePick')}
                </select>
                <label style="font-size:12px; color:var(--text-muted);">${escapeHtml(L.caConvSource)}</label>
                <select id="caConvSource" style="padding:6px 10px; border-radius:8px; border:1px solid var(--border); background:var(--surface-3); color:var(--text); font-size:13px;">${vendorOpts('fortios')}</select>
                <label style="font-size:12px; color:var(--text-muted);">${escapeHtml(L.caConvTarget)}</label>
                <select id="caConvTarget" style="padding:6px 10px; border-radius:8px; border:1px solid var(--border); background:var(--surface-3); color:var(--text); font-size:13px;">${vendorOpts('panos')}</select>
                <button class="btn btn-primary btn-small" style="width:auto; margin:0;" onclick="caConvertPreview()"><i class="fa-solid fa-eye"></i> ${escapeHtml(L.caConvPreviewBtn)}</button>
            </div>
            <textarea id="caConvText" rows="8" placeholder="${escapeHtml(L.caConvTextPh)}" style="width:100%; font-family:var(--font-code); font-size:12px; border:1px solid var(--border); border-radius:8px; background:var(--surface-3); color:var(--text); padding:10px; resize:vertical;"></textarea>
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
                <div style="max-height:320px; overflow:auto; border:1px solid var(--border); border-radius:8px;">
                <table class="data-table" style="width:100%;"><thead><tr>
                    <th>${escapeHtml(L.thCaConvSource)}</th><th>${escapeHtml(L.thCaConvTarget)}</th><th>${escapeHtml(L.thCaConvNote)}</th>
                </tr></thead><tbody>${rows || `<tr><td colspan="3" style="color:var(--text-muted); font-size:12px;">—</td></tr>`}</tbody></table></div>
                <details style="margin-top:10px;">
                    <summary style="cursor:pointer; font-weight:600; font-size:13px;">${escapeHtml(L.caConvUnmapped)} (${unmapped.length})</summary>
                    <pre style="white-space:pre-wrap; font-size:11px; background:var(--surface-3); border:1px solid var(--border); border-radius:8px; padding:10px; margin-top:8px; max-height:240px; overflow:auto;">${escapeHtml(unmapped.join('\n\n'))}</pre>
                </details>
                <div style="display:flex; align-items:center; gap:10px; margin-top:12px;">
                    <div style="font-weight:600; font-size:13px;">Preview</div>
                    <button class="btn btn-secondary btn-small" style="width:auto; margin:0;" onclick="caConvDownload()"><i class="fa-solid fa-download"></i> ${escapeHtml(L.caConvDownload)}</button>
                </div>
                <pre style="white-space:pre-wrap; font-size:11px; background:var(--surface-3); border:1px solid var(--border); border-radius:8px; padding:10px; margin-top:8px; max-height:320px; overflow:auto;">${escapeHtml(caConvLastPreview)}</pre>`;
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
        const dev = caData[idx];
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
        const dev = caData[idx];
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
            data-raw="${encoded}" onclick="caShowRawRoute(this)" style="padding:2px 8px;">
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
            return `<details style="border:1px solid var(--border); border-radius:8px; margin-bottom:8px; background:var(--surface);">
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
            <button type="button" class="ca-pill ${caRouteGroupMode === 'flat' ? 'active' : ''}" onclick="caSwitchRouteGroupMode('flat', ${idx})">${escapeHtml(L.lblCaRouteFlat)}</button>
            <button type="button" class="ca-pill ${caRouteGroupMode === 'byhop' ? 'active' : ''}" onclick="caSwitchRouteGroupMode('byhop', ${idx})">${escapeHtml(L.lblCaRouteByHop)}</button>
        </div>`;
        const staticSection = `${routeToggle}${caRouteGroupMode === 'byhop' ? groupedHtml : staticTable}`;
        const protoCards = protocols.length ? protocols.map(p => `
            <details style="border:1px solid var(--border); border-radius:8px; margin-top:8px; background:var(--surface);">
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
        const nodeFont = { color: '#ffffff', size: 13, face: 'Rubik, sans-serif' };
        const hopFont = { color: '#ffffff', size: 12, face: 'Rubik, sans-serif' };
        const nodes = [{
            id: 'center', label: hostname, shape: 'box',
            color: { background: '#6a5fc1', border: '#a99ff2' },
            font: nodeFont, borderWidth: 2, margin: 8
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
                color: { background: '#2b2144', border: '#a99ff2' },
                font: hopFont, borderWidth: 1.5
            });
            edges.push({
                from: 'center', to: nid,
                label: `${hopCounts[hop]} ${i18n[currentLang].lblCaRouteMapEdge}`,
                color: hopHasDefault[hop] ? { color: '#ffb84d' } : { color: 'rgba(169,159,242,0.65)' },
                width: hopHasDefault[hop] ? 3 : 2,
                font: { color: '#ffffff', size: 12, strokeWidth: 0, background: '#150f23' }
            });
        });
        if (caNetworks[idx]) { try { caNetworks[idx].destroy(); } catch (e) {} }
        const network = new vis.Network(container, { nodes, edges }, {
            physics: { stabilization: { iterations: 100 } },
            interaction: { dragView: true, zoomView: true },
            edges: { font: { color: '#ffffff', size: 12, strokeWidth: 0, background: '#150f23' } }
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
            return `<details style="border:1px solid var(--border); border-radius:8px; margin-bottom:8px; background:var(--surface);">
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
            return `<tr style="cursor:pointer;" data-ca-iface="${escapeHtml(expandIface(i.name).toLowerCase())}" onclick="caToggleIfaceRaw('${rowId}')">
                    <td>${escapeHtml(i.name)}</td><td>${escapeHtml(i.description || '—')}</td><td><span class="badge" style="font-size:10px;">${escapeHtml(mode)}</span></td>
                    <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(String(vlanCol))}</td>
                    <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(i.ip || '—')}</td>
                    <td>${aclChips || '—'}</td><td>${state}</td>
                </tr>
                <tr id="${rowId}" style="display:none;"><td colspan="7"><pre style="font-family:var(--font-code); background:var(--surface); border-radius:6px; padding:8px; margin:0; white-space:pre-wrap; font-size:11px;">${escapeHtml(i.raw || '—')}</pre></td></tr>`;
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
            return { total: 0, body: `<div style="display:flex; align-items:center; gap:8px; padding:10px 12px; border-radius:8px; background:rgba(59,225,136,0.12); border:1px solid rgba(59,225,136,0.35); color:var(--success); font-size:12px;">
                <i class="fa-solid fa-circle-check"></i><span>${escapeHtml(L.msgCaNoIssues)}</span></div>` };
        }
        return { total, body: sections.join('') };
    }

    function caRenderValidation(dev, L, en) {
        if (dev.config_type === 'fortios' || dev.config_type === 'wlc-aireos') {
            const mv = caRenderMvValidationBody(dev, L, en);
            const tenantMv = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
            return `<details class="mac-switch" style="border:1px solid var(--border); border-radius:12px; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" open>
                <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                    <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                    <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                    <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                    ${tenantMv}
                    <span style="margin-left:auto; color:var(--text-muted); font-size:12px;">${mv.total}</span>
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
        const total = unusedAcls.length + missingAcls.length + unusedVlans.length + undefinedVlans.length + routeAclRefs.length;
        const tenant = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
        const chips = arr => arr.map(x => `<span class="ca-chip" style="color:var(--warning); border-color:var(--warning);">${escapeHtml(x)}</span>`).join('');
        let body;
        if (total === 0) {
            body = `<div style="display:flex; align-items:center; gap:8px; padding:10px 12px; border-radius:8px; background:rgba(59,225,136,0.12); border:1px solid rgba(59,225,136,0.35); color:var(--success); font-size:12px;">
                <i class="fa-solid fa-circle-check"></i><span>${escapeHtml(L.msgCaNoIssues)}</span></div>`;
        } else {
            const sections = [];
            if (unusedAcls.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--warning);">${L.titleCaUnusedAcls}</h4><div>${chips(unusedAcls)}</div>`);
            if (missingAcls.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--danger);">${L.titleCaMissingAcls}</h4><div>${missingAcls.map(m => `<span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">${escapeHtml(m.name)} (${L.lblCaReferencedIn}: ${escapeHtml(m.referenced_in || '—')})</span>`).join('')}</div>`);
            if (unusedVlans.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--warning);">${L.titleCaUnusedVlans}</h4><div>${chips(unusedVlans)}</div>`);
            if (undefinedVlans.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--warning);">${L.titleCaUndefinedVlans}</h4><div>${undefinedVlans.map(u => `<span class="ca-chip" style="color:var(--warning); border-color:var(--warning);">${escapeHtml(u.vlan)} (${L.lblCaReferencedIn}: ${escapeHtml(u.referenced_in || '—')})</span>`).join('')}</div>`);
            if (routeAclRefs.length) sections.push(`<h4 style="font-size:12px; margin:10px 0 4px; color:var(--primary);">${L.titleCaRouteAclRefs}</h4><div>${routeAclRefs.map(r => `<span class="ca-chip">${escapeHtml(r.context)} → ${escapeHtml(r.acl)}</span>`).join('')}</div>`);
            body = sections.join('');
        }
        return `<details class="mac-switch" style="border:1px solid var(--border); border-radius:12px; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" open>
            <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                ${tenant}
                <span style="margin-left:auto; color:var(--text-muted); font-size:12px;">${total}</span>
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
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((i.allowaccess || []).join(', ') || '—')}</td>
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
            const disabled = (p.status || '').toLowerCase() === 'disable';
            return `<tr${disabled ? ' style="opacity:0.5;"' : ''}>
                <td>${escapeHtml(p.id != null ? String(p.id) : '—')}</td>
                <td>${escapeHtml(p.name || '—')}${disabled ? ` <span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">disable</span>` : ''}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.srcintf || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.dstintf || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.srcaddr || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.dstaddr || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.service || []).join(', ') || '—')}</td>
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

    function caRenderFwPolicies(dev, L) {
        const rows = (dev.firewall.policies || []).map(p => {
            const act = (p.action || '').toLowerCase();
            const actColor = act === 'accept' ? 'var(--success)' : act === 'deny' ? 'var(--danger)' : 'var(--text-muted)';
            const disabled = (p.status || '').toLowerCase() === 'disable';
            return `<tr${disabled ? ' style="opacity:0.5;"' : ''}>
                <td>${escapeHtml(p.id != null ? String(p.id) : '—')}</td>
                <td>${escapeHtml(p.name || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.srcintf || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.dstintf || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.srcaddr || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.dstaddr || []).join(', ') || '—')}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml((p.service || []).join(', ') || '—')}</td>
                <td style="color:${actColor}; font-weight:700;">${escapeHtml(p.action || '—')}</td>
                <td>${escapeHtml(p.nat || '—')}</td>
            </tr>`;
        }).join('');
        if (!rows) return caMvEmpty();
        return `<div class="table-container"><table><thead><tr>
            <th>ID</th><th>${L.lblCaName}</th><th>${L.thCaFgSrcIntf}</th><th>${L.thCaFgDstIntf}</th><th>${L.thCaFgSrcAddr}</th><th>${L.thCaFgDstAddr}</th><th>${L.thCaFgService}</th><th>${L.thCaFgAction}</th><th>NAT</th>
            </tr></thead><tbody>${rows}</tbody></table></div>`;
    }

    function caRenderFwIfaces(dev, L) {
        const rows = (dev.firewall.interfaces_zones || []).map(i => {
            const st = (i.status || '').toLowerCase();
            const state = st === 'down' || st === 'disable'
                ? `<span class="ca-chip" style="color:var(--danger); border-color:var(--danger);">${escapeHtml(i.status)}</span>`
                : `<span class="ca-chip" style="color:var(--success); border-color:var(--success);">${escapeHtml(i.status || L.lblCaActive)}</span>`;
            return `<tr>
                <td>${escapeHtml(i.name)}</td>
                <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(i.ip || '—')}</td>
                <td>${escapeHtml(i.vdom || '—')}</td>
                <td>${escapeHtml(i.zone || '—')}</td>
                <td>${state}</td>
            </tr>`;
        }).join('');
        if (!rows) return caMvEmpty();
        return `<div class="table-container"><table><thead><tr>
            <th>${L.thCaIface}</th><th>${L.thCaIp}</th><th>${L.thCaFgVdom}</th><th>${L.thCaFgZone}</th><th>${L.thCaState}</th>
            </tr></thead><tbody>${rows}</tbody></table></div>`;
    }

    function caRenderFwNat(dev, L) {
        const rows = (dev.firewall.vips_nat || []).map(v => `<tr>
            <td>${escapeHtml(v.name || '—')}</td>
            <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(v.extip || '—')}</td>
            <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(v.mappedip || '—')}</td>
            <td>${escapeHtml(v.extintf || '—')}</td>
            <td>${escapeHtml(v.extport || '—')}</td>
            <td>${escapeHtml(v.mappedport || '—')}</td>
        </tr>`).join('');
        if (!rows) return caMvEmpty();
        return `<div class="table-container"><table><thead><tr>
            <th>${L.lblCaName}</th><th>${L.thCaFgExtIp}</th><th>${L.thCaFgMappedIp}</th><th>${L.thCaFgExtIntf}</th><th>${L.thCaFgExtPort}</th><th>${L.thCaFgMappedPort}</th>
            </tr></thead><tbody>${rows}</tbody></table></div>`;
    }

    function caRenderFwObjects(dev, L) {
        const rows = (dev.firewall.addresses_services || []).map(o => `<tr>
            <td><span class="badge" style="font-size:10px;">${escapeHtml(o.kind || '—')}</span></td>
            <td>${escapeHtml(o.name || '—')}</td>
            <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(o.subnet || o.tcp_portrange || o.udp_portrange || '—')}</td>
            <td>${escapeHtml(o.type || o.protocol || '—')}</td>
        </tr>`).join('');
        if (!rows) return caMvEmpty();
        return `<div class="table-container"><table><thead><tr>
            <th>${L.thCaFgKind}</th><th>${L.lblCaName}</th><th>${L.thCaFgValue}</th><th>${L.thCaFgType}</th>
            </tr></thead><tbody>${rows}</tbody></table></div>`;
    }

    function caRenderFirewallView(L, en) {
        const fwDevices = (caData || []).filter(d => d.is_firewall);
        const subPills = [
            ['policy', L.pillCaFwPolicy], ['iface', L.pillCaFwIfaces],
            ['nat', L.pillCaFwNat], ['objects', L.pillCaFwObjects],
        ].map(([v, lbl]) => `<button class="ca-pill${caFwView === v ? ' active' : ''}" onclick="caSwitchFwView('${v}')">${escapeHtml(lbl)}</button>`).join('');
        const subBar = `<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px;">${subPills}</div>`;

        if (!fwDevices.length) {
            return subBar + `<div style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.msgCaNoDevices)}</div>`;
        }
        const openAll = fwDevices.length === 1;
        const body = fwDevices.map((dev, idx) => {
            const tenant = dev.tenant ? ` <span class="badge" style="font-size:10px;">${escapeHtml(dev.tenant)}</span>` : '';
            let inner;
            if (!dev.firewall) {
                inner = `<div style="font-size:12px; color:var(--text-muted); padding:8px 0;">${escapeHtml(L.msgCaFwUnsupportedVendor)}</div>`;
            } else if (caFwView === 'iface') {
                inner = caRenderFwIfaces(dev, L);
            } else if (caFwView === 'nat') {
                inner = caRenderFwNat(dev, L);
            } else if (caFwView === 'objects') {
                inner = caRenderFwObjects(dev, L);
            } else {
                inner = caRenderFwPolicies(dev, L);
            }
            return `<details class="mac-switch" style="border:1px solid var(--border); border-radius:12px; background:var(--surface-2); margin-bottom:10px; overflow:hidden;" ${openAll ? 'open' : ''}>
                <summary style="cursor:pointer; padding:12px 14px; display:flex; align-items:center; gap:10px; list-style:none;">
                    <i class="fa-solid fa-chevron-right mac-chev" style="font-size:11px;"></i>
                    <strong>${escapeHtml(dev.hostname || dev.ip)}</strong>
                    <span style="color:var(--text-muted); font-family:var(--font-code); font-size:12px;">${escapeHtml(dev.ip)}</span>
                    ${tenant}
                </summary>
                <div style="padding:0 14px 14px;">${inner}</div>
            </details>`;
        }).join('');
        return subBar + body;
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
