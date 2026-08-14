    // ===== Threat Intel: sub-tab switcher (Matcher interno vs Vendor Watch EUVD) =====
    function tiSwitchView(v) {
        document.getElementById('tiViewMatcher').style.display = v === 'matcher' ? 'block' : 'none';
        document.getElementById('tiViewWatch').style.display = v === 'watch' ? 'block' : 'none';
        document.getElementById('tiTabMatcher').classList.toggle('active', v === 'matcher');
        document.getElementById('tiTabWatch').classList.toggle('active', v === 'watch');
        if (v === 'watch' && !window._vwLoaded) { vwInit(); window._vwLoaded = true; }
    }

    // ===== Vendor Watch (EUVD globale per vendor, indipendente dall'inventario) =====
    const vwState = { vendor: '', data: [], filtered: [] };

    function vwPick(obj, keys) {
        for (let i = 0; i < keys.length; i++) {
            const val = obj ? obj[keys[i]] : undefined;
            if (val !== undefined && val !== null && val !== '') return val;
        }
        return '';
    }

    function vwSeverityClass(score) {
        if (score >= 9) return 'CRITICAL';
        if (score >= 7) return 'HIGH';
        if (score >= 4) return 'MEDIUM';
        return 'LOW';
    }

    // Normalizza un record EUVD grezzo nella forma usata dalla tabella/drawer
    // (porting adattato da euvd_dashboard/dashboard.html: normalizeRecord()).
    function vwNormalize(item) {
        const score = Number(vwPick(item, ['baseScore', 'cvssBaseScore', 'score', 'cvssScore', 'maxBaseScore']));
        const epssRaw = Number(vwPick(item, ['epss', 'epssScore', 'epssPercent']));
        const epss = (Number.isFinite(epssRaw) && epssRaw <= 1) ? epssRaw * 100 : epssRaw;
        const date = vwPick(item, ['datePublished', 'published', 'publishedDate', 'publicationDate', 'date_published', 'published_at', 'date', 'created']);
        const summary = vwPick(item, ['description', 'summary', 'title', 'details']);

        const nestedVendor = (Array.isArray(item.enisaIdVendor) && item.enisaIdVendor[0] && item.enisaIdVendor[0].vendor && item.enisaIdVendor[0].vendor.name) ? item.enisaIdVendor[0].vendor.name : '';
        let vendor = vwPick(item, ['vendor', 'vendorName']) || nestedVendor || item.assigner || '';
        if (String(vendor).toLowerCase() === 'n/a') vendor = '';

        const nestedProduct = (Array.isArray(item.enisaIdProduct) && item.enisaIdProduct[0] && item.enisaIdProduct[0].product && item.enisaIdProduct[0].product.name) ? item.enisaIdProduct[0].product.name : '';
        let product = vwPick(item, ['product', 'productName', 'affectedProduct']) || nestedProduct || '';
        if (String(product).toLowerCase() === 'n/a') product = '';

        const cveRaw = vwPick(item, ['cve', 'cveId', 'cveID', 'aliases']);
        const cve = String(cveRaw).split('\n').find(v => v.trim().startsWith('CVE-')) || String(cveRaw).split('\n')[0] || '';
        const euvd = vwPick(item, ['id', 'euvdId', 'enisaId']);
        const exploitedRaw = vwPick(item, ['exploited', 'isExploited']);
        const exploited = typeof exploitedRaw === 'boolean' ? exploitedRaw : String(exploitedRaw).toLowerCase() === 'true';
        const rawReferences = item.references || item.links || item.externalReferences || [];
        const references = Array.isArray(rawReferences) ? rawReferences : String(rawReferences).split('\n').map(v => v.trim()).filter(Boolean);

        return {
            raw: item,
            cve: cve || 'N/A',
            euvd: euvd || '—',
            product: product || '—',
            vendor: vendor || '—',
            score: Number.isFinite(score) ? score : NaN,
            epss: Number.isFinite(epss) ? epss : NaN,
            exploited: exploited,
            date: date,
            summary: summary || (currentLang === 'en' ? 'No summary provided by the feed.' : 'Nessun riassunto disponibile.'),
            references: references,
            severity: vwSeverityClass(Number.isFinite(score) ? score : 0)
        };
    }

    // Popola i pulsanti vendor dal registro (solo vendor con euvd_term configurato)
    // e avvia il primo caricamento sul primo vendor disponibile.
    async function vwInit() {
        const btnWrap = document.getElementById('vwVendorBtns');
        if (!btnWrap) return;
        try {
            const res = await apiFetch('/api/vendors');
            if (!res || !res.ok) return;
            const vendors = await res.json();
            const entries = Object.entries(vendors || {}).filter(([, v]) => v && v.euvd_term);
            // Escape per il contesto stringa JS (dentro l'onclick single-quoted) PRIMA
            // di passare per escapeHtml (contesto attributo HTML) — stesso pattern di
            // analyzeTenant(tenant) più sopra: l'entity-encoding da solo non basta a
            // prevenire una breakout di stringa JS dentro l'attributo.
            const jsStr = s => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
            btnWrap.innerHTML = entries.map(([name, v], idx) =>
                `<button class="btn btn-secondary btn-small vw-vendor-btn${idx === 0 ? ' active' : ''}" data-term="${escapeHtml(v.euvd_term)}" data-action="vw-select-vendor" style="width:auto; margin:0;">${escapeHtml(name)}</button>`
            ).join('');
            if (entries.length) {
                // Nessuna query EUVD automatica all'apertura: il fetch parte solo
                // quando l'utente sceglie un vendor o preme aggiorna.
                vwState.vendor = entries[0][1].euvd_term;
                const statusEl = document.getElementById('vwStatus');
                if (statusEl) statusEl.textContent = i18n[currentLang].vwStatusIdle;
            } else {
                const statusEl = document.getElementById('vwStatus');
                if (statusEl) statusEl.textContent = i18n[currentLang].noDevicesText.replace(/<[^>]*>/g, '');
            }
        } catch (err) {
            const statusEl = document.getElementById('vwStatus');
            if (statusEl) statusEl.textContent = i18n[currentLang].vwStatusError + err.message;
        }
    }

    document.getElementById('vwVendorBtns')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="vw-select-vendor"]');
        if (btn && btn.dataset.term) {
            vwSelectVendor(btn.dataset.term, btn);
        }
    });

    function vwSelectVendor(term, btnEl) {
        window._vwVendor = term;
        vwState.vendor = term;
        document.querySelectorAll('.vw-vendor-btn').forEach(b => b.classList.toggle('active', b === btnEl));
        vwFetch();
    }

    function vwParseTimestamp(dateStr) {
        if (!dateStr) return 0;
        if (typeof dateStr === 'number') {
            return dateStr < 1e11 ? dateStr * 1000 : dateStr;
        }
        const s = String(dateStr).trim();
        if (!s) return 0;
        if (/^\d+$/.test(s)) {
            const n = parseInt(s, 10);
            return n < 1e11 ? n * 1000 : n;
        }
        let t = Date.parse(s);
        if (!isNaN(t)) return t;

        const dmY = s.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{4})/);
        if (dmY) {
            const d = parseInt(dmY[1], 10);
            const m = parseInt(dmY[2], 10) - 1;
            const y = parseInt(dmY[3], 10);
            t = new Date(y, m, d).getTime();
            return isNaN(t) ? 0 : t;
        }

        const yMd = s.match(/^(\d{4})[/-](\d{1,2})[/-](\d{1,2})/);
        if (yMd) {
            const y = parseInt(yMd[1], 10);
            const m = parseInt(yMd[2], 10) - 1;
            const d = parseInt(yMd[3], 10);
            t = new Date(y, m, d).getTime();
            return isNaN(t) ? 0 : t;
        }

        return 0;
    }

    // Interroga /api/search (proxy NVD autenticato) con i filtri correnti.
    async function vwFetch() {
        const statusEl = document.getElementById('vwStatus');
        const bodyEl = document.getElementById('vwBody');
        if (!statusEl || !bodyEl) return;
        statusEl.textContent = i18n[currentLang].vwStatusLoading;

        const params = new URLSearchParams();
        if (vwState.vendor) params.set('vendor', vwState.vendor);
        const selectedSev = document.getElementById('vwSeverity')?.value;
        if (selectedSev) params.set('severity', selectedSev);
        const minScore = document.getElementById('vwMinScore').value;
        if (minScore) params.set('fromScore', minScore);
        params.set('size', '40');
        if (document.getElementById('vwExploited').checked) params.set('exploited', 'true');
        const fromDate = document.getElementById('vwFromDate').value;
        if (fromDate) params.set('fromDate', fromDate);
        const minEpss = document.getElementById('vwMinEpss').value;
        if (minEpss) params.set('fromEpss', minEpss);

        try {
            const res = await apiFetch('/api/search?' + params.toString());
            if (!res || !res.ok) throw new Error('HTTP ' + (res ? res.status : '?'));
            const payload = await res.json();
            const records = Array.isArray(payload) ? payload : Array.isArray(payload.items) ? payload.items : Array.isArray(payload.content) ? payload.content : [];
            vwState.data = records.map(vwNormalize).sort((a, b) => vwParseTimestamp(b.date) - vwParseTimestamp(a.date));
            vwApplyTextFilter();
        } catch (err) {
            vwState.data = [];
            vwState.filtered = [];
            vwRenderTable();
            statusEl.textContent = i18n[currentLang].vwStatusError + err.message;
        }
    }

    // Filtro testuale, severità, CVSS, EPSS, data ed exploitation lato client sulle righe già caricate.
    function vwApplyTextFilter() {
        const q = (document.getElementById('vwText')?.value || '').trim().toLowerCase();
        const selectedSev = document.getElementById('vwSeverity')?.value;
        const sevRanks = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
        const targetRank = selectedSev ? (sevRanks[selectedSev] || 0) : 0;
        const minCvss = parseFloat(document.getElementById('vwMinScore')?.value);
        const minEpss = parseFloat(document.getElementById('vwMinEpss')?.value);
        const onlyExploited = !!document.getElementById('vwExploited')?.checked;
        const fromDateVal = document.getElementById('vwFromDate')?.value;
        const fromTs = fromDateVal ? vwParseTimestamp(fromDateVal) : 0;

        vwState.filtered = vwState.data.filter(r => {
            if (targetRank > 0) {
                const rRank = sevRanks[r.severity] || 0;
                if (rRank < targetRank) return false;
            }
            if (!isNaN(minCvss) && minCvss > 0) {
                if (isNaN(r.score) || r.score < minCvss) return false;
            }
            if (!isNaN(minEpss) && minEpss > 0) {
                if (isNaN(r.epss) || r.epss < minEpss) return false;
            }
            if (onlyExploited && !r.exploited) return false;
            if (fromTs > 0 && vwParseTimestamp(r.date) < fromTs) return false;
            if (q) {
                return [r.cve, r.euvd, r.product, r.vendor, r.summary].join(' ').toLowerCase().indexOf(q) !== -1;
            }
            return true;
        });
        vwRenderTable();
        const statusEl = document.getElementById('vwStatus');
        if (statusEl) statusEl.textContent = vwState.filtered.length + ' ' + i18n[currentLang].vwStatusRows;
    }

    function applyThreatSeverityFilter() {
        const selSev = document.getElementById('threatSeveritySelect')?.value || 'all';
        const cards = document.querySelectorAll('#securityTriageContainer div[data-sev]');
        const sevRanks = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
        const targetRank = selSev !== 'all' ? (sevRanks[selSev] || 0) : 0;

        cards.forEach(card => {
            const cardSev = (card.getAttribute('data-sev') || '').toUpperCase();
            const cardRank = sevRanks[cardSev] || 0;
            if (targetRank === 0 || cardRank >= targetRank) {
                card.style.display = '';
            } else {
                card.style.display = 'none';
            }
        });
    }

    function vwRenderTable() {
        const bodyEl = document.getElementById('vwBody');
        if (!bodyEl) return;
        bodyEl.innerHTML = vwState.filtered.map((item, idx) => {
            const ts = vwParseTimestamp(item.date);
            const displayDate = ts > 0 ? new Date(ts).toLocaleDateString() : (item.date || '—');
            const subCve = (item.euvd && item.euvd !== item.cve && item.euvd !== '—')
                ? `<div style="font-size:11px; color:var(--text-muted); font-family:var(--font-code);">${escapeHtml(item.euvd)}</div>`
                : '';
            const productHtml = item.product && item.product !== '—'
                ? `<div style="font-weight:600;">${escapeHtml(item.product)}</div><div style="font-size:11px; color:var(--text-muted); text-transform:uppercase;">${escapeHtml(item.vendor)}</div>`
                : `<div style="font-weight:600; text-transform:uppercase;">${escapeHtml(item.vendor)}</div>`;
            return `
            <tr data-action="vw-open-drawer" data-idx="${idx}" style="cursor:pointer;">
                <td><div style="font-family:var(--font-code); font-weight:700;">${escapeHtml(item.cve)}</div>${subCve}</td>
                <td>${productHtml}</td>
                <td><span class="severity-pill severity-${item.severity}">${item.severity}</span></td>
                <td style="font-family:var(--font-code); font-weight:600;">${Number.isFinite(item.score) ? item.score.toFixed(1) : '—'}</td>
                <td style="font-family:var(--font-code);">${Number.isFinite(item.epss) ? item.epss.toFixed(1) + '%' : '—'}</td>
                <td>${item.exploited ? '<span class="badge" style="color:var(--danger); border-color:var(--danger); font-weight:700;">Exploited</span>' : '<span class="badge" style="opacity:0.4;">—</span>'}</td>
                <td data-sort-value="${ts}">${escapeHtml(displayDate)}</td>
            </tr>`;
        }).join('');
    }

    document.getElementById('vwBody')?.addEventListener('click', (e) => {
        const row = e.target.closest('[data-action="vw-open-drawer"]');
        if (row && row.dataset.idx != null) {
            vwOpenDrawer(parseInt(row.dataset.idx, 10));
        }
    });

    // Apre il drawer laterale con i dettagli completi del record selezionato.
    function vwOpenDrawer(idx) {
        const item = vwState.filtered[idx];
        const drawer = document.getElementById('vwDrawer');
        if (!item || !drawer) return;
        // Solo http(s):// diventa un link cliccabile: blocca schemi javascript:/data:
        // che escapeHtml (entity-encoding) da solo non filtrerebbe.
        const refsHtml = item.references.length
            ? item.references.map(r => /^https?:\/\//i.test(r.trim())
                ? `<div><a href="${escapeHtml(r.trim())}" target="_blank" rel="noopener">${escapeHtml(r)}</a></div>`
                : `<div>${escapeHtml(r)}</div>`).join('')
            : '<div style="color:var(--text-muted);">—</div>';
        const subInfo = (item.euvd && item.euvd !== item.cve && item.euvd !== '—') ? ` · ${escapeHtml(item.euvd)}` : '';
        drawer.innerHTML = `
            <button class="btn btn-secondary btn-small" style="width:auto; margin-bottom:14px;" data-action="vw-close-drawer"><i class="fa-solid fa-xmark"></i></button>
            <h3 style="margin:0 0 6px; font-family:var(--font-code);">${escapeHtml(item.cve)}</h3>
            <div style="margin-bottom:10px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <span class="severity-pill severity-${item.severity}">${item.severity}</span>
              <span style="font-weight:600;">CVSS ${Number.isFinite(item.score) ? item.score.toFixed(1) : '—'}</span>
              <span style="color:var(--text-muted);">EPSS ${Number.isFinite(item.epss) ? item.epss.toFixed(1) + '%' : '—'}</span>
              ${item.exploited ? '<span class="badge" style="color:var(--danger); border-color:var(--danger); font-weight:700;">Exploited</span>' : ''}
            </div>
            <div style="margin-bottom:10px; font-weight:600;">${escapeHtml(item.vendor)}${item.product && item.product !== '—' ? ' · ' + escapeHtml(item.product) : ''}${subInfo}</div>
            <div style="margin-bottom:14px; line-height:1.5;">${escapeHtml(item.summary)}</div>
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:6px;">${item.date ? new Date(item.date).toLocaleDateString() : '—'}</div>
            <div style="font-size:12px; word-break:break-all;">${refsHtml}</div>
        `;
        drawer.style.display = 'block';
    }

    document.getElementById('vwDrawer')?.addEventListener('click', (e) => {
        if (e.target.closest('[data-action="vw-close-drawer"]')) {
            const drawer = document.getElementById('vwDrawer');
            if (drawer) drawer.style.display = 'none';
        }
    });

    document.getElementById('vwText')?.addEventListener('input', vwApplyTextFilter);
    document.getElementById('vwSeverity')?.addEventListener('change', vwApplyTextFilter);
    document.getElementById('vwMinScore')?.addEventListener('change', vwApplyTextFilter);
    document.getElementById('vwMinEpss')?.addEventListener('input', vwApplyTextFilter);
    document.getElementById('vwExploited')?.addEventListener('change', vwApplyTextFilter);
    document.getElementById('vwFromDate')?.addEventListener('change', vwApplyTextFilter);

    // Parallelizzazione delle query ENISA tramite Promise.all (Ottimizzazione Performance)
    // Aperta la tab: prepara i controlli (sedi consentite) e avvia automaticamente la scansione.
    function loadThreatIntel() {
        const sel = document.getElementById("threatGroupSelect");
        if (sel) {
            const cur = sel.value;
            const groups = Object.keys(globalGroups || {});
            sel.innerHTML = `<option value="all">${currentLang==='en'?'All tenants':'Tutti i tenant'}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            sel.value = groups.includes(cur) ? cur : 'all';
        }
        startThreatScan();
    }

    // Costruisce la lista di dispositivi da analizzare; le query EUVD reali partono
    // solo al clic del pulsante "Analizza" su ogni singolo dispositivo.
    async function startThreatScan() {
        if (window._threatScanBusy) return;
        window._threatScanBusy = true;
        try {
        const container = document.getElementById("securityTriageContainer");
        if (!container) return;
        const selGroup = document.getElementById("threatGroupSelect")?.value || 'all';
        const includeDiscovered = document.getElementById("threatIncludeDiscovered")?.checked || false;

        const queryingText = i18n[currentLang].queryingEnisa.replace(/<[^>]*>/g, '');
        container.innerHTML = `<div style="text-align:center; padding: 40px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><br><br>${queryingText}</div>`;

        const res = await apiFetch('/api/local-devices');
        if (!res) return;
        const data = await res.json();

        let onlineDevices = data.devices.filter(d => {
            const scan = data.detected_versions[d.IP];
            return scan && scan.status === 'online' && scan.version !== 'Non Scansionato' && scan.version !== 'Unknown';
        });
        if (selGroup !== 'all') onlineDevices = onlineDevices.filter(d => d.Group === selGroup);

        container.innerHTML = "";

        // ── SEZIONE 1: Dispositivi inventariati online ──────────────────────────
        if (onlineDevices.length === 0) {
            container.innerHTML += `<div style="padding: 20px; border: 1px solid var(--border); border-radius:0; text-align:center; color: var(--text-muted); margin-bottom: 20px;">
                ${i18n[currentLang].noDevicesText}
            </div>`;
        } else {
            // Card SELEZIONABILI: la query EUVD parte SOLO quando l'utente sceglie
            // un singolo dispositivo (pulsante Analizza), non su tutti insieme.
            onlineDevices.forEach(d => {
                const scan = data.detected_versions[d.IP] || {};
                const safeIpId = d.IP.replace(/\./g, '-');
                const model = d.Model || scan.model || 'Non Rilevato';
                const modelLabel = model !== 'Non Rilevato' ? `<span style="color:var(--text-muted); margin-left: 10px; font-size:13px;">Modello: <code>${escapeHtml(model)}</code></span>` : '';

                const devCard = document.createElement("div");
                devCard.className = "vuln-card";
                devCard.style.marginBottom = "12px";
                devCard.innerHTML = `
                    <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
                        <div>
                            <span style="font-size:17px; font-weight:700;"><i class="fa-solid fa-server" style="color:var(--primary);"></i> ${d.IP}</span>
                            <span class="badge" style="margin-left: 10px;">${escapeHtml(d.Vendor.toUpperCase())}</span>
                            ${modelLabel}
                            <span style="color:var(--text-muted); margin-left: 10px; font-size:13px;">Firmware: <code>${escapeHtml(scan.version || 'Non Rilevata')}</code></span>
                        </div>
                        <div style="display:flex; align-items:center; gap:12px;">
                            <div id="status-${safeIpId}" style="font-size:13px; font-weight:700; color: var(--text-muted);"></div>
                            <button id="btn-mgd-${safeIpId}"
                                data-action="run-managed-vuln-check"
                                data-ip="${escapeHtml(d.IP)}" data-vendor="${escapeHtml(d.Vendor)}" data-version="${escapeHtml(scan.version || '')}" data-model="${escapeHtml(model)}"
                                style="padding:8px 14px; border-radius:0; border:none; background:var(--cta); color:var(--cta-text); font-weight:700; font-size:13px; cursor:pointer; white-space:nowrap;">
                                ${i18n[currentLang].btnAnalyzeVuln}
                            </button>
                        </div>
                    </div>
                    <div id="results-${safeIpId}" style="display:flex; flex-direction:column; gap:10px; margin-top:10px;"></div>
                `;
                container.appendChild(devCard);
            });
        }

        // ── SEZIONE 2: Vicini Scoperti (CDP/LLDP) – solo se richiesto ──────────
        if (!includeDiscovered) return;
        const mapRes = await apiFetch('/api/network-map?group=' + encodeURIComponent(selGroup));
        if (!mapRes || !mapRes.ok) return;
        const mapData = await mapRes.json();

        let discoveredWithVersion = (mapData.nodes || []).filter(n =>
            n.status === 'discovered' && n.version && n.version.trim() !== ''
        );
        if (selGroup !== 'all') discoveredWithVersion = discoveredWithVersion.filter(n => n.group === selGroup);

        if (discoveredWithVersion.length === 0) return;

        // Header sezione
        const sectionHeader = document.createElement("div");
        sectionHeader.innerHTML = `
            <div style="border-top: 1px solid var(--border); margin: 25px 0 15px 0; padding-top: 20px;">
                <h3 style="font-size:17px; margin-bottom:6px;">
                    ${i18n[currentLang].discoveredNeighborsTitle}
                </h3>
                <p style="font-size:13px; color:var(--text-muted);">
                    ${i18n[currentLang].discoveredNeighborsDesc}
                </p>
            </div>
        `;
        container.appendChild(sectionHeader);

        // Griglia di card selezionabili
        const grid = document.createElement("div");
        grid.style.cssText = "display:grid; grid-template-columns: repeat(auto-fill, minmax(280px,1fr)); gap:12px; margin-bottom:18px;";
        container.appendChild(grid);

        discoveredWithVersion.forEach(n => {
            const safeId = n.id.replace(/[^a-zA-Z0-9]/g, '-');
            const versionShort = extractReadableVersion(n.version);

            const card = document.createElement("div");
            card.id = `disc-card-${safeId}`;
            card.style.cssText = `
                background: var(--surface-2);
                border: 2px solid var(--border);
                border-radius: 0;
                padding: 14px;
                cursor: pointer;
                transition: all 0.2s ease;
                user-select: none;
            `;
            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
                    <div>
                        <div style="font-weight:700; font-size:15px;">${escapeHtml(n.label)}</div>
                        <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-code);">${escapeHtml(n.id)}</div>
                    </div>
                    <span style="font-size:11px; background:color-mix(in srgb, var(--warning) 15%, transparent); color:var(--warning); border:1px solid color-mix(in srgb, var(--warning) 30%, transparent); padding:3px 8px; border-radius:0; font-weight:700;">DISCOVERED</span>
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:10px; line-height:1.4; max-height:38px; overflow:hidden;">
                    <code style="font-size:11px; color:var(--primary);">${escapeHtml(versionShort)}</code>
                </div>
                <button
                    id="btn-disc-${safeId}"
                    data-action="run-discovered-vuln-check"
                    data-id="${escapeHtml(n.id)}" data-label="${escapeHtml(n.label)}"
                    data-version="${escapeHtml(n.version)}" data-vshort="${escapeHtml(versionShort)}"
                    data-vendor="${escapeHtml((n.vendor && n.vendor !== 'discovered') ? n.vendor : '')}"
                    style="width:100%; padding:8px; border-radius:0; border:none; background:var(--cta); color:var(--cta-text); font-weight:700; font-size:13px; cursor:pointer; transition:all 0.2s;">
                    ${i18n[currentLang].btnAnalyzeVuln}
                </button>
            `;
            card.onmouseenter = () => card.style.borderColor = 'var(--warning)';
            card.onmouseleave = () => {
                if (!card.dataset.checked) card.style.borderColor = 'var(--border)';
            };
            grid.appendChild(card);

            const resultArea = document.createElement("div");
            resultArea.id = `disc-results-${safeId}`;
            resultArea.style.cssText = "display:none; grid-column:1/-1;";
            grid.appendChild(resultArea);
        });
        } finally {
            window._threatScanBusy = false;
        }
    }

    function extractReadableVersion(sysDesc) {
        if (!sysDesc) return i18n[currentLang].versionNotAvailable;
        const ciscoMatch = sysDesc.match(/Version\s+([\w.()]+)/i);
        if (ciscoMatch) return `IOS Version ${ciscoMatch[1]}`;
        const linuxMatch = sysDesc.match(/^(Ubuntu|Debian|CentOS|RHEL|Rocky|Alpine)\s+([\d.\w]+)/i);
        if (linuxMatch) return `${linuxMatch[1]} ${linuxMatch[2]}`;
        return sysDesc.substring(0, 60).trim();
    }

    async function runDiscoveredVulnCheck(nodeId, label, fullVersion, versionShort, nodeVendor, btnEl) {
        const safeId = nodeId.replace(/[^a-zA-Z0-9]/g, '-');
        const card = document.getElementById(`disc-card-${safeId}`);
        const resultArea = document.getElementById(`disc-results-${safeId}`);
        if (!resultArea) return;

        btnEl.disabled = true;
        btnEl.innerHTML = i18n[currentLang].scanningEuvd;
        card.style.borderColor = 'var(--primary)';
        card.dataset.checked = '1';

        // Usa il vendor realmente rilevato sul nodo (CDP/LLDP o riclassificato a
        // mano); solo se assente lo deduce dalla versione. MAI usare l'hostname
        // come vendor: inquinerebbe la query EUVD (es. "FGT-120G-SWCOREA").
        let vendor = (nodeVendor || '').trim();
        if (!vendor) {
            const hay = `${fullVersion} ${label}`;
            if (/forti/i.test(hay))                 vendor = 'fortinet';
            else if (/palo|pan-?os/i.test(hay))     vendor = 'paloalto';
            else if (/cisco|catalyst|nexus|ios/i.test(hay)) vendor = 'cisco';
            else if (/hpe|procurve|aruba/i.test(hay)) vendor = 'hpe';
            else if (/junos|juniper/i.test(hay))    vendor = 'juniper';
        }

        resultArea.style.display = "block";
        resultArea.innerHTML = `
            <div class="vuln-card" style="border-color:var(--primary); margin-top: 8px;">
                <div style="font-weight:700; margin-bottom:10px;">
                    <i class="fa-solid fa-satellite-dish" style="color:var(--warning);"></i>
                    ${escapeHtml(label)} <span style="color:var(--text-muted); font-size:12px; font-weight:400;">(${escapeHtml(nodeId)})</span>
                    <span id="disc-status-${safeId}" style="float:right; font-size:13px; color:var(--text-muted);">
                        ${i18n[currentLang].queryingEnisa}
                    </span>
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
                    System Description: <code style="color:var(--primary); font-size:11px;">${escapeHtml(versionShort)}</code>
                </div>
                <div id="disc-vuln-${safeId}"></div>
            </div>
        `;

        await runEuvdQuery(`disc-${safeId}`, vendor, versionShort, `disc-status-${safeId}`, `disc-vuln-${safeId}`);

        btnEl.disabled = false;
        btnEl.innerHTML = i18n[currentLang].btnRescan;
    }

    // Analisi vulnerabilità di UN singolo dispositivo gestito (scelto dall'utente).
    async function runManagedVulnCheck(ip, vendor, version, btnEl, model) {
        const safeIpId = ip.replace(/\./g, '-');
        btnEl.disabled = true;
        btnEl.innerHTML = i18n[currentLang].scanningEuvd;
        const validModel = (model && model !== 'Non Rilevato') ? model : '';
        const queryText = (validModel ? (validModel + ' ' + (version || '')) : (version || '')).trim();
        await runEuvdQuery(safeIpId, vendor, queryText);
        btnEl.disabled = false;
        btnEl.innerHTML = i18n[currentLang].btnRescan;
    }

    function toggleVulnDesc(id, btn) {
        const el = document.getElementById(id);
        if (!el) return;
        const hidden = el.style.display === 'none';
        el.style.display = hidden ? '' : 'none';
        const ic = btn.querySelector('i');
        if (ic) ic.className = hidden ? 'fa-solid fa-chevron-up' : 'fa-solid fa-chevron-down';
    }

    function toggleVulnResults(resultsElId, btn) {
        const wrapper = document.getElementById(`vulncards-${resultsElId}`);
        if (!wrapper) return;
        const hidden = wrapper.style.display === 'none';
        wrapper.style.display = hidden ? '' : 'none';
        const label = hidden
            ? (currentLang === 'en' ? 'Hide results' : 'Nascondi risultati')
            : (currentLang === 'en' ? 'Show results' : 'Mostra risultati');
        btn.innerHTML = `<i class="fa-solid fa-chevron-${hidden ? 'up' : 'down'}"></i> ${label}`;
    }

    async function runEuvdQuery(safeId, vendor, version, statusElId, resultsElId) {
        const effectiveResultsId = resultsElId || `results-${safeId}`;
        const statusEl  = document.getElementById(statusElId  || `status-${safeId}`);
        const resultsEl = document.getElementById(effectiveResultsId);
        if (!statusEl || !resultsEl) return;

        // Il vendor viene incluso solo se noto (altrimenti si cerca solo per testo);
        // il proxy lo risolve nel termine EUVD corretto (es. fortinet).
        const params = new URLSearchParams();
        if (vendor && vendor.trim()) params.set('vendor', vendor.trim());
        params.set('text', version);
        params.set('size', '3');
        const queryUrl = `/api/search?${params.toString()}`;

        try {
            const deviceRes = await apiFetch(queryUrl);
            if (deviceRes && deviceRes.ok) {
                const vulnData = await deviceRes.json();
                // L'API EUVD /api/search risponde con { items: [...], total: N }.
                const items = vulnData.items || vulnData.results || vulnData.content
                            || (Array.isArray(vulnData) ? vulnData : []);

                if (items.length > 0) {
                    statusEl.innerHTML = `<span style="color: var(--danger);"><i class="fa-solid fa-triangle-exclamation"></i> ${items.length} ${i18n[currentLang].vulnerabilitiesDetected}</span>`;
                    const hideLabel = currentLang === 'en' ? 'Hide results' : 'Nascondi risultati';
                    resultsEl.innerHTML = `
                        <div style="display:flex; align-items:center; justify-content:flex-end; margin-bottom:6px;">
                            <button data-action="toggle-vuln-results" data-target="${effectiveResultsId}"
                                style="padding:4px 10px; border-radius:0; border:1px solid var(--border); background:var(--surface-2); color:var(--text-muted); font-size:12px; cursor:pointer; display:inline-flex; align-items:center; gap:5px;">
                                <i class="fa-solid fa-chevron-up"></i> ${hideLabel}
                            </button>
                        </div>
                        <div id="vulncards-${effectiveResultsId}" style="display:flex; flex-direction:column; gap:10px;"></div>
                    `;
                    const cardsEl = document.getElementById(`vulncards-${effectiveResultsId}`);
                    items.slice(0, 3).forEach((v, idx) => {
                        const cveId = v.cveId || v.cve || v.id || "CVE-Unknown";
                        const description = v.description || v.summary || i18n[currentLang].descriptionNotAvailable;
                        // Il punteggio CVSS è nel campo 'baseScore' (numero, può essere 0).
                        const score      = (v.baseScore != null && v.baseScore !== "")
                                         ? v.baseScore : (v.cvssScore || v.score || "N/A");
                        const descId = `vulndesc-${effectiveResultsId}-${idx}`;

                        let severity = "MEDIUM";
                        if (score !== "N/A") {
                            const num = parseFloat(score);
                            if (num >= 9.0)      severity = "CRITICAL";
                            else if (num >= 7.0) severity = "HIGH";
                            else if (num >= 4.0) severity = "MEDIUM";
                            else                 severity = "LOW";
                        }

                        const exploitedFlag = (v.exploited === true || String(v.exploited).toLowerCase() === 'true') ? '1' : '0';
                        cardsEl.innerHTML += `
                            <div data-sev="${severity.toLowerCase()}" data-exploited="${exploitedFlag}" style="background:var(--surface-3); border: 1px solid var(--border); padding: 12px; border-radius: 0; font-size:13px;">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <strong style="color:var(--primary);">${escapeHtml(cveId)}</strong>
                                        <button data-action="toggle-vuln-desc" data-target="${descId}"
                                            style="padding:2px 7px; border-radius:0; border:1px solid var(--border); background:transparent; color:var(--text-muted); font-size:11px; cursor:pointer; display:inline-flex; align-items:center; gap:3px;">
                                            <i class="fa-solid fa-chevron-up"></i>
                                        </button>
                                    </div>
                                    <span class="severity-pill severity-${severity}">CVSS: ${escapeHtml(score)}</span>
                                </div>
                                <div id="${descId}" style="color:var(--text-muted); margin-bottom:6px; line-height:1.4;">${escapeHtml(description)}</div>
                                <div style="font-size:10px; color:var(--primary);">${i18n[currentLang].relevantNis2}</div>
                            </div>
                        `;
                    });
                } else {
                    statusEl.innerHTML = `<span style="color: var(--success);"><i class="fa-solid fa-circle-check"></i> ${i18n[currentLang].safeRelease}</span>`;
                    resultsEl.innerHTML = `<div style="color:var(--text-muted); font-size:13px; font-style:italic;">${i18n[currentLang].noThreatsFound}</div>`;
                }
            } else {
                statusEl.innerHTML = `<span style="color: var(--warning);"><i class="fa-solid fa-triangle-exclamation"></i> ${i18n[currentLang].errorMatch}</span>`;
            }
        } catch (err) {
            statusEl.innerHTML = `<span style="color: var(--danger);">${i18n[currentLang].errorScan}</span>`;
        }
    }

    document.getElementById('securityTriageContainer')?.addEventListener('click', (e) => {
        const mgdBtn = e.target.closest('[data-action="run-managed-vuln-check"]');
        if (mgdBtn) {
            runManagedVulnCheck(mgdBtn.dataset.ip, mgdBtn.dataset.vendor, mgdBtn.dataset.version, mgdBtn, mgdBtn.dataset.model);
            return;
        }
        const discBtn = e.target.closest('[data-action="run-discovered-vuln-check"]');
        if (discBtn) {
            runDiscoveredVulnCheck(discBtn.dataset.id, discBtn.dataset.label, discBtn.dataset.version, discBtn.dataset.vshort, discBtn.dataset.vendor, discBtn);
            return;
        }
        const resBtn = e.target.closest('[data-action="toggle-vuln-results"]');
        if (resBtn && resBtn.dataset.target) {
            toggleVulnResults(resBtn.dataset.target, resBtn);
            return;
        }
        const descBtn = e.target.closest('[data-action="toggle-vuln-desc"]');
        if (descBtn && descBtn.dataset.target) {
            toggleVulnDesc(descBtn.dataset.target, descBtn);
        }
    });

    // Static event listeners for Threat Intel tab
    document.getElementById('tiTabMatcher')?.addEventListener('click', () => tiSwitchView('matcher'));
    document.getElementById('tiTabWatch')?.addEventListener('click', () => tiSwitchView('watch'));
    document.getElementById('threatGroupSelect')?.addEventListener('change', startThreatScan);
    document.getElementById('threatSeveritySelect')?.addEventListener('change', applyThreatSeverityFilter);
    document.getElementById('threatIncludeDiscovered')?.addEventListener('change', startThreatScan);
    document.getElementById('vwRefresh')?.addEventListener('click', vwFetch);
