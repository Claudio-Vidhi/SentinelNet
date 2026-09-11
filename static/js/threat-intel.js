    // ===== Threat Intel: sub-tab switcher (Matcher interno vs Vendor Watch EUVD) =====
    const TI_VIEWS = { matcher: 'tiTabMatcher', priority: 'tiTabPriority',
                       report: 'tiTabReport', watch: 'tiTabWatch' };

    function tiSwitchView(v) {
        for (const name in TI_VIEWS) {
            const pane = document.getElementById('tiView' + name.charAt(0).toUpperCase() + name.slice(1));
            if (pane) pane.style.display = name === v ? 'block' : 'none';
            document.getElementById(TI_VIEWS[name])?.classList.toggle('active', name === v);
        }
        if (v === 'watch' && !window._vwLoaded) { vwInit(); window._vwLoaded = true; }
        if (v === 'priority') cvePriorityLoad();
        if (v === 'report') cveReportLoad();
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
        const exploitedRaw = vwPick(item, ['exploited', 'isExploited']);
        const exploited = typeof exploitedRaw === 'boolean' ? exploitedRaw : String(exploitedRaw).toLowerCase() === 'true';
        const rawReferences = item.references || item.links || item.externalReferences || [];
        const references = Array.isArray(rawReferences) ? rawReferences : String(rawReferences).split('\n').map(v => v.trim()).filter(Boolean);

        return {
            raw: item,
            cve: cve || 'N/A',
            product: product || '—',
            vendor: vendor || '—',
            score: Number.isFinite(score) ? score : NaN,
            epss: Number.isFinite(epss) ? epss : NaN,
            exploited: exploited,
            date: date,
            summary: summary || (tr('tiNoSummaryProvidedBy')),
            references: references,
            severity: vwSeverityClass(Number.isFinite(score) ? score : 0)
        };
    }

    // Populate vendor buttons from every registered vendor (the server resolves
    // the display name to its NVD term) and select the first available vendor.
    async function vwInit() {
        const btnWrap = document.getElementById('vwVendorBtns');
        if (!btnWrap) return;
        try {
            const res = await apiFetch('/api/vendors');
            if (!res || !res.ok) return;
            const vendors = await res.json();
            const entries = Object.entries(vendors || {});
            // Escape per il contesto stringa JS (dentro l'onclick single-quoted) PRIMA
            // di passare per escapeHtml (contesto attributo HTML) — stesso pattern di
            // analyzeTenant(tenant) più sopra: l'entity-encoding da solo non basta a
            // prevenire una breakout di stringa JS dentro l'attributo.
            const jsStr = s => String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
            btnWrap.innerHTML = entries.map(([name], idx) =>
                `<button class="btn btn-secondary btn-small vw-vendor-btn${idx === 0 ? ' active' : ''}" data-term="${escapeHtml(name)}" data-action="vw-select-vendor" style="width:auto; margin:0;">${escapeHtml(name)}</button>`
            ).join('');
            if (entries.length) {
                // Nessuna query EUVD automatica all'apertura: il fetch parte solo
                // quando l'utente sceglie un vendor o preme aggiorna.
                vwState.vendor = entries[0][0];
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
                return [r.cve, r.product, r.vendor, r.summary].join(' ').toLowerCase().indexOf(q) !== -1;
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
            const productHtml = item.product && item.product !== '—'
                ? `<div style="font-weight:600;">${escapeHtml(item.product)}</div><div style="font-size:11px; color:var(--text-muted); text-transform:uppercase;">${escapeHtml(item.vendor)}</div>`
                : `<div style="font-weight:600; text-transform:uppercase;">${escapeHtml(item.vendor)}</div>`;
            return `
            <tr data-action="vw-open-drawer" data-idx="${idx}" style="cursor:pointer;">
                <td><div style="font-family:var(--font-code); font-weight:700;">${escapeHtml(item.cve)}</div></td>
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
        drawer.innerHTML = `
            <button class="btn btn-secondary btn-small" style="width:auto; margin-bottom:14px;" data-action="vw-close-drawer"><i class="fa-solid fa-xmark"></i></button>
            <h3 style="margin:0 0 6px; font-family:var(--font-code);">${escapeHtml(item.cve)}</h3>
            <div style="margin-bottom:10px; display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
              <span class="severity-pill severity-${item.severity}">${item.severity}</span>
              <span style="font-weight:600;">CVSS ${Number.isFinite(item.score) ? item.score.toFixed(1) : '—'}</span>
              <span style="color:var(--text-muted);">EPSS ${Number.isFinite(item.epss) ? item.epss.toFixed(1) + '%' : '—'}</span>
              ${item.exploited ? '<span class="badge" style="color:var(--danger); border-color:var(--danger); font-weight:700;">Exploited</span>' : ''}
            </div>
            <div style="margin-bottom:10px; font-weight:600;">${escapeHtml(item.vendor)}${item.product && item.product !== '—' ? ' · ' + escapeHtml(item.product) : ''}</div>
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
            sel.innerHTML = `<option value="all">${tr('uiAllTenants')}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            sel.value = tenantSelectSeed(cur, groups, 'all');
        }
        startThreatScan();
    }

    // Costruisce la lista di dispositivi da analizzare; le query EUVD reali partono
    // solo al clic del pulsante "Analizza" su ogni singolo dispositivo.
    async function startThreatScan() {
        if (window._threatScanBusy) {
            // NON si scarta la richiesta piu' recente. E' quella che riflette
            // cio' che l'operatore ha appena scelto: buttarla via lascia sullo
            // schermo il risultato del filtro PRECEDENTE, che si legge come se
            // il filtro nuovo non avesse effetto. Il giro in corso finisce, poi
            // si rifa' con la selezione attuale.
            window._threatScanAgain = true;
            return;
        }
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
            // Una sola ripetizione, non una per ogni click arrivato nel
            // frattempo: il flag e' un "c'e' qualcosa di piu' recente", e il
            // giro che parte adesso legge comunque la selezione attuale.
            if (window._threatScanAgain) {
                window._threatScanAgain = false;
                startThreatScan();
            }
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
        // Il modello va anche a parte: serve al server per capire quali CVE
        // riguardano davvero questo apparato e quali altri modelli sullo
        // stesso treno software.
        await runEuvdQuery(safeIpId, vendor, queryText, null, null, validModel);
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
            ? (tr('tiHideResults'))
            : (tr('tiShowResults'));
        btn.innerHTML = `<i class="fa-solid fa-chevron-${hidden ? 'up' : 'down'}"></i> ${label}`;
    }

    async function runEuvdQuery(safeId, vendor, version, statusElId, resultsElId, model) {
        const effectiveResultsId = resultsElId || `results-${safeId}`;
        const statusEl  = document.getElementById(statusElId  || `status-${safeId}`);
        const resultsEl = document.getElementById(effectiveResultsId);
        if (!statusEl || !resultsEl) return;

        // Il vendor viene incluso solo se noto (altrimenti si cerca solo per testo);
        // il proxy lo risolve nel termine EUVD corretto (es. fortinet).
        const params = new URLSearchParams();
        if (vendor && vendor.trim()) params.set('vendor', vendor.trim());
        params.set('text', version);
        if (model && model.trim()) params.set('model', model.trim());
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
                    // Il totale e' quello dichiarato da NVD, non quante
                    // schede si mostrano: dire "3" con 69 CVE che toccano
                    // la versione installata sottostima l'esposizione.
                    const shown = Math.min(3, items.length);
                    const total = (typeof vulnData.total === "number" && vulnData.total > items.length)
                        ? vulnData.total : items.length;
                    const count = total > shown
                        ? tr('tiFoundShowingTop', {total: total, shown: shown})
                        : `${total} ${tr('tiVulnerabilitiesDetected')}`;
                    statusEl.innerHTML = `<span style="color: var(--danger);"><i class="fa-solid fa-triangle-exclamation"></i> ${count}</span>`;
                    const hideLabel = tr('tiHideResults');
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
                        // NVD attribuisce questo CVE ad altri modelli sullo
                        // stesso sistema operativo: si mostra comunque (il suo
                        // elenco hardware e' incompleto) ma detto chiaramente.
                        const otherModel = v.modelScope === 'other'
                            ? `<span class="chip" style="font-size:10px; margin-left:6px; color:var(--text-muted);">${escapeHtml(tr('tiOtherModel'))}</span>`
                            : '';
                        cardsEl.innerHTML += `
                            <div data-sev="${severity.toLowerCase()}" data-exploited="${exploitedFlag}" style="background:var(--surface-3); border: 1px solid var(--border); padding: 12px; border-radius: 0; font-size:13px;">
                                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
                                    <div style="display:flex; align-items:center; gap:8px;">
                                        <strong style="color:var(--primary);">${escapeHtml(cveId)}</strong>${otherModel}
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
                } else if (vulnData.versionUnknown) {
                    // NVD conosce il prodotto ma non questa versione:
                    // dirlo, invece di mostrare il segno di spunta verde.
                    // "Nessun dato" non e' "nessuna vulnerabilita".
                    statusEl.innerHTML = `<span style="color: var(--warning);"><i class="fa-solid fa-circle-question"></i> ${tr('tiVersionUnknown')}</span>`;
                    resultsEl.innerHTML = `<div style="color:var(--text-muted); font-size:13px;">${escapeHtml(tr('tiVersionUnknownHint'))}<br><code style="font-size:11px; color:var(--primary);">${escapeHtml(vulnData.query || '')}</code></div>`;
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

    // ===== Correlazione CVE: F9 (priorita') e F9b (resoconto per tenant) =====
    //
    // Regola che governa entrambe le viste: nessuna uscita puo' essere letta
    // come "non impattato". I punteggi riordinano e non nascondono, e il
    // perimetro di cio' che NON e' stato valutato compare sotto ogni tabella —
    // un punteggio senza perimetro viene letto come completo, e un ordinamento
    // letto come completo diventa un verdetto negativo per gli ultimi in lista.

    const cveState = { rows: [], tenants: [], tenant: 'all' };

    // Le voci di not_evaluated arrivano dal backend come chiavi stabili:
    // tradurle qui evita che il testo mostrato dipenda dalla lingua del server.
    // Le chiavi si scrivono per esteso e non come 'cveNe_' + k: la
    // concatenazione le rende invisibili a check_i18n_coverage.py e a
    // tests/test_i18n_keys.py, che e' come una traduzione mancante arriva a
    // produzione senza che nessun controllo se ne accorga.
    function cveNeLabel(key) {
        if (key === 'reachability') return tr('cveNe_reachability');
        if (key === 'switch_acls') return tr('cveNe_switch_acls');
        if (key === 'vrf') return tr('cveNe_vrf');
        if (key === 'physical_access') return tr('cveNe_physical_access');
        if (key === 'service_state') return tr('cveNe_service_state');
        return key;
    }

    function cveConfLabel(v) {
        if (v === 'exact') return tr('cveConf_exact');
        if (v === 'product') return tr('cveConf_product');
        return tr('cveConf_keyword');
    }

    function cveSvcLabel(v) {
        if (v === 'enabled') return tr('cveSvc_enabled');
        if (v === 'disabled') return tr('cveSvc_disabled');
        return tr('cveSvc_unknown');
    }

    function cveNotEvaluatedText(list) {
        if (!list || !list.length) return '';
        return tr('cveNotEvaluated', { list: list.map(cveNeLabel).join(', ') });
    }

    // Eta' della lettura di versione, stessa formula del resto dell'app.
    // Oltre una settimana passa a var(--warning): e' il punto in cui il dato
    // smette di descrivere la rete di adesso.
    function cveVersionAge(seenAt) {
        const unknown = `<span style="color:var(--warning);">${escapeHtml(tr('cveAgeUnknown'))}</span>`;
        const m = (seenAt || '').match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})/);
        if (!m) return unknown;
        const ts = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) / 1000;
        const h = (Date.now() / 1000 - ts) / 3600;
        return `<span style="color:${h > 168 ? 'var(--warning)' : 'var(--text-muted)'};">${escapeHtml(relativeAge(h))}</span>`;
    }

    async function cvePriorityLoad() {
        const body = document.getElementById('cvePrioBody');
        const status = document.getElementById('cvePrioStatus');
        if (!body || !status) return;

        const sel = cveFillTenantSelect('cvePrioTenant');

        status.textContent = tr('cveLoading');
        body.innerHTML = '';
        const res = await apiFetch('/api/cve/priority?tenant=' +
            encodeURIComponent(sel ? sel.value : 'all'));
        if (!res || !res.ok) { status.textContent = tr('cveLoadError'); return; }
        const data = await res.json();
        cveState.rows = data.rows || [];

        const scope = document.getElementById('cvePrioScope');
        if (scope) scope.textContent = cveNotEvaluatedText(data.not_evaluated);

        if (!cveState.rows.length) {
            status.textContent = tr('cveNoSnapshot');
            return;
        }
        status.textContent = data.total > cveState.rows.length
            ? tr('cveTruncated', { n: cveState.rows.length, total: data.total })
            : tr('cveRowCount', { n: data.total });

        body.innerHTML = cveState.rows.map((r, i) => {
            const stale = r.stale
                ? ` <span class="badge" style="background:color-mix(in srgb, var(--warning) 18%, transparent); color:var(--warning);">${escapeHtml(tr('cveStale'))}</span>`
                : '';
            const cvss = (r.cvss === null || r.cvss === undefined) ? '&mdash;' : escapeHtml(String(r.cvss));
            return `<tr data-action="cve-factors" data-idx="${i}" style="cursor:pointer;">
                <td>${escapeHtml(r.device || '')}<div style="font-size:11px; color:var(--text-muted);">${escapeHtml(r.tenant || '')}</div></td>
                <td><code>${escapeHtml(r.id || '')}</code>${stale}</td>
                <td>${cvss}</td>
                <td>${escapeHtml(cveConfLabel(r.confidence))}</td>
                <td>${escapeHtml(cveSvcLabel(r.service))}</td>
                <td>${cveVersionAge(r.version_seen_at)}</td>
                <td><b>${escapeHtml(String(r.score))}</b></td>
            </tr>
            <tr id="cveFactors-${i}" hidden><td colspan="7" style="background:var(--surface-2); font-size:12px; line-height:1.6;"></td></tr>`;
        }).join('');
    }

    // Il punteggio non e' un numero magico: si apre nei suoi fattori. Se un
    // operatore non puo' ricostruire perche' una riga sta sopra un'altra non
    // si fidera' dell'ordine, e un ordine di cui non ci si fida non viene usato.
    function cveToggleFactors(idx) {
        const row = document.getElementById('cveFactors-' + idx);
        const r = cveState.rows[idx];
        if (!row || !r || !row.firstElementChild) return;
        if (!row.hidden) { row.hidden = true; return; }
        const f = r.factors || {};
        const svcList = (r.services || []).join(', ') || tr('cveSvcNone');
        row.firstElementChild.innerHTML =
            `<div>${escapeHtml(tr('cveFactorFormula', { cvss: f.cvss, cf: f.confidence_factor, sf: f.service_factor, score: r.score }))}</div>`
            + `<div style="color:var(--text-muted);">${escapeHtml(tr('cveFactorConfidence', { v: cveConfLabel(r.confidence) }))}`
            + ` &middot; ${escapeHtml(tr('cveFactorService', { v: cveSvcLabel(r.service), list: svcList }))}`
            + (f.stale ? ` &middot; ${escapeHtml(tr('cveFactorStale'))}` : '')
            + `</div><div style="margin-top:6px;">${escapeHtml(r.summary || '')}</div>`;
        row.hidden = false;
    }

    // Le due viste CVE hanno ognuna il proprio selettore, popolato alla prima
    // apertura e seminato con il tenant globale: chi sceglie una sede in cima
    // alla pagina si aspetta di vedere quella sede anche qui.
    function cveFillTenantSelect(id) {
        const sel = document.getElementById(id);
        if (sel && sel.options.length <= 1) {
            const groups = Object.keys(globalGroups || {});
            sel.innerHTML = `<option value="all">${tr('uiAllTenants')}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
            sel.value = tenantSelectSeed('', groups, 'all');
        }
        return sel;
    }

    async function cveReportLoad() {
        const body = document.getElementById('cveReportBody');
        const cov = document.getElementById('cveReportCoverage');
        if (!body || !cov) return;
        const sel = cveFillTenantSelect('cveReportTenant');
        cveState.tenant = sel ? sel.value : 'all';
        body.innerHTML = '';
        cveRenderMethod();
        const res = await apiFetch('/api/cve/summary?tenant=' +
            encodeURIComponent(cveState.tenant));
        if (!res || !res.ok) { cov.textContent = tr('cveLoadError'); return; }
        cveState.tenants = (await res.json()).tenants || [];
        cveReportRender();
    }

    // Da dove vengono i numeri. Lo stesso testo finisce nel PDF: un documento
    // che gira senza chi l'ha prodotto deve portarsi dietro il suo metodo.
    const CVE_METHOD_KEYS = ['cveMethDevices', 'cveMethWithVersion', 'cveMethExactCpe',
                             'cveMethSeverity', 'cveMethCap', 'cveMethOldest',
                             'cveMethNotEvaluated'];

    function cveMethodParagraphs() {
        return [tr('cveMethIntro')]
            .concat(CVE_METHOD_KEYS.map(k => cveMethodText(k)))
            .concat([tr('cveMethNever')]);
    }

    // Chiavi per esteso, non tr(k): la concatenazione le rende invisibili ai
    // controlli sull'i18n.
    function cveMethodText(key) {
        if (key === 'cveMethDevices') return tr('cveMethDevices');
        if (key === 'cveMethWithVersion') return tr('cveMethWithVersion');
        if (key === 'cveMethExactCpe') return tr('cveMethExactCpe');
        if (key === 'cveMethSeverity') return tr('cveMethSeverity');
        if (key === 'cveMethCap') return tr('cveMethCap');
        if (key === 'cveMethOldest') return tr('cveMethOldest');
        return tr('cveMethNotEvaluated');
    }

    function cveRenderMethod() {
        const box = document.getElementById('cveReportMethodBody');
        if (!box) return;
        box.innerHTML = cveMethodParagraphs()
            .map(t => `<p style="margin:0 0 10px;">${t}</p>`).join('');
    }

    function cveReportRender() {
        const body = document.getElementById('cveReportBody');
        const cov = document.getElementById('cveReportCoverage');
        const scope = document.getElementById('cveReportScope');
        if (!body || !cov || !scope) return;
        const rows = cveState.tenants;

        // Le due frasi che l'aggregato non puo' tacere: quanti apparati non
        // sono nei conteggi, e quali conteggi sono tagliati dal tetto. Frasi,
        // non icone e non asterischi: sono esattamente le cose che verranno
        // fraintese.
        const notes = [];
        const partial = rows.filter(t => t.with_version < t.devices);
        if (partial.length) {
            const missing = partial.reduce((a, t) => a + (t.devices - t.with_version), 0);
            const total = partial.reduce((a, t) => a + t.devices, 0);
            notes.push(tr('cveCoveragePartial', { n: missing, m: total }));
        }
        const capped = rows.filter(t => t.truncated);
        if (capped.length) notes.push(tr('cveTruncatedNote', { n: capped.length }));
        cov.innerHTML = notes
            .map(t => `<div style="color:var(--warning); font-weight:700;">${escapeHtml(t)}</div>`)
            .join('');

        body.innerHTML = rows.map((t, i) => {
            // Il '>=' dice che il numero e' un pavimento, non una misura.
            const ge = t.truncated ? '&ge;&nbsp;' : '';
            const caret = `<i class="fa-solid fa-chevron-right" id="cveCaret-${i}" style="font-size:10px; color:var(--text-muted); margin-right:6px; transition:transform .15s;"></i>`;
            return `<tr data-action="cve-tenant" data-idx="${i}" style="cursor:pointer;">
                <td>${caret}${escapeHtml(t.tenant || '')}</td>
                <td>${t.devices}</td>
                <td${t.with_version < t.devices ? ' style="color:var(--warning); font-weight:700;"' : ''}>${t.with_version}</td>
                <td>${t.exact_cpe}</td>
                <td>${ge}${t.counts.critical}</td>
                <td>${ge}${t.counts.high}</td>
                <td>${ge}${t.counts.medium}</td>
                <td>${cveVersionAge(t.oldest_version_seen_at)}</td>
            </tr>
            <tr id="cveTenant-${i}" hidden><td colspan="8" style="background:var(--surface-2); padding:0;"></td></tr>`;
        }).join('');

        // Il perimetro del verdetto non puo' sparire quando si sale di livello,
        // altrimenti l'aggregato sembra piu' sicuro del dettaglio da cui nasce.
        const union = new Set();
        rows.forEach(t => (t.not_evaluated || []).forEach(k => union.add(k)));
        scope.textContent = cveNotEvaluatedText([...union].sort());
    }

    // Un totale di tenant e' quasi sempre un apparato solo che lo domina.
    // Aprire la riga deve rispondere subito a "chi mi ha fatto questo numero":
    // per questo il dettaglio e' per APPARATO e non per vendor — raggruppare
    // per vendor rimescolerebbe l'apparato anomalo con i suoi simili, che e'
    // proprio cio' che l'aggregato gia' faceva.
    function cveToggleTenant(idx) {
        const row = document.getElementById('cveTenant-' + idx);
        const caret = document.getElementById('cveCaret-' + idx);
        const t = cveState.tenants[idx];
        if (!row || !t || !row.firstElementChild) return;
        if (!row.hidden) {
            row.hidden = true;
            if (caret) caret.style.transform = '';
            return;
        }
        const rowsHtml = (t.devices_detail || []).map((d, i) => {
            const none = d.confidence === 'none';
            const cap = d.truncated
                ? ` <span title="${escapeHtml(tr('cveTruncatedHint', { total: d.total_available || '?' }))}" style="color:var(--warning); font-weight:700;">&ge;</span>`
                : '';
            const conf = none
                ? `<span style="color:var(--text-muted);">${escapeHtml(tr('cveConf_none'))}</span>`
                : escapeHtml(cveConfLabel(d.confidence));
            const host = d.hostname
                ? `<div style="font-size:11px; color:var(--text-muted);">${escapeHtml(d.hostname)}</div>`
                : '';
            const key = `${idx}-${i}`;
            const dcaret = `<i class="fa-solid fa-chevron-right" id="cveDevCaret-${key}" style="font-size:9px; color:var(--text-muted); margin-right:6px; transition:transform .15s;"></i>`;
            return `<tr data-action="cve-device" data-key="${key}" data-ip="${escapeHtml(d.ip || '')}" style="cursor:pointer;">
                <td>${dcaret}${escapeHtml(d.ip || '')}${host}</td>
                <td>${escapeHtml((d.vendor || '').toUpperCase())}</td>
                <td><code style="font-size:11px;">${escapeHtml(d.version || '—')}</code></td>
                <td>${conf}</td>
                <td>${cap}${d.cves}</td>
                <td>${d.counts.critical}</td>
                <td>${d.counts.high}</td>
                <td>${d.counts.medium}</td>
                <td>${cveVersionAge(d.version_seen_at)}</td>
            </tr>
            <tr id="cveDev-${key}" hidden><td colspan="9" style="padding:0;"></td></tr>`;
        }).join('');

        row.firstElementChild.innerHTML = `
            <div style="padding:12px 14px;">
              <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">${escapeHtml(tr('cveBreakdownHint'))}</div>
              <div class="table-wrap"><table style="font-size:12px;">
                <thead><tr>
                  <th>${escapeHtml(tr('cveThDevice'))}</th>
                  <th>Vendor</th>
                  <th>${escapeHtml(tr('cveThVersion'))}</th>
                  <th>${escapeHtml(tr('cveThConfidence'))}</th>
                  <th>${escapeHtml(tr('cveThCves'))}</th>
                  <th>${escapeHtml(tr('cveThCritical'))}</th>
                  <th>${escapeHtml(tr('cveThHigh'))}</th>
                  <th>${escapeHtml(tr('cveThMedium'))}</th>
                  <th>${escapeHtml(tr('cveThVersionAge'))}</th>
                </tr></thead><tbody>${rowsHtml}</tbody></table></div>
            </div>`;
        row.hidden = false;
        if (caret) caret.style.transform = 'rotate(90deg)';
    }


    // Terzo livello: quali CVE, non quante. Il conteggio dice che c'e' lavoro,
    // l'elenco dice quale. Si legge da /api/cve/{ip}, che gia' esiste e gia'
    // restituisce le righe con punteggio e fattori: una rotta nuova sarebbe un
    // secondo ordinamento da tenere allineato a quello della scheda Priorita'.
    const CVE_DEVICE_ROWS = 25;

    async function cveToggleDevice(key, ip) {
        const row = document.getElementById('cveDev-' + key);
        const caret = document.getElementById('cveDevCaret-' + key);
        if (!row || !row.firstElementChild) return;
        if (!row.hidden) {
            row.hidden = true;
            if (caret) caret.style.transform = '';
            return;
        }
        row.hidden = false;
        if (caret) caret.style.transform = 'rotate(90deg)';
        row.firstElementChild.innerHTML =
            `<div style="padding:10px 14px; color:var(--text-muted);">${escapeHtml(tr('cveLoading'))}</div>`;

        const res = await apiFetch('/api/cve/' + encodeURIComponent(ip));
        if (!res || !res.ok) {
            row.firstElementChild.innerHTML =
                `<div style="padding:10px 14px; color:var(--danger);">${escapeHtml(tr('cveLoadError'))}</div>`;
            return;
        }
        const data = await res.json();
        const all = data.rows || [];
        const shown = all.slice(0, CVE_DEVICE_ROWS);
        const more = all.length - shown.length;

        const body = shown.map(r => {
            const stale = r.stale
                ? ` <span style="color:var(--warning); font-size:10px;">${escapeHtml(tr('cveStale'))}</span>`
                : '';
            const cvss = (r.cvss === null || r.cvss === undefined) ? '&mdash;' : escapeHtml(String(r.cvss));
            return `<tr>
                <td><code style="font-size:11px;">${escapeHtml(r.id || '')}</code>${stale}</td>
                <td>${cvss}</td>
                <td>${escapeHtml(r.severity || '')}</td>
                <td>${escapeHtml(cveSvcLabel(r.service))}</td>
                <td><b>${escapeHtml(String(r.score))}</b></td>
                <td class="cve-desc" data-action="cve-desc" role="button" tabindex="0"
                    title="${escapeHtml(tr('cveDescToggle'))}"
                    style="max-width:52ch; color:var(--text-muted);">${escapeHtml(r.summary || '')}</td>
            </tr>`;
        }).join('');

        const moreLine = more > 0
            ? `<div style="font-size:12px; color:var(--text-muted); margin-top:6px;">${escapeHtml(tr('cveMoreRows', { n: more }))}</div>`
            : '';

        row.firstElementChild.innerHTML = `
            <div style="padding:10px 14px 14px 28px;">
              <div style="font-size:12px; color:var(--text-muted); margin-bottom:6px;">${escapeHtml(tr('cveDevCveHint'))}</div>
              <div class="table-wrap"><table style="font-size:12px;">
                <thead><tr>
                  <th>CVE</th><th>CVSS</th><th>${escapeHtml(tr('cveThSeverity'))}</th>
                  <th>${escapeHtml(tr('cveThService'))}</th><th>${escapeHtml(tr('cveThScore'))}</th>
                  <th>${escapeHtml(tr('cveThSummary'))}</th>
                </tr></thead><tbody>${body}</tbody></table></div>
              ${moreLine}
            </div>`;
    }

    // Export lato client come le altre tabelle. La riga di copertura entra nel
    // file: senza, l'export afferma qualcosa che il prodotto non sa.
    function cveReportExport() {
        if (!cveState.tenants.length) return;
        const cols = ['tenant', 'devices', 'with_version', 'exact_cpe',
                      'critical', 'high', 'medium', 'oldest_version_seen_at',
                      'truncated', 'not_evaluated'];
        const lines = [cols.join(',')];
        cveState.tenants.forEach(t => lines.push([
            csvCell(t.tenant), csvCell(t.devices), csvCell(t.with_version),
            csvCell(t.exact_cpe), csvCell(t.counts.critical), csvCell(t.counts.high),
            csvCell(t.counts.medium), csvCell(t.oldest_version_seen_at),
            csvCell(t.truncated ? 'yes' : 'no'),
            csvCell((t.not_evaluated || []).join(' '))
        ].join(',')));
        const partial = cveState.tenants.filter(t => t.with_version < t.devices);
        if (partial.length) {
            const missing = partial.reduce((a, t) => a + (t.devices - t.with_version), 0);
            const total = partial.reduce((a, t) => a + t.devices, 0);
            lines.push('');
            lines.push(csvCell(tr('cveCoveragePartial', { n: missing, m: total })));
        }
        // BOM: senza, Excel legge gli accenti come mojibake.
        const blob = new Blob(['﻿' + lines.join('\r\n')],
                              { type: 'text/csv;charset=utf-8;' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'sentinelnet-cve-tenant-' + new Date().toISOString().slice(0, 10) + '.csv';
        a.click();
        URL.revokeObjectURL(a.href);
    }

    document.getElementById('tiTabPriority')?.addEventListener('click', () => tiSwitchView('priority'));
    document.getElementById('tiTabReport')?.addEventListener('click', () => tiSwitchView('report'));
    document.getElementById('cvePrioTenant')?.addEventListener('change', cvePriorityLoad);
    document.getElementById('cvePrioRefresh')?.addEventListener('click', cvePriorityLoad);
    document.getElementById('cveReportRefresh')?.addEventListener('click', cveReportLoad);
    document.getElementById('cveReportExport')?.addEventListener('click', cveReportExport);
    document.getElementById('cvePrioBody')?.addEventListener('click', (e) => {
        const row = e.target.closest('[data-action="cve-factors"]');
        if (row) cveToggleFactors(Number(row.dataset.idx));
    });

    // ===== Resoconto CVE in PDF =====
    //
    // Si riusa la stampa headless gia' in casa (`/api/netsec-audit/report/pdf`,
    // che riceve HTML e lo stampa con il browser di sistema). Una seconda via
    // di stampa vorrebbe dire due impaginazioni da mantenere allineate, e il
    // giorno che divergono e' il PDF consegnato al cliente a sbagliare.
    //
    // Il documento e' autoconsistente: il printer risolve `MAP * ~NOTFOUND`,
    // quindi ogni foglio di stile o font esterno sarebbe silenziosamente
    // assente. Tutto lo stile sta qui dentro.
    const CVE_PDF_CSS = `
        /* Chrome headless scarta gli sfondi in stampa se non glielo si vieta.
           Il documento regge comunque senza — filetti e peso del carattere
           portano la gerarchia, il colore la rinforza e basta. */
        * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
               color:#1a1d23; margin:26mm 16mm 18mm; font-size:10.5pt; line-height:1.5; }

        /* Testata: un filetto spesso nel blu d'inchiostro, non un banner. */
        .cover { border-top:3px solid #1f4e79; padding-top:12px; margin-bottom:24px; }
        .kicker { font-size:8pt; letter-spacing:.16em; text-transform:uppercase;
                  color:#1f4e79; font-weight:700; margin:0 0 6px; }
        h1 { font-size:21pt; margin:0 0 2px; letter-spacing:-.01em; }
        .meta { color:#565d6b; font-size:9pt; margin:0; }

        /* Sei riquadri: il conteggio e il suo denominatore nello stesso sguardo. */
        .kpis { display:flex; flex-wrap:wrap; gap:0; border:1px solid #d4d8de;
                margin:20px 0 6px; }
        .kpi { flex:1 1 16%; padding:9px 11px; border-right:1px solid #d4d8de; }
        .kpi:last-child { border-right:0; }
        .kpi dt { font-size:7.5pt; letter-spacing:.09em; text-transform:uppercase;
                  color:#565d6b; font-weight:700; margin:0; }
        .kpi dd { margin:2px 0 0; font-size:17pt; font-weight:600;
                  font-variant-numeric:tabular-nums; letter-spacing:-.02em; }
        .kpi dd .of { font-size:9pt; font-weight:400; color:#565d6b; }
        .kpi.crit dd { color:#9b1c1c; }
        .kpi.high dd { color:#a55a00; }
        .kpi.short dd { color:#a55a00; }

        /* Una barra, tre segmenti: la forma della severita' prima dei numeri. */
        .bar { display:flex; height:9px; margin:10px 0 4px; border:1px solid #d4d8de; }
        .bar i { display:block; }
        .barkey { font-size:8pt; color:#565d6b; margin:0 0 18px; }
        .barkey b { font-weight:600; color:#1a1d23; }
        .barkey .sq { display:inline-block; width:7px; height:7px; margin-right:4px; }

        /* Avviso da manuale tecnico: filetti sopra e sotto, nessun fondino.
           La barra colorata a sinistra su un riquadro pieno e' un modo di dire
           da interfaccia web, non da documento stampato — e soprattutto poggia
           su uno sfondo, cioe' proprio la cosa che la stampa puo' scartare.
           Un avviso deve restare visibile esattamente in quel caso. */
        .notice { border-top:1px solid #a55a00; border-bottom:1px solid #a55a00;
                  padding:7px 0; margin:10px 0 8px; font-size:9pt;
                  color:#7a4a00; font-weight:600; }
        .notice b { font-weight:700; }

        /* The index title is an h3 so that, in the PDF bookmarks built from
           the headings, it sits beside the devices under the tenant instead
           of swallowing them as its children. It still looks like an h2. */
        h2, h3.idx { font-size:11pt; margin:26px 0 8px; padding-bottom:4px;
             border-bottom:1.5px solid #1f4e79; letter-spacing:.02em; }
        a.idx-link { color:#1f4e79; text-decoration:none; }

        table { border-collapse:collapse; width:100%; margin:8px 0; font-size:9pt; }
        th { text-align:left; font-size:7.5pt; letter-spacing:.07em;
             text-transform:uppercase; color:#565d6b; font-weight:700;
             padding:5px 7px; border-bottom:1px solid #1a1d23; }
        td { padding:4px 7px; border-bottom:1px solid #e6e9ed; vertical-align:top; }
        tbody tr:nth-child(even) td { background:#f5f6f8; }
        td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
        .sev-c { color:#9b1c1c; font-weight:700; }
        .sev-h { color:#a55a00; font-weight:600; }
        .warn { color:#a55a00; font-weight:700; }
        .scope { color:#6b727f; font-size:8pt; margin:7px 0 0; }

        /* Le schede degli apparati: il corpo del documento. */
        .dev { margin-top:16px; padding-top:11px; border-top:1px solid #e6e9ed;
               page-break-inside:avoid; }
        .dev-name { font-size:11pt; font-weight:700; margin:0; color:#1f4e79; }
        .dev-name code { font-family:"Courier New",monospace; font-size:9.5pt;
                         font-weight:400; color:#1a1d23; margin-left:7px; }
        .dev-sub { font-size:8pt; color:#565d6b; margin:2px 0 7px; }
        /* One CVE = one tbody: the details row, then the description across
           the full width. In its own column the description took half the
           page and left the short columns beside it empty. */
        table.cves { font-size:8pt; page-break-inside:auto; }
        table.cves th, table.cves td { padding:3px 6px; }
        /* Five short values spread over the full width read as five islands:
           keep them together on the left, the last column takes the rest. */
        table.cves th:nth-child(1) { width:20%; }
        table.cves th:nth-child(2) { width:7%; }
        table.cves th:nth-child(3) { width:12%; }
        table.cves th:nth-child(4) { width:14%; }
        table.cves th:nth-child(5), table.cves tr.cve-head td:nth-child(5) { text-align:left; }
        table.cves tbody { break-inside:avoid; page-break-inside:avoid; }
        table.cves tbody tr td { background:none; }
        table.cves tbody:nth-of-type(even) td { background:#f5f6f8; }
        table.cves tr.cve-head td { border-bottom:0; padding-bottom:1px; }
        table.cves tr.cve-desc td { padding-top:0; color:#3d434e; }

        .method { margin-top:28px; page-break-inside:avoid; }
        .method p { margin:0 0 8px; font-size:8.5pt; color:#3d434e; }
        .pagebreak { page-break-after:always; }
    `;

    // Nel PDF la data si scrive per esteso: "3 g" ha senso davanti a chi sa
    // quando ha aperto la pagina, un documento archiviato no.
    function cvePdfDate(seenAt) {
        const m = (seenAt || '').match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})/);
        if (!m) return tr('cveAgeUnknown');
        return `${m[3]}/${m[2]}/${m[1]} ${m[4]}:${m[5]} UTC`;
    }

    // La prima pagina deve rispondere da sola a "come sta messo questo tenant":
    // i sei numeri con i loro denominatori, la forma della severita', cosa non
    // e' stato guardato, e l'indice degli apparati che seguono. Una tabella di
    // sette righe seguita da mezza pagina bianca non lo faceva.
    function cvePdfTenantSection(t, ti) {
        const partial = t.with_version < t.devices;
        const ge = t.truncated ? '&ge;&nbsp;' : '';
        const c = t.counts.critical, h = t.counts.high, m = t.counts.medium;
        const tot = c + h + m;

        const kpi = (cls, label, value, of) => `<div class="kpi ${cls}">
            <dt>${escapeHtml(label)}</dt>
            <dd>${value}${of ? ` <span class="of">${escapeHtml(of)}</span>` : ''}</dd>
        </div>`;

        const bar = tot ? `<div class="bar">
              <i style="width:${(c / tot * 100).toFixed(1)}%; background:#9b1c1c"></i>
              <i style="width:${(h / tot * 100).toFixed(1)}%; background:#c8862c"></i>
              <i style="width:${(m / tot * 100).toFixed(1)}%; background:#9aa3ae"></i>
            </div>
            <p class="barkey">
              <span class="sq" style="background:#9b1c1c"></span><b>${c}</b> ${escapeHtml(tr('cveThCritical'))} &nbsp;
              <span class="sq" style="background:#c8862c"></span><b>${h}</b> ${escapeHtml(tr('cveThHigh'))} &nbsp;
              <span class="sq" style="background:#9aa3ae"></span><b>${m}</b> ${escapeHtml(tr('cveThMedium'))}
            </p>` : '';

        const notices = [];
        if (partial) {
            notices.push(tr('cveCoveragePartial',
                            { n: t.devices - t.with_version, m: t.devices }));
        }
        if (t.truncated) notices.push(tr('cveTruncatedNote', { n: 1 }));

        return `<section>
            <h2>${escapeHtml(t.tenant || '')}</h2>
            <div class="kpis">
              ${kpi('', tr('cveThDevices'), t.devices, '')}
              ${kpi(partial ? 'short' : '', tr('cveThWithVersion'), t.with_version, '/ ' + t.devices)}
              ${kpi('', tr('cveThExactCpe'), t.exact_cpe, '/ ' + t.devices)}
              ${kpi('crit', tr('cveThCritical'), ge + c, '')}
              ${kpi('high', tr('cveThHigh'), ge + h, '')}
              ${kpi('', tr('cveThMedium'), ge + m, '')}
            </div>
            ${bar}
            ${notices.map(n => `<p class="notice">${escapeHtml(n)}</p>`).join('')}
            <p class="scope">${escapeHtml(tr('cveThOldest'))}:
               ${escapeHtml(cvePdfDate(t.oldest_version_seen_at))} &nbsp;&middot;&nbsp;
               ${escapeHtml(cveNotEvaluatedText(t.not_evaluated))}</p>
            ${cvePdfIndex(t, ti)}
        </section>`;
    }

    // Anchor shared by an index row and its device section. Positional, not
    // the IP: an id must be a plain token, and the two lists iterate the same
    // devices_detail in the same order.
    function cvePdfAnchor(ti, di) {
        return `dev-${ti}-${di}`;
    }

    // L'indice: in un rapporto impaginato per apparato dice subito da quale
    // cominciare, e rende evidente quando un apparato solo domina il totale.
    // Each name links to its section: Chrome keeps internal links in the PDF.
    function cvePdfIndex(t, ti) {
        const rows = t.devices_detail || [];
        if (!rows.length) {
            // Un documento che stampa il nulla in silenzio e' peggio di uno che
            // manca: senza questa riga la mezza pagina bianca si legge come
            // "nessun apparato da segnalare".
            return `<p class="notice"><b>${escapeHtml(tr('cvePdfNoDetail'))}</b></p>`;
        }
        const body = rows.map((d, di) => `<tr>
            <td><a class="idx-link" href="#${cvePdfAnchor(ti, di)}">${escapeHtml(d.hostname || d.ip || '')}</a></td>
            <td>${escapeHtml(d.ip || '')}</td>
            <td>${escapeHtml(d.version || '—')}</td>
            <td>${escapeHtml(d.confidence === 'none' ? tr('cveConf_none') : cveConfLabel(d.confidence))}</td>
            <td class="num">${d.truncated ? '<span class="warn">&ge;</span> ' : ''}${d.cves}</td>
            <td class="num sev-c">${d.counts.critical || ''}</td>
            <td class="num sev-h">${d.counts.high || ''}</td>
            <td class="num">${d.counts.medium || ''}</td>
        </tr>`).join('');
        return `<h3 class="idx">${escapeHtml(tr('cvePdfIndexTitle'))}</h3>
            <table>
              <thead><tr>
                <th>${escapeHtml(tr('cveThDevice'))}</th><th>IP</th>
                <th>${escapeHtml(tr('cveThVersion'))}</th>
                <th>${escapeHtml(tr('cveThConfidence'))}</th>
                <th class="num">${escapeHtml(tr('cveThCves'))}</th>
                <th class="num">${escapeHtml(tr('cveThCritical'))}</th>
                <th class="num">${escapeHtml(tr('cveThHigh'))}</th>
                <th class="num">${escapeHtml(tr('cveThMedium'))}</th>
              </tr></thead><tbody>${body}</tbody></table>
            <div class="pagebreak"></div>`;
    }

    // Quante CVE elencare per apparato. Un rapporto che si allega a una mail
    // deve restare leggibile; oltre la soglia si dice quante ne restano invece
    // di stampare pagine che nessuno legge.
    const CVE_PDF_DEVICE_ROWS = 50;

    // Il rapporto e' impaginato PER APPARATO: chi lo riceve lavora su un
    // apparato alla volta, e una tabella piatta lo obbligava a ricomporre da
    // solo quali CVE fossero sue. Le righe vengono da /api/cve/priority, cioe'
    // dallo stesso ordinamento della scheda Priorita': il PDF e la schermata
    // non possono mettere in cima due CVE diverse.
    function cvePdfDeviceSection(d, rows, anchor) {
        const shown = rows.slice(0, CVE_PDF_DEVICE_ROWS);
        const more = rows.length - shown.length;

        const facts = [];
        if (d.version) facts.push(escapeHtml(d.version));
        facts.push(escapeHtml(d.confidence === 'none'
            ? tr('cveConf_none') : cveConfLabel(d.confidence)));
        if (d.version_seen_at) {
            facts.push(escapeHtml(tr('cvePdfVersionRead', { when: cvePdfDate(d.version_seen_at) })));
        }
        facts.push((d.truncated ? '&ge;&nbsp;' : '') +
                   escapeHtml(tr('cvePdfDeviceCves', { n: d.cves })));

        const body = shown.map(r => `<tbody><tr class="cve-head">
            <td>${escapeHtml(r.id || '')}</td>
            <td class="num">${r.cvss === null || r.cvss === undefined ? '&mdash;' : escapeHtml(String(r.cvss))}</td>
            <td>${escapeHtml(r.severity || '')}</td>
            <td>${escapeHtml(cveSvcLabel(r.service))}</td>
            <td class="num">${escapeHtml(String(r.score))}</td>
        </tr><tr class="cve-desc"><td colspan="5">${escapeHtml(r.summary || '')}</td></tr></tbody>`).join('');

        const table = shown.length ? `<table class="cves">
              <thead><tr>
                <th>CVE</th><th class="num">CVSS</th><th>${escapeHtml(tr('cveThSeverity'))}</th>
                <th>${escapeHtml(tr('cveThService'))}</th><th class="num">${escapeHtml(tr('cveThScore'))}</th>
              </tr></thead>${body}</table>`
            : `<p class="scope">${escapeHtml(tr(d.confidence === 'none' ? 'cvePdfNeverCorrelated' : 'cvePdfNoCve'))}</p>`;

        const moreLine = more > 0
            ? `<p class="scope">${escapeHtml(tr('cveMoreRows', { n: more }))}</p>` : '';

        return `<div class="dev">
            <h3 class="dev-name" id="${anchor}">${escapeHtml(d.hostname || d.ip || '')}
              <code>${escapeHtml(d.ip || '')}</code></h3>
            <p class="dev-sub">${facts.join(' &nbsp;|&nbsp; ')}</p>
            ${table}${moreLine}
            <p class="scope">${escapeHtml(cveNotEvaluatedText(d.not_evaluated))}</p>
        </div>`;
    }

    function cvePdfDevices(t, byDevice, ti) {
        return (t.devices_detail || [])
            .map((d, di) => cvePdfDeviceSection(d, (byDevice || {})[d.ip] || [], cvePdfAnchor(ti, di)))
            .join('');
    }

    function cvePdfHtml(byTenant) {
        const scope = cveState.tenant && cveState.tenant !== 'all'
            ? tr('cvePdfScopeOne', { tenant: cveState.tenant })
            : tr('cvePdfScopeAll');
        const title = tr('cvePdfTitle');
        const sections = cveState.tenants.map((t, ti) =>
            cvePdfTenantSection(t, ti) + cvePdfDevices(t, (byTenant || {})[t.tenant] || {}, ti)
        ).join('');
        return '<!doctype html>\n'
            + `<html lang="${currentLang}"><head><meta charset="utf-8">`
            + `<title>${escapeHtml(title)}</title><style>${CVE_PDF_CSS}</style></head><body>`
            + `<div class="cover"><p class="kicker">${escapeHtml(tr('cvePdfKicker'))}</p>`
            + `<h1>${escapeHtml(title)}</h1>`
            + `<p class="meta">${escapeHtml(tr('cvePdfGeneratedAt', { when: new Date().toLocaleString() }))}`
            + ` &middot; ${escapeHtml(scope)}</p></div>`
            + sections
            + `<div class="method"><h2>${escapeHtml(tr('cveMethTitle'))}</h2>`
            + cveMethodParagraphs().map(t => `<p>${t}</p>`).join('')
            + '</div></body></html>';
    }

    // Le CVE per il documento, raggruppate per tenant e poi per apparato: e'
    // la forma in cui il rapporto le stampa. Una sola richiesta —
    // /api/cve/priority applica gia' lo scope RBAC e l'ordinamento.
    async function cvePdfRows() {
        const res = await apiFetch('/api/cve/priority?limit=5000&tenant=' +
            encodeURIComponent(cveState.tenant || 'all'));
        if (!res || !res.ok) return {};
        const grouped = {};
        ((await res.json()).rows || []).forEach(r => {
            const t = grouped[r.tenant] = grouped[r.tenant] || {};
            (t[r.device] = t[r.device] || []).push(r);
        });
        return grouped;
    }

    async function cveReportPdf() {
        const btn = document.getElementById('cveReportPdf');
        if (!cveState.tenants.length) { showToast(tr('cvePdfNoData'), 'error'); return; }
        const orig = btn ? btn.innerHTML : '';
        if (btn) {
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> ${escapeHtml(tr('cveGeneratingPdf'))}`;
            btn.disabled = true;
        }
        try {
            const res = await apiFetch('/api/netsec-audit/report/pdf', {
                method: 'POST',
                body: JSON.stringify({
                    html: cvePdfHtml(await cvePdfRows()),
                    filename: 'sentinelnet-cve-' +
                        (cveState.tenant && cveState.tenant !== 'all' ? cveState.tenant : 'tenant') +
                        '-' + new Date().toISOString().slice(0, 10)
                })
            });
            if (!res || !res.ok) {
                const detail = res ? ((await res.json().catch(() => ({}))).detail || res.status)
                                   : 'network';
                showToast(tr('cvePdfError', { detail: detail }), 'error');
                return;
            }
            const blob = await res.blob();
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'sentinelnet-cve-tenant-' + new Date().toISOString().slice(0, 10) + '.pdf';
            a.click();
            URL.revokeObjectURL(a.href);
        } finally {
            if (btn) { btn.innerHTML = orig; btn.disabled = false; }
        }
    }

    document.getElementById('cveReportBody')?.addEventListener('click', (e) => {
        const desc = e.target.closest('[data-action="cve-desc"]');
        if (desc) { desc.classList.toggle('cve-desc-open'); return; }
        const dev = e.target.closest('[data-action="cve-device"]');
        if (dev) { cveToggleDevice(dev.dataset.key, dev.dataset.ip); return; }
        const row = e.target.closest('[data-action="cve-tenant"]');
        if (row) cveToggleTenant(Number(row.dataset.idx));
    });
    // La cella e' un pulsante a tutti gli effetti: chi naviga da tastiera deve
    // poterla aprire, altrimenti il testo oltre la seconda riga per lui non
    // esiste.
    document.getElementById('cveReportBody')?.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        const desc = e.target.closest('[data-action="cve-desc"]');
        if (desc) { e.preventDefault(); desc.classList.toggle('cve-desc-open'); }
    });

    document.getElementById('cveReportTenant')?.addEventListener('change', cveReportLoad);
    document.getElementById('cveReportPdf')?.addEventListener('click', cveReportPdf);
