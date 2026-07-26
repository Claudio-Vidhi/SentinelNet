// static/js/netsec-audit.js
// ===== NetSec Audit (PREVIEW) — Firewall & Router Security Compliance Audit =====

(function () {
    // Nessun dato fittizio: la lista viene popolata solo da una vera scansione
    // (POST /api/netsec-audit/scan). Vedi renderAuditOverview/renderAuditRulesTable
    // per lo stato vuoto mostrato prima della prima scansione.
    let _auditRules = [];

    async function applyNetSecAuditGating() {
        try {
            const res = await apiFetch('/api/settings/netsec-audit');
            if (!res || !res.ok) return;
            const data = await res.json();
            const nav = document.getElementById('navNetSecAudit');
            if (nav) nav.style.display = data.netsec_audit_preview ? '' : 'none';
            const toggle = document.getElementById('netsecAuditToggle');
            if (toggle) toggle.checked = !!data.netsec_audit_preview;
        } catch (e) {}
    }

    async function setNetSecAuditPreview(enabled) {
        const st = document.getElementById('netsecAuditStatus');
        try {
            const res = await apiFetch('/api/settings/netsec-audit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled: !!enabled })
            });
            if (res && res.ok) {
                if (st) st.textContent = currentLang === 'en' ? 'Saved.' : 'Salvato.';
                await applyNetSecAuditGating();
            }
        } catch (e) {
            if (st) st.textContent = currentLang === 'en' ? 'Error.' : 'Errore.';
        }
    }

    function loadNetSecAuditTab() {
        populateAuditDeviceSelect();
        renderAuditOverview();
        renderAuditRulesTable();
        setupConfigDropzone();
    }

    // Popola #auditDeviceSelect con l'inventario reale (già filtrato per sede
    // lato server). Non aggiunge MAI dispositivi inventati: se il fetch fallisce
    // o l'inventario è vuoto, resta solo l'opzione "Tutti".
    async function populateAuditDeviceSelect() {
        const sel = document.getElementById('auditDeviceSelect');
        if (!sel) return;
        // Segnaposto, non una funzionalita': la scansione multi-dispositivo non
        // esiste e il backend rifiuta 'all' con un messaggio esplicito.
        const allOption = '<option value="all">— Seleziona un dispositivo —</option>';
        try {
            const res = await apiFetch('/api/local-devices');
            if (!res || !res.ok) { sel.innerHTML = allOption; return; }
            const data = await res.json();
            const devices = (data && data.devices) || [];

            if (!devices.length) {
                sel.innerHTML = allOption
                    + `<option value="all" disabled>${currentLang === 'en' ? 'Inventory is empty — no devices found' : 'Inventario vuoto — nessun dispositivo presente'}</option>`;
                return;
            }

            const opts = devices.map(d => {
                const ip = d.IP || '';
                if (!ip) return '';
                const hostname = (d.Hostname || '').trim();
                const vendor = (d.Vendor || '').trim();
                const label = hostname
                    ? `${hostname} (${ip})${vendor ? ' — ' + vendor : ''}`
                    : `${ip}${vendor ? ' — ' + vendor : ''}`;
                return `<option value="${escapeHtml(ip)}">${escapeHtml(label)}</option>`;
            }).join('');

            sel.innerHTML = allOption + opts;
        } catch (e) {
            console.error('populateAuditDeviceSelect error:', e);
            sel.innerHTML = allOption;
        }
    }

    // Riepilogo e punteggio arrivano dal motore. NON ricalcolati qui: la regola
    // (UNKNOWN escluso dal denominatore) vive nel motore, e duplicarla lato
    // client vorrebbe dire prima o poi farle divergere.
    let _auditSummary = null;
    let _auditScore = null;

    function renderAuditOverview() {
        const s = _auditSummary || { total: 0, passed: 0, failed: 0, warned: 0, unknown: 0 };
        const unknown = s.unknown || 0;
        const score = _auditScore;
        const hasScore = (score !== null && score !== undefined);

        const scoreEl = document.getElementById('auditScoreValue');
        if (scoreEl) scoreEl.textContent = hasScore ? `${score}%` : '—';

        const gradeEl = document.getElementById('auditGradeBadge');
        if (gradeEl) {
            if (!hasScore) {
                gradeEl.textContent = !s.total
                    ? (currentLang === 'en' ? 'NO SCAN RUN YET' : 'NESSUNA SCANSIONE ESEGUITA')
                    : (currentLang === 'en' ? 'NOT ASSESSABLE' : 'NON DETERMINABILE');
                gradeEl.style.color = 'var(--text-muted)';
            } else {
                const grade = score >= 80 ? 'GRADE A' : score >= 60 ? 'GRADE B' : 'GRADE C - RISK DETECTED';
                // Un punteggio calcolato su meta' dei controlli non merita un
                // "GRADE A" secco: senza questa qualifica una config parziale
                // (3 regole su 6 valutabili, tutte PASS) mostrerebbe 100% GRADE A,
                // che e' rassicurante quanto il vecchio difetto che stiamo togliendo.
                gradeEl.textContent = unknown > 0
                    ? `${grade} — ${currentLang === 'en' ? 'PARTIAL' : 'PARZIALE'}`
                    : grade;
                gradeEl.style.color = unknown > 0
                    ? 'var(--warning)'
                    : (score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : 'var(--danger)');
            }
        }

        const banner = document.getElementById('auditPartialWarning');
        const bannerText = document.getElementById('auditPartialWarningText');
        if (banner && bannerText) {
            if (unknown > 0) {
                const assessed = s.total - unknown;
                bannerText.textContent = currentLang === 'en'
                    ? `Only ${assessed} of ${s.total} checks could be assessed: ${unknown} config section(s) are absent from the analysed file. The score covers the assessed checks only.`
                    : `Solo ${assessed} controlli su ${s.total} sono stati valutati: ${unknown} sezione/i di configurazione sono assenti nel file analizzato. Lo score copre soltanto i controlli valutabili.`;
                banner.style.display = '';
            } else {
                banner.style.display = 'none';
            }
        }

        const set = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };
        set('auditStatTotal', s.total);
        set('auditStatFailed', s.failed);
        set('auditStatPassed', s.passed);
        set('auditStatWarned', s.warned);
        set('auditStatUnknown', unknown);
    }

    function renderAuditRulesTable() {
        const tbody = document.getElementById('auditRulesTableBody');
        if (!tbody) return;

        if (!_auditRules.length) {
            tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--text-muted);">${currentLang==='en'?'No audit results yet. Select a device and run a scan.':'Nessun risultato di audit disponibile. Seleziona un dispositivo ed esegui una scansione.'}</td></tr>`;
            return;
        }

        const sevFilter = document.getElementById('auditSevFilter') ? document.getElementById('auditSevFilter').value : 'all';
        const catFilter = document.getElementById('auditCatFilter') ? document.getElementById('auditCatFilter').value : 'all';

        let filtered = _auditRules;
        if (sevFilter !== 'all') filtered = filtered.filter(r => r.severity.toLowerCase() === sevFilter.toLowerCase());
        if (catFilter !== 'all') filtered = filtered.filter(r => r.category.toLowerCase() === catFilter.toLowerCase());

        if (!filtered.length) {
            tbody.innerHTML = `<tr><td colspan="6" style="padding:20px; text-align:center; color:var(--text-muted);">${currentLang==='en'?'No audit rules match filter.':'Nessuna regola di audit corrisponde ai filtri.'}</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(r => {
            const statusBadge = r.status === 'PASS'
                ? `<span class="badge" style="background:rgba(34, 197, 94, 0.15); color:var(--success);"><i class="fa-solid fa-check"></i> PASS</span>`
                : r.status === 'FAIL'
                ? `<span class="badge" style="background:rgba(239, 68, 68, 0.15); color:var(--danger);"><i class="fa-solid fa-xmark"></i> FAIL</span>`
                : r.status === 'WARN'
                ? `<span class="badge" style="background:rgba(245, 158, 11, 0.15); color:var(--warning);"><i class="fa-solid fa-triangle-exclamation"></i> WARN</span>`
                : `<span class="badge" style="background:var(--surface-3); color:var(--text-muted);" title="${currentLang==='en'?'Config section absent: not assessable, excluded from the score.':'Sezione di configurazione assente: non valutabile, esclusa dallo score.'}"><i class="fa-solid fa-circle-question"></i> N/D</span>`;

            const sevBadge = r.severity === 'CRITICAL'
                ? `<span class="badge" style="background:var(--danger); color:#fff; font-weight:700;">CRITICAL</span>`
                : r.severity === 'HIGH'
                ? `<span class="badge" style="background:var(--warning); color:#000; font-weight:700;">HIGH</span>`
                : `<span class="badge" style="background:var(--surface-3);">MEDIUM</span>`;

            const ev = r.evidence || [];
            const evId = String(r.id).replace(/[^\w-]/g, '_');
            const evBtn = ev.length
                ? `<button class="btn btn-sm btn-secondary" style="padding:2px 8px; font-size:11px; margin-top:6px;" onclick="toggleAuditEvidence('${escapeHtml(evId)}')">
                       <i class="fa-solid fa-code"></i> ${ev.length} ${currentLang === 'en' ? 'evidence' : 'evidenze'}
                   </button>`
                : '';

            const evRows = ev.map(e => `
                <div style="display:flex; gap:10px; padding:3px 0; font-family:var(--font-code); font-size:11px; flex-wrap:wrap;">
                    <span style="color:var(--text-muted); min-width:60px;">${e.line ? (currentLang === 'en' ? 'line ' : 'riga ') + escapeHtml(String(e.line)) : '—'}</span>
                    <span style="color:var(--text-muted); min-width:190px;">${escapeHtml(e.context || '')}</span>
                    <span style="color:var(--danger);">${escapeHtml(e.text || '')}</span>
                </div>`).join('');

            return `<tr style="font-size:12px; border-top:1px solid var(--border);">
                <td style="padding:8px; font-family:var(--font-code); font-weight:700;">${escapeHtml(r.id)}</td>
                <td style="padding:8px;">
                    <div style="font-weight:700;">${escapeHtml(r.title)}</div>
                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(r.detail)}</div>
                    ${evBtn}
                </td>
                <td style="padding:8px;">${sevBadge}</td>
                <td style="padding:8px;"><span class="badge">${escapeHtml(r.category)}</span></td>
                <td style="padding:8px;">${statusBadge}</td>
                <td style="padding:8px;">
                    <code style="font-size:11px; color:var(--primary); background:var(--surface-2); padding:3px 6px; border-radius:4px; display:inline-block; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                        ${escapeHtml(r.remediation)}
                    </code>
                </td>
            </tr>
            ${ev.length ? `<tr id="auditEv-${escapeHtml(evId)}" style="display:none;">
                <td colspan="6" style="padding:8px 8px 12px 24px; background:var(--surface-2);">${evRows}</td>
            </tr>` : ''}`;
        }).join('');
    }

    function toggleAuditEvidence(ruleId) {
        const row = document.getElementById('auditEv-' + ruleId);
        if (row) row.style.display = (row.style.display === 'none') ? '' : 'none';
    }    let _droppedConfigText = null;

    async function runAuditScan() {
        const btn = document.getElementById('btnRunAuditScan');
        const benchmark = document.getElementById('auditBenchmarkSelect') ? document.getElementById('auditBenchmarkSelect').value : 'cis';
        const deviceIp = document.getElementById('auditDeviceSelect') ? document.getElementById('auditDeviceSelect').value : 'all';

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Audit in corso...`;
        }

        try {
            const res = await apiFetch('/api/netsec-audit/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    benchmark: benchmark,
                    device_ip: deviceIp,
                    config_text: _droppedConfigText || null
                })
            });

            if (res && res.ok) {
                const data = await res.json();
                // Assegnazione incondizionata: se una scansione non produce
                // regole, la tabella deve svuotarsi, non conservare i
                // risultati della scansione precedente su un altro apparato.
                _auditRules = data.rules || [];
                _auditSummary = data.summary || null;
                _auditScore = (data.score === undefined) ? null : data.score;
                renderAuditOverview();
                renderAuditRulesTable();
            } else if (res) {
                // Es. 404 "Nessun backup trovato per <ip>." — dettaglio già in
                // italiano lato backend, mostrato all'utente invece di essere
                // ignorato silenziosamente.
                let detail = '';
                try { const errData = await res.json(); detail = errData && errData.detail; } catch (e) {}
                showToast(detail || (currentLang === 'en' ? 'Audit scan failed.' : 'Scansione audit non riuscita.'), 'error');
            } else {
                showToast(currentLang === 'en' ? 'Audit scan failed.' : 'Scansione audit non riuscita.', 'error');
            }
        } catch (e) {
            console.error('Audit scan error:', e);
            showToast(currentLang === 'en' ? 'Audit scan failed.' : 'Scansione audit non riuscita.', 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-play"></i> Esegui Audit Scan`;
            }
        }
    }

    function setupConfigDropzone() {
        const zone = document.getElementById('auditDropZone');
        const fileInput = document.getElementById('auditFileInput');
        const dropText = document.getElementById('auditDropText');
        const benchSel = document.getElementById('auditBenchmarkSelect');
        if (!zone || !fileInput) return;

        if (benchSel && !benchSel.dataset.bound) {
            benchSel.dataset.bound = 'true';
            benchSel.addEventListener('change', () => runAuditScan());
        }

        zone.onclick = () => fileInput.click();

        zone.ondragover = e => { e.preventDefault(); zone.style.borderColor = 'var(--primary)'; };
        zone.ondragleave = () => { zone.style.borderColor = 'var(--border)'; };
        zone.ondrop = e => {
            e.preventDefault();
            zone.style.borderColor = 'var(--border)';
            if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
        };

        fileInput.onchange = () => {
            if (fileInput.files.length) handleFile(fileInput.files[0]);
        };

        function handleFile(file) {
            const reader = new FileReader();
            reader.onload = e => {
                _droppedConfigText = e.target.result;
                if (dropText) dropText.innerHTML = `<i class="fa-solid fa-file-code" style="color:var(--success);"></i><br>File <strong>${escapeHtml(file.name)}</strong> caricato. Analisi in corso...`;
                runAuditScan();
            };
            reader.readAsText(file);
        }
    }

    function exportAuditReport() {
        const score = document.getElementById('auditScoreValue')?.textContent || '--';
        const benchmark = document.getElementById('auditBenchmarkSelect')?.value?.toUpperCase() || 'CIS';
        alert(currentLang === 'en'
            ? `Report Compliance Security (${benchmark}) generato. Score: ${score}.`
            : `Report Compliance Security (${benchmark}) generato con successo. Score complessivo: ${score}.`);
    }

    // Expose functions globally
    window.loadNetSecAuditTab = loadNetSecAuditTab;
    window.applyNetSecAuditGating = applyNetSecAuditGating;
    window.setNetSecAuditPreview = setNetSecAuditPreview;
    window.runAuditScan = runAuditScan;
    window.exportAuditReport = exportAuditReport;
    window.renderAuditRulesTable = renderAuditRulesTable;
    window.toggleAuditEvidence = toggleAuditEvidence;
})();
