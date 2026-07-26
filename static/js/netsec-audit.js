// static/js/netsec-audit.js
// ===== NetSec Audit (PREVIEW) — Firewall & Router Security Compliance Audit =====

(function () {
    // Nessun dato fittizio: la lista viene popolata solo da una vera scansione
    // (POST /api/netsec-audit/scan). Vedi renderAuditOverview/renderAuditRulesTable
    // per lo stato vuoto mostrato prima della prima scansione.
    let _auditRules = [];

    // Righe espanse memorizzate per id: la tabella viene ricostruita ad ogni
    // render (filtri, nuova scansione) e senza questo l'espansione aperta si
    // chiuderebbe da sola. Dichiarata qui, non accanto a toggleAuditDetail,
    // perche' renderAuditRulesTable la legge: un const usato prima della
    // propria riga di dichiarazione e' nella temporal dead zone e basterebbe
    // una futura chiamata durante l'init del modulo per avere un ReferenceError.
    const _auditOpenRows = new Set();

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
            const isOpen = _auditOpenRows.has(evId);

            // Suggerimento del contenuto nascosto: quante evidenze ci sono.
            // Non e' un pulsante: l'intera riga fa da interruttore, due
            // comandi sovrapposti per la stessa azione confondono.
            const evHint = ev.length
                ? `<span class="badge" style="margin-top:6px; background:var(--surface-3); color:var(--text-muted);">
                       <i class="fa-solid fa-code"></i> ${ev.length} ${currentLang === 'en' ? 'evidence' : 'evidenze'}
                   </span>`
                : '';

            const evRows = ev.length ? `
                <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:.04em; margin:0 0 6px;">
                    ${currentLang === 'en' ? 'Evidence in the analysed config' : 'Evidenze nella configurazione analizzata'}
                </div>
                ${ev.map(e => `
                <div style="display:flex; gap:10px; padding:3px 0; font-family:var(--font-code); font-size:11px; flex-wrap:wrap;">
                    <span style="color:var(--text-muted); min-width:60px;">${e.line ? (currentLang === 'en' ? 'line ' : 'riga ') + escapeHtml(String(e.line)) : '—'}</span>
                    <span style="color:var(--text-muted); min-width:190px;">${escapeHtml(e.context || '')}</span>
                    <span style="color:var(--danger); word-break:break-all;">${escapeHtml(e.text || '')}</span>
                </div>`).join('')}` : '';

            return `<tr style="font-size:12px; border-top:1px solid var(--border); cursor:pointer;"
                        onclick="toggleAuditDetail('${escapeHtml(evId)}')"
                        title="${currentLang === 'en' ? 'Click to expand' : 'Clicca per espandere'}">
                <td style="padding:8px; font-family:var(--font-code); font-weight:700; white-space:nowrap;">
                    <i class="fa-solid fa-chevron-${isOpen ? 'down' : 'right'}" style="color:var(--text-muted); font-size:9px; margin-right:6px;"></i>${escapeHtml(r.id)}
                </td>
                <td style="padding:8px;">
                    <div style="font-weight:700;">${escapeHtml(r.title)}</div>
                    <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(r.detail)}</div>
                    ${evHint}
                </td>
                <td style="padding:8px;">${sevBadge}</td>
                <td style="padding:8px;"><span class="badge">${escapeHtml(r.category)}</span></td>
                <td style="padding:8px;">${statusBadge}</td>
                <td style="padding:8px;">
                    <code title="${escapeHtml(r.remediation)}" style="font-size:11px; color:var(--primary); background:var(--surface-2); padding:3px 6px; border-radius:4px; display:inline-block; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:middle;">${escapeHtml(r.remediation)}</code>
                </td>
            </tr>
            <tr id="auditEv-${escapeHtml(evId)}" style="${isOpen ? '' : 'display:none;'}">
                <td colspan="6" style="padding:12px 12px 14px 30px; background:var(--surface-2); border-top:1px solid var(--border);">
                    <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:.04em; margin-bottom:6px;">
                        ${currentLang === 'en' ? 'Recommendation / CLI fix' : 'Raccomandazione / Fix CLI'}
                    </div>
                    <code style="display:block; font-size:12px; color:var(--primary); background:var(--surface); padding:8px 10px; border-radius:6px; border:1px solid var(--border); white-space:pre-wrap; word-break:break-word; margin-bottom:${ev.length ? '12px' : '0'};">${escapeHtml(r.remediation)}</code>
                    ${evRows}
                </td>
            </tr>`;
        }).join('');
    }

    function toggleAuditDetail(ruleId) {
        if (_auditOpenRows.has(ruleId)) _auditOpenRows.delete(ruleId);
        else _auditOpenRows.add(ruleId);
        renderAuditRulesTable();
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

    // Report HTML scaricabile. Nessuna dipendenza esterna: si costruisce il
    // documento e lo si scarica via Blob, coerentemente col resto dell'app.
    function exportAuditReport() {
        if (!_auditRules.length) {
            showToast(currentLang === 'en'
                ? 'Run a scan before exporting a report.'
                : 'Esegui una scansione prima di esportare il report.', 'warning');
            return;
        }
        const benchSel = document.getElementById('auditBenchmarkSelect');
        const benchmark = benchSel ? benchSel.options[benchSel.selectedIndex].text : 'CIS';
        const devSel = document.getElementById('auditDeviceSelect');
        const device = devSel ? devSel.options[devSel.selectedIndex].text : '—';
        const s = _auditSummary || { total: 0, passed: 0, failed: 0, warned: 0, unknown: 0 };
        const unknown = s.unknown || 0;
        const hasScore = (_auditScore !== null && _auditScore !== undefined);
        const scoreTxt = hasScore ? (_auditScore + '%') : 'N/D';
        const generated = new Date().toLocaleString();

        const rows = _auditRules.map(r => {
            const ev = (r.evidence || []).map(e =>
                `<div class="ev"><span>${e.line ? ('riga ' + escapeHtml(String(e.line))) : '—'}</span>`
                + `<span>${escapeHtml(e.context || '')}</span>`
                + `<code>${escapeHtml(e.text || '')}</code></div>`).join('');
            const label = r.status === 'UNKNOWN' ? 'NON VALUTABILE' : escapeHtml(r.status);
            return `<tr class="st-${escapeHtml(r.status)}">
                <td><strong>${escapeHtml(r.id)}</strong></td>
                <td>${escapeHtml(r.title)}<div class="detail">${escapeHtml(r.detail)}</div>${ev}</td>
                <td>${escapeHtml(r.severity)}</td>
                <td>${label}</td>
                <td><code>${escapeHtml(r.remediation)}</code></td>
            </tr>`;
        }).join('');

        // Se qualcosa non era valutabile va detto in testa al report, non solo
        // in nota: un lettore che vede "100%" senza contesto conclude che tutto
        // sia stato verificato.
        const partialBanner = unknown > 0
            ? `<div class="warn"><strong>Valutazione parziale.</strong> ${s.total - unknown} controlli su ${s.total}
               sono stati valutati; ${unknown} non lo sono perche' le relative sezioni di configurazione
               sono assenti nel file analizzato. Lo score si riferisce ai soli controlli valutabili.</div>`
            : '';

        const html = `<!doctype html><html lang="it"><head><meta charset="utf-8">
<title>Report Audit — ${escapeHtml(device)}</title>
<style>
body{font-family:system-ui,sans-serif;margin:32px;color:#111;}
h1{font-size:20px;margin:0 0 4px;} .meta{color:#666;font-size:13px;margin-bottom:20px;}
.warn{border:1px solid #a60;background:#fff8e6;color:#7a4d00;padding:10px 14px;border-radius:8px;margin-bottom:18px;font-size:13px;line-height:1.5;}
.kpis{display:flex;gap:20px;margin-bottom:20px;flex-wrap:wrap;}
.kpi{border:1px solid #ddd;border-radius:8px;padding:10px 16px;min-width:110px;font-size:12px;color:#666;}
.kpi b{display:block;font-size:22px;color:#111;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th,td{border-bottom:1px solid #e5e5e5;padding:8px;text-align:left;vertical-align:top;}
th{background:#f6f6f6;}
.detail{color:#666;margin-top:3px;}
.ev{display:flex;gap:10px;margin-top:4px;font-family:ui-monospace,monospace;font-size:11px;flex-wrap:wrap;}
.ev span:first-child{color:#999;min-width:60px;} .ev span:nth-child(2){color:#999;min-width:170px;}
.ev code{color:#b00;}
.st-FAIL td:nth-child(4){color:#b00;font-weight:700;}
.st-WARN td:nth-child(4){color:#a60;font-weight:700;}
.st-PASS td:nth-child(4){color:#070;font-weight:700;}
.st-UNKNOWN td:nth-child(4){color:#888;font-weight:700;}
.note{margin-top:20px;font-size:12px;color:#666;border-top:1px solid #ddd;padding-top:10px;line-height:1.5;}
@media print {
    body { margin: 15mm 15mm; font-size: 10pt; }
    h1 { font-size: 16pt; }
    tr { page-break-inside: avoid; }
    .no-print { display: none !important; }
}
</style>
<script src="https://cdn.jsdelivr.net/npm/html2pdf.js@0.10.1/dist/html2pdf.bundle.min.js"></script>
<script>
    async function downloadPdf() {
        const btn = document.getElementById('btnPdfNetsec');
        if (btn) btn.textContent = 'Generazione PDF...';
        const noPrints = document.querySelectorAll('.no-print');
        noPrints.forEach(el => el.style.display = 'none');
        const opt = {
            margin: [10, 10, 10, 10],
            filename: 'audit-${(device || 'device').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}.pdf',
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2, useCORS: true, logging: false },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' }
        };
        try {
            if (typeof html2pdf !== 'undefined') {
                await html2pdf().set(opt).from(document.body).save();
            } else {
                window.print();
            }
        } catch (e) {
            console.error('PDF error:', e);
            window.print();
        } finally {
            noPrints.forEach(el => el.style.display = '');
            if (btn) btn.textContent = 'Scarica PDF';
        }
    }
    function downloadHtml() {
        const clone = document.body.cloneNode(true);
        const noPrints = clone.querySelectorAll('.no-print');
        noPrints.forEach(el => el.remove());
        const blob = new Blob(['<!DOCTYPE html><html>' + clone.outerHTML + '</html>'], { type: 'text/html;charset=utf-8' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'audit-${(device || 'device').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}.html';
        a.click();
    }
</script>
</head><body>
<div class="no-print" style="margin-bottom: 20px; padding: 12px 16px; background: #1e293b; color: white; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; font-family: system-ui, sans-serif;">
    <span style="font-size: 14px; font-weight: bold;">SentinelNet — Anteprima Report Compliance</span>
    <div style="display: flex; gap: 10px;">
        <button id="btnPdfNetsec" onclick="downloadPdf()" style="padding: 8px 16px; background: #10b981; color: white; border: none; border-radius: 6px; font-size: 13px; font-weight: bold; cursor: pointer;">Scarica PDF</button>
        <button onclick="window.print()" style="padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 6px; font-size: 13px; font-weight: bold; cursor: pointer;">Stampa</button>
        <button onclick="downloadHtml()" style="padding: 8px 16px; background: #64748b; color: white; border: none; border-radius: 6px; font-size: 13px; font-weight: bold; cursor: pointer;">Scarica HTML</button>
    </div>
</div>
<h1>Report di Compliance — ${escapeHtml(benchmark)}</h1>
<div class="meta">Apparato: ${escapeHtml(device)} · Generato il ${escapeHtml(generated)}</div>
${partialBanner}
<div class="kpis">
  <div class="kpi"><b>${escapeHtml(scoreTxt)}</b>Score</div>
  <div class="kpi"><b>${s.passed}</b>Conformi</div>
  <div class="kpi"><b>${s.failed}</b>Non conformi</div>
  <div class="kpi"><b>${s.warned}</b>Warning</div>
  <div class="kpi"><b>${unknown}</b>Non valutabili</div>
</div>
<table><thead><tr><th>ID</th><th>Controllo ed evidenze</th><th>Severita'</th><th>Esito</th><th>Rimedio</th></tr></thead>
<tbody>${rows}</tbody></table>
<div class="note">I controlli marcati "non valutabile" corrispondono a sezioni di configurazione assenti nel file analizzato: sono esclusi dal calcolo dello score e non vanno letti come conformita'.</div>
</body></html>`;

        const printWin = window.open('', '_blank');
        if (printWin) {
            printWin.document.write(html);
            printWin.document.close();
        } else {
            const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `audit-${(device || 'device').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
    }

    // Requisiti dichiarati dal motore, non una copia scritta a mano nella UI:
    // se una regola cambia titolo, severita' o rimedio, questo elenco segue.
    let _benchmarkCatalog = null;

    async function renderBenchmarkRequirements() {
        const details = document.getElementById('auditBenchmarkReqs');
        const body = document.getElementById('auditBenchmarkReqsBody');
        if (!body || !details || !details.open) return;

        const key = document.getElementById('auditBenchmarkSelect').value;
        if (!_benchmarkCatalog) {
            body.innerHTML = '<div style="font-size:12px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Caricamento requisiti...</div>';
            try {
                const res = await apiFetch('/api/netsec-audit/benchmarks');
                if (!res || !res.ok) {
                    body.innerHTML = '<div style="font-size:12px; color:var(--danger);">Impossibile caricare i requisiti.</div>';
                    return;
                }
                _benchmarkCatalog = await res.json();
            } catch (e) {
                body.innerHTML = '<div style="font-size:12px; color:var(--danger);">Errore di rete nel caricamento dei requisiti.</div>';
                return;
            }
        }

        const reqs = _benchmarkCatalog[key] || [];
        const sevColor = { CRITICAL: 'var(--danger)', HIGH: 'var(--danger)', MEDIUM: 'var(--warning)', LOW: 'var(--text-muted)' };
        body.innerHTML = `
            <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">${reqs.length} controlli eseguiti sulla configurazione analizzata.</div>
            <table style="width:100%; border-collapse:collapse; font-size:12px;">
                ${reqs.map(r => `
                    <tr style="border-top:1px solid var(--border);">
                        <td style="padding:8px 10px 8px 0; vertical-align:top; white-space:nowrap; font-family:ui-monospace,monospace;">${escapeHtml(r.id)}</td>
                        <td style="padding:8px 10px 8px 0; vertical-align:top;">
                            <strong>${escapeHtml(r.title)}</strong>
                            <div style="color:var(--text-muted); margin-top:2px;">Verifica: ${escapeHtml(r.checks)}</div>
                            <div style="color:var(--text-muted); margin-top:2px;">Rimedio: ${escapeHtml(r.remediation)}</div>
                        </td>
                        <td style="padding:8px 0; vertical-align:top; text-align:right; white-space:nowrap;">
                            <span style="color:${sevColor[r.severity] || 'var(--text-muted)'}; font-weight:700; font-size:11px;">${escapeHtml(r.severity)}</span>
                            <div style="color:var(--text-muted); font-size:11px;">${escapeHtml(r.category)}</div>
                        </td>
                    </tr>
                `).join('')}
            </table>
        `;
    }

    // Expose functions globally
    window.renderBenchmarkRequirements = renderBenchmarkRequirements;
    window.loadNetSecAuditTab = loadNetSecAuditTab;
    window.applyNetSecAuditGating = applyNetSecAuditGating;
    window.setNetSecAuditPreview = setNetSecAuditPreview;
    window.runAuditScan = runAuditScan;
    window.exportAuditReport = exportAuditReport;
    window.renderAuditRulesTable = renderAuditRulesTable;
    window.toggleAuditDetail = toggleAuditDetail;
})();
