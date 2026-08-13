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

    // Piattaforma riconosciuta nella configurazione analizzata: decide quali
    // regole il motore ha eseguito, quindi va detto nel report.
    let _auditVendor = null;

    // Un file caricato diventa una VOCE della tendina dei dispositivi, non uno
    // stato nascosto. Prima il testo restava in una variabile e vinceva sempre
    // sul dispositivo selezionato: si sceglieva un apparato dall'inventario,
    // si lanciava la scansione e si ottenevano i risultati del file caricato
    // mezz'ora prima, senza che nulla lo dicesse. Ora la tendina e' l'unica
    // fonte di verita' su cosa si sta analizzando.
    const UPLOADED_VALUE = '__uploaded__';
    let _droppedConfigText = null;
    let _droppedConfigName = '';

    function loadNetSecAuditTab() {
        // Il report esce per default nella lingua in cui si sta lavorando;
        // il selettore serve a consegnarlo in un'altra, non a doverlo
        // reimpostare ogni volta.
        const langSel = document.getElementById('auditReportLang');
        if (langSel) langSel.value = (currentLang === 'en') ? 'en' : 'it';
        populateAuditDeviceSelect();
        renderAuditOverview();
        renderAuditRulesTable();
        setupConfigDropzone();
        loadAuditHistory();
    }

    // Popola #auditDeviceSelect con l'inventario reale (già filtrato per sede
    // lato server). Non aggiunge MAI dispositivi inventati: se il fetch fallisce
    // o l'inventario è vuoto, resta solo l'opzione "Tutti".
    async function populateAuditDeviceSelect() {
        const sel = document.getElementById('auditDeviceSelect');
        if (!sel) return;
        const previous = sel.value;
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
        } finally {
            // Ricostruire la tendina non deve far sparire il file caricato:
            // e' esattamente il momento in cui l'utente lo perdeva di vista.
            restoreUploadedOption(sel, previous);
        }
    }

    // Rimette in cima la voce del file caricato e ripristina la selezione.
    function restoreUploadedOption(sel, previous) {
        if (_droppedConfigText) {
            const opt = document.createElement('option');
            opt.value = UPLOADED_VALUE;
            opt.textContent = '📄 ' + (_droppedConfigName || 'config');
            sel.insertBefore(opt, sel.firstChild);
        }
        if (previous && [...sel.options].some(o => o.value === previous)) {
            sel.value = previous;
        } else if (_droppedConfigText) {
            sel.value = UPLOADED_VALUE;
        }
        syncDropzoneHint();
    }

    // Il riquadro di upload dice cosa e' caricato e come toglierlo. Senza,
    // l'unico modo di sapere se un file e' ancora in gioco e' ricordarselo.
    function syncDropzoneHint() {
        const dropText = document.getElementById('auditDropText');
        if (!dropText) return;
        const en = currentLang === 'en';
        if (!_droppedConfigText) {
            dropText.innerHTML = `<i class="fa-solid fa-cloud-arrow-up fa-2x" style="color:var(--primary); margin-bottom:8px;"></i><br>
                <span data-i18n="nsaDropText">${en
                    ? 'Drop the configuration file here, or click to upload'
                    : 'Trascina qui il file di configurazione o clicca per caricare'}</span>`;
            return;
        }
        const sel = document.getElementById('auditDeviceSelect');
        const active = sel && sel.value === UPLOADED_VALUE;
        dropText.innerHTML = `
            <i class="fa-solid fa-file-code fa-2x" style="color:var(--success); margin-bottom:8px;"></i><br>
            <strong>${escapeHtml(_droppedConfigName)}</strong><br>
            <span style="color:var(--text-muted);">${active
                ? (en ? 'Selected as the audit target.' : 'Selezionato come oggetto dell\'audit.')
                : (en ? 'Loaded, but a device is selected instead.' : 'Caricato, ma è selezionato un dispositivo.')}</span>
            <br><a href="#" onclick="clearUploadedConfig(); return false;" style="font-size:11px; color:var(--danger);">${en ? 'Remove file' : 'Rimuovi file'}</a>`;
    }

    function clearUploadedConfig() {
        _droppedConfigText = null;
        _droppedConfigName = '';
        const sel = document.getElementById('auditDeviceSelect');
        if (sel) {
            [...sel.options].forEach(o => {
                if (o.value === UPLOADED_VALUE) o.remove();
            });
            sel.value = 'all';
        }
        const fileInput = document.getElementById('auditFileInput');
        if (fileInput) fileInput.value = '';
        syncDropzoneHint();
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

    // "Perche' dovrebbe essere impostato cosi'": motivazione, impatto del
    // rimedio e valore di fabbrica. Arrivano dal motore (guidance.py) gia'
    // nella lingua del report; il blocco sparisce del tutto se il controllo
    // non ha una voce, invece di mostrare tre riquadri vuoti.
    function auditGuidanceBlock(r) {
        const g = r.guidance || {};
        if (!g.why && !g.impact && !g.default) return '';
        const en = currentLang === 'en';
        const section = (label, text, color) => text ? `
            <div style="margin-bottom:10px;">
                <div style="font-size:11px; font-weight:700; color:${color}; text-transform:uppercase; letter-spacing:.04em; margin-bottom:4px;">${label}</div>
                <div style="font-size:12px; line-height:1.55; color:var(--text);">${escapeHtml(text)}</div>
            </div>` : '';
        return `
            <div style="padding:2px 0 2px 12px; margin-bottom:14px;">
                ${section(en ? 'Why it matters' : 'Perché conta', g.why, 'var(--primary)')}
                ${section(en ? 'Impact of the fix' : 'Impatto del rimedio', g.impact, 'var(--warning)')}
                ${section(en ? 'Factory default' : 'Valore di fabbrica', g.default, 'var(--text-muted)')}
            </div>`;
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
                : `<span class="badge" style="background:var(--surface-3);">${escapeHtml(r.severity || 'MEDIUM')}</span>`;

            // Riferimento alla raccomandazione nel benchmark di origine: senza
            // di esso l'esito non e' verificabile contro il documento.
            const refBadge = r.ref
                ? `<span class="badge" style="background:var(--surface-3); color:var(--text-muted); font-weight:600;"
                         title="${currentLang === 'en' ? 'Benchmark recommendation' : 'Raccomandazione del benchmark'}">${escapeHtml(String(r.ref))}</span>`
                : '';
            const levelBadge = r.level
                ? `<span class="badge" style="background:var(--surface-3); color:var(--text-muted);"
                         title="${currentLang === 'en' ? 'CIS profile level' : 'Livello di profilo CIS'}">L${escapeHtml(String(r.level))}</span>`
                : '';
            // Il benchmark distingue i controlli automatizzabili da quelli che
            // vuole verificati a mano: quelli manuali qui sono valutati su cio'
            // che la configurazione dichiara, non sul comportamento reale.
            const manualBadge = (r.automated === false)
                ? `<span class="badge" style="background:var(--surface-3); color:var(--text-muted);"
                         title="${currentLang === 'en' ? 'The benchmark marks this as a manual check: the verdict here reads the configuration, it does not observe the device.' : 'Il benchmark la marca come verifica manuale: il verdetto qui legge la configurazione, non osserva l\'apparato.'}"><i class="fa-solid fa-hand"></i> ${currentLang === 'en' ? 'manual' : 'manuale'}</span>`
                : '';

            const ev = r.evidence || [];
            const evId = String(r.id).replace(/[^\w-]/g, '_');
            const isOpen = _auditOpenRows.has(evId);

            // Suggerimento del contenuto nascosto: quante evidenze ci sono.
            // Non e' un pulsante: l'intera riga fa da interruttore, due
            // comandi sovrapposti per la stessa azione confondono.
            const evHint = ev.length
                ? `<span class="badge" style="background:var(--surface-3); color:var(--text-muted);">
                       <i class="fa-solid fa-code"></i> ${ev.length} ${currentLang === 'en' ? 'evidence' : 'evidenze'}
                   </span>`
                : '';

            // Segnala che espandendo si trova la motivazione, non solo il
            // comando: senza, nessuno apre la riga di un controllo PASS.
            const whyHint = (r.guidance && (r.guidance.why || r.guidance.impact))
                ? `<span class="badge" style="background:rgba(99,102,241,0.15); color:var(--primary); font-weight:600;">
                       <i class="fa-solid fa-circle-question"></i> ${currentLang === 'en' ? 'why' : 'perché'}
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
                    <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center; margin-top:6px;">
                        ${refBadge}${levelBadge}${manualBadge}${whyHint}${evHint}
                    </div>
                </td>
                <td style="padding:8px;">${sevBadge}</td>
                <td style="padding:8px;"><span class="badge">${escapeHtml(r.category)}</span></td>
                <td style="padding:8px;">${statusBadge}</td>
                <td style="padding:8px;">
                    <code title="${escapeHtml(r.remediation)}" style="font-size:11px; color:var(--primary); background:var(--surface-2); padding:3px 6px; border-radius:0; display:inline-block; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; vertical-align:middle;">${escapeHtml(r.remediation)}</code>
                </td>
            </tr>
            <tr id="auditEv-${escapeHtml(evId)}" style="${isOpen ? '' : 'display:none;'}">
                <td colspan="6" style="padding:12px 12px 14px 30px; background:var(--surface-2); border-top:1px solid var(--border);">
                    ${auditGuidanceBlock(r)}
                    ${r.audit ? `
                    <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:.04em; margin-bottom:6px;">
                        ${currentLang === 'en' ? 'Verify on the device' : 'Verifica sull\'apparato'}
                    </div>
                    <code style="display:block; font-size:12px; color:var(--text); background:var(--surface); padding:8px 10px; border-radius:0; border:1px solid var(--border); white-space:pre-wrap; word-break:break-word; margin-bottom:12px;">${escapeHtml(r.audit)}</code>` : ''}
                    <div style="font-size:11px; font-weight:700; color:var(--text-muted); text-transform:uppercase; letter-spacing:.04em; margin-bottom:6px;">
                        ${currentLang === 'en' ? 'Recommendation / CLI fix' : 'Raccomandazione / Fix CLI'}
                    </div>
                    <code style="display:block; font-size:12px; color:var(--primary); background:var(--surface); padding:8px 10px; border-radius:0; border:1px solid var(--border); white-space:pre-wrap; word-break:break-word; margin-bottom:${ev.length ? '12px' : '0'};">${escapeHtml(r.remediation)}</code>
                    ${evRows}
                </td>
            </tr>`;
        }).join('');
    }

    function toggleAuditDetail(ruleId) {
        if (_auditOpenRows.has(ruleId)) _auditOpenRows.delete(ruleId);
        else _auditOpenRows.add(ruleId);
        renderAuditRulesTable();
    }

    async function runAuditScan() {
        const btn = document.getElementById('btnRunAuditScan');
        const benchmark = document.getElementById('auditBenchmarkSelect') ? document.getElementById('auditBenchmarkSelect').value : 'cis';
        const deviceIp = document.getElementById('auditDeviceSelect') ? document.getElementById('auditDeviceSelect').value : 'all';
        // Il testo caricato si invia SOLO se e' lui l'oggetto selezionato:
        // altrimenti sovrascriverebbe in silenzio il dispositivo scelto.
        const uploaded = (deviceIp === UPLOADED_VALUE);

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Audit in corso...`;
        }

        const saveRun = document.getElementById('auditSaveRun') ? document.getElementById('auditSaveRun').checked : false;

        try {
            const res = await apiFetch('/api/netsec-audit/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    benchmark: benchmark,
                    // La tabella a schermo segue la lingua dell'interfaccia;
                    // il report esportato ha un proprio selettore.
                    lang: currentLang,
                    device_ip: uploaded ? null : deviceIp,
                    config_text: uploaded ? _droppedConfigText : null,
                    save: saveRun
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
                _auditVendor = data.vendor || null;
                renderAuditOverview();
                renderAuditRulesTable();
                if (data.saved_id) {
                    loadAuditHistory();
                }
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

        const devSel = document.getElementById('auditDeviceSelect');
        if (devSel && !devSel.dataset.bound) {
            devSel.dataset.bound = 'true';
            devSel.addEventListener('change', syncDropzoneHint);
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
                _droppedConfigName = file.name;
                const sel = document.getElementById('auditDeviceSelect');
                if (sel) {
                    [...sel.options].forEach(o => {
                        if (o.value === UPLOADED_VALUE) o.remove();
                    });
                    restoreUploadedOption(sel, UPLOADED_VALUE);
                }
                syncDropzoneHint();
                runAuditScan();
            };
            reader.readAsText(file);
        }
    }

    // Rivaluta la stessa configurazione in un'altra lingua. Ripete la
    // scansione invece di tradurre a schermo: i verdetti nascono nel motore,
    // e tradurli qui significherebbe tenerne una seconda copia disallineata.
    async function rescanForLanguage(benchmarkKey, lang) {
        const devSel = document.getElementById('auditDeviceSelect');
        const deviceIp = devSel ? devSel.value : 'all';
        const uploaded = (deviceIp === UPLOADED_VALUE);
        try {
            const res = await apiFetch('/api/netsec-audit/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    benchmark: benchmarkKey,
                    device_ip: uploaded ? null : deviceIp,
                    lang: lang,
                    config_text: uploaded ? _droppedConfigText : null,
                    save: document.getElementById('auditSaveRun') ? document.getElementById('auditSaveRun').checked : false
                })
            });
            if (res && res.ok) return await res.json();
            let detail = '';
            try { const err = await res.json(); detail = err && err.detail; } catch (e) {}
            showToast(detail || (currentLang === 'en'
                ? 'Could not produce the report in the selected language.'
                : 'Impossibile produrre il report nella lingua selezionata.'), 'error');
        } catch (e) {
            console.error('Audit re-scan error:', e);
            showToast(currentLang === 'en'
                ? 'Could not produce the report in the selected language.'
                : 'Impossibile produrre il report nella lingua selezionata.', 'error');
        }
        return null;
    }

    // Etichette del documento esportato. Non passano da i18n.js perche' il
    // report puo' uscire in una lingua diversa da quella dell'interfaccia:
    // usare le stringhe della UI legherebbe le due cose.
    const REPORT_TEXT = {
        it: {
            docTitle: 'Report Audit', heading: 'Report di Compliance',
            device: 'Apparato', platform: 'Piattaforma',
            generatedOn: 'Generato il', score: 'Score',
            passed: 'Conformi', failed: 'Non conformi', warned: 'Warning',
            unknown: 'Non valutabili', notAssessable: 'NON VALUTABILE',
            na: 'N/D', level: 'Livello', manual: 'verifica manuale',
            verifyOn: 'Verifica sull\'apparato', line: 'riga',
            thId: 'ID', thCheck: 'Controllo ed evidenze', thSeverity: 'Severità',
            thStatus: 'Esito', thFix: 'Rimedio',
            why: 'Perché conta', impact: 'Impatto del rimedio',
            defaultValue: 'Valore di fabbrica',
            partialTitle: 'Valutazione parziale.',
            partial: (a, t, u) => `${a} controlli su ${t} sono stati valutati; ${u} non lo sono perché le relative sezioni di configurazione sono assenti nel file analizzato. Lo score si riferisce ai soli controlli valutabili.`,
            note: 'I controlli marcati "non valutabile" corrispondono a sezioni di configurazione assenti nel file analizzato: sono esclusi dal calcolo dello score e non vanno letti come conformità.',
            preview: 'Anteprima Report Compliance', pdf: 'Scarica PDF',
            generating: 'Generazione PDF...', print: 'Stampa',
            html: 'Scarica HTML',
        },
        en: {
            docTitle: 'Audit Report', heading: 'Compliance Report',
            device: 'Device', platform: 'Platform',
            generatedOn: 'Generated on', score: 'Score',
            passed: 'Compliant', failed: 'Non-compliant', warned: 'Warning',
            unknown: 'Not assessable', notAssessable: 'NOT ASSESSABLE',
            na: 'N/A', level: 'Level', manual: 'manual check',
            verifyOn: 'Verify on the device', line: 'line',
            thId: 'ID', thCheck: 'Check and evidence', thSeverity: 'Severity',
            thStatus: 'Result', thFix: 'Remediation',
            why: 'Why it matters', impact: 'Impact of the fix',
            defaultValue: 'Factory default',
            partialTitle: 'Partial assessment.',
            partial: (a, t, u) => `${a} of ${t} checks were assessed; ${u} were not, because the corresponding configuration sections are absent from the analysed file. The score covers the assessed checks only.`,
            note: 'Checks marked "not assessable" correspond to configuration sections absent from the analysed file: they are excluded from the score and must not be read as compliance.',
            preview: 'Compliance Report Preview', pdf: 'Download PDF',
            generating: 'Generating PDF...', print: 'Print',
            html: 'Download HTML',
        },
    };

    // Report HTML scaricabile. Nessuna dipendenza esterna: si costruisce il
    // documento e lo si scarica via Blob, coerentemente col resto dell'app.
    //
    // La lingua del report e' indipendente da quella dell'interfaccia. I
    // verdetti sono resi dal motore, quindi cambiarla significa rieseguire la
    // valutazione: e' una funzione pura sul testo di configurazione, costa
    // quanto la scansione appena fatta e garantisce che TUTTO il documento sia
    // nella lingua scelta, non solo le intestazioni.
    async function exportAuditReport() {
        if (!_auditRules.length) {
            showToast(currentLang === 'en'
                ? 'Run a scan before exporting a report.'
                : 'Esegui una scansione prima di esportare il report.', 'warning');
            return;
        }
        const langSel = document.getElementById('auditReportLang');
        const lang = (langSel && langSel.value === 'en') ? 'en' : 'it';
        const T = REPORT_TEXT[lang];

        const benchSel = document.getElementById('auditBenchmarkSelect');
        const benchmarkKey = benchSel ? benchSel.value : 'cis';
        const benchmark = benchSel ? benchSel.options[benchSel.selectedIndex].text : 'CIS';
        const devSel = document.getElementById('auditDeviceSelect');
        const device = devSel ? devSel.options[devSel.selectedIndex].text : '—';

        let rules = _auditRules;
        let summary = _auditSummary;
        let score = _auditScore;
        if (lang !== currentLang) {
            const refreshed = await rescanForLanguage(benchmarkKey, lang);
            if (!refreshed) return;          // errore già segnalato all'utente
            rules = refreshed.rules || [];
            summary = refreshed.summary || summary;
            score = (refreshed.score === undefined) ? null : refreshed.score;
        }

        const s = summary || { total: 0, passed: 0, failed: 0, warned: 0, unknown: 0 };
        const unknown = s.unknown || 0;
        const hasScore = (score !== null && score !== undefined);
        const scoreTxt = hasScore ? (score + '%') : T.na;
        const generated = new Date().toLocaleString(lang === 'en' ? 'en-GB' : 'it-IT');
        const platform = _auditVendor === 'ios' ? 'Cisco IOS XE'
            : _auditVendor === 'fortios' ? 'FortiOS' : '—';

        const rows = rules.map(r => {
            const ev = (r.evidence || []).map(e =>
                `<div class="ev"><span>${e.line ? (T.line + ' ' + escapeHtml(String(e.line))) : '—'}</span>`
                + `<span>${escapeHtml(e.context || '')}</span>`
                + `<code>${escapeHtml(e.text || '')}</code></div>`).join('');
            const label = r.status === 'UNKNOWN' ? T.notAssessable : escapeHtml(r.status);
            // Il riferimento alla raccomandazione e il comando di verifica
            // rendono il report controllabile contro il benchmark di origine:
            // senza di essi resta un'affermazione da prendere per buona.
            const ref = r.ref
                ? `<div class="detail">${escapeHtml(String(r.ref))}${r.level ? ' · ' + T.level + ' ' + escapeHtml(String(r.level)) : ''}${r.automated === false ? ' · ' + T.manual : ''}</div>`
                : '';
            const auditCmd = r.audit
                ? `<div class="detail">${T.verifyOn}: <code style="white-space:pre-wrap;">${escapeHtml(r.audit)}</code></div>`
                : '';
            const g = r.guidance || {};
            const guide = (label2, text) => text
                ? `<div class="guide"><b>${label2}:</b> ${escapeHtml(text)}</div>` : '';
            const guidance = guide(T.why, g.why) + guide(T.impact, g.impact)
                + guide(T.defaultValue, g.default);
            return `<tr class="st-${escapeHtml(r.status)}">
                <td><strong>${escapeHtml(r.id)}</strong>${ref}</td>
                <td>${escapeHtml(r.title)}<div class="detail">${escapeHtml(r.detail)}</div>${guidance}${auditCmd}${ev}</td>
                <td>${escapeHtml(r.severity)}</td>
                <td>${label}</td>
                <td><code>${escapeHtml(r.remediation)}</code></td>
            </tr>`;
        }).join('');

        // Se qualcosa non era valutabile va detto in testa al report, non solo
        // in nota: un lettore che vede "100%" senza contesto conclude che tutto
        // sia stato verificato.
        const partialBanner = unknown > 0
            ? `<div class="warn"><strong>${T.partialTitle}</strong> ${T.partial(s.total - unknown, s.total, unknown)}</div>`
            : '';

        const html = `<!doctype html><html lang="${lang}"><head><meta charset="utf-8">
<title>${T.docTitle} — ${escapeHtml(device)}</title>
<style>
body{font-family:system-ui,sans-serif;margin:32px;color:#111;}
h1{font-size:20px;margin:0 0 4px;} .meta{color:#666;font-size:13px;margin-bottom:20px;}
.warn{border:1px solid #a60;background:#fff8e6;color:#7a4d00;padding:10px 14px;border-radius:0;margin-bottom:18px;font-size:13px;line-height:1.5;}
.kpis{display:flex;gap:20px;margin-bottom:20px;flex-wrap:wrap;}
.kpi{border:1px solid #ddd;border-radius:0;padding:10px 16px;min-width:110px;font-size:12px;color:#666;}
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
.guide{color:#444;margin-top:4px;font-size:11px;line-height:1.5;}
.guide b{color:#111;}
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
        if (btn) btn.textContent = '${T.generating}';
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
            if (btn) btn.textContent = '${T.pdf}';
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
<div class="no-print" style="margin-bottom: 20px; padding: 12px 16px; background: #1e293b; color: white; border-radius: 0; display: flex; justify-content: space-between; align-items: center; font-family: system-ui, sans-serif;">
    <span style="font-size: 14px; font-weight: bold;">SentinelNet — ${T.preview}</span>
    <div style="display: flex; gap: 10px;">
        <button id="btnPdfNetsec" onclick="downloadPdf()" style="padding: 8px 16px; background: #10b981; color: white; border: none; border-radius: 0; font-size: 13px; font-weight: bold; cursor: pointer;">${T.pdf}</button>
        <button onclick="window.print()" style="padding: 8px 16px; background: #2563eb; color: white; border: none; border-radius: 0; font-size: 13px; font-weight: bold; cursor: pointer;">${T.print}</button>
        <button onclick="downloadHtml()" style="padding: 8px 16px; background: #64748b; color: white; border: none; border-radius: 0; font-size: 13px; font-weight: bold; cursor: pointer;">${T.html}</button>
    </div>
</div>
<h1>${T.heading} — ${escapeHtml(benchmark)}</h1>
<div class="meta">${T.device}: ${escapeHtml(device)} · ${T.platform}: ${escapeHtml(platform)} · ${T.generatedOn} ${escapeHtml(generated)}</div>
${partialBanner}
<div class="kpis">
  <div class="kpi"><b>${escapeHtml(scoreTxt)}</b>${T.score}</div>
  <div class="kpi"><b>${s.passed}</b>${T.passed}</div>
  <div class="kpi"><b>${s.failed}</b>${T.failed}</div>
  <div class="kpi"><b>${s.warned}</b>${T.warned}</div>
  <div class="kpi"><b>${unknown}</b>${T.unknown}</div>
</div>
<table><thead><tr><th>${T.thId}</th><th>${T.thCheck}</th><th>${T.thSeverity}</th><th>${T.thStatus}</th><th>${T.thFix}</th></tr></thead>
<tbody>${rows}</tbody></table>
<div class="note">${T.note}</div>
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

        const en = currentLang === 'en';
        const key = document.getElementById('auditBenchmarkSelect').value;
        if (!_benchmarkCatalog) {
            body.innerHTML = `<div style="font-size:12px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> ${en ? 'Loading requirements…' : 'Caricamento requisiti...'}</div>`;
            try {
                const res = await apiFetch('/api/netsec-audit/benchmarks');
                if (!res || !res.ok) {
                    body.innerHTML = `<div style="font-size:12px; color:var(--danger);">${en ? 'Unable to load the requirements.' : 'Impossibile caricare i requisiti.'}</div>`;
                    return;
                }
                _benchmarkCatalog = await res.json();
            } catch (e) {
                body.innerHTML = `<div style="font-size:12px; color:var(--danger);">${en ? 'Network error while loading the requirements.' : 'Errore di rete nel caricamento dei requisiti.'}</div>`;
                return;
            }
        }

        const reqs = _benchmarkCatalog[key] || [];
        const sevColor = { CRITICAL: 'var(--danger)', HIGH: 'var(--danger)', MEDIUM: 'var(--warning)', LOW: 'var(--text-muted)' };
        // Le regole di un benchmark coprono piu' piattaforme: una scansione ne
        // esegue solo quelle del vendor riconosciuto nella configurazione, e
        // dirlo qui evita che l'elenco sembri una promessa di eseguirle tutte.
        const vendorLabel = { fortios: 'FortiOS', ios: 'Cisco IOS XE' };
        const counts = reqs.reduce((acc, r) => {
            acc[r.vendor] = (acc[r.vendor] || 0) + 1;
            return acc;
        }, {});
        const breakdown = Object.keys(counts).sort()
            .map(v => `${counts[v]} ${vendorLabel[v] || v}`).join(' · ');
        body.innerHTML = `
            <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">
                ${reqs.length} ${en ? 'checks' : 'controlli'} (${escapeHtml(breakdown)}). ${en
                    ? 'Only the checks matching the platform detected in the analysed configuration are run.'
                    : 'Vengono eseguiti solo i controlli della piattaforma riconosciuta nella configurazione analizzata.'}
            </div>
            <table style="width:100%; border-collapse:collapse; font-size:12px;">
                ${reqs.map(r => `
                    <tr style="border-top:1px solid var(--border);">
                        <td style="padding:8px 10px 8px 0; vertical-align:top; white-space:nowrap; font-family:ui-monospace,monospace;">
                            ${escapeHtml(r.id)}
                            ${r.ref ? `<div style="color:var(--text-muted); font-size:11px;">${escapeHtml(String(r.ref))}${r.level ? ' · L' + escapeHtml(String(r.level)) : ''}</div>` : ''}
                        </td>
                        <td style="padding:8px 10px 8px 0; vertical-align:top;">
                            <strong>${escapeHtml(r.title)}</strong>
                            <div style="color:var(--text-muted); margin-top:2px;">${en ? 'Check' : 'Verifica'}: ${escapeHtml(r.checks)}</div>
                            ${r.audit ? `<div style="color:var(--text-muted); margin-top:2px; font-family:ui-monospace,monospace; white-space:pre-wrap;">${en ? 'Audit' : 'Audit'}: ${escapeHtml(r.audit)}</div>` : ''}
                            <div style="color:var(--text-muted); margin-top:2px;">${en ? 'Remediation' : 'Rimedio'}: ${escapeHtml(r.remediation)}</div>
                        </td>
                        <td style="padding:8px 0; vertical-align:top; text-align:right; white-space:nowrap;">
                            <span style="color:${sevColor[r.severity] || 'var(--text-muted)'}; font-weight:700; font-size:11px;">${escapeHtml(r.severity)}</span>
                            <div style="color:var(--text-muted); font-size:11px;">${escapeHtml(r.category)}</div>
                            <div style="color:var(--text-muted); font-size:11px;">${escapeHtml(vendorLabel[r.vendor] || r.vendor || '')}</div>
                        </td>
                    </tr>
                `).join('')}
            </table>
        `;
    }

    async function loadAuditHistory() {
        const tbody = document.getElementById('auditHistoryBody');
        if (!tbody) return;
        try {
            const res = await apiFetch('/api/netsec-audit/history');
            if (!res || !res.ok) {
                tbody.innerHTML = `<tr><td colspan="8" style="padding:15px; text-align:center; color:var(--text-muted);">${currentLang === 'en' ? 'Error loading history.' : 'Errore nel caricamento dello storico.'}</td></tr>`;
                return;
            }
            const data = await res.json();
            const runs = (data && data.runs) || [];
            if (!runs.length) {
                tbody.innerHTML = `<tr><td colspan="8" style="padding:15px; text-align:center; color:var(--text-muted);">${currentLang === 'en' ? 'No saved audits in history.' : 'Nessun audit salvato nello storico.'}</td></tr>`;
                return;
            }
            tbody.innerHTML = runs.map(r => {
                const dt = new Date(r.ts * 1000).toLocaleString();
                const dev = escapeHtml(r.device_name || r.device_ip || (currentLang === 'en' ? 'Pasted config' : 'Config incollata'));
                const bench = escapeHtml(r.benchmark_title || r.benchmark || '');
                const vendor = escapeHtml(r.vendor || '—');
                const hasScore = (r.score !== null && r.score !== undefined);
                const scoreStr = hasScore ? `${r.score}%` : '—';
                const gradeStr = !hasScore
                    ? (currentLang === 'en' ? 'NOT ASSESSABLE' : 'NON DETERMINABILE')
                    : (r.score >= 80 ? 'GRADE A' : r.score >= 60 ? 'GRADE B' : 'GRADE C - RISK DETECTED');
                const gradeColor = !hasScore
                    ? 'var(--text-muted)'
                    : (r.score >= 80 ? 'var(--success)' : r.score >= 60 ? 'var(--warning)' : 'var(--danger)');
                const actor = escapeHtml(r.actor || '—');
                return `<tr>
                    <td style="font-size:12px;">${escapeHtml(dt)}</td>
                    <td style="font-size:12px; font-weight:600;">${dev}</td>
                    <td style="font-size:12px;">${bench}</td>
                    <td style="font-size:12px;">${vendor}</td>
                    <td style="font-size:12px; font-weight:700;">${scoreStr}</td>
                    <td style="font-size:11px; font-weight:700; color:${gradeColor};">${escapeHtml(gradeStr)}</td>
                    <td style="font-size:12px; color:var(--text-muted);">${actor}</td>
                    <td>
                        <button class="btn btn-secondary" onclick="openAuditRun(${r.id})" style="padding:2px 8px; font-size:11px; margin:0 4px 0 0;" data-i18n="auditHistoryOpen">Apri</button>
                        <button class="btn btn-secondary requires-admin" onclick="deleteAuditRun(${r.id})" style="padding:2px 8px; font-size:11px; margin:0; color:var(--danger);" data-i18n="auditHistoryDelete">Elimina</button>
                    </td>
                </tr>`;
            }).join('');
            if (typeof applyRoleUI === 'function') applyRoleUI(currentUsername, currentRole);
        } catch (e) {
            console.error('loadAuditHistory error:', e);
            tbody.innerHTML = `<tr><td colspan="8" style="padding:15px; text-align:center; color:var(--text-muted);">${currentLang === 'en' ? 'Error loading history.' : 'Errore nel caricamento dello storico.'}</td></tr>`;
        }
    }

    async function openAuditRun(id) {
        try {
            const res = await apiFetch(`/api/netsec-audit/history/${id}`);
            if (!res || !res.ok) {
                showToast(currentLang === 'en' ? 'Unable to load audit run.' : 'Impossibile caricare la run di audit.', 'error');
                return;
            }
            const data = await res.json();
            _auditRules = data.rules || [];
            _auditSummary = data.summary || null;
            _auditScore = (data.score === undefined) ? null : data.score;
            _auditVendor = data.vendor || null;
            renderAuditOverview();
            renderAuditRulesTable();
            showToast(currentLang === 'en' ? 'Audit run loaded from history.' : 'Run di audit caricata dallo storico.', 'info');
        } catch (e) {
            console.error('openAuditRun error:', e);
            showToast(currentLang === 'en' ? 'Unable to load audit run.' : 'Impossibile caricare la run di audit.', 'error');
        }
    }

    async function deleteAuditRun(id) {
        const msg = currentLang === 'en'
            ? 'Permanently delete this audit from history?'
            : 'Eliminare definitivamente questo audit dallo storico?';
        if (!confirm(msg)) return;
        try {
            const res = await apiFetch(`/api/netsec-audit/history/${id}`, { method: 'DELETE' });
            if (res && res.ok) {
                showToast(currentLang === 'en' ? 'Audit run deleted.' : 'Run di audit eliminata.', 'info');
                loadAuditHistory();
            } else {
                showToast(currentLang === 'en' ? 'Failed to delete audit run.' : 'Eliminazione della run non riuscita.', 'error');
            }
        } catch (e) {
            console.error('deleteAuditRun error:', e);
            showToast(currentLang === 'en' ? 'Failed to delete audit run.' : 'Eliminazione della run non riuscita.', 'error');
        }
    }

    // Expose functions globally
    window.renderBenchmarkRequirements = renderBenchmarkRequirements;
    window.loadNetSecAuditTab = loadNetSecAuditTab;
    window.runAuditScan = runAuditScan;
    window.exportAuditReport = exportAuditReport;
    window.renderAuditRulesTable = renderAuditRulesTable;
    window.toggleAuditDetail = toggleAuditDetail;
    window.clearUploadedConfig = clearUploadedConfig;
    window.loadAuditHistory = loadAuditHistory;
    window.openAuditRun = openAuditRun;
    window.deleteAuditRun = deleteAuditRun;
})();

