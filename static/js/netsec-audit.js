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
    let _auditDeviceName = '';
    let _auditBenchmarkName = '';

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
        if (previous === UPLOADED_VALUE && _droppedConfigText) {
            sel.value = UPLOADED_VALUE;
        } else if (previous && previous !== 'all' && previous !== UPLOADED_VALUE && [...sel.options].some(o => o.value === previous)) {
            sel.value = previous;
        } else if (_droppedConfigText) {
            sel.value = UPLOADED_VALUE;
        } else if ([...sel.options].some(o => o.value === 'all')) {
            sel.value = 'all';
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
            <br><a href="#" data-action="clear-uploaded-config" style="font-size:11px; color:var(--danger);">${en ? 'Remove file' : 'Rimuovi file'}</a>`;
    }

    function clearUploadedConfig() {
        _droppedConfigText = null;
        _droppedConfigName = '';
        _auditRules = [];
        _auditSummary = null;
        _auditScore = null;
        _auditVendor = null;
        _auditDeviceName = '';
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
        renderAuditOverview();
        renderAuditRulesTable();
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
        const statusFilter = document.getElementById('auditStatusFilter') ? document.getElementById('auditStatusFilter').value : 'all';

        let filtered = _auditRules;
        if (sevFilter !== 'all') filtered = filtered.filter(r => r.severity.toLowerCase() === sevFilter.toLowerCase());
        if (catFilter !== 'all') filtered = filtered.filter(r => r.category.toLowerCase() === catFilter.toLowerCase());
        if (statusFilter !== 'all') filtered = filtered.filter(r => {
            // Come il badge: tutto cio' che non e' PASS/FAIL/WARN e' N/D.
            const st = (r.status === 'PASS' || r.status === 'FAIL' || r.status === 'WARN') ? r.status : 'UNKNOWN';
            return st === statusFilter;
        });

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
                        data-action="toggle-audit-detail" data-ev-id="${escapeHtml(evId)}"
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
        const devSel = document.getElementById('auditDeviceSelect');
        const deviceIp = devSel ? devSel.value : 'all';
        // Il testo caricato si invia SOLO se e' lui l'oggetto selezionato:
        // altrimenti sovrascriverebbe in silenzio il dispositivo scelto.
        const uploaded = (deviceIp === UPLOADED_VALUE);

        if (uploaded && !_droppedConfigText) {
            showToast(currentLang === 'en' ? 'Please upload a configuration file first.' : 'Carica prima un file di configurazione.', 'error');
            return;
        }

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Audit in corso...`;
        }

        const saveRun = document.getElementById('auditSaveRun') ? document.getElementById('auditSaveRun').checked : false;
        const runName = (saveRun && document.getElementById('auditRunName')) ? document.getElementById('auditRunName').value.trim() : null;

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
                    device_name: uploaded ? _droppedConfigName : (devSel && devSel.selectedIndex >= 0 ? devSel.options[devSel.selectedIndex]?.text : null),
                    config_text: uploaded ? _droppedConfigText : null,
                    save: saveRun,
                    run_name: runName
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
                _auditDeviceName = data.device_name || (uploaded ? _droppedConfigName : (devSel ? devSel.options[devSel.selectedIndex]?.text : '')) || 'Device';
                _auditBenchmarkName = data.benchmark_title || data.benchmark || benchmark;
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
        if (!zone || !fileInput) return;

        if (!zone.dataset.bound) {
            zone.dataset.bound = 'true';

            fileInput.addEventListener('click', (e) => {
                e.stopPropagation();
            });

            zone.addEventListener('click', (e) => {
                if (e.target === fileInput) return;
                const clearBtn = e.target.closest('[data-action="clear-uploaded-config"]');
                if (clearBtn) {
                    e.preventDefault();
                    e.stopPropagation();
                    clearUploadedConfig();
                    return;
                }
                fileInput.value = '';
                fileInput.click();
            });

            zone.addEventListener('dragover', (e) => {
                e.preventDefault();
                zone.style.borderColor = 'var(--primary)';
            });

            zone.addEventListener('dragleave', () => {
                zone.style.borderColor = 'var(--border)';
            });

            zone.addEventListener('drop', (e) => {
                e.preventDefault();
                zone.style.borderColor = 'var(--border)';
                if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
                    handleFile(e.dataTransfer.files[0]);
                }
            });

            fileInput.addEventListener('change', () => {
                if (fileInput.files && fileInput.files.length) {
                    handleFile(fileInput.files[0]);
                }
            });
        }

        const benchSel = document.getElementById('auditBenchmarkSelect');
        if (benchSel && !benchSel.dataset.bound) {
            benchSel.dataset.bound = 'true';
            benchSel.addEventListener('change', () => runAuditScan());
        }

        const devSel = document.getElementById('auditDeviceSelect');
        if (devSel && !devSel.dataset.bound) {
            devSel.dataset.bound = 'true';
            devSel.addEventListener('change', syncDropzoneHint);
        }

        function handleFile(file) {
            if (!file) return;
            const reader = new FileReader();
            reader.onload = e => {
                _droppedConfigText = e.target.result;
                _droppedConfigName = file.name;
                _auditDeviceName = file.name;
                const sel = document.getElementById('auditDeviceSelect');
                if (sel) {
                    [...sel.options].forEach(o => {
                        if (o.value === UPLOADED_VALUE) o.remove();
                    });
                    restoreUploadedOption(sel, UPLOADED_VALUE);
                    sel.value = UPLOADED_VALUE;
                }
                syncDropzoneHint();
                runAuditScan();
            };
            reader.onerror = err => {
                console.error('File read error:', err);
                showToast(currentLang === 'en' ? 'Failed to read file.' : 'Impossibile leggere il file.', 'error');
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
        const saveRun = document.getElementById('auditSaveRun') ? document.getElementById('auditSaveRun').checked : false;
        const runName = (saveRun && document.getElementById('auditRunName')) ? document.getElementById('auditRunName').value.trim() : null;
        try {
            const res = await apiFetch('/api/netsec-audit/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    benchmark: benchmarkKey,
                    device_ip: uploaded ? null : deviceIp,
                    device_name: uploaded ? _droppedConfigName : (devSel && devSel.selectedIndex >= 0 ? devSel.options[devSel.selectedIndex]?.text : null),
                    lang: lang,
                    config_text: uploaded ? _droppedConfigText : null,
                    save: saveRun,
                    run_name: runName
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
            docTitle: 'Report di Compliance di Sicurezza',
            heading: 'Report di Compliance di Sicurezza',
            subheading: 'Audit di Sicurezza e Conformità Configurazione',
            device: 'Apparato',
            platform: 'Piattaforma',
            benchmark: 'Benchmark',
            generatedOn: 'Data Generazione',
            score: 'Score di Conformità',
            passed: 'Conformi (PASS)',
            failed: 'Non Conformi (FAIL)',
            warned: 'Avvisi (WARN)',
            unknown: 'Non Valutabili',
            notAssessable: 'NON VALUTABILE',
            na: 'N/D',
            level: 'Livello',
            manual: 'Verifica manuale',
            verifyOn: 'Verifica sull\'apparato',
            line: 'riga',
            thId: 'ID / Rif',
            thCheck: 'Controllo, Guida ed Evidenze',
            thSeverity: 'Severità',
            thStatus: 'Esito',
            thFix: 'Rimedio Consigliato (CLI)',
            why: 'Perché conta',
            impact: 'Impatto del rimedio',
            defaultValue: 'Valore di fabbrica',
            evidenceTitle: 'Evidenze riscontrate nella configurazione',
            partialTitle: 'Valutazione parziale.',
            partial: (a, t, u) => `${a} controlli su ${t} sono stati valutati; ${u} non lo sono perché le relative sezioni di configurazione sono assenti nel file analizzato. Lo score si riferisce ai soli controlli valutabili.`,
            note: 'I controlli marcati "non valutabile" corrispondono a sezioni di configurazione assenti nel file analizzato: sono esclusi dal calcolo dello score e non vanno interpretati come conformità.',
            footerNotice: 'Report di Audit di Sicurezza generato automaticamente da SentinelNet Engine. Documento confidenziale.',
            preview: 'Anteprima Report Compliance',
            pdf: 'Scarica PDF',
            printVector: 'Stampa / Salva in PDF',
            generating: 'Generazione PDF in corso...',
            print: 'Stampa',
            html: 'Scarica HTML',
        },
        en: {
            docTitle: 'Security Compliance Audit Report',
            heading: 'Security Compliance Report',
            subheading: 'Security & Configuration Compliance Audit',
            device: 'Target Device',
            platform: 'Platform',
            benchmark: 'Benchmark',
            generatedOn: 'Generated on',
            score: 'Compliance Score',
            passed: 'Compliant (PASS)',
            failed: 'Non-compliant (FAIL)',
            warned: 'Warnings (WARN)',
            unknown: 'Not Assessable',
            notAssessable: 'NOT ASSESSABLE',
            na: 'N/A',
            level: 'Level',
            manual: 'Manual check',
            verifyOn: 'Verify command on device',
            line: 'line',
            thId: 'ID / Ref',
            thCheck: 'Check, Guidance & Evidence',
            thSeverity: 'Severity',
            thStatus: 'Result',
            thFix: 'Recommended Remediation (CLI)',
            why: 'Why it matters',
            impact: 'Impact of the fix',
            defaultValue: 'Factory default',
            evidenceTitle: 'Evidence in analysed configuration',
            partialTitle: 'Partial assessment.',
            partial: (a, t, u) => `${a} of ${t} checks were assessed; ${u} were not, because the corresponding configuration sections are absent from the analysed file. The score covers the assessed checks only.`,
            note: 'Checks marked "not assessable" correspond to configuration sections absent from the analysed file: they are excluded from the score and must not be read as compliance.',
            footerNotice: 'Security Compliance Audit Report automatically generated by SentinelNet Engine. Confidential document.',
            preview: 'Compliance Report Preview',
            pdf: 'Download PDF',
            printVector: 'Print / Save as PDF',
            generating: 'Generating PDF...',
            print: 'Print',
            html: 'Download HTML',
        },
    };

    // Report HTML scaricabile e visualizzabile in anteprima.
    // La lingua del report e' indipendente da quella dell'interfaccia.
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
        const benchmark = _auditBenchmarkName || (benchSel ? benchSel.options[benchSel.selectedIndex].text : 'CIS');
        const devSel = document.getElementById('auditDeviceSelect');
        const device = _auditDeviceName || (devSel ? devSel.options[devSel.selectedIndex].text : '—');

        let rules = _auditRules;
        let summary = _auditSummary;
        let score = _auditScore;
        if (lang !== currentLang) {
            const hasUpload = (_droppedConfigText && _droppedConfigText.trim().length > 0);
            const hasDev = (devSel && devSel.value && devSel.value !== 'all' && devSel.value !== UPLOADED_VALUE);
            if (hasUpload || hasDev) {
                const refreshed = await rescanForLanguage(benchmarkKey, lang);
                if (refreshed) {
                    rules = refreshed.rules || rules;
                    summary = refreshed.summary || summary;
                    score = (refreshed.score === undefined) ? score : refreshed.score;
                }
            }
        }

        const s = summary || { total: 0, passed: 0, failed: 0, warned: 0, unknown: 0 };
        const unknown = s.unknown || 0;
        const hasScore = (score !== null && score !== undefined);
        const scoreTxt = hasScore ? (score + '%') : T.na;
        const generated = new Date().toLocaleString(lang === 'en' ? 'en-GB' : 'it-IT');
        const platform = _auditVendor === 'ios' ? 'Cisco IOS XE'
            : _auditVendor === 'fortios' ? 'FortiOS'
            : _auditVendor === 'linux' ? 'Linux' : '—';

        const filename = `audit-${(device || 'device').replace(/[^\w.-]+/g, '_')}-${new Date().toISOString().slice(0, 10)}`;

        const rows = rules.map(r => {
            const ev = (r.evidence || []).map(e => {
                const rawCtx = e.context || '';
                const ctxClean = rawCtx.replace(/^firewall policy\s*\/\s*(\d+)$/i, 'Policy ID #$1')
                                       .replace(/^policy\s*\/\s*(\d+)$/i, 'Policy ID #$1');
                return `<div class="evidence-item">`
                    + `<span class="evidence-line">${e.line ? (T.line + ' ' + escapeHtml(String(e.line))) : '—'}</span>`
                    + `<span class="evidence-ctx">${escapeHtml(ctxClean)}</span>`
                    + `<span class="evidence-txt">${escapeHtml(e.text || '')}</span>`
                    + `</div>`;
            }).join('');

            const evBlock = ev ? `<div class="evidence-box"><div class="evidence-hdr">${T.evidenceTitle}</div>${ev}</div>` : '';

            const statusClass = r.status === 'PASS' ? 'badge-pass'
                : r.status === 'FAIL' ? 'badge-fail'
                : r.status === 'WARN' ? 'badge-warn' : 'badge-unknown';

            const statusIcon = r.status === 'PASS' ? '✔ '
                : r.status === 'FAIL' ? '✖ '
                : r.status === 'WARN' ? '⚠ ' : '? ';

            const statusLabel = r.status === 'UNKNOWN' ? T.notAssessable : escapeHtml(r.status);

            const sevClass = r.severity === 'CRITICAL' ? 'badge-critical'
                : r.severity === 'HIGH' ? 'badge-high'
                : r.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low';

            const refBadges = [];
            if (r.ref) refBadges.push(`<span class="badge badge-ref">${escapeHtml(String(r.ref))}</span>`);
            if (r.level) refBadges.push(`<span class="badge badge-ref">L${escapeHtml(String(r.level))}</span>`);
            if (r.automated === false) refBadges.push(`<span class="badge badge-ref">${escapeHtml(T.manual)}</span>`);
            const refHtml = refBadges.length ? `<div class="ref-badges">${refBadges.join(' ')}</div>` : '';

            const auditCmd = r.audit
                ? `<div class="verify-box"><span class="verify-lbl">${T.verifyOn}:</span> <code>${escapeHtml(r.audit)}</code></div>`
                : '';

            const g = r.guidance || {};
            const guideItems = [];
            if (g.why) guideItems.push(`<div class="guide-item"><strong class="guide-lbl">${T.why}:</strong> <span class="guide-val">${escapeHtml(g.why)}</span></div>`);
            if (g.impact) guideItems.push(`<div class="guide-item"><strong class="guide-lbl">${T.impact}:</strong> <span class="guide-val">${escapeHtml(g.impact)}</span></div>`);
            if (g.default) guideItems.push(`<div class="guide-item"><strong class="guide-lbl">${T.defaultValue}:</strong> <span class="guide-val">${escapeHtml(g.default)}</span></div>`);
            const guidanceHtml = guideItems.length ? `<div class="guidance-box">${guideItems.join('')}</div>` : '';

            return `<tr class="finding-row st-${escapeHtml(r.status)}">
                <td class="col-id">
                    <strong class="rule-id">${escapeHtml(r.id)}</strong>
                    ${refHtml}
                </td>
                <td class="col-check">
                    <div class="rule-title">${escapeHtml(r.title)}</div>
                    <div class="rule-desc">${escapeHtml(r.detail)}</div>
                    ${guidanceHtml}
                    ${auditCmd}
                    ${evBlock}
                </td>
                <td class="col-sev"><span class="badge ${sevClass}">${escapeHtml(r.severity || 'MEDIUM')}</span></td>
                <td class="col-status"><span class="badge ${statusClass}">${statusIcon}${statusLabel}</span></td>
                <td class="col-fix"><code class="remediation-code">${escapeHtml(r.remediation || '—')}</code></td>
            </tr>`;
        }).join('');

        const partialBanner = unknown > 0
            ? `<div class="warn-banner"><strong>${T.partialTitle}</strong> ${T.partial(s.total - unknown, s.total, unknown)}</div>`
            : '';

        const scoreColor = (score !== null && score !== undefined)
            ? (score >= 80 ? '#10b981' : score >= 50 ? '#f59e0b' : '#ef4444')
            : '#64748b';

        const html = `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${T.docTitle} — ${escapeHtml(device)}</title>
<style>
*, *::before, *::after {
    box-sizing: border-box;
    -webkit-print-color-adjust: exact !important;
    print-color-adjust: exact !important;
    color-adjust: exact !important;
}
@page {
    size: A4 portrait;
    margin: 10mm 12mm 14mm 12mm;
}
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    color: #0f172a;
    background: #ffffff;
    margin: 0;
    padding: 14px 18px;
    font-size: 10px;
    line-height: 1.45;
}
.report-container {
    width: 100%;
    max-width: 100%;
    margin: 0 auto;
    box-sizing: border-box;
}
.report-actions-bar {
    display: none;
    margin-bottom: 16px;
    padding: 10px 16px;
    background: #0f172a;
    color: #ffffff;
    border-radius: 2px;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
.act-btn {
    padding: 6px 14px;
    border: none;
    border-radius: 2px;
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    margin-left: 6px;
    transition: opacity 0.15s ease;
}
.act-btn:hover { opacity: 0.9; }
.act-btn-blue { background: #2563eb; color: #fff; }
.act-btn-green { background: #10b981; color: #fff; }
.act-btn-cyan { background: #0284c7; color: #fff; }
.act-btn-gray { background: #475569; color: #fff; }

/* Report Header */
.report-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 2px solid #0f172a;
    padding-bottom: 10px;
    margin-bottom: 14px;
    break-inside: avoid;
    page-break-inside: avoid;
}
.brand-title {
    font-size: 18px;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
}
.report-subtitle {
    font-size: 12px;
    font-weight: 600;
    color: #334155;
    margin-top: 3px;
}
.header-tag {
    background: #e2e8f0;
    color: #1e293b;
    padding: 3px 8px;
    border-radius: 2px;
    font-size: 9.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

/* Metadata Grid */
.meta-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 6px;
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    border-radius: 2px;
    padding: 8px 12px;
    margin-bottom: 14px;
    break-inside: avoid;
    page-break-inside: avoid;
}
.meta-item { font-size: 10px; }
.meta-label {
    color: #475569;
    font-weight: 700;
    text-transform: uppercase;
    font-size: 8.5px;
    letter-spacing: 0.04em;
    display: block;
    margin-bottom: 2px;
}
.meta-value {
    color: #0f172a;
    font-weight: 700;
    font-size: 11px;
    word-break: break-word;
}

/* KPI Summary Cards */
.kpis {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 6px;
    margin-bottom: 14px;
    break-inside: avoid;
    page-break-inside: avoid;
}
.kpi-card {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 2px;
    padding: 6px 8px;
    text-align: center;
    border-top: 3px solid #64748b;
    break-inside: avoid;
    page-break-inside: avoid;
}
.kpi-card.kpi-score { border-top-color: ${scoreColor}; background: #f8fafc; }
.kpi-card.kpi-pass { border-top-color: #10b981; }
.kpi-card.kpi-fail { border-top-color: #ef4444; }
.kpi-card.kpi-warn { border-top-color: #f59e0b; }
.kpi-card.kpi-unknown { border-top-color: #94a3b8; }
.kpi-num {
    font-size: 17px;
    font-weight: 800;
    line-height: 1.1;
    color: #0f172a;
}
.kpi-card.kpi-score .kpi-num { color: ${scoreColor}; }
.kpi-card.kpi-pass .kpi-num { color: #059669; }
.kpi-card.kpi-fail .kpi-num { color: #dc2626; }
.kpi-card.kpi-warn .kpi-num { color: #d97706; }
.kpi-card.kpi-unknown .kpi-num { color: #475569; }
.kpi-label {
    font-size: 8.5px;
    font-weight: 700;
    color: #475569;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    margin-top: 2px;
}

/* Warning banner */
.warn-banner {
    background: #fffbeb;
    border: 1px solid #fde68a;
    color: #92400e;
    padding: 8px 12px;
    border-radius: 2px;
    margin-bottom: 14px;
    font-size: 10.5px;
    line-height: 1.4;
    break-inside: avoid;
    page-break-inside: avoid;
}

/* Findings Table */
table.findings-table {
    width: 100%;
    table-layout: fixed;
    border-collapse: collapse;
    font-size: 10px;
    background: #ffffff;
}
thead { display: table-header-group; }
th {
    background: #0f172a;
    color: #ffffff;
    padding: 6px 8px;
    font-size: 9.5px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    border: 1px solid #0f172a;
    text-align: left;
}
tr.finding-row {
    border-bottom: 1px solid #cbd5e1;
    break-inside: avoid;
    page-break-inside: avoid;
}
tr.finding-row:nth-child(even) { background: #f8fafc; }
td {
    padding: 6px 8px;
    vertical-align: top;
    border: 1px solid #cbd5e1;
    word-break: break-word;
    overflow-wrap: break-word;
}
.col-id { width: 12%; word-break: break-all; }
.col-check { width: 52%; word-break: break-word; }
.col-sev { width: 8%; text-align: center; }
.col-status { width: 8%; text-align: center; }
.col-fix { width: 20%; word-break: break-word; }

/* Badges */
.badge {
    display: inline-block;
    padding: 2px 5px;
    font-size: 8.5px;
    font-weight: 700;
    border-radius: 2px;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    white-space: nowrap;
}
.badge-pass { background: #dcfce7; color: #15803d; border: 1px solid #bbf7d0; }
.badge-fail { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
.badge-warn { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
.badge-unknown { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }

.badge-critical { background: #991b1b; color: #ffffff; }
.badge-high { background: #ea580c; color: #ffffff; }
.badge-medium { background: #f59e0b; color: #000000; }
.badge-low { background: #64748b; color: #ffffff; }
.badge-ref { background: #e2e8f0; color: #1e293b; font-family: 'Azeret Mono', ui-monospace, 'Cascadia Mono', Consolas, monospace; font-size: 8.5px; font-weight: 600; margin-top: 3px; }
.ref-badges { display: flex; flex-wrap: wrap; gap: 3px; margin-top: 4px; }

/* Rule details */
.rule-id { font-family: 'Azeret Mono', ui-monospace, 'Cascadia Mono', Consolas, monospace; font-size: 9.5px; color: #0f172a; font-weight: 700; word-break: break-all; }
.rule-title { font-weight: 700; color: #0f172a; font-size: 11px; margin-bottom: 2px; line-height: 1.35; }
.rule-desc { color: #0f172a; font-size: 10px; margin-top: 2px; line-height: 1.4; }
.guidance-box {
    margin-top: 5px;
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    border-radius: 2px;
    padding: 6px 8px;
    font-size: 9.5px;
    line-height: 1.45;
    color: #0f172a !important;
    break-inside: avoid;
    page-break-inside: avoid;
}
.guide-item { margin-bottom: 3px; color: #0f172a !important; }
.guide-item:last-child { margin-bottom: 0; }
.guide-lbl { font-weight: 800; color: #0f172a !important; margin-right: 3px; }
.guide-val { color: #0f172a !important; font-weight: 500; }

.verify-box {
    margin-top: 5px;
    font-size: 9.5px;
    color: #0f172a;
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    padding: 4px 6px;
    border-radius: 2px;
    break-inside: avoid;
    page-break-inside: avoid;
}
.verify-box code { font-family: 'Azeret Mono', ui-monospace, 'Cascadia Mono', Consolas, monospace; color: #0f172a; font-weight: 600; white-space: pre-wrap; word-break: break-all; font-size: 9px; }
.verify-lbl { font-weight: 700; color: #334155; margin-right: 4px; }

.evidence-box {
    margin-top: 5px;
    border: 1px solid #fca5a5;
    background: #fff5f5;
    border-radius: 2px;
    padding: 5px 8px;
    break-inside: avoid;
    page-break-inside: avoid;
}
.evidence-hdr { font-size: 9px; font-weight: 700; color: #991b1b; text-transform: uppercase; letter-spacing: 0.03em; margin-bottom: 2px; }
.evidence-item {
    font-family: 'Azeret Mono', ui-monospace, 'Cascadia Mono', Consolas, monospace;
    font-size: 9px;
    display: flex;
    gap: 6px;
    padding: 1px 0;
    flex-wrap: wrap;
    color: #0f172a;
}
.evidence-line { color: #475569; font-weight: 700; min-width: 45px; }
.evidence-ctx { color: #0f172a; font-weight: 700; min-width: 100px; }
.evidence-txt { color: #b91c1c; font-weight: 700; word-break: break-all; }

.remediation-code {
    font-family: 'Azeret Mono', ui-monospace, 'Cascadia Mono', Consolas, monospace;
    font-size: 9px;
    background: #f0f9ff;
    border: 1px solid #bae6fd;
    color: #0369a1;
    padding: 4px 6px;
    border-radius: 2px;
    display: block;
    font-weight: 600;
    white-space: pre-wrap;
    word-break: break-word;
}

/* Footer & Note */
.report-note {
    font-size: 9px;
    color: #475569;
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    border-radius: 2px;
    padding: 7px 10px;
    margin-top: 14px;
    break-inside: avoid;
    page-break-inside: avoid;
}
.report-footer {
    margin-top: 16px;
    padding-top: 8px;
    border-top: 1px solid #cbd5e1;
    font-size: 9px;
    color: #475569;
    display: flex;
    justify-content: space-between;
    align-items: center;
    break-inside: avoid;
    page-break-inside: avoid;
}

@media print {
    body { padding: 0; margin: 0; }
    .no-print { display: none !important; }
    .report-container { max-width: 100%; width: 100%; }
}
</style>
<base href="/">
<script src="/static/vendor/html2pdf/html2pdf.bundle.min.js"></script>
<script>
window.addEventListener('DOMContentLoaded', function() {
    if (window.self === window.top) {
        var bar = document.querySelector('.report-actions-bar');
        if (bar) bar.style.display = 'flex';
    }
});

async function downloadPdf() {
    var btn = document.querySelector('.act-btn-green');
    var origText = btn ? btn.textContent : '';
    if (btn) btn.textContent = '...';

    var h2p = (typeof html2pdf !== 'undefined') ? html2pdf : (window.parent && window.parent.html2pdf);
    if (!h2p && window.parent && typeof window.parent.ensureHtml2Pdf === 'function') {
        try {
            h2p = await window.parent.ensureHtml2Pdf();
        } catch(err) {}
    }

    if (h2p) {
        var opt = {
            margin: 10,
            filename: '${filename}.pdf',
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: {
                scale: 2,
                useCORS: true,
                backgroundColor: '#ffffff',
                logging: false,
                scrollY: 0,
                scrollX: 0
            },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait', compress: true },
            pagebreak: { mode: 'css' }
        };
        var styleEl = document.querySelector('style');
        var reportEl = document.querySelector('.report-container');
        var wrapper = document.createElement('div');
        wrapper.style.width = '100%';
        wrapper.style.boxSizing = 'border-box';
        wrapper.style.padding = '0 6px';
        wrapper.style.background = '#ffffff';
        if (styleEl) wrapper.appendChild(styleEl.cloneNode(true));
        if (reportEl) {
            var clone = reportEl.cloneNode(true);
            clone.querySelectorAll('.no-print').forEach(function(el) { el.remove(); });
            wrapper.appendChild(clone);
        }
        try {
            await h2p().set(opt).from(wrapper).save();
        } catch(e) {
            console.error('PDF error:', e);
            alert('Errore durante la generazione del PDF: ' + (e.message || e));
        } finally {
            if (btn) btn.textContent = origText;
        }
    } else {
        if (btn) btn.textContent = origText;
        alert('Libreria PDF non caricata. Riprova.');
    }
}

function downloadDocx() {
    if (window.parent && typeof window.parent.downloadModalDocx === 'function') {
        window.parent.downloadModalDocx();
    } else {
        alert('Esportazione DOCX disponibile dal pannello principale.');
    }
}

function downloadHtml() {
    var clone = document.documentElement.cloneNode(true);
    var noPrints = clone.querySelectorAll('.no-print');
    noPrints.forEach(function(el) { el.remove(); });
    var blob = new Blob(['<!doctype html>\\n' + clone.outerHTML], { type: 'text/html;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = '${filename}.html';
    a.click();
}
</script>
</head>
<body>
<div class="report-container">
    <div class="no-print report-actions-bar">
        <div>
            <strong style="font-size:13px;">SentinelNet</strong>
            <span style="color:#cbd5e1; font-size:12px;"> — ${T.subheading}</span>
        </div>
        <div>
            <button onclick="downloadPdf()" class="act-btn act-btn-green">${T.pdf}</button>
            <button onclick="downloadDocx()" class="act-btn act-btn-cyan"><i class="fa-solid fa-file-word"></i> DOCX</button>
            <button onclick="downloadHtml()" class="act-btn act-btn-gray">${T.html}</button>
            <button onclick="window.print()" class="act-btn act-btn-blue">${T.printVector}</button>
        </div>
    </div>

    <div class="report-header">
        <div>
            <h1 class="brand-title">SentinelNet <span style="font-weight:400; color:#64748b;">|</span> ${T.heading}</h1>
            <div class="report-subtitle">${escapeHtml(benchmark)}</div>
        </div>
        <div class="header-tag">Security Audit</div>
    </div>

    <div class="meta-grid">
        <div class="meta-item"><span class="meta-label">${T.device}</span><span class="meta-value">${escapeHtml(device)}</span></div>
        <div class="meta-item"><span class="meta-label">${T.platform}</span><span class="meta-value">${escapeHtml(platform)}</span></div>
        <div class="meta-item"><span class="meta-label">${T.benchmark}</span><span class="meta-value">${escapeHtml(benchmark)}</span></div>
        <div class="meta-item"><span class="meta-label">${T.generatedOn}</span><span class="meta-value">${escapeHtml(generated)}</span></div>
    </div>

    ${partialBanner}

    <div class="kpis">
        <div class="kpi-card kpi-score"><div class="kpi-num">${escapeHtml(scoreTxt)}</div><div class="kpi-label">${T.score}</div></div>
        <div class="kpi-card kpi-pass"><div class="kpi-num">${s.passed}</div><div class="kpi-label">${T.passed}</div></div>
        <div class="kpi-card kpi-fail"><div class="kpi-num">${s.failed}</div><div class="kpi-label">${T.failed}</div></div>
        <div class="kpi-card kpi-warn"><div class="kpi-num">${s.warned}</div><div class="kpi-label">${T.warned}</div></div>
        <div class="kpi-card kpi-unknown"><div class="kpi-num">${unknown}</div><div class="kpi-label">${T.unknown}</div></div>
    </div>

    <table class="findings-table">
        <thead>
            <tr>
                <th class="col-id">${T.thId}</th>
                <th class="col-check">${T.thCheck}</th>
                <th class="col-sev">${T.thSeverity}</th>
                <th class="col-status">${T.thStatus}</th>
                <th class="col-fix">${T.thFix}</th>
            </tr>
        </thead>
        <tbody>
            ${rows}
        </tbody>
    </table>

    <div class="report-note">${T.note}</div>

    <div class="report-footer">
        <span>${T.footerNotice}</span>
        <span>${escapeHtml(generated)}</span>
    </div>
</div>
</body>
</html>`;

        openAuditReportModal(html, filename, `SentinelNet — ${T.preview}`, {
            rules,
            summary: s,
            score,
            device_name: device,
            benchmark: benchmarkKey,
            benchmark_title: benchmark,
            vendor: _auditVendor,
            lang,
            generated
        });
    }

    let _currentReportHtml = '';
    let _currentReportFilename = '';
    let _currentAuditPayload = null;

    async function ensureHtml2Pdf() {
        if (typeof window.html2pdf === 'function') return window.html2pdf;
        return new Promise((resolve, reject) => {
            const s = document.createElement('script');
            s.src = '/static/vendor/html2pdf/html2pdf.bundle.min.js';
            s.onload = () => resolve(window.html2pdf);
            s.onerror = () => reject(new Error('Impossibile caricare la libreria html2pdf'));
            document.head.appendChild(s);
        });
    }
    window.ensureHtml2Pdf = ensureHtml2Pdf;

    function openAuditReportModal(html, filename, titleText, payload) {
        _currentReportHtml = html;
        _currentReportFilename = filename || 'audit-report';
        _currentAuditPayload = payload || null;
        const modal = document.getElementById('auditReportModal');
        const frame = document.getElementById('auditReportFrame');
        const titleEl = document.getElementById('auditReportModalTitle');
        if (titleEl && titleText) {
            titleEl.innerHTML = `<i class="fa-solid fa-file-shield" style="color:var(--primary);"></i> <span>${escapeHtml(titleText)}</span>`;
        }
        if (modal) {
            modal.style.display = 'flex';
        }
        if (frame) {
            frame.srcdoc = html;
        }
    }

    function closeAuditReportModal() {
        const modal = document.getElementById('auditReportModal');
        if (modal) modal.style.display = 'none';
    }

    async function downloadModalPdf() {
        const btn = document.getElementById('auditModalBtnPdf');
        const origHtml = btn ? btn.innerHTML : '';
        if (btn) {
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ' + (currentLang === 'en' ? 'Generating PDF...' : 'Generazione PDF...');
            btn.disabled = true;
        }
        try {
            const h2p = await ensureHtml2Pdf();
            if (!h2p) {
                throw new Error(currentLang === 'en' ? 'PDF library not loaded' : 'Libreria PDF non disponibile');
            }

            const frame = document.getElementById('auditReportFrame');
            const doc = frame && frame.contentDocument ? frame.contentDocument : null;

            const filename = (_currentReportFilename || 'compliance-report') + '.pdf';
            const opt = {
                margin: 10,
                filename: filename,
                image: { type: 'jpeg', quality: 0.98 },
                html2canvas: {
                    scale: 2,
                    useCORS: true,
                    backgroundColor: '#ffffff',
                    logging: false,
                    scrollY: 0,
                    scrollX: 0
                },
                jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait', compress: true },
                pagebreak: { mode: 'css' }
            };

            const styleEl = doc ? doc.querySelector('style') : null;
            const reportEl = doc ? doc.querySelector('.report-container') : null;

            if (reportEl) {
                const wrapper = document.createElement('div');
                wrapper.style.width = '100%';
                wrapper.style.boxSizing = 'border-box';
                wrapper.style.padding = '0 6px';
                wrapper.style.background = '#ffffff';
                if (styleEl) wrapper.appendChild(styleEl.cloneNode(true));
                const clone = reportEl.cloneNode(true);
                clone.querySelectorAll('.no-print').forEach(el => el.remove());
                wrapper.appendChild(clone);

                await h2p().set(opt).from(wrapper).save();
                showToast(currentLang === 'en' ? 'PDF downloaded successfully.' : 'PDF scaricato con successo.', 'info');
            } else {
                throw new Error(currentLang === 'en' ? 'Report content not found' : 'Contenuto del report non trovato');
            }
        } catch (e) {
            console.error('PDF export error:', e);
            showToast((currentLang === 'en' ? 'Failed to generate PDF: ' : 'Errore generazione PDF: ') + (e.message || e), 'error');
        } finally {
            if (btn) {
                btn.innerHTML = origHtml;
                btn.disabled = false;
            }
        }
    }

    async function downloadModalDocx() {
        const payload = _currentAuditPayload || {
            rules: _auditRules,
            summary: _auditSummary,
            score: _auditScore,
            device_name: _auditDeviceName,
            benchmark_title: _auditBenchmarkName,
            vendor: _auditVendor,
            lang: currentLang
        };

        const btn = document.getElementById('auditModalBtnDoc');
        const origHtml = btn ? btn.innerHTML : '';
        if (btn) {
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ' + (currentLang === 'en' ? 'Generating DOCX...' : 'Generazione DOCX...');
            btn.disabled = true;
        }

        try {
            const res = await apiFetch('/api/netsec-audit/export/docx', {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (!res || !res.ok) {
                throw new Error(currentLang === 'en' ? 'Failed to generate DOCX on server' : 'Errore server durante la generazione del DOCX');
            }
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = (_currentReportFilename || 'compliance-report') + '.docx';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast(currentLang === 'en' ? 'DOCX file downloaded successfully.' : 'File DOCX scaricato con successo.', 'info');
        } catch (e) {
            console.error('DOCX export error:', e);
            showToast((currentLang === 'en' ? 'Failed to export DOCX: ' : 'Errore esportazione DOCX: ') + (e.message || e), 'error');
        } finally {
            if (btn) {
                btn.innerHTML = origHtml;
                btn.disabled = false;
            }
        }
    }
    window.downloadModalDocx = downloadModalDocx;

    function printModalReport() {
        const frame = document.getElementById('auditReportFrame');
        if (frame && frame.contentWindow) {
            frame.contentWindow.focus();
            frame.contentWindow.print();
        }
    }

    function downloadModalHtml() {
        if (!_currentReportHtml) return;
        const blob = new Blob([_currentReportHtml], { type: 'text/html;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = (_currentReportFilename || 'audit-report') + '.html';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
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
                const runName = r.run_name ? escapeHtml(r.run_name) : null;
                const devDisplay = runName
                    ? `<strong style="color:var(--text); font-size:12px;">${runName}</strong><br><span style="font-size:11px; color:var(--text-muted);">${dev}</span>`
                    : `<span style="font-size:12px; font-weight:600;">${dev}</span>`;
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
                    <td style="font-size:12px;">${devDisplay}</td>
                    <td style="font-size:12px;">${bench}</td>
                    <td style="font-size:12px;">${vendor}</td>
                    <td style="font-size:12px; font-weight:700;">${scoreStr}</td>
                    <td style="font-size:11px; font-weight:700; color:${gradeColor};">${escapeHtml(gradeStr)}</td>
                    <td style="font-size:12px; color:var(--text-muted);">${actor}</td>
                    <td>
                        <button class="btn btn-secondary btn-small" data-action="open-audit-run" data-run-id="${r.id}" style="padding:2px 8px; font-size:11px; margin:0 4px 0 0;" title="Apri Matrice Risultati"><i class="fa-solid fa-table-list"></i> Apri</button>
                        <button class="btn btn-secondary btn-small" data-action="view-audit-report" data-run-id="${r.id}" style="padding:2px 8px; font-size:11px; margin:0 4px 0 0;" title="Anteprima Relazione Compliance"><i class="fa-solid fa-file-lines"></i> Report</button>
                        <button class="btn btn-secondary btn-small requires-admin" data-action="delete-audit-run" data-run-id="${r.id}" style="padding:2px 8px; font-size:11px; margin:0; color:var(--danger);" title="Elimina dallo storico"><i class="fa-solid fa-trash"></i></button>
                    </td>
                </tr>`;
            }).join('');
            if (typeof applyRoleUI === 'function') applyRoleUI(currentUsername, currentRole);
        } catch (e) {
            console.error('loadAuditHistory error:', e);
            tbody.innerHTML = `<tr><td colspan="8" style="padding:15px; text-align:center; color:var(--text-muted);">${currentLang === 'en' ? 'Error loading history.' : 'Errore nel caricamento dello storico.'}</td></tr>`;
        }
    }

    function toggleAuditSaveNameInput() {
        const input = document.getElementById('auditRunName');
        const chk = document.getElementById('auditSaveRun');
        if (input && input.value.trim() !== '' && chk) {
            chk.checked = true;
        }
    }

    function switchNetSecSubtab(sub) {
        const btnScan = document.getElementById('subtabBtnAuditScan');
        const btnChecklist = document.getElementById('subtabBtnChecklist');
        const paneScan = document.getElementById('netsecSubtabScan');
        const paneChecklist = document.getElementById('netsecSubtabChecklist');
        if (!btnScan || !btnChecklist || !paneScan || !paneChecklist) return;

        if (sub === 'checklist') {
            btnScan.classList.remove('active');
            btnChecklist.classList.add('active');
            paneScan.style.display = 'none';
            paneChecklist.style.display = 'block';
            if (typeof loadAuditChecklistTab === 'function') loadAuditChecklistTab();
        } else {
            btnChecklist.classList.remove('active');
            btnScan.classList.add('active');
            paneChecklist.style.display = 'none';
            paneScan.style.display = 'block';
            loadAuditHistory();
        }
    }

    async function openAuditRun(id, openReport = false) {
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
            _auditDeviceName = data.device_name || data.run_name || data.device_ip || 'Audit';
            _auditBenchmarkName = data.benchmark_title || data.benchmark || 'CIS';
            renderAuditOverview();
            renderAuditRulesTable();
            showToast(currentLang === 'en' ? 'Audit run loaded from history.' : 'Run di audit caricata dallo storico.', 'info');

            if (openReport) {
                exportAuditReport();
            } else {
                const target = document.getElementById('auditRulesTableBody')?.closest('.panel') || document.getElementById('auditRulesTableBody');
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            }
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

    // Delegated and static event listeners
    document.getElementById('netsecSubtabNav')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-subtab]');
        if (btn && btn.dataset.subtab) switchNetSecSubtab(btn.dataset.subtab);
    });

    document.getElementById('auditBenchmarkSelect')?.addEventListener('change', renderBenchmarkRequirements);
    document.getElementById('auditBenchmarkReqs')?.addEventListener('toggle', renderBenchmarkRequirements);
    document.getElementById('auditRunName')?.addEventListener('input', toggleAuditSaveNameInput);
    document.getElementById('btnRunAuditScan')?.addEventListener('click', runAuditScan);
    document.getElementById('btnExportAuditReport')?.addEventListener('click', exportAuditReport);
    document.getElementById('auditSevFilter')?.addEventListener('change', renderAuditRulesTable);
    document.getElementById('auditCatFilter')?.addEventListener('change', renderAuditRulesTable);
    document.getElementById('auditStatusFilter')?.addEventListener('change', renderAuditRulesTable);
    document.getElementById('btnRefreshAuditHistory')?.addEventListener('click', loadAuditHistory);

    document.getElementById('auditRulesTableBody')?.addEventListener('click', (e) => {
        const row = e.target.closest('tr[data-action="toggle-audit-detail"]');
        if (row && row.dataset.evId) {
            toggleAuditDetail(row.dataset.evId);
        }
    });

    document.getElementById('auditHistoryBody')?.addEventListener('click', (e) => {
        const openBtn = e.target.closest('[data-action="open-audit-run"]');
        if (openBtn && openBtn.dataset.runId) {
            openAuditRun(Number(openBtn.dataset.runId), false);
            return;
        }
        const repBtn = e.target.closest('[data-action="view-audit-report"]');
        if (repBtn && repBtn.dataset.runId) {
            openAuditRun(Number(repBtn.dataset.runId), true);
            return;
        }
        const delBtn = e.target.closest('[data-action="delete-audit-run"]');
        if (delBtn && delBtn.dataset.runId) {
            deleteAuditRun(Number(delBtn.dataset.runId));
        }
    });

    document.getElementById('auditModalBtnPdf')?.addEventListener('click', downloadModalPdf);
    document.getElementById('auditModalBtnDoc')?.addEventListener('click', downloadModalDocx);
    document.getElementById('auditModalBtnPrint')?.addEventListener('click', printModalReport);
    document.getElementById('auditModalBtnHtml')?.addEventListener('click', downloadModalHtml);
    document.getElementById('auditModalBtnClose')?.addEventListener('click', closeAuditReportModal);
    document.getElementById('auditReportModal')?.addEventListener('click', (e) => {
        if (e.target.id === 'auditReportModal') closeAuditReportModal();
    });

    // Expose functions globally
    window.renderBenchmarkRequirements = renderBenchmarkRequirements;
    window.loadNetSecAuditTab = loadNetSecAuditTab;
    window.runAuditScan = runAuditScan;
    window.exportAuditReport = exportAuditReport;
    window.openAuditReportModal = openAuditReportModal;
    window.closeAuditReportModal = closeAuditReportModal;
    window.renderAuditRulesTable = renderAuditRulesTable;
    window.toggleAuditDetail = toggleAuditDetail;
    window.clearUploadedConfig = clearUploadedConfig;
    window.loadAuditHistory = loadAuditHistory;
    window.openAuditRun = openAuditRun;
    window.deleteAuditRun = deleteAuditRun;
    window.toggleAuditSaveNameInput = toggleAuditSaveNameInput;
    window.switchNetSecSubtab = switchNetSecSubtab;

    // Auto-init if tab is active or rendered
    loadNetSecAuditTab();
})();

