// Tabelle di routing di piu' apparati in una vista sola.
//
// La tab FortiGate mostra da sempre la RIB di UN firewall alla volta. La
// domanda che si fa davvero e' l'altra — "chi ha una rotta verso questa rete,
// e i due apparati sono d'accordo" — e per rispondere bisognava aprire la tab
// una volta per apparato e confrontare a occhio.
//
// Qui non si raccoglie niente di nuovo: /api/routes chiama lo stesso servizio
// su tutti gli apparati in scope e ne normalizza le risposte.
(function () {
    'use strict';

    let _rtRows = [];
    let _rtCounts = {};
    let _rtErrors = [];

    // I colori dei tipi sono gli stessi in tabella e nel grafico: una barra
    // gialla e una riga gialla devono voler dire la stessa cosa senza che
    // l'utente debba leggere due legende.
    // Solo le quattro famiglie che si incontrano davvero hanno un colore
    // proprio; il resto resta muto. --accent non esiste in questa palette (i
    // token sono --primary/--success/--warning/--danger/--info): chiederlo
    // tornava stringa vuota, quindi la barra BGP finiva sul grigio di ripiego
    // e il badge su un var() non valido.
    const RT_TYPE_COLORS = {
        connected: '--success',
        local: '--text-muted',
        static: '--primary',
        ospf: '--warning',
        bgp: '--info',
        eigrp: '--text-muted',
        rip: '--text-muted',
        isis: '--text-muted',
        other: '--text-muted',
        unknown: '--text-muted',
    };
    const RT_TYPE_ORDER = ['connected', 'local', 'static', 'ospf', 'bgp',
                           'eigrp', 'rip', 'isis', 'other', 'unknown'];

    function rtTypeColor(type) {
        const varName = RT_TYPE_COLORS[type] || '--text-muted';
        return `var(${varName})`;
    }

    function rtSelectedDevices() {
        return pickerValues('rtDeviceFilter');
    }

    function rtFilters() {
        const val = id => {
            const el = /** @type {HTMLInputElement|HTMLSelectElement|null} */ (
                document.getElementById(id));
            return el ? el.value : '';
        };
        return { device: rtSelectedDevices().join(','),
                 type: val('rtTypeFilter'), q: val('rtSearch') };
    }

    // L'elenco arriva dall'inventario, non dalle righe tornate: un apparato
    // mai interrogato deve poter essere scelto, ed e' il motivo per cui gli
    // switch non comparivano qui.
    async function loadRtDeviceList() {
        let devices = [];
        try {
            const res = await apiFetch('/api/routes/devices');
            if (res && res.ok) devices = (await res.json()).devices || [];
        } catch (e) { devices = []; }
        renderPickerItems('rtDeviceFilter', devices
            .sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''))
            .map(d => ({ value: d.ip, label: d.hostname || d.ip, hint: d.ip })));
    }

    // Apertura del tab: si popola la lista e si aspetta. Interrogare da soli
    // tutta la flotta e' esattamente quello che questa vista non deve fare.
    async function routesTabShown() {
        await loadRtDeviceList();
        rtTraceSyncSources();
        renderRtTrace();
        renderRtTable();
        renderRtChart();
    }

    async function loadRoutesTab() {
        const f = rtFilters();
        if (!f.device) {
            // Nessun apparato scelto: nessuna sessione aperta.
            _rtRows = []; _rtCounts = {}; _rtErrors = [];
            renderRtErrors();
            renderRtTable();
            renderRtChart();
            return;
        }
        const url = `/api/routes?device=${encodeURIComponent(f.device)}`
            + `&type=${encodeURIComponent(f.type)}&q=${encodeURIComponent(f.q.trim())}`;
        const body = document.getElementById('rtTableBody');
        if (body) {
            body.innerHTML = `<tr><td colspan="5" style="padding:20px; text-align:center;
                color:var(--text-muted);">${escapeHtml(tr('rtLoading'))}</td></tr>`;
        }
        try {
            const res = await apiFetch(url);
            if (!res || !res.ok) throw new Error('HTTP ' + (res ? res.status : '?'));
            const data = await res.json();
            _rtRows = data.rows || [];
            _rtCounts = data.counts || {};
            _rtErrors = data.errors || [];
        } catch (e) {
            _rtRows = [];
            _rtCounts = {};
            _rtErrors = [{ device_ip: '', error: String(e) }];
        }
        renderRtErrors();
        renderRtTable();
        renderRtChart();
    }

    function renderRtErrors() {
        const box = document.getElementById('rtErrors');
        if (!box) return;
        if (!_rtErrors.length) { box.style.display = 'none'; box.innerHTML = ''; return; }
        // Un apparato muto e' una riga accanto agli altri, non una tabella
        // vuota per tutti: senza dirlo, l'assenza delle sue rotte si legge
        // come "non ne ha".
        box.style.display = '';
        box.innerHTML = `<div style="border:1px solid var(--warning);
              background:color-mix(in srgb, var(--warning) 8%, transparent); padding:10px 14px; font-size:12px;">
            <strong>${escapeHtml(tr('rtPartial', { n: _rtErrors.length }))}</strong>
            <ul style="margin:6px 0 0; padding-left:18px;">${
                _rtErrors.map(e => `<li><span style="font-family:var(--font-code);">${
                    escapeHtml(e.device_ip || '?')}</span> &mdash; ${escapeHtml(e.error)}</li>`).join('')}</ul>
          </div>`;
    }

    function rtTypeBadge(type) {
        const color = rtTypeColor(type);
        return `<span class="badge" style="border-color:${color}; color:${color};">${
            escapeHtml(type)}</span>`;
    }

    function renderRtTable() {
        const tbody = document.getElementById('rtTableBody');
        const count = document.getElementById('rtCount');
        if (!tbody) return;
        if (count) count.textContent = tr('rtCount', { n: _rtRows.length });
        if (!_rtRows.length) {
            const msg = rtSelectedDevices().length ? tr('rtEmpty') : tr('rtPickDevices');
            tbody.innerHTML = `<tr><td colspan="5" style="padding:20px; text-align:center;
                color:var(--text-muted);">${escapeHtml(msg)}</td></tr>`;
            return;
        }
        const dash = '<span style="color:var(--text-muted);">&mdash;</span>';
        let lastGroup = null;
        const html = [];
        for (const r of _rtRows) {
            const group = `${r.device} ${r.type}`;
            if (group !== lastGroup) {
                lastGroup = group;
                // Intestazione di gruppo: raggruppare per apparato E tipo e'
                // il modo in cui si legge una RIB, non per righe alfabetiche.
                // Righe lette dal backup e non dall'apparato: il badge sta
                // sull'intestazione perche' l'origine e' dell'apparato, non
                // della singola rotta.
                const fromBackup = r.from_backup
                    ? ` <span class="badge" style="border-color:var(--warning); color:var(--warning);">${
                          escapeHtml(tr('rtFromBackup'))}</span>` : '';
                html.push(`<tr style="background:var(--surface-3);">
                    <td colspan="5" style="padding:6px 8px; font-weight:700; font-size:12px;">
                      ${escapeHtml(r.device)} &middot; ${rtTypeBadge(r.type)}${fromBackup}
                      <span style="color:var(--text-muted); font-weight:400; font-family:var(--font-code);">
                        ${escapeHtml(r.device_ip || '')}</span>
                    </td></tr>`);
            }
            const hop = [r.gateway, r.interface ? `(${r.interface})` : '']
                .filter(Boolean).join(' ');
            html.push(`<tr style="border-top:1px solid var(--border); font-size:12px;">
                <td style="padding:6px 8px; font-family:var(--font-code);">${escapeHtml(r.network)}</td>
                <td style="padding:6px 8px; font-family:var(--font-code);">${hop ? escapeHtml(hop) : dash}</td>
                <td style="padding:6px 8px;">${rtTypeBadge(r.type)}</td>
                <td style="padding:6px 8px; text-align:right; font-family:var(--font-code);">${
                    r.distance === null || r.distance === undefined ? dash : escapeHtml(String(r.distance))}</td>
                <td style="padding:6px 8px; text-align:right; font-family:var(--font-code);">${
                    r.metric === null || r.metric === undefined ? dash : escapeHtml(String(r.metric))}</td>
            </tr>`);
        }
        tbody.innerHTML = html.join('');
    }

    function renderRtChart() {
        const canvas = /** @type {HTMLCanvasElement|null} */ (
            document.getElementById('rtChartCanvas'));
        if (!canvas) return;
        const devices = Object.keys(_rtCounts).sort();
        const ratio = window.devicePixelRatio || 1;
        const width = canvas.clientWidth || 600;
        const height = canvas.clientHeight || 220;
        canvas.width = width * ratio;
        canvas.height = height * ratio;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        ctx.clearRect(0, 0, width, height);
        if (!devices.length) return;

        const css = getComputedStyle(document.body);
        const textColor = css.getPropertyValue('--text-muted') || '#888';
        const borderColor = css.getPropertyValue('--border') || '#444';
        const colorOf = t => (css.getPropertyValue(
            RT_TYPE_COLORS[t] || '--text-muted') || '#888').trim();

        const totals = devices.map(d => Object.values(_rtCounts[d])
            .reduce((a, b) => a + b, 0));
        const peak = Math.max(...totals, 1);
        const pad = { top: 22, right: 12, bottom: 34, left: 44 };
        const graphW = width - pad.left - pad.right;
        const graphH = height - pad.top - pad.bottom;
        const slot = graphW / devices.length;
        const barW = Math.min(72, slot * 0.6);

        ctx.font = '10px sans-serif';
        ctx.lineWidth = 1;
        [0, 0.5, 1].forEach(factor => {
            const y = height - pad.bottom - factor * graphH;
            ctx.strokeStyle = factor === 0 ? borderColor : 'rgba(128,128,128,0.18)';
            ctx.beginPath();
            ctx.moveTo(pad.left, y);
            ctx.lineTo(width - pad.right, y);
            ctx.stroke();
            ctx.fillStyle = textColor;
            ctx.textAlign = 'right';
            ctx.textBaseline = 'middle';
            ctx.fillText(String(Math.round(peak * factor)), pad.left - 8, y);
        });

        devices.forEach((device, i) => {
            const cx = pad.left + slot * i + slot / 2;
            let bottom = height - pad.bottom;
            // Impilate nell'ordine dichiarato e non in quello del dizionario:
            // altrimenti la stessa flotta cambia disposizione a ogni refresh.
            RT_TYPE_ORDER.forEach(type => {
                const n = _rtCounts[device][type] || 0;
                if (!n) return;
                const h = (n / peak) * graphH;
                ctx.fillStyle = colorOf(type);
                ctx.fillRect(cx - barW / 2, bottom - h, barW, h);
                bottom -= h;
            });
            ctx.fillStyle = textColor;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'top';
            ctx.fillText(device.length > 14 ? device.slice(0, 13) + '…' : device,
                         cx, height - pad.bottom + 6);
        });

        // Legenda: senza, le barre impilate sono colori senza nome.
        let lx = pad.left;
        const ly = 4;
        RT_TYPE_ORDER.forEach(type => {
            if (!devices.some(d => _rtCounts[d][type])) return;
            ctx.fillStyle = colorOf(type);
            ctx.fillRect(lx, ly, 9, 9);
            ctx.fillStyle = textColor;
            ctx.textAlign = 'left';
            ctx.textBaseline = 'top';
            ctx.fillText(type, lx + 13, ly);
            lx += 22 + ctx.measureText(type).width;
        });
    }


    // --- ANALISI DI PERCORSO -------------------------------------------------
    //
    // Le rotte raccolte rispondono anche alla domanda successiva: dove finisce
    // un indirizzo, e perche' su ogni apparato ha vinto quella riga. Il calcolo
    // sta nel backend (/api/routes/trace) e gira sugli apparati SELEZIONATI: la
    // vista non allarga la selezione da sola.

    let _trace = null;
    let _traceTimer = null;
    // Due analisi lanciate a distanza di un istante (clic e poi Invio): vale
    // quella chiesta per ultima, non quella che risponde per ultima.
    let _traceSeq = 0;

    // I tre criteri, nell'ordine in cui un apparato li guarda. Le etichette
    // sono chiamate letterali: tr() con una chiave costruita a runtime
    // sfugge al controllo di copertura del dizionario.
    const rtRules = () => [
        { key: 'prefisso', label: tr('rtRulePrefix') },
        { key: 'distanza', label: tr('rtRuleDistance') },
        { key: 'metrica', label: tr('rtRuleMetric') },
    ];

    const RT_VERDICTS = {
        'consegna': 'ok',
        'fuori inventario': 'muted',
        'nessuna rotta': 'bad',
        'anello': 'bad',
        'biforcazione': 'warn',
        'non interrogato': 'warn',
        'limite salti': 'warn',
    };

    const RT_END = {
        'consegna': { label: 'rtTraceEndDelivery', color: 'var(--lamp-up-ink)' },
        'fuori inventario': { label: 'rtTraceEndOutside', color: 'var(--text-muted)' },
        'nessuna rotta': { label: 'rtTraceEndDropped', color: 'var(--lamp-fault-ink)' },
        'anello': { label: 'rtTraceEndLoop', color: 'var(--lamp-fault-ink)' },
        'biforcazione': { label: 'rtTraceEndFork', color: 'var(--lamp-warn-ink)' },
        'non interrogato': { label: 'rtTraceEndUnknown', color: 'var(--lamp-warn-ink)' },
        'limite salti': { label: 'rtTraceEndHopLimit', color: 'var(--lamp-warn-ink)' },
    };

    function rtTraceSyncSources() {
        // Si parte da uno degli apparati scelti: partire da uno non
        // selezionato sarebbe una richiesta a sorpresa, ed e' un 404 lato API.
        const sel = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        if (!sel) return;
        const current = sel.value;
        const chosen = pickerSelected('rtDeviceFilter');
        sel.innerHTML = chosen.length
            ? chosen.map(d => `<option value="${escapeHtml(d.value)}">${
                  escapeHtml(d.label)}</option>`).join('')
            : `<option value="">${escapeHtml(tr('rtTraceNoDevices'))}</option>`;
        if (chosen.some(d => d.value === current)) sel.value = current;
    }

    function rtTraceVerdict(kind, text) {
        const box = document.getElementById('rtTraceVerdict');
        if (!box) return;
        box.className = 'badge rt-verdict on ' + kind;
        box.textContent = text;
    }

    function rtTraceOutcomeText(data) {
        const n = (data.hops || []).length;
        switch (data.outcome) {
            case 'consegna': return tr('rtTraceDelivered', { n: n });
            case 'fuori inventario': return tr('rtTraceOutside', { hop: data.exit_hop || '?' });
            case 'nessuna rotta': return tr('rtTraceNoRoute');
            case 'anello': return tr('rtTraceLoop');
            case 'biforcazione': return tr('rtTraceFork');
            case 'non interrogato': return tr('rtTraceNotQueried', { ip: data.device_ip || '?' });
            case 'limite salti': return tr('rtTraceHopLimit', { n: n });
            default: return data.outcome || '';
        }
    }

    async function loadRtTrace() {
        const src = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        const dst = /** @type {HTMLInputElement|null} */ (
            document.getElementById('rtTraceDst'));
        if (!src || !dst) return;
        clearInterval(_traceTimer);
        const mine = ++_traceSeq;
        const devices = rtSelectedDevices().join(',');
        if (!devices || !src.value) { rtTraceVerdict('muted', tr('rtPickDevices')); return; }
        if (!dst.value.trim()) { rtTraceVerdict('muted', tr('rtTraceNeedDst')); return; }

        rtTraceVerdict('muted', tr('rtTraceRunning'));
        const url = `/api/routes/trace?device=${encodeURIComponent(devices)}`
            + `&src=${encodeURIComponent(src.value)}&dst=${encodeURIComponent(dst.value.trim())}`;
        try {
            const res = await apiFetch(url);
            if (!res || mine !== _traceSeq) return;
            const data = await res.json();
            if (mine !== _traceSeq) return;
            if (!res.ok) {
                _trace = null;
                renderRtTrace();
                rtTraceVerdict('bad', data.detail || ('HTTP ' + res.status));
                return;
            }
            _trace = data;
        } catch (e) {
            _trace = null;
            renderRtTrace();
            rtTraceVerdict('bad', String(e));
            return;
        }
        renderRtTrace();
        rtTracePlay();
    }

    function renderRtTrace() {
        const rail = document.getElementById('rtTraceRail');
        const steps = document.getElementById('rtTraceSteps');
        const play = document.getElementById('btnRtTracePlay');
        const probe = document.getElementById('rtProbeBox');
        if (!rail || !steps) return;
        if (!_trace || !(_trace.hops || []).length) {
            rail.style.display = 'none';
            rail.innerHTML = '';
            // Non un vuoto: la vista dice cosa le serve per rispondere.
            steps.innerHTML = `<p class="rt-idle">${escapeHtml(tr('rtTraceIdle'))}</p>`;
            if (play) play.style.display = 'none';
            if (probe) probe.style.display = 'none';
            return;
        }
        rtTraceVerdict(RT_VERDICTS[_trace.outcome] || 'muted',
                       tr((RT_END[_trace.outcome] || RT_END['non interrogato']).label));
        rail.style.display = '';
        rail.innerHTML = rtRailHtml(_trace);
        steps.innerHTML = rtStepsHtml(_trace);
        if (play) play.style.display = '';
        // Il traceroute manda pacchetti: e' un'azione, non una lettura, e a un
        // viewer non viene nemmeno offerta.
        if (probe) probe.style.display = (currentRole === 'viewer') ? 'none' : '';
        const out = document.getElementById('rtProbeOut');
        if (out) { out.style.display = 'none'; out.innerHTML = ''; }
    }

    // La catena in HTML e non in SVG: i riquadri si dimensionano sul contenuto,
    // quindi un hostname lungo non finisce sopra il suo IP e la striscia non
    // viene rimpicciolita per stare in larghezza — su schermo stretto va a capo.
    function rtRailHtml(data) {
        const hops = data.hops || [];
        const end = RT_END[data.outcome] || RT_END['non interrogato'];
        const items = hops.map((hop, i) => {
            const win = hop.best;
            const role = i === 0 ? tr('rtTraceStart') : tr('rtTraceHopN', { n: i });
            const flag = hop.from_backup
                ? `<span class="rt-node-flag">${escapeHtml(tr('rtFromBackup'))}</span>` : '';
            const meta = win
                ? (win.gateway ? tr('rtTraceVia', { hop: win.gateway }) + '  ·  ad ' + win.ad
                               : tr('rtTraceOnIface', { iface: win.interface || '?' }))
                : '';
            const link = win ? `
                <div class="rt-link">
                  <span class="rt-link-net"><b class="rt-kind" style="background:${
                      rtTypeColor(win.type)}">${escapeHtml(
                          (win.type || '?').slice(0, 1).toUpperCase())}</b>${
                      escapeHtml(win.network || '')}</span>
                  <span class="rt-link-line"></span>
                  <span class="rt-link-meta">${escapeHtml(meta)}</span>
                </div>` : '';
            return `<li class="rt-hop" data-hop="${i}">
                <div class="rt-node">
                  <span class="rt-node-role">${escapeHtml(role)}</span>
                  <span class="rt-node-name">${escapeHtml(hop.device || '')}</span>
                  <span class="rt-node-ip">${escapeHtml(hop.device_ip || '')}</span>
                  ${flag}
                </div>${link}
              </li>`;
        }).join('');
        // Il riquadro d'esito chiude la catena: e' l'unico che porta il colore
        // dello stato, perche' in questo sistema il colore vuol dire stato.
        const tail = `<li class="rt-hop rt-hop-end" data-hop="${hops.length}">
            <div class="rt-node rt-node-end" style="--rt-end:${end.color}">
              <span class="rt-node-role">${escapeHtml(tr('rtTraceEnd'))}</span>
              <span class="rt-node-name">${escapeHtml(tr(end.label))}</span>
              <span class="rt-node-ip">${escapeHtml(rtTraceEndDetail(data))}</span>
            </div>
          </li>`;
        return `<ol class="rt-chain" aria-label="${
            escapeHtml(rtTraceOutcomeText(data))}">${items}${tail}</ol>`;
    }

    /** Il dettaglio sotto l'esito: l'indirizzo che chiude il percorso. */
    function rtTraceEndDetail(data) {
        if (data.outcome === 'consegna') return data.dst || '';
        if (data.outcome === 'fuori inventario') return data.exit_hop || '';
        if (data.outcome === 'non interrogato') return data.device_ip || '';
        return '';
    }

    function rtStepsHtml(data) {
        return (data.hops || []).map((hop, i) => {
            const cand = hop.candidates || [];
            const tiedCount = (hop.tied || []).length;
            const rows = cand.map((r, j) => {
                const color = rtTypeColor(r.type);
                const win = tiedCount ? j < tiedCount : j === 0;
                return `<tr class="${win ? 'won' : 'lost'}">
                    <td class="rt-lead"><b class="rt-kind" style="background:${color}">${
                        escapeHtml((r.type || '?').slice(0, 1).toUpperCase())}</b>${escapeHtml(r.network || '')}</td>
                    <td>${r.gateway ? escapeHtml(tr('rtTraceVia', { hop: r.gateway }))
                                    : escapeHtml(tr('rtTraceOnIface', { iface: r.interface || '?' }))}</td>
                    <td class="rt-num">/${escapeHtml(String(r.prefixlen))}</td>
                    <td class="rt-num">${escapeHtml(String(r.ad))}</td>
                    <td class="rt-num">${escapeHtml(String(r.metric || 0))}</td>
                    <td class="rt-num"><span class="rt-outcome${win ? ' win' : ''}">${
                        escapeHtml(win ? tr('rtTraceWins') : tr('rtTraceDropped'))}</span></td>
                  </tr>`;
            }).join('');
            let decided = false;
            const rules = rtRules().map(rule => {
                const hit = hop.decided_by === rule.key;
                const cls = hit ? 'hit' : (decided ? 'moot' : '');
                if (hit) decided = true;
                return `<span class="rt-rule-step ${cls}">${escapeHtml(rule.label)}</span>`;
            }).join('');
            let say = tr('rtWhyOnly');
            if (cand.length >= 2) {
                if (hop.decided_by === 'prefisso') say = tr('rtWhyPrefix', { len: cand[0].prefixlen });
                else if (hop.decided_by === 'distanza') say = tr('rtWhyDistance');
                else if (hop.decided_by === 'ecmp') say = tr('rtWhyEcmp');
                else say = tr('rtWhyMetric');
            }
            const backup = hop.from_backup
                ? ` <span style="color:var(--warning);">${escapeHtml(tr('rtWhyBackup'))}</span>` : '';
            const table = cand.length
                ? `<table class="rt-cand">
                    <thead><tr>
                      <th data-no-sort="1">${escapeHtml(tr('rtColNetwork'))}</th>
                      <th data-no-sort="1">${escapeHtml(tr('rtColNextHop'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColPrefix'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColAd'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtColMetric'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColOutcome'))}</th>
                    </tr></thead><tbody>${rows}</tbody></table>
                    <div class="rt-rule">${rules}</div>`
                : `<span class="rt-step-empty">${
                      escapeHtml(tr('rtTraceNoRoute'))}</span>`;
            return `<div class="rt-step pending" data-step="${i}">
                <div class="rt-step-gutter"><span class="rt-step-n">${i + 1}</span></div>
                <div class="rt-step-body">
                  <div class="rt-step-head">
                    <span class="rt-step-dev">${escapeHtml(hop.device || '')}</span>
                    <span class="rt-step-ip">${escapeHtml(hop.device_ip || '')}</span>
                    ${hop.from_backup
                        ? `<span class="badge rt-badge-backup">${escapeHtml(tr('rtFromBackup'))}</span>`
                        : ''}
                  </div>
                  <p class="rt-step-say">${escapeHtml(say)}${backup}</p>
                  ${table}
                </div>
              </div>`;
        }).join('');
    }

    /** Rivelazione dei salti, uno alla volta: il tempo dell'animazione e' il
     *  tempo della spiegazione. Con prefers-reduced-motion si mostra tutto. */
    function rtTracePlay() {
        clearInterval(_traceTimer);
        const steps = [...document.querySelectorAll('#rtTraceSteps .rt-step')];
        const rail = document.getElementById('rtTraceRail');
        if (!steps.length || !rail) return;
        const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        const show = n => {
            steps.forEach((el, i) => {
                el.classList.toggle('pending', i >= n);
                el.classList.toggle('decided', i < n);
            });
            // Il salto i e il tratto che ne esce si accendono insieme: il
            // riquadro d'esito e' l'ultimo elemento della catena.
            rail.querySelectorAll('.rt-hop').forEach((hop, i) => {
                hop.classList.toggle('on', i < n);
            });
            // L'esito e' l'ultimo riquadro della catena e sta oltre l'ultimo
            // salto: si accende quando i salti sono finiti, non un giro dopo.
            rail.querySelector('.rt-hop-end')?.classList.toggle('on', n >= steps.length);
        };
        if (reduced) { show(steps.length); return; }
        show(0);
        let n = 0;
        _traceTimer = setInterval(() => {
            n += 1;
            show(n);
            if (n >= steps.length) clearInterval(_traceTimer);
        }, 700);
    }

    async function runRtProbe() {
        const src = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        const dst = /** @type {HTMLInputElement|null} */ (
            document.getElementById('rtTraceDst'));
        const out = document.getElementById('rtProbeOut');
        if (!src || !dst || !out) return;
        out.style.display = '';
        out.textContent = tr('rtProbeRunning');
        let data = null;
        try {
            const res = await apiFetch('/api/routes/trace/probe', {
                method: 'POST',
                body: JSON.stringify({ device_ip: src.value, dst: dst.value.trim() }),
            });
            if (!res) return;
            data = await res.json();
            if (!res.ok) {
                out.innerHTML = `<span class="rt-ink-bad">${
                    escapeHtml(data.detail || ('HTTP ' + res.status))}</span>`;
                return;
            }
        } catch (e) {
            out.innerHTML = `<span class="rt-ink-bad">${escapeHtml(String(e))}</span>`;
            return;
        }
        if (data.error) {
            out.innerHTML = `<span class="rt-ink-bad">${escapeHtml(data.error)}</span>`;
            return;
        }
        // Confronto fra atteso e visto: un next-hop che non risponde non e' un
        // guasto (puo' non rispondere a ICMP), e' il punto da cui guardare.
        const expected = ((_trace && _trace.hops) || [])
            .map(h => h.best && h.best.gateway).filter(Boolean);
        const seen = (data.hops || []).map(h => h.ip).filter(Boolean);
        const missing = expected.filter(ip => seen.indexOf(ip) === -1);
        const line = missing.length
            ? `<span class="rt-ink-warn">${escapeHtml(
                  tr('rtProbeMissing', { hops: missing.join(', ') }))}</span>`
            : `<span class="rt-ink-ok">${escapeHtml(tr('rtProbeMatch'))}</span>`;
        const path = (data.hops || []).map(h => h.ip || '*').join(' -> ') || '-';
        out.innerHTML = `<div>${escapeHtml(tr('rtProbeSeen', { hops: path }))}</div>
          <div style="margin-top:6px;">${line}</div>
          <pre>${escapeHtml(data.output || '')}</pre>`;
    }

    document.getElementById('btnRtTrace')?.addEventListener('click', loadRtTrace);
    document.getElementById('btnRtTracePlay')?.addEventListener('click', rtTracePlay);
    document.getElementById('btnRtProbe')?.addEventListener('click', runRtProbe);
    document.getElementById('rtDeviceFilter')?.addEventListener('picker-change', rtTraceSyncSources);
    document.getElementById('rtTraceDst')?.addEventListener('keydown', e => {
        if (/** @type {KeyboardEvent} */ (e).key === 'Enter') loadRtTrace();
    });

    let _rtSearchTimer = null;
    document.getElementById('rtSearch')?.addEventListener('input', () => {
        clearTimeout(_rtSearchTimer);
        _rtSearchTimer = setTimeout(loadRoutesTab, 350);
    });
    // La selezione non fa partire da sola la query: si sceglie e si preme
    // Aggiorna. Ogni apparato in piu' e' una sessione in piu' aperta.
    document.getElementById('rtTypeFilter')?.addEventListener('change', loadRoutesTab);
    document.getElementById('btnRtRefresh')?.addEventListener('click', loadRoutesTab);

    window.loadRoutesTab = routesTabShown;
})();
