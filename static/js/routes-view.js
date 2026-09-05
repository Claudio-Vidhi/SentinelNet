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
        const sel = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtDeviceFilter'));
        if (!sel) return [];
        return [...sel.selectedOptions].map(o => o.value);
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
        const sel = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtDeviceFilter'));
        if (!sel) return;
        let devices = [];
        try {
            const res = await apiFetch('/api/routes/devices');
            if (res && res.ok) devices = (await res.json()).devices || [];
        } catch (e) { devices = []; }
        const chosen = new Set(rtSelectedDevices());
        sel.innerHTML = devices
            .sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''))
            .map(d => `<option value="${escapeHtml(d.ip)}"${chosen.has(d.ip) ? ' selected' : ''}>${
                escapeHtml(d.hostname)} (${escapeHtml(d.ip)})</option>`).join('');
    }

    // Apertura del tab: si popola la lista e si aspetta. Interrogare da soli
    // tutta la flotta e' esattamente quello che questa vista non deve fare.
    async function routesTabShown() {
        await loadRtDeviceList();
        rtTraceSyncSources();
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
    };

    const RT_END = {
        'consegna': { label: 'rtTraceEndDelivery', color: 'var(--success)' },
        'fuori inventario': { label: 'rtTraceEndOutside', color: 'var(--text-muted)' },
        'nessuna rotta': { label: 'rtTraceEndDropped', color: 'var(--danger)' },
        'anello': { label: 'rtTraceEndLoop', color: 'var(--danger)' },
        'biforcazione': { label: 'rtTraceEndFork', color: 'var(--warning)' },
        'non interrogato': { label: 'rtTraceEndUnknown', color: 'var(--warning)' },
    };

    function rtTraceSyncSources() {
        // Si parte da uno degli apparati scelti: partire da uno non
        // selezionato sarebbe una richiesta a sorpresa, ed e' un 404 lato API.
        const sel = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        if (!sel) return;
        const current = sel.value;
        const chosen = [...document.querySelectorAll('#rtDeviceFilter option')]
            .map(o => /** @type {HTMLOptionElement} */ (o))
            .filter(o => o.selected)
            .map(o => ({ ip: o.value, label: o.textContent || '' }));
        sel.innerHTML = chosen.length
            ? chosen.map(d => `<option value="${escapeHtml(d.ip)}">${escapeHtml(d.label)}</option>`).join('')
            : `<option value="">${escapeHtml(tr('rtTraceNoDevices'))}</option>`;
        if (chosen.some(d => d.ip === current)) sel.value = current;
    }

    function rtTraceVerdict(kind, text) {
        const box = document.getElementById('rtTraceVerdict');
        if (!box) return;
        box.className = 'rt-verdict on ' + kind;
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
            default: return data.outcome || '';
        }
    }

    async function loadRtTrace() {
        const src = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        const dst = /** @type {HTMLInputElement|null} */ (
            document.getElementById('rtTraceDst'));
        if (!src || !dst) return;
        const devices = rtSelectedDevices().join(',');
        if (!devices || !src.value) { rtTraceVerdict('muted', tr('rtPickDevices')); return; }
        if (!dst.value.trim()) { rtTraceVerdict('muted', tr('rtTraceNeedDst')); return; }

        rtTraceVerdict('muted', tr('rtTraceRunning'));
        const url = `/api/routes/trace?device=${encodeURIComponent(devices)}`
            + `&src=${encodeURIComponent(src.value)}&dst=${encodeURIComponent(dst.value.trim())}`;
        try {
            const res = await apiFetch(url);
            if (!res) return;
            const data = await res.json();
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
            steps.innerHTML = '';
            if (play) play.style.display = 'none';
            if (probe) probe.style.display = 'none';
            return;
        }
        rtTraceVerdict(RT_VERDICTS[_trace.outcome] || 'muted', rtTraceOutcomeText(_trace));
        rail.style.display = '';
        rail.innerHTML = rtRailSvg(_trace);
        steps.innerHTML = rtStepsHtml(_trace);
        if (play) play.style.display = '';
        // Il traceroute manda pacchetti: e' un'azione, non una lettura, e a un
        // viewer non viene nemmeno offerta.
        if (probe) probe.style.display = (currentRole === 'viewer') ? 'none' : '';
        const out = document.getElementById('rtProbeOut');
        if (out) { out.style.display = 'none'; out.innerHTML = ''; }
    }

    function rtRailSvg(data) {
        const hops = data.hops || [];
        const BW = 196, BH = 62, GAP = 268, X0 = 8, Y = 30, H = 118;
        const W = X0 + hops.length * GAP + 160;
        const parts = [];
        hops.forEach((hop, i) => {
            const x = X0 + i * GAP;
            const y = Y + BH / 2;
            const win = hop.best;
            const color = win ? rtTypeColor(win.type) : 'var(--text-muted)';
            if (win) {
                const to = x + GAP;
                const mid = (x + BW + to) / 2;
                parts.push(`<line x1="${x + BW}" y1="${y}" x2="${to - 7}" y2="${y}"
                    stroke="var(--border)" stroke-width="1.5"></line>`);
                parts.push(`<path d="M ${to - 7} ${y - 4} L ${to} ${y} L ${to - 7} ${y + 4} Z"
                    fill="var(--border-strong)"></path>`);
                parts.push(`<line class="rt-lit" data-seg="${i}" x1="${x + BW}" y1="${y}"
                    x2="${x + BW}" y2="${y}" stroke="${color}" stroke-width="1.5"></line>`);
                parts.push(`<g class="rt-seg-label" data-seg="${i}" opacity="0">
                    <text x="${mid}" y="${y - 14}" fill="var(--text)" font-size="11"
                          text-anchor="middle">${escapeHtml(win.network || '')}</text>
                    <text x="${mid}" y="${y + 20}" fill="var(--text-muted)" font-size="10"
                          text-anchor="middle">${escapeHtml(win.gateway
                              ? tr('rtTraceVia', { hop: win.gateway })
                              : tr('rtTraceOnIface', { iface: win.interface || '?' }))}</text>
                  </g>`);
            }
            parts.push(`<g class="rt-rail-node" data-hop="${i}">
                <rect data-box="${i}" x="${x}" y="${Y}" width="${BW}" height="${BH}"
                      fill="var(--surface-3)" stroke="var(--border)" stroke-width="1"></rect>
                <rect x="${x}" y="${Y}" width="2" height="${BH}" fill="${color}"></rect>
                <text x="${x + 14}" y="${Y + 20}" fill="var(--text-muted)" font-size="9"
                      letter-spacing="1.3">${escapeHtml(
                          (i === 0 ? tr('rtTraceStart') : tr('rtTraceHopN', { n: i })).toUpperCase())}</text>
                <text x="${x + 14}" y="${Y + 40}" fill="var(--text)" font-size="13"
                      font-weight="700">${escapeHtml(hop.device || '')}</text>
                <text x="${x + BW - 14}" y="${Y + 40}" fill="var(--text-muted)" font-size="10.5"
                      text-anchor="end">${escapeHtml(hop.device_ip || '')}</text>
                ${hop.from_backup
                    ? `<text x="${x + 14}" y="${Y + 55}" fill="var(--warning)" font-size="9.5">${
                          escapeHtml(tr('rtFromBackup'))}</text>` : ''}
              </g>`);
        });
        const end = RT_END[data.outcome] || RT_END['non interrogato'];
        const ex = X0 + hops.length * GAP;
        parts.push(`<g>
            <rect x="${ex}" y="${Y}" width="150" height="${BH}" fill="none"
                  stroke="${end.color}" stroke-width="1" stroke-dasharray="3 3"></rect>
            <text x="${ex + 14}" y="${Y + 20}" fill="var(--text-muted)" font-size="9"
                  letter-spacing="1.3">${escapeHtml(tr('rtTraceEnd').toUpperCase())}</text>
            <text x="${ex + 14}" y="${Y + 41}" fill="${end.color}" font-size="12"
                  font-weight="700">${escapeHtml(tr(end.label))}</text>
          </g>`);
        return `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${
            escapeHtml(rtTraceOutcomeText(data))}">${parts.join('')}</svg>`;
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
                    <td class="rt-num">${escapeHtml(win ? tr('rtTraceWins') : tr('rtTraceDropped'))}</td>
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
                      <th>${escapeHtml(tr('rtColNetwork'))}</th>
                      <th>${escapeHtml(tr('rtColNextHop'))}</th>
                      <th class="rt-num">${escapeHtml(tr('rtTraceColPrefix'))}</th>
                      <th class="rt-num">${escapeHtml(tr('rtTraceColAd'))}</th>
                      <th class="rt-num">${escapeHtml(tr('rtColMetric'))}</th>
                      <th class="rt-num">${escapeHtml(tr('rtTraceColOutcome'))}</th>
                    </tr></thead><tbody>${rows}</tbody></table>
                    <div class="rt-rule">${rules}</div>`
                : `<span style="font-size:12.5px; color:var(--text-muted);">${
                      escapeHtml(tr('rtTraceNoRoute'))}</span>`;
            return `<div class="rt-step pending" data-step="${i}">
                <div class="rt-step-gutter"><span class="rt-step-n">${i + 1}</span></div>
                <div class="rt-step-body">
                  <div class="rt-step-head">
                    <span class="rt-step-dev">${escapeHtml(hop.device || '')}</span>
                    <span class="rt-step-ip">${escapeHtml(hop.device_ip || '')}</span>
                    <span class="rt-step-say">${escapeHtml(say)}${backup}</span>
                  </div>
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
            rail.querySelectorAll('.rt-lit').forEach((line, i) => {
                const box = rail.querySelector(`[data-box="${i + 1}"]`);
                const done = i < n - 1 && box;
                const x = done ? Number(box.getAttribute('x')) - 7
                               : Number(line.getAttribute('x1'));
                line.setAttribute('x2', String(x));
            });
            rail.querySelectorAll('.rt-seg-label').forEach((g, i) => {
                g.setAttribute('opacity', i < n - 1 ? '1' : '0');
            });
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
                out.innerHTML = `<span style="color:var(--danger);">${
                    escapeHtml(data.detail || ('HTTP ' + res.status))}</span>`;
                return;
            }
        } catch (e) {
            out.innerHTML = `<span style="color:var(--danger);">${escapeHtml(String(e))}</span>`;
            return;
        }
        if (data.error) {
            out.innerHTML = `<span style="color:var(--danger);">${escapeHtml(data.error)}</span>`;
            return;
        }
        // Confronto fra atteso e visto: un next-hop che non risponde non e' un
        // guasto (puo' non rispondere a ICMP), e' il punto da cui guardare.
        const expected = ((_trace && _trace.hops) || [])
            .map(h => h.best && h.best.gateway).filter(Boolean);
        const seen = (data.hops || []).map(h => h.ip).filter(Boolean);
        const missing = expected.filter(ip => seen.indexOf(ip) === -1);
        const line = missing.length
            ? `<span style="color:var(--warning);">${escapeHtml(
                  tr('rtProbeMissing', { hops: missing.join(', ') }))}</span>`
            : `<span style="color:var(--success);">${escapeHtml(tr('rtProbeMatch'))}</span>`;
        const path = (data.hops || []).map(h => h.ip || '*').join(' -> ') || '-';
        out.innerHTML = `<div>${escapeHtml(tr('rtProbeSeen', { hops: path }))}</div>
          <div style="margin-top:6px;">${line}</div>
          <pre>${escapeHtml(data.output || '')}</pre>`;
    }

    document.getElementById('btnRtTrace')?.addEventListener('click', loadRtTrace);
    document.getElementById('btnRtTracePlay')?.addEventListener('click', rtTracePlay);
    document.getElementById('btnRtProbe')?.addEventListener('click', runRtProbe);
    document.getElementById('rtDeviceFilter')?.addEventListener('change', rtTraceSyncSources);
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
