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
                html.push(`<tr style="background:var(--surface-3);">
                    <td colspan="5" style="padding:6px 8px; font-weight:700; font-size:12px;">
                      ${escapeHtml(r.device)} &middot; ${rtTypeBadge(r.type)}
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
