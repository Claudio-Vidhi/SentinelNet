// --- OPERATIONS HOME (landing) ---
// Estratto dal blocco inline di templates/dashboard.html (CSP senza
// 'unsafe-inline'). Dipende dai globali di i18n.js/core.js/devices.js,
// che nel markup caricano prima di questo file.

// Mirror renderDeviceTable's canonical status mapping: status is on
// globalVersions[device.IP].status, NOT on the device object itself.
function homeStatusInfo(status) {
    if (status === 'online')      return { cls: 'ok',   led: 'led-success', key: 'homeStOnline' };
    if (status === 'auth_failed') return { cls: 'warn', led: 'led-warning', key: 'homeStAuth' };
    return { cls: 'bad', led: 'led-danger', key: 'homeStOffline' };
}

let _pingRefreshTimer = null;

async function loadHome() {
    // Reset any previous auto-refresh timer; it will be re-armed below if
    // the ping monitor is still active.
    if (_pingRefreshTimer) { clearInterval(_pingRefreshTimer); _pingRefreshTimer = null; }
    // Reuse the globals cached at login; fetch only if empty (same shape as appInit).
    if (!globalDevices || globalDevices.length === 0) {
        const res = await apiFetch('/api/local-devices');
        if (res && res.ok) {
            const data = await res.json();
            globalDevices  = data.devices || [];
            if (data.groups) globalGroups = data.groups;
            globalVersions = data.detected_versions || {};
        }
    }
    // When the continuous ping monitor is active, its results are the
    // authoritative source for up/down state — fresher than the last scan.
    try {
        const pmRes = await apiFetch('/api/ping-monitor/status');
        if (pmRes && pmRes.ok) {
            const pm = await pmRes.json();
            if (pm.enabled && pm.devices && pm.devices.length) {
                pm.devices.forEach(d => {
                    if (!globalVersions[d.ip]) globalVersions[d.ip] = {};
                    globalVersions[d.ip].status = d.up ? 'online' : 'offline';
                });
                // Keep the home tab live: re-poll at the monitor cadence.
                // loadHome() is cheap here — globalDevices is cached, so
                // only the ping status and the render are repeated.
                const ms = Math.max(5, pm.interval_seconds || 60) * 1000;
                _pingRefreshTimer = setInterval(() => loadHome(), ms);
            }
        }
    } catch (_) { /* monitor endpoint optional */ }
    const devs = globalDevices || [];

    let online = 0;
    const attention = [];
    devs.forEach(d => {
        const scan = globalVersions[d.IP] || {};
        if (scan.status === 'online') online++;
        else attention.push(d); // auth_failed / offline / unknown / missing
    });

    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setText('homeKpiTotal', devs.length);
    setText('homeKpiOnline', online);
    setText('homeKpiAttention', attention.length);

    // Righe di contesto sotto ogni bay: un numero nudo non dice se sia molto.
    const L = i18n[currentLang];
    const pct = devs.length ? Math.round((online / devs.length) * 100) : 0;
    setText('homeStatOnline', `${pct}% ${L.homeOfFleet}`);
    setText('homeStatAttention', `${L.homeOutOf} ${devs.length}`);

    // Cartiglio del disegno: revisione = istante dell'ultima lettura.
    setText('homeOnelineRev', new Date().toLocaleString(currentLang === 'en' ? 'en-GB' : 'it-IT'));

    renderFleetOneline(devs);

    const body = document.getElementById('homeAttentionBody');
    if (body) {
        if (attention.length === 0) {
            const okMsg = i18n[currentLang].homeNoAttention;
            body.innerHTML = `<tr><td colspan="4" style="color:var(--text-muted); text-align:center; padding:16px;">${okMsg}</td></tr>`;
        } else {
            body.innerHTML = attention.slice(0, 8).map(d => {
                const scan  = globalVersions[d.IP] || {};
                const info  = homeStatusInfo(scan.status);
                const label = i18n[currentLang][info.key] || scan.status || 'offline';
                const host  = d.Hostname ? escapeHtml(d.Hostname) : '<span style="color:var(--text-muted)">&mdash;</span>';
                return `<tr>
                    <td>${host}</td>
                    <td><code>${escapeHtml(d.IP || '')}</code></td>
                    <td><span class="badge" style="cursor:pointer;" data-action="open-inventory-tenant" data-tenant="${escapeHtml(d.Group || '')}" title="${escapeHtml(d.Group || '')}">${escapeHtml(d.Group || '')}</span></td>
                    <td><span class="status ${info.cls}"><span class="led ${info.led}"></span>${escapeHtml(label)}</span></td>
                </tr>`;
            }).join('');
        }
    }

    if (currentRole === 'admin') loadHomeAnomalies();
    else renderEventStripDenied();
}

// Una bay per tenant: e' l'estate a essere indicizzata. Lo stato della bay e'
// il peggiore dei suoi apparati, perche' su un quadro una sbarra in allarme
// si vede prima del dettaglio che l'ha causata.
function renderFleetOneline(devs) {
    const host = document.getElementById('homeOnelineBays');
    if (!host) return;
    const L = i18n[currentLang];

    const bays = new Map();
    devs.forEach(d => {
        const tenant = (d.Group || '').trim() || L.homeBayUnassigned;
        if (!bays.has(tenant)) bays.set(tenant, { total: 0, down: 0, warn: 0, idle: 0 });
        const b = bays.get(tenant);
        b.total++;
        const st = (globalVersions[d.IP] || {}).status;
        if (!st) b.idle++;                                   // mai interrogato
        else if (st === 'offline' || st === 'unknown') b.down++;
        else if (st !== 'online') b.warn++;
    });

    if (bays.size === 0) {
        host.innerHTML = `<p class="oneline-empty">${escapeHtml(L.homeOnelineEmpty)}</p>`;
        return;
    }

    // Molte bay non stanno sulla sbarra: si mostrano le piu' grandi e si
    // raccoglie la coda in una bay di riepilogo, come un quadro di gruppo.
    const sorted = [...bays.entries()].sort((a, b) => b[1].total - a[1].total);
    const shown = sorted.slice(0, 6);
    const rest  = sorted.slice(6);

    // Peggiore stato della bay:
    // - 'idle': nessun apparato della bay è mai stato scansionato
    // - 'down': TUTTI gli apparati della bay sono giù (interruttore aperto / irraggiungibile)
    // - 'warn': solo ALCUNI apparati sono giù o in attenzione (degradato / attenzione)
    // - 'up': tutti gli apparati operativi (eccitato)
    const state = b => (!b || !b.total || b.idle === b.total) ? 'idle'
                     : (b.down === b.total) ? 'down'
                     : (b.down > 0 || b.warn > 0) ? 'warn'
                     : 'up';
    let html = shown.map(([name, b]) => `
        <button type="button" class="oneline-bay" data-state="${state(b)}"
                data-action="open-inventory-tenant" data-tenant="${escapeHtml(name)}"
                title="${escapeHtml(name)}">
          <span class="oneline-drop"></span><span class="oneline-sw"></span>
          <span class="oneline-node">
            <span class="oneline-count">${b.total}</span>
            <span class="oneline-name">${escapeHtml(name)}</span>
            <span class="oneline-sub">${b.down ? escapeHtml(`${b.down} ${L.homeBayDown}`)
                 : (b.idle === b.total) ? escapeHtml(L.homeBayUnscanned)
                 : escapeHtml(L.homeBayAllUp)}</span>
          </span>
        </button>`).join('');

    if (rest.length) {
        const agg = rest.reduce((a, [, b]) => ({
            total: a.total + b.total, down: a.down + b.down,
            warn: a.warn + b.warn, idle: a.idle + b.idle
        }), { total: 0, down: 0, warn: 0, idle: 0 });
        html += `
        <button type="button" class="oneline-bay" data-state="${state(agg)}"
                data-action="switch-tab" data-tab="tab-devices">
          <span class="oneline-drop"></span><span class="oneline-sw"></span>
          <span class="oneline-node">
            <span class="oneline-count">${agg.total}</span>
            <span class="oneline-name">${escapeHtml(`+${rest.length} ${L.homeBayOther}`)}</span>
            <span class="oneline-sub">${escapeHtml(L.homeBayOtherSub)}</span>
          </span>
        </button>`;
    }
    host.innerHTML = html;
}

// Apre l'inventario gia' filtrato sul tenant della bay cliccata.
function openInventoryForTenant(tenant) {
    const sel = document.getElementById('filterGroupSelect');
    if (sel) {
        const hasOption = Array.from(sel.options).some(o => o.value === tenant);
        sel.value = hasOption ? tenant : 'all';
    }
    renderDeviceTable();
    switchTab('tab-devices');
}


async function loadHomeAnomalies() {
    const box = document.getElementById('homeAnomSummary');
    if (!box) return;
    const L = i18n[currentLang];
    // Una sola chiamata: la striscia eventi vuole le righe recenti, il
    // riepilogo vuole quante ne restano da lavorare.
    const res = await apiFetch('/api/observability/anomalies?status=all&limit=100');
    if (!res || !res.ok) return;
    const rows = (await res.json()).anomalies || [];
    renderEventStrip(rows.slice(0, 5));
    if (rows.length === 0) {
        box.innerHTML = `<p style="color:var(--text-muted); margin:0; padding:8px 0;">${escapeHtml(L.homeNoAnomalies)}</p>`;
        return;
    }
    const openCount = rows.filter(a => a.status === 'new').length;
    box.innerHTML = `
        <div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap; padding:4px 0;">
            <span class="status ${openCount ? 'warn' : 'ok'}" style="font-size:15px;">${openCount}</span>
            <span style="font-size:13px; color:var(--text-muted);">${escapeHtml(L.homeAnomOpenCount)}</span>
            <button class="btn btn-small" style="width:auto; margin:0;" data-action="open-traffico-anomalies">
                <i class="fa-solid fa-arrow-right"></i> ${escapeHtml(L.homeAnomOpenLink)}
            </button>
        </div>`;
}

// Una sezione che non si puo' mostrare spiega perche', invece di sparire.
function renderEventStripDenied() {
    const strip = document.getElementById('homeEventStrip');
    if (strip) strip.innerHTML =
        `<p class="eventstrip-empty">${escapeHtml(i18n[currentLang].homeEventStripDenied)}</p>`;
}

// Striscia eventi: una riga per evento, la piu' recente in alto, come la
// stampante di sala controllo da cui prende la forma.
function renderEventStrip(rows) {
    const strip = document.getElementById('homeEventStrip');
    if (!strip) return;
    const L = i18n[currentLang];
    if (!rows || rows.length === 0) {
        strip.innerHTML = `<p class="eventstrip-empty">${escapeHtml(L.homeNoAnomalies)}</p>`;
        return;
    }
    strip.innerHTML = rows.map(a => {
        const sev = (a.severity || '').toString().toLowerCase();
        const cls = (sev === 'high' || sev === 'critical') ? 'bad' : (sev === 'medium' ? 'warn' : 'ok');
        const when = a.created_ts
            ? new Date(a.created_ts * 1000).toLocaleTimeString(currentLang === 'en' ? 'en-GB' : 'it-IT')
            : '--:--:--';
        const src = escapeHtml((a.src_ip || '').toString());
        const dst = escapeHtml((a.dst_ip || '').toString());
        const kind = escapeHtml((a.kind || '').toString());
        return `<div class="eventstrip-row">
            <span class="eventstrip-time">${escapeHtml(when)}</span>
            <span class="eventstrip-text">${kind}${src ? ` &middot; ${src} &rarr; ${dst}` : ''}</span>
            <span class="status ${cls}"><span class="led led-${cls === 'bad' ? 'danger' : cls === 'warn' ? 'warning' : 'success'}"></span>${escapeHtml((a.severity || '—').toString())}</span>
        </div>`;
    }).join('');
}

document.getElementById('btnHomeRunTriage')?.addEventListener('click', () => {
    if (typeof startGroupTriage === 'function') {
        startGroupTriage('all');
    }
});

document.getElementById('homeOnelineBays')?.addEventListener('click', (e) => {
    const bay = e.target.closest('[data-action]');
    if (!bay) return;
    const act = bay.dataset.action;
    if (act === 'open-inventory-tenant' && bay.dataset.tenant) {
        openInventoryForTenant(bay.dataset.tenant);
    } else if (act === 'switch-tab' && bay.dataset.tab) {
        switchTab(bay.dataset.tab);
    }
});

document.getElementById('homeAttentionBody')?.addEventListener('click', (e) => {
    const el = e.target.closest('[data-action="open-inventory-tenant"]');
    if (el && el.dataset.tenant) {
        openInventoryForTenant(el.dataset.tenant);
    }
});

document.getElementById('homeAnomSummary')?.addEventListener('click', (e) => {
    if (e.target.closest('[data-action="open-traffico-anomalies"]')) {
        openTrafficoAnomalies();
    }
});
