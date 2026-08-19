// --- OPERATIONS HOME (landing) ---
// Estratto dal blocco inline di templates/dashboard.html (CSP senza
// 'unsafe-inline'). Dipende dai globali di i18n.js/core.js/devices.js,
// che nel markup caricano prima di questo file.

// Mirror renderDeviceTable's canonical status mapping: status is on
// globalVersions[device.IP].status, NOT on the device object itself.
// Devices reachable only through an SSH bastion. They are excluded from the
// online/attention counters on purpose (no ICMP crosses the tunnel, so any
// up/down there would be invented), which used to make them vanish from Home
// altogether. The status shown is the last SSH triage outcome, which is a real
// measurement -- it went through the bastion and talked to the device.
function renderBastionPanel(devices) {
    const panel = document.getElementById('homeBastionPanel');
    const body = document.getElementById('homeBastionBody');
    if (!panel || !body) return;
    if (!devices.length) { panel.style.display = 'none'; return; }
    panel.style.display = '';
    const L = i18n[currentLang];
    const count = document.getElementById('homeBastionCount');
    if (count) count.textContent = `${devices.length} ${L.homeBastionDevices}`;
    body.innerHTML = devices.slice(0, 8).map(d => {
        // scan.status here comes from the triage (update_version_inventory),
        // never from a ping: the ping monitor reports 'unknown' for these.
        const scan = globalVersions[d.IP] || {};
        const triaged = scan.status && scan.status !== 'unknown';
        const info = triaged ? homeStatusInfo(scan.status) : homeStatusInfo('unknown');
        const label = triaged
            ? (i18n[currentLang][info.key] || scan.status)
            : L.homeBastionNeverTriaged;
        const host = d.Hostname ? escapeHtml(d.Hostname) : '<span style="color:var(--text-muted)">&mdash;</span>';
        return `<tr>
            <td>${host}</td>
            <td><code>${escapeHtml(d.IP || '')}</code></td>
            <td><span class="badge">${escapeHtml(d.Site || 'central')}</span></td>
            <td><span class="status ${info.cls}"><span class="led ${info.led}"></span>${escapeHtml(label)}</span></td>
        </tr>`;
    }).join('');
}

function homeStatusInfo(status) {
    if (status === 'online')      return { cls: 'ok',   led: 'led-success', key: 'homeStOnline' };
    if (status === 'auth_failed') return { cls: 'warn', led: 'led-warning', key: 'homeStAuth' };
    // A jump-site device: the SSH bastion tunnel carries no ICMP, so this is
    // not measurable, never a confirmed down. Reusing led-discovered (the
    // existing "not confirmed" grey/dashed lamp) rather than the red fault lamp.
    if (status === 'unknown')     return { cls: 'idle', led: 'led-discovered', key: 'homeStUnknown' };
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
                    // d.status is the tri-state the ping monitor already computed
                    // server-side: for a jump-site device (bastion tunnel, no ICMP)
                    // d.up is null and d.status is 'unknown' — never collapse that
                    // to 'offline', it would report a false down.
                    // 'unknown' from the monitor means "I could not measure
                    // this" (jump site: no ICMP through the bastion), not "the
                    // state is unknown". Writing it over a status the SSH
                    // triage established would erase a real result with a
                    // non-result, which is what made a triaged jump device go
                    // back to an em dash on the next render.
                    if (d.status === 'unknown') {
                        if (!globalVersions[d.ip].status) globalVersions[d.ip].status = 'unknown';
                    } else {
                        globalVersions[d.ip].status = d.up ? 'online' : 'offline';
                    }
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
    let notMeasurable = 0;
    const attention = [];
    // Out of the counters, but not out of sight: these get their own panel.
    const viaBastion = [];
    devs.forEach(d => {
        const scan = globalVersions[d.IP] || {};
        // A jump-site device has no measurable reachability: the bastion tunnel
        // carries no ICMP. It is neither online nor something to act on, so it
        // stays out of both counters and out of the percentage's denominator.
        // Without this a customer whose whole estate sits behind one bastion
        // read "Online: 0", "0% of the fleet", "Needs attention: 40 of 40",
        // permanently — while the bays right below correctly said "not
        // measurable". icmp_reachable comes from /api/local-devices, scan.status
        // from the ping monitor; either one is enough to know.
        if (d.icmp_reachable === false || scan.status === 'unknown') {
            notMeasurable++;
            viaBastion.push(d);
            return;
        }
        if (scan.status === 'online') online++;
        else attention.push(d); // auth_failed / offline / missing
    });

    const setText = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    setText('homeKpiTotal', devs.length);
    setText('homeKpiOnline', online);
    setText('homeKpiAttention', attention.length);

    // Righe di contesto sotto ogni bay: un numero nudo non dice se sia molto.
    const L = i18n[currentLang];
    // The percentage is honest about what it can see: the denominator is the
    // measurable part of the fleet, and when nothing is measurable there is no
    // percentage to give, only the state itself.
    const measurable = devs.length - notMeasurable;
    setText('homeStatOnline', measurable
        ? `${Math.round((online / measurable) * 100)}% ${L.homeOfFleet}`
        : L.homeStUnknown);
    setText('homeStatAttention', `${L.homeOutOf} ${measurable}`);

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

    renderBastionPanel(viaBastion);

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
        if (!bays.has(tenant)) bays.set(tenant, { total: 0, down: 0, warn: 0, idle: 0, unknown: 0 });
        const b = bays.get(tenant);
        b.total++;
        const st = (globalVersions[d.IP] || {}).status;
        if (!st) b.idle++;                                   // mai interrogato
        // 'unknown': jump-site device, no ICMP through the bastion — not
        // measurable, NOT a confirmed down. Its own bucket, not merged into
        // 'down' (that painted a bastion-only tenant's bay red as an outage).
        else if (st === 'unknown') b.unknown++;
        else if (st === 'offline') b.down++;
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
    // - 'unknown': TUTTI gli apparati non-idle della bay sono su un sito jump
    //   (nessun ICMP attraverso il bastione) — non misurabile, MAI un'interruzione:
    //   una sede raggiunta solo via bastione non deve sembrare un'interruzione.
    // - 'warn': un mix di giù/attenzione/non misurabile (degradato / attenzione)
    // - 'up': tutti gli apparati operativi (eccitato)
    const state = b => (!b || !b.total || b.idle === b.total) ? 'idle'
                     : (b.down === b.total) ? 'down'
                     : (b.unknown === b.total) ? 'unknown'
                     : (b.down > 0 || b.warn > 0 || b.unknown > 0) ? 'warn'
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
                 : b.unknown ? escapeHtml(`${b.unknown} ${L.homeBayUnknown}`)
                 : (b.idle === b.total) ? escapeHtml(L.homeBayUnscanned)
                 : escapeHtml(L.homeBayAllUp)}</span>
          </span>
        </button>`).join('');

    if (rest.length) {
        const agg = rest.reduce((a, [, b]) => ({
            total: a.total + b.total, down: a.down + b.down,
            warn: a.warn + b.warn, idle: a.idle + b.idle,
            unknown: a.unknown + b.unknown
        }), { total: 0, down: 0, warn: 0, idle: 0, unknown: 0 });
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

document.getElementById('homeAnomSummary')?.addEventListener('click', async (e) => {
    if (e.target.closest('[data-action="open-traffico-anomalies"]')) {
        // observability.js owns openTrafficoAnomalies and is lazy-loaded with
        // the Flows tab. Calling it bare from Home was a ReferenceError until
        // the user had opened Flows once, i.e. a silently dead button;
        // switching tab first is what loads the module.
        const nav = document.querySelector('[data-tabs="tab-flows"]');
        await switchTab('tab-flows', nav || undefined);
        window.openTrafficoAnomalies?.();
    }
});
