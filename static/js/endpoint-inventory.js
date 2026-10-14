// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// Inventario endpoint: elenco dei client scoperti, filtrabile ed esportabile.
// Ogni valore che arriva dagli apparati passa da escapeHtml(x).
//
// La vista e' DERIVATA: nessuna annotazione salvata, nessuno stato da tenere
// allineato a una rete che cambia da sola. Quello che si vede e' quello che
// le scansioni hanno raccolto, con l'eta' del dato sempre a schermo.

let _epRows = [];          // righe a schermo: sono queste che l'export porta via
let _epTruncated = false;
let _epQuery = '';         // term from the tab's search box, '' = none

function loadEndpointsTab() {
    _epFillFilters();
    endpointsApplyFilters();
}

// Switch and Probe options come from the tenant's inventory, not from the
// rows on screen: options built from the results vanish once they filter.
function _epFillFilters() {
    const tenant = locTenant();
    let devs = globalDevices || [];
    if (tenant && tenant !== 'all') devs = devs.filter(d => d.Group === tenant);
    const sw = /** @type {HTMLSelectElement|null} */ (document.getElementById('epFilterSwitch'));
    if (sw) {
        const cur = sw.value;
        const label = d => d.Hostname || d.IP;
        sw.innerHTML = `<option value="">${escapeHtml(tr('epAllSwitches'))}</option>` + devs.slice()
            .sort((a, b) => label(a).localeCompare(label(b)))
            .map(d => `<option value="${escapeHtml(d.IP)}">${escapeHtml(label(d))}</option>`).join('');
        sw.value = devs.some(d => d.IP === cur) ? cur : '';
    }
    const pr = /** @type {HTMLSelectElement|null} */ (document.getElementById('epFilterProbe'));
    if (pr) {
        const cur = pr.value;
        const probes = [...new Set(devs.map(d => d.Probe).filter(Boolean))].sort();
        pr.innerHTML = `<option value="">${escapeHtml(tr('epAllProbes'))}</option>` +
            probes.map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('');
        pr.value = probes.includes(cur) ? cur : '';
    }
}

// UNICO punto d'ingresso dei filtri: ricarica i dati e poi ridisegna nella
// modalita' CORRENTE. I filtri chiamavano endpointsSearch() direttamente, e
// questo produceva due difetti dallo stesso errore: la select del tenant non
// era agganciata a niente (cambiarla non ricaricava nulla, restavano a schermo
// i dispositivi del tenant precedente), e cercare mentre si era in modalita'
// porte ridipingeva elenco e KPI sotto la barra delle porte, lasciando due
// viste diverse sovrapposte.
async function endpointsApplyFilters() {
    await endpointsSearch();
}

function endpointsParams(q) {
    const val = id => ((/** @type {HTMLInputElement|null} */ (document.getElementById(id)) || {}).value || '').trim();
    const params = new URLSearchParams({ stale_days: String(parseInt(val('epFilterStale'), 10) || 7) });
    if (q) params.set('q', q);
    const tenant = locTenant();
    if (tenant && tenant !== 'all') params.set('tenant', tenant);
    if (val('epFilterSwitch')) params.set('switch', val('epFilterSwitch'));
    if (val('epFilterVlan')) params.set('vlan', val('epFilterVlan'));
    if (val('epFilterProbe')) params.set('probe', val('epFilterProbe'));
    for (const [id, key] of [['epFilterFrom', 'frm'], ['epFilterTo', 'to']]) {
        const v = val(id);
        if (!v) continue;
        try { params.set(key, new Date(v).toISOString()); } catch (e) { params.set(key, v); }
    }
    return params;
}

async function endpointsSearch() {
    const host = document.getElementById('epResults');
    if (!host) return;
    host.innerHTML = `<div class="panel" style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
        <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>${escapeHtml(tr('epiLoading'))}</div>`;

    const res = await apiFetch('/api/endpoints/list?' + endpointsParams(_epQuery).toString());
    if (!res || !res.ok) {
        host.innerHTML = `<div class="panel" style="padding:22px; text-align:center; color:var(--danger); font-size:13px;">${escapeHtml(tr('epiCouldNotLoadThe'))}</div>`;
        return;
    }
    endpointsRender(await res.json());
}

function endpointsRender(d) {
    const L = i18n[currentLang];
    _epRows = d.results || [];
    _epTruncated = !!d.truncated;

    const kpis = document.getElementById('epKpis');
    if (kpis) {
        const c = d.counts || {};
        const item = (label, value) => `<span>${escapeHtml(label)} <b>${escapeHtml(String(value ?? 0))}</b></span>`;
        kpis.innerHTML = item(L.epKpiEndpoints, c.endpoints) + item(L.epKpiSwitches, c.switches) +
            item(L.epKpiVlans, c.vlans) + item(L.epKpiStale, c.stale) + item(L.epKpiNew, c.new) + item(L.epKpiNoIp, c.no_ip);
    }
    const chip = document.getElementById('epQueryChip');
    if (chip) chip.innerHTML = _epQuery
        ? `<span class="ep-chip">“${escapeHtml(_epQuery)}”<button type="button" data-action="ep-clear-query" aria-label="${escapeHtml(tr('ariaEpQueryClear'))}">×</button></span>`
        : '';

    const host = document.getElementById('epResults');
    if (!host) return;

    const retentionBanner = d.outside_retention
        ? `<div style="padding:10px 12px; margin-bottom:10px; border-radius:0; background:color-mix(in srgb, var(--danger) 12%, transparent); border:1px solid color-mix(in srgb, var(--danger) 35%, transparent); color:var(--danger); font-size:12px;">
            <i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(
                tr('epiTheRequestedStartDate', {retention_days: d.retention_days}))}</div>`
        : '';

    if (!_epRows.length) {
        host.innerHTML = retentionBanner + `<div class="panel" style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;">
            <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.epEmpty)}</div>`;
        return;
    }

    const banner = (_epTruncated
        ? `<div style="padding:10px 12px; margin-bottom:10px; border-radius:0; background:color-mix(in srgb, var(--warning) 12%, transparent); border:1px solid color-mix(in srgb, var(--warning) 35%, transparent); color:var(--warning); font-size:12px;">
            <i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(
                L.epTruncated.replace('{shown}', String(_epRows.length)).replace('{total}', String(d.total)))}</div>`
        : '') + retentionBanner;

    const body = _epRows.map(r => `<tr class="ep-row" data-action="ep-open" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}" tabindex="0">
        <td class="ep-mono">${escapeHtml(r.mac)}<span class="ep-sub">${escapeHtml(r.oui_vendor || '')}</span></td>
        <td class="ep-mono">${escapeHtml((r.ips || []).join(', ') || '—')}</td>
        <td>${escapeHtml(r.switch_name || r.switch_ip || '—')}<span class="ep-sub ep-mono">${escapeHtml(r.switch_name ? r.switch_ip || '' : '')}</span></td>
        <td class="ep-mono">${escapeHtml(r.interface || '—')}</td>
        <td class="ep-mono">${escapeHtml(r.vlan || '—')}</td>
        <td>${escapeHtml(_epTime(r.last_seen))}</td>
        <td>${(r.flags || []).map(_epFlag).join(' ')}</td>
    </tr>`).join('');

    host.innerHTML = `${banner}
        <div class="table-wrap ep-table"><table>
          <thead><tr>
            <th>${escapeHtml(L.epThMac)}</th><th>IP</th><th>${escapeHtml(tr('epThSwitch'))}</th>
            <th>${escapeHtml(tr('epThPort'))}</th><th>${escapeHtml(L.epThVlan)}</th>
            <th>${escapeHtml(L.epThLast)}</th><th>${escapeHtml(L.epThFlags)}</th>
          </tr></thead>
          <tbody>${body}</tbody>
        </table></div>`;
    if (_epDrawer) document.querySelector(`#epResults tr.ep-row[data-mac="${CSS.escape(_epDrawer.mac)}"]`)?.classList.add('is-selected');
}

// I flag sono derivati in lettura e dicono una cosa sola ciascuno: nessuno
// di loro e' un giudizio, tutti sono un fatto sul dato raccolto.
const _EP_FLAG_COLOR = {
    'AMBIGUOUS': 'var(--warning)', 'STALE': 'var(--warning)',
    'TRANSIT-ONLY': 'var(--warning)', 'RANDOM': 'var(--text-muted)',
    'NO-IP': 'var(--text-muted)', 'VM': 'var(--primary)',
    'MULTI-IP': 'var(--primary)', 'NEW': 'var(--success)',
};

function _epFlag(f) {
    const color = _EP_FLAG_COLOR[f] || 'var(--text-muted)';
    return `<span style="font-size:10px; color:${color}; border:1px solid ${color}; border-radius:0; padding:0 4px; white-space:nowrap;">${escapeHtml(f)}</span>`;
}

function _epTime(iso) {
    return String(iso || '').replace('T', ' ').slice(0, 16) || '—';
}

// Export lato client, come exportCategoriesCsv() in topology.js: il file si
// costruisce da cio' che la tabella mostra. Una rotta di export sarebbe un
// secondo formattatore, e i due ordini di colonne divergerebbero.
const _EP_COLS = ['mac', 'oui_vendor', 'tenant', 'probe', 'ips', 'switch_ip',
                  'switch_name', 'interface', 'vlan', 'client_type',
                  'first_seen', 'last_seen', 'seen_count', 'access_port_count',
                  'flags'];

function endpointsExport(format) {
    const L = i18n[currentLang];
    if (!_epRows.length) return;
    // Se l'elenco e' tagliato lo si dice PRIMA di scaricare: un inventario
    // parziale spacciato per intero e' peggio di un export rifiutato.
    if (_epTruncated && !confirm(L.epExportPartial)) return;

    const stamp = new Date().toISOString().slice(0, 10);
    let blob, name;
    if (format === 'json') {
        blob = new Blob([JSON.stringify(_epRows, null, 2)], { type: 'application/json' });
        name = `sentinelnet-endpoints-${stamp}.json`;
    } else {
        const lines = [_EP_COLS.join(',')];
        _epRows.forEach(r => lines.push(_EP_COLS.map(k => csvCell(r[k])).join(',')));
        // BOM: senza, Excel legge gli accenti come mojibake.
        blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
        name = `sentinelnet-endpoints-${stamp}.csv`;
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}

// La riga conosce gia' il proprio tenant — la chiave e' (MAC, tenant) — quindi
// lo passa alla diagnosi, che percio' non deve chiedere quale sede. La domanda
// resta per chi digita un indirizzo a mano.
function endpointsDiagnose(mac, tenant) {
    const input = document.getElementById('diagClientInput');
    if (input) input.value = mac;
    _diagClient = mac;
    _diagTenant = tenant || null;
    switchTab('tab-endpoint');
    locSwitchView('diagnosi');
    runDiagnosi();
}

// `lastRead`: the response of an on-demand read just made, laid over what the
// list returns (the stored read may not be visible yet to the next query).
async function endpointsPorts(lastRead) {
    const host = document.getElementById('ptResults');
    const picker = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptSwitch'));
    if (!host) return;
    const sw = picker ? picker.value : '';
    if (!sw) return;
    const res = await apiFetch('/api/endpoints/ports?switch=' + encodeURIComponent(sw));
    if (!res || !res.ok) {
        host.innerHTML = `<div class="panel" style="padding:22px; text-align:center; color:var(--danger); font-size:13px;">${escapeHtml(tr('epiCouldNotLoadPort'))}</div>`;
        return;
    }
    const portData = await res.json();
    let ifaceConfigs = {};
    try {
        const caRes = await apiFetch('/api/config-analyzer/' + encodeURIComponent(sw));
        if (caRes && caRes.ok) {
            const ca = await caRes.json();
            for (const iface of (ca.interfaces || [])) {
                if (iface.name && iface.raw) {
                    ifaceConfigs[expandIface(iface.name).toLowerCase()] = iface.raw;
                }
            }
        }
    } catch (_) { /* nessun backup analizzato per lo switch */ }
    // Errors column: always rendered, hidden by default; the table's column
    // picker is what turns it on.
    const portErrors = {};
    const dev = _epDeviceOf(sw);
    const q = new URLSearchParams({ device: sw, window: /** @type {HTMLSelectElement|null} */ (document.getElementById('ptWindow'))?.value || '24h' });
    if (dev.Group) q.set('tenant', dev.Group);
    try {
        const er = await apiFetch('/api/interface-errors?' + q.toString());
        if (er && er.ok) {
            for (const p of ((await er.json()).ports || [])) {
                portErrors[expandIface(p.interface).toLowerCase()] = p;
            }
        }
    } catch (_) { /* column stays "—" */ }
    if (lastRead && lastRead.device_ip === sw) {
        for (const p of (lastRead.ports || [])) {
            portErrors[expandIface(p.interface).toLowerCase()] = _epReadRow(p, lastRead);
        }
    }
    endpointsPortsRender(portData, ifaceConfigs, portErrors, sw);
}

// Port config on one line: the body without the "interface ..." header and
// "!" separators, the first two statements, and how many are left.
function portCfgSummary(raw) {
    const body = String(raw || '').split('\n').map(l => l.trim())
        .filter(l => l && l !== '!' && !/^interface\s/i.test(l));
    return { text: body.slice(0, 2).join(' · '), more: Math.max(0, body.length - 2), count: body.length };
}

// Inventory device for a switch IP, preferring the tenant being viewed.
function _epDeviceOf(ip) {
    const tenant = locTenant();
    const all = (globalDevices || []).filter(d => d.IP === ip);
    return all.find(d => tenant && tenant !== 'all' && d.Group === tenant) || all[0] || {};
}

// A port from an on-demand read, shaped like a list row for ifaceErrorsBadge.
function _epReadRow(p, read) {
    return { ...p, last_read: { ...p, ts: read.ts, source: read.source, interval_s: read.interval_s } };
}

async function _epLoadPortErrors(slot, device, port, tenant) {
    if (!slot) return;
    const q = new URLSearchParams({ device, port, window: '24h' });
    if (tenant) q.set('tenant', tenant);
    let data = null;
    try {
        const res = await apiFetch('/api/interface-errors/port?' + q.toString());
        data = res && res.ok ? await res.json() : null;
    } catch (_) { data = null; }
    slot.innerHTML = data && data.known
        ? ifaceErrorsBadge(data.port)
        : `<span style="color:var(--text-muted);">${escapeHtml(tr('epErrUnknown'))}</span>`;
}

// On-demand read (SNMP, else SSH). Returns the response, or null after a toast.
async function _epReadErrors(btn) {
    btn.disabled = true;
    try {
        const res = await apiFetch('/api/interface-errors/read', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device: btn.dataset.device, tenant: btn.dataset.tenant || null }),
        });
        if (!res || !res.ok) {
            const body = res ? await res.json().catch(() => ({})) : {};
            showToast(body.detail || tr('ifErrReadFailed'), 'error');
            return null;
        }
        return await res.json();
    } finally {
        btn.disabled = false;
    }
}

// A port behind an unmanaged switch or a hypervisor learns dozens of MACs:
// listing them all turned one row into a wall. Collapsed like the config cell,
// and diffed like config drift: new / present / gone against the last scan.
let _epPortHist = [];       // mac_history per rendered port, by row index

function macCell(p, idx) {
    const hist = p.mac_history || [];
    const cur = hist.filter(m => m.status !== 'gone').map(m => m.mac);
    const nNew = hist.filter(m => m.status === 'new').length;
    const nGone = hist.length - cur.length;
    if (cur.length === 1 && !nGone) return `<button type="button" class="ep-link" data-action="ep-open-mac" data-mac="${escapeHtml(cur[0])}">${escapeHtml(cur[0])}</button>`;
    if (cur.length <= 3 && !nGone) return escapeHtml(cur.join(', ') || (p.uplink_to ? '→ ' + p.uplink_to : '—'));
    const label = tr('epMacExpand').replace('{n}', String(hist.length));
    return `<button type="button" data-action="ep-toggle-macs" data-idx="${idx}" class="ep-cfg-toggle" aria-expanded="false"
        aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}">
        <i class="fa-solid fa-chevron-right ep-chevron"></i>
        <code class="ep-cfg-summary">${escapeHtml(cur.slice(0, 2).join(', ') || '—')}</code>
        ${cur.length > 2 ? `<span class="ep-cfg-more">+${cur.length - 2}</span>` : ''}
        ${nNew ? `<span class="ep-cfg-more ep-mac-new">${escapeHtml(tr('epMacNewN').replace('{n}', String(nNew)))}</span>` : ''}
        ${nGone ? `<span class="ep-cfg-more ep-mac-gone">${escapeHtml(tr('epMacGoneN').replace('{n}', String(nGone)))}</span>` : ''}
    </button>`;
}

function macHistHtml(hist) {
    const day = _epTime;
    const line = m => {
        const [sign, note] = m.status === 'new' ? ['+', tr('epMacFirstSeen') + ' ' + day(m.first_seen)]
            : m.status === 'gone' ? ['−', tr('epMacLastSeen') + ' ' + day(m.last_seen)]
            : [' ', tr('epMacSince') + ' ' + day(m.first_seen)];
        return `<div class="ep-mac-line is-${m.status}">${sign} ${escapeHtml(m.mac)}  <span>${escapeHtml(note)}</span></div>`;
    };
    return `<div class="ep-mac-hist"><div class="ep-mac-legend">${escapeHtml(tr('epMacLegend'))}</div>${hist.map(line).join('')}</div>`;
}

function endpointsPortsRender(d, ifaceConfigs = {}, portErrors = {}, sw = '') {
    const host = document.getElementById('ptResults');
    const L = i18n[currentLang];
    if (!host) return;

    // Elenco assente: si DICE, e si esce prima di qualunque conteggio. "0
    // porte libere su 0 porte" e' un'informazione falsa travestita da dato.
    if (!d.port_list_known) {
        host.innerHTML = `<div class="panel" style="padding:22px; font-size:13px; color:var(--warning);">
            <i class="fa-solid fa-triangle-exclamation" style="margin-right:8px;"></i>${escapeHtml(L.epPortsUnknown)}</div>`;
        return;
    }

    const c = d.counts || {};
    const ageDays = d.if_list_age_s === null || d.if_list_age_s === undefined
        ? null : Math.round(d.if_list_age_s / 86400);
    const stateColor = { occupied: 'var(--success)', uplink: 'var(--warning)', free: 'var(--text-muted)' };
    const stateLabel = { occupied: L.epStateOccupied, uplink: L.epStateUplink, free: L.epStateFree };

    const onlyBad = /** @type {HTMLInputElement|null} */ (document.getElementById('ptBad'))?.checked;
    const errOf = p => portErrors[expandIface(p.interface).toLowerCase()];
    const ports = (d.ports || []).filter(p => !onlyBad || ['erroring', 'discards'].includes((errOf(p) || {}).status));
    _epPortHist = ports.map(p => p.mac_history || []);
    const rows = ports.map((p, i) => {
        const raw = ifaceConfigs[expandIface(p.interface).toLowerCase()];
        let cfgHtml;
        if (raw) {
            const sum = portCfgSummary(raw);
            const expandLabel = L.epCfgExpand.replace('{n}', String(sum.count));
            cfgHtml = `<div class="ep-cfg-cell">
                <button type="button" data-action="ep-toggle-cfg" class="ep-cfg-toggle" aria-expanded="false"
                    data-raw="${escapeHtml(raw.trim())}" aria-label="${escapeHtml(expandLabel)}" title="${escapeHtml(expandLabel)}">
                    <i class="fa-solid fa-chevron-right ep-chevron"></i>
                    <code class="ep-cfg-summary">${escapeHtml(sum.text || tr('epCfgEmpty'))}</code>
                    ${sum.more ? `<span class="ep-cfg-more">+${sum.more}</span>` : ''}
                </button>
                <button type="button" data-action="ep-copy-cfg" data-raw="${escapeHtml(raw.trim())}" class="ep-cfg-copy"
                    title="${escapeHtml(L.epBtnCopyCfg)}" aria-label="${escapeHtml(L.epBtnCopyCfg)}"><i class="fa-regular fa-copy"></i></button>
            </div>`;
        } else {
            cfgHtml = `<span style="color:var(--text-muted); font-size:12px;" title="${escapeHtml(L.epNoConfigFound)}">—</span>`;
        }

        return `<tr>
            <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(p.interface)}${
                p.physical ? '' : ' <span style="font-size:10px; color:var(--text-muted); border:1px solid var(--border); border-radius:0; padding:0 4px;">virt</span>'}</td>
            <td><span style="font-size:10px; color:${stateColor[p.state]}; border:1px solid ${stateColor[p.state]}; border-radius:0; padding:1px 5px;">${escapeHtml(stateLabel[p.state] || p.state)}</span></td>
            <td style="font-family:var(--font-code); font-size:11px;">${macCell(p, i)}</td>
            <td>${ifaceErrorsBadge(portErrors[expandIface(p.interface).toLowerCase()])}</td>
            <td>${cfgHtml}</td>
        </tr>`;
    }).join('');

    host.innerHTML = `
        <div style="padding:10px 12px; margin-bottom:10px; border-radius:0; background:color-mix(in srgb, var(--warning) 12%, transparent); border:1px solid color-mix(in srgb, var(--warning) 35%, transparent); color:var(--warning); font-size:12px;">
            <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.epPortsFreeWarn)}
            ${ageDays === null ? '' : `<div style="margin-top:4px; color:var(--text-muted);">${escapeHtml(L.epPortsAge)} — ${escapeHtml(String(ageDays))}g</div>`}
        </div>
        <div class="panel" style="padding:12px 14px; margin-bottom:10px; font-size:13px;">
            <b>${escapeHtml(String(c.free ?? 0))}</b> ${escapeHtml(L.epStateFree)} ·
            <b>${escapeHtml(String(c.occupied ?? 0))}</b> ${escapeHtml(L.epStateOccupied)} ·
            <b>${escapeHtml(String(c.uplink ?? 0))}</b> ${escapeHtml(L.epStateUplink)}
            <span style="color:var(--text-muted);">/ ${escapeHtml(String(c.total ?? 0))}</span>

        </div>
        <div class="panel" style="padding:0;"><div class="table-container"><table>
            <thead><tr><th>${escapeHtml(L.epThWhere)}</th><th>${escapeHtml(tr('epThPortState'))}</th><th>${escapeHtml(L.epThMac)}</th><th>${escapeHtml(tr('epThErrors'))}</th><th>${escapeHtml(L.epThConfig)}</th></tr></thead>
            <tbody>${rows}</tbody>
        </table></div></div>`;
}

// Delegated click listener on #epResults
document.getElementById('epResults')?.addEventListener('click', (e) => {
    const openRow = e.target.closest('tr[data-action="ep-open"]');
    if (openRow && !e.target.closest('button, a, input, select')) {
        openEpDrawer(openRow.dataset.mac, openRow.dataset.tenant || '', openRow);
    }
});

// Delegated keydown on #epResults for accessibility
document.getElementById('epResults')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
        const row = e.target.closest('tr[data-action="ep-open"]');
        if (row && e.target === row) {
            e.preventDefault();
            openEpDrawer(row.dataset.mac, row.dataset.tenant || '', row);
        }
    }
});

// Static event listeners for Endpoint Inventory

document.getElementById('locSearchForm')?.addEventListener('submit', (e) => { e.preventDefault(); locSearchSubmit(); });
// "/" jumps to the search while the tab is open and nothing else has the keyboard.
document.addEventListener('keydown', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    if (e.key !== '/' || /INPUT|SELECT|TEXTAREA/.test(t.tagName) || t.isContentEditable) return;
    if (!document.getElementById('tab-endpoint')?.classList.contains('active')) return;
    e.preventDefault();
    document.getElementById('locSearch')?.focus();
});
for (const id of ['epFilterSwitch', 'epFilterVlan', 'epFilterProbe', 'epFilterStale', 'epFilterFrom', 'epFilterTo']) {
    document.getElementById(id)?.addEventListener('change', endpointsApplyFilters);
}
document.getElementById('btnEpReset')?.addEventListener('click', () => {
    for (const id of ['epFilterSwitch', 'epFilterVlan', 'epFilterProbe', 'epFilterFrom', 'epFilterTo']) {
        const el = /** @type {HTMLInputElement|null} */ (document.getElementById(id));
        if (el) el.value = '';
    }
    const stale = /** @type {HTMLInputElement|null} */ (document.getElementById('epFilterStale'));
    if (stale) stale.value = '7';
    _epQuery = '';
    endpointsApplyFilters();
});
document.getElementById('epQueryChip')?.addEventListener('click', (e) => {
    if (!(/** @type {HTMLElement} */ (e.target)).closest('[data-action="ep-clear-query"]')) return;
    _epQuery = '';
    const input = /** @type {HTMLInputElement|null} */ (document.getElementById('locSearch'));
    if (input) input.value = '';
    const msg = document.getElementById('locSearchMsg');
    if (msg) msg.textContent = '';
    endpointsApplyFilters();
});
document.getElementById('btnEpExportCsv')?.addEventListener('click', () => endpointsExport('csv'));
document.getElementById('btnEpExportJson')?.addEventListener('click', () => endpointsExport('json'));

// The tab's search box. One hit opens that endpoint; several fill the list;
// none says so and leaves the view where it was.
async function locSearchSubmit() {
    const input = /** @type {HTMLInputElement|null} */ (document.getElementById('locSearch'));
    const msg = document.getElementById('locSearchMsg');
    if (!input || !msg) return;
    const term = input.value.trim();
    msg.textContent = '';
    if (!term) { _epQuery = ''; _locLoaded.endpoint = true; locSwitchView('endpoint'); endpointsSearch(); return; }
    const res = await apiFetch('/api/endpoints/list?' + endpointsParams(term).toString());
    if (!res || !res.ok) { msg.textContent = tr('epiCouldNotLoadThe'); return; }
    const d = await res.json();
    if (!d.total) { msg.textContent = tr('locSearchNone', { q: term }); return; }
    _epQuery = term;
    const firstTime = !_locLoaded.endpoint;
    _locLoaded.endpoint = true;          // rendered below: no second fetch
    locSwitchView('endpoint');
    if (firstTime) _epFillFilters();
    endpointsRender(d);
    msg.textContent = tr('locSearchFound', { n: String(d.total) });
    if ((d.results || []).length === 1) openEpDrawer(d.results[0].mac, d.results[0].tenant || '', input);
}

// ===== Sub-tab "Port errors": every device's ports, from /api/interface-errors =====
// Same data and verdicts as the Interfaces tab and the occupancy column; this
// view only answers "which ports, across the tenant, are erroring now".

async function loadPortErrorsPane() {
    const host = document.getElementById('ptResults');
    if (!host) return;
    const tenant = locTenant();
    const windowVal = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptWindow'))?.value || '24h';

    host.innerHTML = `<div class="panel" style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
        <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>${escapeHtml(tr('epiLoading'))}</div>`;
    const q = new URLSearchParams({ window: windowVal });
    let data = null;
    try {
        const res = await apiFetch('/api/interface-errors?' + q.toString());
        data = res && res.ok ? await res.json() : null;
    } catch (_) { data = null; }
    if (!data) {
        host.innerHTML = `<div class="panel" style="padding:22px; text-align:center; color:var(--danger); font-size:13px;">${escapeHtml(tr('peLoadFailed'))}</div>`;
        return;
    }
    // The global tenant selector narrows the view; the server already limits
    // it to the user's own tenants.
    const all = (data.ports || []).filter(p => !tenant || tenant === 'all' || p.tenant === tenant);
    const rows = all.filter(p => p.status === 'erroring' || p.status === 'discards');
    const bad = all.filter(p => p.status === 'erroring').length;
    const disc = all.filter(p => p.status === 'discards').length;

    const summary = `<div class="panel" style="padding:12px 14px; margin-bottom:10px; font-size:13px;">
        <b style="color:${bad ? 'var(--danger)' : 'var(--text)'};">${escapeHtml(String(bad))}</b> ${escapeHtml(tr('peWithErrors'))} ·
        <b>${escapeHtml(String(disc))}</b> ${escapeHtml(tr('peWithDiscards'))}
        <span style="color:var(--text-muted);">/ ${escapeHtml(tr('peWithCounters', { n: String(all.length) }))}</span>
        ${data.truncated ? `<div style="margin-top:4px; color:var(--warning); font-size:12px;">${escapeHtml(tr('peTruncated'))}</div>` : ''}
    </div>`;

    if (!rows.length) {
        host.innerHTML = summary + `<div class="panel" style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;">
            <i class="fa-solid fa-circle-check" style="margin-right:6px; color:var(--success);"></i>${escapeHtml(tr(all.length ? 'peNoBadPorts' : 'peNoData'))}</div>`;
        return;
    }

    // The most recent evidence: an on-demand read newer than the last poll.
    const latest = (p) => (p.last_read && (!p.window || (p.last_read.ts || 0) >= (p.window.observed_ts || 0)))
        ? { item: p.last_read, ts: p.last_read.ts, src: String(p.last_read.source || '').toUpperCase() }
        : { item: p.window, ts: p.window && p.window.observed_ts, src: 'SNMP' };
    const detail = (p) => {
        const grown = Object.entries((latest(p).item || {}).delta || {}).filter(([, v]) => v)
            .map(([f, v]) => `${IFERR_FIELD_KEYS[f] ? tr(IFERR_FIELD_KEYS[f]) : f} +${v}`);
        return grown.join(', ') || '—';
    };
    const seen = (p) => {
        const l = latest(p);
        return l.ts ? `${new Date(l.ts * 1000).toLocaleString()} · ${l.src}` : '—';
    };
    const body = rows.map(p => `<tr>
        <td style="font-size:12px; white-space:nowrap;">${escapeHtml(p.hostname || p.device_ip)}<div style="color:var(--text-muted); font-family:var(--font-code); font-size:11px;">${escapeHtml(p.device_ip)}</div></td>
        <td style="font-family:var(--font-code); font-size:12px; white-space:nowrap;">${escapeHtml(p.interface)}</td>
        <td style="font-size:12px;">${escapeHtml(p.tenant || '—')}</td>
        <td>${ifaceErrorsBadge(p)}</td>
        <td style="font-size:12px; line-height:1.5; min-width:220px;">${escapeHtml(detail(p))}</td>
        <td style="font-size:11px; color:var(--text-muted); white-space:nowrap;">${escapeHtml(seen(p))}</td>
        <td style="white-space:nowrap;"><button type="button" data-action="pe-portcfg" class="btn btn-secondary btn-small" style="width:auto; margin:0;"
            data-ip="${escapeHtml(p.device_ip)}" data-port="${escapeHtml(p.interface)}" data-name="${escapeHtml(p.hostname || '')}"
            title="${escapeHtml(tr('epActPortCfg'))}"><i class="fa-solid fa-file-lines"></i> ${escapeHtml(tr('epThConfig'))}</button></td>
    </tr>`).join('');

    host.innerHTML = summary + `<div class="panel" style="padding:0;"><div class="table-container"><table>
        <thead><tr>
            <th>${escapeHtml(tr('peThDevice'))}</th><th>${escapeHtml(tr('peThPort'))}</th>
            <th>${escapeHtml(tr('peThTenant'))}</th><th>${escapeHtml(tr('ifThErrors'))}</th>
            <th>${escapeHtml(tr('peThDetail'))}</th><th>${escapeHtml(tr('peThSeen'))}</th>
            <th>${escapeHtml(tr('epThConfig'))}</th>
        </tr></thead>
        <tbody>${body}</tbody>
    </table></div></div>`;
}

// Porte: a chosen switch shows all its ports (occupancy + errors); "all"
// shows only the erroring ports across the tenant.
function loadPortsView() {
    const picker = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptSwitch'));
    if (picker) {
        const cur = picker.value;
        const tenant = locTenant();
        let devs = globalDevices || [];
        if (tenant && tenant !== 'all') devs = devs.filter(d => d.Group === tenant);
        const label = d => d.Hostname || d.IP;
        picker.innerHTML = `<option value="">${escapeHtml(tr('ptSwitchAll'))}</option>` + devs.slice()
            .sort((a, b) => label(a).localeCompare(label(b)))
            .map(d => `<option value="${escapeHtml(d.IP)}">${escapeHtml(label(d))} — ${escapeHtml(d.IP)}</option>`).join('');
        picker.value = devs.some(d => d.IP === cur) ? cur : '';
    }
    const bad = /** @type {HTMLInputElement|null} */ (document.getElementById('ptBad'));
    if (bad) bad.disabled = !picker?.value;      // "all" is problems-only by definition
    if (picker?.value) endpointsPorts(); else loadPortErrorsPane();
}

for (const id of ['ptSwitch', 'ptWindow', 'ptBad']) document.getElementById(id)?.addEventListener('change', loadPortsView);
document.getElementById('ptRefresh')?.addEventListener('click', loadPortsView);
document.getElementById('ptRead')?.addEventListener('click', async (e) => {
    const btn = /** @type {HTMLButtonElement} */ (e.currentTarget);
    const device = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptSwitch'))?.value || '';
    if (!device) { showToast(tr('ifErrPickDevice'), 'warning'); return; }
    btn.dataset.device = device;
    btn.dataset.tenant = _epDeviceOf(device).Group || '';
    const read = await _epReadErrors(btn);
    if (read) {
        showToast(tr('ifErrReadDone', { device, src: String(read.source || '').toUpperCase(), s: String(read.interval_s) }), 'success');
        endpointsPorts(read);
    }
});
document.getElementById('ptLegendBtn')?.addEventListener('click', (e) => {
    const btn = /** @type {HTMLElement} */ (e.currentTarget);
    const box = document.getElementById('ptLegend');
    if (!box) return;
    box.hidden = !box.hidden;
    btn.setAttribute('aria-expanded', box.hidden ? 'false' : 'true');
});
document.addEventListener('click', (e) => {
    const box = document.getElementById('ptLegend');
    if (box && !box.hidden && !(/** @type {HTMLElement} */ (e.target)).closest('.ep-pop')) {
        box.hidden = true;
        document.getElementById('ptLegendBtn')?.setAttribute('aria-expanded', 'false');
    }
});
document.getElementById('ptResults')?.addEventListener('click', (e) => {
    const open = /** @type {HTMLElement|null} */ (e.target.closest('[data-action="ep-open-mac"]'));
    if (open) { openEpDrawer(open.dataset.mac || '', locTenant() === 'all' ? '' : locTenant(), open); return; }
    const pc = /** @type {HTMLElement|null} */ (e.target.closest('[data-action="pe-portcfg"]'));
    if (pc) { showPortConfig(pc.dataset.ip, pc.dataset.port, pc.dataset.name); return; }
    const copyCfgBtn = e.target.closest('[data-action="ep-copy-cfg"]');
    if (copyCfgBtn) {
        const raw = copyCfgBtn.dataset.raw || '';
        if (navigator.clipboard && raw) {
            navigator.clipboard.writeText(raw).then(() => {
                const orig = copyCfgBtn.innerHTML;
                copyCfgBtn.innerHTML = `<i class="fa-solid fa-check" style="color:var(--success);"></i>`;
                setTimeout(() => { copyCfgBtn.innerHTML = orig; }, 1500);
            });
        }
        return;
    }
    const toggleCfgBtn = e.target.closest('[data-action="ep-toggle-cfg"], [data-action="ep-toggle-macs"]');
    if (toggleCfgBtn) {
        // The full block opens in a row of its own, full table width: inside the
        // cell it squeezed a multi-line config into a narrow column.
        const row = toggleCfgBtn.closest('tr');
        const next = row?.nextElementSibling;
        const open = toggleCfgBtn.getAttribute('aria-expanded') === 'true';
        if (next && next.classList.contains('ep-cfg-row')) next.remove();
        // MAC and config toggles share the one detail row: the other closes.
        row?.querySelectorAll('[data-action="ep-toggle-cfg"], [data-action="ep-toggle-macs"]').forEach(b => b.setAttribute('aria-expanded', 'false'));
        if (row && !open) {
            const cfgRow = document.createElement('tr');
            cfgRow.className = 'ep-cfg-row';
            const body = toggleCfgBtn.dataset.action === 'ep-toggle-macs'
                ? macHistHtml(_epPortHist[Number(toggleCfgBtn.dataset.idx)] || [])
                : `<pre class="ep-cfg-full">${escapeHtml(toggleCfgBtn.dataset.raw || '')}</pre>`;
            cfgRow.innerHTML = `<td colspan="${row.cells.length}">${body}</td>`;
            row.after(cfgRow);
        }
        toggleCfgBtn.setAttribute('aria-expanded', open ? 'false' : 'true');
        return;
    }
});

// ===== Endpoint drawer =====
// Docked beside the list on wide screens, so the next row is one click away;
// a modal sheet on narrow ones, through the modal manager.
const _EP_NARROW = '(max-width: 900px)';
let _epDrawer = null;      // { mac, tenant, opener }

async function openEpDrawer(mac, tenant, opener) {
    const host = document.getElementById('epDrawerHost');
    const box = document.getElementById('epDrawer');
    if (!host || !box) return;
    const tok = _epDrawer = { mac, tenant, opener: opener || document.activeElement };
    const listRow = _epRows.find(r => r.mac === mac && (r.tenant || '') === tenant)
                 || _epRows.find(r => r.mac === mac) || { mac, tenant };
    document.querySelectorAll('#epResults tr.ep-row.is-selected').forEach(tr => tr.classList.remove('is-selected'));
    document.querySelector(`#epResults tr.ep-row[data-mac="${CSS.escape(mac)}"]`)?.classList.add('is-selected');
    box.innerHTML = `<div class="drawer-body"><div class="drawer-section">${escapeHtml(tr('epiLoading'))}</div></div>`;
    _epShowDrawer(host);

    let loc = null;
    try {
        const q = '/api/mac/locate?mac=' + encodeURIComponent(mac) + (tenant ? '&tenant=' + encodeURIComponent(tenant) : '');
        const res = await apiFetch(q);
        loc = res && res.ok ? await res.json() : null;
    } catch (_) { loc = null; }
    if (_epDrawer !== tok) return;       // closed, or another row opened meanwhile
    const row = _epRowFromLocate(listRow, loc);
    box.innerHTML = _epDrawerHtml(row, loc);
    if (row.switch_ip && row.interface) {
        _epLoadPortErrors(box.querySelector('.ep-err-slot'), row.switch_ip, row.interface, row.tenant || '');
    }
    /** @type {HTMLElement|null} */ (box.querySelector('[data-action="ep-drawer-close"]'))?.focus({ preventScroll: true });
}

function _epShowDrawer(host) {
    host.style.display = '';
    host.hidden = false;
    if (window.matchMedia(_EP_NARROW).matches) {
        openModal('epDrawerHost', closeEpDrawer);
    } else {
        document.getElementById('locBody')?.classList.add('has-drawer');
    }
}

function closeEpDrawer() {
    const host = document.getElementById('epDrawerHost');
    if (!host || host.hidden) { _epDrawer = null; return; }
    const opener = _epDrawer && _epDrawer.opener;
    _epDrawer = null;
    if (isModalOpen('epDrawerHost')) closeModal('epDrawerHost');
    host.hidden = true;
    document.getElementById('locBody')?.classList.remove('has-drawer');
    document.querySelectorAll('#epResults tr.ep-row.is-selected').forEach(tr => tr.classList.remove('is-selected'));
    if (opener && document.contains(opener)) opener.focus({ preventScroll: true });
}

// A drawer opened without a list row (from Porte, the terminal, a search on a
// view never loaded) takes its position from the locate answer: the switch,
// port and VLAN are there even when the list is not.
function _epRowFromLocate(row, loc) {
    if (!loc || row.switch_ip) return row;
    const e = (loc.results && loc.results.length) ? loc.results[0] : loc;
    const o = (e.origin || [])[0];
    if (!o) return row;
    return { ...row, mac: e.mac || loc.mac || row.mac, tenant: row.tenant || e.tenant || '',
             switch_ip: o.switch_ip, switch_name: o.switch_name, interface: o.interface, vlan: o.vlan };
}

const _EP_STATUS_TAG = {
    resolved: ['iferr-ok', 'epDrStatusResolved'],
    ambiguous: ['iferr-warn', 'epDrStatusAmbiguous'],
    transit_only: ['iferr-warn', 'epDrStatusTransit'],
    not_found: ['iferr-warn', 'epDrStatusNotFound'],
};

function _epDrawerHtml(r, loc) {
    const entries = loc ? ((loc.results && loc.results.length) ? loc.results : [loc]) : [];
    const e = entries[0] || {};
    const [cls, key] = _EP_STATUS_TAG[e.status] || _EP_STATUS_TAG.not_found;
    const kv = (k, v) => `<div class="drawer-kpi"><span class="kpi-label">${escapeHtml(k)}</span><strong>${escapeHtml(v || '—')}</strong></div>`;
    const hop = (s, kind) => `<li class="ep-hop is-${kind}">${escapeHtml(s.switch_name || s.switch_ip)} ${escapeHtml(s.interface || '')}${
        s.uplink_to ? ' → ' + escapeHtml(s.uplink_to) : ''} <span>· ${escapeHtml(tr(kind === 'access' ? 'epDrAccess' : 'epDrTransit'))} · VLAN&nbsp;${escapeHtml(s.vlan || '—')}</span></li>`;
    const origin = entries.flatMap(x => x.origin || []);
    const transit = entries.flatMap(x => x.transit || []);
    const ips = (r.ips || []).length
        ? `<div class="drawer-kpi-grid">${(r.ips || []).map(ip => kv('IP', ip)).join('')}</div>`
        : `<p class="ep-dr-note">${escapeHtml(tr('epDrNoIp'))}</p>`;
    const banner = e.status === 'ambiguous'
        ? `<p class="ep-dr-note is-warn">${escapeHtml(tr('cmapMultiplePossibleAccessPorts', { access_count: e.access_count }))}</p>`
        : e.status === 'not_found'
        ? `<p class="ep-dr-note is-warn">${escapeHtml(tr('cmapNotInLatestScan') + (e.last_seen ? ' ' + tr('cmapLastSeenAt', { when: fmtMacTime(e.last_seen) }) : ''))}</p>`
        : entries.length > 1
        ? `<p class="ep-dr-note">${escapeHtml(tr('cmapThisMacExistsIn', { length: entries.length }))}</p>`
        : '';
    const port = (r.switch_ip && r.interface) ? `
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrPort', { port: r.interface }))}</h4>
          <div class="ep-err-slot">${escapeHtml(tr('epErrLoading'))}</div>
          <div><button type="button" class="btn btn-secondary btn-small requires-write" data-action="ep-err-read"
              data-device="${escapeHtml(r.switch_ip)}" data-port="${escapeHtml(r.interface)}" data-tenant="${escapeHtml(r.tenant || '')}">
              <i class="fa-solid fa-stethoscope"></i> ${escapeHtml(tr('epErrReadNow'))}</button></div>
        </section>` : '';
    return `
      <div class="drawer-header">
        <div class="drawer-title-wrap">
          <span class="drawer-eyebrow">${escapeHtml(r.tenant || '')}${r.probe ? ' · ' + escapeHtml(r.probe) : ''}</span>
          <h3 id="epDrawerTitle" class="drawer-title ep-dr-mac">${escapeHtml(r.mac)}</h3>
          <span class="ep-dr-vendor">${escapeHtml(r.oui_vendor || '')}</span>
        </div>
        <button type="button" class="drawer-close-btn" data-action="ep-drawer-close" aria-label="${escapeHtml(tr('epDrClose'))}"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="drawer-body">
        <div class="ep-dr-actions">
          <span class="iferr ${cls}">${escapeHtml(tr(key))}</span>
          <button type="button" class="btn btn-primary btn-small" data-action="ep-diagnose" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}"><i class="fa-solid fa-stethoscope"></i> ${escapeHtml(tr('tabDiagnosi'))}</button>
          ${(r.switch_ip && r.interface) ? `<button type="button" class="btn btn-secondary btn-small" data-action="ep-portcfg" data-switch-ip="${escapeHtml(r.switch_ip)}" data-switch-port="${escapeHtml(r.interface)}" data-switch-name="${escapeHtml(r.switch_name || '')}"><i class="fa-solid fa-file-lines"></i> ${escapeHtml(tr('epThConfig'))}</button>` : ''}
          <button type="button" class="btn btn-secondary btn-small" data-action="ep-copy-mac" data-mac="${escapeHtml(r.mac)}" aria-label="${escapeHtml(tr('epDrCopyMac'))}"><i class="fa-regular fa-copy"></i></button>
        </div>
        ${banner}
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrPosition'))}</h4>
          <div class="drawer-kpi-grid">${kv(tr('epThSwitch'), r.switch_name || r.switch_ip)}${kv(tr('epThPort'), r.interface)}${kv('VLAN', r.vlan)}${kv(tr('epDetailClientType'), r.client_type)}</div>
        </section>
        <section class="drawer-section"><h4 class="drawer-section-title">IP</h4>${ips}</section>
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrPath'))}</h4>
          <ul class="ep-path">${origin.map(s => hop(s, 'access')).join('')}${transit.map(s => hop(s, 'transit')).join('')}</ul>
          ${transit.length ? '' : `<p class="ep-dr-note">${escapeHtml(tr('epDrNoTransit'))}</p>`}
        </section>
        ${port}
        <section class="drawer-section">
          <h4 class="drawer-section-title">${escapeHtml(tr('epDrHistory'))}</h4>
          <div class="drawer-kpi-grid">${kv(tr('epDetailFirstSeen'), _epTime(r.first_seen))}${kv(tr('epDetailLastSeen'), _epTime(r.last_seen))}${kv(tr('epDetailSeenCount'), String(r.seen_count ?? '—'))}</div>
          <div>${(r.flags || []).map(_epFlag).join(' ')}</div>
        </section>
      </div>`;
}

document.getElementById('epDrawer')?.addEventListener('click', (e) => {
    const t = /** @type {HTMLElement} */ (e.target);
    if (t.closest('[data-action="ep-drawer-close"]')) { closeEpDrawer(); return; }
    const diag = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-diagnose"]'));
    if (diag) { closeEpDrawer(); endpointsDiagnose(diag.dataset.mac, diag.dataset.tenant || ''); return; }
    const cfg = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-portcfg"]'));
    if (cfg) { showPortConfig(cfg.dataset.switchIp, cfg.dataset.switchPort, cfg.dataset.switchName); return; }
    const copy = /** @type {HTMLElement|null} */ (t.closest('[data-action="ep-copy-mac"]'));
    if (copy) {
        navigator.clipboard?.writeText(copy.dataset.mac || '').then(
            () => showToast(tr('epDrCopied'), 'success'), () => showToast(copy.dataset.mac || '', 'info'));
        return;
    }
    const read = /** @type {HTMLButtonElement|null} */ (t.closest('[data-action="ep-err-read"]'));
    if (read) {
        const slot = document.querySelector('#epDrawer .ep-err-slot');
        if (slot) slot.textContent = tr('epErrLoading');
        _epReadErrors(read).then(res => {
            if (!slot) return;
            const want = expandIface(read.dataset.port).toLowerCase();
            const p = res && (res.ports || []).find(x => expandIface(x.interface).toLowerCase() === want);
            if (p) slot.innerHTML = ifaceErrorsBadge(_epReadRow(p, res));
            else _epLoadPortErrors(slot, read.dataset.device, read.dataset.port, read.dataset.tenant);
        });
    }
});

// Esc closes the docked drawer too; the narrow sheet gets Esc from the modal manager.
document.addEventListener('keydown', (e) => {
    // A modal on top handles its own Esc (and marks it): that press is not for the drawer.
    if (e.key === 'Escape' && !e.defaultPrevented && _epDrawer && !isModalOpen('epDrawerHost')) closeEpDrawer();
});

// A MAC clicked in the CLI terminal opens its endpoint here.
function locateMacFromTerminal(mac) {
    switchTab('tab-endpoint');
    locSwitchView('endpoint');
    openEpDrawer(mac, '', null);
}
