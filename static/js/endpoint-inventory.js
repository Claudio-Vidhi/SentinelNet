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

function loadEndpointsTab() {
    endpointsApplyFilters();
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
    // In modalita' porte l'elenco appena riletto serve a ricostruire il
    // selettore degli switch: col tenant cambiato, gli switch sono altri.
    if (_epMode === 'ports') endpointsMode('ports');
}

async function endpointsSearch() {
    const host = document.getElementById('epResults');
    if (!host) return;
    const L = i18n[currentLang];

    const q = ((document.getElementById('epFilterQ') || {}).value || '').trim();
    const tenant = locTenant();
    const staleDays = parseInt((document.getElementById('epFilterStale') || {}).value, 10) || 7;
    const fromVal = ((document.getElementById('epFilterFrom') || {}).value || '').trim();
    const toVal = ((document.getElementById('epFilterTo') || {}).value || '').trim();

    host.innerHTML = `<div class="panel" style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
        <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>${escapeHtml(tr('epiLoading'))}</div>`;

    const params = new URLSearchParams({ stale_days: String(staleDays) });
    if (q) params.set('q', q);
    if (tenant && tenant !== 'all') params.set('tenant', tenant);
    if (fromVal) {
        try { params.set('frm', new Date(fromVal).toISOString()); } catch (e) { params.set('frm', fromVal); }
    }
    if (toVal) {
        try { params.set('to', new Date(toVal).toISOString()); } catch (e) { params.set('to', toVal); }
    }

    const res = await apiFetch('/api/endpoints/list?' + params.toString());
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
        const tile = (label, value, color) => `<div class="kpi">
            <h4 title="${escapeHtml(label)}">${escapeHtml(label)}</h4>
            <strong style="color:${color || 'var(--text)'};">${escapeHtml(String(value ?? 0))}</strong>
        </div>`;
        kpis.innerHTML =
            tile(L.epKpiEndpoints, c.endpoints, 'var(--primary)') +
            tile(L.epKpiSwitches, c.switches) +
            tile(L.epKpiVlans, c.vlans) +
            tile(L.epKpiStale, c.stale, c.stale ? 'var(--warning)' : undefined) +
            tile(L.epKpiNew, c.new) +
            tile(L.epKpiNoIp, c.no_ip);
    }

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

    // Le tre azioni esistono gia' altrove: qui si rendono solo raggiungibili
    // dalla riga. stopPropagation non serve piu' grazie alla delegazione.
    const act = (icon, title, action, dataAttrs, enabled) => enabled
        ? `<button data-action="${action}" ${dataAttrs} title="${escapeHtml(title)}"
             style="border:none; background:none; color:var(--primary); cursor:pointer; font-size:12px; margin-right:8px;">
             <i class="fa-solid ${icon}"></i></button>`
        : `<span style="color:var(--text-muted); font-size:12px; margin-right:8px; opacity:0.35;"><i class="fa-solid ${icon}"></i></span>`;

    const body = _epRows.map(r => `<tr data-action="ep-row-toggle" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}" tabindex="0" role="button" aria-expanded="false" style="cursor:pointer;">
        <td style="font-family:var(--font-code); font-size:12px; white-space:nowrap;">
            <i class="fa-solid fa-chevron-right ep-chevron" style="color:var(--text-muted); font-size:10px; margin-right:8px; transition:transform 0.18s ease; display:inline-block;"></i>${escapeHtml(r.mac)}
        </td>
        <td style="font-size:12px;">${escapeHtml(r.oui_vendor || '—')}</td>
        <td style="font-size:12px;">${escapeHtml(r.tenant || '—')} <span style="color:var(--text-muted);">/ ${escapeHtml(r.site || '—')}</span></td>
        <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml((r.ips || []).join(', ') || '—')}</td>
        <td style="font-size:12px;">${escapeHtml(r.switch_name || r.switch_ip || '—')} <span style="color:var(--text-muted);">${escapeHtml(r.interface || '')}</span></td>
        <td style="font-size:12px;">${escapeHtml(r.vlan || '—')}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(_epTime(r.first_seen))}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(_epTime(r.last_seen))}</td>
        <td>${(r.flags || []).map(_epFlag).join(' ')}</td>
        <td style="white-space:nowrap;">${
            act('fa-stethoscope', L.epActDiagnose, 'ep-diagnose',
                `data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}"`, true) +
            act('fa-magnifying-glass-location', L.epActLocate, 'ep-locate',
                `data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}"`, true) +
            act('fa-file-lines', L.epActPortCfg, 'ep-portcfg',
                `data-switch-ip="${escapeHtml(r.switch_ip || '')}" data-switch-port="${escapeHtml(r.interface || '')}" data-switch-name="${escapeHtml(r.switch_name || '')}"`,
                !!(r.switch_ip && r.interface))
        }</td>
    </tr>`).join('');

    host.innerHTML = `${banner}
        <div class="panel" style="padding:0;">
          <div class="table-container">
            <table>
              <thead><tr>
                <th>${escapeHtml(L.epThMac)}</th><th>${escapeHtml(L.epThVendor)}</th>
                <th>${escapeHtml(L.epThTenant)}</th><th>${escapeHtml(L.epThIps)}</th>
                <th>${escapeHtml(L.epThWhere)}</th><th>${escapeHtml(L.epThVlan)}</th>
                <th>${escapeHtml(L.epThFirst)}</th><th>${escapeHtml(L.epThLast)}</th>
                <th>${escapeHtml(L.epThFlags)}</th>
                <th>${escapeHtml(L.epThActions)}</th>
              </tr></thead>
              <tbody>${body}</tbody>
            </table>
          </div>
        </div>`;
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
const _EP_COLS = ['mac', 'oui_vendor', 'tenant', 'site', 'ips', 'switch_ip',
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

function _renderEndpointDetailRow(r) {
    const L = i18n[currentLang];
    return `
        <td colspan="10" style="padding:16px 20px; background:var(--surface-2); box-shadow:inset 0 2px 4px rgba(0,0,0,0.03);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; gap:12px; flex-wrap:wrap; border-bottom:1px solid var(--border); padding-bottom:10px;">
                <div style="display:flex; align-items:center; gap:10px;">
                    <span style="display:inline-flex; align-items:center; justify-content:center; width:32px; height:32px; border-radius:0; background:color-mix(in srgb, var(--primary) 15%, transparent); color:var(--primary); font-size:14px;">
                        <i class="fa-solid fa-network-wired"></i>
                    </span>
                    <div>
                        <div style="font-weight:700; font-size:14px; color:var(--text); font-family:var(--font-code);">${escapeHtml(r.mac)}</div>
                        ${r.oui_vendor ? `<div style="font-size:11px; color:var(--text-muted);">${escapeHtml(r.oui_vendor)}</div>` : ''}
                    </div>
                </div>
                <div style="display:flex; gap:8px; align-items:center;">
                    <button data-action="ep-diagnose" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}" class="btn btn-primary btn-small" style="width:auto; margin:0; display:flex; align-items:center; gap:6px;" title="${escapeHtml(L.epActDiagnose)}">
                        <i class="fa-solid fa-stethoscope"></i> ${escapeHtml(L.tabDiagnosi)}
                    </button>
                    <button data-action="ep-locate" data-mac="${escapeHtml(r.mac)}" data-tenant="${escapeHtml(r.tenant || '')}" class="btn btn-secondary btn-small" style="width:auto; margin:0; display:flex; align-items:center; gap:6px;" title="${escapeHtml(L.epActLocate)}">
                        <i class="fa-solid fa-magnifying-glass-location"></i> ${escapeHtml(L.epThWhere)}
                    </button>
                    ${(r.switch_ip && r.interface) ? `
                    <button data-action="ep-portcfg" data-switch-ip="${escapeHtml(r.switch_ip)}" data-switch-port="${escapeHtml(r.interface)}" data-switch-name="${escapeHtml(r.switch_name || '')}" class="btn btn-secondary btn-small" style="width:auto; margin:0; display:flex; align-items:center; gap:6px;" title="${escapeHtml(L.epActPortCfg)}">
                        <i class="fa-solid fa-file-lines"></i> ${escapeHtml(L.epThConfig)}
                    </button>` : ''}
                </div>
            </div>
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(170px, 1fr)); gap:10px; font-size:12px;">
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;"><i class="fa-solid fa-cube" style="margin-right:4px;"></i>${escapeHtml(L.epDetailClientType)}</div>
                    <div><b>${escapeHtml(r.client_type || '—')}</b></div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;" title="${escapeHtml(tr('epDetailSeenCountHint'))}"><i class="fa-solid fa-eye" style="margin-right:4px;"></i>${escapeHtml(L.epDetailSeenCount)}</div>
                    <div><b>${escapeHtml(String(r.seen_count ?? 1))}</b></div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;" title="${escapeHtml(tr('epDetailAccessPortsHint'))}"><i class="fa-solid fa-ethernet" style="margin-right:4px;"></i>${escapeHtml(L.epDetailAccessPorts)}</div>
                    <div><b>${escapeHtml(String(r.access_port_count ?? 1))}</b></div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;"><i class="fa-solid fa-globe" style="margin-right:4px;"></i>${escapeHtml(L.epDetailIps)}</div>
                    <div style="font-family:var(--font-code); font-size:11px;">${escapeHtml((r.ips || []).join(', ') || '—')}</div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;"><i class="fa-solid fa-building" style="margin-right:4px;"></i>${escapeHtml(L.epDetailTenantSite)}</div>
                    <div>${escapeHtml(r.tenant || '—')} <span style="color:var(--text-muted);">/ ${escapeHtml(r.site || '—')}</span></div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;"><i class="fa-solid fa-server" style="margin-right:4px;"></i>${escapeHtml(L.epDetailSwitchPort)}</div>
                    <div>${escapeHtml(r.switch_name || r.switch_ip || '—')} <span style="color:var(--primary); font-weight:600; font-family:var(--font-code);">${escapeHtml(r.interface || '')}</span></div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;"><i class="fa-solid fa-tag" style="margin-right:4px;"></i>${escapeHtml(L.epDetailVlan)}</div>
                    <div>${escapeHtml(r.vlan || '—')}</div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;"><i class="fa-regular fa-clock" style="margin-right:4px;"></i>${escapeHtml(L.epDetailFirstSeen)}</div>
                    <div style="font-size:11px;">${escapeHtml(_epTime(r.first_seen))}</div>
                </div>
                <div style="background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:2px;"><i class="fa-solid fa-clock-rotate-left" style="margin-right:4px;"></i>${escapeHtml(L.epDetailLastSeen)}</div>
                    <div style="font-size:11px;">${escapeHtml(_epTime(r.last_seen))}</div>
                </div>
                ${(r.switch_ip && r.interface) ? `
                <div style="grid-column:1/-1; background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap;">
                    <div>
                        <div style="color:var(--text-muted); font-size:11px; margin-bottom:4px;"><i class="fa-solid fa-heart-pulse" style="margin-right:4px;"></i>${escapeHtml(tr('epDetailPortErrors'))}</div>
                        <div class="ep-err-slot" style="font-size:12px;">${escapeHtml(tr('epErrLoading'))}</div>
                    </div>
                    <button type="button" class="btn btn-secondary btn-small requires-write" style="width:auto; margin:0;" data-action="ep-err-read"
                        data-device="${escapeHtml(r.switch_ip)}" data-port="${escapeHtml(r.interface)}" data-tenant="${escapeHtml(r.tenant || '')}">
                        <i class="fa-solid fa-stethoscope"></i> ${escapeHtml(tr('epErrReadNow'))}</button>
                </div>` : ''}
                <div style="grid-column:1/-1; background:var(--surface-1); padding:8px 12px; border-radius:0; border:1px solid var(--border);">
                    <div style="color:var(--text-muted); font-size:11px; margin-bottom:4px;">${escapeHtml(L.epDetailFlags)}</div>
                    <div>${(r.flags || []).length ? (r.flags || []).map(_epFlag).join(' ') : '—'}</div>
                </div>
            </div>
        </td>
    `;
}

function _toggleEndpointDetail(row) {
    const tbody = row.parentNode;
    if (!tbody) return;
    const next = row.nextElementSibling;
    const currentChevron = row.querySelector('.ep-chevron');
    if (next && next.classList.contains('ep-detail-row')) {
        next.remove();
        row.setAttribute('aria-expanded', 'false');
        row.style.background = '';
        if (currentChevron) {
            currentChevron.style.transform = '';
            currentChevron.style.color = '';
        }
        return;
    }
    tbody.querySelectorAll('.ep-detail-row').forEach(dr => {
        const prevRow = dr.previousElementSibling;
        if (prevRow) {
            prevRow.setAttribute('aria-expanded', 'false');
            prevRow.style.background = '';
            const ch = prevRow.querySelector('.ep-chevron');
            if (ch) { ch.style.transform = ''; ch.style.color = ''; }
        }
        dr.remove();
    });
    const mac = row.dataset.mac;
    const tenant = row.dataset.tenant || '';
    const r = _epRows.find(item => item.mac === mac && (item.tenant || '') === tenant)
           || _epRows.find(item => item.mac === mac);
    if (!r) return;

    const detailTr = document.createElement('tr');
    detailTr.className = 'ep-detail-row';
    detailTr.dataset.detailFor = mac;
    detailTr.style.background = 'var(--surface-2)';
    detailTr.innerHTML = _renderEndpointDetailRow(r);
    row.after(detailTr);
    if (r.switch_ip && r.interface) {
        _epLoadPortErrors(detailTr.querySelector('.ep-err-slot'), r.switch_ip, r.interface, r.tenant || '');
    }
    row.setAttribute('aria-expanded', 'true');
    row.style.background = 'color-mix(in srgb, var(--primary) 6%, transparent)';
    if (currentChevron) {
        currentChevron.style.transform = 'rotate(90deg)';
        currentChevron.style.color = 'var(--primary)';
    }
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

// Seconda modalita' della stessa tab. L'elenco delle interfacce arriva da
// switch_if_macs, popolata a ogni scansione MAC: e' fresco quanto l'ultima
// scansione di QUELLO switch, e la sua eta' si mostra sempre.
let _epMode = 'list';

function endpointsMode(mode) {
    _epMode = mode;
    const listBtn = document.getElementById('epModeListBtn');
    const portsBtn = document.getElementById('epModePortsBtn');
    const picker = document.getElementById('epPortsSwitch');
    const active = 'border-color:var(--primary); color:var(--primary);';
    if (listBtn) listBtn.style.cssText = 'width:auto; margin:0;' + (mode === 'list' ? active : '');
    if (portsBtn) portsBtn.style.cssText = 'width:auto; margin:0;' + (mode === 'ports' ? active : '');
    if (picker) picker.style.display = mode === 'ports' ? '' : 'none';

    if (mode === 'list') { endpointsSearch(); return; }
    // I KPI sono un riassunto dell'INTERO elenco: in modalita' porte non
    // descrivono piu' cio' che e' a schermo (le porte di un solo switch), e
    // lasciarli visibili li fa leggere come fatti su quello switch.
    const kpis = document.getElementById('epKpis');
    if (kpis) kpis.innerHTML = '';
    // Gli apparati arrivano dall'INVENTARIO del tenant, non dagli endpoint
    // caricati. Costruire l'elenco da _epRows mostrava solo gli switch che
    // erano la posizione di accesso VINCENTE di almeno un endpoint: uno
    // switch visto meno di recente spariva, e soprattutto uno switch SENZA
    // endpoint non compariva mai — cioe' proprio quello con piu' porte
    // libere, che e' la domanda per cui questa vista esiste.
    // Stesso filtro di macFilteredDevices() in client-map.js.
    if (picker) {
        const cur = picker.value;
        const tenant = locTenant();
        let devs = globalDevices || [];
        if (tenant && tenant !== 'all') devs = devs.filter(d => d.Group === tenant);
        const label = d => d.Hostname || d.IP;
        picker.innerHTML = devs.slice()
            .sort((a, b) => label(a).localeCompare(label(b)))
            .map(d => `<option value="${escapeHtml(d.IP)}">${escapeHtml(label(d))} — ${escapeHtml(d.IP)}</option>`)
            .join('');
        // Un apparato senza elenco interfacce risponde comunque, dichiarando
        // 'elenco porte non disponibile': meglio di non poterlo nemmeno
        // scegliere.
        if (devs.some(d => d.IP === cur)) picker.value = cur;
    }
    endpointsPorts();
}

// `lastRead`: the response of an on-demand read just made, laid over what the
// list returns (the stored read may not be visible yet to the next query).
async function endpointsPorts(lastRead) {
    const host = document.getElementById('epResults');
    const picker = document.getElementById('epPortsSwitch');
    const L = i18n[currentLang];
    if (!host) return;
    const sw = picker ? picker.value : '';
    if (!sw) {
        host.innerHTML = `<div class="panel" style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;">${escapeHtml(L.epPortsPick)}</div>`;
        return;
    }
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
    const q = new URLSearchParams({ device: sw, window: '24h' });
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

function endpointsPortsRender(d, ifaceConfigs = {}, portErrors = {}, sw = '') {
    const host = document.getElementById('epResults');
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

    const rows = (d.ports || []).map(p => {
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
            <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml((p.macs || []).join(', ') || (p.uplink_to ? '→ ' + p.uplink_to : '—'))}</td>
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
            ${sw ? `<button type="button" class="btn btn-secondary btn-small requires-write" style="width:auto; margin:0 0 0 12px;"
                data-action="ep-err-read-switch" data-device="${escapeHtml(sw)}" data-tenant="${escapeHtml(_epDeviceOf(sw).Group || '')}">
                <i class="fa-solid fa-stethoscope"></i> ${escapeHtml(tr('ifBtnReadErrors'))}</button>` : ''}
        </div>
        <div class="panel" style="padding:0;"><div class="table-container"><table>
            <thead><tr><th>${escapeHtml(L.epThWhere)}</th><th>${escapeHtml(tr('epThPortState'))}</th><th>${escapeHtml(L.epThMac)}</th><th data-col-default-hidden="1">${escapeHtml(tr('epThErrors'))}</th><th>${escapeHtml(L.epThConfig)}</th></tr></thead>
            <tbody>${rows}</tbody>
        </table></div></div>`;
}

// Delegated click listener on #epResults
document.getElementById('epResults')?.addEventListener('click', (e) => {
    const diagBtn = e.target.closest('[data-action="ep-diagnose"]');
    if (diagBtn) {
        endpointsDiagnose(diagBtn.dataset.mac, diagBtn.dataset.tenant || '');
        return;
    }
    const locBtn = e.target.closest('[data-action="ep-locate"]');
    if (locBtn) {
        macLocate(locBtn.dataset.mac, locBtn.dataset.tenant || '');
        return;
    }
    const portBtn = e.target.closest('[data-action="ep-portcfg"]');
    if (portBtn) {
        showPortConfig(portBtn.dataset.switchIp, portBtn.dataset.switchPort, portBtn.dataset.switchName);
        return;
    }
    const errReadBtn = e.target.closest('[data-action="ep-err-read"]');
    if (errReadBtn) {
        const slot = errReadBtn.closest('td')?.querySelector('.ep-err-slot');
        if (slot) slot.textContent = tr('epErrLoading');
        _epReadErrors(errReadBtn).then(read => {
            if (!slot) return;
            const want = expandIface(errReadBtn.dataset.port).toLowerCase();
            const p = read && (read.ports || []).find(x => expandIface(x.interface).toLowerCase() === want);
            if (p) slot.innerHTML = ifaceErrorsBadge(_epReadRow(p, read));
            else _epLoadPortErrors(slot, errReadBtn.dataset.device, errReadBtn.dataset.port, errReadBtn.dataset.tenant);
        });
        return;
    }
    const switchReadBtn = e.target.closest('[data-action="ep-err-read-switch"]');
    if (switchReadBtn) {
        _epReadErrors(switchReadBtn).then(read => { if (read) endpointsPorts(read); });
        return;
    }
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
    const toggleCfgBtn = e.target.closest('[data-action="ep-toggle-cfg"]');
    if (toggleCfgBtn) {
        // The full block opens in a row of its own, full table width: inside the
        // cell it squeezed a multi-line config into a narrow column.
        const row = toggleCfgBtn.closest('tr');
        const next = row?.nextElementSibling;
        const open = toggleCfgBtn.getAttribute('aria-expanded') === 'true';
        if (next && next.classList.contains('ep-cfg-row')) next.remove();
        if (row && !open) {
            const cfgRow = document.createElement('tr');
            cfgRow.className = 'ep-cfg-row';
            cfgRow.innerHTML = `<td colspan="${row.cells.length}"><pre class="ep-cfg-full">${escapeHtml(toggleCfgBtn.dataset.raw || '')}</pre></td>`;
            row.after(cfgRow);
        }
        toggleCfgBtn.setAttribute('aria-expanded', open ? 'false' : 'true');
        return;
    }
    const row = e.target.closest('tr[data-action="ep-row-toggle"]');
    if (row && !e.target.closest('button, a, input, select')) {
        _toggleEndpointDetail(row);
    }
});

// Delegated keydown on #epResults for accessibility
document.getElementById('epResults')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
        const row = e.target.closest('tr[data-action="ep-row-toggle"]');
        if (row && e.target === row) {
            e.preventDefault();
            _toggleEndpointDetail(row);
        }
    }
});

// Static event listeners for Endpoint Inventory
document.getElementById('epModeListBtn')?.addEventListener('click', () => endpointsMode('list'));
document.getElementById('epModePortsBtn')?.addEventListener('click', () => endpointsMode('ports'));
document.getElementById('epPortsSwitch')?.addEventListener('change', () => endpointsPorts());

document.getElementById('epFilterQ')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') endpointsApplyFilters();
});
document.getElementById('epFilterStale')?.addEventListener('change', endpointsApplyFilters);
document.getElementById('epFilterStale')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') endpointsApplyFilters();
});
document.getElementById('btnEpFilter')?.addEventListener('click', endpointsApplyFilters);
document.getElementById('btnEpResetTime')?.addEventListener('click', () => {
    const f = document.getElementById('epFilterFrom');
    const t = document.getElementById('epFilterTo');
    if (f) f.value = '';
    if (t) t.value = '';
    endpointsApplyFilters();
});
document.getElementById('epFilterFrom')?.addEventListener('change', endpointsApplyFilters);
document.getElementById('epFilterTo')?.addEventListener('change', endpointsApplyFilters);
document.getElementById('btnEpExportCsv')?.addEventListener('click', () => endpointsExport('csv'));
document.getElementById('btnEpExportJson')?.addEventListener('click', () => endpointsExport('json'));

// ===== Sub-tab "Port errors": every device's ports, from /api/interface-errors =====
// Same data and verdicts as the Interfaces tab and the occupancy column; this
// view only answers "which ports, across the tenant, are erroring now".

async function loadPortErrorsPane() {
    const host = document.getElementById('peResults');
    const picker = /** @type {HTMLSelectElement|null} */ (document.getElementById('peDevice'));
    if (!host) return;
    const tenant = locTenant();
    if (picker) {
        const cur = picker.value;
        let devs = globalDevices || [];
        if (tenant && tenant !== 'all') devs = devs.filter(d => d.Group === tenant);
        const label = d => d.Hostname || d.IP;
        picker.innerHTML = `<option value="">${escapeHtml(tr('peDeviceAll'))}</option>` + devs.slice()
            .sort((a, b) => label(a).localeCompare(label(b)))
            .map(d => `<option value="${escapeHtml(d.IP)}">${escapeHtml(label(d))} — ${escapeHtml(d.IP)}</option>`)
            .join('');
        if (devs.some(d => d.IP === cur)) picker.value = cur;
    }
    const device = picker ? picker.value : '';
    const windowVal = /** @type {HTMLSelectElement|null} */ (document.getElementById('peWindow'))?.value || '24h';
    const show = /** @type {HTMLSelectElement|null} */ (document.getElementById('peShow'))?.value || 'bad';

    host.innerHTML = `<div class="panel" style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
        <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>${escapeHtml(tr('epiLoading'))}</div>`;
    const q = new URLSearchParams({ window: windowVal });
    if (device) {
        q.set('device', device);
        const dev = _epDeviceOf(device);
        if (dev.Group) q.set('tenant', dev.Group);
    }
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
    const rows = show === 'all' ? all : all.filter(p => p.status === 'erroring' || p.status === 'discards');
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

document.getElementById('peDevice')?.addEventListener('change', () => loadPortErrorsPane());
document.getElementById('peWindow')?.addEventListener('change', () => loadPortErrorsPane());
document.getElementById('peShow')?.addEventListener('change', () => loadPortErrorsPane());
document.getElementById('peRefresh')?.addEventListener('click', () => loadPortErrorsPane());
document.getElementById('peResults')?.addEventListener('click', (e) => {
    const b = /** @type {HTMLElement|null} */ (/** @type {HTMLElement} */ (e.target).closest('[data-action="pe-portcfg"]'));
    if (b) showPortConfig(b.dataset.ip, b.dataset.port, b.dataset.name);
});
document.getElementById('peReadNow')?.addEventListener('click', async (e) => {
    const btn = /** @type {HTMLButtonElement} */ (e.currentTarget);
    const device = /** @type {HTMLSelectElement|null} */ (document.getElementById('peDevice'))?.value || '';
    if (!device) { showToast(tr('ifErrPickDevice'), 'warning'); return; }
    btn.dataset.device = device;
    btn.dataset.tenant = _epDeviceOf(device).Group || '';
    const read = await _epReadErrors(btn);
    if (read) {
        showToast(tr('ifErrReadDone', { device, src: String(read.source || '').toUpperCase(), s: String(read.interval_s) }), 'success');
        loadPortErrorsPane();
    }
});
