// Inventario endpoint: elenco dei client scoperti, filtrabile ed esportabile.
// Ogni valore che arriva dagli apparati passa da escapeHtml(jsStr(x)).
//
// La vista e' DERIVATA: nessuna annotazione salvata, nessuno stato da tenere
// allineato a una rete che cambia da sola. Quello che si vede e' quello che
// le scansioni hanno raccolto, con l'eta' del dato sempre a schermo.

let _epRows = [];          // righe a schermo: sono queste che l'export porta via
let _epTruncated = false;

function loadEndpointsTab() {
    endpointsSearch();
}

async function endpointsSearch() {
    const host = document.getElementById('epResults');
    if (!host) return;
    const en = currentLang === 'en';
    const L = i18n[currentLang];

    const q = ((document.getElementById('epFilterQ') || {}).value || '').trim();
    const tenant = (document.getElementById('epFilterTenant') || {}).value || '';
    const staleDays = parseInt((document.getElementById('epFilterStale') || {}).value, 10) || 7;

    host.innerHTML = `<div class="panel" style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
        <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>${escapeHtml(en ? 'Loading…' : 'Caricamento…')}</div>`;

    const params = new URLSearchParams({ stale_days: String(staleDays) });
    if (q) params.set('q', q);
    if (tenant && tenant !== 'all') params.set('tenant', tenant);

    const res = await apiFetch('/api/endpoints/list?' + params.toString());
    if (!res || !res.ok) {
        host.innerHTML = `<div class="panel" style="padding:22px; text-align:center; color:var(--danger); font-size:13px;">${escapeHtml(en ? 'Could not load the inventory.' : 'Inventario non caricabile.')}</div>`;
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
        const tile = (label, value, color) => `<div class="panel" style="padding:12px 14px;">
            <div style="font-size:22px; font-weight:800; color:${color || 'var(--text)'};">${escapeHtml(String(value ?? 0))}</div>
            <div style="font-size:11px; color:var(--text-muted); text-transform:uppercase; font-weight:700;">${escapeHtml(label)}</div>
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
    if (!_epRows.length) {
        host.innerHTML = `<div class="panel" style="padding:28px; text-align:center; color:var(--text-muted); font-size:13px;">
            <i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml(L.epEmpty)}</div>`;
        return;
    }

    const banner = _epTruncated
        ? `<div style="padding:10px 12px; margin-bottom:10px; border-radius:8px; background:rgba(255,184,77,0.12); border:1px solid rgba(255,184,77,0.35); color:var(--warning); font-size:12px;">
            <i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(
                L.epTruncated.replace('{shown}', String(_epRows.length)).replace('{total}', String(d.total)))}</div>`
        : '';

    const body = _epRows.map(r => `<tr style="cursor:pointer;" onclick="endpointsDiagnose('${escapeHtml(jsStr(r.mac))}','${escapeHtml(jsStr(r.tenant || ''))}')">
        <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(jsStr(r.mac))}</td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.oui_vendor || '—'))}</td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.tenant || '—'))} <span style="color:var(--text-muted);">/ ${escapeHtml(jsStr(r.site || '—'))}</span></td>
        <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml(jsStr((r.ips || []).join(', ') || '—'))}</td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.switch_name || r.switch_ip || '—'))} <span style="color:var(--text-muted);">${escapeHtml(jsStr(r.interface || ''))}</span></td>
        <td style="font-size:12px;">${escapeHtml(jsStr(r.vlan || '—'))}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(jsStr(_epTime(r.first_seen)))}</td>
        <td style="font-size:11px; color:var(--text-muted);">${escapeHtml(jsStr(_epTime(r.last_seen)))}</td>
        <td>${(r.flags || []).map(_epFlag).join(' ')}</td>
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
    return `<span style="font-size:10px; color:${color}; border:1px solid ${color}; border-radius:4px; padding:0 4px; white-space:nowrap;">${escapeHtml(jsStr(f))}</span>`;
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
        const cell = v => {
            const s = Array.isArray(v) ? v.join(' ') : (v === null || v === undefined ? '' : String(v));
            return /[",;\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
        };
        const lines = [_EP_COLS.join(',')];
        _epRows.forEach(r => lines.push(_EP_COLS.map(k => cell(r[k])).join(',')));
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
    switchTab('tab-diagnosi');
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
    // Gli switch li conosce gia' l'elenco caricato: nessuna chiamata in piu'.
    if (picker) {
        const seen = {};
        _epRows.forEach(r => { if (r.switch_ip) seen[r.switch_ip] = r.switch_name || r.switch_ip; });
        picker.innerHTML = Object.keys(seen).sort().map(ip =>
            `<option value="${escapeHtml(jsStr(ip))}">${escapeHtml(jsStr(seen[ip]))} — ${escapeHtml(jsStr(ip))}</option>`).join('');
    }
    endpointsPorts();
}

async function endpointsPorts() {
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
    if (!res || !res.ok) return;
    endpointsPortsRender(await res.json());
}

function endpointsPortsRender(d) {
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

    const rows = (d.ports || []).map(p => `<tr>
        <td style="font-family:var(--font-code); font-size:12px;">${escapeHtml(jsStr(p.interface))}${
            p.physical ? '' : ' <span style="font-size:10px; color:var(--text-muted); border:1px solid var(--border); border-radius:4px; padding:0 4px;">virt</span>'}</td>
        <td><span style="font-size:10px; color:${stateColor[p.state]}; border:1px solid ${stateColor[p.state]}; border-radius:4px; padding:1px 5px;">${escapeHtml(jsStr(stateLabel[p.state] || p.state))}</span></td>
        <td style="font-family:var(--font-code); font-size:11px;">${escapeHtml(jsStr((p.macs || []).join(', ') || (p.uplink_to ? '→ ' + p.uplink_to : '—')))}</td>
    </tr>`).join('');

    host.innerHTML = `
        <div style="padding:10px 12px; margin-bottom:10px; border-radius:8px; background:rgba(255,184,77,0.12); border:1px solid rgba(255,184,77,0.35); color:var(--warning); font-size:12px;">
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
            <thead><tr><th>${escapeHtml(L.epThWhere)}</th><th></th><th>${escapeHtml(L.epThMac)}</th></tr></thead>
            <tbody>${rows}</tbody>
        </table></div></div>`;
}
