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
