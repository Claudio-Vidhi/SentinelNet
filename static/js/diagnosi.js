// static/js/diagnosi.js
// Referto di diagnosi client (L2+L3). Viveva in una modale di client-map.js:
// spostato qui perche' la tab ha lo spazio per cronologia e catena trunk, e
// perche' due copie dello stesso referto sarebbero due copie da tenere
// allineate. Il pulsante della Client Map porta qui, non apre piu' nulla.
//
// Ogni valore che arriva dagli apparati passa da escapeHtml(x). jsStr in piu'
// serve SOLO dentro una stringa JS — qui l'unico caso e' l'onclick di
// diagnosiPickTenant, dove escapeHtml produce &#39; che il parser HTML
// ritrasforma in ' prima che JS legga la stringa. In testo HTML jsStr
// aggiungeva soltanto backslash visibili, e si leggevano proprio nei messaggi
// di rifiuto delle azioni sulla porta.

let _diagClient = null;    // client a schermo, per il "rilancia"
let _diagMac = '';         // MAC risolto: il bounce e il WLC lavorano per MAC
let _diagSwitch = null;    // {ip, port} della porta di accesso trovata
let _diagTenant = null;    // tenant scelto quando l'indirizzo esiste in piu' sedi

function diagnosiTabShown() {
    const el = document.getElementById('diagClientInput');
    if (el) el.focus();
    loadDiagGatewayCandidates(_diagTenant);
}

async function loadDiagGatewayCandidates(tenant) {
    const sel = document.getElementById('diagGatewaySelect');
    if (!sel) return;
    try {
        const url = tenant ? `/api/diagnose/gateway-candidates?tenant=${encodeURIComponent(tenant)}` : '/api/diagnose/gateway-candidates';
        const res = await apiFetch(url);
        if (res && res.ok) {
            const list = await res.json();
            const options = list.map(g => `<option value="${escapeHtml(g.ip)}">${escapeHtml(g.name || g.ip)} (${escapeHtml(g.ip)})</option>`).join('');
            sel.innerHTML = `<option value="">Auto (ARP / Subnet)</option>` + options;
        }
    } catch (e) {
        console.error('Error loading gateway candidates:', e);
    }
}

function onDiagGatewaySelectChange() {
    const sel = document.getElementById('diagGatewaySelect');
    const input = document.getElementById('diagGatewayInput');
    if (sel && input && sel.value) {
        input.value = sel.value;
    }
}

async function detectGatewayTracerouteUI() {
    const en = currentLang === 'en';
    const target = ((document.getElementById('diagClientInput') || {}).value || (document.getElementById('diagDestInput') || {}).value || '').trim();
    if (!target) {
        alert(en ? 'Enter a Client or Destination IP first.' : 'Inserisci prima un IP Client o Destinazione.');
        return;
    }
    const input = document.getElementById('diagGatewayInput');
    if (input) input.placeholder = en ? 'Detecting via traceroute…' : 'Rilevamento via traceroute…';
    try {
        const res = await apiFetch('/api/diagnose/traceroute-gateway', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target })
        });
        if (res && res.ok) {
            const data = await res.json();
            if (data.known && data.gateway_ip) {
                if (input) input.value = data.gateway_ip;
                alert(en ? `Gateway detected via traceroute: ${data.gateway_ip}` : `Gateway rilevato via traceroute: ${data.gateway_ip}`);
            } else {
                alert(data.reason || (en ? 'No gateway hop detected.' : 'Nessun gateway rilevato.'));
            }
        }
    } catch (e) {
        console.error('Traceroute gateway error:', e);
    } finally {
        if (input && !input.value) input.placeholder = 'Es. 192.168.1.1';
    }
}

// Ingresso dalla Client Map (e da chiunque altro): riempie e lancia.
function diagnoseClientInTab(client, dest) {
    _diagTenant = null;
    switchTab('tab-endpoint');
    locSwitchView('diagnosi');
    const c = document.getElementById('diagClientInput');
    const d = document.getElementById('diagDestInput');
    if (c) c.value = client || '';
    if (d && dest !== undefined) d.value = dest || '';
    loadDiagGatewayCandidates();
    runDiagnosi();
}

async function runDiagnosi() {
    const en = currentLang === 'en';
    const host = document.getElementById('diagResult');
    const client = (document.getElementById('diagClientInput') || {}).value || '';
    if (!host) return;
    if (!client.trim()) {
        host.innerHTML = _diagEmpty(en ? 'Enter an IP or MAC.' : 'Inserisci un IP o un MAC.');
        return;
    }
    if (_diagClient !== client.trim()) _diagTenant = null;
    _diagClient = client.trim();
    const dest = ((document.getElementById('diagDestInput') || {}).value || '').trim();
    const gwInput = ((document.getElementById('diagGatewayInput') || {}).value || '').trim();
    const gwSelect = ((document.getElementById('diagGatewaySelect') || {}).value || '').trim();
    const gatewayIp = gwInput || gwSelect || null;

    host.innerHTML = `<div class="panel" style="padding:26px; text-align:center; color:var(--text-muted); font-size:13px;">
        <i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>
        ${escapeHtml(en ? 'Querying switch and firewall — re-scanning if the data is stale…'
                        : 'Interrogazione di switch e firewall — riscansione se il dato e\' vecchio…')}
    </div>`;

    const body = { client: _diagClient };
    if (_diagTenant) body.tenant = _diagTenant;
    if (gatewayIp) body.gateway_ip = gatewayIp;
    if (dest) {
        body.dest = dest;
        body.protocol = (document.getElementById('diagProtoInput') || {}).value || 'TCP';
        body.dest_port = parseInt((document.getElementById('diagPortInput') || {}).value) || 443;
    }
    const res = await apiFetch('/api/diagnose/client', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (!res || !res.ok) {
        const e = res ? await res.json().catch(() => ({})) : {};
        host.innerHTML = _diagEmpty(escapeHtml(e.detail || (en ? 'Diagnosis failed.' : 'Diagnosi fallita.')), true);
        return;
    }
    renderDiagnosi(await res.json(), dest);
}

function _diagEmpty(msg, danger) {
    return `<div class="panel" style="padding:22px; text-align:center; font-size:13px;
        color:${danger ? 'var(--danger)' : 'var(--text-muted)'};">${msg}</div>`;
}

// Una scheda: pallino di stato, titolo, corpo. Se la sezione non e' nota il
// corpo e' il MOTIVO — che e' l'informazione utile, non un ripiego.
function _diagCard(icon, title, section, bodyFn, extra) {
    const en = currentLang === 'en';
    const known = section && section.known;
    const err = section && section.error;
    const color = err ? 'var(--danger)' : (known ? 'var(--success)' : 'var(--warning)');
    let body;
    if (err) {
        body = `<div style="color:var(--danger); font-size:12px;">${escapeHtml(err)}</div>`;
    } else if (!known) {
        body = `<div style="color:var(--text-muted); font-size:12px;"><i class="fa-solid fa-circle-info" style="margin-right:6px;"></i>${escapeHtml((section && section.reason) || (en ? 'not known' : 'non noto'))}</div>`;
    } else {
        body = bodyFn(section);
    }
    return `<div class="panel" style="padding:14px 16px; margin-bottom:12px;">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:10px; font-size:13px; font-weight:600;">
            <span style="width:8px; height:8px; border-radius:50%; background:${color}; flex:none;"></span>
            <i class="fa-solid ${icon}" style="color:var(--text-muted);"></i> ${escapeHtml(title)}
        </div>${body}${extra || ''}</div>`;
}

const _kv = (k, v) => `<div style="display:flex; gap:8px; font-size:12px; padding:2px 0; flex-wrap:wrap;">
    <span style="color:var(--text-muted); min-width:150px;">${escapeHtml(k)}</span>
    <span style="font-family:var(--font-code);">${escapeHtml(v === null || v === undefined || v === '' ? '—' : String(v))}</span></div>`;

function _diagAge(s) {
    if (s === null || s === undefined) return '—';
    const n = Math.round(s);
    if (n < 90) return `${n}s`;
    if (n < 5400) return `${Math.round(n / 60)}min`;
    if (n < 172800) return `${Math.round(n / 3600)}h`;
    return `${Math.round(n / 86400)}g`;
}

// La freschezza non e' decorazione: dice se il referto descrive la rete di
// adesso o quella dell'ultima scansione a mano.
function _diagFreshness(f) {
    if (!f) return '';
    const en = currentLang === 'en';
    const bad = f.stale || f.error;
    const icon = f.refreshed ? 'fa-rotate' : (bad ? 'fa-triangle-exclamation' : 'fa-circle-check');
    const color = bad ? 'var(--warning)' : 'var(--text-muted)';
    const ages = f.ages || {};
    return `<div style="display:flex; align-items:center; gap:8px; font-size:11px; color:${color}; margin-bottom:12px;">
        <i class="fa-solid ${icon}"></i>
        <span>${escapeHtml(f.reason || '')}</span>
        <span style="font-family:var(--font-code);">
            ${escapeHtml(en ? 'binding' : 'binding')} ${escapeHtml(_diagAge(ages.binding_s))} ·
            ${escapeHtml(en ? 'port' : 'porta')} ${escapeHtml(_diagAge(ages.port_s))}
        </span>
        ${(f.scanned || []).length ? `<span>${escapeHtml((en ? 're-scanned: ' : 'riscansionati: ') + f.scanned.join(', '))}</span>` : ''}
    </div>`;
}

function renderDiagnosi(d, dest) {
    const en = currentLang === 'en';
    const s = d.sections || {};
    const host = document.getElementById('diagResult');
    if (!host) return;

    // L'indirizzo esiste in piu' sedi e nessuna e' stata scelta: non c'e'
    // nessun referto da mostrare. Mostrarne uno "provvisorio" sarebbe la
    // stessa scelta silenziosa con un'etichetta sopra.
    if (d.status === 'ambiguous') {
        host.innerHTML = _diagTenantChoice(d);
        return;
    }

    const pos = s.position || {};
    _diagMac = pos.mac || (/^[0-9a-fA-F:.-]{12,17}$/.test(_diagClient || '') ? _diagClient : '');
    _diagSwitch = (pos.switch_ip && pos.switch_port)
        ? { ip: pos.switch_ip, port: pos.switch_port } : null;

    const badge = d.complete
        ? `<span class="badge" style="color:var(--success);">${escapeHtml(en ? 'complete' : 'completo')}</span>`
        : `<span class="badge" style="color:var(--warning);" title="${escapeHtml(en ? 'Some sections could not be answered — see below' : 'Alcune sezioni non hanno risposta — vedi sotto')}">${escapeHtml(en ? 'partial' : 'parziale')}</span>`;

    const position = _diagCard('fa-location-dot', en ? 'Position' : 'Posizione', s.position, p =>
        _kv('MAC', p.mac) + _kv('IP', p.ip) +
        _kv(en ? 'Tenant / site' : 'Tenant / sede', `${p.tenant || '—'} / ${p.site || '—'}`) +
        _kv(en ? 'Access switch' : 'Switch di accesso', `${p.switch_name || ''} ${p.switch_ip || ''}`.trim()) +
        _kv(en ? 'Port / VLAN' : 'Porta / VLAN', `${p.switch_port || '—'} / ${p.port_vlan || '—'}`) +
        _kv('Gateway', `${p.gateway_name || ''} ${p.gateway_ip || ''} (${p.gateway_type || '—'})`.trim()) +
        (p.port_known === false ? `<div style="color:var(--warning); font-size:12px; margin-top:6px;">${escapeHtml(p.port_reason || '')}</div>` : '') +
        // Senza ARP la posizione fisica c'e' lo stesso: va detto cosa manca e
        // perche' le sezioni del firewall non risponderanno, altrimenti si
        // legge come un guasto invece che come un limite di visibilita'.
        (p.l2_only ? `<div style="color:var(--warning); font-size:12px; margin-top:6px;">
            <i class="fa-solid fa-layer-group" style="margin-right:6px;"></i>
            <b>${escapeHtml(en ? 'L2 only' : 'Solo L2')}</b> — ${escapeHtml(p.binding_reason || '')}</div>` : '') +
        (p.ambiguous ? `<div style="color:var(--warning); font-size:12px; margin-top:6px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(en ? 'Other bindings for this address' : 'Altri binding per questo indirizzo')}: ${p.ambiguous.map(a => escapeHtml(a.mac)).join(', ')}</div>` : '')
    );

    const l2 = _diagCard('fa-ethernet', en ? 'L2 link health' : 'Salute del collegamento L2', s.l2_health, h => {
        const i = h.interface || {};
        let out = '';
        if (i.known) {
            const d1 = i.error_delta || {};
            out += _kv('Link', `${i.link || '—'} (admin ${i.admin_status || '—'})`);
            out += _kv(en ? 'Errors in/out' : 'Errori in/out',
                i.error_delta === null
                    ? (en ? 'single sample: cannot tell' : 'un solo campione: non si puo\' dire')
                    : `${d1.in_errors === null ? '?' : d1.in_errors} / ${d1.out_errors === null ? '?' : d1.out_errors}` +
                      (i.error_window_s ? ` (${i.error_window_s}s)` : ''));
            if (i.erroring) out += `<div style="color:var(--danger); font-size:12px; margin-top:6px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(en ? 'Error counters are rising: suspect cabling, transceiver or duplex mismatch.' : 'I contatori di errore stanno salendo: sospetta cablaggio, transceiver o duplex mismatch.')}</div>`;
        } else {
            out += `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(i.reason || i.error || '')}</div>`;
        }
        if (h.vlan_mismatch) out += `<div style="color:var(--warning); font-size:12px; margin-top:6px;">
            <i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(en ? 'Port moved VLAN' : 'Porta spostata di VLAN')}:
            ${escapeHtml(h.vlan_mismatch.mac_table)} → <b>${escapeHtml(h.vlan_mismatch.live)}</b>.
            ${escapeHtml(h.vlan_mismatch.note)}</div>`;
        return out + _diagTrunk(h.trunk || {});
    }, _diagBounceControl());

    const history = _diagCard('fa-clock-rotate-left', en ? 'History' : 'Cronologia', s.history, hs => {
        if (hs.empty) return `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(en ? 'Never seen before this scan.' : 'Mai visto prima di questa scansione.')}</div>`;
        const pos = (hs.positions || []).map(p => `<div style="font-size:12px; padding:3px 0; display:flex; gap:10px; flex-wrap:wrap;">
            <span style="font-family:var(--font-code);">${escapeHtml(p.switch_name || p.switch_ip)} ${escapeHtml(p.interface)}</span>
            <span style="color:var(--text-muted);">VLAN ${escapeHtml(p.vlan || '—')}</span>
            <span style="color:var(--text-muted);">${escapeHtml(p.first_seen)} → ${escapeHtml(p.last_seen)}</span>
            <span class="badge" style="font-size:10px;">×${escapeHtml(p.seen_count)}</span></div>`).join('');
        const ips = (hs.addresses || []).map(a => `<div style="font-size:12px; padding:3px 0; display:flex; gap:10px; flex-wrap:wrap;">
            <span style="font-family:var(--font-code);">${escapeHtml(a.ip)}</span>
            <span style="color:var(--text-muted);">via ${escapeHtml(a.source_name || a.source_ip)}</span>
            <span style="color:var(--text-muted);">${escapeHtml(a.first_seen)} → ${escapeHtml(a.last_seen)}</span>
            <span class="badge" style="font-size:10px;">×${escapeHtml(a.seen_count)}</span></div>`).join('');
        return `<div style="font-size:12px; font-weight:600; margin-bottom:4px;">${escapeHtml(en ? 'Positions' : 'Posizioni')}</div>${pos || '—'}
            <div style="font-size:12px; font-weight:600; margin:10px 0 4px;">${escapeHtml(en ? 'Addresses' : 'Indirizzi')}</div>${ips || '—'}
            <div style="color:var(--text-muted); font-size:11px; margin-top:8px;">${escapeHtml(en ? 'Retention' : 'Retention')}: ${escapeHtml(hs.retention_days)} ${escapeHtml(en ? 'days' : 'giorni')}. ${escapeHtml(en ? 'Rows aggregate: repeated moves between the same two ports are not counted separately.' : 'Le righe aggregano: i rimbalzi fra le stesse due porte non si contano singolarmente.')}</div>`;
    });

    const path = _diagCard('fa-route', en ? 'Traffic path' : 'Percorso del traffico', s.path, p =>
        (p.hops || []).map(h => `<div style="font-size:12px; padding:3px 0; ${h.known ? '' : 'color:var(--warning);'}">
            <i class="fa-solid ${h.known ? 'fa-circle-check' : 'fa-circle-question'}" style="margin-right:8px;"></i>${escapeHtml(h.label || h.kind)}</div>`).join('')
    );

    const relay = s.firewall && s.firewall.policy_lookup;
    const relayNote = relay ? `<div style="margin-top:8px; padding-top:8px; border-top:1px solid var(--border);">
        ${relay.known
            ? `<div style="font-size:12px; font-weight:600; margin-bottom:4px;">${escapeHtml(en ? 'Matching policy (via relay)' : 'Policy che matcherebbe (via relay)')}</div>
               <pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:0; padding:10px; margin:0; white-space:pre-wrap; font-size:11px; max-height:180px; overflow:auto;">${escapeHtml(JSON.stringify(relay.data, null, 2))}</pre>`
            : `<div style="color:${relay.pending ? 'var(--warning)' : 'var(--text-muted)'}; font-size:12px;">
                 <i class="fa-solid ${relay.pending ? 'fa-hourglass-half' : 'fa-circle-info'}" style="margin-right:6px;"></i>${escapeHtml(relay.reason || '')}</div>`}
    </div>` : '';

    const fw = _diagCard('fa-shield-halved', 'Firewall', s.firewall, f => {
        let out = _kv('FortiGate', f.fortigate) + _kv(en ? 'Chosen by' : 'Scelto per', f.resolved_by);
        const sub = f.sections || {};
        const pl = sub.policy_lookup;
        if (pl && pl.data) {
            out += `<div style="margin-top:8px; padding-top:8px; border-top:1px solid var(--border); font-size:12px; font-weight:600;">${escapeHtml(en ? 'Matching policy' : 'Policy che matcherebbe')}</div>`;
            out += `<pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:0; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:180px; overflow:auto;">${escapeHtml(JSON.stringify(pl.data, null, 2))}</pre>`;
        }
        const failed = Object.keys(sub).filter(k => sub[k] && sub[k].error);
        if (failed.length) out += `<div style="color:var(--text-muted); font-size:11px; margin-top:8px;">${escapeHtml(en ? 'Sections unavailable' : 'Sezioni non disponibili')}: ${escapeHtml(failed.join(', '))}</div>`;
        out += `<details style="margin-top:8px;"><summary style="cursor:pointer; font-size:11px; color:var(--text-muted);">${escapeHtml(en ? 'Raw FortiGate output' : 'Output grezzo del FortiGate')}</summary>
            <pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:0; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:260px; overflow:auto;">${escapeHtml(JSON.stringify(sub, null, 2))}</pre></details>`;
        return out;
    }, relayNote);

    const across = !s.across_sites ? '' : _diagCard('fa-tower-broadcast',
        en ? 'Across sites' : 'Fra sedi', s.across_sites, a => {
        if (a.same_site === null) return `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(a.note || '')}</div>`;
        let out = _kv(en ? 'Source site' : 'Sede sorgente', a.source.site) +
                  _kv(en ? 'Destination site' : 'Sede destinazione', `${a.destination.site || '—'}`);
        if (a.same_site) return out + `<div style="color:var(--text-muted); font-size:12px; margin-top:6px;">${escapeHtml(a.note || '')}</div>`;
        const fe = a.far_end_policy || {};
        out += `<div style="margin-top:8px; font-size:12px; font-weight:600;">${escapeHtml(en ? 'Far-end firewall policy' : 'Policy del firewall remoto')}</div>`;
        out += fe.data
            ? `<pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:0; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:160px; overflow:auto;">${escapeHtml(JSON.stringify(fe.data, null, 2))}</pre>`
            : `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(fe.reason || fe.error || '')}</div>`;
        if (a.route) {
            const rd = a.route.data || {};
            out += _kv(en ? 'Route to destination' : 'Rotta verso la destinazione',
                a.route.error ? a.route.error
                    : (rd.matched ? `${rd.destination} → ${rd.gateway || '—'} (${rd.interface || '—'})`
                                  : (en ? 'NO ROUTE' : 'NESSUNA ROTTA')));
            if (rd.matched === false) out += `<div style="color:var(--danger); font-size:12px; margin-top:6px;"><i class="fa-solid fa-triangle-exclamation" style="margin-right:6px;"></i>${escapeHtml(en ? 'The firewall has no route to that address: a permitted policy would not help.' : 'Il firewall non ha una rotta verso questo indirizzo: una policy che permette non basterebbe.')}</div>`;
        }
        return out;
    });

    const denies = _diagCard('fa-ban', en ? 'Blocks (last hour)' : 'Blocchi (ultima ora)', s.denies, b => {
        let out = _kv(en ? 'Total' : 'Totale', b.total);
        if (b.total && b.by_policy.length) {
            out += `<div style="margin-top:8px; font-size:12px;">` + b.by_policy.map(p =>
                `<div style="padding:2px 0;"><span class="badge" style="font-size:10px;">policy ${escapeHtml(p.policy_id)}</span>
                 <span style="color:var(--text-muted);">${escapeHtml(p.subtype)}</span> — ${escapeHtml(p.count)}</div>`).join('') + `</div>`;
        }
        if (b.truncated) out += `<div style="color:var(--warning); font-size:11px; margin-top:6px;">${escapeHtml(en ? 'Scan capped: this is a minimum, not a total.' : 'Scansione troncata: e\' un minimo, non un totale.')}</div>`;
        return out;
    });

    host.innerHTML = `
        <div class="panel" style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:12px; padding:12px 16px;">
            <span style="font-family:var(--font-code); font-size:14px; color:var(--primary);">${escapeHtml(d.client)}</span>
            ${badge}
            <div style="flex:1; min-width:20px;"></div>
            <button data-action="rerun-diagnosi" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-rotate"></i> ${escapeHtml(en ? 'Re-run' : 'Rilancia')}</button>
        </div>
        ${_diagFreshness(d.freshness)}
        <div class="diag-cards">${position}${l2}${history}${path}${fw}${across}${denies}${_diagWifiCard()}</div>`;
}

// Lo stesso indirizzo puo' esistere in piu' tenant: 192.0.2.50 sta in ogni
// sede del mondo. Sceglierne uno in silenzio significa diagnosticare la rete
// sbagliata senza dirlo, quindi si elencano e si ASPETTA. Il tenant scelto
// RESTRINGE lo scoping lato server, non lo allarga.
function _diagTenantChoice(d) {
    const list = d.tenants_available || [];
    if (list.length < 2) return '';
    const en = currentLang === 'en';
    // Ordinati dal piu' recente, con la data: e' il dato su cui si decide —
    // un portatile e' dove e' stato visto per ULTIMO. Ma nessuno e'
    // preselezionato: la scelta e' di chi legge.
    const chips = list.map(t => {
        const where = [t.switch_name, t.switch_port].filter(Boolean).join(' ');
        return `<button data-action="diagnosi-pick-tenant" data-tenant="${escapeHtml(t.tenant)}"
            class="btn btn-secondary btn-small" style="width:auto; margin:0; text-align:left;"
            title="${escapeHtml(`${t.ip || ''} ${where}`.trim())}">
            <i class="fa-solid fa-sitemap" style="margin-right:6px;"></i>${escapeHtml(t.tenant)}
            <span style="color:var(--text-muted); font-weight:400;">
                ${escapeHtml(t.ip || (en ? 'no IP' : 'senza IP'))}${where ? ' · ' + escapeHtml(where) : ''}
                · ${escapeHtml(String(t.last_seen || '').replace('T', ' ').slice(0, 16))}
            </span>
        </button>`;
    }).join('');
    return `<div class="panel" style="padding:22px;">
        <div style="display:flex; gap:10px; align-items:flex-start; margin-bottom:14px;">
            <i class="fa-solid fa-triangle-exclamation" style="color:var(--warning); margin-top:2px;"></i>
            <div>
                <div style="font-size:14px; font-weight:700; margin-bottom:4px;">${escapeHtml(
                    en ? 'This address exists in more than one tenant'
                       : 'Questo indirizzo esiste in più tenant')}</div>
                <div style="font-size:12px; color:var(--text-muted);">${escapeHtml(
                    en ? 'No report was produced: each site is its own network, and diagnosing the wrong one would be wrong in silence. Pick the site.'
                       : 'Nessun referto è stato prodotto: ogni sede è una rete a sé, e diagnosticare quella sbagliata lo sarebbe in silenzio. Scegli la sede.')}</div>
            </div>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">${chips}</div>
    </div>`;
}

function diagnosiPickTenant(tenant) {
    _diagTenant = tenant;
    runDiagnosi();
}

// Catena trunk: un salto per riga. Un salto senza backup e' 'unknown', non un
// salto promosso — chi legge sta per andare a toccare la rete.
function _diagTrunk(t) {
    const en = currentLang === 'en';
    let out = `<div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border); font-size:12px; font-weight:600;">
        ${escapeHtml(en ? 'VLAN along the trunk chain' : 'VLAN lungo la catena di trunk')}</div>`;
    if (!t.known) {
        return out + `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(t.reason || t.error || '')}</div>`;
    }
    // Provenienza del gateway dedotto: letta anche a catena riuscita, non
    // solo nel ramo degradato sotto — e' il caso di successo per cui la
    // deduzione esiste. Legge solo campi presenti in entrambe le forme.
    if (t.gateway_source && t.gateway_source !== 'arp') {
        const age = t.gateway_backup_age_s
            ? ` — ${en ? 'backup' : 'backup di'} ${Math.floor(t.gateway_backup_age_s / 86400)}g`
            : '';
        const how = t.gateway_source === 'manual'
            ? (en ? 'declared by an operator' : 'dichiarato da un operatore')
            : (en ? 'derived from the configuration' : 'dedotto dalla configurazione');
        out += `<div style="font-size:12px; color:var(--text-muted); margin-top:6px;">
            <i class="fa-solid fa-route" style="margin-right:6px;"></i>${escapeHtml(en ? 'VLAN gateway' : 'Gateway della VLAN')}:
            ${escapeHtml(t.gateway_device || '')}${t.gateway_vlan_ip ? ' (' + escapeHtml(t.gateway_vlan_ip) + ')' : ''} — ${how}${age}</div>`;
    }
    if (!t.chain_known) {
        out += `<div style="font-size:12px;">${t.ok
            ? escapeHtml(en ? 'allowed on this switch' : 'ammessa su questo switch')
            : `<span style="color:var(--danger);">${escapeHtml(en ? 'MISSING on this switch' : 'MANCANTE su questo switch')}</span>`}</div>
            <div style="color:var(--text-muted); font-size:11px; margin-top:4px;">${escapeHtml(t.scope || '')}</div>`;
        // Ignoto non e' assente: se la deduzione del gateway e' fallita per
        // apparati non letti, quella e' la ragione da mostrare — non lo
        // scope generico sopra, che qui direbbe "nessun gateway noto" anche
        // quando la risposta e' solo ignota.
        if (t.route_owner_reason) {
            out += `<div style="color:var(--text-muted); font-size:11px; margin-top:4px;">${escapeHtml(t.route_owner_reason)}</div>`;
        }
        if (t.unreadable_devices && t.unreadable_devices.length) {
            out += `<div style="color:var(--warning); font-size:11px; margin-top:4px;">${escapeHtml(en
                ? 'some devices could not be read: ' : 'alcuni apparati non sono stati letti: ')}${
                t.unreadable_devices.map(d => escapeHtml(d)).join(', ')}</div>`;
        }
        return out;
    }
    const icons = { carrying: ['fa-circle-check', 'var(--success)'],
                    missing: ['fa-circle-xmark', 'var(--danger)'],
                    unknown: ['fa-circle-question', 'var(--warning)'] };
    out += (t.hops || []).map(h => {
        const [ic, col] = icons[h.verdict] || icons.unknown;
        return `<div style="font-size:12px; padding:3px 0; display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
            <i class="fa-solid ${ic}" style="color:${col};"></i>
            <span style="font-family:var(--font-code);">${escapeHtml(h.device)}</span>
            <span style="color:var(--text-muted);">${escapeHtml(h.egress || '—')}</span>
            <span style="color:var(--text-muted);">${escapeHtml(h.allowed || h.reason || '')}</span></div>`;
    }).join('');
    if (t.reason) out += `<div style="color:var(--danger); font-size:12px; margin-top:6px;">${escapeHtml(t.reason)}</div>`;
    return out;
}

// --- Wireless (Cisco WLC) --------------------------------------------------
// Sta a parte e si lancia a mano perche' richiede un dato che la diagnosi L2/L3
// non ha: QUALE controller interrogare. Non si indovina dall'inventario, il
// router accetta anche vendor 'cisco' generico e un elenco filtrato per vendor
// proporrebbe ogni switch Cisco come se fosse un WLC. Su richiesta anche
// perche' una sessione SSH al controller non la deve pagare un client su cavo.
function _diagWifiCard() {
    const en = currentLang === 'en';
    return `<div class="panel" style="padding:14px 16px; margin-bottom:12px;">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:10px; font-size:13px; font-weight:600; flex-wrap:wrap;">
            <span style="width:8px; height:8px; border-radius:50%; background:var(--text-muted); flex:none;"></span>
            <i class="fa-solid fa-wifi" style="color:var(--text-muted);"></i> ${escapeHtml(en ? 'Wireless (Cisco WLC)' : 'Wireless (Cisco WLC)')}
            <div style="flex:1; min-width:20px;"></div>
            <input id="diagWlcIp" placeholder="${escapeHtml(en ? 'WLC address' : 'indirizzo WLC')}"
                   style="background:var(--surface); border:1px solid var(--border); border-radius:0; padding:4px 10px; font-size:12px; color:var(--text); width:170px;">
            <button data-action="diagnose-wifi" class="btn btn-secondary btn-small" style="width:auto; margin:0;"><i class="fa-solid fa-stethoscope"></i> ${escapeHtml(en ? 'Run' : 'Lancia')}</button>
        </div>
        <div id="diagWifiBody"><div style="color:var(--text-muted); font-size:12px;">${escapeHtml(
            _diagMac ? (en ? 'Client detail, AP, WLAN and nearby rogue APs — on demand.'
                           : 'Dettaglio client, AP, WLAN e rogue AP vicini — su richiesta.')
                     : (en ? 'No MAC known for this client: the controller is queried by MAC.'
                           : 'Nessun MAC noto per questo client: il controller si interroga per MAC.'))}</div></div>
    </div>`;
}

async function diagnoseWifi() {
    const en = currentLang === 'en';
    const host = document.getElementById('diagWifiBody');
    const ipEl = document.getElementById('diagWlcIp');
    const ip = ipEl ? ipEl.value.trim() : '';
    if (!host) return;
    if (!ip || !_diagMac) {
        host.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">${escapeHtml(
            en ? 'Enter the WLC address; the client MAC comes from the report above.'
               : 'Inserisci l\'indirizzo del WLC; il MAC del client arriva dal referto qui sopra.')}</div>`;
        return;
    }
    host.innerHTML = `<div style="color:var(--text-muted); font-size:12px;"><i class="fa-solid fa-circle-notch fa-spin" style="margin-right:8px;"></i>${escapeHtml(en ? 'Querying the controller…' : 'Interrogazione del controller…')}</div>`;
    const res = await apiFetch(`/api/wlc/${encodeURIComponent(ip)}/diagnose-client/${encodeURIComponent(_diagMac)}`);
    if (!res || !res.ok) {
        const e = res ? await res.json().catch(() => ({})) : {};
        host.innerHTML = `<div style="color:var(--danger); font-size:12px;">${escapeHtml(e.detail || (en ? 'WiFi diagnosis failed.' : 'Diagnosi WiFi fallita.'))}</div>`;
        return;
    }
    const d = await res.json();
    const sections = d.sections || {};
    // Stessa forma della diagnosi FortiGate: sezioni best-effort, ognuna coi
    // propri dati o col proprio errore. Si dice quale ha risposto.
    const rows = Object.keys(sections).map(name => {
        const sec = sections[name] || {};
        const n = Array.isArray(sec.data) ? sec.data.length : null;
        return _kv(name, sec.error ? (en ? 'error: ' : 'errore: ') + sec.error
                                   : (n === null ? (en ? 'answered' : 'ha risposto') : String(n)));
    }).join('');
    host.innerHTML = _kv('WLC', d.wlc) + _kv(en ? 'Platform' : 'Piattaforma', d.platform) +
        _kv('MAC', d.client_mac) + rows +
        `<details style="margin-top:8px;"><summary style="cursor:pointer; font-size:11px; color:var(--text-muted);">${escapeHtml(en ? 'Raw controller output' : 'Output grezzo del controller')}</summary>
         <pre style="font-family:var(--font-code); background:var(--surface); border:1px solid var(--border); border-radius:0; padding:10px; margin:6px 0 0; white-space:pre-wrap; font-size:11px; max-height:260px; overflow:auto;">${escapeHtml(JSON.stringify(sections, null, 2))}</pre></details>`;
}

// --- Azioni sulla porta ----------------------------------------------------
// Le uniche scritture della tab. Il nome della porta va digitato: una conferma
// che si puo' dare col mouse senza leggere non e' una conferma.
//
// Riavvia e Isola non sono la stessa cosa e i bottoni lo dicono: il bounce
// torna su da solo, l'isolamento resta giu' finche' qualcuno non lo toglie.
// Riattiva invece non chiede la conferma digitata: e' la via di ritorno, e
// rendere difficile disfare un isolamento e' esso stesso un guasto.
function _diagBounceControl() {
    if (!_diagSwitch) return '';
    const en = currentLang === 'en';
    return `<div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border);">
        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
            <span style="font-size:12px; color:var(--text-muted);">${escapeHtml(en ? 'Act on port' : 'Agisci sulla porta')}
                <b style="font-family:var(--font-code);">${escapeHtml(_diagSwitch.port)}</b></span>
            <input id="diagBounceConfirm" placeholder="${escapeHtml(en ? 'type the port name' : 'digita il nome della porta')}"
                   style="background:var(--surface); border:1px solid var(--border); border-radius:0; padding:4px 10px; font-size:12px; color:var(--text); width:190px;">
            <button data-action="diag-bounce-port" class="btn btn-secondary btn-small" style="width:auto; margin:0;">
                <i class="fa-solid fa-power-off"></i> ${escapeHtml(en ? 'Bounce' : 'Riavvia porta')}</button>
            <button data-action="diag-isolate-port" class="btn btn-danger btn-small" style="width:auto; margin:0;">
                <i class="fa-solid fa-plug-circle-xmark"></i> ${escapeHtml(en ? 'Isolate' : 'Isola porta')}</button>
            <button data-action="diag-restore-port" class="btn btn-secondary btn-small" style="width:auto; margin:0;">
                <i class="fa-solid fa-plug-circle-check"></i> ${escapeHtml(en ? 'Re-enable' : 'Riattiva porta')}</button>
        </div>
        <div id="diagBounceOut" style="font-size:12px; margin-top:6px;"></div>
        <div style="color:var(--text-muted); font-size:11px; margin-top:4px;">
            ${escapeHtml(en ? 'Admin only. Bounce and isolate are refused on an uplink or a stale position — a stale port belongs to someone else. Isolate leaves the port DOWN until re-enabled.'
                            : 'Solo admin. Riavvio e isolamento sono rifiutati su un uplink o su una posizione vecchia: una porta vecchia e\' di qualcun altro. L\'isolamento lascia la porta GIU\' finche\' non la si riattiva.')}</div>
    </div>`;
}

// Isolamento e riattivazione passano dalla stessa rotta: cambia l'azione e,
// con essa, cosa il server pretende prima di eseguirla.
async function _diagPortControl(action) {
    const en = currentLang === 'en';
    const out = document.getElementById('diagBounceOut');
    if (!out || !_diagSwitch) return;
    out.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${escapeHtml(en ? 'Working…' : 'In corso…')}`;
    const res = await apiFetch('/api/mac/port-control', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: _diagSwitch.ip, port: _diagSwitch.port,
                               action: action, client_mac: _diagMac })
    });
    if (!res || !res.ok) {
        const e = res ? await res.json().catch(() => ({})) : {};
        out.innerHTML = `<span style="color:var(--danger);">${escapeHtml(e.detail || (en ? 'Refused.' : 'Rifiutato.'))}</span>`;
        return;
    }
    out.innerHTML = action === 'shutdown'
        ? `<span style="color:var(--warning);">${escapeHtml(en ? 'Port isolated: it stays DOWN until re-enabled.' : 'Porta isolata: resta GIU\' finche\' non la riattivi.')}</span>`
        : `<span style="color:var(--success);">${escapeHtml(en ? 'Port re-enabled.' : 'Porta riattivata.')}</span>`;
}

async function diagIsolatePort() {
    const en = currentLang === 'en';
    const out = document.getElementById('diagBounceOut');
    const typed = ((document.getElementById('diagBounceConfirm') || {}).value || '').trim();
    if (!out || !_diagSwitch) return;
    if (typed.toLowerCase() !== String(_diagSwitch.port).toLowerCase()) {
        out.innerHTML = `<span style="color:var(--warning);">${escapeHtml(en ? 'Type the exact port name to confirm.' : 'Digita il nome esatto della porta per confermare.')}</span>`;
        return;
    }
    await _diagPortControl('shutdown');
}

// Nessuna conferma digitata: riaccendere una porta non fa danni, non poterla
// riaccendere si.
async function diagRestorePort() {
    await _diagPortControl('no-shutdown');
}

async function diagBouncePort() {
    const en = currentLang === 'en';
    const out = document.getElementById('diagBounceOut');
    const typed = ((document.getElementById('diagBounceConfirm') || {}).value || '').trim();
    if (!out || !_diagSwitch) return;
    if (typed.toLowerCase() !== String(_diagSwitch.port).toLowerCase()) {
        out.innerHTML = `<span style="color:var(--warning);">${escapeHtml(en ? 'Type the exact port name to confirm.' : 'Digita il nome esatto della porta per confermare.')}</span>`;
        return;
    }
    out.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${escapeHtml(en ? 'Bouncing…' : 'In corso…')}`;
    const res = await apiFetch('/api/diagnose/port-bounce', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_mac: _diagMac, switch_ip: _diagSwitch.ip,
                               interface: _diagSwitch.port })
    });
    if (!res || !res.ok) {
        const e = res ? await res.json().catch(() => ({})) : {};
        out.innerHTML = `<span style="color:var(--danger);">${escapeHtml(e.detail || (en ? 'Bounce refused.' : 'Bounce rifiutato.'))}</span>`;
        return;
    }
    const r = await res.json();
    out.innerHTML = r.up_ok
        ? `<span style="color:var(--success);">${escapeHtml(en ? 'Port bounced.' : 'Porta riavviata.')}</span>`
        : `<span style="color:var(--danger);">${escapeHtml(r.error || (en ? 'PORT LEFT DOWN.' : 'PORTA RIMASTA GIU.'))}</span>`;
}

// Delegated click listener on #diagResult
document.getElementById('diagResult')?.addEventListener('click', (e) => {
    if (e.target.closest('[data-action="rerun-diagnosi"]')) {
        runDiagnosi();
        return;
    }
    const pickBtn = e.target.closest('[data-action="diagnosi-pick-tenant"]');
    if (pickBtn && pickBtn.dataset.tenant) {
        diagnosiPickTenant(pickBtn.dataset.tenant);
        return;
    }
    if (e.target.closest('[data-action="diagnose-wifi"]')) {
        diagnoseWifi();
        return;
    }
    if (e.target.closest('[data-action="diag-bounce-port"]')) {
        diagBouncePort();
        return;
    }
    if (e.target.closest('[data-action="diag-isolate-port"]')) {
        diagIsolatePort();
        return;
    }
    if (e.target.closest('[data-action="diag-restore-port"]')) {
        diagRestorePort();
    }
});

// Static event listeners for Diagnosi tab
const diagInputs = ['diagClientInput', 'diagDestInput', 'diagGatewayInput'];
diagInputs.forEach(id => {
    document.getElementById(id)?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') runDiagnosi();
    });
});
document.getElementById('btnDiagTraceroute')?.addEventListener('click', detectGatewayTracerouteUI);
document.getElementById('diagGatewaySelect')?.addEventListener('change', onDiagGatewaySelectChange);
document.getElementById('btnRunDiagnosi')?.addEventListener('click', runDiagnosi);
