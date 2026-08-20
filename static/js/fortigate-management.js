// ===== Fortigate Management tab — token API + oggetti firewall live =====
// La tab e' admin-only (nav-item requires-admin), non piu' dietro un flag di
// preview. Questa è l'unica proprietaria della UI token/oggetti FortiGate:
// il duplicato che viveva in tab-provisioner (provisioning.js) è stato
// rimosso. Le stringhe derivate dal FortiGate passano sempre da
// escapeHtml(x) (jsStr definito in mcp-client.js).

// Registro delle viste di sola lettura. Ogni voce dice DOVE prendere i dati
// e QUALI colonne mostrarne: un solo loader e un solo renderer li servono
// tutte, aggiungerne una costa tre righe. `pick` estrae il ramo giusto per
// le risposte annidate (risorse, HA, profili).
const FGT_DATASETS = {
    // --- Overview ---
    // pick assente: si tiene l'intero {status, checksums} (Finding 3 —
    // un cluster "in sync" con checksum divergenti è il caso che conta).
    ha:        { url: ip => `/api/fortigate/${ip}/system/ha`, cols: [] },
    resources: { url: ip => `/api/fortigate/${ip}/system/resources`, pick: d => (d || {}).usage, cols: [] },
    // --- Network ---
    // monitor/system/interface non ha un campo `status`: lo stato del link sta
    // in `link` (booleano), e i contatori sono tx_bytes/rx_bytes.
    interfaces:   { url: ip => `/api/fortigate/${ip}/interfaces`,
                    cols: [['name','colFgtIfName'], ['alias','colFgtIfAlias'], ['ip','colFgtIfIp'],
                           ['mask','colFgtIfMask'], ['mac','colFgtIfMac'], ['link','colFgtIfStatus','badge'],
                           ['speed','colFgtIfSpeed'], ['tx_bytes','colFgtIfTx','bytes'],
                           ['rx_bytes','colFgtIfRx','bytes']] },
    arp:          { url: ip => `/api/fortigate/${ip}/arp`,
                    cols: [['ip','colFgtArpIp'], ['mac','colFgtArpMac'], ['interface','colFgtArpIntf'], ['age','colFgtArpAge']] },
    dhcp:         { url: ip => `/api/fortigate/${ip}/dhcp-leases`,
                    cols: [['ip','colFgtDhcpIp'], ['mac','colFgtDhcpMac'], ['hostname','colFgtDhcpHost'],
                           ['expire_time','colFgtDhcpExpire','time'], ['interface','colFgtDhcpIntf']] },
    routes:       { url: ip => `/api/fortigate/${ip}/routes`,
                    cols: [['ip_mask','colFgtRouteDest'], ['gateway','colFgtRouteGw'], ['interface','colFgtRouteIntf'],
                           ['type','colFgtRouteType'], ['distance','colFgtRouteDist'], ['metric','colFgtRouteMetric']] },
    vpn:          { url: ip => `/api/fortigate/${ip}/vpn/tunnels`,
                    cols: [['name','colFgtVpnName'], ['rgwy','colFgtVpnPeer'], ['status','colFgtVpnStatus','badge'],
                           ['incoming_bytes','colFgtVpnIn','bytes'], ['outgoing_bytes','colFgtVpnOut','bytes']] },
    sdwan:        { url: ip => `/api/fortigate/${ip}/sdwan/health`,
                    cols: [['name','colFgtSdwanName'], ['status','colFgtSdwanStatus','badge'], ['latency','colFgtSdwanLatency'],
                           ['jitter','colFgtSdwanJitter'], ['packet_loss','colFgtSdwanLoss','meter']] },
    // --- Firewall ---
    addresses:    { url: ip => `/api/fortigate/${ip}/firewall/addresses`,
                    cols: [['name','colFgtAddrName'], ['type','colFgtAddrType'], ['subnet','colFgtAddrSubnet'],
                           ['fqdn','colFgtAddrFqdn'], ['comment','colFgtAddrComment']] },
    addressGroups:{ url: ip => `/api/fortigate/${ip}/firewall/address-groups`,
                    cols: [['name','colFgtGrpName'], ['member','colFgtGrpMembers'], ['comment','colFgtGrpComment']] },
    services:     { url: ip => `/api/fortigate/${ip}/firewall/services`,
                    cols: [['name','colFgtSvcName'], ['tcp-portrange','colFgtSvcTcp'],
                           ['udp-portrange','colFgtSvcUdp'], ['comment','colFgtSvcComment']] },
    serviceGroups:{ url: ip => `/api/fortigate/${ip}/firewall/service-groups`,
                    cols: [['name','colFgtGrpName'], ['member','colFgtGrpMembers'], ['comment','colFgtGrpComment']] },
    vips:         { url: ip => `/api/fortigate/${ip}/firewall/vips`,
                    cols: [['name','colFgtVipName'], ['extip','colFgtVipExt'], ['mappedip','colFgtVipMapped'],
                           ['extintf','colFgtVipIntf'], ['portforward','colFgtVipPf','badge'], ['comment','colFgtVipComment']] },
    ipPools:      { url: ip => `/api/fortigate/${ip}/firewall/ip-pools`,
                    cols: [['name','colFgtPoolName'], ['type','colFgtPoolType'],
                           ['startip','colFgtPoolStart'], ['endip','colFgtPoolEnd']] },
    policies:     { url: ip => `/api/fortigate/${ip}/firewall/policies-with-stats`,
                    cols: [['policyid','colFgtPolId'], ['name','colFgtPolName'],
                           ['srcintf','colFgtPolSrcIntf'], ['dstintf','colFgtPolDstIntf'],
                           ['srcaddr','colFgtPolSrcAddr'], ['dstaddr','colFgtPolDstAddr'],
                           ['service','colFgtPolService'], ['action','colFgtPolAction','badge'],
                           ['status','colFgtPolStatus','badge'], ['hit_count','colFgtPolHits'],
                           ['active_sessions','colFgtPolSessions'], ['last_used','colFgtPolLastUsed','time']] },
    // Quale policy matcherebbe un flusso: risposta a oggetto singolo, resa
    // come tabella chiave/valore (cols vuoto -> ramo isKv del renderer).
    policyLookup: { url: ip => `/api/fortigate/${ip}/policy-lookup`, method: 'POST',
                    body: () => ({ src_ip: _fgtVal('fgtLookupSrc'), dest: _fgtVal('fgtLookupDst'),
                                   protocol: _fgtVal('fgtLookupProto') || 'TCP',
                                   dest_port: parseInt(_fgtVal('fgtLookupPort')) || 443,
                                   srcintf: _fgtVal('fgtLookupIntf') || null }),
                    requires: 'fgtLookupSrc', cols: [] },
    securityProfiles: { url: ip => `/api/fortigate/${ip}/firewall/security-profiles`, cols: [] },
    // --- Traffic ---
    deviceInventory:{ url: ip => `/api/fortigate/${ip}/device-inventory`,
                    cols: [['hostname','colFgtDevHost'], ['mac','colFgtDevMac'], ['ipv4_address','colFgtDevIp'],
                           ['os_name','colFgtDevOs'], ['detected_interface','colFgtDevIntf'], ['is_online','colFgtDevOnline','badge']] },
    sessions:     { url: ip => `/api/fortigate/${ip}/sessions`, method: 'POST',
                    body: () => ({ src_ip: _fgtVal('fgtSessSrc') || null, dst_ip: _fgtVal('fgtSessDst') || null,
                                   dst_port: parseInt(_fgtVal('fgtSessPort')) || null, count: 100 }),
                    cols: [['protocol','colFgtSessProto'], ['source','colFgtSessSrc'], ['source_port','colFgtSessSport'],
                           ['destination','colFgtSessDst'], ['destination_port','colFgtSessDport'],
                           ['policy_id','colFgtSessPolicy'], ['duration','colFgtSessDuration']] },
    logs:         { url: ip => `/api/fortigate/${ip}/logs`, method: 'POST',
                    body: () => ({ src_ip: _fgtVal('fgtLogSrc') || null, dst_ip: _fgtVal('fgtLogDst') || null,
                                   action: _fgtVal('fgtLogAction') || null,
                                   count: parseInt(_fgtVal('fgtLogCount')) || 100,
                                   log_device: _fgtVal('fgtLogDevice') || 'disk',
                                   log_type: _fgtVal('fgtLogType') || 'traffic',
                                   log_subtype: _fgtVal('fgtLogSubtype') || 'forward',
                                   cli_category: _fgtVal('fgtLogType') || 'traffic',
                                   since: _fgtVal('fgtLogSince') || null,
                                   until: _fgtVal('fgtLogUntil') || null }),
                    cols: [['date','colFgtLogDate'], ['time','colFgtLogTime'], ['srcip','colFgtLogSrc'],
                           ['srcport','colFgtLogSport'], ['dstip','colFgtLogDst'], ['dstport','colFgtLogDport'],
                           ['proto','colFgtLogProto'], ['action','colFgtLogAction','badge'],
                           ['policyid','colFgtLogPolicy'], ['service','colFgtLogService'],
                           ['app','colFgtLogApp'], ['sentbyte','colFgtLogSent','bytes'],
                           ['rcvdbyte','colFgtLogRcvd','bytes']] },
    // Diagnosi client: unica rotta della tab che risponde SENZA l'involucro
    // {source, data} — torna {client, sections:{...}} perché nasce per l'AI e
    // per MCP. Per questo `pick` legge il secondo argomento, il corpo intero.
    clientDiagnosis:{ url: ip => `/api/fortigate/${ip}/diagnose-client`, method: 'POST',
                    body: () => ({ client: _fgtVal('fgtDiagClient'),
                                   dest: _fgtVal('fgtDiagDst') || null,
                                   dest_port: parseInt(_fgtVal('fgtDiagPort')) || 443,
                                   protocol: _fgtVal('fgtDiagProto') || 'TCP' }),
                    pick: (_data, body) => _fgtSectionRows(body),
                    requires: 'fgtDiagClient',
                    cols: [['section','colFgtDiagSection'], ['outcome','colFgtDiagOutcome','badge'],
                           ['detail','colFgtDiagDetail']] },
    // --- Security ---
    admins:       { url: ip => `/api/fortigate/${ip}/system/admins`,
                    cols: [['name','colFgtAdminName'], ['accprofile','colFgtAdminProfile'],
                           ['trusthost1','colFgtAdminTrust'], ['two-factor','colFgtAdmin2fa','badge'], ['comments','colFgtAdminComment']] },
    bannedUsers:  { url: ip => `/api/fortigate/${ip}/system/banned-users`,
                    cols: [['ip_address','colFgtBanIp'], ['cause','colFgtBanCause'], ['expires','colFgtBanExpires','time']] },
    certificates: { url: ip => `/api/fortigate/${ip}/system/certificates`,
                    cols: [['name','colFgtCertName'], ['type','colFgtCertType'], ['status','colFgtCertStatus','badge'],
                           ['valid_to','colFgtCertExpiry','time'], ['issuer','colFgtCertIssuer']] },
    configRevisions:{ url: ip => `/api/fortigate/${ip}/system/config-revisions`,
                    cols: [['id','colFgtRevId'], ['date','colFgtRevDate','time'], ['admin','colFgtRevAdmin'], ['comment','colFgtRevComment']] },
    // --- WiFi ---
    wifiAps:      { url: ip => `/api/fortigate/${ip}/wifi/aps`,
                    cols: [['name','colFgtApName'], ['status','colFgtApStatus','badge'], ['ip','colFgtApIp'],
                           ['os_version','colFgtApVersion'], ['clients','colFgtApClients']] },
    wifiClients:  { url: ip => `/api/fortigate/${ip}/wifi/clients`,
                    cols: [['hostname','colFgtWcHost'], ['mac','colFgtWcMac'], ['ip','colFgtWcIp'],
                           ['ssid','colFgtWcSsid'], ['signal','colFgtWcSignal'], ['channel','colFgtWcChannel']] },
    // --- Settings ---
    // Contiene segreti (operator+ lato rotta): mai caricata di default, solo
    // dietro al pulsante esplicito in Impostazioni.
    fullConfig:   { url: ip => `/api/fortigate/${ip}/full-config`, cols: [] },
};

// Valore di un input, stringa vuota se l'elemento non c'è ancora.
function _fgtVal(id) {
    const el = document.getElementById(id);
    return el ? String(el.value || '').trim() : '';
}

let fgtDatasetRows = {};   // key -> { rows, source, apiError, error }

// Un solo loader per tutte le viste. Un dataset che fallisce non è un
// errore della tab: su un FortiGate senza SD-WAN o senza controller WiFi
// il 502 è la risposta giusta, e la vista si rende vuota con il motivo nel
// title invece di sparare un toast rosso.
// Session kill: same filters as the sessions view, DELETE instead of POST.
// The route accepts an empty filter set and would then drop every session on
// the firewall, so an empty form is refused here rather than sent.
async function fgtKillSessions() {
    const ip = fgtCurrentTarget();
    if (!ip) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    const en = currentLang === 'en';
    const src = _fgtVal('fgtSessSrc');
    const dst = _fgtVal('fgtSessDst');
    const port = _fgtVal('fgtSessPort');
    if (!src && !dst && !port) {
        showToast(L.msgFgtKillNeedsFilter || (en
            ? 'Set at least one filter: an empty filter would kill every session.'
            : 'Indica almeno un filtro: senza, verrebbero terminate tutte le sessioni.'), 'warning');
        return;
    }
    const shown = [src && `src=${src}`, dst && `dst=${dst}`, port && `dport=${port}`]
        .filter(Boolean).join(', ');
    const question = en
        ? `Kill the sessions matching ${shown} on ${ip}?`
        : `Terminare le sessioni che corrispondono a ${shown} su ${ip}?`;
    if (!confirm(question)) return;
    const body = {};
    if (src) body.src_ip = src;
    if (dst) body.dst_ip = dst;
    if (port) body.dst_port = parseInt(port, 10);
    const res = await apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/sessions`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (!res || !res.ok) {
        const e = res ? await res.json().catch(() => ({})) : {};
        showToast(e.detail || (en ? 'Session kill failed.' : 'Terminazione sessioni non riuscita.'), 'error');
        return;
    }
    showToast(en ? 'Sessions killed.' : 'Sessioni terminate.', 'success');
    loadFgtDataset('sessions');
}

async function loadFgtDataset(key) {
    const spec = FGT_DATASETS[key];
    if (!spec) return;
    const ip = fgtCurrentTarget();
    if (!ip) {
        const host = document.getElementById('fgtView-' + key);
        if (host) {
            const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
            const en = currentLang === 'en';
            host.innerHTML = _fgtEmpty(L.msgFgtNoTarget || (en ? 'No target selected.' : 'Nessun target selezionato.'));
        }
        return;
    }
    // Viste che interrogano un flusso o un client: aprire la pill le carica,
    // e senza il campo obbligatorio partirebbe una richiesta con la domanda
    // vuota. Il firewall risponderebbe pure — a un'altra domanda.
    if (spec.requires && !_fgtVal(spec.requires)) {
        const host = document.getElementById('fgtView-' + key);
        if (host) {
            const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
            const en = currentLang === 'en';
            host.innerHTML = _fgtEmpty(L.msgFgtFormRequired
                || (en ? 'Fill the form above, then run the query.'
                       : 'Compila il modulo qui sopra, poi lancia la query.'));
        }
        return;
    }
    const opts = spec.method === 'POST'
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(spec.body ? spec.body() : {}) }
        : undefined;
    try {
        const res = await apiFetch(spec.url(encodeURIComponent(ip)), opts);
        if (res && res.ok) {
            const body = await res.json();
            // Secondo argomento: il corpo intero, per le rotte che non usano
            // l'involucro {source, data} (vedi clientDiagnosis).
            const data = spec.pick ? spec.pick(body.data, body) : body.data;
            fgtDatasetRows[key] = {
                rows: _fgtRows(data, spec),
                raw: data, source: body.source, apiError: body.api_error || null,
                errors: body.errors || null, error: null,
                // Eco della query effettiva (i log la restituiscono): serve a
                // distinguere "il firewall non ha quei log" da "abbiamo
                // chiesto un'altra cosa".
                query: { log_device: body.log_device, log_type: body.log_type,
                         log_subtype: body.log_subtype,
                         subtype_enforced: body.subtype_enforced,
                         days_queried: body.days_queried },
            };
        } else {
            const err = res ? await res.json().catch(() => ({})) : {};
            fgtDatasetRows[key] = { rows: [], raw: null, source: null, apiError: null,
                                    error: err.detail || 'HTTP ' + (res ? res.status : '?') };
        }
    } catch (e) {
        fgtDatasetRows[key] = { rows: [], raw: null, source: null, apiError: null, error: String(e) };
    }
    renderFgtDataset(key);
}

// Le risposte del service sono {source, data, api_error?} e `data` può
// essere lista, dict o testo CLI grezzo quando è scattato il fallback SSH.
// Il vecchio renderer conosceva solo il primo caso.
function renderFgtDataset(key) {
    const host = document.getElementById('fgtView-' + key);
    if (!host) return;
    const spec = FGT_DATASETS[key];
    const st = fgtDatasetRows[key];
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    const en = currentLang === 'en';

    if (!st) { host.innerHTML = _fgtEmpty(L.msgFgtNotLoaded || (en ? 'Not loaded.' : 'Non caricato.')); return; }
    if (st.error) {
        host.innerHTML = _fgtEmpty(en ? 'Not available on this device.' : 'Non disponibile su questo dispositivo.', st.error);
        return;
    }

    // Fallback SSH: dirlo. "REST non ha risposto e stiamo leggendo la CLI"
    // non è la stessa cosa di "il firewall ha risposto", e finora la UI lo
    // nascondeva.
    const badge = st.source === 'ssh'
        ? `<div style="margin-bottom:8px;"><span class="status warn" title="${escapeHtml(st.apiError || '')}">
             <i class="fa-solid fa-terminal"></i> ${escapeHtml(L.badgeFgtSshFallback || (en ? 'CLI fallback — REST failed' : 'Fallback CLI — REST fallita'))}</span></div>`
        : '';

    // Eco della query che il FortiGate ha effettivamente servito. Senza,
    // "questi non sono i log forward" è indistinguibile da "abbiamo chiesto
    // altro": il service restituisce log_device/log_type/log_subtype proprio
    // per poterlo dire, e finora nessuno lo mostrava.
    const eq = st.query || {};
    const qEcho = (eq.log_type || eq.log_subtype || eq.log_device)
        ? `<div style="margin-bottom:8px; font-size:11px; color:var(--text-muted);">
             ${escapeHtml(L.lblFgtLogEffective || (en ? 'Executed query' : 'Query eseguita'))}:
             <code style="font-family:var(--font-code);">log/${escapeHtml(eq.log_device || '?')}/${escapeHtml(eq.log_type || '?')}/${escapeHtml(eq.log_subtype || '?')}</code>
             ${eq.subtype_enforced ? `<span class="status warn" style="margin-left:8px;"
                  title="${escapeHtml(L.msgFgtSubtypeEnforcedHint || (en ? 'FortiOS returned other subtypes for this path; rows were filtered on the log subtype field so the view matches the FortiGate GUI 1:1.' : 'FortiOS ha restituito altri sottotipi per questo percorso; le righe sono state filtrate sul campo subtype perché la vista corrisponda 1:1 alla GUI del FortiGate.'))}">${escapeHtml(L.badgeFgtSubtypeEnforced || (en ? 'subtype filtered' : 'sottotipo filtrato'))}</span>` : ''}
             ${eq.days_queried ? `<span style="margin-left:8px;">${escapeHtml(
                  (L.lblFgtLogDaysQueried || (en ? '{n} day(s) queried' : '{n} giorno/i interrogato/i'))
                      .replace('{n}', String(eq.days_queried)))}${
                  eq.days_queried >= 31 ? ' — ' + escapeHtml(L.msgFgtLogRangeCapped
                      || (en ? 'range capped at 31 days, older days not queried'
                            : 'intervallo limitato a 31 giorni, i giorni più vecchi non sono stati interrogati')) : ''}</span>` : ''}
           </div>`
        : '';
    const head = badge + qEcho;

    // Testo grezzo: configurazione completa, oppure l'uscita CLI di un
    // dataset che è caduto sul fallback SSH. In entrambi i casi sono migliaia
    // di righe, e un blocco unico senza ricerca non si consulta: si filtra per
    // riga e si racchiude in <details> (nativo: nessun toggle da scrivere).
    if (typeof st.raw === 'string') {
        const fi = document.getElementById('fgtFilter-' + key);
        if (fi) fi.style.display = '';          // c'è qualcosa da cercare, ora
        const q = (_fgtVal('fgtFilter-' + key) || '').toLowerCase();
        const all = st.raw.split('\n');
        const lines = q ? all.filter(l => l.toLowerCase().includes(q)) : all;
        const counter = q ? `${lines.length} / ${all.length}` : `${all.length}`;
        host.innerHTML = head + `<details open>
            <summary style="cursor:pointer; font-size:12px; color:var(--text-muted); margin-bottom:8px;">
              ${escapeHtml(counter)} ${escapeHtml(L.lblFgtLines || (en ? 'lines' : 'righe'))}</summary>
            <pre style="font-family:var(--font-code); font-size:12px; background:var(--surface);
            border:1px solid var(--border); border-radius:0; padding:12px; margin:0;
            white-space:pre-wrap; max-height:420px; overflow:auto;">${escapeHtml(lines.join('\n'))}</pre>
          </details>`;
        return;
    }
    if (!st.rows.length) { host.innerHTML = head + _fgtEmpty(L.msgFgtObjEmpty || (en ? 'No data.' : 'Nessun dato.')); return; }

    // Le risorse sono serie storiche, non un dict piatto: hanno un renderer
    // proprio (piccoli multipli + sparkline). Vedi renderFgtResources.
    if (key === 'resources') { renderFgtResources(host, st.rows[0] || {}, badge); return; }

    // Un dict singolo (HA, policy lookup) diventa una tabella chiave/valore.
    const isKv = st.rows.length === 1 && !spec.cols.some(([k]) => k in (st.rows[0] || {}));
    const filter = (_fgtVal('fgtFilter-' + key) || '').toLowerCase();
    const html = isKv ? _fgtKvTable(st.rows[0], st.errors) : _fgtColTable(spec.cols, st.rows, filter, L, key);
    host.innerHTML = head + html;
}

function _fgtEmpty(msg, title) {
    return `<div style="text-align:center; padding:20px; color:var(--text-muted); font-size:13px;"
        ${title ? `title="${escapeHtml(title)}"` : ''}>${escapeHtml(msg)}</div>`;
}

function _fgtCell(v) {
    if (Array.isArray(v)) v = v.map(x => (x && typeof x === 'object') ? (x.name || JSON.stringify(x)) : x).join(', ');
    if (v === null || v === undefined || v === '') return '—';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
}

// Una diagnosi risponde a sezioni best-effort: ognuna può portare dati o il
// proprio errore. Qui diventa una riga per sezione — quale ha risposto e con
// cosa — invece di un blob JSON. I dati per esteso hanno già la loro vista
// nella tab (ARP, sessioni, log, inventario): questa dice se sono arrivati.
function _fgtSectionRows(body) {
    const sections = (body || {}).sections || {};
    return Object.entries(sections).map(([name, raw]) => {
        const s = raw || {};
        let detail;
        if (s.error) {
            detail = s.error;
        } else if (Array.isArray(s.data)) {
            detail = `${s.data.length}` + (s.source ? ` (${s.source})` : '');
        } else {
            // Oggetto singolo (policy lookup, route): si mostra, ma troncato —
            // una config intera nel DOM di una cella non serve a nessuno.
            detail = _fgtCell(s.data === undefined ? s : s.data);
            if (detail.length > 300) detail = detail.slice(0, 300) + '…';
        }
        return { section: name, outcome: s.error ? 'error' : 'ok', detail };
    });
}

// --- Formattatori di colonna -----------------------------------------------
// Terzo elemento opzionale di una voce `cols`. Ricevono il valore GREZZO del
// dispositivo e restituiscono HTML: sono l'unico punto della tab in cui si
// costruisce markup attorno a un dato del FortiGate, quindi ognuno DEVE far
// passare il valore da escapeHtml(...) prima di interpolarlo. Un
// formattatore che dimentica di farlo è una XSS con sorgente il firewall.

// Stati che il FortiOS scrive in mille modi diversi per dire la stessa cosa.
const _FGT_OK = ['up', 'enable', 'enabled', 'online', 'accept', 'in-sync', 'insync', 'true', 'ok', 'valid'];
const _FGT_BAD = ['down', 'disable', 'disabled', 'offline', 'deny', 'out-of-sync', 'false', 'expired', 'blocked', 'error'];

const FGT_FMT = {
    // Pastiglia verde/rossa/gialla. Riusa .status del design system invece di
    // inventare colori: gli stessi tre stati compaiono già altrove nell'app.
    badge(v) {
        if (v === null || v === undefined || v === '') return '—';
        const raw = String(typeof v === 'boolean' ? v : v).toLowerCase().trim();
        const kind = _FGT_OK.includes(raw) ? 'ok' : _FGT_BAD.includes(raw) ? 'bad' : 'warn';
        return `<span class="status ${kind}">${escapeHtml(String(v))}</span>`;
    },
    // Barra 0-100. FortiOS restituisce spesso [{current: N}] invece di N.
    meter(v) {
        const n = Number(Array.isArray(v) ? (v[0] || {}).current : v);
        if (!isFinite(n)) return '—';
        const pct = Math.max(0, Math.min(100, n));
        const kind = pct >= 90 ? 'bad' : pct >= 75 ? 'warn' : 'ok';
        return `<span class="fgt-meter"><span class="fgt-meter-bar"><span class="fgt-meter-fill ${kind}"
            style="width:${pct}%"></span></span><span class="fgt-meter-num">${escapeHtml(pct.toFixed(0))}%</span></span>`;
    },
    // Epoch (secondi o millisecondi) -> data locale. 1786009452 non dice
    // niente a chi guarda una scadenza DHCP.
    time(v) {
        const n = Number(v);
        if (!isFinite(n) || n <= 0) return _fgtCell(v) === '—' ? '—' : escapeHtml(_fgtCell(v));
        // Sotto ~10^11 è in secondi, sopra in millisecondi.
        const d = new Date(n < 1e11 ? n * 1000 : n);
        if (isNaN(d.getTime())) return escapeHtml(String(v));
        return `<span title="${escapeHtml(String(v))}">${escapeHtml(d.toLocaleString())}</span>`;
    },
    // Contatori di byte: 14680064 non si legge, 14.0 MB sì.
    bytes(v) {
        const n = Number(v);
        if (!isFinite(n)) return _fgtCell(v) === '—' ? '—' : escapeHtml(_fgtCell(v));
        const u = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0, x = n;
        while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
        return escapeHtml((i ? x.toFixed(1) : String(x)) + ' ' + u[i]);
    },
};

// Righe di una risposta. Alcuni endpoint FortiOS non restituiscono una lista
// ma una MAPPA con chiave il nome dell'oggetto (monitor/system/interface ->
// {"port1": {...}, "port2": {...}}). Trattarla come riga singola incollava
// l'intero JSON in una cella: se la vista dichiara delle colonne e i valori
// sono tutti oggetti, la mappa è un elenco e va srotolata.
function _fgtRows(data, spec) {
    if (Array.isArray(data)) return data;
    if (data == null) return [];
    if (spec.cols.length && typeof data === 'object') {
        const vals = Object.values(data);
        if (vals.length && vals.every(v => v && typeof v === 'object' && !Array.isArray(v))) return vals;
    }
    return [data];
}

// Valore di cella già pronto per il DOM: col formattatore se la colonna ne
// dichiara uno, altrimenti testo escapato come sempre.
function _fgtFmtCell(row, key, fmt) {
    const v = row ? row[key] : undefined;
    if (fmt && FGT_FMT[fmt]) return FGT_FMT[fmt](v);
    return escapeHtml(_fgtCell(v));
}

// --- Risorse di sistema: piccoli multipli con sparkline ---------------------
// monitor/system/resource/usage NON è un valore puntuale: ogni metrica porta
// `current` più `historical` con finestre 1-min ... 24-hour, ognuna una lista
// di coppie [timestamp_ms, valore]. Renderla come dump chiave/valore
// significava incollare a schermo migliaia di numeri.
//
// Quattro metriche con unità diverse (percentuali contro un conteggio di
// sessioni) non vanno su un grafico solo: sarebbero due scale y sullo stesso
// piano, cioè una correlazione inventata. Una card per metrica.

const FGT_RES_WINDOWS = ['1-min', '10-min', '30-min', '1-hour', '12-hour', '24-hour'];
const FGT_RES_METRICS = [
    // chiave API, etichetta, unità ('pct' = soglie di stato, 'num' = neutro)
    ['cpu', 'CPU', 'pct'],
    ['mem', 'Memory|Memoria', 'pct'],
    ['disk', 'Disk|Disco', 'pct'],
    ['session', 'Sessions|Sessioni', 'num'],
];
let fgtResWindow = '1-hour';

function fgtSetResWindow(w) {
    fgtResWindow = w;
    renderFgtDataset('resources');
}

// FortiOS annida la metrica in un array di un elemento su alcune versioni.
function _fgtResEntry(v) { return Array.isArray(v) ? (v[0] || {}) : (v || {}); }

function _fgtSparkline(points, kind, w, h) {
    // Percentuali con scala fissa 0-100: auto-scalare farebbe sembrare una
    // salita drammatica un passaggio dal 5% al 6%.
    const vals = points.map(p => p[1]);
    const top = kind === 'pct' ? 100 : Math.max(1, ...vals);
    const n = points.length;
    const x = i => (n < 2 ? 0 : (i / (n - 1)) * w);
    const y = v => h - (Math.max(0, Math.min(top, v)) / top) * h;
    const line = points.map((p, i) => `${x(i).toFixed(1)},${y(p[1]).toFixed(1)}`).join(' ');
    const avg = vals.reduce((a, b) => a + b, 0) / (vals.length || 1);
    const last = points[n - 1];
    const stroke = kind !== 'pct' ? 'var(--primary)'
        : last && last[1] >= 90 ? 'var(--danger)'
        : last && last[1] >= 75 ? 'var(--warning)' : 'var(--success)';
    // ponytail: tooltip nativo via <title> invece di un crosshair su misura.
    // I valori sono comunque leggibili (attuale + min/media/max sotto la card
    // e la vista tabellare), quindi il crosshair aggiungerebbe JS senza
    // sbloccare un dato. Se servirà leggere il singolo campione, il passo
    // successivo è un layer nearest-point sul mousemove dell'svg.
    const when = t => { try { return new Date(t).toLocaleString(); } catch (e) { return String(t); } };
    const unit = kind === 'pct' ? '%' : '';
    const tip = last ? `${when(last[0])} — ${last[1]}${unit}` : '';
    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" width="100%" height="${h}"
        style="display:block; overflow:visible;" role="img"
        aria-label="${escapeHtml(`${vals.length} campioni, min ${Math.min(...vals)}${unit}, max ${Math.max(...vals)}${unit}`)}">
        <title>${escapeHtml(tip)}</title>
        <line x1="0" y1="${y(avg).toFixed(1)}" x2="${w}" y2="${y(avg).toFixed(1)}"
              stroke="var(--border)" stroke-width="1" vector-effect="non-scaling-stroke"/>
        <polyline points="${line}" fill="none" stroke="${stroke}" stroke-width="2"
              stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
        ${last ? `<circle cx="${x(n - 1).toFixed(1)}" cy="${y(last[1]).toFixed(1)}" r="3"
              fill="${stroke}" stroke="var(--surface)" stroke-width="2" vector-effect="non-scaling-stroke"/>` : ''}
      </svg>`;
}

function renderFgtResources(host, usage, badge) {
    const en = currentLang === 'en';
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    const lbl = s => { const [e, i] = s.split('|'); return i && !en ? i : e; };

    // Una sola riga di filtro sopra TUTTE le card: un selettore per card
    // rispondrebbe a domande diverse in grafici affiancati.
    const bar = `<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px;">` +
        FGT_RES_WINDOWS.map(w =>
            `<button type="button" class="ca-pill${w === fgtResWindow ? ' active' : ''}"
                 data-fgt-res-win="${escapeHtml(w)}">${escapeHtml(w)}</button>`).join('') +
        `</div>`;

    const cards = FGT_RES_METRICS.map(([k, label, kind]) => {
        const e = _fgtResEntry(usage[k]);
        const hist = (e.historical || {})[fgtResWindow] || {};
        // FortiOS elenca i campioni dal più recente: si ordina per tempo
        // crescente, altrimenti la sparkline scorre all'indietro.
        const pts = (Array.isArray(hist.values) ? hist.values : [])
            .filter(p => Array.isArray(p) && p.length >= 2)
            .slice().sort((a, b) => a[0] - b[0]);
        const unit = kind === 'pct' ? '%' : '';
        const cur = e.current;
        const stat = (name, v) => `<span style="color:var(--text-muted);">${escapeHtml(name)}
            <strong style="color:var(--text); font-variant-numeric:tabular-nums;">${escapeHtml(
                v == null ? '—' : String(v) + unit)}</strong></span>`;
        return `<div class="panel" style="margin:0; padding:14px;">
            <div style="display:flex; align-items:baseline; justify-content:space-between; gap:8px;">
              <span style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:.04em;">${escapeHtml(lbl(label))}</span>
              <span style="font-family:var(--font-display); font-size:21px;">${escapeHtml(cur == null ? '—' : String(cur) + unit)}</span>
            </div>
            <div style="margin:10px 0 8px; min-height:48px;">${pts.length
                ? _fgtSparkline(pts, kind, 240, 48)
                : `<div style="font-size:12px; color:var(--text-muted); padding:14px 0;">${escapeHtml(L.msgFgtNoHistory || (en ? 'No history in this window.' : 'Nessuno storico in questa finestra.'))}</div>`}</div>
            <div style="display:flex; gap:12px; font-size:11px; flex-wrap:wrap;">
              ${stat(en ? 'min' : 'min', hist.min)}${stat(en ? 'avg' : 'media', hist.average)}${stat('max', hist.max)}
            </div>
          </div>`;
    }).join('');

    // Gemello tabellare: i valori restano leggibili senza passare dal grafico.
    const rows = FGT_RES_METRICS.map(([k, label, kind]) => {
        const e = _fgtResEntry(usage[k]);
        const h = (e.historical || {})[fgtResWindow] || {};
        const u = kind === 'pct' ? '%' : '';
        const c = v => `<td style="padding:6px 12px; font-family:var(--font-code); font-size:12px; font-variant-numeric:tabular-nums;">${escapeHtml(v == null ? '—' : String(v) + u)}</td>`;
        return `<tr style="border-bottom:1px solid var(--border);">
            <td style="padding:6px 12px; font-weight:600;">${escapeHtml(lbl(label))}</td>
            ${c(e.current)}${c(h.min)}${c(h.average)}${c(h.max)}</tr>`;
    }).join('');
    const table = `<details style="margin-top:12px;">
        <summary style="cursor:pointer; font-size:12px; color:var(--text-muted);">${escapeHtml(L.lblFgtTableView || (en ? 'Table view' : 'Vista tabellare'))}</summary>
        <div class="table-wrap" style="margin-top:8px;"><table style="width:100%; font-size:13px; border-collapse:collapse;">
          <thead><tr style="border-bottom:1px solid var(--border); background:var(--surface-3);">
            <th style="padding:6px 12px; text-align:left;"></th>
            <th style="padding:6px 12px; text-align:left;">${escapeHtml(en ? 'current' : 'attuale')}</th>
            <th style="padding:6px 12px; text-align:left;">min</th>
            <th style="padding:6px 12px; text-align:left;">${escapeHtml(en ? 'avg' : 'media')}</th>
            <th style="padding:6px 12px; text-align:left;">max</th>
          </tr></thead><tbody>${rows}</tbody></table></div>
      </details>`;

    host.innerHTML = badge + bar +
        `<div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:12px;">${cards}</div>` +
        table;
}

// `errors` (opzionale): mappa chiave->motivo per i rami che sono falliti
// senza far fallire l'intero dataset (es. security-profiles per famiglia
// senza licenza). Si evidenzia la riga col motivo nel title.
function _fgtKvTable(obj, errors) {
    const rows = Object.entries(obj || {}).map(([k, v]) => {
        const err = errors && errors[k];
        const warn = err ? 'color:var(--warning);' : '';
        const title = err ? ` title="${escapeHtml(err)}"` : '';
        return `<tr style="border-bottom:1px solid var(--border);">
           <td style="padding:8px 12px; font-weight:600; width:32%;">${escapeHtml(k)}</td>
           <td style="padding:8px 12px; font-family:var(--font-code); font-size:12px;${warn}"${title}>${escapeHtml(_fgtCell(v))}</td>
         </tr>`;
    }).join('');
    return `<div class="table-wrap" style="margin-top:0;"><table style="width:100%; font-size:13px; border-collapse:collapse;"><tbody>${rows}</tbody></table></div>`;
}

// `key` serve al dettaglio riga: la riga cliccata è ritrovata per indice
// nell'array ORIGINALE (non in quello filtrato), altrimenti con un filtro
// attivo si aprirebbe il dettaglio di un'altra riga.
function _fgtColTable(cols, rows, filter, L, key) {
    const text = r => cols.map(([k]) => _fgtCell(r ? r[k] : undefined)).join(' ').toLowerCase();
    const idx = rows.map((r, i) => i);
    const shown = filter ? idx.filter(i => text(rows[i]).includes(filter)) : idx;
    const head = `<th style="padding:8px 6px; width:22px;"></th>` +
        cols.map(([, lk]) => `<th style="padding:8px 12px; text-align:left;">${escapeHtml(L[lk] || lk)}</th>`).join('');
    const body = shown.map(i => {
        const r = rows[i];
        // Una policy con contatore a zero è un rilievo d'audit, non una riga
        // qualunque: si evidenzia.
        //
        // I difetti statici dal backup e i contatori rispondono a due domande
        // diverse. "Mai colpita" puo' voler dire solo che quel traffico non si
        // e' ancora presentato. "Coperta da una regola precedente" dice che non
        // potrebbe scattare comunque. Insieme non lasciano scampo: e' una
        // regola morta, e va segnalata piu' forte di entrambe le meta'.
        const defects = (r && r.findings) || [];
        const blocked = defects.some(f => f.key === 'shadowed' || f.key === 'unreachable');
        const confirmedDead = blocked && r && r.never_hit;
        const dead = confirmedDead ? 'color:var(--danger);'
                   : (blocked || (r && r.never_hit)) ? 'color:var(--warning);' : '';
        const mark = confirmedDead
            ? `<i class="fa-solid fa-circle-xmark" style="color:var(--danger); font-size:10px;" title="${escapeHtml(L.lblFgtPolDeadRule || 'Regola morta: coperta da una precedente e mai colpita')}"></i>`
            : blocked
            ? `<i class="fa-solid fa-triangle-exclamation" style="color:var(--warning); font-size:10px;" title="${escapeHtml(L.lblFgtPolShadowed || 'Coperta da una regola precedente')}"></i>`
            : `<i class="fa-solid fa-chevron-right" style="font-size:10px;"></i>`;
        const tds = cols.map(([k, , fmt]) =>
            `<td style="padding:8px 12px; font-family:var(--font-code); font-size:12px;${dead}">${_fgtFmtCell(r, k, fmt)}</td>`).join('');
        // Le colonne mostrano una manciata di campi; un log di traffico ne ha
        // decine (porte, interfacce, byte, app, country, sessionid...). Il
        // dettaglio apre la riga GREZZA, come il pannello Details della GUI
        // del FortiGate, invece di allargare la tabella a 40 colonne.
        return `<tr class="fgt-row" style="border-bottom:1px solid var(--border); cursor:pointer;"
                    data-fgt-key="${escapeHtml(key)}" data-fgt-idx="${i}"
                    title="${escapeHtml(L.lblFgtRowDetails || 'Dettagli')}">
              <td style="padding:8px 6px; color:var(--text-muted);">${mark}</td>
              ${tds}</tr>
            <tr class="fgt-row-detail" style="display:none;"><td colspan="${cols.length + 1}" style="padding:0 12px 12px;"></td></tr>`;
    }).join('');
    return `<div class="table-wrap" style="margin-top:0;">
        <table style="width:100%; font-size:13px; border-collapse:collapse;">
          <thead><tr style="border-bottom:1px solid var(--border); background:var(--surface-3);">${head}</tr></thead>
          <tbody>${body}</tbody>
        </table></div>`;
}

// Apre/chiude il dettaglio di una riga. Costruito alla prima apertura: con
// 100 log da ~40 campi, renderli tutti in anticipo sarebbe 4000 righe di DOM
// che nessuno guarda.
function fgtToggleRow(key, idx, tr) {
    const detail = tr.nextElementSibling;
    if (!detail || !detail.classList.contains('fgt-row-detail')) return;
    const open = detail.style.display !== 'none';
    const chevron = tr.querySelector('i');
    if (open) {
        detail.style.display = 'none';
        if (chevron) chevron.className = 'fa-solid fa-chevron-right';
        return;
    }
    const cell = detail.firstElementChild;
    if (cell && !cell.dataset.built) {
        const row = ((fgtDatasetRows[key] || {}).rows || [])[idx] || {};
        cell.innerHTML = _fgtKvTable(row);
        cell.dataset.built = '1';
    }
    detail.style.display = '';
    if (chevron) chevron.className = 'fa-solid fa-chevron-down';
}

// --- Caricamento tab ---
function loadFgtTab() {
    populateFgtPrevDeviceSelects();
    loadFgtTargets().then(() => {
        fgtDatasetRows = {};   // target può essere cambiato: niente dati stantii
        fgtSwitchView(fgtPane);
    });
}

function populateFgtPrevDeviceSelects() {
    const fgtDevices = (typeof globalDevices !== 'undefined' ? globalDevices : []).filter(dev =>
        (dev.Vendor || '').toLowerCase() === 'fortinet'
    );
    const opts = '<option value="" data-i18n="optFgtSelectDevice">-- seleziona dispositivo --</option>' +
        fgtDevices.map(dev =>
            `<option value="${escapeHtml(dev.IP)}" title="${escapeHtml(dev.Hostname || dev.IP)}">${escapeHtml(dev.IP)} (${escapeHtml(dev.Hostname || 'unknown')})</option>`
        ).join('');
    ['fgtPrevTokenDevice'].forEach(id => {
        const select = document.getElementById(id);
        if (!select) return;
        const currentValue = select.value;
        select.innerHTML = opts;
        if (currentValue) select.value = currentValue;
    });
}

// --- Token API (admin-only) ---

async function loadFgtPrevTokens() {
    try {
        const res = await apiFetch('/api/fortigate/tokens');
        if (!res || !res.ok) {
            document.getElementById('fgtPrevTokensEmpty').style.display = '';
            document.getElementById('fgtPrevTokensTable').style.display = 'none';
            return;
        }
        renderFgtPrevTokensTable(await res.json());
    } catch (e) {
        console.error('Errore caricamento token FortiGate:', e);
    }
}

function renderFgtPrevTokensTable(tokens) {
    const tbody = document.getElementById('fgtPrevTokensTableBody');
    const emptyMsg = document.getElementById('fgtPrevTokensEmpty');
    const table = document.getElementById('fgtPrevTokensTable');
    if (!tbody) return;

    const entries = Object.entries(tokens || {});
    if (!entries.length) {
        tbody.innerHTML = '';
        table.style.display = 'none';
        emptyMsg.style.display = '';
        return;
    }

    table.style.display = '';
    emptyMsg.style.display = 'none';
    tbody.innerHTML = entries.map(([ip, conf]) => {
        const port = conf.port || 443;
        const verifyTls = conf.verify_tls !== false ? 'Sì' : 'No';
        const status = '<span class="status ok"><i class="fa-solid fa-check"></i> Configurato</span>';
        return `<tr style="border-bottom:1px solid var(--border);">
            <td style="padding:8px 12px;">${escapeHtml(ip)}</td>
            <td style="padding:8px 12px;">${port}</td>
            <td style="padding:8px 12px;">${verifyTls}</td>
            <td style="padding:8px 12px;">${status}</td>
        </tr>`;
    }).join('');
}

async function saveFgtPrevToken() {
    const ip = document.getElementById('fgtPrevTokenDevice').value.trim();
    const token = document.getElementById('fgtPrevTokenValue').value;
    const port = parseInt(document.getElementById('fgtPrevTokenPort').value) || 443;
    const verifyTls = document.getElementById('fgtPrevTokenVerifyTls').checked;
    const st = document.getElementById('fgtPrevTokenStatus');

    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }
    if (port < 1 || port > 65535) { showToast(currentLang === 'en' ? 'Invalid port (1-65535)' : 'Porta non valida (1-65535)', 'error'); return; }
    if (!token) { showToast(currentLang === 'en' ? 'Enter a token' : 'Inserire un token', 'warning'); return; }

    const res = await apiFetch('/api/fortigate/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, token, port, verify_tls: verifyTls })
    });
    if (res && res.ok) {
        showToast(currentLang === 'en' ? 'Token saved successfully (encrypted)' : 'Token salvato con successo (cifrato)', 'success');
        document.getElementById('fgtPrevTokenValue').value = '';
        document.getElementById('fgtPrevTokenPort').value = '443';
        document.getElementById('fgtPrevTokenVerifyTls').checked = false;
        document.getElementById('fgtPrevTokenDevice').value = '';
        if (st) st.textContent = '';
        await loadFgtPrevTokens();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || (currentLang === 'en' ? 'Token save failed' : 'Salvataggio token fallito')}`, 'error');
    }
}

async function removeFgtPrevToken() {
    const ip = document.getElementById('fgtPrevTokenDevice').value.trim();
    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }
    if (!confirm(currentLang === 'en' ? `Remove the API token for ${ip}?` : `Rimuovere il token API per ${ip}?`)) return;

    const res = await apiFetch('/api/fortigate/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, token: "", port: 443, verify_tls: false })
    });
    if (res && res.ok) {
        showToast(currentLang === 'en' ? 'Token removed successfully' : 'Token rimosso con successo', 'success');
        document.getElementById('fgtPrevTokenDevice').value = '';
        await loadFgtPrevTokens();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || (currentLang === 'en' ? 'Token removal failed' : 'Rimozione token fallita')}`, 'error');
    }
}

async function testFgtPrevToken() {
    const ip = document.getElementById('fgtPrevTokenDevice').value.trim();
    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }

    const statusDiv = document.getElementById('fgtPrevTokenStatus');
    statusDiv.textContent = currentLang === 'en' ? 'Testing...' : 'Test in corso...';
    statusDiv.style.color = 'var(--text-muted)';

    const res = await apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/status`);
    if (res && res.ok) {
        const data = await res.json();
        const source = data.source || 'unknown';
        const results = data.data || {};
        let hostname = results.hostname || results.host || 'Unknown';
        let version = results.version || results.FortiOS_version || 'Unknown';
        if (results.results) {
            hostname = results.results.hostname || hostname;
            version = results.results.version || version;
        }
        let msg = `Test OK (${source}): ${hostname} v${version}`;
        if (source === 'ssh' && data.api_error) {
            msg += currentLang === 'en' ? ` — REST API failed: ${data.api_error}` : ` — REST API fallita: ${data.api_error}`;
        }
        showToast(msg, 'success');
        statusDiv.textContent = msg;
        statusDiv.style.color = 'var(--success)';
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        const msg = `${currentLang === 'en' ? 'Test failed: ' : 'Test fallito: '}${err.detail || (currentLang === 'en' ? 'Device unreachable' : 'Dispositivo non raggiungibile')}`;
        showToast(msg, 'error');
        statusDiv.textContent = msg;
        statusDiv.style.color = 'var(--danger)';
    }
}

// --- Multi-target FortiGate: selettore + modale di gestione ---------------
// Ogni FortiGate configurato (services/fortigate_service.py, JSON con
// "_active" per il target corrente) può avere un nome descrittivo. Il
// selettore in testa alla tab imposta il target attivo lato server; il
// modale "Gestisci FortiGate" elenca/aggiunge/modifica/rimuove i target e
// ne testa la connessione. Stringhe derivate dal FortiGate/inventario
// passano sempre da escapeHtml(x).

// L'IP su cui operano tutte le viste: il target attivo scelto in testa alla tab.
function fgtCurrentTarget() {
    return _fgtVal('fgtTargetSelect');
}

let fgtTargetsCache = [];

async function loadFgtTargets() {
    try {
        const res = await apiFetch('/api/fortigate/targets');
        fgtTargetsCache = (res && res.ok) ? await res.json() : [];
    } catch (e) {
        console.error('Errore caricamento target FortiGate:', e);
        fgtTargetsCache = [];
    }
    renderFgtTargetSelect();
}

function renderFgtTargetSelect() {
    const sel = document.getElementById('fgtTargetSelect');
    if (!sel) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (!fgtTargetsCache.length) {
        sel.innerHTML = `<option value="">${escapeHtml(L.optFgtNoTargets || '-- nessun target configurato --')}</option>`;
        return;
    }
    sel.innerHTML = fgtTargetsCache.map(t => {
        const label = `${t.name || t.ip} (${t.ip})`;
        return `<option value="${escapeHtml(t.ip)}" ${t.active ? 'selected' : ''}>${escapeHtml(label)}</option>`;
    }).join('');
}

async function onFgtTargetSelectChange() {
    const ip = document.getElementById('fgtTargetSelect')?.value;
    if (!ip) return;
    const res = await apiFetch('/api/fortigate/targets/active', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (res && res.ok) {
        showToast(L.msgFgtTargetActivated || 'Target FortiGate attivo aggiornato.', 'success');
        await loadFgtTargets();
        fgtDatasetRows = {};
        fgtSwitchView(fgtPane);
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || ''}`, 'error');
    }
}

function openFgtManageModal() {
    populateFgtMgrDeviceSelect();
    resetFgtMgrForm();
    renderFgtMgrTable();
    document.getElementById('fgtManageModal').style.display = 'flex';
}

function closeFgtManageModal() {
    document.getElementById('fgtManageModal').style.display = 'none';
}

function populateFgtMgrDeviceSelect() {
    const fgtDevices = (typeof globalDevices !== 'undefined' ? globalDevices : []).filter(dev =>
        (dev.Vendor || '').toLowerCase() === 'fortinet'
    );
    const sel = document.getElementById('fgtMgrIp');
    if (!sel) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    const current = sel.value;
    sel.innerHTML = `<option value="">${escapeHtml(L.optFgtSelectDevice || '-- seleziona dispositivo --')}</option>` +
        fgtDevices.map(dev =>
            `<option value="${escapeHtml(dev.IP)}">${escapeHtml(dev.IP)} (${escapeHtml(dev.Hostname || 'unknown')})</option>`
        ).join('');
    if (current) sel.value = current;
}

function renderFgtMgrTable() {
    const tbody = document.getElementById('fgtMgrTableBody');
    const table = document.getElementById('fgtMgrTable');
    const emptyMsg = document.getElementById('fgtMgrEmpty');
    if (!tbody) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};

    if (!fgtTargetsCache.length) {
        tbody.innerHTML = '';
        table.style.display = 'none';
        emptyMsg.style.display = '';
        return;
    }
    table.style.display = '';
    emptyMsg.style.display = 'none';

    tbody.innerHTML = fgtTargetsCache.map(t => {
        const ip = escapeHtml(t.ip);
        const name = escapeHtml(t.name || '');
        const tlsBadge = t.verify_tls
            ? `<span class="status ok">${escapeHtml(L.badgeFgtTestOk || 'OK')}</span>`
            : `<span class="status warn">off</span>`;
        return `<tr style="border-bottom:1px solid var(--border);" data-ip="${ip}">
            <td style="padding:8px 12px;">${name || '—'}</td>
            <td style="padding:8px 12px; font-family:var(--font-code);">${ip}</td>
            <td style="padding:8px 12px;">${t.port}</td>
            <td style="padding:8px 12px;">${tlsBadge}</td>
            <td style="padding:8px 12px; text-align:center;">
                <input type="radio" name="fgtMgrActiveRadio" ${t.active ? 'checked' : ''} data-fgt-action="activate-target" data-ip="${ip}">
            </td>
            <td style="padding:8px 12px; text-align:center;">
                <button type="button" class="btn btn-secondary btn-small" style="width:auto; margin:0;" data-fgt-action="test-target" data-ip="${ip}">${L.btnFgtMgrTest || '<i class="fa-solid fa-plug"></i>'}</button>
                <span class="fgt-mgr-test-result" style="margin-left:6px; font-size:11px;"></span>
            </td>
            <td style="padding:8px 12px; text-align:right; white-space:nowrap;">
                <button type="button" class="btn btn-secondary btn-small" style="width:auto; margin:0;" data-fgt-action="edit-target" data-ip="${ip}" title="${currentLang === 'en' ? 'Edit' : 'Modifica'}"><i class="fa-solid fa-pen"></i></button>
                <button type="button" class="btn btn-danger btn-small" style="width:auto; margin:0;" data-fgt-action="delete-target" data-ip="${ip}">${L.btnFgtMgrDelete || '<i class="fa-solid fa-trash"></i>'}</button>
            </td>
        </tr>`;
    }).join('');
}

function resetFgtMgrForm() {
    document.getElementById('fgtMgrEditIp').value = '';
    document.getElementById('fgtMgrName').value = '';
    const ipSel = document.getElementById('fgtMgrIp');
    if (ipSel) { ipSel.value = ''; ipSel.disabled = false; }
    document.getElementById('fgtMgrPort').value = '443';
    document.getElementById('fgtMgrVerifyTls').checked = false;
    const tokenInput = document.getElementById('fgtMgrToken');
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    tokenInput.value = '';
    tokenInput.placeholder = L.phFgtMgrTokenNew || 'token API';
    const st = document.getElementById('fgtMgrStatus');
    if (st) st.textContent = '';
}

function editFgtMgrTarget(ip) {
    const t = fgtTargetsCache.find(x => x.ip === ip);
    if (!t) return;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    document.getElementById('fgtMgrEditIp').value = t.ip;
    document.getElementById('fgtMgrName').value = t.name || '';
    const ipSel = document.getElementById('fgtMgrIp');
    if (ipSel) { ipSel.value = t.ip; ipSel.disabled = true; }
    document.getElementById('fgtMgrPort').value = t.port || 443;
    document.getElementById('fgtMgrVerifyTls').checked = !!t.verify_tls;
    const tokenInput = document.getElementById('fgtMgrToken');
    tokenInput.value = '';
    tokenInput.placeholder = L.phFgtMgrTokenEdit || '•••• invariato';
}

async function saveFgtMgrTarget() {
    const editIp = document.getElementById('fgtMgrEditIp').value.trim();
    const ip = editIp || document.getElementById('fgtMgrIp').value.trim();
    const name = document.getElementById('fgtMgrName').value.trim();
    const port = parseInt(document.getElementById('fgtMgrPort').value) || 443;
    const verifyTls = document.getElementById('fgtMgrVerifyTls').checked;
    const token = document.getElementById('fgtMgrToken').value;
    const st = document.getElementById('fgtMgrStatus');
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};

    if (!ip) { showToast(currentLang === 'en' ? 'Select a FortiGate device' : 'Selezionare un dispositivo FortiGate', 'warning'); return; }
    if (port < 1 || port > 65535) { showToast(currentLang === 'en' ? 'Invalid port (1-65535)' : 'Porta non valida (1-65535)', 'error'); return; }

    let res;
    if (editIp) {
        // Modifica: aggiornamento parziale via PUT, token omesso/vuoto = resta
        // quello già salvato ("•••• invariato" è quindi veritiero).
        res = await apiFetch(`/api/fortigate/targets/${encodeURIComponent(editIp)}`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, port, verify_tls: verifyTls, token: token || null })
        });
    } else {
        // Nuovo target: il token è obbligatorio (flusso esistente di creazione).
        if (!token) { showToast(currentLang === 'en' ? 'Enter a token' : 'Inserire un token', 'warning'); return; }
        res = await apiFetch('/api/fortigate/token', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, token, port, verify_tls: verifyTls, name })
        });
    }
    if (res && res.ok) {
        showToast(L.msgFgtTargetSaved || 'Target FortiGate salvato.', 'success');
        if (st) st.textContent = '';
        resetFgtMgrForm();
        await loadFgtTargets();
        renderFgtMgrTable();
        populateFgtPrevDeviceSelects();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || ''}`, 'error');
    }
}

async function activateFgtMgrTarget(ip) {
    const res = await apiFetch('/api/fortigate/targets/active', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
    });
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (res && res.ok) {
        showToast(L.msgFgtTargetActivated || 'Target FortiGate attivo aggiornato.', 'success');
        await loadFgtTargets();
        renderFgtMgrTable();
    }
}

async function testFgtMgrTarget(ip, btn) {
    const row = btn.closest('tr');
    const resultSpan = row ? row.querySelector('.fgt-mgr-test-result') : null;
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (resultSpan) resultSpan.textContent = currentLang === 'en' ? 'Testing...' : 'Test in corso...';
    const res = await apiFetch(`/api/fortigate/targets/${encodeURIComponent(ip)}/test`, { method: 'POST' });
    const data = res ? await res.json().catch(() => ({ ok: false })) : { ok: false };
    if (resultSpan) {
        if (data.ok) {
            resultSpan.innerHTML = `<span class="status ok">${escapeHtml(L.badgeFgtTestOk || 'OK')}${data.version ? ' v' + escapeHtml(data.version) : ''}</span>`;
        } else {
            resultSpan.innerHTML = `<span class="status bad" title="${escapeHtml(data.error || '')}">${escapeHtml(L.badgeFgtTestFail || 'Fallito')}</span>`;
        }
    }
}

async function deleteFgtMgrTarget(ip) {
    const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};
    if (!confirm(L.confirmFgtTargetDelete || 'Rimuovere questo target FortiGate?')) return;
    const res = await apiFetch('/api/fortigate/token', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, token: '', port: 443, verify_tls: false })
    });
    if (res && res.ok) {
        showToast(L.msgFgtTargetDeleted || 'Target FortiGate rimosso.', 'success');
        resetFgtMgrForm();
        await loadFgtTargets();
        renderFgtMgrTable();
        populateFgtPrevDeviceSelects();
    } else {
        const err = res ? await res.json().catch(() => ({})) : {};
        showToast(`${currentLang === 'en' ? 'Error: ' : 'Errore: '}${err.detail || ''}`, 'error');
    }
}

// --- Sotto-tab -------------------------------------------------------------
// Panes locali, non tab-content separate: condividono un solo target e un
// solo contesto di dispositivo, quindi switchTab() non c'entra.
const FGT_PANES = ['overview', 'network', 'firewall', 'traffic', 'security', 'wifi', 'settings'];
// Prima vista di ogni pane: si carica da sola quando il pane si apre.
const FGT_PANE_DEFAULT = {
    network: 'interfaces', firewall: 'addresses', traffic: 'sessions',
    security: 'admins', wifi: 'wifiAps',
};
let fgtPane = 'overview';

function fgtSwitchView(pane) {
    fgtPane = pane;
    FGT_PANES.forEach(p => {
        const el = document.getElementById('fgtPane-' + p);
        if (el) el.style.display = p === pane ? '' : 'none';
        const btn = document.getElementById('fgtSub-' + p);
        if (btn) btn.classList.toggle('active', p === pane);
    });
    if (pane === 'overview') { renderFgtOverview(); return; }
    if (pane === 'settings') { loadFgtPrevTokens(); loadFgtTargets(); return; }
    const key = FGT_PANE_DEFAULT[pane];
    if (key) fgtPickView(pane, key);
}

// Sceglie la vista dentro un pane. Carica solo alla prima apertura: i dati
// restano finché non si preme Aggiorna, altrimenti ogni click rifà una
// chiamata REST al firewall.
function fgtPickView(pane, key) {
    Object.keys(FGT_DATASETS).forEach(k => {
        const view = document.getElementById('fgtView-' + k);
        const pill = document.getElementById('fgtPill-' + k);
        const filter = document.getElementById('fgtFilter-' + k);
        const form = document.getElementById('fgtForm-' + k);
        if (view && pill) {  // solo le viste del pane corrente hanno una pill
            if (k === key) {
                view.style.display = ''; pill.classList.add('active');
                if (filter) filter.style.display = '';
                if (form) form.style.display = '';
            } else if (pill.closest('#fgtPane-' + pane)) {
                view.style.display = 'none'; pill.classList.remove('active');
                if (filter) filter.style.display = 'none';
                if (form) form.style.display = 'none';
            }
        }
    });
    if (!fgtDatasetRows[key]) loadFgtDataset(key); else renderFgtDataset(key);
}

// Ricarica esplicita della vista aperta nel pane corrente.
function refreshFgtView() {
    const open = Object.keys(FGT_DATASETS).find(k => {
        const v = document.getElementById('fgtView-' + k);
        return v && v.style.display !== 'none' && v.closest('#fgtPane-' + fgtPane);
    });
    if (open) loadFgtDataset(open);
}

// --- Panoramica ------------------------------------------------------------
// Bespoke: quattro numeri in evidenza, non una tabella. Il resto della tab
// passa dal registro.
async function renderFgtOverview() {
    const ip = fgtCurrentTarget();
    const host = document.getElementById('fgtOverviewTiles');
    const en = currentLang === 'en';
    if (!host) return;
    if (!ip) { host.innerHTML = _fgtEmpty(en ? 'No target selected.' : 'Nessun target selezionato.'); return; }

    const [status, resources, ha] = await Promise.all([
        apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/status`).then(r => r && r.ok ? r.json() : null).catch(() => null),
        apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/system/resources`).then(r => r && r.ok ? r.json() : null).catch(() => null),
        apiFetch(`/api/fortigate/${encodeURIComponent(ip)}/system/ha`).then(r => r && r.ok ? r.json() : null).catch(() => null),
    ]);

    const s = (status && status.data) || {};
    const u = (resources && resources.data && resources.data.usage) || {};
    const num = v => (Array.isArray(v) ? (v[0] || {}).current : v);

    // Tessera "valore": il corpo è già HTML, quindi chi la chiama passa o una
    // stringa escapata o l'uscita di un formattatore (che escapa da sé).
    const tile = (label, bodyHtml) => `<div class="panel" style="margin:0; padding:14px;">
        <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted); font-weight:700; letter-spacing:.04em;">${escapeHtml(label)}</div>
        <div style="margin-top:8px; font-family:var(--font-display); font-size:21px; line-height:1.2;">${bodyHtml}</div>
      </div>`;
    const plain = v => escapeHtml(v == null || v === '' ? '—' : String(v));
    // Una percentuale come barra: 62 da solo non dice se sia molto o poco.
    const gauge = v => `<div style="font-size:13px;">${FGT_FMT.meter(v)}</div>`;

    // HA: lo stato del cluster E l'allineamento dei checksum. Un cluster che
    // si dichiara in sync ma ha checksum divergenti è il caso che conta, ed è
    // il motivo per cui il service li chiede insieme.
    const h = (ha && ha.data) || {};
    const hstat = (h.status && (h.status.mode || h.status.group_name)) || null;
    const csums = Array.isArray(h.checksums) ? h.checksums : null;
    const inSync = csums && csums.length > 1
        ? csums.every(c => JSON.stringify((c || {}).checksum) === JSON.stringify((csums[0] || {}).checksum))
        : null;
    const haBody = !hstat
        ? plain(null)
        : FGT_FMT.badge(hstat) + (inSync === null ? '' :
            ` ${FGT_FMT.badge(inSync ? (en ? 'in-sync' : 'in-sync') : 'out-of-sync')}`);

    host.style.display = 'grid';
    host.style.gridTemplateColumns = 'repeat(auto-fit, minmax(190px, 1fr))';
    host.style.gap = '12px';
    host.innerHTML =
        tile('Hostname', plain(s.hostname)) +
        tile('FortiOS', plain(s.version)) +
        tile('HA', haBody) +
        tile('CPU', gauge(u.cpu)) +
        tile(en ? 'Memory' : 'Memoria', gauge(u.mem)) +
        tile(en ? 'Disk' : 'Disco', gauge(u.disk)) +
        tile(en ? 'Sessions' : 'Sessioni', plain(num(u.session)));

    loadFgtDataset('resources');
    loadFgtDataset('ha');
}

// Delegated and static event listeners
document.getElementById('fgtTargetSelect')?.addEventListener('change', onFgtTargetSelectChange);
document.getElementById('btnFgtManageTargets')?.addEventListener('click', openFgtManageModal);

document.getElementById('fgtSubtabBar')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-fgt-view]');
    if (btn && btn.dataset.fgtView) fgtSwitchView(btn.dataset.fgtView);
});

document.getElementById('tab-fortigate')?.addEventListener('click', (e) => {
    const pill = e.target.closest('.ca-pill[data-fgt-section]');
    if (pill && pill.dataset.fgtSection && pill.dataset.fgtPill) {
        fgtPickView(pill.dataset.fgtSection, pill.dataset.fgtPill);
        return;
    }
    if (e.target.closest('[data-action="fgt-refresh"]')) {
        refreshFgtView();
        return;
    }
    const winBtn = e.target.closest('[data-fgt-res-win]');
    if (winBtn && winBtn.dataset.fgtResWin) {
        fgtSetResWindow(winBtn.dataset.fgtResWin);
        return;
    }
    const row = e.target.closest('.fgt-row[data-fgt-key]');
    if (row && row.dataset.fgtKey && row.dataset.fgtIdx != null) {
        fgtToggleRow(row.dataset.fgtKey, Number(row.dataset.fgtIdx), row);
        return;
    }
});

document.getElementById('tab-fortigate')?.addEventListener('input', (e) => {
    const input = e.target.closest('.fgt-filter-input[data-fgt-dataset]');
    if (input && input.dataset.fgtDataset) {
        renderFgtDataset(input.dataset.fgtDataset);
    }
});

// The <tbody> renderFgtMgrTargets() fills: bind the delegated listener here,
// not to an id that does not exist.
document.getElementById('fgtMgrTableBody')?.addEventListener('click', (e) => {
    const el = e.target.closest('[data-fgt-action]');
    if (!el || !el.dataset.ip) return;
    const action = el.dataset.fgtAction;
    const ip = el.dataset.ip;
    if (action === 'activate-target') activateFgtMgrTarget(ip);
    else if (action === 'test-target') testFgtMgrTarget(ip, el);
    else if (action === 'edit-target') editFgtMgrTarget(ip);
    else if (action === 'delete-target') deleteFgtMgrTarget(ip);
});

document.getElementById('btnFgtLookupRun')?.addEventListener('click', () => loadFgtDataset('policyLookup'));
document.getElementById('btnFgtSessLoad')?.addEventListener('click', () => loadFgtDataset('sessions'));
document.getElementById('btnFgtSessionKill')?.addEventListener('click', fgtKillSessions);
document.getElementById('btnFgtLogLoad')?.addEventListener('click', () => loadFgtDataset('logs'));
document.getElementById('btnFgtDiagRun')?.addEventListener('click', () => loadFgtDataset('clientDiagnosis'));
document.getElementById('btnFgtTokenSave')?.addEventListener('click', saveFgtPrevToken);
document.getElementById('btnFgtTokenRemove')?.addEventListener('click', removeFgtPrevToken);
document.getElementById('btnFgtTokenTest')?.addEventListener('click', testFgtPrevToken);
document.getElementById('btnFgtFullConfigLoad')?.addEventListener('click', () => loadFgtDataset('fullConfig'));

document.getElementById('fgtManageModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'fgtManageModal' || e.target.closest('#btnCloseFgtManage')) {
        closeFgtManageModal();
    }
});
document.getElementById('btnSaveFgtMgrTarget')?.addEventListener('click', saveFgtMgrTarget);
document.getElementById('btnResetFgtMgrForm')?.addEventListener('click', resetFgtMgrForm);

