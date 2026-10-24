// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// static/js/topology.js
// Estratto da templates/dashboard.html: tab-map (Topologia, report Port-Channel),
// tab-map-interactive (mappa vis.js classica + mappa minimalista stile Visio,
// legenda, filtri dispositivi/link, overlay Visio con contenitori Sede e fasci
// Port-Channel/vPC/peer) e tab-categories (Pannello Dispositivi & Categorie,
// classificazione manuale, risoluzione conflitti CDP/LLDP). networkInstance e
// categoriesData vivono qui perche' usati solo da questo modulo.
//
// showPortConfig/closePortConfigModal/openPortInAnalyzer/expandIface e i globali
// caFocusIp/caFocusPort sono stati promossi a static/js/core.js: sono invocati
// anche dal tab MAC-tracker/ARP (ancora inline in dashboard.html) e da
// static/js/config-analyzer.js, quindi non sono esclusivi di questo modulo.

    // La lista adjacency testuale è stata rimossa (non human-readable): il tab
    // mostra solo il report Port-Channel; la topologia vive nella mappa 2D.
    async function loadTopology() {
        const groupSelect = document.getElementById('topologyGroupSelect');
        const selectedGroup = groupSelect ? groupSelect.value : '';
        loadPortchannelReport(selectedGroup);
    }

    // Abbrevia un nome di interfaccia per le etichette compatte sui link
    // (es. "Ethernet0/1" → "Et0/1", "GigabitEthernet1/0/1" → "Gi1/0/1").
    function shortIface(name) {
        if (!name) return '';
        return String(name)
            .replace(/^TenGigabitEthernet/i, 'Te')
            .replace(/^FortyGigabitEthernet/i, 'Fo')
            .replace(/^GigabitEthernet/i, 'Gi')
            .replace(/^FastEthernet/i, 'Fa')
            .replace(/^Ethernet/i, 'Et')
            .replace(/^Port-channel/i, 'Po');
    }

    // Port-channel name on each end of a link. The id often differs between
    // the two devices (Po8 on the core, Po1 on the access switch), and one
    // shared name hid which was which. '?' marks the end whose config is not
    // known: borrowing the other end's name would show a Po that is not there.
    function pcEnds(l) {
        const fallback = l.pc_name ? shortIface(l.pc_name)
            : (l.member_count > 1 ? `LAG ×${l.member_count}` : 'LAG');
        const a = l.local_pc ? shortIface(l.local_pc) : '';
        const b = l.remote_pc ? shortIface(l.remote_pc) : '';
        if (!a && !b) return { local: fallback, remote: fallback, same: true, text: fallback };
        const local = a || '?', remote = b || '?';
        return { local, remote, same: local === remote,
                 text: local === remote ? local : `${local} ⇄ ${remote}` };
    }

    // A mid-cable label cannot say which end is which, so its order does:
    // the device drawn on the left (or above, for a vertical cable) is
    // written first. `s` = {prefix, a, b, same, am?, bm?}, a/am = link source.
    function sideLabel(s, aFirst) {
        const [x, y, xm, ym] = aFirst ? [s.a, s.b, s.am, s.bm] : [s.b, s.a, s.bm, s.am];
        let t = s.prefix + (s.same ? x : `${x} ⇄ ${y}`);
        if (xm && ym) t += `\n${xm} ⇄ ${ym}`;
        return t;
    }

    function aIsLeft(pos, from, to) {
        const a = pos[from], b = pos[to];
        if (!a || !b) return true;
        return Math.abs(b.x - a.x) >= Math.abs(b.y - a.y) ? a.x <= b.x : a.y <= b.y;
    }

    let cachedPortchannelsData = null;
    let cachedTopologyNodes = [];
    // Adiacenze dell'ultima mappa caricata: il pannello laterale ci legge i
    // vicini del nodo scelto (porta locale ⇄ porta remota, Port-Channel).
    let cachedTopologyLinks = [];
    let currentSelectedNodeId = null;

    // Riquadro Port-Channel per switch: aggregati + interfacce membro e interfacce
    // fisiche singole non aggregate (stile elenco).
    async function loadPortchannelReport(selectedGroup) {
        const box = document.getElementById("portchannelReport");
        if (!box) return;
        // Nessun Tenant scelto: non si interroga il backend e non si stampa
        // nulla. Aprire il tab elencando d'ufficio TUTTI i tenant mescolava
        // reti di clienti diversi senza che nessuno l'avesse chiesto.
        if (!selectedGroup) {
            cachedPortchannelsData = null;
            box.innerHTML = `<p style="color:var(--text-muted); font-size:13px;">${escapeHtml(tr('topoChooseATenantTo'))}</p>`;
            return;
        }
        try {
            const res = await apiFetch('/api/portchannels?group=' + encodeURIComponent(selectedGroup));
            if (!res || !res.ok) { box.innerHTML = ''; return; }
            const data = await res.json();
            cachedPortchannelsData = data;
            const devices = (data.devices || []).filter(d => (d.portchannels || []).length);
            if (!devices.length) {
                box.innerHTML = `<p style="color:var(--text-muted); font-size:13px;">${tr('topoNoPortChannelData')}</p>`;
                return;
            }
            const toText = tr('topoTo');
            // backupAgeLabel() sta in core.js: lo stesso dato lo mostra anche il
            // Config Analyzer, e una seconda copia della formula divergerebbe.
            const age = ts => ts ? ` · ${backupAgeLabel(ts)}` : '';
            box.innerHTML = devices.map(d => {
                const pcs = (d.portchannels || []).slice().sort((a,b)=>{
                    const na=parseInt(String(a.name).replace(/\D/g,''))||0, nb=parseInt(String(b.name).replace(/\D/g,''))||0; return na-nb;
                });
                const pcHtml = pcs.length ? pcs.map(po => {
                    const neigh = (po.neighbors && po.neighbors.length)
                        ? `<span style="font-size:11px; color:var(--primary);"> <i class="fa-solid fa-arrow-right-long"></i> ${toText} <strong>${po.neighbors.map(escapeHtml).join(', ')}</strong></span>`
                        : `<span style="font-size:11px; color:var(--text-muted);"> <i class="fa-solid fa-arrow-right-long"></i> ${tr('topoUnknownNeighbor')}</span>`;
                    // Stato operativo. Lo stato VIVO (SNMP) vince sul backup:
                    // descrive adesso, non l'ultimo salvataggio.
                    let stateBadge = '';
                    if (po.live_total) {
                        const ok = po.live_up === po.live_total;
                        const col = ok ? 'var(--lamp-up-ink)' : 'var(--lamp-fault-ink)';
                        stateBadge = `<span title="${tr('topoLiveSnmpState')}" style="font-size:10px; color:${col}; border:1px solid ${col}; border-radius:0; padding:1px 6px; margin-left:6px;"><i class="fa-solid fa-tower-broadcast"></i> ${po.live_up}/${po.live_total} UP</span>`;
                    } else if (po.status === 'up' && !po.issue) {
                        stateBadge = `<span title="${tr('topoAllMembersBundled')}" style="font-size:10px; color:var(--success); border:1px solid var(--success); border-radius:0; padding:1px 6px; margin-left:6px;"><i class="fa-solid fa-circle-check"></i> ${po.up}/${po.total} UP</span>`;
                    } else if (po.issue) {
                        const down = po.status === 'down';
                        stateBadge = `<span title="${escapeHtml(po.issue_msg||'')}" style="font-size:10px; color:${down?'var(--lamp-fault-ink)':'var(--lamp-warn-ink)'}; border:1px solid ${down?'var(--lamp-fault)':'var(--lamp-warn)'}; border-radius:0; padding:1px 6px; margin-left:6px;"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(po.issue_msg || (tr('topoIssue')))}</span>`;
                    }
                    return `<div style="margin-bottom:6px;">
                        <span style="display:inline-block; font-weight:700; color:var(--warning); font-size:12px; min-width:120px;"><i class="fa-solid fa-link"></i> ${escapeHtml(po.name)}</span>
                        <span style="font-family:var(--font-code); font-size:12px;">${(po.members||[]).map(m => {
                            const st = (po.live || {})[m];
                            const shut = (po.shut_members || []).includes(m);
                            const down = shut || (st && String(st.link).toLowerCase() === 'down');
                            const title = shut ? (tr('topoAdministrativelyShut'))
                                : (down ? (tr('topoLinkDown')) : '');
                            // Un membro spento resta membro, ma non compone il
                            // bundle: mostrarlo verde come gli altri fa credere
                            // che l'aggregato sia integro.
                            return `<span style="color:${down ? 'var(--lamp-fault-ink)' : 'var(--lamp-up-ink)'};"${title ? ` title="${escapeHtml(title)}"` : ''}>${escapeHtml(m)}${shut ? ' ⛔' : ''}</span>`;
                        }).join(', ')}</span>
                        <span style="font-size:11px; color:var(--text-muted);"> (${(po.members||[]).length} ${tr('topoMembers')})</span>
                        ${stateBadge}
                        ${neigh}
                    </div>`;
                }).join('')
                    : `<div style="font-size:12px; color:var(--text-muted);">${tr('topoNoPortChannels')}</div>`;
                return `<div style="background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:14px; margin-bottom:12px;">
                    <h4 style="font-size:14px; margin-bottom:10px;"><i class="fa-solid fa-network-wired" style="color:var(--primary);"></i> ${escapeHtml(d.hostname)} <span style="color:var(--text-muted); font-weight:400; font-size:12px;">${escapeHtml(d.ip)} · ${escapeHtml(d.group)}</span>${age(d.backup_ts)}</h4>
                    ${pcHtml}
                </div>`;
            }).join('');
        } catch (e) {
            box.innerHTML = '';
        }
    }

    // Apre/chiude la legenda della mappa su richiesta dell'utente.
    function toggleLegend() {
        const body = document.getElementById("legendBody");
        const btn = document.getElementById("legendToggleBtn");
        if (!body) return;
        const hidden = body.style.display === 'none';
        body.style.display = hidden ? 'flex' : 'none';
        if (btn) btn.innerHTML = `<i class="fa-solid fa-chevron-${hidden ? 'down' : 'up'}"></i>`;
    }

    // --- VIS.JS TOPOLOGY GRAPH VIEW ---

    let networkInstance = null;
    // Piani correnti della vista "A livelli" e Sede a cui si riferiscono: servono
    // al trascinamento verticale, che riassegna il piano del nodo mosso.
    let layeredAssigned = {};
    let layeredGroup = 'all';
    // Membro → gruppo aperto che lo contiene: il doppio click su un membro
    // richiude il suo gruppo.
    let layeredGroupOfChild = {};
    let lastRenderedNodeIds = [];
    let lastNetworkView = null;   // view of the instance being replaced (renderNetwork)
    let viewPositions = {}, viewPosGroup = null;   // view -> {id: {x, y}}, for one site selection

    // Optional names of the hierarchy levels, per site selection:
    // {"<gruppo>": ["", "Core", ...]}. Empty by default: no "Level 1" text.
    let layeredLevelNames = {};
    try { layeredLevelNames = JSON.parse(localStorage.getItem('layeredLevelNames') || '{}'); } catch (e) { layeredLevelNames = {}; }

    // Generatore dinamico di schede SVG ad alta tecnologia per i nodi del network
    // Metadati per tipo di apparato: colore distintivo (feature: colori per tipo
    // di device) ed etichette bilingue. "switch" è il default.
    const DEVICE_TYPE_META = {
        firewall: { color: "#ff6b7c", it: "Firewall",      en: "Firewall" },
        wlc:      { color: "#b76bff", it: "WLC",           en: "WLC" },
        ap:       { color: "#38bdf8", it: "Access Point",  en: "Access Point" },
        router:   { color: "#5ecf8d", it: "Router",        en: "Router" },
        switch:   { color: "#4f8ef7", it: "Switch",        en: "Switch" },
        server:   { color: "#f7b84f", it: "Server",        en: "Server" },
        phone:    { color: "#38d9c0", it: "Telefono IP",   en: "IP Phone" },
        camera:   { color: "#e8a33d", it: "Telecamera IP", en: "IP Camera" },
        pc:       { color: "#a3a3a3", it: "PC",            en: "PC" },
        other:    { color: "#8d9bb0", it: "Altro",         en: "Other" },
    };
    // ===== Vista "A livelli": assegnazione dei piani =====
    // Il tipo di apparato da solo NON basta: core, distribuzione e accesso sono
    // tutti "switch", quindi finivano sulla stessa riga e il disegno restava
    // piatto. Il piano viene dedotto dalla TOPOLOGIA (distanza in salti dalle
    // radici); l'utente lo corregge trascinando il nodo in verticale.
    const TIER_LEVEL = { firewall: 0, router: 1, wlc: 1, switch: 2, ap: 3, server: 3, phone: 4, camera: 4, pc: 4, other: 3 };
    // Radici candidate in ordine di preferenza: chi sta al confine con l'esterno.
    const ROOT_TYPES = ['firewall', 'router'];
    const LAYERED_SEPARATION = 190;   // row pitch: 56px cards, port tags in between, clusters up to ~140px
    const LAYERED_PITCH = 250;        // card centre to card centre on one row (cards ~220px)

    function tierLevel(t) {
        return TIER_LEVEL[t] === undefined ? TIER_LEVEL.other : TIER_LEVEL[t];
    }

    // Override manuali per Sede: {"<gruppo>": {"<id>": livello}}. Stessa forma e
    // stessa persistenza della checklist dispositivi.
    let layeredLevels = {};
    try { layeredLevels = JSON.parse(localStorage.getItem('layeredLevels') || '{}'); } catch (e) { layeredLevels = {}; }
    function saveLayeredLevels() { localStorage.setItem('layeredLevels', JSON.stringify(layeredLevels)); }
    function setLayeredLevel(group, id, level) {
        const m = layeredLevels[group] || (layeredLevels[group] = {});
        m[id] = level;
        saveLayeredLevels();
    }
    function resetLayeredLevels(group) {
        delete layeredLevels[group];
        saveLayeredLevels();
        redrawInteractiveMap();
    }

    // Cores chosen by hand, up to two per location (a core pair):
    // {"<tenant>": {"<zone>": ["<id>", "<id>"]}}. Both views start their rows
    // from them. The deduction starts from the border (firewall/router) or the
    // best connected device; where that is not the real core of a site, the
    // user names it and that site's levels are redone from there.
    let layeredRoots = {};
    try { layeredRoots = JSON.parse(localStorage.getItem('layeredRoots') || '{}'); } catch (e) { layeredRoots = {}; }
    // Older saves: a bare id per tenant, then one id per location.
    const rootsOf = group => {
        const r = layeredRoots[group];
        const m = typeof r === 'string' ? { [zoneKeyOf(r) || '']: r } : (r || {});
        const out = {};
        Object.entries(m).forEach(([z, v]) => { out[z] = (Array.isArray(v) ? v : [v]).filter(Boolean); });
        return out;
    };
    function setLayeredRoots(group, zone, ids) {
        const roots = rootsOf(group);
        const list = [...new Set(ids.filter(Boolean))].slice(0, 2);
        if (list.length) roots[zone] = list; else delete roots[zone];
        // Un piano riassegnato a mano su questo nodo vincerebbe sul suo
        // ruolo di radice, lasciandolo a meta' mappa.
        if (layeredLevels[group] && list.some(id => id in layeredLevels[group])) {
            list.forEach(id => { delete layeredLevels[group][id]; });
            saveLayeredLevels();
        }
        layeredRoots[group] = roots;
        localStorage.setItem('layeredRoots', JSON.stringify(layeredRoots));
        redrawInteractiveMap();
    }

    // "Core" menu in the map toolbar, for both views: per location, a first
    // and a second core picked among its switches and routers.
    function fillMapCoreMenu(nodesData, group) {
        const box = document.getElementById('mapCoreList');
        if (!box) return;
        const roots = rootsOf(group), zones = new Map();
        nodesData.filter(n => n.device_type === 'switch' || n.device_type === 'router').forEach(n => {
            const z = mapZones[n.id] || { key: '', label: '' };
            if (!zones.has(z.key)) zones.set(z.key, { label: z.label, nodes: [] });
            zones.get(z.key).nodes.push(n);
        });
        const many = zones.size > 1;
        const count = document.getElementById('mapCoreCount');
        const picked = Object.values(roots).reduce((t, l) => t + l.length, 0);
        if (count) count.textContent = picked ? `(${picked})` : '';
        if (!zones.size) { box.innerHTML = `<div class="map-core-empty">${escapeHtml(tr('topoCoreNone'))}</div>`; return; }
        box.innerHTML = [...zones.entries()].map(([key, z]) => {
            const sel = roots[key] || [];
            const select = slot => {
                const name = tr(slot ? 'topoCore2For' : 'topoCoreFor', { zone: z.label || '—' });
                const first = slot ? tr('topoCore2None') : tr('topoCoreAuto');
                return `<select class="map-core" data-zone="${attrEsc(key)}" data-slot="${slot}" aria-label="${attrEsc(name)}"${slot && !sel[0] ? ' disabled' : ''}>
                    <option value="">${escapeHtml(first)}</option>${
                    z.nodes.filter(n => !slot || n.id !== sel[0]).map(n => `<option value="${attrEsc(n.id)}"${sel[slot] === n.id ? ' selected' : ''}>${
                        escapeHtml(n.label || n.id)}</option>`).join('')}</select>`;
            };
            return `<div class="map-core-row">${many ? `<span class="map-core-zone">${escapeHtml(z.label || '—')}</span>` : ''}${select(0)}${select(1)}</div>`;
        }).join('');
    }

    // ===== Vista "A livelli": raggruppamento delle foglie =====
    // Otto access point appesi allo stesso switch sono otto riquadri che dicono
    // la stessa cosa. Le foglie dello stesso TIPO sotto lo STESSO padre
    // diventano un riquadro solo; un click lo apre, un doppio click su un
    // membro lo richiude. Solo apparati terminali: switch e router non si
    // raggruppano mai, sono la struttura della mappa.
    const GROUPABLE_TYPES = ['ap', 'phone', 'camera', 'pc', 'server'];
    const GROUP_MIN = 3;
    const GROUP_PREFIX = 'grp:';

    // Gruppi aperti per Sede: {"<gruppo>": ["grp:<padre>:<tipo>", ...]}
    let layeredExpanded = {};
    try { layeredExpanded = JSON.parse(localStorage.getItem('layeredExpanded') || '{}'); } catch (e) { layeredExpanded = {}; }
    function saveLayeredExpanded() { localStorage.setItem('layeredExpanded', JSON.stringify(layeredExpanded)); }
    function toggleLayeredGroup(group, key) {
        const arr = layeredExpanded[group] || (layeredExpanded[group] = []);
        const idx = arr.indexOf(key);
        if (idx === -1) arr.push(key); else arr.splice(idx, 1);
        saveLayeredExpanded();
        redrawInteractiveMap();
    }
    // Free move: cards go anywhere and stay there, per site:
    // {"<site>": {"<id>": {x, y}}}. Off, the automatic layout is back;
    // "Riordina mappa" forgets the site's positions.
    let layeredFree = localStorage.getItem('layeredFree') === '1';
    // Hierarchy-map cable labels: toolbar settings, per-link size flips (a
    // click on a tag) and hand offsets (a drag). Browser-only conveniences.
    const loadTagJson = (k, d) => { try { return JSON.parse(localStorage.getItem(k) || 'null') || d; } catch (e) { return d; } };
    let layeredTagCfg = Object.assign({ size: 'big', form: 'abbr', place: 'auto', lane: true }, loadTagJson('layeredTagCfg', {}));
    let layeredTagFlip = loadTagJson('layeredTagFlip', {});
    let layeredTagAdjust = loadTagJson('layeredTagAdjust', {});
    let layeredTagHits = [];   // rebuilt on every draw: {key, link, x, y, w, h}
    function saveLayeredTags() {
        try {
            localStorage.setItem('layeredTagCfg', JSON.stringify(layeredTagCfg));
            localStorage.setItem('layeredTagFlip', JSON.stringify(layeredTagFlip));
            localStorage.setItem('layeredTagAdjust', JSON.stringify(layeredTagAdjust));
        } catch (e) { /* private window: settings last until reload */ }
    }
    let layeredFreePos = {};
    try { layeredFreePos = JSON.parse(localStorage.getItem('layeredFreePos') || '{}'); } catch (e) { layeredFreePos = {}; }
    function saveLayeredFreePos() { localStorage.setItem('layeredFreePos', JSON.stringify(layeredFreePos)); }
    function collapseAllLayeredGroups(group) {
        delete layeredExpanded[group];
        saveLayeredExpanded();
        redrawInteractiveMap();
    }

    // Sostituisce le foglie raggruppabili con un nodo aggregato. Restituisce i
    // nodi/link da disegnare e, per i gruppi aperti, la mappa membro → gruppo
    // (serve al doppio click per richiudere).
    function groupLayeredLeaves(nodesData, linksData, group) {
        const expanded = new Set(layeredExpanded[group] || []);
        const degree = new Map();
        const firstLink = new Map();
        nodesData.forEach(n => degree.set(n.id, 0));
        linksData.forEach(l => {
            if (!degree.has(l.source) || !degree.has(l.target)) return;
            degree.set(l.source, degree.get(l.source) + 1);
            degree.set(l.target, degree.get(l.target) + 1);
            if (!firstLink.has(l.source)) firstLink.set(l.source, l);
            if (!firstLink.has(l.target)) firstLink.set(l.target, l);
        });

        const buckets = new Map();
        nodesData.forEach(n => {
            if (!GROUPABLE_TYPES.includes(n.device_type) || degree.get(n.id) !== 1) return;
            const l = firstLink.get(n.id);
            const parent = l.source === n.id ? l.target : l.source;
            const key = `${GROUP_PREFIX}${parent}:${n.device_type}`;
            const b = buckets.get(key) || { key, parent, type: n.device_type, members: [] };
            b.members.push(n);
            buckets.set(key, b);
        });

        const groupOfChild = {};
        const collapsed = [];
        buckets.forEach(b => {
            if (b.members.length < GROUP_MIN) return;
            b.members.forEach(m => { groupOfChild[m.id] = b.key; });
            if (!expanded.has(b.key)) collapsed.push(b);
        });
        if (!collapsed.length) return { nodes: nodesData, links: linksData, groupOfChild };

        const hidden = new Set();
        collapsed.forEach(b => b.members.forEach(m => hidden.add(m.id)));
        const nodes = nodesData.filter(n => !hidden.has(n.id));
        const links = linksData.filter(l => !hidden.has(l.source) && !hidden.has(l.target));
        collapsed.forEach(b => {
            const parentNode = nodesData.find(n => n.id === b.parent) || {};
            // Lo stato dell'aggregato è il peggiore dei membri: un gruppo "su"
            // che nasconde un apparato giù sarebbe una bugia.
            const statuses = b.members.map(m => m.status);
            const status = statuses.includes('offline') ? 'offline'
                : (statuses.includes('online') ? 'online' : (statuses[0] || 'discovered'));
            nodes.push({
                id: b.key,
                label: `${b.members.length} × ${deviceTypeLabel(b.type)}`,
                group: parentNode.group,
                status: status,
                device_type: b.type,
                vendor: b.members[0] && b.members[0].vendor,
                is_group: true,
                member_count: b.members.length,
                members: b.members,
            });
            links.push({ source: b.parent, target: b.key, kind: 'group',
                         member_count: b.members.length });
        });
        return { nodes, links, groupOfChild };
    }

    // Analisi della configurazione per IP: una sola chiamata per apparato, il
    // risultato serve solo a riempire la sezione VLAN del pannello.
    const drawerAnalysisCache = new Map();
    let drawerFetchToken = 0;

    function renderDrawerPortChannels(ip, hostname, topNode) {
        const pcListEl = document.getElementById('drawerPortChannelList');
        if (!pcListEl) return;
        let pcItems = [];
        if (cachedPortchannelsData && cachedPortchannelsData.devices) {
            const pcDev = cachedPortchannelsData.devices.find(d => d.ip === ip || d.hostname === hostname);
            if (pcDev && pcDev.portchannels && pcDev.portchannels.length) pcItems = pcDev.portchannels;
        }
        if (!pcItems.length && topNode.portchannels && topNode.portchannels.length) {
            pcItems = topNode.portchannels;
        }
        if (!pcItems.length) {
            // Gli aggregati che la mappa conosce dai link valgono comunque:
            // meglio dire "Po1 verso X" che "nessun Port-Channel".
            pcItems = (cachedTopologyLinks || [])
                .filter(l => l.is_portchannel && (l.source === topNode.id || l.target === topNode.id))
                .map(l => {
                    const mine = l.source === topNode.id;
                    const other = (cachedTopologyNodes || []).find(n => n.id === (mine ? l.target : l.source));
                    const ends = pcEnds(l);
                    const theirs = mine ? ends.remote : ends.local;
                    const neighbor = (other && other.label) || (mine ? l.target : l.source);
                    return {
                        // This device's own Po, and the neighbour's next to its name.
                        name: mine ? ends.local : ends.remote,
                        members: (mine ? l.local_ports : l.remote_ports) || [],
                        neighbor: ends.same ? neighbor : `${neighbor} (${theirs})`,
                    };
                });
        }
        const pcCountEl = document.getElementById('drawerPortChannelCount');
        if (pcCountEl) pcCountEl.textContent = pcItems.length ? `(${pcItems.length})` : '';
        if (!pcItems.length) {
            const noPcTxt = tr('topoNoPortChannelsConfigured');
            pcListEl.innerHTML = `<div style="font-size:12px; color:var(--text-muted);">${escapeHtml(noPcTxt)}</div>`;
            return;
        }
        const membersTxt = tr('topoMembers2');
        const towardTxt = tr('topoToward');
        pcListEl.innerHTML = pcItems.map(pc => {
            const members = (pc.members || pc.interfaces || []).map(shortIface).join(', ') || '—';
            const neigh = (pc.neighbors && pc.neighbors.length) ? pc.neighbors.join(', ') : (pc.neighbor || '—');
            // Lo stato dal vivo, quando il report ce l'ha: "2/2 su".
            const live = (pc.live_total ? `${pc.live_up}/${pc.live_total} ${tr('topoUp')}` : 'LACP ACTIVE');
            const allUp = !pc.live_total || pc.live_up === pc.live_total;
            return `<div class="drawer-list-item">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                    <strong style="color:var(--primary); font-family:var(--font-data); font-size:12.5px;">${escapeHtml(shortIface(pc.name || 'Po'))}</strong>
                    <span class="badge badge-${allUp ? 'success' : 'danger'}" style="font-size:10px;">${escapeHtml(live)}</span>
                </div>
                <div style="font-size:11.5px; color:var(--text-muted);">
                    <span>${membersTxt}: <code style="font-size:11px;">${escapeHtml(members)}</code></span>
                </div>
                ${neigh !== '—' ? `<div style="font-size:11.5px; color:var(--text-muted); margin-top:2px;">
                    <span>${towardTxt}: <strong>${escapeHtml(neigh)}</strong></span>
                </div>` : ''}
            </div>`;
        }).join('');
    }

    // "GigabitEthernet1/0/4" e "Gi1/0/4" sono la stessa porta: il nome della
    // config e quello annunciato da CDP/LLDP vanno confrontati abbreviati.
    function ifaceKey(name) {
        return shortIface(String(name || '')).toLowerCase().replace(/\s+/g, '');
    }

    // VLAN di una porta di accesso/trunk, dalla config dello switch che la
    // ospita: è così che si sa in quale VLAN vive un apparato che una config
    // propria non ce l'ha (access point, telefono, telecamera).
    function vlansFromSwitchPort(analysis, portName) {
        if (!analysis || !portName) return [];
        const key = ifaceKey(portName);
        const iface = (analysis.interfaces || []).find(i => ifaceKey(i.name) === key);
        if (!iface) return [];
        const tags = [];
        if (iface.access_vlan) tags.push(`${iface.access_vlan} (access)`);
        if (iface.voice_vlan) tags.push(`${iface.voice_vlan} (voice)`);
        if (iface.trunk_native) tags.push(`${iface.trunk_native} (native)`);
        String(iface.trunk_allowed || '').split(',')
            .map(v => v.trim()).filter(Boolean)
            .forEach(v => tags.push(v));
        return tags;
    }

    function renderDrawerVlans(ip, topNode, dev, analysis, fromPort) {
        const vlanEl = document.getElementById('drawerVlanTags');
        if (!vlanEl) return;
        let tags = [];
        let source = '';
        if (analysis && Array.isArray(analysis.vlans) && analysis.vlans.length) {
            // "10 (Data)" — id e nome dalla configurazione; l'SVI marca le VLAN
            // che questo apparato instrada, non solo commuta.
            tags = analysis.vlans.map(v => `${v.id}${v.name ? ` (${v.name})` : ''}${v.svi ? ' ⇢' : ''}`);
        }
        if (!tags.length && fromPort && fromPort.tags.length) {
            tags = fromPort.tags;
            source = `${tr('topoFrom')} ${fromPort.neighbor} · ${shortIface(fromPort.port)}`;
        }
        if (!tags.length && Array.isArray(topNode.vlans) && topNode.vlans.length) {
            tags = topNode.vlans;
        }
        if (!tags.length && dev.VLANs) {
            tags = Array.isArray(dev.VLANs) ? dev.VLANs : String(dev.VLANs).split(',').map(s => s.trim()).filter(Boolean);
        }
        if (!tags.length && topNode.mgmt_vlan) tags = [`${topNode.mgmt_vlan} (mgmt)`];
        if (!tags.length && topNode.vtp_domain) tags = [`VTP: ${topNode.vtp_domain}`];
        vlanEl.innerHTML = (tags.length
            ? tags.map(v => `<span class="drawer-tag">${escapeHtml(String(v))}</span>`).join('')
            : `<span style="font-size:12px; color:var(--text-muted);">${escapeHtml(tr('topoDefaultTrunk'))}</span>`)
            + (source ? `<div style="width:100%; font-size:11px; color:var(--text-muted); margin-top:4px;">${escapeHtml(source)}</div>` : '');
    }

    // Riempie le due sezioni che dipendono dal backend. Il token evita che la
    // risposta di un nodo finisca nel pannello di un altro nodo scelto nel
    // frattempo.
    async function fillDrawerFromBackend(nodeId, ip, hostname, topNode, dev) {
        const token = ++drawerFetchToken;
        const stillCurrent = () => token === drawerFetchToken && currentSelectedNodeId === nodeId;

        if (!cachedPortchannelsData) {
            const sel = document.getElementById('interactiveGroupSelect');
            try {
                const res = await apiFetch('/api/portchannels?group=' + encodeURIComponent(sel ? sel.value : 'all'));
                if (res && res.ok) cachedPortchannelsData = await res.json();
            } catch (_) {}
            if (stillCurrent()) renderDrawerPortChannels(ip, hostname, topNode);
        }

        // Le VLAN si leggono dalla configurazione salvata.
        const analysis = await fetchAnalysis(ip);
        if (analysis && (analysis.vlans || []).length) {
            if (stillCurrent()) renderDrawerVlans(ip, topNode, dev, analysis);
            return;
        }

        // Un access point (o un telefono, o una telecamera) una config non ce
        // l'ha: le sue VLAN sono scritte sulla porta dello switch che lo
        // alimenta, ed è quella che va letta.
        const uplink = (cachedTopologyLinks || [])
            .filter(l => l.source === nodeId || l.target === nodeId)
            .map(l => {
                const mine = l.source === nodeId;
                const otherId = mine ? l.target : l.source;
                const ports = (mine ? l.remote_ports : l.local_ports) || [mine ? l.remote_port : l.local_port];
                return { otherId, port: (ports || []).filter(Boolean)[0] };
            })
            .find(u => u.port && /^\d{1,3}(\.\d{1,3}){3}$/.test(u.otherId));
        if (!uplink) return;
        const upAnalysis = await fetchAnalysis(uplink.otherId);
        const tags = vlansFromSwitchPort(upAnalysis, uplink.port);
        if (!tags.length || !stillCurrent()) return;
        const other = (cachedTopologyNodes || []).find(n => n.id === uplink.otherId);
        renderDrawerVlans(ip, topNode, dev, null,
                          { tags, neighbor: (other && other.label) || uplink.otherId, port: uplink.port });
    }

    // In cache va la PROMESSA, non il risultato: due click ravvicinati sullo
    // stesso nodo facevano ripartire due volte l'analisi del backup lato
    // server, perché il risultato arrivava solo dopo l'await.
    function fetchAnalysis(ip) {
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return Promise.resolve(null);
        let pending = drawerAnalysisCache.get(ip);
        if (!pending) {
            pending = apiFetch('/api/config-analyzer/' + encodeURIComponent(ip))
                .then(res => (res && res.ok) ? res.json() : null)
                .catch(() => null);
            drawerAnalysisCache.set(ip, pending);
        }
        return pending;
    }

    // Tooltip dell'aggregato: i membri, con il loro indirizzo quando c'è.
    function groupTooltip(n) {
        const container = document.createElement("div");
        const rows = (n.members || []).map(m => {
            const addr = m.display_ip || (String(m.id).includes('.') ? m.id : '');
            return `<div style="font-size:11px; color:var(--text-muted);">${escapeHtml(m.label || m.id)}${addr ? ` · ${escapeHtml(addr)}` : ''}</div>`;
        }).join('');
        container.innerHTML = `<div style="background:var(--surface-2); border:1px solid var(--border); padding:10px 12px; max-width:260px;">
            <div style="font-weight:700; font-size:12px; margin-bottom:6px;">${escapeHtml(n.label)}</div>
            ${rows}
            <div style="font-size:10.5px; color:var(--text-muted); margin-top:6px;">${escapeHtml(tr('topoClickToExpandDouble'))}</div>
        </div>`;
        return container;
    }

    // Piano di ogni nodo: BFS dalle radici (firewall, poi router, altrimenti il
    // nodo con più adiacenze). Chi resta irraggiungibile ricade sul tipo di
    // apparato. Gli override dell'utente vincono su tutto.
    function computeLayeredLevels(nodesData, linksData, group) {
        const adj = new Map();
        nodesData.forEach(n => adj.set(n.id, []));
        linksData.forEach(l => {
            // A cable between two locations (a WAN uplink, a discovered device
            // seen from both sides) does not make one site hang off the other.
            if (adj.has(l.source) && adj.has(l.target) && zoneKeyOf(l.source) === zoneKeyOf(l.target)) {
                adj.get(l.source).push(l.target);
                adj.get(l.target).push(l.source);
            }
        });
        // Cores chosen by hand, up to two per location (older saves: a bare id,
        // or one id per location).
        const chosen = layeredRoots[group];
        const picked = new Set([].concat(...(typeof chosen === 'string' ? [chosen] : Object.values(chosen || {}))));
        const depth = new Map();
        const walk = start => {
            let frontier = start, d = 0;
            while (frontier.length) {
                const next = [];
                frontier.forEach(id => {
                    if (depth.has(id)) return;
                    depth.set(id, d);
                    adj.get(id).forEach(nb => { if (!depth.has(nb)) next.push(nb); });
                });
                frontier = next;
                d++;
            }
        };
        // Every connected part (a location, once the cables between locations
        // are set aside) gets its own root: the core chosen by hand for it,
        // else its border devices (firewall/router), else its best connected
        // one. A lone device keeps its per-type tier.
        for (const n of nodesData) {
            if (depth.has(n.id) || !adj.get(n.id).length) continue;
            const part = [], seen = new Set([n.id]), stack = [n.id];
            while (stack.length) {
                const id = stack.pop();
                part.push(id);
                adj.get(id).forEach(nb => { if (!seen.has(nb)) { seen.add(nb); stack.push(nb); } });
            }
            const typeOf = new Map(nodesData.map(x => [x.id, x.device_type]));
            let r = part.filter(id => picked.has(id));
            for (const t of ROOT_TYPES) {
                if (r.length) break;
                r = part.filter(id => typeOf.get(id) === t);
            }
            if (!r.length) r = [part.slice().sort((a, b) => adj.get(b).length - adj.get(a).length)[0]];
            walk(r);
        }
        const overrides = layeredLevels[group] || {};
        const levels = {};
        nodesData.forEach(n => {
            levels[n.id] = overrides[n.id] !== undefined
                ? overrides[n.id]
                : (depth.has(n.id) ? depth.get(n.id) : tierLevel(n.device_type));
        });
        return levels;
    }
    function deviceTypeMeta(t) { return DEVICE_TYPE_META[t] || DEVICE_TYPE_META.other; }
    function deviceTypeLabel(t) { const m = deviceTypeMeta(t); return currentLang === 'en' ? m.en : m.it; }

    // Colore stabile per dominio VTP (feature: range dominio VTP).
    const VTP_PALETTE = ["#b76bff","#4f8ef7","#3be188","#ffb84d","#ff6b7c","#38d9c0","#f7b84f","#8d6bff","#e879f9","#22d3ee"];
    function vtpDomainColor(domain) {
        if (!domain) return "#5a6473";
        let h = 0;
        for (let i = 0; i < domain.length; i++) h = (h * 31 + domain.charCodeAt(i)) >>> 0;
        return VTP_PALETTE[h % VTP_PALETTE.length];
    }

    // Categorie di apparato da mostrare sulla mappa (persistite). Default: solo
    // infrastruttura (switch/router/firewall/wlc); il resto si abilita a scelta.
    const MAP_DEFAULT_CATS = ['switch', 'router', 'firewall', 'wlc'];
    let mapCatVis;
    try { mapCatVis = JSON.parse(localStorage.getItem('mapCatVis')); } catch (e) { mapCatVis = null; }
    if (!mapCatVis || typeof mapCatVis !== 'object') {
        mapCatVis = {};
        Object.keys(DEVICE_TYPE_META).forEach(k => { mapCatVis[k] = MAP_DEFAULT_CATS.includes(k); });
    }
    function isMapCatVisible(c) {
        // Categorie note (DEVICE_TYPE_META) sono sempre seminate in mapCatVis.
        // Le categorie dinamiche (custom o "client") non ancora viste vengono
        // trattate come "other": nascoste finché l'utente non le abilita, ma
        // comunque presenti/gestibili nel menu una volta apparse in mappa.
        if (Object.prototype.hasOwnProperty.call(mapCatVis, c)) return mapCatVis[c] !== false;
        return false;
    }
    function toggleMapCat(cat, on) {
        mapCatVis[cat] = on;
        localStorage.setItem('mapCatVis', JSON.stringify(mapCatVis));
        loadInteractiveMap();
    }
    // Metadati (colore + etichetta) per una categoria di mappa, incluse quelle
    // dinamiche non presenti in DEVICE_TYPE_META (es. "client" o categorie
    // custom create dall'utente).
    function mapCatMeta(k) {
        if (DEVICE_TYPE_META[k]) return DEVICE_TYPE_META[k];
        if (k === 'client') return { color: DEVICE_TYPE_META.other.color, it: i18n.it.devTypeClient, en: i18n.en.devTypeClient };
        return { color: DEVICE_TYPE_META.other.color, it: k, en: k };
    }
    function mapCatLabel(k) { const m = mapCatMeta(k); return currentLang === 'en' ? m.en : m.it; }
    function renderMapCatMenu(nodesData) {
        const box = document.getElementById('mapCatList');
        if (!box) return;
        // Menu = categorie built-in + qualsiasi device_type dinamico presente
        // nei nodi correnti (custom category, "client", ecc.), così anche
        // queste diventano filtrabili invece di restare sempre visibili.
        const cats = Object.keys(DEVICE_TYPE_META);
        (nodesData || []).forEach(n => {
            if (n.device_type && !cats.includes(n.device_type)) cats.push(n.device_type);
        });
        box.innerHTML = cats.map(k => `
            <label style="display:flex; align-items:center; gap:8px; font-size:12px; padding:3px 0; cursor:pointer; color:var(--text);">
                <input type="checkbox" ${isMapCatVisible(k)?'checked':''} data-action="toggle-map-cat" data-k="${escapeHtml(k)}" style="accent-color:var(--primary);">
                <span style="display:inline-block; width:10px; height:10px; border-radius:0; background:${mapCatMeta(k).color};"></span>
                ${mapCatLabel(k)}
            </label>`).join('');
    }

    document.getElementById('mapCatList')?.addEventListener('change', (e) => {
        const cb = e.target.closest('input[data-action="toggle-map-cat"]');
        if (cb && cb.dataset.k) {
            toggleMapCat(cb.dataset.k, cb.checked);
        }
    });

    // Costruisce la legenda dei colori per tipo di apparato sotto la mappa.
    function renderDeviceTypeLegend() {
        const box = document.getElementById("deviceTypeLegend");
        if (!box) return;
        box.innerHTML = Object.keys(DEVICE_TYPE_META).map(t => {
            const m = DEVICE_TYPE_META[t];
            return `<div class="legend-item"><span style="width:12px;height:12px;border-radius:0;background:${m.color};display:inline-block;"></span><span>${deviceTypeLabel(t)}</span></div>`;
        }).join("");
    }

    // ===== Stack (StackWise & co.) =====
    // Il badge arriva dal backend su ogni nodo come n.redundancy (vedi
    // redundancy/service.py device_redundancy_badge). Testo unico riusato da
    // mappa classica, mappa minimal, tooltip e tab Dispositivi.
    const STACK_COLOR = '#ff8c42';

    function nodeStack(n) {
        const r = n && n.redundancy;
        return (r && r.type === 'stack') ? r : null;
    }

    // "2 × Cisco WS-C3850-24XS-S in STACK" — conteggio e modello dai dati.
    function stackLine(stack, vendorTxt, fallbackModel) {
        const parts = [vendorTxt, stack.model || fallbackModel || ''].filter(Boolean).join(' ').trim();
        const n = stack.member_count;
        if (!parts) return tr('topoUnitsInStack', {n: n});
        return `${n} × ${parts} in STACK`;
    }

    // Node state → colours and text, read from the active theme tokens:
    // the SVG is painted on canvas and cannot resolve var(--...).
    function nodeStatusMeta(status, isBoundary) {
        const lamp = k => ({ color: cssVar(`--lamp-${k}-ink`, '#93a0a8'), glow: cssVar(`--lamp-${k}`, '#6c7a83') });
        if (isBoundary) return { color: cssVar('--text-soft', '#909ba2'), glow: 'transparent', text: tr('topoExternal'), problem: false };
        if (status === 'online')      return { ...lamp('up'),    text: 'ONLINE',   problem: false };
        if (status === 'offline')     return { ...lamp('fault'), text: 'OFFLINE',  problem: true };
        if (status === 'auth_failed') return { ...lamp('warn'),  text: 'AUTH ERR', problem: true };
        if (status === 'discovered')  return { ...lamp('idle'),  text: tr('topoDiscovered'), problem: false };
        // Bastion-probe device: the SSH bastion tunnel carries no ICMP, so
        // reachability is not measurable — never paint it as the red
        // "offline" fault lamp, that would be a false down.
        if (status === 'manual')      return { ...lamp('idle'),  text: tr('devStManual'), problem: false };
        if (status === 'unknown')     return { ...lamp('idle'),  text: tr('mapStatusUnknown'), problem: false };
        return { ...lamp('idle'), text: 'OFFLINE', problem: false };
    }

    // Vector icon (viewBox 24) for each device type.
    function nodeIconSvg(deviceType, typeColor) {
        let iconSvg = "";
        if (deviceType === "router") {
            // Icona router
            iconSvg = `<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" fill="${typeColor}"/>`;
        } else if (deviceType === "ap") {
            // Icona Access Point (Wi-Fi)
            iconSvg = `<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15.92c-.32.05-.65.08-1 .08s-.68-.03-1-.08v-2.12c.32.08.65.12 1 .12s.68-.04 1-.12v2.12zm0-4.22c-.32.12-.65.18-1 .18s-.68-.06-1-.18v-3.8c.32.18.65.28 1 .28s.68-.1 1-.28v3.8zm0-5.8c-.32.22-.65.34-1 .34s-.68-.12-1-.34V4.18c.32.28.65.44 1 .44s.68-.16 1-.44v3.28z" fill="${typeColor}"/>`;
        } else if (deviceType === "wlc") {
            // Icona WLC (controller wireless: tower + base)
            iconSvg = `<path d="M12 8a2 2 0 0 0-2 2c0 .74.4 1.38 1 1.72V21h2v-9.28c.6-.34 1-.98 1-1.72a2 2 0 0 0-2-2zM7.05 6.05 5.64 4.64a9 9 0 0 0 0 10.72l1.41-1.41a7 7 0 0 1 0-7.9zm9.9 0a7 7 0 0 1 0 7.9l1.41 1.41a9 9 0 0 0 0-10.72l-1.41 1.41zM4.46 3.46 3.05 2.05a13 13 0 0 0 0 16.9l1.41-1.41a11 11 0 0 1 0-14.08zm16.49-1.41-1.41 1.41a11 11 0 0 1 0 14.08l1.41 1.41a13 13 0 0 0 0-16.9z" fill="${typeColor}"/>`;
        } else if (deviceType === "firewall") {
            // Icona Firewall (muro di mattoni + scudo)
            iconSvg = `<path d="M3 3h18v4H3V3zm0 6h6v4H3V9zm8 0h10v4H11V9zM3 15h10v4H3v-4zm12 0h6v4h-6v-4z" fill="${typeColor}"/>`;
        } else if (deviceType === "server") {
            // Icona Server 2U Rack
            iconSvg = `<path d="M19 13H5c-1.1 0-2 .9-2 2v3c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2v-3c0-1.1-.9-2-2-2zm-8 4H5v-2h6v2zm8 0h-2v-2h2v2zm0-10H5c-1.1 0-2 .9-2 2v3c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V9c0-1.1-.9-2-2-2zm-8 4H5V9h6v2zm8 0h-2V9h2v2z" fill="${typeColor}"/>`;
        } else if (deviceType === "phone") {
            // Icona Telefono IP
            iconSvg = `<path d="M20 15.5c-1.2 0-2.4-.2-3.6-.6-.3-.1-.7 0-1 .2l-2.2 2.2c-2.8-1.4-5.1-3.8-6.6-6.6l2.2-2.2c.3-.3.4-.7.2-1-.4-1.2-.6-2.4-.6-3.6 0-.6-.4-1-1-1H3.5c-.6 0-1 .4-1 1C2.5 17 7 21.5 16.5 21.5c.6 0 1-.4 1-1V16.5c0-.6-.4-1-1-1z" fill="${typeColor}"/>`;
        } else if (deviceType === "camera") {
            // Icona Telecamera IP (corpo + obiettivo)
            iconSvg = `<path d="M4 6h11a2 2 0 0 1 2 2v1.6l4-2.4v9.6l-4-2.4V17a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2zm5.5 3a3.5 3.5 0 1 0 0 7 3.5 3.5 0 0 0 0-7z" fill="${typeColor}"/>`;
        } else if (deviceType === "pc") {
            // Icona Workstation PC
            iconSvg = `<path d="M21 2H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h7l-2 3v1h8v-1l-2-3h7c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 12H3V4h18v10z" fill="${typeColor}"/>`;
        } else {
            // Icona Switch rack standard
            iconSvg = `<path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6zm3 2h2v2H7V8zm0 4h2v2H7v-2zm4-4h2v2h-2V8zm0 4h2v2h-2v-2zm4-4h2v2h-2V8zm0 4h2v2h-2v-2z" fill="${typeColor}"/>`;
        }

        return iconSvg;
    }

    // System fonts: an SVG image drawn on canvas cannot load the page fonts.
    const SVG_FONT = 'Segoe UI, Roboto, Helvetica, Arial, sans-serif';
    const SVG_MONO = 'Consolas, Menlo, monospace';

    // Classic card height: 62px, plus 20px per STACK/VTP band.
    function classicCardHeight(bands) { return 62 + (bands ? 20 * bands + 2 : 0); }

    // Classic card: type chip, name, address and state in words. Flat: the
    // old gradient, shadow and pair of badges took room without saying more.
    // The border turns to the state colour only when something is wrong.
    function createNodeSvg(label, ip, deviceType, status, isBoundary, vendor, vtp, stack, model) {
        const st = nodeStatusMeta(status, isBoundary);
        const typeColor = deviceTypeMeta(deviceType).color;
        const muted = cssVar('--text-muted', '#94a3b8');
        vtp = vtp || {};
        let border = cssVar('--border', '#233245');
        const bands = [];
        if (stack) {
            bands.push({ color: STACK_COLOR, text: `STACK ×${stack.member_count}${stack.model ? ' · ' + stack.model : ''}`.slice(0, 34) });
        }
        if (vtp.showDomain && vtp.domain) {
            const dcol = vtpDomainColor(vtp.domain);
            border = dcol;
            const dEsc = String(vtp.domain).slice(0, 24);
            const modeEsc = vtp.mode ? String(vtp.mode).toLowerCase() : '';
            bands.push({ color: dcol, text: `VTP: ${(modeEsc ? `${dEsc} · ${modeEsc}` : dEsc).slice(0, 30)}` });
        }
        if (st.problem) border = st.color;
        const cardH = classicCardHeight(bands.length);
        const bandsSvg = bands.map((b, i) => {
            const y = 62 + 20 * i;
            return `<rect x="12" y="${y}" width="196" height="15" rx="4" fill="${b.color}" fill-opacity="0.13" stroke="${b.color}" stroke-opacity="0.45"/>
          <text x="110" y="${y + 10.5}" font-family="${SVG_FONT}" font-size="8.5" font-weight="800" fill="${b.color}" text-anchor="middle">${escapeHtml(b.text)}</text>`;
        }).join('');
        const vendorTxt = (vendor && vendor !== 'discovered' ? vendor : tr('topoNeighbor')).toUpperCase();
        // Model under the name when known (the address moves to the state
        // row), otherwise the address there and vendor · type on the right.
        const right = model ? ip : `${vendorTxt} · ${deviceTypeLabel(deviceType)}`.slice(0, 28);
        const second = model
            ? `<text x="48" y="37" font-family="${SVG_FONT}" font-size="10.5" fill="${muted}">${escapeHtml(String(model).slice(0, 26))}</text>`
            : `<text x="48" y="37" font-family="${SVG_MONO}" font-size="10.5" fill="${muted}">${escapeHtml(ip)}</text>`;
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="${cardH}" viewBox="0 0 220 ${cardH}">
          <rect x="2" y="3" width="216" height="${cardH - 4}" rx="10" fill="#000" fill-opacity="0.18"/>
          <rect x="1" y="1" width="218" height="${cardH - 4}" rx="10" fill="${cssVar('--surface', '#121a24')}" stroke="${border}" stroke-width="${st.problem ? 2 : 1}"/>
          <rect x="10" y="10" width="28" height="28" rx="7" fill="${typeColor}" fill-opacity="0.14" stroke="${typeColor}" stroke-opacity="0.55"/>
          <g transform="translate(15, 15) scale(0.75)">${nodeIconSvg(deviceType, typeColor)}</g>
          <text x="48" y="22" font-family="${SVG_FONT}" font-size="13" font-weight="700" fill="${cssVar('--text', '#f1f5f9')}">${escapeHtml(label)}</text>
          ${second}
          <circle cx="15" cy="49" r="3.5" fill="${st.glow}"/>
          <text x="23" y="52.5" font-family="${SVG_FONT}" font-size="9.5" font-weight="700" fill="${st.color}">${escapeHtml(st.text)}</text>
          <text x="208" y="52.5" font-family="${model ? SVG_MONO : SVG_FONT}" font-size="${model ? 9.5 : 8.5}" font-weight="700" letter-spacing="${model ? 0 : 0.4}" fill="${muted}" text-anchor="end">${escapeHtml(right)}</text>
          ${bandsSvg}
        </svg>`;
        return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
    }

    // Collapsed group of leaves (layered view): one dot per member, red when
    // it is down, so an offline AP shows without opening the group.
    const CLUSTER_COLS = 8, CLUSTER_MAX = 48;
    function createGroupClusterSvg(n) {
        const members = n.members || [];
        const shown = members.slice(0, CLUSTER_MAX);
        const W = 180, H = 34 + Math.max(1, Math.ceil(shown.length / CLUSTER_COLS)) * 17;
        const typeColor = deviceTypeMeta(n.device_type).color;
        const fault = cssVar('--lamp-fault', '#ef4444'), idle = cssVar('--lamp-idle', '#6c7a83');
        const off = members.filter(m => m.status === 'offline').length;
        const dots = shown.map((m, i) => {
            const fill = m.status === 'offline' ? fault : (m.status === 'online' ? typeColor : idle);
            return `<circle cx="${17 + (i % CLUSTER_COLS) * 19}" cy="${35 + Math.floor(i / CLUSTER_COLS) * 17}" r="6" fill="${fill}" fill-opacity="${m.status === 'offline' ? 1 : 0.7}"/>`;
        }).join('');
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
          <rect x="1" y="1" width="${W - 2}" height="${H - 2}" rx="10" fill="${cssVar('--surface-3', '#1d2a3b')}" fill-opacity="0.6" stroke="${off ? fault : cssVar('--border', '#233245')}"/>
          <text x="10" y="17" font-family="${SVG_FONT}" font-size="11" font-weight="700" fill="${cssVar('--text', '#f1f5f9')}">${escapeHtml(deviceTypeLabel(n.device_type))} ×${members.length}</text>
          ${off ? `<text x="${W - 10}" y="17" font-family="${SVG_MONO}" font-size="9.5" font-weight="700" fill="${fault}" text-anchor="end">${off} OFFLINE</text>` : ''}
          ${dots}
        </svg>`;
        return { image: "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg), size: Math.min(W, H) / 2 };
    }

    // A node's image and vis.js size for the current view. vis.js scales
    // the image so that its short side measures 2 × size.
    function nodeVisual(n, status, vendor, vtp, stack) {
        // Groups of leaves only exist in the hierarchy view.
        if (n.is_group) return createGroupClusterSvg(n);
        const bands = (stack ? 1 : 0) + ((vtp && vtp.showDomain && vtp.domain) ? 1 : 0);
        return { image: createNodeSvg(n.label || String(n.id), String(n.id), n.device_type, status, n.is_boundary, vendor, vtp, stack, stack ? '' : (n.model || n.platform || '')),
                 size: Math.round(classicCardHeight(bands) * 0.45) };
    }

    // Generatore dinamico del Tooltip HTML premium per ciascun apparato (al passaggio del mouse)
    function createNodeTooltip(n, scan, resolvedVendor) {
        let statusLed = "";
        if (n.status === "online") statusLed = `<span style="color: var(--lamp-up-ink); font-weight: bold;">● ONLINE</span>`;
        else if (n.status === "offline") statusLed = `<span style="color: var(--lamp-fault-ink); font-weight: bold;">● OFFLINE</span>`;
        else if (n.status === "auth_failed") statusLed = `<span style="color: var(--lamp-warn-ink); font-weight: bold;">● AUTH FAILED</span>`;
        else if (n.status === "discovered") statusLed = `<span style="color: var(--lamp-idle-ink); font-weight: bold;">● DISCOVERED</span>`;
        else if (n.status === "unknown") statusLed = `<span style="color: var(--lamp-idle-ink); font-weight: bold;">● ${escapeHtml(tr('mapStatusUnknown'))}</span>`;
        
        const firmware = (n.version) ? n.version : ((scan && scan.version) ? scan.version : (tr('topoNotDetectedOffline')));
        const vendorName = (resolvedVendor && resolvedVendor !== 'discovered') ? resolvedVendor : (tr('topoLldpCdpNeighbor'));
        
        const titleText = tr('topoDeviceMetadata');
        const labelIpText = tr('topoIpAddress');
        const labelGroupText = tr('topoTenant');
        const labelStatusText = tr('topoNetworkStatus');

        // IP annunciato via CDP/LLDP diverso dall'IP di management reale: il vicino
        // ha pubblicato l'indirizzo di una SVI (es. Vlan1). Lo mostriamo come nota.
        // Stack: numero di unità fisiche + elenco compatto (ruolo · serial).
        const stackInfo = nodeStack(n);
        const stackRow = stackInfo ? `
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">Stack:</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:${STACK_COLOR};">${escapeHtml(stackLine(stackInfo, '', n.model))}${stackInfo.health === 'degraded' ? ' <i class="fa-solid fa-triangle-exclamation"></i>' : ''}<div style="font-weight: 400; font-size: 10px; color: var(--text-muted); margin-top: 2px;">${(stackInfo.members || []).map(m => escapeHtml(`${m.role || '?'} · ${m.serial || '—'}`)).join('<br>')}</div></td></tr>` : '';

        const reportedRow = (n.reported_ip && n.reported_ip !== n.id) ? `
            <tr style="border: none;"><td style="color: var(--warning); font-size: 11px; padding: 2px 0; border: none; background:none;">${tr('topoAnnouncedIp')}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:var(--warning);" title="${tr('topoCdpLldpAdvertisedA')}">${escapeHtml(n.reported_ip)} <i class="fa-solid fa-triangle-exclamation"></i></td></tr>` : '';

        const htmlString = `
        <div style="font-family: var(--font-main); min-width: 230px; color: var(--text);">
          <div style="font-size: 14px; font-weight: 700; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 6px; color: var(--primary); display: flex; align-items: center; gap: 8px;">
            <i class="fa-solid fa-network-wired"></i> ${titleText}
          </div>
          <table style="width: 100%; border-collapse: collapse; background: transparent;">
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; width: 90px; border: none; background:none;">Hostname:</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:var(--text);">${escapeHtml(n.label)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${labelIpText}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:var(--text);">${escapeHtml(n.status === 'discovered' ? (n.reported_ip || '—') : n.id)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">Vendor:</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; text-transform: uppercase; color:#fff;">${escapeHtml(vendorName)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${labelGroupText}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:var(--text);">${escapeHtml(n.group)}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${labelStatusText}</td><td style="font-size: 11px; padding: 2px 0; border: none; background:none;">${statusLed}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">${tr('topoType')}</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:${deviceTypeMeta(n.device_type).color};">${escapeHtml(deviceTypeLabel(n.device_type))}</td></tr>
            <tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">Firmware:</td><td style="font-size: 11px; padding: 2px 0; border: none; background:none;"><code style="font-family: var(--font-code); color: var(--primary); font-size: 10px;">${escapeHtml(firmware)}</code></td></tr>
            ${(n.vtp_domain || n.vtp_mode) ? `<tr style="border: none;"><td style="color: var(--text-muted); font-size: 11px; padding: 2px 0; border: none; background:none;">VTP:</td><td style="font-weight: 700; font-size: 11px; padding: 2px 0; border: none; background:none; color:${vtpDomainColor(n.vtp_domain)};">${escapeHtml([n.vtp_domain, n.vtp_mode].filter(Boolean).join(' · '))}</td></tr>` : ''}
            ${stackRow}
            ${reportedRow}
          </table>
        </div>
        `;
        const container = document.createElement("div");
        container.innerHTML = htmlString;
        return container;
    }

    // ===== Checklist dispositivi (filtro esplicito per Sede/Gruppo) =====
    // ponytail: storage minimale, solo le ESCLUSIONI (default = tutto visibile),
    // indicizzate per Sede così la scelta non si mescola tra tenant diversi.
    // {"<gruppo>": ["id1","id2", ...]}
    let deviceFilterHidden = {};
    try { deviceFilterHidden = JSON.parse(localStorage.getItem('deviceFilterHidden') || '{}'); } catch (e) { deviceFilterHidden = {}; }
    function saveDeviceFilterHidden() { localStorage.setItem('deviceFilterHidden', JSON.stringify(deviceFilterHidden)); }
    function isDeviceHidden(group, id) {
        const arr = deviceFilterHidden[group];
        return !!(arr && arr.includes(id));
    }
    function toggleDeviceFilter(group, id, hidden) {
        const arr = deviceFilterHidden[group] || (deviceFilterHidden[group] = []);
        const idx = arr.indexOf(id);
        if (hidden && idx === -1) arr.push(id);
        if (!hidden && idx !== -1) arr.splice(idx, 1);
        saveDeviceFilterHidden();
        loadInteractiveMap();
    }
    // Popola la checklist coi dispositivi della Sede selezionata (dati grezzi,
    // prima del filtro per categoria/scoperti: la checklist mostra sempre tutto).
    function renderDeviceFilterMenu(nodesData, group) {
        const box = document.getElementById('deviceFilterList');
        if (!box) return;
        // Solo i dispositivi del Tenant scelto: i nodi "boundary" degli altri
        // tenant restano in mappa ma non compaiono nella checklist. Se il
        // dispositivo è in inventario fa fede il SUO tenant, non quello
        // ereditato via CDP/LLDP dallo switch che lo ha scoperto.
        if (group !== 'all' && Array.isArray(nodesData)) {
            nodesData = nodesData.filter(n => {
                const inv = globalDevices.find(d => d.IP === n.id);
                return (inv ? inv.Group : n.group) === group;
            });
        }
        if (!nodesData || !nodesData.length) {
            box.innerHTML = `<div style="font-size:12px; color:var(--text-muted);">${tr('uiNoDevices')}</div>`;
            return;
        }
        box.innerHTML = nodesData.map(n => `
            <label style="display:flex; align-items:center; gap:8px; padding:3px 0; font-size:12px; cursor:pointer; color:var(--text);">
                <input type="checkbox" ${isDeviceHidden(group, n.id) ? '' : 'checked'} data-action="toggle-device-filter" data-group="${attrEsc(group)}" data-node-id="${attrEsc(n.id)}" style="accent-color:var(--primary);">
                <span>${escapeHtml(n.label || n.id)}</span>
            </label>`).join('');
    }

    document.getElementById('deviceFilterList')?.addEventListener('change', (e) => {
        const cb = e.target.closest('input[data-action="toggle-device-filter"]');
        if (cb && cb.dataset.group && cb.dataset.nodeId) {
            toggleDeviceFilter(cb.dataset.group, cb.dataset.nodeId, !cb.checked);
        }
    });

    // Nessuna Sede scelta: la mappa resta vuota. Disegnare d'ufficio TUTTE le
    // sedi mescolava reti di tenant diversi appena si apriva la tab, oltre a
    // interrogare il backend per dati che nessuno aveva chiesto.
    function showMapPlaceholder() {
        if (networkInstance) { networkInstance.destroy(); networkInstance = null; }
        cachedTopologyNodes = [];
        cachedTopologyLinks = [];
        closeTopologyNodeDrawer();
        const container = document.getElementById("networkGraphContainer");
        if (!container) return;
        container.style.background = '';
        const txt = tr('topoChooseATenantTo2');
        container.innerHTML = `<div style="display:flex; align-items:center; justify-content:center; height:100%; color:var(--text-muted); font-size:14px; gap:8px;"><i class="fa-solid fa-diagram-project"></i>${escapeHtml(txt)}</div>`;
    }

    // Ultimo payload disegnato: aprire un gruppo o cambiare piano è una scelta
    // di disegno, non un dato nuovo. Prima ogni click rifaceva due chiamate al
    // backend e ricostruiva la scheda SVG di ogni nodo.
    let lastMapPayload = null;
    let lastMapGroup = null;
    function redrawInteractiveMap() {
        const sel = document.getElementById('interactiveGroupSelect');
        const same = lastMapPayload && lastMapGroup === (sel ? sel.value : '');
        return loadInteractiveMap({ fromCache: same });
    }

    async function loadInteractiveMap(opts) {
        const groupSelect = document.getElementById('interactiveGroupSelect');
        const selectedGroup = groupSelect ? groupSelect.value : '';
        if (!selectedGroup) { showMapPlaceholder(); return; }
        const fromCache = !!(opts && opts.fromCache) && lastMapPayload
                          && lastMapGroup === selectedGroup;

        // Sync fresh live reachability from ping monitor when available
        try {
            const pmRes = fromCache ? null : await apiFetch('/api/ping-monitor/status');
            if (pmRes && pmRes.ok) {
                const pm = await pmRes.json();
                if (pm.devices && pm.devices.length) {
                    pm.devices.forEach(d => {
                        if (!globalVersions[d.ip]) globalVersions[d.ip] = {};
                        // d.status is the tri-state the ping monitor already computed
                        // server-side: for a bastion-probe device (bastion tunnel, no ICMP)
                        // d.up is null and d.status is 'unknown' — never collapse that
                        // to 'offline', it would paint the map with a false down.
                        globalVersions[d.ip].status = d.status === 'unknown' ? 'unknown' : (d.up ? 'online' : 'offline');
                    });
                }
            }
        } catch (_) {}

        let data = lastMapPayload;
        if (!fromCache) {
            const res = await apiFetch("/api/network-map?group=" + encodeURIComponent(selectedGroup));
            if (!res || !res.ok) return;
            data = await res.json();
            lastMapPayload = data;
            lastMapGroup = selectedGroup;
        }
        cachedTopologyNodes = data.nodes || [];
        cachedTopologyLinks = data.links || [];

        // Stato degli interruttori di filtro/evidenziazione della mappa
        const showVtpDomain    = document.getElementById("toggleVtpDomain")?.checked || false;
        const showDiscovered   = document.getElementById("toggleDiscovered")?.checked || false;

        renderDeviceTypeLegend();
        renderMapCatMenu(data.nodes);
        renderDeviceFilterMenu(data.nodes, selectedGroup);

        // Filtra i nodi: terminali (server/telefoni/PC) e access point sono nascosti
        // di default, lasciando in mappa solo switch e router.
        let filteredNodesData = data.nodes.filter(n => {
            // I dispositivi scoperti (CDP/LLDP) si vedono solo col toggle "Mostra
            // Scoperti". La visibilità per TIPO è governata dal selettore Categorie.
            if (n.status === 'discovered' && !showDiscovered) return false;
            // Esclusione manuale via checklist dispositivi (per Sede/Gruppo).
            if (isDeviceHidden(selectedGroup, n.id)) return false;
            return isMapCatVisible(n.device_type);
        });

        // Mantieni solo i link i cui due estremi sono ancora visibili
        const validNodeIds = new Set(filteredNodesData.map(n => n.id));
        let filteredLinksData = data.links.filter(l => validNodeIds.has(l.source) && validNodeIds.has(l.target));
        mapZones = assignZones(filteredNodesData, filteredLinksData, selectedGroup === 'all');

        // La nuova mappa minimalista riusa gli STESSI dati e filtri: cambia solo la
        // resa grafica. I Port-Channel qui sono visibili di default (etichetta
        // aggregata con le interfacce membro), senza bisogno di alcun interruttore.
        updateMapViewButtons();
        fillMapCoreMenu(filteredNodesData, selectedGroup);
        // Both views: the drawer's "set as core" and the Schema core pair read it.
        layeredGroup = selectedGroup;
        if (getMapView() === 'minimal') {
            const hoverInfo = document.getElementById("toggleMinimalHover")?.checked || false;
            // "Collapsed group": the hierarchy's grouping of leaves (3+ APs
            // under one switch become one box, opened with a click).
            layeredGroupOfChild = {};
            if (schemaApMode() === 'group') {
                const grouped = groupLayeredLeaves(filteredNodesData, filteredLinksData, selectedGroup);
                layeredGroupOfChild = grouped.groupOfChild;
                grouped.nodes.forEach(n => { if (n.is_group) mapZones[n.id] = topoZone(n); });
                filteredNodesData = grouped.nodes;
                filteredLinksData = grouped.links;
            }
            const { nodes, edges, options, bundles, groupsInfo } = buildMinimalGraph(filteredNodesData, filteredLinksData, { showVtpDomain, hoverInfo, group: selectedGroup });
            const hasOverlay = (bundles && bundles.length) || (groupsInfo && groupsInfo.length > 1);
            // Conservati per l'export Visio: il .vsdx replica ESATTAMENTE il
            // disegno dell'overlay (cavi paralleli, etichette porta, pillole).
            minimalOverlayData = { bundles, groupsInfo, nodes };
            // A new map: the focused node may be gone (filter, tenant).
            schemaFocusId = null;
            renderNetwork(nodes, edges, options, MINIMAL_MAP_STYLE.background,
                          hasOverlay ? (ctx => drawMinimalOverlay(ctx, bundles, groupsInfo)) : null);
            return;
        }
        minimalOverlayData = null;

        // Piani della vista "A livelli" (ignorati dalle altre viste). I piani si
        // calcolano sulla topologia VERA, prima di comprimere le foglie: il
        // nodo aggregato eredita poi il piano dei suoi membri.
        layeredGroupOfChild = {};
        {
            layeredAssigned = computeLayeredLevels(filteredNodesData, filteredLinksData, selectedGroup);
            const grouped = groupLayeredLeaves(filteredNodesData, filteredLinksData, selectedGroup);
            layeredGroupOfChild = grouped.groupOfChild;
            grouped.nodes.forEach(n => {
                if (n.is_group) mapZones[n.id] = topoZone(n);
                if (n.is_group) {
                    layeredAssigned[n.id] = Math.min(...n.members.map(m => layeredAssigned[m.id] || 0));
                }
            });
            filteredNodesData = grouped.nodes;
            filteredLinksData = grouped.links;
        }

        // Trasforma nodi filtrati per l'interfaccia interattiva Vis.js
        const nodes = filteredNodesData.map(n => {
            const scan = globalVersions[n.id] || { version: tr('topoNotDetected'), status: n.status };
            const effectiveStatus = (scan && scan.status && scan.status !== 'unknown') ? scan.status : (n.status || 'offline');
            n.status = effectiveStatus;
            
            // Risolve robustamente il vendor sul client confrontando l'IP con l'anagrafica di globalDevices
            const matchedDev = globalDevices.find(d => d.IP === n.id);
            const resolvedVendor = (n.vendor && n.vendor !== 'discovered')
                ? n.vendor
                : (matchedDev && matchedDev.Vendor ? matchedDev.Vendor : 'discovered');

            const vtp = { domain: n.vtp_domain, mode: n.vtp_mode, showDomain: showVtpDomain };
            const stack = nodeStack(n);

            return {
                id: n.id,
                shape: "image",
                // image + size: card, or cluster for a group of leaves.
                ...nodeVisual(n, effectiveStatus, resolvedVendor, vtp, stack),
                // A group's tooltip lists its members: what is inside shows
                // without opening it.
                title: n.is_group ? groupTooltip(n) : createNodeTooltip(n, scan, resolvedVendor),
                labelVal: n.label,
                deviceTypeVal: n.device_type,
                isBoundaryVal: n.is_boundary || false,
                vendorVal: resolvedVendor,
                vtpVal: vtp,
                nodeDataVal: n
            };
        });

        // Trasforma archi filtrati per Vis.js con indicazioni di porta super leggibili ed eleganti
        const edges = filteredLinksData.map(l => {
            // Cavo verso un aggregato di foglie: non è un collegamento fisico,
            // quindi tratteggiato e senza etichette di porta.
            if (l.kind === 'group') {
                return {
                    from: l.source,
                    to: l.target,
                    // The cluster already shows the count.
                    label: '',
                    dashes: [4, 4],
                    color: { color: hexToRgba(cssVar('--text-soft', '#8d9bb0'), 0.55), highlight: cssVar('--text-soft', '#c4bdf7') },
                    width: 1.5,
                    arrows: { to: { enabled: false } },
                    kind: 'group'
                };
            }
            if (l.kind === 'redundancy_heartbeat') {
                return {
                    from: l.source,
                    to: l.target,
                    label: 'HA',
                    dashes: true,
                    physics: false,
                    color: { color: '#f9a825', highlight: '#f9a825' },
                    width: 2,
                    kind: 'redundancy_heartbeat'
                };
            }
            const isPC      = !!l.is_portchannel;

            // Interfacce membro per lato (liste affidabili dal backend)
            const localPorts  = (Array.isArray(l.local_ports)  && l.local_ports.length)  ? l.local_ports  : [l.local_port];
            const remotePorts = (Array.isArray(l.remote_ports) && l.remote_ports.length) ? l.remote_ports : [l.remote_port];

            // Nome dell'aggregato per estremo (Po8 sul core, Po1 sull'accesso),
            // altrimenti "LAG ×N" quando ci sono più link fisici verso lo stesso vicino.
            const ends = pcEnds(l);

            // Interfacce membro compatte: Et0/1+Et0/2 ⇄ Et0/0+Et0/2
            const localMembers  = localPorts.map(shortIface).filter(Boolean).join('+');
            const remoteMembers = remotePorts.map(shortIface).filter(Boolean).join('+');

            const pcBadge = isPC ? `
              <div style="display:inline-flex; align-items:center; gap:6px; font-size:10px; font-weight:700; color:var(--warning); background:color-mix(in srgb, var(--warning) 12%, transparent); border:1px solid color-mix(in srgb, var(--warning) 30%, transparent); padding:2px 7px; border-radius:0; margin-bottom:8px;">
                <i class="fa-solid fa-link"></i> ${tr('topoAggregated')} · ${escapeHtml(ends.text)}${l.member_count > 1 ? ` · ${l.member_count} ${tr('topoMembers')}` : ''}
              </div>` : '';

            // Interfacce membro per lato, con il Port-channel di quel lato.
            const memberRows = (isPC && (localMembers || remoteMembers)) ? `
              <div style="margin-top:8px; border-top:1px solid rgba(255,255,255,0.08); padding-top:6px; font-family:var(--font-code); font-size:10px;">
                <div style="color:var(--text-muted); font-size:9px; text-transform:uppercase; margin-bottom:4px;">${tr('topoMemberInterfaces')}</div>
                <div style="display:flex; justify-content:space-between; gap:10px; padding:1px 0;"><span style="color:var(--text-muted);">${escapeHtml(l.source)}</span><span><b style="color:var(--warning);">${escapeHtml(ends.local)}</b> <span style="color:var(--success);">${escapeHtml(localMembers || '—')}</span></span></div>
                <div style="display:flex; justify-content:space-between; gap:10px; padding:1px 0;"><span style="color:var(--text-muted);">${escapeHtml(l.target)}</span><span><b style="color:var(--warning);">${escapeHtml(ends.remote)}</b> <span style="color:var(--success);">${escapeHtml(remoteMembers || '—')}</span></span></div>
              </div>` : '';

            // Generatore del Tooltip HTML premium al passaggio sul collegamento
            const linkTooltip = `
            <div style="font-family: var(--font-main); min-width: 240px; color: var(--text);">
              <div style="font-size: 13px; font-weight: 700; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 6px; color: var(--primary); display: flex; align-items: center; gap: 8px;">
                <i class="fa-solid fa-circle-nodes"></i> ${tr('topoInterconnectionLink')}
              </div>
              ${pcBadge}
              <div style="display: grid; grid-template-columns: 1fr 30px 1fr; gap: 8px; align-items: center; font-size: 11px; line-height: 1.4;">
                <div>
                  <span style="color: var(--text-muted); font-size: 9px; display: block; text-transform: uppercase; margin-bottom: 2px;">${tr('topoSource')}</span>
                  <strong style="font-size:11px; color:var(--text);">${escapeHtml(l.source)}</strong>
                  <code style="color: var(--success); display: block; font-family: var(--font-code); margin-top: 2px; font-size: 10px;">${escapeHtml(isPC ? (l.pc_name ? shortIface(l.pc_name) : (localMembers || l.local_port)) : l.local_port) || (tr('topoPortNA'))}</code>
                </div>
                <div style="color: var(--primary); font-size: 14px; text-align: center;"><i class="fa-solid fa-right-left"></i></div>
                <div style="text-align: right;">
                  <span style="color: var(--text-muted); font-size: 9px; display: block; text-transform: uppercase; margin-bottom: 2px;">${tr('topoDestination')}</span>
                  <strong style="font-size:11px; color:var(--text);">${escapeHtml(l.target)}</strong>
                  <code style="color: var(--success); display: block; font-family: var(--font-code); margin-top: 2px; font-size: 10px;">${escapeHtml(isPC ? (remoteMembers || l.remote_port) : l.remote_port) || (tr('topoPortNA'))}</code>
                </div>
              </div>
              ${memberRows}
            </div>
            `;
            const container = document.createElement("div");
            container.innerHTML = linkTooltip;

            return {
                from: l.source,
                to: l.target,
                title: container, // HTML Tooltip DOM element
                arrows: { to: { enabled: false } },
                // ponytail: dati "piatti" (no oggetti color vis.js) usati solo dall'export Visio
                // Il colore finisce nel .vsdx: Visio vuole un #RRGGBB, e un
                // "var(--x)" cadeva nel fallback viola di _hex_to_rgb_fraction().
                exportVal: { isPortChannel: isPC, pcEnds: ends, color: isPC ? PC_COPPER : cssVar('--text-soft', '#8d9bb0') }
            };
        });

        // Hierarchy view: vis.js places each level (layeredMapOptions), the
        // cables are drawn by the overlay (bus per parent, one line per Po
        // member), so the vis.js edges only keep tooltip and selection.
        nodes.forEach(nd => { nd.level = layeredAssigned[nd.id] || 0; });
        edges.forEach((e, i) => Object.assign(e, {
            lnk: filteredLinksData[i], label: '', dashes: false, width: 0.0001,
            color: { color: 'rgba(0,0,0,0)', highlight: 'rgba(0,0,0,0)', hover: 'rgba(0,0,0,0)' }
        }));
        renderNetwork(nodes, edges, layeredMapOptions(), '', drawLayeredLinks, drawLayeredColumns);
    }

    // ===== Map view selector (Schema / Hierarchy) =====
    // La scelta è ricordata in localStorage. Entrambe le viste condividono dati,
    // filtri, interruttori, selettore Sede/Categorie e istanza Vis.js.
    // The overview is gone: a saved 'classic' opens the hierarchy, whose
    // free move does what the overview was kept for.
    const MAP_VIEWS = ['minimal', 'layered'];
    let mapViewMode = MAP_VIEWS.includes(localStorage.getItem('mapViewMode')) ? localStorage.getItem('mapViewMode') : 'layered';
    function getMapView() { return mapViewMode; }
    function updateMapViewButtons() {
        const base = 'width:auto; margin:0; padding:5px 12px; border-radius:0; border:1px solid; font-family:inherit; font-size:12px; font-weight:700; cursor:pointer;';
        const on  = base + 'background:var(--cta); color:var(--cta-text); border-color:var(--cta);';
        const off = base + 'background:var(--surface-2); color:var(--text-muted); border-color:var(--border);';
        const m = document.getElementById('mapViewMinimalBtn');
        const l = document.getElementById('mapViewLayeredBtn');
        if (m) m.setAttribute('style', mapViewMode === 'minimal' ? on : off);
        if (l) l.setAttribute('style', mapViewMode === 'layered' ? on : off);
        const lrw = document.getElementById('layeredResetWrap');
        if (lrw) lrw.style.display = mapViewMode === 'layered' ? 'inline-flex' : 'none';
        const fr = document.getElementById('toggleLayeredFree');
        if (fr) fr.checked = layeredFree;
        const ltb = document.getElementById('layeredTidyBtn');
        if (ltb) ltb.style.display = layeredFree ? 'inline-block' : 'none';
        // L'interruttore "Info al passaggio" riguarda solo la nuova mappa.
        const hw = document.getElementById('minimalHoverWrap');
        if (hw) hw.style.display = mapViewMode === 'minimal' ? 'inline-flex' : 'none';
        const tb = document.getElementById('schemaTidyBtn');
        if (tb) tb.style.display = mapViewMode === 'minimal' ? 'inline-block' : 'none';
        const hc = document.getElementById('toggleMinimalHover');
        if (hc) hc.checked = localStorage.getItem('minimalHoverInfo') === '1';
        // Schema readability controls (focus, port labels, wrap, grouped uplinks).
        const srw = document.getElementById('schemaReadWrap');
        if (srw) srw.style.display = mapViewMode === 'minimal' ? 'inline-flex' : 'none';
        syncSchemaReadControls();
        // Color-picker/legenda dei tipi di link: visibile solo sulla nuova mappa.
        const lw = document.getElementById('minimalLegendWrap');
        if (lw) { lw.style.display = mapViewMode === 'minimal' ? 'inline-flex' : 'none'; if (mapViewMode === 'minimal') renderMinimalLegend(); }
        // Gestione categorie personalizzate: visibile solo sulla nuova mappa.
        const cm = document.getElementById('minimalCustomCatMenu');
        if (cm) { cm.style.display = mapViewMode === 'minimal' ? 'inline-block' : 'none'; if (mapViewMode === 'minimal') renderMinimalCustomCatPanel(); }
    }
    function syncSchemaReadControls() {
        const f = /** @type {HTMLInputElement|null} */ (document.getElementById('toggleSchemaFocus'));
        const w = /** @type {HTMLInputElement|null} */ (document.getElementById('toggleSchemaWrap'));
        const g = /** @type {HTMLInputElement|null} */ (document.getElementById('toggleSchemaGroupUplinks'));
        const l = /** @type {HTMLSelectElement|null} */ (document.getElementById('schemaPortLabels'));
        if (f) f.checked = schemaPref('schemaFocus', '1') === '1';
        if (w) w.checked = schemaPref('schemaWrap', '0') === '1';
        if (g) g.checked = schemaPref('schemaGroupUplinks', '0') === '1';
        if (l) l.value = schemaPortLabelMode();
        const ap = /** @type {HTMLSelectElement|null} */ (document.getElementById('schemaApMode'));
        if (ap) ap.value = schemaApMode();
    }
    function schemaPortLabelMode() {
        const v = schemaPref('schemaPortLabels', 'all');
        return v === 'focus' || v === 'none' ? v : 'all';
    }
    // The two presets of the approved preview. Wrapping re-runs the tidy
    // only when it changes, since the tidy drops manual moves.
    const SCHEMA_PRESETS = {
        recommended: { schemaFocus: '1', schemaPortLabels: 'focus', schemaWrap: '1', schemaGroupUplinks: '0' },
        overview:    { schemaFocus: '1', schemaPortLabels: 'none',  schemaWrap: '1', schemaGroupUplinks: '1' },
    };
    function applySchemaPreset(name) {
        const p = SCHEMA_PRESETS[name];
        const wrapChanged = schemaPref('schemaWrap', '0') !== p.schemaWrap;
        Object.entries(p).forEach(([k, v]) => setSchemaPref(k, v));
        syncSchemaReadControls();
        if (wrapChanged) packSchemaRows();
        else if (networkInstance) networkInstance.redraw();
    }
    function setMapView(mode) {
        mapViewMode = MAP_VIEWS.includes(mode) ? mode : 'layered';
        localStorage.setItem('mapViewMode', mapViewMode);
        updateMapViewButtons();
        loadInteractiveMap();
    }

    // Hierarchy view: same cards, data, tooltips and drawer as the overview.
    // vis.js packs each subtree under its parent from the levels we assign;
    // a hand-made row layout spread a large site over a sparse, unreadable
    // width.
    function layeredMapOptions() {
        return {
            layout: { improvedLayout: false, randomSeed: 42, hierarchical: { enabled: true, direction: 'UD', sortMethod: 'directed', levelSeparation: LAYERED_SEPARATION, nodeSpacing: LAYERED_PITCH, treeSpacing: 300, shakeTowards: 'roots' } },
            physics: { enabled: false },
            interaction: { hover: true, hoverConnectedEdges: true, selectConnectedEdges: true, tooltipDelay: 150, dragNodes: true, dragView: true, zoomView: true, multiselect: true },
            nodes: { shadow: { enabled: false } },
            edges: { smooth: false, shadow: { enabled: false } }
        };
    }

    // Crea/ricrea l'istanza Vis.js condivisa e congela il layout a stabilizzazione
    // completata (usata da entrambe le viste).
    function renderNetwork(nodes, edges, options, background, afterDraw, beforeDraw) {
        const container = document.getElementById("networkGraphContainer");
        // Sfondo per-vista: la mappa minimalista usa il bianco, la classica torna
        // allo sfondo scuro definito nel CSS (#networkGraphContainer).
        container.style.background = background || '';

        // --- Conserva le posizioni tra un refresh e l'altro ---------------------
        // Ogni ricaricamento dati (polling triage/scan, cambio tab, toggle) ricrea
        // l'istanza Vis.js. Senza intervento la fisica riparte da zero e i nodi
        // "saltano", perdendo le posizioni trascinate dall'utente. Catturiamo le
        // posizioni correnti PRIMA di distruggere e le riapplichiamo ai nodi
        // omonimi; se TUTTI i nodi sono già noti spegniamo del tutto la fisica così
        // la mappa resta immobile (niente reset). I nodi nuovi mantengono la fisica.
        // Each view keeps its own positions: opened after the hierarchy, the
        // overview used to inherit its rows. The Schema ones also outlive a
        // reload (saved per site in the browser).
        const group = lastMapGroup || '';
        if (viewPosGroup !== group) { viewPositions = {}; viewPosGroup = group; }
        if (networkInstance && lastNetworkView) viewPositions[lastNetworkView] = networkInstance.getPositions();
        const view = getMapView(), hierarchy = view === 'layered';
        const prevPos = viewPositions[view] || (view === 'minimal' ? loadSchemaPositions(group) : null);
        // Hierarchy view: the layout owns y (the level) and the column; only a
        // horizontal drag inside the same row survives a refresh (re-applied
        // after tidyLayeredTree, below).
        if (prevPos && !hierarchy) {
            nodes.forEach(nd => {
                const p = prevPos[nd.id];
                if (p) { nd.x = p.x; nd.y = p.y; }
            });
        }
        lastNetworkView = view;
        const allKnown = !!prevPos && nodes.length > 0 && nodes.every(nd => prevPos[nd.id]);
        if (allKnown) {
            // Clona per non mutare l'oggetto opzioni del chiamante e disattiva fisica.
            options = Object.assign({}, options, { physics: false });
        }

        // Ordine dei nodi disegnati: lo usa la navigazione da tastiera per
        // passare da un apparato al successivo senza toccare il mouse.
        lastRenderedNodeIds = nodes.map(nd => nd.id);
        const graphData = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
        if (networkInstance) networkInstance.destroy();
        networkInstance = new vis.Network(container, graphData, options);
        // Overlay disegnato in coordinate rete (ctx già trasformato da vis.js):
        // usato dalla vista minimalista per i fasci Port-Channel/vPC in stile Visio.
        if (typeof afterDraw === 'function') {
            networkInstance.on('afterDrawing', afterDraw);
        }
        // Zoom bar level: every frame, so wheel, fit and animations all show.
        const zoomLabel = document.getElementById('mapZoomLevel');
        networkInstance.on('afterDrawing', () => {
            const t = Math.round(networkInstance.getScale() * 100) + '%';
            if (zoomLabel && zoomLabel.textContent !== t) zoomLabel.textContent = t;
        });
        // Under nodes and cables: site zones (classic), plane bands (layered).
        if (typeof beforeDraw === 'function') {
            networkInstance.on('beforeDrawing', beforeDraw);
        }
        // Nella nuova mappa i riquadri non possono MAI sovrapporsi: al termine
        // di ogni trascinamento il nodo mosso viene respinto fuori dai riquadri
        // che intersecherebbe (Fix no node overlapping).
        if (getMapView() === 'minimal') {
            networkInstance.on('dragEnd', p => {
                if (p.nodes && p.nodes.length) { resolveNodeOverlaps(p.nodes); saveSchemaPositions(); }
            });
        }
        // Vista "A livelli": trascinare un nodo IN VERTICALE lo sposta di piano e
        // la scelta resta (per Sede). Uno spostamento solo orizzontale non
        // ridisegna nulla, così il nodo resta dove l'utente lo lascia.
        if (getMapView() === 'layered') {
            let dragFrom = null;
            networkInstance.on('dragStart', p => {
                dragFrom = (p.nodes && p.nodes.length)
                    ? networkInstance.getPositions(p.nodes)[p.nodes[0]] : null;
            });
            networkInstance.on('dragEnd', p => {
                // Free move: wherever it lands, no level change, kept per site.
                if (layeredFree) {
                    dragFrom = null;
                    if (!p.nodes || !p.nodes.length) return;
                    const saved = layeredFreePos[layeredGroup] || (layeredFreePos[layeredGroup] = {});
                    Object.assign(saved, networkInstance.getPositions(p.nodes));
                    saveLayeredFreePos();
                    return;
                }
                if (!dragFrom || !p.nodes || !p.nodes.length) return;
                const id = p.nodes[0];
                const to = networkInstance.getPositions([id])[id];
                const steps = Math.round((to.y - dragFrom.y) / LAYERED_SEPARATION);
                const fromY = dragFrom.y;
                dragFrom = null;
                // Same level: back onto its row, keeping the new x.
                if (!steps) { networkInstance.moveNode(id, to.x, fromY); return; }
                setLayeredLevel(layeredGroup, id, Math.max(0, (layeredAssigned[id] || 0) + steps));
                redrawInteractiveMap();
            });
        }
        // Eventi di selezione nodo: apre il pannello ispettore laterale (Node Drawer).
        // Sull'aggregato di foglie il click apre il gruppo invece del pannello:
        // un riquadro "8 × Access Point" non ha un ispettore da mostrare.
        networkInstance.on('selectNode', p => {
            if (!p.nodes || !p.nodes.length) return;
            const id = String(p.nodes[0]);
            if (id.startsWith(GROUP_PREFIX)) {
                schemaRetidy = getMapView() === 'minimal';
                toggleLayeredGroup(layeredGroup, id);
                return;
            }
            openTopologyNodeDrawer(p.nodes[0]);
        });
        // Doppio click su un membro di un gruppo aperto: lo richiude.
        networkInstance.on('doubleClick', p => {
            if (!p.nodes || !p.nodes.length) return;
            const key = layeredGroupOfChild[p.nodes[0]];
            if (!key) return;
            schemaRetidy = getMapView() === 'minimal';
            toggleLayeredGroup(layeredGroup, key);
        });
        networkInstance.on('deselectNode', () => {
            closeTopologyNodeDrawer();
        });
        networkInstance.on('click', p => {
            if (!p.nodes || !p.nodes.length) closeTopologyNodeDrawer();
            // Schema focus follows the click: a node focuses, empty space clears.
            // On 'click' rather than select/deselect, whose order vis does not fix.
            if (getMapView() === 'minimal') {
                const on = /** @type {HTMLInputElement|null} */ (document.getElementById('toggleSchemaFocus'))?.checked;
                const id = on && p.nodes && p.nodes.length ? String(p.nodes[0]) : null;
                if (id !== schemaFocusId) applySchemaFocus(id);
            }
        });

        let mapFrozen = false;
        const isMinimal = getMapView() === 'minimal';
        const freezeLayout = () => {
            // Fix A: forma esplicita {enabled:false} (non solo lo shorthand booleano)
            // così vis.js disattiva anche il solver di stabilizzazione, non solo il
            // rendering della fisica: sulla mappa minimalista, con riquadri grandi e
            // avoidOverlap:1, il solver può non emettere mai 'stabilized' e restare
            // in animazione perenne se non forzato esplicitamente allo stop.
            if (networkInstance && !mapFrozen) {
                mapFrozen = true;
                networkInstance.setOptions({ physics: { enabled: false } });
            }
        };
        // Schema: nothing known → full layout; some devices new → only those
        // are placed, at the end of their row.
        if (isMinimal) networkInstance.once('afterDrawing', growSchemaColumnParents);
        if (isMinimal && (!allKnown || schemaRetidy)) {
            const full = schemaRetidy;
            schemaRetidy = false;
            networkInstance.once('afterDrawing', () => {
                const known = nodes.filter(nd => prevPos && prevPos[nd.id]).map(nd => nd.id);
                if (known.length && !full) placeNewSchemaNodes(known); else packSchemaRows();
            });
        }
        // Hierarchy view: vis.js lays the rows out again on every render, so
        // the tidy pass always runs; a horizontal drag is put back on top.
        // vis.js fits the cards only, which cuts the site headers drawn
        // above them; step back a little on the first frame.
        if (hierarchy) {
            networkInstance.once('afterDrawing', () => {
                tidyLayeredTree();
                // Only when the same cards come back: after a group opens or
                // closes the tidy layout moved everyone, and the old x put the
                // known cards on top of the new ones.
                if (allKnown && Object.keys(prevPos).length === nodes.length) {
                    const now = networkInstance.getPositions();
                    Object.keys(now).forEach(id => {
                        const p = prevPos[id];
                        if (p && Math.abs(p.y - now[id].y) < 1) networkInstance.moveNode(id, p.x, now[id].y);
                    });
                }
                const free = layeredFree && layeredFreePos[layeredGroup];
                if (free) Object.keys(free).forEach(id => { if (nodes.some(nd => nd.id === id)) networkInstance.moveNode(id, free[id].x, free[id].y); });
                // Always: a fresh instance has no zoom of the user's to keep,
                // and vis.js centred the cards before the tidy pass moved them.
                networkInstance.fit();
                networkInstance.moveTo({ scale: networkInstance.getScale() * 0.85 });
            });
        }
        networkInstance.once('stabilizationIterationsDone', freezeLayout);
        networkInstance.once('stabilized', freezeLayout);
        // Sulla mappa minimalista il solver barnesHut con riquadri grandi/avoidOverlap
        // può non stabilizzarsi mai: fallback più aggressivo (2.5s) per non lasciarla
        // in animazione percepibile "per sempre". La classica resta a 5s (invariata).
        networkInstance.once('afterDrawing', () => setTimeout(freezeLayout, isMinimal ? 2500 : 5000));
    }

    // Hierarchy view: vis.js fills each row in id order, so siblings were
    // scattered, buses of different parents ran over each other, and a
    // device hanging on one access switch could sit at the far end of the
    // row with its cable across the whole site. The rows are kept, the x
    // is redone as a tidy tree: every device has one parent (the nearest
    // linked device above it), each subtree gets the width of its leaves,
    // and a parent sits centred over its children. Sites stay side by side.
    // ponytail: one pitch for every card; a narrower leaf cluster only
    // leaves extra room.
    const LAYERED_TENANT_GAP = 160;
    function tidyLayeredTree() {
        const pos = networkInstance.getPositions(), ids = Object.keys(pos), adj = {}, kids = {}, isKid = {}, parentOf = {};
        const nodesDs = networkInstance.body.data.nodes;
        // Blocks side by side per location (the zone), not per tenant.
        const tenantOf = id => { const nd = nodesDs.get(id); return nd && nd.nodeDataVal ? topoZone(nd.nodeDataVal).key : ''; };
        networkInstance.body.data.edges.forEach(e => {
            (adj[e.from] || (adj[e.from] = [])).push(e.to);
            (adj[e.to] || (adj[e.to] = [])).push(e.from);
        });
        ids.sort((a, b) => pos[a].x - pos[b].x).forEach(id => {
            const ups = (adj[id] || []).filter(n => pos[n] && pos[n].y < pos[id].y - 1 && tenantOf(n) === tenantOf(id))
                .sort((a, b) => (pos[b].y - pos[a].y) || (Math.abs(pos[a].x - pos[id].x) - Math.abs(pos[b].x - pos[id].x)));
            if (!ups.length) return;
            (kids[ups[0]] || (kids[ups[0]] = [])).push(id);
            isKid[id] = parentOf[id] = ups[0];
        });
        // A card's slot is as wide as its widest port tag: a Po with four
        // members is wider than the card and ran over the next device's.
        const meas = document.createElement('canvas').getContext('2d');
        meas.font = `600 10px ${cssVar('--font-data', 'monospace')}`;
        const tagW = {};
        networkInstance.body.data.edges.forEach(e => {
            const l = e.lnk;
            if (!l || !pos[e.from] || !pos[e.to]) return;
            const down = pos[e.from].y > pos[e.to].y ? e.from : e.to;
            const ends = l.is_portchannel ? pcEnds(l) : { local: '', remote: '' };
            [[ends.local, l.local_ports, l.local_port], [ends.remote, l.remote_ports, l.remote_port]].forEach(([po, ps, p]) => {
                const ports = ((ps && ps.length) ? ps : [p]).map(shortIface).filter(Boolean).join(' · ');
                const w = (po ? meas.measureText(po).width + 14 : 0) + (ports ? meas.measureText(ports).width + 14 : 0);
                tagW[down] = Math.max(tagW[down] || 0, w + 30);
            });
        });
        // Other parents with nothing of their own (the second firewall of a
        // pair) join the root that owns their child: the pair becomes one
        // block centred over the child, and the subtree widens to hold it.
        const below = id => (adj[id] || []).find(n => pos[n] && pos[n].y > pos[id].y + 1 && parentOf[n]);
        const beside = ids.filter(id => !isKid[id] && !kids[id] && below(id));
        const satOf = {};
        beside.forEach(id => {
            const p = parentOf[below(id)];
            if (!parentOf[p] && Math.abs(pos[p].y - pos[id].y) < 1) (satOf[p] || (satOf[p] = [])).push(id);
        });
        const inBlock = new Set([].concat(...Object.values(satOf)));
        const width = {};
        const span = id => width[id] || (width[id] = Math.max(LAYERED_PITCH * (1 + (satOf[id] || []).length), tagW[id] || 0,
            (kids[id] || []).reduce((t, k) => t + span(k), 0)));
        const place = (id, left) => {
            const ks = kids[id] || [];
            let l = left;
            ks.forEach(k => { place(k, l); l += span(k); });
            pos[id].x = ks.length ? (pos[ks[0]].x + pos[ks[ks.length - 1]].x) / 2 : left + span(id) / 2;
        };
        let left = 0, prevTenant = null;
        ids.filter(id => !isKid[id] && !beside.includes(id))
            .sort((a, b) => tenantOf(a).localeCompare(tenantOf(b)) || (pos[a].x - pos[b].x))
            .forEach(id => {
                if (prevTenant !== null && tenantOf(id) !== prevTenant) left += LAYERED_TENANT_GAP;
                prevTenant = tenantOf(id);
                place(id, left);
                const block = [id].concat(satOf[id] || []), half = (block.length - 1) / 2 * LAYERED_PITCH;
                if (block.length > 1) {
                    const c = Math.min(Math.max(pos[id].x, left + half + LAYERED_PITCH / 2), left + span(id) - half - LAYERED_PITCH / 2);
                    block.forEach((b, j) => { pos[b].x = c - half + j * LAYERED_PITCH; });
                }
                left += span(id);
            });
        // The rest (its partner sits lower, or has a parent): beside it when
        // there is room, else at the end of the row.
        const taken = ids.filter(id => !beside.includes(id) || inBlock.has(id));
        beside.filter(id => !inBlock.has(id)).forEach(id => {
            const p = pos[parentOf[below(id)]];
            const free = x => taken.every(o => Math.abs(pos[o].y - pos[id].y) > 1 || Math.abs(pos[o].x - x) >= LAYERED_PITCH);
            const x = [1, -1, 2, -2, 3, -3].map(k => p.x + k * LAYERED_PITCH).find(free);
            pos[id].x = x !== undefined ? x : (left += LAYERED_PITCH) - LAYERED_PITCH / 2;
            taken.push(id);
        });
        ids.forEach(id => networkInstance.moveNode(id, pos[id].x, pos[id].y));
    }

    function roundRectPath(ctx, x, y, w, h, r) {
        ctx.beginPath();
        ctx.moveTo(x + r, y);
        ctx.arcTo(x + w, y, x + w, y + h, r);
        ctx.arcTo(x + w, y + h, x, y + h, r);
        ctx.arcTo(x, y + h, x, y, r);
        ctx.arcTo(x, y, x + w, y, r);
        ctx.closePath();
    }

    // Hierarchy view backdrop: a dot grid that pans and zooms with the map.
    function drawDotGrid(ctx) {
        const scale = networkInstance.getScale();
        if (scale < 0.5) return;   // ponytail: too dense to read below half zoom, and costly
        const c = document.getElementById('networkGraphContainer');
        const a = networkInstance.DOMtoCanvas({ x: 0, y: 0 });
        const b = networkInstance.DOMtoCanvas({ x: c.clientWidth, y: c.clientHeight });
        const step = 24, s = 1.6 / scale;
        ctx.save();
        ctx.fillStyle = cssVar('--border', '#233245');
        for (let x = Math.floor(a.x / step) * step; x < b.x; x += step) {
            for (let y = Math.floor(a.y / step) * step; y < b.y; y += step) ctx.fillRect(x, y, s, s);
        }
        ctx.restore();
    }

    // --- Map zones: one per location, not per tenant -------------------------
    const ip4n = ip => {
        const p = String(ip || '').split('.');
        if (p.length !== 4 || p.some(x => !/^\d{1,3}$/.test(x) || +x > 255)) return null;
        return ((+p[0] << 24) >>> 0) + (+p[1] << 16) + (+p[2] << 8) + +p[3];
    };
    const inCidr = (a, cidr) => {
        const [net, len] = String(cidr).split('/');
        const n = ip4n(net), l = Number(len);
        if (n === null || !(l >= 0 && l <= 32)) return false;
        const mask = l ? (0xFFFFFFFF << (32 - l)) >>> 0 : 0;
        return ((a & mask) >>> 0) === ((n & mask) >>> 0);
    };
    /** The location a map node sits in: a managed device's own, else the
     *  location of its tenant whose subnets hold its address (a discovered
     *  switch), else the tenant itself. Keyed by id: two locations of one
     *  tenant may share a name. `withOrg` prefixes the tenant, for the
     *  all-tenants view where "HQ" alone would be ambiguous. */
    function topoZoneOwn(n, withOrg) {
        const ip = n.display_ip || n.id;
        const dev = globalDevices.find(d => d.IP === ip);
        let loc = dev && dev.Location ? locationById(dev.Location) : null;
        const a = ip4n(ip);
        if (!loc && a !== null) {
            loc = globalLocations.find(l => l.org === n.group && (l.subnets || []).some(c => inCidr(a, c))) || null;
        }
        if (!loc) return null;
        return { key: loc.id, label: withOrg ? `${n.group} · ${loc.name}` : loc.name };
    }

    // Zone of every node on the current map, set by loadInteractiveMap. A
    // device with no location of its own (a discovered switch outside every
    // declared subnet) takes the zone of the nearest located device it is
    // cabled to: it hangs off that site. Only with no located neighbour at
    // all does it fall back to its tenant.
    let mapZones = {};
    function assignZones(nodesData, linksData, withOrg) {
        const out = {}, adj = {};
        nodesData.forEach(n => { const z = topoZoneOwn(n, withOrg); if (z) out[n.id] = z; });
        linksData.forEach(l => {
            (adj[l.source] || (adj[l.source] = [])).push(l.target);
            (adj[l.target] || (adj[l.target] = [])).push(l.source);
        });
        let frontier = Object.keys(out);
        while (frontier.length) {
            const next = [];
            frontier.forEach(id => (adj[id] || []).forEach(nb => {
                if (!out[nb]) { out[nb] = out[id]; next.push(nb); }
            }));
            frontier = next;
        }
        nodesData.forEach(n => { if (!out[n.id]) out[n.id] = { key: 'org|' + (n.group || ''), label: n.group || '' }; });
        return out;
    }
    function topoZone(n) {
        if (n.is_group && (n.members || []).length) return topoZone(n.members[0]);
        return mapZones[n.id] || { key: 'org|' + (n.group || ''), label: n.group || '' };
    }
    const zoneKeyOf = id => (mapZones[id] || {}).key;

    // Site panel header: name on the left, device count and offline count on
    // the right. A collapsed group counts as its members.
    function drawZoneHeader(ctx, name, nds, x0, x1, y0) {
        let total = 0, off = 0;
        nds.forEach(nd => {
            const n = nd.nodeDataVal || {};
            const ms = n.is_group ? (n.members || []) : [n];
            total += ms.length;
            off += ms.filter(m => m.status === 'offline').length;
        });
        ctx.textBaseline = 'middle';
        ctx.textAlign = 'left';
        ctx.fillStyle = cssVar('--text-muted', '#94a3b8');
        ctx.font = `700 18px ${cssVar('--font-legend', 'sans-serif')}`;
        ctx.fillText(String(name).toUpperCase(), x0 + 16, y0 + 26);
        const txt = off ? tr('topoZoneSummary', { n: total, k: off }) : tr('topoZoneCount', { n: total });
        ctx.font = `12px ${cssVar('--font-data', 'monospace')}`;
        ctx.textAlign = 'right';
        ctx.fillText(txt, x1 - 16, y0 + 26);
        ctx.fillStyle = cssVar(off ? '--lamp-fault' : '--lamp-up', '#10b981');
        ctx.beginPath();
        ctx.arc(x1 - 26 - ctx.measureText(txt).width, y0 + 26, 4, 0, Math.PI * 2);
        ctx.fill();
    }

    // Hierarchy view, under the map: one panel per site, a dashed rule
    // between levels, and the level's name only where the user wrote one.
    function drawLayeredColumns(ctx) {
        if (!networkInstance) return;
        drawDotGrid(ctx);
        const pos = networkInstance.getPositions();
        const tenants = {}, rows = {};
        let top = Infinity, bottom = -Infinity;
        networkInstance.body.data.nodes.forEach(nd => {
            const bb = networkInstance.getBoundingBox(nd.id);
            if (!bb || !pos[nd.id]) return;
            const z = topoZone(nd.nodeDataVal || {});
            const s = tenants[z.key] || (tenants[z.key] = { label: z.label, x0: Infinity, x1: -Infinity, nodes: [] });
            s.x0 = Math.min(s.x0, bb.left); s.x1 = Math.max(s.x1, bb.right); s.nodes.push(nd);
            top = Math.min(top, bb.top); bottom = Math.max(bottom, bb.bottom);
            const lv = layeredAssigned[nd.id] || 0;
            const r = rows[lv] || (rows[lv] = { top: Infinity, bottom: -Infinity });
            r.top = Math.min(r.top, bb.top); r.bottom = Math.max(r.bottom, bb.bottom);
        });
        const levels = Object.keys(rows).map(Number).sort((a, b) => a - b);
        if (!levels.length) return;
        // A rule halfway between a row's lowest card and the next row's highest.
        const rules = levels.slice(1).map((lv, i) => (rows[levels[i]].bottom + rows[lv].top) / 2);
        const names = layeredLevelNames[layeredGroup] || [];
        const y0 = top - 64, y1 = bottom + 30;
        const border = cssVar('--border', '#233245');
        ctx.save();
        Object.keys(tenants).forEach(g => {
            const s = tenants[g], x0 = s.x0 - 30, x1 = s.x1 + 30;
            roundRectPath(ctx, x0, y0, x1 - x0, y1 - y0, 14);
            ctx.globalAlpha = 0.4;
            ctx.fillStyle = cssVar('--surface-3', '#1d2a3b');
            ctx.fill();
            ctx.globalAlpha = 1;
            ctx.strokeStyle = border;
            ctx.lineWidth = 1;
            ctx.stroke();
            drawZoneHeader(ctx, s.label, s.nodes, x0, x1, y0);
            ctx.strokeStyle = border;
            ctx.setLineDash([2, 5]);
            ctx.beginPath();
            rules.forEach(y => { ctx.moveTo(x0 + 12, y); ctx.lineTo(x1 - 12, y); });
            ctx.stroke();
            ctx.setLineDash([]);
            levels.forEach((lv, i) => {
                const name = names[lv];
                if (!name) return;
                const y = i ? rules[i - 1] : y0 + 50;
                const t = name.toUpperCase();
                ctx.font = `700 13px ${cssVar('--font-legend', 'sans-serif')}`;
                roundRectPath(ctx, x0 + 12, y - 9, ctx.measureText(t).width + 14, 18, 4);
                ctx.fillStyle = cssVar('--surface', '#121a24');
                ctx.fill();
                ctx.stroke();
                ctx.fillStyle = cssVar('--text-muted', '#94a3b8');
                ctx.textAlign = 'left';
                ctx.textBaseline = 'middle';
                ctx.fillText(t, x0 + 19, y + 0.5);
            });
        });
        ctx.restore();
    }

    // Copper for Port-Channel members: reads on both the light and dark map.
    const PC_COPPER = '#c2773a';

    // A cable end's label: a Po shows its name filled in copper with its
    // member ports beside it; a plain link shows the port alone.
    function endTagWidths(ctx, t) {
        const mono = cssVar('--font-data', 'monospace');
        ctx.font = `600 10px ${mono}`;
        const w2 = t.ports ? ctx.measureText(t.ports).width + 14 : 0;
        ctx.font = `700 10px ${mono}`;
        const w1 = t.po ? ctx.measureText(t.po).width + 14 : 0;
        return { w1, w2, w: w1 + w2 };
    }
    // The tag's box for an anchor point: y is its vertical centre.
    function endTagRect(w, x, y, anchor) {
        return { x: anchor === 'start' ? x : anchor === 'end' ? x - w : x - w / 2, y: y - 9, w, h: 18 };
    }

    // Plain text on a borderless backing: the copper pill and its outline
    // competed with the cables for attention.
    function drawEndTag(ctx, t, x, y, anchor) {
        if (!t.ports && !t.po) return;
        const mono = cssVar('--font-data', 'monospace'), h = 16;
        const { w1, w2, w } = endTagWidths(ctx, t);
        const X = endTagRect(w, x, y, anchor).x;
        roundRectPath(ctx, X + 3, y - h / 2, w - 6, h, 4);
        ctx.fillStyle = cssVar('--surface-2', '#16202d');
        ctx.fill();
        ctx.textBaseline = 'middle';
        ctx.textAlign = 'center';
        if (t.po) {
            ctx.font = `700 10px ${mono}`;
            ctx.fillStyle = PC_COPPER;
            ctx.fillText(t.po, X + w1 / 2, y + 0.5);
        }
        if (t.ports) {
            ctx.font = `600 10px ${mono}`;
            ctx.fillStyle = t.po ? cssVar('--text', '#f1f5f9') : cssVar('--text-muted', '#94a3b8');
            ctx.fillText(t.ports, X + w1 + w2 / 2, y + 0.5);
        }
    }

    // Radius of the hierarchy map's cable corners.
    const LINK_R = 8;
    // Orthogonal polyline with rounded corners; a corner never takes more
    // than half of either segment beside it.
    function roundedRun(ctx, pts) {
        ctx.moveTo(pts[0][0], pts[0][1]);
        for (let i = 1; i < pts.length - 1; i++) {
            const [px, py] = pts[i - 1], [x, y] = pts[i], [nx, ny] = pts[i + 1];
            const r = Math.min(LINK_R, Math.hypot(x - px, y - py) / 2, Math.hypot(nx - x, ny - y) / 2);
            ctx.arcTo(x, y, nx, ny, r);
        }
        const last = pts[pts.length - 1];
        ctx.lineTo(last[0], last[1]);
    }

    // Hierarchy view cables: an elbow from the upper card's bottom edge to the
    // lower card's top with rounded corners, one copper line per Port-Channel
    // (its size in the tag), a straight run between cards on the same level.
    // Dashed when it leaves the site.
    function drawLayeredLinks(ctx) {
        if (!networkInstance) return;
        const pos = networkInstance.getPositions();
        const bb = id => networkInstance.getBoundingBox(id);
        const nodesDs = networkInstance.body.data.nodes;
        const tenantOf = id => { const nd = nodesDs.get(id); return (nd && nd.nodeDataVal && nd.nodeDataVal.group) || ''; };
        const edges = networkInstance.body.data.edges.get().filter(e => e.lnk && pos[e.from] && pos[e.to]);
        const muted = hexToRgba(cssVar('--text-muted', '#94a3b8'), 0.55);
        // Org-chart wiring: each parent drops ONE trunk to a bus that spans its
        // children, and every child hangs off that bus. One cable per child
        // with its own horizontal run piled a dozen lines on the same y and
        // nobody could follow them on a large site.
        // A child with several parents (two firewalls, a core and a side
        // device) gets one drop per parent, side by side, ordered like the
        // parents: on one shared drop their cables and tags overlapped.
        const upper = e => (pos[e.from].y < pos[e.to].y ? e.from : e.to);
        const lower = e => (pos[e.from].y < pos[e.to].y ? e.to : e.from);
        const vert = edges.filter(e => Math.abs(pos[e.from].y - pos[e.to].y) >= 1);
        const drops = {}, dropX = {}, dropIdx = {};
        vert.forEach(e => (drops[lower(e)] || (drops[lower(e)] = [])).push(e));
        Object.entries(drops).forEach(([d, es]) => {
            es.sort((a, b) => pos[upper(a)].x - pos[upper(b)].x);
            const w = bb(d).right - bb(d).left, step = es.length > 1 ? Math.min(70, (w - 40) / (es.length - 1)) : 0;
            es.forEach((e, i) => { dropX[e.id] = pos[d].x + (i - (es.length - 1) / 2) * step; dropIdx[e.id] = i; });
        });
        // A drop that skips a level would run through the cards of the row in
        // between: it comes down the nearest free gap beside them instead and
        // steps across to its child just above the tags.
        const ids = Object.keys(pos);
        const hits = (x, y0, y1, skip) => ids.some(id => {
            if (skip.includes(id)) return false;
            const o = bb(id);
            return x > o.left - 8 && x < o.right + 8 && o.bottom > y0 && o.top < y1;
        });
        const corridor = {};
        vert.forEach(e => {
            const U = upper(e), D = lower(e), y0 = bb(U).bottom + 24, y1 = bb(D).top - 60, skip = [U, D];
            if (!hits(dropX[e.id], y0, y1, skip)) return;
            const cands = [];
            ids.forEach(id => {
                if (skip.includes(id)) return;
                const o = bb(id);
                if (o.bottom > y0 && o.top < y1) cands.push(o.left - 16, o.right + 16);
            });
            const x = cands.filter(c => !hits(c, y0, y1, skip)).sort((a, b) => Math.abs(a - dropX[e.id]) - Math.abs(b - dropX[e.id]))[0];
            if (x !== undefined) corridor[e.id] = x;
        });
        const buses = {};
        vert.forEach(e => {
            const up = upper(e);
            const b = buses[up] || (buses[up] = { up, xs: [pos[up].x], pcXs: [], plainXs: [] });
            const x = corridor[e.id] ?? dropX[e.id];
            b.xs.push(x);
            (e.lnk.is_portchannel ? b.pcXs : b.plainXs).push(x);
        });
        // A parent with both kinds of child drew one grey bus and copper drops
        // off it: the Po cable changed colour halfway. With the option on, its
        // Po cables get their own copper lane just below, end to end.
        Object.values(buses).forEach(b => {
            b.pc = !b.plainXs.length;
            b.split = layeredTagCfg.lane && b.pcXs.length > 0 && b.plainXs.length > 0;
        });
        const PC_LANE = 5;
        // Buses below the same row get their own lane only where they overlap.
        const busY = {}, laneEnds = {};
        Object.values(buses).sort((a, b) => Math.min(...a.xs) - Math.min(...b.xs)).forEach(b => {
            const lo = Math.min(...b.xs), hi = Math.max(...b.xs), row = Math.round(pos[b.up].y);
            const ends = laneEnds[row] || (laneEnds[row] = []);
            let lane = ends.findIndex(x => x < lo - 12);
            if (lane === -1) lane = ends.length;
            ends[lane] = hi;
            busY[b.up] = bb(b.up).bottom + 16 + lane * 10;
            b.lo = lo; b.hi = hi;
        });
        // Where tags must not land (auto placement): cards, buses, cables.
        const obstacles = ids.map(id => { const o = bb(id); return { x: o.left, y: o.top, w: o.right - o.left, h: o.bottom - o.top }; });
        // Rounded corners where the bus turns: at its two ends, into the
        // trunk or into the outermost drop. A drop that starts on a rounded
        // corner is recorded in 'hooked' and starts below it.
        const hooked = new Map();   // drop start -> corner radius
        const hookKey = (x, y) => `${Math.round(x)}|${Math.round(y)}`;
        const busRun = (up, xs, y, color, dx = 0) => {
            const tx = pos[up].x + dx, lo = Math.min(tx, ...xs), hi = Math.max(tx, ...xs);
            const r = Math.min(LINK_R, (hi - lo) / 2, (y - bb(up).bottom) / 2);
            ctx.strokeStyle = color;
            ctx.beginPath();
            if (hi - lo < 1) { ctx.moveTo(tx, bb(up).bottom); ctx.lineTo(tx, y); ctx.stroke(); return; }
            const trunkDown = xs.some(x => Math.abs(x - tx) < 0.5);   // a drop continues the trunk
            const end = x => (Math.abs(x - tx) < 0.5 ? (trunkDown ? 't' : 'trunk') : 'drop');
            const left = end(lo), right = end(hi);
            // Trunk: rounded into the bus when it sits at one end with nothing below it.
            ctx.moveTo(tx, bb(up).bottom);
            if (left === 'trunk') { ctx.arcTo(tx, y, tx + r, y, r); }
            else if (right === 'trunk') { ctx.arcTo(tx, y, tx - r, y, r); }
            else ctx.lineTo(tx, y);
            // Bus, with a hook down into an outermost drop.
            if (left === 'drop') { ctx.moveTo(lo, y + r); ctx.arcTo(lo, y, lo + r, y, r); hooked.set(hookKey(lo, y), r); }
            else ctx.moveTo(left === 'trunk' ? lo + r : lo, y);
            if (right === 'drop') { ctx.lineTo(hi - r, y); ctx.arcTo(hi, y, hi, y + r, r); hooked.set(hookKey(hi, y), r); }
            else ctx.lineTo(right === 'trunk' ? hi - r : hi, y);
            ctx.stroke();
            obstacles.push({ x: lo - 2, y: y - 3, w: hi - lo + 4, h: 6 });
        };
        ctx.save();
        ctx.lineWidth = 1.5;
        Object.values(buses).forEach(b => {
            if (!b.split) { busRun(b.up, b.xs, busY[b.up], b.pc ? PC_COPPER : muted); return; }
            // Two trunks side by side: on one x the copper one hid the grey.
            busRun(b.up, b.plainXs, busY[b.up], muted, -PC_LANE);
            busRun(b.up, b.pcXs, busY[b.up] + PC_LANE, PC_COPPER, PC_LANE);
        });
        ctx.restore();
        // Top of a drop: its own copper lane when the parent's bus is split.
        const dropTop = e => busY[upper(e)] + (buses[upper(e)].split && e.lnk.is_portchannel ? PC_LANE : 0);

        // Label text. Small labels drop the prefix every device of the view
        // shares ("abbr"), or the name ("ports"), or become one per link ("one").
        const labels = nodesDs.get().map(n => (n.nodeDataVal && n.nodeDataVal.label) || '').filter(Boolean);
        const preCount = {};
        labels.forEach(lb => {
            const seen = new Set();
            for (let i = 0; i < lb.length; i++) if ('-_.'.includes(lb[i])) seen.add(lb.slice(0, i + 1).toLowerCase());
            seen.forEach(p => { preCount[p] = (preCount[p] || 0) + 1; });
        });
        // ponytail: the longest prefix half the view shares; one prefix per tenant if names mix tenants.
        const namePrefix = Object.keys(preCount).filter(p => preCount[p] >= 2 && preCount[p] * 2 >= labels.length)
            .sort((a, b) => b.length - a.length)[0] || '';
        const shortName = n => (namePrefix && n.length > namePrefix.length && n.toLowerCase().startsWith(namePrefix)) ? n.slice(namePrefix.length) : n;
        const plain = p => (p && p !== 'Vicino' && p !== 'Neighbor') ? shortIface(p) : '';
        const tags = [];   // painted after every cable: no cable runs over a tag
        const overLanes = {};   // row y -> last lane used above it
        ctx.save();
        ctx.lineJoin = 'round';
        edges.forEach(e => {
            const l = e.lnk, isPC = !!l.is_portchannel;
            const kind = l.kind === 'group' ? 'group' : (l.kind === 'redundancy_heartbeat' ? 'ha' : (isPC ? 'pc' : 'link'));
            const lp = ((l.local_ports && l.local_ports.length) ? l.local_ports : [l.local_port]).map(shortIface).filter(Boolean);
            const rp = ((l.remote_ports && l.remote_ports.length) ? l.remote_ports : [l.remote_port]).map(shortIface).filter(Boolean);
            // Members actually configured: a Po is one copper line, its size
            // goes in the tag (×m).
            const m = kind === 'pc' ? Math.max(1, lp.length, rp.length) : 1;
            const ends = kind === 'pc' ? pcEnds(l) : null;
            // fromSide: the end on the link's source device (local_*).
            // Each tag names its own device: two stacked tags with only ports
            // did not say which switch each one belonged to. A bundle shows
            // its member count; the full list is in the link tooltip.
            // A click on a tag flips its link from the global size.
            const linkKey = `${e.from}~${e.to}`;
            const small = (layeredTagCfg.size === 'small') !== !!layeredTagFlip[linkKey];
            const form = small ? layeredTagCfg.form : 'big';
            const endTag = fromSide => {
                const nd = nodesDs.get(fromSide ? e.from : e.to);
                const full = (nd && nd.nodeDataVal && nd.nodeDataVal.label) || '';
                const who = form === 'big' ? full : form === 'abbr' ? shortName(full) : '';
                const sep = form === 'big' ? ' · ' : ' ';
                if (kind === 'pc') {
                    const ps = fromSide ? lp : rp;
                    return { po: fromSide ? ends.local : ends.remote,
                             ports: [who, ps.length > 1 ? `×${ps.length}` : ps[0]].filter(Boolean).join(sep) };
                }
                if (kind !== 'link') return null;
                const port = plain(fromSide ? l.local_port : l.remote_port);
                return { ports: port ? [who, port].filter(Boolean).join(sep) : '' };
            };
            // "One per link": a Po shows both ids and its size, a cable a dot.
            const oneTag = () => kind === 'pc'
                ? { po: ends.same ? ends.local : `${ends.local}⇄${ends.remote}`, ports: `×${m}` }
                : kind === 'link' ? { ports: '•' } : null;
            const one = form === 'one';
            const push = (part, t, x, y, anchor, extra) => tags.push(Object.assign(
                { key: `${linkKey}~${part}`, link: linkKey, t, ax: x, ay: y, cands: [{ x, y, anchor }] }, extra || {}));
            ctx.strokeStyle = kind === 'pc' ? PC_COPPER : (kind === 'ha' ? '#f9a825' : muted);
            ctx.lineWidth = kind === 'pc' ? 2 : 1.25;
            ctx.setLineDash(kind === 'group' || kind === 'ha' ? [4, 4] : (tenantOf(e.from) !== tenantOf(e.to) ? [7, 4] : []));
            const a = pos[e.from], b = pos[e.to];
            ctx.beginPath();
            if (Math.abs(a.y - b.y) < 1) {
                const fromLeft = a.x <= b.x;
                const L = fromLeft ? e.from : e.to, R = fromLeft ? e.to : e.from;
                const x1 = bb(L).right, x2 = bb(R).left;
                // Other cards in between: up from both tops, across above the
                // row, down again; a straight run crossed every card between.
                if (hits((x1 + x2) / 2, a.y - 1, a.y + 1, [L, R]) || ids.some(id => id !== L && id !== R
                        && Math.abs(pos[id].y - a.y) < 1 && pos[id].x > pos[L].x && pos[id].x < pos[R].x)) {
                    const top = Math.min(bb(L).top, bb(R).top), row = Math.round(a.y);
                    const lane = overLanes[row] = (overLanes[row] ?? -1) + 1;
                    const ly = top - 58 - lane * 10;
                    const lx = bb(L).right - 24, rx = bb(R).left + 24;
                    roundedRun(ctx, [[lx, bb(L).top], [lx, ly], [rx, ly], [rx, bb(R).top]]);
                    ctx.stroke();
                    obstacles.push({ x: lx, y: ly - 4, w: rx - lx, h: 8 });
                    if (one) { push('o', oneTag(), (lx + rx) / 2, ly - 12, 'middle'); return; }
                    push('u', endTag(fromLeft), lx + 10, ly - 12, 'start');
                    push('d', endTag(!fromLeft), rx - 10, ly - 12, 'end');
                    return;
                }
                ctx.moveTo(x1, a.y); ctx.lineTo(x2, a.y);
                ctx.stroke();
                obstacles.push({ x: x1, y: a.y - 5, w: x2 - x1, h: 10 });
                if (one) { push('o', oneTag(), (x1 + x2) / 2, a.y - 20, 'middle'); return; }
                push('u', endTag(fromLeft), x1 + 6, a.y - 20, 'start');
                push('d', endTag(!fromLeft), x2 - 6, a.y + 20, 'end');
                return;
            }
            const fromUp = a.y < b.y, U = fromUp ? e.from : e.to, D = fromUp ? e.to : e.from;
            const cx = dropX[e.id], cy = bb(D).top, lift = (drops[D].length - 1 - dropIdx[e.id]) * 46;
            // The child's drop from its parent's bus; it starts below the
            // bus corner when the bus turns into it.
            const cor = corridor[e.id], jy = cy - 56 - lift, top = dropTop(e);
            const y0 = top + (hooked.get(hookKey(cor ?? cx, top)) || 0);
            roundedRun(ctx, cor === undefined ? [[cx, y0], [cx, cy]] : [[cor, y0], [cor, jy], [cx, jy], [cx, cy]]);
            ctx.stroke();
            const half = 4;
            if (cor === undefined) obstacles.push({ x: cx - half, y: top, w: 2 * half, h: cy - top });
            else obstacles.push({ x: cor - half, y: top, w: 2 * half, h: jy - top },
                                { x: Math.min(cor, cx) - half, y: jy - half, w: Math.abs(cx - cor) + 2 * half, h: 2 * half },
                                { x: cx - half, y: jy, w: 2 * half, h: cy - jy });
            if (layeredTagCfg.place === 'stack') {
                // Both ends sit on the lower card's own drop, upper device first:
                // siblings' tags can never land on each other.
                // With several parents the pairs stack, the leftmost parent's on top.
                if (one) { push('o', oneTag(), cx, cy - 15 - lift, 'middle'); return; }
                push('u', endTag(fromUp), cx, cy - 38 - lift, 'middle');
                push('d', endTag(!fromUp), cx, cy - 15 - lift, 'middle');
                return;
            }
            // Beside the cable, each device's tag at its own end: the upper one
            // where the drop leaves the bus, the lower one where it reaches the
            // card, so the cable reads from one device to the other. Auto mode
            // tries right, left and a few heights for the first free spot.
            const beside = (x, y, dys) => dys.flatMap(dy => [
                { x: x + half + 6, y: y + dy, anchor: 'start' }, { x: x - half - 6, y: y + dy, anchor: 'end' }]);
            const ux = cor ?? cx, uy = top + 16, dy = cy - 14;
            if (one) {
                const my = ((cor === undefined ? top : jy) + cy) / 2;
                push('o', oneTag(), cx, my, 'start', { cands: beside(cx, my, [0, -20, 20, -40, 40]) });
                return;
            }
            push('u', endTag(fromUp), ux, uy, 'start', { cands: beside(ux, uy, [0, 12, 24, 36]) });
            push('d', endTag(!fromUp), cx, dy, 'start', { cands: beside(cx, dy, [0, -12, -24, -36]) });
        });
        ctx.setLineDash([]);
        // Placement: auto takes the first candidate clear of cards, cables and
        // tags already placed; a hand drag is added on top in every mode.
        const free = r => !obstacles.some(o => r.x - 3 < o.x + o.w && o.x < r.x + r.w + 3 && r.y - 3 < o.y + o.h && o.y < r.y + r.h + 3);
        layeredTagHits = [];
        const placed = tags.filter(g => g.t && (g.t.ports || g.t.po)).map(g => {
            const w = endTagWidths(ctx, g.t).w;
            let c = g.cands[0];
            if (layeredTagCfg.place === 'auto') c = g.cands.find(k => free(endTagRect(w, k.x, k.y, k.anchor))) || c;
            const adj = layeredTagAdjust[g.key] || { dx: 0, dy: 0 };
            const at = { x: c.x + adj.dx, y: c.y + adj.dy, anchor: c.anchor };
            const r = endTagRect(w, at.x, at.y, at.anchor);
            obstacles.push(r);
            return { g, at, r };
        });
        // A tag moved off its cable keeps a dotted leader back to it.
        placed.forEach(({ g, r }) => {
            const ex = Math.max(r.x, Math.min(g.ax, r.x + r.w)), ey = Math.max(r.y, Math.min(g.ay, r.y + r.h));
            if (Math.hypot(ex - g.ax, ey - g.ay) <= 3) return;
            ctx.save();
            ctx.strokeStyle = g.t.po ? PC_COPPER : muted;
            ctx.fillStyle = ctx.strokeStyle;
            ctx.lineWidth = 1;
            ctx.setLineDash([2, 2]);
            ctx.beginPath(); ctx.moveTo(g.ax, g.ay); ctx.lineTo(ex, ey); ctx.stroke();
            ctx.setLineDash([]);
            ctx.beginPath(); ctx.arc(g.ax, g.ay, 2, 0, 2 * Math.PI); ctx.fill();
            ctx.restore();
        });
        placed.forEach(({ g, at, r }) => {
            drawEndTag(ctx, g.t, at.x, at.y, at.anchor);
            layeredTagHits.push(Object.assign({ key: g.key, link: g.link }, r));
        });
        ctx.restore();
        initLayeredTagInteraction();
    }

    // Hierarchy-map tags: a click flips that link between large and small, a
    // drag moves the tag. Same capture trick as the minimal map's pills: the
    // container sees the pointer first, so vis.js does not pan the view.
    let layeredTagDrag = null, layeredTagUiReady = false;
    function initLayeredTagInteraction() {
        if (layeredTagUiReady) return;
        const container = document.getElementById('networkGraphContainer');
        if (!container) return;
        layeredTagUiReady = true;
        const toNet = ev => {
            const cv = container.querySelector('canvas');
            const rect = (cv || container).getBoundingClientRect();
            return networkInstance.DOMtoCanvas({ x: ev.clientX - rect.left, y: ev.clientY - rect.top });
        };
        const hitAt = m => {
            for (let i = layeredTagHits.length - 1; i >= 0; i--) {
                const h = layeredTagHits[i];
                if (m.x >= h.x && m.x <= h.x + h.w && m.y >= h.y && m.y <= h.y + h.h) return h;
            }
            return null;
        };
        const begin = ev => {
            if (getMapView() !== 'layered' || !networkInstance || (ev.button !== undefined && ev.button !== 0)) return;
            const h = hitAt(toNet(ev));
            if (!h) return;
            ev.preventDefault(); ev.stopPropagation();
            if (layeredTagDrag) return; // started by the other event type
            const a = layeredTagAdjust[h.key] || { dx: 0, dy: 0 };
            layeredTagDrag = { h, start: toNet(ev), orig: { dx: a.dx, dy: a.dy }, moved: false };
        };
        container.addEventListener('pointerdown', begin, true);
        container.addEventListener('mousedown', begin, true);
        const move = ev => {
            const d = layeredTagDrag;
            if (!d || !networkInstance) return;
            const m = toNet(ev), dx = m.x - d.start.x, dy = m.y - d.start.y;
            if (!d.moved && Math.hypot(dx, dy) < 3) return;
            d.moved = true;
            layeredTagAdjust[d.h.key] = { dx: d.orig.dx + dx, dy: d.orig.dy + dy };
            networkInstance.redraw();
        };
        window.addEventListener('pointermove', move);
        window.addEventListener('mousemove', move);
        const end = () => {
            const d = layeredTagDrag;
            if (!d) return;
            layeredTagDrag = null;
            if (!d.moved) {
                if (layeredTagFlip[d.h.link]) delete layeredTagFlip[d.h.link];
                else layeredTagFlip[d.h.link] = 1;
            }
            saveLayeredTags();
            if (networkInstance) networkInstance.redraw();
        };
        window.addEventListener('pointerup', end);
        window.addEventListener('mouseup', end);
        container.addEventListener('mousemove', ev => {
            if (layeredTagDrag || getMapView() !== 'layered' || !networkInstance) return;
            container.style.cursor = hitAt(toNet(ev)) ? 'pointer' : '';
        });
    }

    // "visto dal WLC 3 h fa": età dell'ultimo censimento del controller, con la
    // provenienza scritta nell'etichetta — non è un uptime dell'apparato.
    function wlcSeenLabel(iso) {
        if (!iso) return '';
        const ts = Date.parse(iso);
        if (isNaN(ts)) return '';
        const age = relativeAge((Date.now() - ts) / 3600000);
        return tr('topoSeenByWlcAgo', {age: age});
    }

    function openTopologyNodeDrawer(nodeId) {
        if (!nodeId) return;
        currentSelectedNodeId = nodeId;
        const drawer = document.getElementById('topologyNodeDrawer');
        if (!drawer) return;

        const dev = (globalDevices || []).find(d => d.IP === nodeId || d.Hostname === nodeId || d.ID === nodeId) || {};
        const topNode = (cachedTopologyNodes || []).find(n => n.id === nodeId || n.label === nodeId) || {};

        const hostname = dev.Hostname || topNode.label || nodeId;
        // Un nodo scoperto ha per id "discovered_<hostname>": l'indirizzo vero è
        // quello annunciato via CDP/LLDP (o quello che il WLC conosce per l'AP).
        const ip = dev.IP || topNode.display_ip
            || (nodeId.includes('.') ? nodeId : '—');
        const vendor = (dev.Vendor || topNode.vendor || 'Discovered').toUpperCase();
        // Il modello vero viene dal backup/CDP; "device_type" è una categoria,
        // non un modello: mostrarlo come tale ("CISCO ap") diceva meno di nulla.
        const model = dev.Model || topNode.model || topNode.platform || dev.Type || '—';
        const status = (dev.Status || topNode.status || 'online').toLowerCase();
        // Un AP non ha backup: quello che si sa è quando il controller l'ha
        // visto l'ultima volta, e va detto che viene da lì.
        const uptime = dev.Uptime || (dev.LastBackup ? backupAgeLabel(dev.LastBackup) : '')
            || wlcSeenLabel(topNode.wlc_seen_at) || '—';
        const tenant = dev.Group || topNode.group || '—';
        // Il seriale di un AP lo sa solo il controller che l'ha adottato: arriva
        // dal backend insieme al MAC, che per un apparato senza IP è l'unico
        // identificativo stabile.
        const serial = [dev.Serial || topNode.serial, topNode.mac].filter(Boolean).join(' · ') || '—';
        const software = (globalVersions[nodeId] || {}).version || topNode.version || '—';
        const mgmtVlan = topNode.mgmt_vlan ? `VLAN ${topNode.mgmt_vlan}` : '';
        const vtp = [topNode.vtp_domain, topNode.vtp_mode].filter(Boolean).join(' · ');
        // Un AP non ha né VLAN di management né VTP: al loro posto vale sapere a
        // quale controller si è agganciato.
        const joinedWlc = topNode.wlc_ip
            ? `${tr('topoJoinedWlc')} ${topNode.wlc_ip}`
            : '';

        const hostEl = document.getElementById('drawerNodeHostname');
        if (hostEl) hostEl.textContent = hostname;
        const twinEl = document.getElementById('drawerTwinWarn');
        if (twinEl) {
            const twins = nameTwins(nodeId);
            twinEl.hidden = !twins.length;
            twinEl.innerHTML = twins.length ? `<i class="fa-solid fa-clone" aria-hidden="true"></i> ${
                escapeHtml(tr('twinBadgeTitle', { list: twins.map(t => `${t.IP} (${locationLabel(t.Location)})`).join(', ') }))}
                <button type="button" class="btn btn-secondary btn-small" data-action="open-name-twins" data-ip="${attrEsc(nodeId)}">${
                escapeHtml(tr('twinOpen'))}</button>` : '';
        }
        const ipEl = document.getElementById('drawerNodeIp');
        if (ipEl) ipEl.textContent = ip;
        const modelEl = document.getElementById('drawerNodeModel');
        if (modelEl) modelEl.textContent = `${vendor} ${model !== '—' ? model : ''}`.trim();
        const statusEl = document.getElementById('drawerNodeStatus');
        if (statusEl) {
            statusEl.className = `badge badge-${status === 'online' ? 'success' : (status === 'offline' ? 'danger' : 'warning')}`;
            statusEl.textContent = status.toUpperCase();
        }
        const uptimeEl = document.getElementById('drawerNodeUptime');
        // backupAgeLabel() restituisce markup (già con contenuto escapato): con
        // textContent il riquadro mostrava i tag invece dell'età del backup.
        if (uptimeEl) uptimeEl.innerHTML = uptime.startsWith('<') ? uptime : escapeHtml(uptime);
        const tenantEl = document.getElementById('drawerNodeTenant');
        if (tenantEl) tenantEl.textContent = `${tenant} · ${deviceTypeLabel(topNode.device_type)}`;
        const serialEl = document.getElementById('drawerNodeSerial');
        if (serialEl) serialEl.textContent = serial;
        const swEl = document.getElementById('drawerNodeSoftware');
        if (swEl) swEl.textContent = software;
        const vlanMgmtEl = document.getElementById('drawerNodeMgmtVlan');
        if (vlanMgmtEl) vlanMgmtEl.textContent = [mgmtVlan, vtp].filter(Boolean).join(' · ') || joinedWlc || '—';

        // Stack: presente solo sugli switch impilati, quindi la riga compare solo
        // quando c'è davvero qualcosa da dire (ruolo e seriale per membro).
        const stackEl = document.getElementById('drawerStackInfo');
        if (stackEl) {
            const stack = nodeStack(topNode);
            if (stack) {
                const members = (stack.members || [])
                    .map(m => `${escapeHtml(m.role || '?')} · ${escapeHtml(m.serial || '—')}`)
                    .join('<br>');
                stackEl.style.display = '';
                stackEl.innerHTML = `<div class="drawer-list-item">
                    <strong style="color:${STACK_COLOR}; font-size:12.5px;">${escapeHtml(stackLine(stack, '', model))}</strong>
                    ${stack.health === 'degraded' ? ' <i class="fa-solid fa-triangle-exclamation" style="color:var(--warning);"></i>' : ''}
                    ${members ? `<div style="font-size:11.5px; color:var(--text-muted); margin-top:4px;">${members}</div>` : ''}
                </div>`;
            } else {
                stackEl.style.display = 'none';
                stackEl.innerHTML = '';
            }
        }

        // Vicini: chi c'è dall'altra parte del cavo e su quali porte. Fino a ora
        // il pannello non lo diceva, ed è la domanda per cui si apre una mappa.
        const neighEl = document.getElementById('drawerNeighborList');
        if (neighEl) {
            const rows = (cachedTopologyLinks || [])
                .filter(l => l.source === nodeId || l.target === nodeId)
                .map(l => {
                    const mine = l.source === nodeId;
                    const otherId = mine ? l.target : l.source;
                    const other = (cachedTopologyNodes || []).find(n => n.id === otherId);
                    const localPorts = (mine ? l.local_ports : l.remote_ports) || [mine ? l.local_port : l.remote_port];
                    const remotePorts = (mine ? l.remote_ports : l.local_ports) || [mine ? l.remote_port : l.local_port];
                    const fmt = p => (p || []).map(shortIface).filter(Boolean).join('+') || '—';
                    // Same order as the ports below: this device's Po first.
                    const ends = pcEnds(l);
                    const ownPc = mine ? ends.local : ends.remote, peerPc = mine ? ends.remote : ends.local;
                    const pcTag = l.is_portchannel
                        ? `<span class="badge badge-warning" style="font-size:10px;">${escapeHtml(ends.same ? ownPc : `${ownPc} ⇄ ${peerPc}`)}</span>`
                        : (l.kind === 'redundancy_heartbeat'
                            ? '<span class="badge badge-warning" style="font-size:10px;">HA</span>' : '');
                    return `<div class="drawer-list-item">
                        <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:4px;">
                            <strong style="font-size:12.5px;">${escapeHtml((other && other.label) || otherId)}</strong>
                            ${pcTag}
                        </div>
                        <div style="font-size:11.5px; color:var(--text-muted);">
                            <code style="font-size:11px;">${escapeHtml(fmt(localPorts))}</code> ⇄ <code style="font-size:11px;">${escapeHtml(fmt(remotePorts))}</code>
                            ${other && other.id !== other.label ? ` · <span>${escapeHtml(other.id)}</span>` : ''}
                        </div>
                    </div>`;
                });
            const neighCountEl = document.getElementById('drawerNeighborCount');
            if (neighCountEl) neighCountEl.textContent = rows.length ? `(${rows.length})` : '';
            neighEl.innerHTML = rows.length
                ? rows.join('')
                : `<div style="font-size:12px; color:var(--text-muted);">${escapeHtml(tr('topoNoAdjacencyDiscoveredFor'))}</div>`;
        }

        renderDrawerPortChannels(ip, hostname, topNode);
        renderDrawerVlans(ip, topNode, dev);
        // Port-Channel e VLAN non viaggiano con la mappa: si leggono dal report
        // aggregati e dalla configurazione. Finché non arrivano le due sezioni
        // dicevano "nessuno" per apparati che invece ne hanno.
        fillDrawerFromBackend(nodeId, ip, hostname, topNode, dev);

        // Action buttons
        const btnAnalyzer = document.getElementById('drawerBtnAnalyzer');
        if (btnAnalyzer) {
            btnAnalyzer.onclick = () => {
                openPortInAnalyzer(ip, '');
            };
        }
        const btnTriage = document.getElementById('drawerBtnTriage');
        if (btnTriage) {
            btnTriage.onclick = () => {
                switchTab('tab-triage');
            };
        }

        // Richiudi il gruppo: unica via praticabile su touch, dove il doppio
        // click su un membro non è un gesto.
        const btnCollapseGrp = document.getElementById('drawerBtnCollapseGroup');
        if (btnCollapseGrp) {
            const key = layeredGroupOfChild[nodeId];
            btnCollapseGrp.style.display = key ? '' : 'none';
            btnCollapseGrp.onclick = key ? () => { closeTopologyNodeDrawer(); toggleLayeredGroup(layeredGroup, key); } : null;
        }

        // Core by hand, in both views: a third pick replaces the second core.
        const btnCore = document.getElementById('drawerBtnSetCore');
        if (btnCore) {
            const zone = zoneKeyOf(nodeId) || '';
            const cores = rootsOf(layeredGroup)[zone] || [];
            const isCore = cores.includes(nodeId);
            btnCore.querySelector('span').textContent = isCore
                ? (tr('topoClearCore'))
                : (tr('topoSetAsCore'));
            btnCore.onclick = () => {
                closeTopologyNodeDrawer();
                setLayeredRoots(layeredGroup, zone, isCore ? cores.filter(id => id !== nodeId)
                    : cores.length < 2 ? [...cores, nodeId] : [cores[0], nodeId]);
            };
        }

        drawer.classList.add('open');
        // Il pannello è un dialogo: il fuoco ci entra, così chi naviga da
        // tastiera legge quello che è appena comparso invece di restare sulla
        // mappa. Alla chiusura il fuoco torna da dove è arrivato.
        const titleEl = document.getElementById('drawerNodeHostname');
        if (titleEl && document.activeElement !== titleEl) titleEl.focus({ preventScroll: true });
    }

    function closeTopologyNodeDrawer() {
        const drawer = document.getElementById('topologyNodeDrawer');
        if (drawer) drawer.classList.remove('open');
        currentSelectedNodeId = null;
    }

    document.getElementById('btnCloseNodeDrawer')?.addEventListener('click', closeTopologyNodeDrawer);

    // ===== Tastiera sulla mappa =====
    // Vis.js disegna su canvas: senza questi tasti un apparato si può scegliere
    // solo col mouse, e il pannello resta irraggiungibile. Frecce = nodo
    // precedente/successivo, Invio = apri, Esc = chiudi.
    function focusMapNode(step) {
        if (!networkInstance) return;
        const ids = lastRenderedNodeIds;
        if (!ids.length) return;
        const cur = ids.indexOf(currentSelectedNodeId);
        const next = ids[(cur + step + ids.length) % ids.length];
        networkInstance.selectNodes([next]);
        networkInstance.focus(next, { scale: networkInstance.getScale(), animation: false });
        openTopologyNodeDrawer(next);
    }
    document.getElementById('networkGraphContainer')?.addEventListener('keydown', ev => {
        if (ev.key === 'ArrowRight' || ev.key === 'ArrowDown') { ev.preventDefault(); focusMapNode(1); }
        else if (ev.key === 'ArrowLeft' || ev.key === 'ArrowUp') { ev.preventDefault(); focusMapNode(-1); }
        else if (ev.key === 'Enter' && currentSelectedNodeId) { ev.preventDefault(); openTopologyNodeDrawer(currentSelectedNodeId); }
    });
    document.getElementById('topologyNodeDrawer')?.addEventListener('keydown', ev => {
        if (ev.key !== 'Escape') return;
        closeTopologyNodeDrawer();
        document.getElementById('networkGraphContainer')?.focus({ preventScroll: true });
    });

    // Separazione AABB dei riquadri dopo un trascinamento: il nodo mosso viene
    // spinto fuori da ogni riquadro intersecato lungo l'asse di minima
    // penetrazione, iterando finché non restano sovrapposizioni.
    function resolveNodeOverlaps(movedIds) {
        if (!networkInstance) return;
        const margin = 14;
        const allIds = networkInstance.body.data.nodes.getIds();
        for (let iter = 0; iter < 15; iter++) {
            let pushed = false;
            movedIds.forEach(id => {
                let bb; try { bb = networkInstance.getBoundingBox(id); } catch (e) { return; }
                let pos = networkInstance.getPosition(id);
                allIds.forEach(oid => {
                    if (oid === id || movedIds.includes(oid) && oid < id) return;
                    let ob; try { ob = networkInstance.getBoundingBox(oid); } catch (e) { return; }
                    const overlapX = Math.min(bb.right, ob.right) - Math.max(bb.left, ob.left) + margin;
                    const overlapY = Math.min(bb.bottom, ob.bottom) - Math.max(bb.top, ob.top) + margin;
                    if (overlapX <= 0 || overlapY <= 0) return;
                    const op = networkInstance.getPosition(oid);
                    if (overlapX < overlapY) {
                        const dir = pos.x >= op.x ? 1 : -1;
                        networkInstance.moveNode(id, pos.x + dir * overlapX, pos.y);
                    } else {
                        const dir = pos.y >= op.y ? 1 : -1;
                        networkInstance.moveNode(id, pos.x, pos.y + dir * overlapY);
                    }
                    pushed = true;
                    bb = networkInstance.getBoundingBox(id);
                    pos = networkInstance.getPosition(id);
                });
            });
            if (!pushed) break;
        }
        // moveNode() qui è un salto diretto (nessuna fisica coinvolta): ribadiamo
        // comunque physics disattivata per difesa, nel caso una regressione futura
        // la riattivasse durante il drag (Fix A: la mappa non deve mai tornare ad
        // animarsi da sola dopo la stabilizzazione iniziale).
        networkInstance.setOptions({ physics: { enabled: false } });
        networkInstance.redraw();
    }

    // Schema view layout, run once the boxes have their real size: one row
    // per level, each box under the mean x of its neighbours in the rows
    // above, never closer than SCHEMA_GAP to the next one. The space between
    // two rows grows with the cables crossing it, so their runs get tracks.
    // ponytail: one top-down barycentre pass, like the hierarchy view's.
    const SCHEMA_GAP = 70;
    const SCHEMA_WRAP_MIN = 8;   // rows longer than this wrap when "Wrap rows" is on
    function packSchemaRows() {
        if (!networkInstance) return;
        const wrap = schemaPref('schemaWrap', '0') === '1';
        const ds = networkInstance.body.data.nodes;
        // One block of rows per location, blocks side by side: packed as one
        // set of rows, two sites' boxes interleaved and their zones overlapped.
        const zoneOf = nd => topoZone(nd.nodeDataVal || { id: nd.id }).key;
        const box = {}, zones = {};
        ds.forEach(nd => {
            const b = networkInstance.getBoundingBox(nd.id);
            box[nd.id] = { w: b.right - b.left, h: b.bottom - b.top };
            const rows = zones[zoneOf(nd)] || (zones[zoneOf(nd)] = {});
            (rows[nd.schemaLevel] || (rows[nd.schemaLevel] = [])).push(nd);
        });
        const adj = {}, wires = {}, same = {};
        (minimalOverlayData ? minimalOverlayData.bundles : []).forEach(b => {
            const la = ds.get(b.from), lb = ds.get(b.to);
            if (!la || !lb || zoneOf(la) !== zoneOf(lb)) return;
            (adj[b.from] || (adj[b.from] = [])).push(b.to);
            (adj[b.to] || (adj[b.to] = [])).push(b.from);
            const top = Math.min(la.schemaLevel, lb.schemaLevel);
            if (la.schemaLevel !== lb.schemaLevel) wires[top] = (wires[top] || 0) + b.members.length;
            else same[top] = (same[top] || 0) + b.members.length;
        });
        // "Column" AP mode: a switch's single-homed APs leave the rows and
        // stand in a column beside it, on its right. Under it they sat where
        // the switch's own cables leave and were cut through. The switch grows
        // as tall as its column and counts as wide as switch + column, so
        // nothing hangs below it and its row keeps the rest clear.
        // COL_SIDE: switch edge to spine; BRANCH: spine to AP, room for the port name.
        const COL_GAP = 6, COL_SIDE = 10, BRANCH = 50;
        const cols = schemaApMode() === 'column' && minimalOverlayData
            ? schemaLeafColumns(minimalOverlayData.bundles || [], id => ((ds.get(id) || {}).nodeDataVal || {}).device_type, GROUPABLE_TYPES)
            : {};
        const col = {};
        Object.entries(cols).forEach(([parent, leaves]) => {
            if (!box[parent] || leaves.some(id => !box[id])) return;
            leaves.forEach(id => {
                const nd = ds.get(id), rows = zones[zoneOf(nd)];
                rows[nd.schemaLevel] = rows[nd.schemaLevel].filter(x => x.id !== id);
            });
            col[parent] = { leaves, w: COL_SIDE + BRANCH + Math.max(...leaves.map(id => box[id].w)),
                            h: leaves.reduce((t, id) => t + box[id].h, 0) + COL_GAP * (leaves.length - 1) };
        });
        // Room a box takes in its row: switch + its AP column; the unit's
        // centre sits unitOff(id) right of the switch centre.
        const ew = id => box[id].w + (col[id] ? col[id].w : 0);
        const eh = id => col[id] ? Math.max(box[id].h, col[id].h) : box[id].h;
        const unitOff = id => col[id] ? col[id].w / 2 : 0;
        const pos = {};
        let base = 0;
        Object.keys(zones).sort().forEach(zk => {
        const rows = zones[zk];
        let top = 0;
        Object.keys(rows).map(Number).sort((a, b) => a - b).forEach(lv => {
            if (!rows[lv].length) return;   // a row of APs all moved into columns
            // Room above the row for cables between its own boxes that run over it.
            if (same[lv]) top += 20 + 8 * same[lv];
            const want = nd => {
                const xs = (adj[nd.id] || []).filter(id => pos[id]).map(id => pos[id].x);
                return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
            };
            const row = rows[lv].map(nd => ({ nd, w: want(nd) }))
                .sort((a, b) => ((a.w ?? Infinity) - (b.w ?? Infinity)) || String(a.nd.id).localeCompare(String(b.nd.id)));
            // "Wrap rows": a long row splits into two staggered sub-rows,
            // centred under the mean of what it hangs from.
            // Small leaf boxes (APs) are never zigzagged: they stay packed under their switch.
            if (wrap && row.length > SCHEMA_WRAP_MIN && !row.some(r => r.nd._compact)) {
                const z = zigzagRow(row.map(r => ew(r.nd.id)), SCHEMA_GAP);
                const maxW = Math.max(...row.map(r => ew(r.nd.id)));
                const maxH = Math.max(...row.map(r => eh(r.nd.id)));
                const blockW = z[z.length - 1].x + maxW / 2;
                const ws = row.filter(r => r.w !== null).map(r => r.w);
                const left = ws.length ? ws.reduce((a, b) => a + b, 0) / ws.length - blockW / 2 : base;
                row.forEach((r, i) => {
                    pos[r.nd.id] = { x: left + z[i].x - unitOff(r.nd.id), y: top + z[i].sub * (maxH + 60) + eh(r.nd.id) / 2 };
                });
                top += 2 * maxH + 60 + 120 + 8 * (wires[lv] || 0);
                return;
            }
            let right = -Infinity, prevCompact = false;
            row.forEach(r => {
                const bw = ew(r.nd.id);
                // Two small leaf boxes side by side (APs of one switch) sit close.
                const gap = prevCompact && r.nd._compact ? 16 : SCHEMA_GAP;
                const want = r.w === null ? null : r.w + unitOff(r.nd.id);
                const x = Math.max(want ?? (right === -Infinity ? base + bw / 2 : right + gap + bw / 2), right + gap + bw / 2);
                pos[r.nd.id] = { x: x - unitOff(r.nd.id), y: top + eh(r.nd.id) / 2 };
                right = x + bw / 2;
                prevCompact = !!r.nd._compact;
            });
            // Pushed right by the packing: slide the row back so it stays
            // centred under what it hangs from.
            const off = row.filter(r => r.w !== null).map(r => pos[r.nd.id].x - r.w);
            const shift = off.length ? off.reduce((a, b) => a + b, 0) / off.length : 0;
            row.forEach(r => { pos[r.nd.id].x -= shift; });
            top += Math.max(...row.map(r => eh(r.nd.id))) + 120 + 8 * (wires[lv] || 0);
        });
        // Rows were centred under their parents: shift the block so its left
        // edge starts where the previous site ended, then leave a gap.
        const ids = [].concat(...Object.values(rows)).map(nd => nd.id);
        const left = Math.min(...ids.map(id => pos[id].x - box[id].w / 2));
        ids.forEach(id => { pos[id].x += base - left; });
        base = Math.max(...ids.map(id => pos[id].x - box[id].w / 2 + ew(id))) + SCHEMA_GAP * 4;
        });
        // Unpack the columns beside their switch, the first AP level with its top.
        const grow = [];
        Object.entries(col).forEach(([parent, c]) => {
            const p = pos[parent];
            if (!p) return;
            const x0 = p.x + box[parent].w / 2 + COL_SIDE + BRANCH;
            let y = p.y - eh(parent) / 2;
            c.leaves.forEach(id => {
                pos[id] = { x: x0 + box[id].w / 2, y: y + box[id].h / 2 };
                y += box[id].h + COL_GAP;
            });
            if (c.h > box[parent].h) grow.push({ id: parent, heightConstraint: { minimum: Math.ceil(c.h) } });
        });
        if (grow.length) ds.update(grow);
        Object.entries(pos).forEach(([id, p]) => networkInstance.moveNode(id, p.x, p.y));
        saveSchemaPositions();
        setTimeout(() => networkInstance && networkInstance.fit(), 50);
    }

    // Schema positions per site, in the browser: {"<site>": {"<id>": [x, y]}}.
    // Same persistence as the hierarchy levels; "Riordina mappa" rewrites them.
    function loadSchemaPositions(group) {
        try {
            const m = (JSON.parse(localStorage.getItem('schemaPositions') || '{}') || {})[group];
            if (!m) return null;
            const out = {};
            Object.entries(m).forEach(([id, p]) => { out[id] = { x: p[0], y: p[1] }; });
            return out;
        } catch (e) { return null; }
    }
    function saveSchemaPositions() {
        if (!networkInstance || getMapView() !== 'minimal') return;
        try {
            const all = JSON.parse(localStorage.getItem('schemaPositions') || '{}') || {};
            const m = {};
            Object.entries(networkInstance.getPositions()).forEach(([id, p]) => { m[id] = [Math.round(p.x), Math.round(p.y)]; });
            all[lastMapGroup || ''] = m;
            localStorage.setItem('schemaPositions', JSON.stringify(all));
        } catch (e) { /* storage full or blocked: the layout just is not remembered */ }
    }

    // Devices new since the saved layout: each goes at the right end of its
    // level's row (the row of an already placed device of the same level),
    // so nothing the user arranged moves. A level with no saved row goes
    // below the drawing.
    function placeNewSchemaNodes(knownIds) {
        const ds = networkInstance.body.data.nodes, known = new Set(knownIds);
        const rowTop = {}, rowRight = {};
        let bottom = -Infinity;
        // A row is a level: boxes of one row share their top edge, not their centre.
        ds.forEach(nd => {
            if (!known.has(nd.id)) return;
            const b = networkInstance.getBoundingBox(nd.id), lv = nd.schemaLevel;
            bottom = Math.max(bottom, b.bottom);
            rowTop[lv] = Math.min(rowTop[lv] ?? Infinity, b.top);
            rowRight[lv] = Math.max(rowRight[lv] ?? -Infinity, b.right);
        });
        ds.forEach(nd => {
            if (known.has(nd.id)) return;
            const b = networkInstance.getBoundingBox(nd.id), w = b.right - b.left, h = b.bottom - b.top;
            const lv = nd.schemaLevel;
            if (rowTop[lv] === undefined) { rowTop[lv] = bottom + 160; bottom += 160 + h; }
            const x = (rowRight[lv] ?? -SCHEMA_GAP) + SCHEMA_GAP + w / 2;
            rowRight[lv] = x + w / 2;
            networkInstance.moveNode(nd.id, x, rowTop[lv] + h / 2);
        });
        saveSchemaPositions();
    }

    // ===== Nuova mappa minimalista (stile diagramma Visio) =====
    // Stili centralizzati: modificare QUI per ritoccare la resa (nodi, colori,
    // spessori, font). Ispirata all'immagine di esempio fornita dall'utente.
    const MINIMAL_MAP_STYLE = {
        background: '#ffffff',                     // sfondo bianco/neutro, alta leggibilità
        node: {
            shape: 'box',                          // riquadri rettangolari a spigoli vivi
            borderRadius: 0,
            borderWidth: 1,
            borderColor: '#37474f',                // bordo scuro sottile
            margin: { top: 8, right: 12, bottom: 8, left: 12 },
            font: { multi: 'html', color: '#1a2430', size: 12, face: 'Arial, Helvetica, sans-serif', strokeWidth: 0,
                    // <i> = riga di management attenuata e più piccola; <b> = nome host.
                    ital: { color: '#6b7a8a', size: 10, face: 'Arial, Helvetica, sans-serif' },
                    bold: { color: '#1a2430', size: 12, face: 'Arial, Helvetica, sans-serif' } },
            offlineOpacity: 0.45,
            // Riempimenti pastello per categoria di apparato (varianti ciano/giallo pallido)
            fill: {
                switch:   '#d8f0f7',
                router:   '#def0dc',
                firewall: '#fbe4e2',
                wlc:      '#ebe2f7',
                ap:       '#e0ecfb',
                server:   '#fdf3d5',
                phone:    '#dcf5ef',
                camera:   '#fbecd6',
                pc:       '#ededed',
                other:    '#f4f4f4'
            }
        },
        edge: {
            color:   '#78909c',                    // link semplice: pieno, tonalità sobria
            width:   1.5,
            pcColor: '#8B4513',                    // aggregato Port-Channel/vPC: rame/marrone (stile Cisco)
            pcWidth: 2,
            peerColor: '#2e7d32',                  // peer-link / peer-keepalive vPC: verde
            font: { multi: 'html', color: '#455a64', size: 10, face: 'Arial, Helvetica, sans-serif', strokeWidth: 0, background: '#ffffff' },
            pcFontColor: '#8B4513',
            // Contenitore tratteggiato di raggruppamento per Sede/Gruppo
            group: { stroke: '#90a4ae', fill: 'rgba(120,144,156,0.05)', font: '#607d8b' }
        }
    };

    // ponytail: unica fonte tipo→colore per render + legenda + color-picker.
    // I default ricalcano i colori di MINIMAL_MAP_STYLE; l'utente li può cambiare
    // e la scelta è ricordata in localStorage e applicata a ogni ridisegno.
    const MINIMAL_LINK_TYPES = [
        { key: 'pc',        it: 'Port-Channel',      en: 'Port-Channel',      def: MINIMAL_MAP_STYLE.edge.pcColor },
        { key: 'peer',      it: 'Peer-link / vPC',   en: 'Peer-link / vPC',   def: MINIMAL_MAP_STYLE.edge.peerColor },
        { key: 'keepalive', it: 'Peer-keepalive',    en: 'Peer-keepalive',    def: MINIMAL_MAP_STYLE.edge.peerColor },
        { key: 'link',      it: 'Link semplice',     en: 'Simple link',       def: MINIMAL_MAP_STYLE.edge.color }
    ];
    let minimalLinkColors = {};
    try { minimalLinkColors = JSON.parse(localStorage.getItem('minimalLinkColors') || '{}'); } catch (e) { minimalLinkColors = {}; }
    function linkColor(key) {
        if (minimalLinkColors[key]) return minimalLinkColors[key];
        const t = MINIMAL_LINK_TYPES.find(x => x.key === key);
        return t ? t.def : MINIMAL_MAP_STYLE.edge.color;
    }
    // Converte un colore #rrggbb nel corrispondente rgba() con alpha (per i
    // riempimenti traslucidi della pillola aggregata).
    function hexToRgba(hex, a) {
        const m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || '');
        if (!m) return hex;
        return `rgba(${parseInt(m[1],16)},${parseInt(m[2],16)},${parseInt(m[3],16)},${a})`;
    }
    // Color-picker + legenda della nuova mappa: righe generate dalla stessa
    // tabella tipo→colore usata dal renderer (fonte unica).
    function renderMinimalLegend() {
        const box = document.getElementById('minimalLegendWrap');
        if (!box) return;
        box.innerHTML = MINIMAL_LINK_TYPES.map(t => `
            <label style="display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:700; color:var(--text-muted); cursor:pointer; user-select:none;" title="${currentLang==='en'?t.en:t.it}">
                <input type="color" value="${linkColor(t.key)}" data-action="set-minimal-link-color" data-key="${attrEsc(t.key)}" style="width:22px; height:18px; padding:0; border:1px solid var(--border); border-radius:0; background:none; cursor:pointer;">
                <span>${currentLang==='en'?t.en:t.it}</span>
            </label>`).join('')
            // Categorie personalizzate (sola visualizzazione: gestione nel pannello
            // dedicato "Categorie link"), stessa tabella tipo→colore mostrata come
            // fonte unica di legenda.
            + Object.keys(minimalCustomCats.categories).map(nm => {
                const c = minimalCustomCats.categories[nm];
                return `<span style="display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:700; color:var(--text-muted);" title="${escapeHtml(nm)}">
                    <span style="width:18px; height:0; border-top:2px ${c.dash==='dashed'?'dashed':(c.dash==='dotted'?'dotted':'solid')} ${c.color}; display:inline-block;"></span>
                    <span>${escapeHtml(nm)}</span>
                </span>`;
            }).join('');
    }

    document.getElementById('minimalLegendWrap')?.addEventListener('change', (e) => {
        const inp = e.target.closest('input[data-action="set-minimal-link-color"]');
        if (inp && inp.dataset.key) {
            setMinimalLinkColor(inp.dataset.key, inp.value);
        }
    });

    function setMinimalLinkColor(key, val) {
        minimalLinkColors[key] = val;
        localStorage.setItem('minimalLinkColors', JSON.stringify(minimalLinkColors));
        renderMinimalLegend();
        loadInteractiveMap();
    }

    // ===== Categorie personalizzate per i link (assegnazione manuale) =====
    // ponytail: stessa idea della tabella tipo→colore sopra, ma per categorie
    // create dall'utente e assegnate a SINGOLI collegamenti (non per tipo).
    // Storage minimale in localStorage: { categories: {nome:{color,dash}},
    // assignments: {edgeKey:nome} }. edgeKey = stessa chiave stabile from~to~pcTag
    // già usata per le pillole Port-Channel spostabili (pillKey), così un solo
    // formato di chiave copre entrambe le feature.
    let minimalCustomCats = { categories: {}, assignments: {} };
    try {
        const parsed = JSON.parse(localStorage.getItem('minimalCustomCats') || '{}');
        minimalCustomCats.categories = parsed.categories || {};
        minimalCustomCats.assignments = parsed.assignments || {};
    } catch (e) { /* mantiene i default vuoti */ }
    function saveMinimalCustomCats() { localStorage.setItem('minimalCustomCats', JSON.stringify(minimalCustomCats)); }
    function dashArrFor(style) { return style === 'dashed' ? [6, 4] : style === 'dotted' ? [2, 3] : null; }
    // Stile di una categoria personalizzata assegnata a un arco (se presente):
    // vince sempre sullo stile per-tipo standard in styleFor().
    function customStyleForEdge(edgeKey) {
        const nm = minimalCustomCats.assignments[edgeKey];
        const c = nm && minimalCustomCats.categories[nm];
        return c ? { color: c.color, dash: dashArrFor(c.dash) } : null;
    }
    function addMinimalCustomCat() {
        const nameInput = document.getElementById('minimalCatNameInput');
        const colorInput = document.getElementById('minimalCatColorInput');
        const dashInput = document.getElementById('minimalCatDashInput');
        const name = (nameInput?.value || '').trim();
        if (!name) return;
        minimalCustomCats.categories[name] = { color: colorInput?.value || '#607d8b', dash: dashInput?.value || 'solid' };
        saveMinimalCustomCats();
        if (nameInput) nameInput.value = '';
        renderMinimalCustomCatPanel();
        loadInteractiveMap();
    }
    function deleteMinimalCustomCat(name) {
        delete minimalCustomCats.categories[name];
        Object.keys(minimalCustomCats.assignments).forEach(k => {
            if (minimalCustomCats.assignments[k] === name) delete minimalCustomCats.assignments[k];
        });
        saveMinimalCustomCats();
        renderMinimalCustomCatPanel();
        loadInteractiveMap();
    }
    // Piccola UI di gestione accanto a legenda/color-picker: elenco categorie
    // (pallino colore + stile tratteggio + elimina) e form nativo per crearne una.
    function renderMinimalCustomCatPanel() {
        const box = document.getElementById('minimalCustomCatList');
        if (!box) return;
        const names = Object.keys(minimalCustomCats.categories);
        const dashLabel = d => d === 'dashed' ? (tr('topoDashed'))
                              : d === 'dotted' ? (tr('topoDotted'))
                              : (tr('topoSolid'));
        const rows = names.map(nm => {
            const c = minimalCustomCats.categories[nm];
            return `<div style="display:flex; align-items:center; gap:6px; padding:3px 0;">
                <span style="width:14px; height:14px; border-radius:0; background:${c.color}; border:1px solid var(--border); display:inline-block;"></span>
                <span style="flex:1; font-size:12px; color:var(--text);">${escapeHtml(nm)}</span>
                <span style="font-size:10px; color:var(--text-muted);">${dashLabel(c.dash)}</span>
                <button data-action="delete-minimal-custom-cat" data-name="${attrEsc(nm)}" title="${tr('uiDelete')}" style="background:none; border:none; color:var(--lamp-fault-ink); cursor:pointer; font-size:12px; padding:2px;"><i class="fa-solid fa-trash-can"></i></button>
            </div>`;
        }).join('') || `<div style="font-size:12px; color:var(--text-muted); padding:4px 0;">${tr('topoNoCategoriesYet')}</div>`;
        box.innerHTML = rows + `
            <div style="display:flex; align-items:center; gap:6px; margin-top:8px; padding-top:8px; border-top:1px solid var(--border);">
                <input id="minimalCatNameInput" type="text" placeholder="${tr('topoName')}" style="flex:1; min-width:0; padding:4px 6px; border-radius:0; border:1px solid var(--border); background:var(--surface-1); color:var(--text); font-size:12px;">
                <input id="minimalCatColorInput" type="color" value="#607d8b" style="width:24px; height:24px; padding:0; border:1px solid var(--border); border-radius:0; background:none; cursor:pointer;">
                <select id="minimalCatDashInput" style="padding:3px; border-radius:0; border:1px solid var(--border); background:var(--surface-1); color:var(--text); font-size:11px;">
                    <option value="solid">${tr('topoSolid')}</option>
                    <option value="dashed">${tr('topoDashed')}</option>
                    <option value="dotted">${tr('topoDotted')}</option>
                </select>
                <button data-action="add-minimal-custom-cat" title="${tr('topoAddCategory')}" style="background:var(--cta); color:var(--cta-text); border:none; border-radius:0; padding:4px 8px; cursor:pointer; font-size:12px;"><i class="fa-solid fa-plus"></i></button>
            </div>`;
    }

    document.getElementById('minimalCustomCatList')?.addEventListener('click', (e) => {
        const delBtn = e.target.closest('[data-action="delete-minimal-custom-cat"]');
        if (delBtn && delBtn.dataset.name) {
            deleteMinimalCustomCat(delBtn.dataset.name);
            return;
        }
        const addBtn = e.target.closest('[data-action="add-minimal-custom-cat"]');
        if (addBtn) {
            addMinimalCustomCat();
        }
    });
    // Menu contestuale (click destro su un cavo nella mappa minimalista) per
    // assegnare/rimuovere la categoria personalizzata di un singolo collegamento.
    function closeEdgeCatMenu() {
        const m = document.getElementById('edgeCatMenu');
        if (m) m.remove();
        document.removeEventListener('mousedown', closeEdgeCatMenuOutside, true);
    }
    function closeEdgeCatMenuOutside(ev) {
        const m = document.getElementById('edgeCatMenu');
        if (m && !m.contains(ev.target)) closeEdgeCatMenu();
    }
    function showEdgeCatMenu(x, y, edgeKey) {
        closeEdgeCatMenu();
        const names = Object.keys(minimalCustomCats.categories);
        const cur = minimalCustomCats.assignments[edgeKey];
        const div = document.createElement('div');
        div.id = 'edgeCatMenu';
        div.style.cssText = `position:fixed; left:${x}px; top:${y}px; z-index:9999; background:var(--surface-2); border:1px solid var(--border); border-radius:0; padding:6px; box-shadow:0 10px 30px rgba(0,0,0,0.5); font-family:inherit; font-size:12px; min-width:170px;`;
        const rowsHtml = names.length ? names.map(nm => `
            <div class="edgeCatRow" data-nm="${attrEsc(nm)}" style="display:flex; align-items:center; gap:6px; padding:4px 6px; border-radius:0; cursor:pointer; color:var(--text); ${nm===cur?'background:rgba(120,144,156,0.25);':''}">
                <span style="width:10px; height:10px; border-radius:50%; background:${minimalCustomCats.categories[nm].color}; display:inline-block;"></span>
                <span>${escapeHtml(nm)}</span>
            </div>`).join('')
            : `<div style="padding:4px 6px; color:var(--text-muted);">${tr('topoNoCustomCategoriesYet')}</div>`;
        const noneRow = `<div class="edgeCatRow" data-nm="" style="display:flex; align-items:center; gap:6px; padding:4px 6px; border-radius:0; cursor:pointer; color:var(--text-muted);">${tr('topoNoneDefaultStyle')}</div>`;
        div.innerHTML = rowsHtml + `<div style="border-top:1px solid var(--border); margin:4px 0;"></div>` + noneRow;
        document.body.appendChild(div);
        div.querySelectorAll('.edgeCatRow').forEach(row => {
            row.addEventListener('click', () => {
                const nm = row.getAttribute('data-nm');
                if (nm) minimalCustomCats.assignments[edgeKey] = nm;
                else delete minimalCustomCats.assignments[edgeKey];
                saveMinimalCustomCats();
                closeEdgeCatMenu();
                if (networkInstance) networkInstance.redraw();
            });
        });
        setTimeout(() => document.addEventListener('mousedown', closeEdgeCatMenuOutside, true), 0);
    }

    // Costruisce nodi/archi/opzioni per la vista minimalista dai medesimi dati già
    // filtrati della mappa classica. Nodi = riquadri con nome in grassetto e
    // vendor/modello sulla seconda riga; i Port-Channel sono SEMPRE visibili come
    // un arco aggregato con etichetta "Po1" + coppie di interfacce membro sotto.
    // Port-channel name shown at each end of a bundle, beside the bracket that
    // groups its member ports. Empty for plain links and keepalives.
    function pcEndTags(b) {
        if (b.type !== 'pc' && b.type !== 'peer') return { from: '', to: '' };
        return b.asymmetricPc ? { from: b.localLabel, to: b.remoteLabel } : { from: b.label, to: b.label };
    }

    function buildMinimalGraph(nodeData, linkData, opts) {
        const S = MINIMAL_MAP_STYLE;
        const showVtpDomain = !!(opts && opts.showVtpDomain);
        // Tooltip al passaggio del mouse: opt-in tramite l'interruttore dedicato.
        // Le informazioni Port-Channel restano comunque SEMPRE visibili come
        // etichette permanenti sul disegno.
        const hoverInfo     = !!(opts && opts.hoverInfo);

        // Raggruppamento spaziale per Sede: ogni gruppo riceve un "centro" su una
        // circonferenza e i suoi nodi partono da lì (la fisica mantiene i cluster).
        // vis.js non supporta i riquadri tratteggiati di raggruppamento: si
        // approssima con la sola vicinanza spaziale.
        const zoneOf = {};
        nodeData.forEach(n => { zoneOf[n.id] = topoZone(n); });
        const groups = [...new Set(nodeData.map(n => zoneOf[n.id].key))];
        const groupCenter = {};
        groups.forEach((g, i) => {
            const angle = (2 * Math.PI * i) / groups.length;
            const radius = groups.length > 1 ? 600 : 0;
            groupCenter[g] = { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius };
        });

        const compact = schemaCompactLeaves(nodeData, linkData, GROUPABLE_TYPES);
        const nodes = nodeData.map((n, idx) => {
            const scan = globalVersions[n.id] || { version: tr('topoNotDetected'), status: n.status };
            const effectiveStatus = (scan && scan.status && scan.status !== 'unknown') ? scan.status : (n.status || 'offline');
            n.status = effectiveStatus;
            const matchedDev = globalDevices.find(d => d.IP === n.id);
            const resolvedVendor = (n.vendor && n.vendor !== 'discovered')
                ? n.vendor : (matchedDev && matchedDev.Vendor ? matchedDev.Vendor : 'discovered');

            // Seconda riga del riquadro: vendor + modello (es. "Cisco N9K-C93180YC-EX")
            const vendorTxt = (resolvedVendor && resolvedVendor !== 'discovered')
                ? resolvedVendor.charAt(0).toUpperCase() + resolvedVendor.slice(1) : '';
            // Se il nodo è uno stack la riga diventa "N × <vendor> <modello> in STACK".
            const stack = nodeStack(n);
            const modelLine = stack
                ? stackLine(stack, vendorTxt, n.model || n.platform)
                : [vendorTxt, n.model || n.platform || ''].filter(Boolean).join(' ').trim();
            // Riga di management (piccola, in corsivo/attenuata): VLAN + IP di
            // gestione mostrati DENTRO il riquadro. La VLAN arriva dal backend
            // (SVI con l'IP di management); se assente si mostra solo l'IP.
            const mgmtIp = n.is_group ? '' : (n.mgmt_ip || (n.status === 'discovered' ? n.reported_ip : n.id) || '');
            const mgmtBits = [];
            if (n.mgmt_vlan) mgmtBits.push((tr('topoVlan')) + n.mgmt_vlan);
            if (mgmtIp) mgmtBits.push(mgmtIp);
            const mgmtLine = mgmtBits.join('  ·  ');
            let label = `<b>${n.label}</b>`;
            // Small leaf box: name and address only.
            if (compact.has(n.id)) { if (mgmtIp) label += `\n<i>${mgmtIp}</i>`; }
            else {
                if (modelLine) label += `\n${modelLine}`;
                if (mgmtLine)  label += `\n<i>${mgmtLine}</i>`;
            }
            if (showVtpDomain && n.vtp_domain) {
                const vtpModeTxt = n.vtp_mode ? String(n.vtp_mode).toLowerCase() : '';
                label += `\nVTP: ${vtpModeTxt ? `${n.vtp_domain} · ${vtpModeTxt}` : n.vtp_domain}`;
            }

            // Riempimento pastello per categoria; col toggle VTP il bordo assume il
            // colore del dominio VTP (il riempimento resta neutro e leggibile).
            const fill = S.node.fill[n.device_type] || S.node.fill.other;
            const border = showVtpDomain && n.vtp_domain ? vtpDomainColor(n.vtp_domain) : S.node.borderColor;

            // Posizione iniziale: attorno al centro del proprio gruppo/Sede.
            const c = groupCenter[zoneOf[n.id].key] || { x: 0, y: 0 };
            const jitter = 180;

            return {
                id: n.id,
                shape: S.node.shape,
                shapeProperties: { borderRadius: S.node.borderRadius },
                margin: compact.has(n.id) ? { top: 5, right: 10, bottom: 5, left: 10 } : S.node.margin,
                _compact: compact.has(n.id),
                label,
                title: hoverInfo ? (n.is_group ? groupTooltip(n) : createNodeTooltip(n, scan, resolvedVendor)) : undefined,
                borderWidth: (stack && stack.health === 'degraded') ? S.node.borderWidth + 1
                           : (showVtpDomain && n.vtp_domain ? 2 : S.node.borderWidth),
                borderWidthSelected: S.node.borderWidth + 1,
                color: {
                    background: fill, border,
                    highlight: { background: fill, border: '#1a2430' },
                    hover: { background: fill, border: '#1a2430' }
                },
                opacity: (effectiveStatus === 'offline') ? S.node.offlineOpacity : 1,
                font: S.node.font,
                x: c.x + ((idx * 137) % (2 * jitter)) - jitter,
                y: c.y + ((idx * 89)  % (2 * jitter)) - jitter,
                nodeDataVal: n,
                // Testi della targhetta (nome + vendor/modello) usati dal
                // dimensionamento per garantire che le etichette di porta
                // disegnate ai bordi non collidano mai col nome centrale.
                _nameTexts: [n.label || '', modelLine, mgmtLine]
            };
        });

        // Fasci Port-Channel/vPC con ≥2 interfacce membro: disegnati come linee
        // parallele separate (una per cavo fisico) con etichette di porta a ciascun
        // estremo e un'ellisse "Po/vPC" che attraversa il gruppo (stile Cisco Visio).
        // Questi non producono un arco vis.js visibile: sono resi nell'overlay
        // afterDrawing. Un arco invisibile viene comunque creato per mantenere la
        // fisica (attrazione tra i due nodi) e il tooltip.
        // Mappa id→label per riconoscere coppie di peer vPC (es. EX_1/EX_2, Nexus-A/
        // Nexus-B) dagli hostname, e info di raggruppamento per i contenitori Sede.
        const labelById = {};
        nodeData.forEach(n => { labelById[n.id] = n.label || n.id; });
        // vPC esiste solo su NX-OS: la coppia peer va confermata dalla
        // piattaforma (modello/platform Nexus), altrimenti un normale
        // Port-channel tra "SW1"/"SW2" verrebbe etichettato a torto "poX/vpc"
        // (fix §9.7 del piano). Heuristica hostname mantenuta SOLO come
        // condizione aggiuntiva, mai da sola.
        const isNxos = {};
        nodeData.forEach(n => {
            isNxos[n.id] = /nexus|nx-?os|\bn[359]k\b/i.test(
                [n.model, n.platform, n.version].filter(Boolean).join(' '));
        });
        const isMgmtPort = p => /mgmt|ma\d|management/i.test(p || '');
        // Due nodi formano una coppia peer se gli hostname condividono lo stesso
        // prefisso e differiscono solo per il suffisso finale (1/2, A/B, _1/_2…).
        const looksLikePeerPair = (a, b) => {
            const na = String(a || '').split('.')[0], nb = String(b || '').split('.')[0];
            if (!na || !nb || na.toLowerCase() === nb.toLowerCase()) return false;
            const strip = s => s.replace(/[ _-]?([12]|[ab])$/i, '');
            const ra = strip(na), rb = strip(nb);
            return ra && ra.toLowerCase() === rb.toLowerCase() && ra !== na && rb !== nb;
        };

        // Info raggruppamento per Sede/Gruppo (contenitore tratteggiato nell'overlay).
        const groupsInfo = groups.map(g => {
            const ids = nodeData.filter(n => zoneOf[n.id].key === g).map(n => n.id);
            return { group: ids.length ? zoneOf[ids[0]].label : '', ids };
        }).filter(gi => gi.ids.length > 0);

        const bundles = [];
        // Requisiti di dimensione per nodo: per far stare TUTTE le etichette di porta
        // disegnate dentro il riquadro (Fix dimensionamento dinamico). Per ciascun
        // nodo si tiene lo "spread" massimo (n. membri × spaziatura) e la larghezza
        // massima del testo di porta, misurata con lo stesso font dell'overlay.
        const _measCanvas = document.createElement('canvas');
        const _measCtx = _measCanvas.getContext('2d');
        _measCtx.font = '9px Arial, Helvetica, sans-serif';
        const measurePort = t => t ? _measCtx.measureText(t).width : 0;
        // Bracket (4 gap + 4 tick + 4 gap) + Port-channel name in bold 10px.
        const measureTag = t => {
            if (!t) return 0;
            _measCtx.font = 'bold 10px Arial, Helvetica, sans-serif';
            const w = _measCtx.measureText(t).width;
            _measCtx.font = '9px Arial, Helvetica, sans-serif';
            return w + 12;
        };
        // Rows by level, as in the hierarchy view: the core on top, its
        // children below. A physics layout scattered the boxes at random and
        // every cable crossed half the drawing to reach its peer. The level
        // also tells which side of the box each cable uses (sizing below).
        const levels = computeLayeredLevels(nodeData, linkData, (opts && opts.group) || '');
        const nodeReq = {};   // id -> { spread, labelW, N, S, E }: port slots per side
        const bumpReq = (id, peer, spread, labelW, slots, portW) => {
            const r = nodeReq[id] || (nodeReq[id] = { spread: 0, labelW: 0, portW: 0, N: 0, S: 0, E: 0 });
            r.spread = Math.max(r.spread, spread);
            r.labelW = Math.max(r.labelW, labelW);
            r.portW = Math.max(r.portW, portW);
            const lv = levels[id] || 0, pl = levels[peer] || 0;
            // Same row: E/W beside a neighbour, over the top (N) otherwise.
            if (pl < lv) r.N += slots; else if (pl > lv) r.S += slots; else { r.N += slots; r.E += slots; }
        };
        const edges = linkData.map(l => {
            const isPC      = !!l.is_portchannel;
            // Peer vPC: mgmt0↔mgmt0 = peer-keepalive; PortChannel tra una coppia di
            // peer (hostname appaiati) = peer-link. Entrambi resi in verde.
            // Entrambi gli estremi devono essere NX-OS (o il backend deve
            // marcare esplicitamente l.is_vpc): mai vPC su piattaforme IOS.
            const bothNxos = !!(isNxos[l.source] && isNxos[l.target]);
            const isKeepalive = bothNxos && isMgmtPort(l.local_port) && isMgmtPort(l.remote_port);
            const isPeerLink  = isPC && (l.is_vpc === true ||
                (bothNxos && looksLikePeerPair(labelById[l.source], labelById[l.target])));

            const localPorts  = (Array.isArray(l.local_ports)  && l.local_ports.length)  ? l.local_ports  : [l.local_port];
            const remotePorts = (Array.isArray(l.remote_ports) && l.remote_ports.length) ? l.remote_ports : [l.remote_port];
            const members       = localPorts.map(shortIface).filter(Boolean).join(', ');
            const remoteMembers = remotePorts.map(shortIface).filter(Boolean).join(', ');
            // Nome aggregato per-lato: il Port-channel può avere id diverso sui due
            // estremi (es. Po1 su A, Po4 su B). Se differiscono si etichetta ciascun
            // estremo col proprio id; se coincidono si tiene la pillola centrale.
            const ends = pcEnds(l);
            // pcTag also keys the saved pill positions (pillKey): it keeps
            // its old value, the per-end names are only for display.
            const pcTag = l.pc_name ? shortIface(l.pc_name) : (l.member_count > 1 ? `LAG ×${l.member_count}` : 'LAG');
            const localPcTag  = ends.local;
            const remotePcTag = ends.remote;
            const asymmetricPc = !ends.same;

            // OGNI collegamento è reso dall'overlay ortogonale con stile
            // UNIFORME (Fix rappresentazione standardizzata): i Port-Channel
            // come fascio di cavi paralleli attraversati dalla pillola ovale
            // (anche quando è nota una sola interfaccia membro), i link
            // semplici come cavo singolo ortogonale con le etichette di porta
            // sul bordo interno del riquadro (Fix porte non aggregate).
            // L'arco vis.js resta sempre invisibile: mantiene solo fisica,
            // selezione e tooltip.
            const clean = s => (s && s !== 'Vicino' && s !== 'Neighbor') ? s : '';
            const memberPairs = [];
            const maxMembers = Math.max(localPorts.length, remotePorts.length);
            if (isPC && maxMembers > 1) {
                for (let i = 0; i < maxMembers; i++) {
                    memberPairs.push({
                        local:  shortIface(localPorts[i]  || localPorts[localPorts.length - 1]   || ''),
                        remote: shortIface(remotePorts[i] || remotePorts[remotePorts.length - 1] || '')
                    });
                }
            } else {
                memberPairs.push({ local: clean(shortIface(l.local_port)),
                                   remote: clean(shortIface(l.remote_port)) });
            }
            const type = (isKeepalive && !isPC) ? 'keepalive'
                       : (isPeerLink ? 'peer' : (isPC ? 'pc' : 'link'));
            // ponytail: formato etichetta "poX/vpc" quando vPC, "poX" altrimenti,
            // con 'po' minuscolo (richiesta utente). lc() abbassa il prefisso Po→po.
            const lc = t => (t || '').replace(/^Po/i, 'po');
            bundles.push({
                from: l.source, to: l.target,
                pcTag, members: memberPairs,
                // 'peer' = peer-link vPC (verde), 'pc' = aggregato dati (rame),
                // 'keepalive' = mgmt0↔mgmt0 (verde tratteggiato), 'link' = semplice.
                type,
                label: type === 'peer' ? `${lc(pcTag)}/vpc`
                     : (type === 'pc' ? lc(pcTag)
                     : (type === 'keepalive' ? 'peer-keepalive' : '')),
                localPcTag, remotePcTag, asymmetricPc: isPC && asymmetricPc,
                // Etichette per-estremo quando i nomi differiscono tra i due lati.
                localLabel:  isPeerLink ? `${lc(localPcTag)}/vpc`  : lc(localPcTag),
                remoteLabel: isPeerLink ? `${lc(remotePcTag)}/vpc` : lc(remotePcTag)
            });

            // Requisiti di spazio per i due nodi: lo spread dei cavi, la
            // larghezza del testo di porta più lungo su ciascun lato e il
            // numero di slot occupati sul perimetro del riquadro.
            // The Port-channel bracket and its name sit beside the port labels,
            // so they count toward the same width.
            const spread = (memberPairs.length - 1) * 11;
            const tags = pcEndTags(bundles[bundles.length - 1]);
            const locP = Math.max(...memberPairs.map(m => measurePort(m.local)), 0);
            const remP = Math.max(...memberPairs.map(m => measurePort(m.remote)), 0);
            bumpReq(l.source, l.target, spread, locP + measureTag(tags.from), memberPairs.length, locP);
            bumpReq(l.target, l.source, spread, remP + measureTag(tags.to), memberPairs.length, remP);

            const tip = document.createElement('div');
            tip.innerHTML = `<div style="font-family:var(--font-main); min-width:180px; color:var(--text); font-size:11px;">
                <strong style="color:var(--primary);">${escapeHtml(l.source)} ⇄ ${escapeHtml(l.target)}</strong>
                ${isPC ? `<div style="margin-top:4px; color:var(--text-muted);">${tr('topoAggregate')}: <span style="color:var(--warning);">${escapeHtml(ends.text)}</span>${l.member_count > 1 ? ` · ${l.member_count} ${tr('topoMembers')}` : ''}</div>
                <div style="font-family:var(--font-code); font-size:10px; margin-top:2px;">${escapeHtml(members||'—')} ⇄ ${escapeHtml(remoteMembers||'—')}</div>`
                : `<div style="font-family:var(--font-code); font-size:10px; margin-top:4px;">${escapeHtml(shortIface(l.local_port)||'—')} ⇄ ${escapeHtml(shortIface(l.remote_port)||'—')}</div>`}
            </div>`;

            // Tutto il disegno visibile avviene nell'overlay: l'arco vis.js è
            // sempre trasparente e serve solo per fisica, selezione e tooltip.
            return {
                from: l.source, to: l.target,
                srcLink: l,   // for the draw.io export
                label: '',
                title: hoverInfo ? tip : undefined,
                color: { color: 'rgba(0,0,0,0)', highlight: 'rgba(0,0,0,0)', hover: 'rgba(0,0,0,0)' },
                width: 0.0001,
                arrows: { to: { enabled: false } },
                smooth: { type: 'continuous', roundness: 0.2 }
            };
        });

        // Dimensionamento dinamico dei riquadri (Fix auto-expanding + Fix
        // leggibilità etichette): larghezza e altezza minime tali che il blocco
        // di testo centrale (nome + vendor/modello + riga management) e TUTTE le
        // etichette di porta disegnate ai bordi dall'overlay convivano con un
        // buffer costante, senza mai sovrapporsi né toccare il bordo.
        //
        // Causa radice risolta QUI (layout condiviso, non toppe per-lato): sui
        // lati N/S l'overlay impila le etichette di porta a partire dal bordo
        // VERSO il centro (una per riga, LINE_H px); con molte porte finivano
        // sopra il nome. Riserviamo al centro una "fascia nome" e cresciamo il
        // riquadro così che la pila peggiore (tutti gli slot su un solo lato)
        // resti separata dalla fascia nome di almeno BUF px. Sui lati E/W le
        // etichette stanno sul bordo, già separate dal nome dalla larghezza.
        const INSET = 13;       // distanza etichetta↔bordo (buffer ampio, ≥ richiesto)
        const LINE_H = 11;      // passo di impilamento/etichetta (= 'spacing' overlay)
        const BUF = 6;          // buffer costante etichetta↔fascia-nome / ↔bordo
        const EDGE_INSET = 14;  // margine ancoraggi dagli angoli (= overlay)
        nodes.forEach(nd => {
            const r = nodeReq[nd.id];
            // Leaf box: its own port name is not printed inside it, so no room is reserved.
            if (nd._compact) { nd.widthConstraint = { minimum: 90 }; return; }
            if (!r) return;
            _measCtx.font = 'bold 12px Arial, Helvetica, sans-serif';
            const nameW = _measCtx.measureText(nd._nameTexts[0] || '').width;
            _measCtx.font = '12px Arial, Helvetica, sans-serif';
            const modelW = _measCtx.measureText(nd._nameTexts[1] || '').width;
            _measCtx.font = 'italic 10px Arial, Helvetica, sans-serif';
            const mgmtW = _measCtx.measureText(nd._nameTexts[2] || '').width;
            const textW = Math.max(nameW, modelW, mgmtW);
            // Fascia verticale occupata dal blocco nome (righe non vuote × ~14px).
            const nameLines = nd._nameTexts.filter(Boolean).length || 1;
            const nameH = nameLines * 14;
            // Sized for the sides the row layout really uses: the labels of the
            // top and bottom stacks stay clear of the centred name, and E/W
            // labels only widen a box that has a neighbour on its own row.
            // Sizing for every slot on one side drew the core as a tall empty
            // column.
            // Top/bottom: vertical labels, then the bracket, then the Po name
            // at one of two depths (9 + label + 4 + 2 x 11).
            const depth = (r.N || r.S) ? r.portW + 35 : INSET;
            const minH = Math.max(2 * (depth + BUF) + nameH, r.E * LINE_H + 2 * EDGE_INSET, 46);
            const minW = Math.max(textW + (r.E ? 2 * (r.labelW + INSET + BUF) : 2 * INSET),
                                  Math.max(r.N, r.S) * LINE_H + 2 * EDGE_INSET, 100);
            nd.widthConstraint  = { minimum: Math.round(minW) };
            nd.heightConstraint = { minimum: Math.round(minH) };
            // Width the box needs if the overlay ends up drawing E/W labels
            // anyway (boxes of side-by-side sites, a dragged box): the overlay
            // grows the box to it, see drawMinimalOverlay.
            nd._ewMinW = Math.round(textW + 2 * (r.labelW + INSET + BUF));
        });

        // Final x/y come from packSchemaRows() once vis.js has sized the boxes.
        nodes.forEach((nd, i) => { nd.schemaLevel = levels[nd.id] || 0; nd.x = i * 400; nd.y = nd.schemaLevel * 400; });
        const options = {
            layout: { improvedLayout: false, randomSeed: 42 },
            physics: { enabled: false },
            interaction: { hover: hoverInfo, hoverConnectedEdges: hoverInfo, selectConnectedEdges: true, tooltipDelay: 150, dragNodes: true, dragView: true, zoomView: true, multiselect: true },
            nodes: { shadow: { enabled: false } },
            edges: { smooth: { type: 'continuous', roundness: 0.2 }, shadow: { enabled: false } }
        };

        return { nodes, edges, options, bundles, groupsInfo };
    }

    // ponytail: pillole Port-Channel spostabili/ridimensionabili direttamente su
    // canvas. Per ogni pillola si memorizza uno scostamento {dx,dy} e una scala
    // in una mappa persistita in localStorage, indicizzata da un id stabile del
    // Port-Channel (from~to~tag). Interazione più semplice possibile: hit-test in
    // coordinate rete (DOMtoCanvas) sui rettangoli disegnati; TRASCINA il corpo =
    // sposta, trascina la MANIGLIA all'angolo = ridimensiona. Niente dipendenze.
    let pillAdjust = {};
    try { pillAdjust = JSON.parse(localStorage.getItem('minimalPillAdjust') || '{}'); } catch (e) { pillAdjust = {}; }
    let pillHitboxes = [];     // ricostruiti a ogni disegno: {key, x,y,w,h, hx,hy,hr}
    let pillDrag = null;       // {key, mode:'move'|'resize'|'label', startM, orig, cx, cy}
    let hoverBundleKey = null; // pillKey of the bundle under the mouse
    const pillKey = b => `${b.from}~${b.to}~${b.pcTag || ''}`;

    // ===== Schema readability: focus, port labels, wrapped rows, grouped uplinks =====
    // Hover beats focus: while the mouse is on a cable only that one stays lit.
    function schemaDimmed(b, key, hoverKey, focusId) {
        if (hoverKey) return key !== hoverKey;
        if (focusId) return !(b.ends || [b.from, b.to]).includes(focusId);
        return false;
    }
    function schemaNeighbors(bundles, focusId) {
        const out = new Set([focusId]);
        bundles.forEach(b => {
            const ends = b.ends || [b.from, b.to];
            if (ends.includes(focusId)) ends.forEach(id => out.add(id));
        });
        return out;
    }
    // Unknown stored value: every label, as before the setting existed.
    function schemaPortLabelVisible(mode, b, focusId) {
        if (mode === 'none') return false;
        if (mode === 'focus') return !!focusId && (b.ends || [b.from, b.to]).includes(focusId);
        return true;
    }
    // Two staggered sub-rows: each lower box sits centred in the gap of the
    // upper row, so its straight drop passes between the upper boxes. A
    // third sub-row would not narrow it: the drop clearance fixes the step.
    // ponytail: clearance is gap/2 each side of the box centre, so a box with
    // more than ~6 cables on its top side can still graze its upper neighbours.
    function zigzagRow(widths, gap) {
        const maxW = Math.max(...widths), step = maxW / 2 + gap / 2;
        return widths.map((w, i) => ({ x: maxW / 2 + i * step, sub: i % 2 }));
    }
    // Core pairs whose shared uplinks can be drawn as one cable each. A pair:
    // same level, boxes overlapping in height, nothing of that level between
    // them, a bundle joining them (or both named in the Core menu: `forced`)
    // and at least two targets cabled to both.
    function schemaUplinkGroups(bundles, ids, levelOf, boxOf, forced) {
        const pk = (a, c) => a < c ? a + '|' + c : c + '|' + a;
        const between = {}, nbrs = {};
        bundles.forEach(b => {
            (between[pk(b.from, b.to)] || (between[pk(b.from, b.to)] = [])).push(b);
            (nbrs[b.from] || (nbrs[b.from] = new Set())).add(b.to);
            (nbrs[b.to] || (nbrs[b.to] = new Set())).add(b.from);
        });
        const forcedSet = new Set((forced || []).map(p => pk(p[0], p[1])));
        const used = new Set(), consumed = new Set(), out = [];
        const tryPair = (p, q) => {
            if (used.has(p) || used.has(q)) return;
            if (!boxOf(p) || !boxOf(q) || levelOf(p) !== levelOf(q)) return;
            if (boxOf(p).left > boxOf(q).left) [p, q] = [q, p];
            const L = boxOf(p), R = boxOf(q);
            if (Math.min(L.bottom, R.bottom) <= Math.max(L.top, R.top)) return;
            const lv = levelOf(p);
            if (ids.some(o => o !== p && o !== q && levelOf(o) === lv
                && (bo => bo && bo.right > L.right && bo.left < R.left)(boxOf(o)))) return;
            if (!between[pk(p, q)] && !forcedSet.has(pk(p, q))) return;
            // A cable already merged into another pair's group is not shared again.
            const shared = [...(nbrs[p] || [])].filter(t => t !== q && nbrs[q] && nbrs[q].has(t)
                && ![...between[pk(p, t)], ...between[pk(q, t)]].some(x => consumed.has(x)));
            if (shared.length < 2) return;
            used.add(p); used.add(q);
            const id = '__pair:' + p + '|' + q;
            shared.forEach(t => {
                const parts = [...between[pk(p, t)], ...between[pk(q, t)]];
                parts.forEach(x => consumed.add(x));
                out.push({ id, pair: [p, q], target: t, parts });
            });
        };
        (forced || []).forEach(pq => { if (ids.includes(pq[0]) && ids.includes(pq[1])) tryPair(pq[0], pq[1]); });
        const byLevel = {};
        ids.forEach(id => { if (boxOf(id)) (byLevel[levelOf(id)] || (byLevel[levelOf(id)] = [])).push(id); });
        Object.values(byLevel).forEach(row => {
            row.sort((a, c) => boxOf(a).left - boxOf(c).left);
            for (let i = 0; i + 1 < row.length; i++) tryPair(row[i], row[i + 1]);
        });
        return out.sort((a, c) => a.target.localeCompare(c.target) || a.id.localeCompare(c.id));
    }
    // Access points in a column: single-homed leaves of the given types, per
    // parent, sorted by id. {"<parent>": ["<leaf>", ...]}
    function schemaLeafColumns(bundles, typeOf, types) {
        const peers = {};
        bundles.forEach(b => {
            (peers[b.from] || (peers[b.from] = new Set())).add(b.to);
            (peers[b.to] || (peers[b.to] = new Set())).add(b.from);
        });
        const out = {};
        Object.keys(peers).sort().forEach(id => {
            if (peers[id].size !== 1 || !types.includes(typeOf(id))) return;
            const parent = [...peers[id]][0];
            if (types.includes(typeOf(parent))) return;
            (out[parent] || (out[parent] = [])).push(id);
        });
        return out;
    }
    // Leaves drawn as small boxes in the Schema view: single-homed devices of
    // the given types (APs, phones, cameras...), never a group box. Sized like
    // a switch, with room reserved for port stacks, an AP box was ~190px tall.
    function schemaCompactLeaves(nodes, links, types) {
        const deg = {};
        links.forEach(l => { deg[l.source] = (deg[l.source] || 0) + 1; deg[l.target] = (deg[l.target] || 0) + 1; });
        return new Set(nodes.filter(n => !n.is_group && types.includes(n.device_type) && deg[n.id] === 1).map(n => n.id));
    }
    // "Column" mode: a switch is as tall as the AP column beside it. The
    // tidy sets it, but every render rebuilds the boxes, so it is set again.
    function growSchemaColumnParents() {
        if (schemaApMode() !== 'column' || !networkInstance || !minimalOverlayData) return;
        const ds = networkInstance.body.data.nodes;
        const bb = id => { try { return networkInstance.getBoundingBox(id); } catch (e) { return null; } };
        const cols = schemaLeafColumns(minimalOverlayData.bundles || [], id => ((ds.get(id) || {}).nodeDataVal || {}).device_type, GROUPABLE_TYPES);
        const grow = [];
        Object.entries(cols).forEach(([p, ls]) => {
            const pb = bb(p), lb = ls.map(bb);
            if (!pb || lb.some(x => !x)) return;
            const h = lb.reduce((t, x) => t + x.bottom - x.top, 0) + 6 * (ls.length - 1);   // 6 = COL_GAP
            if (h > pb.bottom - pb.top + 0.5) grow.push({ id: p, heightConstraint: { minimum: Math.ceil(h) } });
        });
        if (grow.length) ds.update(grow);
    }
    // Schema access-point mode: 'each' (one box per AP, as before), 'group'
    // (the hierarchy's collapsed group) or 'column' (stacked under the switch).
    function schemaApMode() {
        const v = schemaPref('schemaApMode', 'each');
        return v === 'group' || v === 'column' ? v : 'each';
    }
    // Set before a redraw whose new boxes need the full tidy (AP mode, a group
    // opened or closed): placed at the end of their row they land far away.
    let schemaRetidy = false;
    // Preferences: storage can throw (private window, blocked site data).
    function schemaPref(key, fallback) {
        try { const v = localStorage.getItem(key); return v === null ? fallback : v; } catch (e) { return fallback; }
    }
    function setSchemaPref(key, value) {
        try { localStorage.setItem(key, value); } catch (e) { /* still applies to this page */ }
    }
    let schemaFocusId = null;
    // base: the node's own opacity (offline is already dimmed).
    function schemaNodeOpacity(base, kept) { return kept ? base : Math.min(base, 0.35); }
    // Focused node and its neighbours stay as they are, the rest fades; null clears.
    function applySchemaFocus(id) {
        schemaFocusId = id || null;
        if (!networkInstance) return;
        const ds = networkInstance.body.data.nodes;
        const keep = schemaFocusId && minimalOverlayData ? schemaNeighbors(minimalOverlayData.bundles || [], schemaFocusId) : null;
        ds.update(ds.getIds().map(nid => {
            const nd = ds.get(nid);
            if (nd._baseOpacity === undefined) nd._baseOpacity = nd.opacity ?? 1;
            return { id: nid, opacity: schemaNodeOpacity(nd._baseOpacity, !keep || keep.has(nid)) };
        }));
        networkInstance.redraw();
    }
    const routeMemo = {};      // pillKey -> { h, over }: last route shape, for hysteresis
    const pillAdj = key => pillAdjust[key] || { dx: 0, dy: 0, scale: 1 };
    // Scostamento delle ETICHETTE di testo (es. "po1"), indipendente dalla
    // pillola: ogni cartiglio è trascinabile per conto suo e viene persistito.
    let labelAdjust = {};
    try { labelAdjust = JSON.parse(localStorage.getItem('minimalLabelAdjust') || '{}'); } catch (e) { labelAdjust = {}; }
    let labelHitboxes = [];    // ricostruiti a ogni disegno: {key, x,y,w,h}
    const labelAdj = key => labelAdjust[key] || { dx: 0, dy: 0 };
    // ponytail: hit-test per l'assegnazione categoria via click destro sul cavo.
    // Stessa chiave stabile di pillKey; segmenti ricostruiti a ogni disegno.
    let edgeHitSegs = [];      // [{key, segs:[[x1,y1,x2,y2], ...]}]
    function distToSegment(px, py, x1, y1, x2, y2) {
        const dx = x2 - x1, dy = y2 - y1;
        const len2 = dx * dx + dy * dy;
        let t = len2 ? ((px - x1) * dx + (py - y1) * dy) / len2 : 0;
        t = Math.max(0, Math.min(1, t));
        return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
    }
    function hitEdgeAt(m, threshold) {
        threshold = threshold || 6;
        let best = null, bestD = threshold;
        edgeHitSegs.forEach(e => e.segs.forEach(s => {
            const d = distToSegment(m.x, m.y, s[0], s[1], s[2], s[3]);
            if (d < bestD) { bestD = d; best = e.key; }
        }));
        return best;
    }
    let pillInteractionReady = false;
    function initPillInteraction() {
        if (pillInteractionReady) return;
        const container = document.getElementById('networkGraphContainer');
        if (!container) return;
        pillInteractionReady = true;
        // Suggerimento d'uso (tooltip nativo del contenitore).
        container.title = tr('topoPortChannelPillDrag');
        // Punto del mouse in coordinate RETE (le stesse dell'overlay).
        const toNet = ev => {
            const cv = container.querySelector('canvas');
            const rect = (cv || container).getBoundingClientRect();
            return networkInstance.DOMtoCanvas({ x: ev.clientX - rect.left, y: ev.clientY - rect.top });
        };
        const hitAt = m => {
            // Le etichette di testo hanno precedenza assoluta (sono piccole e
            // disegnate sopra tutto), poi la maniglia, poi il corpo della pillola;
            // scorro in ordine inverso (le ultime disegnate stanno "sopra").
            for (let i = labelHitboxes.length - 1; i >= 0; i--) {
                const p = labelHitboxes[i];
                if (m.x >= p.x && m.x <= p.x + p.w && m.y >= p.y && m.y <= p.y + p.h) return { p, mode: 'label' };
            }
            for (let i = pillHitboxes.length - 1; i >= 0; i--) {
                const p = pillHitboxes[i];
                if (Math.hypot(m.x - p.hx, m.y - p.hy) <= p.hr + 2) return { p, mode: 'resize' };
            }
            for (let i = pillHitboxes.length - 1; i >= 0; i--) {
                const p = pillHitboxes[i];
                if (m.x >= p.x && m.x <= p.x + p.w && m.y >= p.y && m.y <= p.y + p.h) return { p, mode: 'move' };
            }
            return null;
        };
        // Capture sul contenitore: intercetta PRIMA di vis.js così il trascinamento
        // della pillola non fa panning/selezione della vista. Vis.js (Hammer)
        // ascolta i POINTER event, non solo mousedown: vanno bloccati entrambi,
        // altrimenti trascinando la pillola si muove anche tutta la mappa.
        const beginPillDrag = ev => {
            if (getMapView() !== 'minimal' || !networkInstance) return;
            const hit = hitAt(toNet(ev));
            if (!hit) return;
            ev.preventDefault(); ev.stopPropagation();
            if (pillDrag) return; // già iniziato dall'altro tipo di evento
            const a = hit.mode === 'label' ? labelAdj(hit.p.key) : pillAdj(hit.p.key);
            pillDrag = { key: hit.p.key, mode: hit.mode, startM: toNet(ev),
                         orig: { dx: a.dx, dy: a.dy, scale: a.scale },
                         cx: hit.p.cx, cy: hit.p.cy };
            container.style.cursor = hit.mode === 'resize' ? 'nwse-resize' : 'move';
        };
        container.addEventListener('pointerdown', beginPillDrag, true);
        container.addEventListener('mousedown', beginPillDrag, true);
        container.addEventListener('touchstart', ev => {
            // Blocca anche il touch: Hammer altrimenti avvia il pan della mappa.
            if (pillDrag) { ev.preventDefault(); ev.stopPropagation(); }
        }, true);
        window.addEventListener('mousemove', ev => {
            if (!pillDrag || !networkInstance) return;
            const m = toNet(ev);
            if (pillDrag.mode === 'label') {
                const la = labelAdjust[pillDrag.key] || (labelAdjust[pillDrag.key] = {});
                la.dx = pillDrag.orig.dx + (m.x - pillDrag.startM.x);
                la.dy = pillDrag.orig.dy + (m.y - pillDrag.startM.y);
                networkInstance.redraw();
                return;
            }
            const a = pillAdjust[pillDrag.key] || (pillAdjust[pillDrag.key] = {});
            if (pillDrag.mode === 'move') {
                a.dx = pillDrag.orig.dx + (m.x - pillDrag.startM.x);
                a.dy = pillDrag.orig.dy + (m.y - pillDrag.startM.y);
                a.scale = pillDrag.orig.scale;
            } else {
                // Scala = rapporto tra distanza attuale dal centro e distanza iniziale.
                const d0 = Math.max(Math.hypot(pillDrag.startM.x - pillDrag.cx, pillDrag.startM.y - pillDrag.cy), 6);
                const d1 = Math.hypot(m.x - pillDrag.cx, m.y - pillDrag.cy);
                a.dx = pillDrag.orig.dx; a.dy = pillDrag.orig.dy;
                a.scale = Math.min(4, Math.max(0.5, pillDrag.orig.scale * (d1 / d0)));
            }
            networkInstance.redraw();
        });
        const endDrag = () => {
            if (!pillDrag) return;
            pillDrag = null;
            localStorage.setItem('minimalPillAdjust', JSON.stringify(pillAdjust));
            localStorage.setItem('minimalLabelAdjust', JSON.stringify(labelAdjust));
            if (pillInteractionReady) document.getElementById('networkGraphContainer').style.cursor = '';
        };
        window.addEventListener('mouseup', endDrag);
        window.addEventListener('pointerup', endDrag);
        // Hovering a cable or pill dims every other bundle, so its members
        // can be followed through a crowded stretch.
        const setHover = key => {
            if (key === hoverBundleKey) return;
            hoverBundleKey = key;
            networkInstance.redraw();
        };
        container.addEventListener('mousemove', ev => {
            if (pillDrag || getMapView() !== 'minimal' || !networkInstance) return;
            const m = toNet(ev);
            const pill = pillHitboxes.find(p => m.x >= p.x && m.x <= p.x + p.w && m.y >= p.y && m.y <= p.y + p.h);
            setHover(pill ? pill.key : hitEdgeAt(m));
        });
        container.addEventListener('mouseleave', () => { if (networkInstance) setHover(null); });
        // Click destro su un cavo: menu per assegnare/rimuovere una categoria
        // personalizzata al collegamento (Task categorie link).
        container.addEventListener('contextmenu', ev => {
            if (getMapView() !== 'minimal' || !networkInstance) return;
            const key = hitEdgeAt(toNet(ev));
            if (!key) return;
            ev.preventDefault();
            showEdgeCatMenu(ev.clientX, ev.clientY, key);
        });
    }

    // ===== Overlay Visio (contenitori Sede + fasci Port-Channel / vPC / peer) =====
    // Contesto già trasformato da vis.js nelle coordinate della rete. Disegna:
    //  1) contenitori tratteggiati per Sede/Gruppo con etichetta;
    //  2) per ogni fascio, un cavo ORTOGONALE (a gradino, no diagonali) per ogni
    //     interfaccia membro, spaziati così da non sovrapporsi nelle pieghe;
    //  3) le etichette di porta sul bordo INTERNO del riquadro, nel punto d'aggancio;
    //  4) una "pillola" traslucida verticale che attraversa i cavi paralleli con il
    //     nome dell'aggregato (es. "Po2 / vPC2"). Rame per i dati, verde per i peer.
    function drawMinimalOverlay(ctx, bundles, groupsInfo) {
        if (!networkInstance) return;
        const S = MINIMAL_MAP_STYLE;
        initPillInteraction();
        pillHitboxes = [];   // ricostruiti sotto per l'hit-test di drag/resize
        labelHitboxes = [];  // ricostruiti sotto per il drag delle etichette
        edgeHitSegs = [];    // ricostruiti sotto per l'hit-test del menu categorie
        const deferredTags = [];

        // --- 1) Contenitori di raggruppamento per Sede/Gruppo ------------------
        if (Array.isArray(groupsInfo) && groupsInfo.length > 1) {
            ctx.save();
            ctx.setLineDash([8, 5]);
            ctx.lineWidth = 1.2;
            groupsInfo.forEach(gi => {
                let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity, found = 0;
                gi.ids.forEach(id => {
                    let bb; try { bb = networkInstance.getBoundingBox(id); } catch (e) { bb = null; }
                    if (!bb) return;
                    found++;
                    minX = Math.min(minX, bb.left);  minY = Math.min(minY, bb.top);
                    maxX = Math.max(maxX, bb.right); maxY = Math.max(maxY, bb.bottom);
                });
                if (!found) return;
                const pad = 28;
                minX -= pad; minY -= pad; maxX += pad; maxY += pad;
                ctx.strokeStyle = S.edge.group.stroke;
                ctx.fillStyle = S.edge.group.fill;
                ctx.beginPath();
                ctx.rect(minX, minY, maxX - minX, maxY - minY);
                ctx.fill();
                ctx.stroke();
                // Etichetta Sede in alto a sinistra del contenitore.
                ctx.setLineDash([]);
                ctx.font = 'bold 11px Arial, Helvetica, sans-serif';
                ctx.textAlign = 'left';
                ctx.textBaseline = 'bottom';
                ctx.fillStyle = S.edge.group.font;
                ctx.fillText(gi.group, minX + 4, minY - 3);
                ctx.setLineDash([8, 5]);
            });
            ctx.restore();
        }

        if (!Array.isArray(bundles) || !bundles.length) return;

        const spacing = 11;         // distanza tra cavi paralleli / slot di porta
        const EDGE_INSET = 14;      // margine degli ancoraggi dagli angoli del riquadro
        const labelMode = schemaPortLabelMode();

        const realBox = id => { try { return networkInstance.getBoundingBox(id); } catch (e) { return null; } };
        // Grouped uplinks: one cable per target from a virtual '__pair:p|q'
        // box, the union of the two cores. A drawing change only: the vis
        // nodes stay as they are and the drawer still lists every port.
        // ponytail: recomputed every frame, O(boxes²); cache per render if big sites stutter.
        const pairBox = {};
        // Not on the export: Visio glues connectors to real boxes and wants every port name.
        if (!visioConnectorSink && schemaPref('schemaGroupUplinks', '0') === '1') {
            const ds0 = networkInstance.body.data.nodes;
            const roots = rootsOf(layeredGroup);
            const forced = Object.values(roots).filter(l => l.length === 2);
            const groups = schemaUplinkGroups(bundles, ds0.getIds().map(String),
                id => (ds0.get(id) || {}).schemaLevel, realBox, forced);
            if (groups.length) {
                const grouped = new Set(groups.flatMap(gr => gr.parts));
                const merged = groups.map(gr => {
                    const a = realBox(gr.pair[0]), c = realBox(gr.pair[1]);
                    pairBox[gr.id] = { left: Math.min(a.left, c.left), right: Math.max(a.right, c.right),
                                       top: Math.min(a.top, c.top), bottom: Math.max(a.bottom, c.bottom) };
                    return { from: gr.id, to: gr.target, ends: [...gr.pair, gr.target],
                             members: [{ local: '', remote: '' }],
                             type: gr.parts.some(p => p.type === 'pc' || p.type === 'peer') ? 'pc' : 'link',
                             pcTag: '', label: '', grouped: '×' + gr.parts.length };
                });
                bundles = bundles.filter(b => !grouped.has(b)).concat(merged);
                // One bar under each pair, from core to core: the grouped
                // cables hang from it instead of from the empty gap.
                ctx.save();
                ctx.strokeStyle = linkColor('link');
                ctx.lineWidth = 4;
                ctx.lineCap = 'butt';
                [...new Set(groups.map(gr => gr.id))].forEach(id => {
                    const [p, q] = groups.find(gr => gr.id === id).pair.map(realBox);
                    const y = pairBox[id].bottom, xa = (p.left + p.right) / 2, xb = (q.left + q.right) / 2;
                    ctx.beginPath();
                    ctx.moveTo(xa, y);
                    ctx.lineTo(xb, y);
                    // A shorter core reaches down to the bar.
                    [[xa, p], [xb, q]].forEach(([x, bx]) => { if (bx.bottom < y) { ctx.moveTo(x, bx.bottom); ctx.lineTo(x, y); } });
                    ctx.stroke();
                });
                ctx.restore();
            }
        }
        // "Column" AP mode: the APs stand beside their switch (see
        // packSchemaRows). One stub leaves the switch's right edge into a
        // vertical spine, a branch runs from it into each AP with the switch
        // port written above it. The normal route would cross the boxes.
        if (schemaApMode() === 'column') {
            const dsc = networkInstance.body.data.nodes;
            const cols = schemaLeafColumns(bundles, id => ((dsc.get(id) || {}).nodeDataVal || {}).device_type, GROUPABLE_TYPES);
            const leafOf = {};
            Object.entries(cols).forEach(([p, ls]) => ls.forEach(l => { leafOf[l] = p; }));
            const spineB = bundles.filter(b => leafOf[b.from] === b.to || leafOf[b.to] === b.from);
            if (spineB.length) {
                bundles = bundles.filter(b => !spineB.includes(b));
                ctx.save();
                ctx.font = '9px Arial, Helvetica, sans-serif';
                ctx.textBaseline = 'bottom';
                ctx.textAlign = 'left';
                Object.entries(cols).forEach(([p, ls]) => {
                    const pb = realBox(p), lb = ls.map(realBox);
                    if (!pb || lb.some(x => !x)) return;
                    const cy = lb.map(x => (x.top + x.bottom) / 2);
                    const sx = pb.right + 10;   // = COL_SIDE in packSchemaRows
                    const ys = Math.min(Math.max(cy[0], pb.top + 6), pb.bottom - 6);
                    const color = linkColor('link');
                    ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = 1.4;
                    ctx.globalAlpha = 1;
                    ctx.beginPath();
                    ctx.moveTo(pb.right, ys); ctx.lineTo(sx, ys);
                    ctx.moveTo(sx, Math.min(ys, ...cy)); ctx.lineTo(sx, Math.max(ys, ...cy));
                    ctx.stroke();
                    ls.forEach((l, k) => {
                        const b = spineB.find(x => x.from === l || x.to === l), y = cy[k];
                        ctx.globalAlpha = !visioConnectorSink && schemaDimmed(b, pillKey(b), hoverBundleKey, schemaFocusId) ? 0.18 : 1;
                        ctx.beginPath(); ctx.moveTo(sx, y); ctx.lineTo(lb[k].left, y); ctx.stroke();
                        ctx.fillRect(lb[k].left + 1, y - 2.5, 5, 5);
                        const m = b.members[0] || {}, port = b.from === p ? m.local : m.remote;
                        if (port && (visioConnectorSink || schemaPortLabelVisible(labelMode, b, schemaFocusId))) ctx.fillText(port, sx + 4, y - 2);
                    });
                });
                ctx.restore();
            }
        }
        const bbox = id => pairBox[id] || realBox(id);
        const dsAll = networkInstance.body.data.nodes;
        const compactIds = new Set(dsAll.getIds().filter(id => (dsAll.get(id) || {})._compact));
        const posOf = id => {
            const pb = pairBox[id];
            return pb ? { x: (pb.left + pb.right) / 2, y: (pb.top + pb.bottom) / 2 } : networkInstance.getPosition(id);
        };
        // Stile UNIFORME per tipo di collegamento (Fix rappresentazione
        // standardizzata): stesso colore/spessore per ogni Port-Channel, verde
        // per peer-link/keepalive, tinta sobria per i link semplici.
        // ponytail: colore preso dalla tabella tipo→colore (fonte unica), così il
        // color-picker/legenda e il disegno restano sempre allineati.
        // ponytail: una categoria personalizzata assegnata manualmente (click
        // destro sul cavo) vince sempre sullo stile standard per-tipo.
        const styleFor = b => {
            const custom = customStyleForEdge(pillKey(b));
            if (custom) return { color: custom.color, lw: 1.8, dash: custom.dash };
            return b.type === 'peer'      ? { color: linkColor('peer'),      lw: 1.8, dash: null }
                 : b.type === 'keepalive' ? { color: linkColor('keepalive'), lw: 1.2, dash: [4, 3] }
                 : b.type === 'pc'        ? { color: linkColor('pc'),        lw: 1.8, dash: null }
                                          : { color: linkColor('link'),      lw: 1.4, dash: null };
        };

        // --- PASSO 1: ancoraggi per lato -----------------------------------
        // Ogni collegamento occupa 'members.length' slot sul lato del riquadro
        // rivolto verso il peer; gli slot di TUTTI i collegamenti (fasci e
        // porte singole) sono distribuiti lungo il lato ordinati per la
        // coordinata del peer, così nessun cavo o etichetta si sovrappone.
        const sideRegistry = {};   // nodeId -> { E|W|N|S: [entry] }
        const pre = bundles.map((b, bi) => {
            let p1, p2;
            try { p1 = posOf(b.from); p2 = posOf(b.to); }
            catch (e) { return null; }
            if (!p1 || !p2) return null;
            const dx = p2.x - p1.x, dy = p2.y - p1.y;
            // Side by side (boxes overlapping in height): E/W; otherwise the
            // cable leaves from the bottom/top, which on the row layout keeps
            // it out of the boxes of the same row.
            const ba = bbox(b.from), bb2 = bbox(b.to);
            // Hysteresis: a route changes shape only once the boxes moved
            // HYST px past the threshold, so nudging a box no longer flips
            // its cables between side, top and over-the-row routes.
            const HYST = 30, memo = routeMemo[pillKey(b)] || {};
            const ov = ba && bb2 ? Math.min(ba.bottom, bb2.bottom) - Math.max(ba.top, bb2.top) : null;
            let horizontal = ov === null ? Math.abs(dx) >= Math.abs(dy)
                : ov > (memo.h === undefined ? 0 : memo.h ? -HYST : HYST);
            // Same row with other boxes in between: a straight run would cross
            // them, so the cable leaves both tops and runs above the row.
            const m = memo.over ? HYST : memo.over === undefined ? 0 : -HYST;
            const over = !!(horizontal && ba && bb2) && networkInstance.body.data.nodes.getIds().some(id => {
                if (id === b.from || id === b.to) return false;
                const o = bbox(id);
                return o && o.right > Math.min(ba.right, bb2.right) - m && o.left < Math.max(ba.left, bb2.left) + m
                    && o.top < Math.max(ba.bottom, bb2.bottom) + m && o.bottom > Math.min(ba.top, bb2.top) - m;
            });
            routeMemo[pillKey(b)] = { h: horizontal, over };
            if (over) horizontal = false;
            const fromSide = over ? 'N' : horizontal ? (dx >= 0 ? 'E' : 'W') : (dy >= 0 ? 'S' : 'N');
            const toSide   = over ? 'N' : horizontal ? (dx >= 0 ? 'W' : 'E') : (dy >= 0 ? 'N' : 'S');
            const reg = (id, side, key) => {
                const sides = sideRegistry[id] || (sideRegistry[id] = {});
                const arr = sides[side] || (sides[side] = []);
                const entry = { count: b.members.length, key, slot: 0, step: 0, total: 1 };
                arr.push(entry);
                return entry;
            };
            return { b, bi, horizontal, over, fromSide, toSide,
                     fromEntry: reg(b.from, fromSide, horizontal ? p2.y : p2.x),
                     toEntry:   reg(b.to,   toSide,   horizontal ? p1.y : p1.x) };
        }).filter(Boolean);

        Object.keys(sideRegistry).forEach(id => {
            const bb = bbox(id); if (!bb) return;
            Object.keys(sideRegistry[id]).forEach(side => {
                const entries = sideRegistry[id][side].sort((a, c) => a.key - c.key);
                const total = entries.reduce((s, e) => s + e.count, 0);
                const sideLen = (side === 'E' || side === 'W') ? (bb.bottom - bb.top) : (bb.right - bb.left);
                const usable = Math.max(sideLen - 2 * EDGE_INSET, 0);
                const step = total > 1 ? Math.min(spacing, usable / (total - 1)) : 0;
                let slot = 0;
                entries.forEach((e, j) => { e.slot = slot; e.step = step; e.total = total; e.idx = j; slot += e.count; });
            });
        });
        // Sizing guessed the sides from the levels; the geometry decides. A box
        // drawing E/W labels it was not sized for would print them over its
        // own name, so it grows now and the next frame draws it clear.
        const ds = networkInstance.body.data.nodes;
        const grow = Object.keys(sideRegistry).map(id => {
            const s = sideRegistry[id], nd = ds.get(id), bb = bbox(id);
            if (!(s.E || s.W) || !nd || !nd._ewMinW || !bb || bb.right - bb.left >= nd._ewMinW - 1) return null;
            return { id: nd.id, widthConstraint: { minimum: nd._ewMinW } };
        }).filter(Boolean);
        if (grow.length && !visioConnectorSink) setTimeout(() => ds.update(grow), 0);

        // Punto di aggancio dello slot i-esimo di una entry sul lato del nodo.
        const anchorPoint = (id, side, entry, i) => {
            const bb = bbox(id);
            const p = posOf(id);
            const off = ((entry.slot + i) - (entry.total - 1) / 2) * entry.step;
            if (side === 'E') return { x: bb ? bb.right : p.x, y: p.y + off };
            if (side === 'W') return { x: bb ? bb.left : p.x,  y: p.y + off };
            if (side === 'S') return { x: p.x + off, y: bb ? bb.bottom : p.y };
            return { x: p.x + off, y: bb ? bb.top : p.y };
        };

        // --- PASSO 2: geometria delle polilinee ortogonali ------------------
        // Calcolata PRIMA di disegnare, così da poter rilevare gli incroci tra
        // percorsi indipendenti e scavalcarli con un ponticello (Fix bridges).
        const geoms = pre.map(g => {
            const b = g.b;
            const n = b.members.length, half = (n - 1) / 2;
            const members = b.members.map((m, i) => {
                const A = anchorPoint(b.from, g.fromSide, g.fromEntry, i);
                const B = anchorPoint(b.to,   g.toSide,   g.toEntry,   i);
                let pts;
                if (g.horizontal) {
                    const mid = (A.x + B.x) / 2 + (i - half) * spacing;
                    pts = [A, { x: mid, y: A.y }, { x: mid, y: B.y }, B];
                } else if (g.over) {
                    const top = Math.min(A.y, B.y) - 24 - i * spacing;
                    pts = [A, { x: A.x, y: top }, { x: B.x, y: top }, B];
                } else {
                    const mid = (A.y + B.y) / 2 + (i - half) * spacing;
                    pts = [A, { x: A.x, y: mid }, { x: B.x, y: mid }, B];
                }
                return { m, A, B, pts };
            });
            return Object.assign({}, g, { members, style: styleFor(b) });
        });

        // Vertical cables leaving the same box side fan out like a ribbon:
        // the wire heading furthest out turns first, so no two of them
        // cross. Without this every run sat on the halfway line and each
        // cable bridged over all the others.
        const fans = {};
        geoms.forEach(g => {
            if (g.horizontal || g.over) return;
            g.members.forEach(mm => {
                const up = mm.A.y <= mm.B.y ? mm.A : mm.B, dn = up === mm.A ? mm.B : mm.A;
                const key = `${up === mm.A ? g.b.from : g.b.to}|${dn.x >= up.x ? 'R' : 'L'}`;
                (fans[key] || (fans[key] = [])).push({ mm, up, dn });
            });
        });
        Object.entries(fans).forEach(([key, ws]) => {
            const right = key.endsWith('R');
            ws.sort((a, c) => right ? c.up.x - a.up.x : a.up.x - c.up.x);
            ws.forEach((w, k) => {
                const y = Math.min(w.up.y + 22 + k * 8, w.dn.y - 20);
                w.mm.pts[1].y = y; w.mm.pts[2].y = y;
            });
        });

        // Middle runs of different bundles all sat on the same halfway line
        // and merged into one unreadable band. Slide each bundle's middle
        // run to the nearest free track, staying between its two ends.
        // ponytail: greedy, first come first served; crossings stay (bridged).
        const placedRuns = [];
        geoms.forEach(g => {
            const ax = g.horizontal ? 'x' : 'y', bx = g.horizontal ? 'y' : 'x';
            const runs = d => g.members.map(mm => {
                const c = mm.pts[1][ax] + d;
                return { c, lo: Math.min(mm.pts[1][bx], mm.pts[2][bx]), hi: Math.max(mm.pts[1][bx], mm.pts[2][bx]),
                         ok: g.over ? c < Math.min(mm.A.y, mm.B.y) - 12
                             : c > Math.min(mm.A[ax], mm.B[ax]) + 6 && c < Math.max(mm.A[ax], mm.B[ax]) - 6 };
            });
            const clash = rs => rs.some(r => !r.ok || placedRuns.some(p => p.h === g.horizontal
                && Math.abs(p.c - r.c) < 7 && p.lo < r.hi && r.lo < p.hi));
            let d = 0;
            for (let k = 1; k < 40 && clash(runs(d)); k++) d = (k % 2 ? 1 : -1) * Math.ceil(k / 2) * 8;
            if (clash(runs(d))) d = 0;
            g.members.forEach(mm => { mm.pts[1][ax] += d; mm.pts[2][ax] += d; });
            runs(0).forEach(r => placedRuns.push(Object.assign(r, { h: g.horizontal })));
        });

        // Raccolta dei segmenti verticali (per membro) da tutti i fasci: sono gli
        // ostacoli che i tratti orizzontali dovranno scavalcare.
        const verticals = [];
        geoms.forEach(g => {
            if (!g) return;
            g.members.forEach(mm => {
                for (let k = 0; k < mm.pts.length - 1; k++) {
                    const p = mm.pts[k], q = mm.pts[k + 1];
                    if (Math.abs(p.x - q.x) < 0.5 && Math.abs(p.y - q.y) > 0.5) {
                        verticals.push({ x: p.x, ymin: Math.min(p.y, q.y), ymax: Math.max(p.y, q.y), bundle: g.bi });
                    }
                }
            });
        });

        const BR = 5;   // raggio del ponticello (semi-arco)
        // Disegna un tratto orizzontale scavalcando con un arco i segmenti verticali
        // di ALTRI fasci che lo attraversano (i membri dello stesso fascio, paralleli,
        // sono esclusi e non generano ponti).
        const drawHSeg = (x1, y, x2, bundleIdx) => {
            const dir = Math.sign(x2 - x1) || 1;
            const lo = Math.min(x1, x2), hi = Math.max(x1, x2);
            let hops = verticals
                .filter(v => v.bundle !== bundleIdx && v.x > lo + BR && v.x < hi - BR && y > v.ymin + 0.5 && y < v.ymax - 0.5)
                .map(v => v.x);
            hops = [...new Set(hops.map(x => Math.round(x)))].sort((a, b) => dir > 0 ? a - b : b - a);
            ctx.beginPath();
            ctx.moveTo(x1, y);
            hops.forEach(hx => {
                ctx.lineTo(hx - dir * BR, y);
                if (dir > 0) ctx.arc(hx, y, BR, Math.PI, 0, false);
                else         ctx.arc(hx, y, BR, 0, Math.PI, true);
            });
            ctx.lineTo(x2, y);
            ctx.stroke();
        };
        const drawVSeg = (x, y1, y2) => {
            ctx.beginPath(); ctx.moveTo(x, y1); ctx.lineTo(x, y2); ctx.stroke();
        };

        // --- PASSO 3: disegno cavi + etichette ------------------------------
        geoms.forEach(g => {
            const b = g.b, horizontal = g.horizontal, color = g.style.color;

            ctx.save();
            // Not on the export context: only the live map follows the mouse.
            if (!visioConnectorSink && schemaDimmed(b, pillKey(b), hoverBundleKey, schemaFocusId)) ctx.globalAlpha = 0.18;
            ctx.strokeStyle = color;
            ctx.lineWidth = g.style.lw;
            ctx.setLineDash(g.style.dash || []);
            ctx.lineJoin = 'round';
            ctx.lineCap = 'butt';
            ctx.font = '9px Arial, Helvetica, sans-serif';
            ctx.textBaseline = 'middle';

            // Etichetta di porta sul bordo INTERNO del riquadro, nel punto d'aggancio.
            // ponytail: sui lati alti/bassi (N/S) gli ancoraggi sono ravvicinati in
            // orizzontale, quindi le etichette centrate si accavallavano in un
            // groviglio illeggibile ("Te1/1d1t21/1"). Le impiliamo verticalmente una
            // per riga (slotIdx), allineate a sinistra, come già avviene sui lati E/W.
            // Top and bottom sides: the label turns vertical and runs inward
            // along its own cable, as on a Visio rack drawing. Stacked one row
            // per port, a core with twenty uplinks became a tall empty column.
            const drawPortLabel = (text, pt, side) => {
                if (!text) return;
                // The export (visioConnectorSink) always gets every port name.
                if (!visioConnectorSink && !schemaPortLabelVisible(labelMode, b, schemaFocusId)) return;
                ctx.fillStyle = color;
                if (side === 'E')      { ctx.textAlign = 'right';  ctx.fillText(text, pt.x - 13, pt.y - 5); }
                else if (side === 'W') { ctx.textAlign = 'left';   ctx.fillText(text, pt.x + 13, pt.y - 5); }
                else {
                    ctx.save();
                    ctx.translate(pt.x, side === 'S' ? pt.y - 9 : pt.y + 9);
                    ctx.rotate(side === 'S' ? -Math.PI / 2 : Math.PI / 2);
                    ctx.textAlign = 'left';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(text, 0, 0);
                    ctx.restore();
                }
            };

            // ponytail: quadratino di terminazione appena DENTRO il bordo, colore del
            // cavo (stile drawio). ~5px a zoom base: non copre il testo di porta.
            const drawTermSquare = (pt, side) => {
                const s = 5, h = s / 2;
                let x = pt.x, y = pt.y;
                if (side === 'E')      x -= h + 1;
                else if (side === 'W') x += h + 1;
                else if (side === 'S') y -= h + 1;
                else                   y += h + 1;
                ctx.fillStyle = color;
                ctx.fillRect(x - h, y - h, s, s);
            };

            g.members.forEach((mm, i) => {
                // Export Visio attivo: il cavo NON viene rasterizzato come
                // segmenti sciolti ma consegnato come connettore STRUTTURATO
                // (polilinea continua + nodi di aggancio), che il backend
                // trasforma in una forma 1-D incollata ai connection point.
                if (visioConnectorSink) {
                    visioConnectorSink.push({
                        from: b.from, to: b.to,
                        points: mm.pts.map(p => [p.x, p.y]),
                        color: visioColor(color).hex,
                        width: g.style.lw,
                        dash: !!g.style.dash
                    });
                } else {
                    // Disegna i segmenti della polilinea: gli orizzontali scavalcano
                    // con un ponticello i segmenti verticali degli ALTRI percorsi.
                    for (let k = 0; k < mm.pts.length - 1; k++) {
                        const p = mm.pts[k], q = mm.pts[k + 1];
                        if (Math.abs(p.y - q.y) < 0.5) drawHSeg(p.x, p.y, q.x, g.bi);
                        else                           drawVSeg(p.x, p.y, q.y);
                    }
                    drawTermSquare(mm.A, g.fromSide);
                    drawTermSquare(mm.B, g.toSide);
                }
                // Indice di slot globale sul lato (entry.slot + i): garantisce che le
                // etichette N/S di fasci diversi si impilino su righe distinte.
                // A small leaf box has no room for its own port name.
                if (!compactIds.has(b.from)) drawPortLabel(mm.m.local,  mm.A, g.fromSide);
                if (!compactIds.has(b.to))   drawPortLabel(mm.m.remote, mm.B, g.toSide);
            });
            // Segmenti del fascio per l'hit-test del menu categorie (click destro).
            edgeHitSegs.push({ key: pillKey(b), segs: g.members.flatMap(mm =>
                mm.pts.slice(0, -1).map((p, k) => [p.x, p.y, mm.pts[k + 1].x, mm.pts[k + 1].y])) });
            ctx.setLineDash([]);

            // Centro del fascio e ampiezza (per pillola/etichette).
            const half = (b.members.length - 1) / 2;
            const spread = half * spacing;
            // On the cable itself: the first (E/W) or the last (N/S) leg, both
            // straight runs of the whole bundle. The midpoint of the two ends
            // floated in empty space once the runs fanned out.
            const leg = horizontal ? 0 : 2;
            const mid = k => g.members.reduce((t, mm) => t + (mm.pts[leg][k] + mm.pts[leg + 1][k]) / 2, 0) / g.members.length;
            const cx = mid('x'), cy = mid('y');

            // Cartiglio bianco riutilizzabile per i nomi aggregato. Se 'key' è
            // fornita, il cartiglio è trascinabile: applica lo scostamento
            // dell'utente e registra la propria hitbox per il drag.
            const drawTag = (text, lx, ly, key) => {
                const la = key ? labelAdj(key) : {};
                lx += la.dx || 0; ly += la.dy || 0;
                ctx.font = 'bold 10px Arial, Helvetica, sans-serif';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                const tw = ctx.measureText(text).width;
                if (key) labelHitboxes.push({ key, x: lx - tw / 2 - 3, y: ly - 7, w: tw + 6, h: 14 });
                // Painted after every cable: drawn inline, the next bundle's
                // cables ran over the tags of the previous ones.
                deferredTags.push(() => {
                    ctx.font = 'bold 10px Arial, Helvetica, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(lx - tw / 2 - 3, ly - 7, tw + 6, 14);
                    ctx.fillStyle = color;
                    ctx.fillText(text, lx, ly);
                });
            };

            // Grouped uplink: how many real cables it stands for, on the cable
            // just before the target.
            if (b.grouped) {
                const B = g.members[0].B;
                drawTag(b.grouped, B.x, B.y + (g.toSide === 'N' ? -16 : 16));
            }
            if (b.type === 'keepalive') {
                drawTag(b.label || 'peer-keepalive', cx, cy - 10, pillKey(b) + '~ka');
                ctx.restore();
                return;
            }
            if (b.type === 'link') { ctx.restore(); return; }

            // --- Pillola ovale standard: SEMPRE presente su ogni Port-Channel
            // e peer-link, qualunque sia il numero di membri visibili.
            // ponytail: posizione e dimensione regolabili dall'utente (drag/resize);
            // lo scostamento {dx,dy} e la scala vengono dalla mappa persistita.
            const adj = pillAdj(pillKey(b));
            const sc  = adj.scale || 1;
            const pcx = cx + (adj.dx || 0), pcy = cy + (adj.dy || 0);
            const pillHalfW = 9 * sc;
            const pillHalfSpread = (spread + 12) * sc;
            let px, py, pw, ph;
            if (horizontal) { px = pcx - pillHalfW; py = pcy - pillHalfSpread; pw = pillHalfW * 2; ph = pillHalfSpread * 2; }
            else            { px = pcx - pillHalfSpread; py = pcy - pillHalfW; pw = pillHalfSpread * 2; ph = pillHalfW * 2; }
            const r = Math.min(pillHalfW, 8);
            ctx.beginPath();
            ctx.moveTo(px + r, py);
            ctx.arcTo(px + pw, py, px + pw, py + ph, r);
            ctx.arcTo(px + pw, py + ph, px, py + ph, r);
            ctx.arcTo(px, py + ph, px, py, r);
            ctx.arcTo(px, py, px + pw, py, r);
            ctx.closePath();
            ctx.fillStyle = hexToRgba(color, 0.16);
            ctx.fill();
            ctx.lineWidth = 1.4;
            ctx.strokeStyle = color;
            ctx.stroke();
            // Hitbox per il drag della pillola (niente maniglia visibile: il
            // ridimensionamento resta possibile trascinando l'angolo esterno).
            pillHitboxes.push({ key: pillKey(b), x: px, y: py, w: pw, h: ph,
                                hx: px + pw, hy: py + ph, hr: 6, cx: pcx, cy: pcy });

            // Port-channel name at each end, inside the device box: a bracket
            // groups the member port labels and carries that side's name
            // (po1 on one end, po2 on the other when they differ). A tag on
            // the cable covered the cables of the bundles it crossed.
            const drawBracket = (text, ends, ports, side, entry) => {
                if (!text) return;
                ctx.font = '9px Arial, Helvetica, sans-serif';
                const ws = ports.map(p => p ? ctx.measureText(p).width : 0);
                let x, y0, y1, tick;
                if (side === 'E' || side === 'W') {
                    // Port labels: aligned 13px in from the anchor, 5px above it.
                    const inward = side === 'E' ? -1 : 1;
                    tick = -inward * 4;
                    x = ends[0].x + inward * (13 + Math.max(...ws) + 4);
                    y0 = Math.min(...ends.map(p => p.y)) - 10;
                    y1 = Math.max(...ends.map(p => p.y));
                } else {
                    // Vertical port labels: a horizontal bracket closes them
                    // and the name sits past it. Neighbouring bundles take
                    // turns at two depths so their names never touch.
                    const inward = side === 'S' ? -1 : 1;
                    const y = ends[0].y + inward * (9 + Math.max(...ws) + 4);
                    const xa = Math.min(...ends.map(p => p.x)) - 3, xb = Math.max(...ends.map(p => p.x)) + 3;
                    ctx.strokeStyle = color;
                    ctx.lineWidth = 1;
                    ctx.beginPath();
                    ctx.moveTo(xa, y - inward * 4); ctx.lineTo(xa, y); ctx.lineTo(xb, y); ctx.lineTo(xb, y - inward * 4);
                    ctx.stroke();
                    ctx.font = 'bold 10px Arial, Helvetica, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillStyle = color;
                    ctx.fillText(text, (xa + xb) / 2, y + inward * (8 + (entry.idx % 2) * 11));
                    return;
                }
                ctx.strokeStyle = color;
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(x + tick, y0); ctx.lineTo(x, y0); ctx.lineTo(x, y1); ctx.lineTo(x + tick, y1);
                ctx.stroke();
                ctx.font = 'bold 10px Arial, Helvetica, sans-serif';
                ctx.textAlign = side === 'E' ? 'right' : 'left';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = color;
                ctx.fillText(text, x - tick, (y0 + y1) / 2);
            };
            const tags = pcEndTags(b);
            drawBracket(tags.from, g.members.map(mm => mm.A), g.members.map(mm => mm.m.local),  g.fromSide, g.fromEntry);
            drawBracket(tags.to,   g.members.map(mm => mm.B), g.members.map(mm => mm.m.remote), g.toSide,   g.toEntry);
            ctx.restore();
        });
        ctx.save();
        deferredTags.forEach(paint => paint());
        ctx.restore();
    }

    // ===== Pannello Dispositivi & Categorie (classificazione manuale) =====
    let categoriesData = { categories: {}, nodes: [], counts_by_category: {}, counts_by_group: {}, vendors: [], models: {} };

    // ===== Dispositivi & Categorie: rail | lista | inspector =====
    // The list is read-only; the inspector edits ONE device and saves it on
    // its own. The old table put an input in every cell and saved a batch of
    // rows at once: dense to read, and a half-edited row was easy to miss.
    function attrEsc(s) { return escapeHtml(String(s == null ? '' : s)).replace(/"/g, '&quot;'); }

    // 'todo' | 'conflict' | 'all' | '<cat>' | '<cat>/<sub>'
    let clsView = 'all';
    let clsSelected = null;
    let clsDirty = false;
    let clsViewChosen = false;
    // AI proposals for queued devices + naming convention per tenant. Read
    // from the server, which keeps them: reopening the tab costs no request.
    let clsAi = { suggestions: {}, conventions: {} };
    let clsMerges = [];
    // Rows picked with Ctrl/Cmd+click, for "add these to the managed ones".
    const clsPicked = new Set();

    // A device discovered via CDP/LLDP whose category was only inferred: no
    // human has looked at it yet. That is the queue the view opens on.
    function clsToClassify(n) { return n.discovered && !n.is_manual; }
    function clsHasConflict(n) { return (n.name_options || []).length > 1; }
    function clsHasTwins(n) { return (n.name_twins || []).length > 0; }
    // The AI said this discovered device is infrastructure worth managing,
    // and it announced an address to reach it at.
    function clsToManage(n) { return n.discovered && !!n.display_ip && !!(clsAi.suggestions[n.id] || {}).manage; }
    function clsCanPromote(n) { return n.discovered && !!n.display_ip; }
    function clsCanWrite() { return isAdminRole(currentRole) || currentRole === 'operator'; }

    function clsScopedNodes() {
        const g = /** @type {HTMLSelectElement|null} */ (document.getElementById('categoriesGroupSelect'))?.value || 'all';
        return categoriesData.nodes.filter(n => g === 'all' || n.group === g);
    }

    function clsInView(n) {
        if (clsView === 'all') return true;
        if (clsView === 'todo') return clsToClassify(n);
        if (clsView === 'manage') return clsToManage(n);
        if (clsView === 'conflict') return clsHasConflict(n);
        if (clsView === 'twins') return clsHasTwins(n);
        const [cat, sub] = clsView.split('/');
        return n.device_type === cat && (sub === undefined || (n.subcategory || '') === sub);
    }

    function clsVisibleNodes() {
        const q = (/** @type {HTMLInputElement|null} */ (document.getElementById('clsSearch'))?.value || '').trim().toLowerCase();
        return clsScopedNodes()
            .filter(clsInView)
            .filter(n => !q || [n.label, n.display_ip, n.vendor, n.model]
                .some(v => String(v || '').toLowerCase().includes(q)))
            .sort((a, b) => (a.group || '').localeCompare(b.group || '')
                || (a.label || '').localeCompare(b.label || ''));
    }

    async function loadCategoriesData() {
        const devList = document.getElementById("categoriesDeviceList");
        if (!categoriesData.nodes.length && devList) {
            devList.innerHTML = `<p class="cls-empty"><i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> ${escapeHtml(tr('topoScanningBackupsAndClassifying'))}</p>`;
        }
        const res = await apiFetch("/api/device-classification");
        if (!res || !res.ok) {
            if (devList && !categoriesData.nodes.length) devList.innerHTML = '';
            return;
        }
        categoriesData = await res.json();
        await loadClsAiSuggestions();
        categoriesData.vendors = categoriesData.vendors || [];
        categoriesData.models = categoriesData.models || {};

        const gsel = /** @type {HTMLSelectElement|null} */ (document.getElementById("categoriesGroupSelect"));
        if (gsel) {
            const cur = gsel.value;
            const groups = Object.keys(categoriesData.counts_by_group).sort();
            gsel.innerHTML = `<option value="all">${tr('topoFilterByTenantAll')}</option>` +
                groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(orgLabel(g))}</option>`).join("");
            gsel.value = tenantSelectSeed(cur, groups, "all");
        }
        const dl = document.getElementById("catKeyList");
        if (dl) dl.innerHTML = Object.keys(categoriesData.categories)
            .map(k => `<option value="${escapeHtml(k)}">`).join("");

        // First open: start on the queue when there is something in it.
        if (!clsViewChosen) clsView = clsScopedNodes().some(clsToClassify) ? 'todo' : 'all';
        // Sent here by a "same name" badge (Inventory, map): open on that device.
        const twin = window.clsPendingTwin;
        window.clsPendingTwin = null;
        if (twin && categoriesData.nodes.some(n => n.id === twin)) {
            clsView = 'twins';
            clsViewChosen = true;
            clsSelected = twin;
        }
        clsDirty = false;
        renderCategoriesPanel();
    }

    function renderCategoriesPanel() {
        const visible = clsVisibleNodes();
        if (!visible.some(n => n.id === clsSelected)) clsSelected = visible.length ? visible[0].id : null;
        const shown = new Set(visible.map(n => n.id));
        [...clsPicked].forEach(id => { if (!shown.has(id)) clsPicked.delete(id); });
        renderClsRail();
        renderClsList(visible);
        renderClsBulk();
        renderClsInspector();
    }

    function renderClsBulk() {
        const bar = document.getElementById('clsBulkBar');
        if (!bar) return;
        bar.hidden = !clsPicked.size;
        if (!clsPicked.size) return;
        const ready = clsPickedPromotable();
        const info = document.getElementById('clsBulkInfo');
        if (info) info.textContent = tr('clsBulkInfo', { n: clsPicked.size });
        const btn = /** @type {HTMLButtonElement|null} */ (document.getElementById('btnClsBulkPromote'));
        if (btn) {
            btn.disabled = !ready.length;
            btn.textContent = tr('clsBulkPromote', { n: ready.length });
        }
    }

    function clsPickedPromotable() {
        return categoriesData.nodes.filter(n => clsPicked.has(n.id) && clsCanPromote(n));
    }

    function clsSwatch(type) {
        return `<span class="cls-sq" style="background:${deviceTypeMeta(type).color}" aria-hidden="true"></span>`;
    }

    function clsCatLabel(k) {
        const c = categoriesData.categories[k];
        return c ? c.label : deviceTypeLabel(k);
    }

    function renderClsRail() {
        const box = document.getElementById('clsRail');
        if (!box) return;
        const nodes = clsScopedNodes();
        const canWrite = clsCanWrite();
        const count = f => nodes.filter(f).length;
        const item = (key, label, n, lead, cls = '', del = '') =>
            `<div class="cls-rail-row ${cls}">
               <button type="button" class="cls-rail-item" data-action="cls-view" data-view="${attrEsc(key)}"
                       aria-current="${clsView === key}">${lead}<span class="cls-rail-label">${escapeHtml(label)}</span><span class="cls-rail-n">${n}</span></button>${del}
             </div>`;
        const delBtn = (action, k, s, aria) => canWrite
            ? `<button type="button" class="cls-rail-del" data-action="${action}" data-k="${attrEsc(k)}"${s !== undefined ? ` data-s="${attrEsc(s)}"` : ''}
                       aria-label="${attrEsc(aria)}" title="${attrEsc(aria)}"><i class="fa-solid fa-xmark" aria-hidden="true"></i></button>` : '';
        let html = `<div class="cls-rail-h">${escapeHtml(tr('clsQueues'))}</div>`
            + item('todo', tr('clsToClassify'), count(clsToClassify),
                   '<span class="cls-iso warn" aria-hidden="true"></span>', 'queue')
            + item('manage', tr('clsToManage'), count(clsToManage),
                   '<i class="fa-solid fa-wand-magic-sparkles cls-rail-ai" aria-hidden="true"></i>', 'queue')
            + item('conflict', tr('clsConflicts'), count(clsHasConflict),
                   '<span class="cls-iso fault" aria-hidden="true"></span>', 'queue')
            + item('twins', tr('clsTwins'), count(clsHasTwins),
                   '<i class="fa-solid fa-clone cls-rail-ai" aria-hidden="true"></i>', 'queue')
            + `<div class="cls-rail-h">${escapeHtml(tr('clsCategories'))}</div>`
            + item('all', tr('clsAll'), nodes.length, '<span class="cls-sq all" aria-hidden="true"></span>');
        for (const [k, c] of Object.entries(categoriesData.categories)) {
            html += item(k, c.label, count(x => x.device_type === k), clsSwatch(k), '',
                         c.builtin ? '' : delBtn('delete-category', k, undefined, tr('clsDeleteCategory', { label: c.label })));
            for (const s of (c.subcategories || [])) {
                html += item(`${k}/${s}`, s, count(x => x.device_type === k && (x.subcategory || '') === s), '', 'sub',
                             delBtn('delete-subcategory', k, s, tr('clsDeleteSub', { sub: s })));
            }
        }
        box.innerHTML = html;
    }

    function renderClsList(visible) {
        const title = document.getElementById('clsListTitle');
        const countEl = document.getElementById('clsListCount');
        const hint = document.getElementById('clsHint');
        const box = document.getElementById('categoriesDeviceList');
        if (!box) return;
        const [cat, sub] = clsView.split('/');
        if (title) title.textContent = clsView === 'all' ? tr('clsAll')
            : clsView === 'todo' ? tr('clsToClassify')
            : clsView === 'manage' ? tr('clsToManage')
            : clsView === 'conflict' ? tr('clsConflicts')
            : clsView === 'twins' ? tr('clsTwins')
            : clsCatLabel(cat) + (sub !== undefined ? ` / ${sub}` : '');
        if (countEl) countEl.textContent = tr('clsCountN', { n: visible.length });
        if (hint) {
            hint.hidden = !visible.length;
            hint.textContent = tr(clsView === 'todo' ? 'clsHintQueue' : clsView === 'manage' ? 'clsHintManage'
                : clsView === 'twins' ? 'clsHintTwins' : 'clsHintPick');
        }
        if (!visible.length) {
            box.innerHTML = `<p class="cls-empty">${escapeHtml(tr(clsView === 'todo' ? 'clsEmptyQueue'
                : clsView === 'manage' ? 'clsEmptyManage' : clsView === 'twins' ? 'clsEmptyTwins' : 'clsEmptyList'))}</p>`;
            return;
        }
        const byGroup = {};
        visible.forEach(n => { (byGroup[n.group] ||= []).push(n); });
        box.innerHTML = Object.keys(byGroup).map(g =>
            `<div class="cls-grp">${escapeHtml(g)} <span>${byGroup[g].length}</span></div>`
            + byGroup[g].map(n => {
                const vm = [n.vendor && n.vendor !== 'discovered' ? n.vendor : '', n.model].filter(Boolean).join(' · ');
                const flags = (n.stack ? `<span class="cls-flag" title="${attrEsc(tr('topoShowStackUnits'))}">×${n.stack.member_count}</span>` : '')
                    + (n.stack && n.stack.health === 'degraded' ? `<span class="cls-iso fault" title="${attrEsc(tr('topoDegradedStack'))}"></span>` : '')
                    + (n.ha_group ? '<span class="cls-flag">HA</span>' : '')
                    + (clsHasConflict(n) ? `<span class="cls-iso fault" title="${attrEsc(tr('topoCdpLldpNameConflict'))}"></span>` : '')
                    + (clsHasTwins(n) ? `<span class="cls-flag" title="${attrEsc(tr('twinBadge'))}"><i class="fa-solid fa-clone" aria-hidden="true"></i></span>` : '')
                    + (clsAi.suggestions[n.id] ? `<span class="cls-flag cls-flag-ai" title="${attrEsc(tr('clsAiFlag'))}">AI</span>` : '')
                    + (clsToManage(n) ? `<span class="cls-flag cls-flag-ai" title="${attrEsc(tr('clsManageFlag'))}"><i class="fa-solid fa-arrow-up-from-bracket" aria-hidden="true"></i></span>` : '');
                return `<button type="button" class="cls-row${clsPicked.has(n.id) ? ' cls-picked' : ''}" data-action="cls-select" data-node-id="${attrEsc(n.id)}"
                        aria-current="${n.id === clsSelected}" aria-pressed="${clsPicked.has(n.id)}">
                    ${clsSwatch(n.device_type)}
                    <span class="cls-id"><span class="cls-name">${escapeHtml(n.label)}</span><span class="cls-vm">${escapeHtml(vm || '—')}</span></span>
                    <span class="cls-ip">${escapeHtml(n.display_ip || '—')}</span>
                    <span class="cls-cat">${escapeHtml(clsCatLabel(n.device_type))}${n.subcategory ? ` <i>/ ${escapeHtml(n.subcategory)}</i>` : ''}</span>
                    <span class="cls-src${n.discovered ? ' disc' : ''}">${escapeHtml(tr(n.discovered ? 'clsDiscovered' : 'clsManaged'))}</span>
                    <span class="cls-flags">${flags}</span>
                </button>`;
            }).join('')).join('');
    }

    function clsField(id, label, control) {
        return `<div class="cls-field"><label for="${id}">${escapeHtml(label)}</label>${control}</div>`;
    }

    function clsSubSelect(subs, cur) {
        return clsField('clsFSub', tr('clsFieldSub'), `<select id="clsFSub" data-field="subcategory">
            <option value="">—</option>${subs.map(s => `<option value="${attrEsc(s)}"${s === cur ? ' selected' : ''}>${escapeHtml(s)}</option>`).join('')}
          </select>`);
    }

    function renderClsInspector() {
        const box = document.getElementById('clsInspector');
        if (!box) return;
        const n = categoriesData.nodes.find(x => x.id === clsSelected);
        clsDirty = false;
        if (!n) { box.innerHTML = `<p class="cls-empty">${escapeHtml(tr('clsPickDevice'))}</p>`; return; }
        const canWrite = clsCanWrite();
        // /api/redundancy/groups is admin-only: so is stack editing.
        const canAdmin = isAdminRole(currentRole);
        const cats = categoriesData.categories;
        const subs = (cats[n.device_type] && cats[n.device_type].subcategories) || [];
        const vendor = n.vendor && n.vendor !== 'discovered' ? n.vendor : '';

        const conflict = clsHasConflict(n) ? `<div class="cls-conflict">
              <p>${escapeHtml(tr('clsConflictMsg', { ip: n.display_ip || n.id }))}</p>
              <div class="cls-conflict-opts">${n.name_options.map(o =>
                  `<button type="button" class="chip-choice" data-action="cls-pick-name" data-name="${attrEsc(o.name)}"
                           data-ver="${attrEsc(o.version || '')}" aria-pressed="${o.name === n.label}"${canWrite ? '' : ' disabled'}>${
                      escapeHtml(o.name)}${o.version ? `<span class="cls-ver">${escapeHtml(o.version)}</span>` : ''}</button>`).join('')}</div>
            </div>` : '';

        let fields;
        if (canWrite) {
            fields = clsField('clsFName', tr('clsFieldName'),
                        `<input id="clsFName" class="ui-input" data-field="name" value="${attrEsc(n.label)}">`)
                + `<div class="cls-two">${clsField('clsFCat', tr('clsFieldCategory'),
                        `<select id="clsFCat" data-field="category">${Object.keys(cats).map(k =>
                            `<option value="${attrEsc(k)}"${k === n.device_type ? ' selected' : ''}>${escapeHtml(cats[k].label)}</option>`).join('')}</select>`)}${
                    subs.length ? clsSubSelect(subs, n.subcategory || '') : ''}</div>`
                + `<div class="cls-two">${clsField('clsFVendor', tr('clsFieldVendor'),
                        `<input id="clsFVendor" class="ui-input" data-field="vendor" list="catVendorDL" value="${attrEsc(vendor)}" placeholder="—">`)}${
                    clsField('clsFModel', tr('clsFieldModel'),
                        `<input id="clsFModel" class="ui-input" data-field="model" list="catModelDL" value="${attrEsc(n.model || '')}" placeholder="—">`)}</div>`
                + clsField('clsFHa', tr('clsFieldHa'),
                        `<input id="clsFHa" class="ui-input" data-field="ha_group" value="${attrEsc(n.ha_group || '')}" placeholder="${attrEsc(tr('clsHaNone'))}">`)
                + `<datalist id="catVendorDL">${categoriesData.vendors.map(v => `<option value="${attrEsc(v)}">`).join('')}</datalist>`
                + `<datalist id="catModelDL">${(categoriesData.models[vendor.toLowerCase()] || []).map(m => `<option value="${attrEsc(m)}">`).join('')}</datalist>`;
        } else {
            fields = `<dl class="cls-facts">
                <dt>${escapeHtml(tr('clsFieldCategory'))}</dt><dd>${escapeHtml(clsCatLabel(n.device_type))}${n.subcategory ? ' / ' + escapeHtml(n.subcategory) : ''}</dd>
                <dt>${escapeHtml(tr('clsFieldVendor'))}</dt><dd>${escapeHtml(vendor || '—')}</dd>
                <dt>${escapeHtml(tr('clsFieldModel'))}</dt><dd>${escapeHtml(n.model || '—')}</dd>
                <dt>${escapeHtml(tr('clsFieldHa'))}</dt><dd>${escapeHtml(n.ha_group || '—')}</dd>
              </dl>`;
        }

        let stack = '';
        if (n.stack) {
            const members = n.stack.members || [];
            const cell = (i, f, v, label) => canAdmin
                ? `<input class="ui-input" data-stack-field="${f}" data-stack-idx="${i}" value="${attrEsc(v || '')}" aria-label="${attrEsc(label + ' ' + (i + 1))}">`
                : escapeHtml(v || '—');
            stack = `<div class="cls-stack">
                <div class="cls-sec-h">${escapeHtml(tr('clsStackUnits', { n: members.length }))}${n.stack.health === 'degraded'
                    ? ` <span class="cls-bad">${escapeHtml(tr('topoDegradedStack'))}</span>` : ''}</div>
                <table class="cls-stack-t" data-no-colpicker><thead><tr>
                  <th data-no-sort="1">#</th><th data-no-sort="1">${escapeHtml(tr('topoRole'))}</th>
                  <th data-no-sort="1">${escapeHtml(tr('topoModel'))}</th><th data-no-sort="1">${escapeHtml(tr('topoSerial'))}</th>
                  <th data-no-sort="1">${escapeHtml(tr('topoState'))}</th></tr></thead><tbody>${members.map((m, i) => `<tr>
                    <td>${escapeHtml(String(m.index != null ? m.index : i + 1))}</td>
                    <td>${cell(i, 'role', m.role, tr('topoRole'))}</td>
                    <td>${cell(i, 'model', m.model, tr('topoModel'))}</td>
                    <td>${cell(i, 'serial', m.serial, tr('topoSerial'))}</td>
                    <td class="${m.state && m.state !== 'ready' ? 'cls-bad' : ''}">${escapeHtml(m.state || '—')}</td></tr>`).join('')}</tbody></table>
                ${canAdmin ? `<div class="cls-actions">
                    <button type="button" class="btn btn-secondary btn-small" data-action="save-stack-members">${escapeHtml(tr('topoSaveStack'))}</button>
                    <button type="button" class="btn btn-danger btn-small cls-isolate" data-action="remove-stack">${escapeHtml(tr('topoRemoveStack'))}</button>
                  </div>` : ''}
              </div>`;
        }

        const canMark = canAdmin && !n.stack && !n.discovered && ['switch', 'router'].includes(n.device_type);
        const vtp = [n.vtp_domain, n.vtp_mode].filter(Boolean).join(' · ');
        const facts = `<dl class="cls-facts">
            <dt>${escapeHtml(tr('clsVersion'))}</dt><dd>${escapeHtml(n.version || '—')}</dd>
            ${n.serial ? `<dt>${escapeHtml(tr('topoSerial'))}</dt><dd>${escapeHtml(n.serial)}</dd>` : ''}
            ${vtp ? `<dt>VTP</dt><dd>${escapeHtml(vtp)}</dd>` : ''}
            <dt>${escapeHtml(tr('clsOrigin'))}</dt><dd>${escapeHtml(tr(n.is_manual ? 'clsOriginManual' : 'clsOriginAuto'))}</dd>
          </dl>`;
        const actions = [
            (n.discovered && canWrite && n.display_ip)
                ? `<button type="button" class="btn btn-secondary btn-small" data-action="promote-device" title="${attrEsc(tr('topoAddToManagedTriage'))}">
                     <i class="fa-solid fa-arrow-up-from-bracket" aria-hidden="true"></i> ${escapeHtml(tr('clsPromote'))}</button>` : '',
            canMark ? `<button type="button" class="btn btn-secondary btn-small" data-action="mark-as-stack" title="${attrEsc(tr('topoDeclareThisDeviceAs'))}">
                     <i class="fa-solid fa-layer-group" aria-hidden="true"></i> ${escapeHtml(tr('clsMarkStack'))}</button>` : '',
        ].filter(Boolean).join('');

        const foot = canWrite ? `<div class="cls-foot">
              <button type="button" class="btn btn-primary btn-small" id="btnSaveCatEdits" data-action="cls-save">${
                  escapeHtml(tr(clsToClassify(n) ? 'clsConfirm' : 'clsSave'))}</button>
              <button type="button" class="btn btn-secondary btn-small" id="btnDiscardCatEdits" data-action="cls-undo">${escapeHtml(tr('clsUndo'))}</button>
              <span class="cls-dirty">${escapeHtml(tr('clsUnsaved'))}</span>
              <span class="cls-kbd" aria-hidden="true">↑ ↓</span>
            </div>` : '';

        box.innerHTML = `<div class="cls-insp-head">
              <div class="cls-insp-title">${clsSwatch(n.device_type)}<span>${escapeHtml(n.label)}</span></div>
              <div class="cls-insp-sub">${escapeHtml([n.display_ip || '—', n.group, tr(n.discovered ? 'clsDiscoveredVia' : 'clsManaged')].join(' · '))}</div>
            </div>
            <div class="cls-insp-body">${clsTwinBox(n)}${canWrite ? clsAiBox(n) : ''}${conflict}${fields}${stack}${facts}${actions ? `<div class="cls-actions">${actions}</div>` : ''}</div>
            ${foot}`;
    }

    // The devices sharing this one's name, side by side with what tells them
    // apart. Renaming is the form below: the normal save path.
    function clsTwinBox(n) {
        if (!clsHasTwins(n)) return '';
        const loc = id => {
            const d = globalDevices.find(x => x.IP === id);
            return d ? locationLabel(d.Location) : '—';
        };
        const ids = [n.id].concat(n.name_twins);
        const nodeOf = id => categoriesData.nodes.find(x => x.id === id) || { id, label: id, group: '', macs: [], seen_on: [] };
        // A list, not a table: the inspector is narrow and a MAC column ran off it.
        const row = id => {
            const t = nodeOf(id), seen = t.seen_on || [];
            // A discovered twin has no location of its own: the switch it hangs off has.
            const where = globalDevices.some(x => x.IP === id) ? loc(id) : (seen.length ? loc(seen[0].switch) : '—');
            return `<li${id === n.id ? ' class="cls-twin-me"' : ''}><b>${escapeHtml(t.label)}</b> · ${escapeHtml(t.group)} · ${escapeHtml(where)}
                <span class="cls-mono">${escapeHtml(t.display_ip || id)}</span>
                ${(t.macs || []).length ? `<span class="cls-mono cls-twin-mac">MAC ${escapeHtml(t.macs.slice(0, 3).join(', '))}</span>` : ''}
                ${seen.map(s => `<span class="cls-twin-mac">${escapeHtml(tr('clsTwinSeen', { sw: s.switch_label, port: s.port }))}
                    <span class="cls-mono">${escapeHtml(s.macs.length ? s.macs.slice(0, 3).join(', ') : tr('clsTwinNoMac'))}</span></span>`).join('')}</li>`;
        };
        const switches = [...new Set(ids.flatMap(id => (nodeOf(id).seen_on || []).map(s => s.switch)))];
        // Reads the whole MAC table of those switches (read-only, the MAC
        // tracker's own scan): the map then tells the twins apart by MAC.
        const scan = switches.length && clsCanWrite()
            ? `<button type="button" class="btn btn-secondary btn-small" data-action="cls-twin-scan" data-ips="${attrEsc(switches.join(','))}">
                 <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i> ${escapeHtml(tr('clsTwinScan', { n: switches.length }))}</button>` : '';
        return `<div class="cls-twins">
              <div class="cls-ai-h"><i class="fa-solid fa-clone" aria-hidden="true"></i> ${escapeHtml(tr('clsTwinsTitle'))}</div>
              <ul class="cls-twin-list">${ids.map(row).join('')}</ul>
              <p class="cls-ai-why">${escapeHtml(tr('clsTwinsHow'))}</p>${scan}
            </div>`;
    }

    async function scanTwinPorts(btn) {
        const ips = (btn.dataset.ips || '').split(',').filter(Boolean);
        if (!ips.length) return;
        /** @type {HTMLButtonElement} */ (btn).disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> ${escapeHtml(tr('clsAiRunning'))}`;
        const res = await apiFetch('/api/mac/scan', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ips })
        });
        const data = res ? await res.json().catch(() => ({})) : {};
        if (!(res && res.ok)) { showToast(data.detail || tr('clsTwinScanFailed'), 'error'); }
        else showToast(tr('clsTwinScanDone'), 'info');
        await loadCategoriesData();
    }

    async function loadClsAiSuggestions() {
        const r = await apiFetch('/api/device-classification/ai-suggestions');
        clsAi = (r && r.ok) ? await r.json() : { suggestions: {}, conventions: {} };
    }

    // The proposal is shown, not applied: "Applica" fills the form and the
    // user saves it like any manual edit.
    function clsAiBox(n) {
        const s = clsAi.suggestions[n.id];
        if (!s) return '';
        const cat = s.category ? clsCatLabel(s.category) + (s.subcategory ? ` / ${s.subcategory}` : '') : '';
        const row = (k, v) => v ? `<dt>${escapeHtml(tr(k))}</dt><dd>${escapeHtml(v)}</dd>` : '';
        const conv = clsAi.conventions[n.group];
        return `<div class="cls-ai">
              <div class="cls-ai-h"><i class="fa-solid fa-wand-magic-sparkles" aria-hidden="true"></i> ${escapeHtml(tr('clsAiBoxTitle'))}
                <span class="cls-ai-conf">${escapeHtml(tr('clsAiConfidence', { n: s.confidence }))}</span></div>
              <dl>${row('clsFieldName', s.name)}${row('clsFieldCategory', cat)}${row('clsFieldVendor', s.vendor)}${row('clsFieldModel', s.model)}${row('clsFieldHa', s.ha_group)}</dl>
              ${s.reason ? `<p class="cls-ai-why">${escapeHtml(s.reason)}</p>` : ''}
              ${conv ? `<p class="cls-ai-why">${escapeHtml(tr('clsAiConv', { text: conv }))}</p>` : ''}
              ${s.manage && clsCanPromote(n) ? `<p class="cls-ai-manage"><i class="fa-solid fa-arrow-up-from-bracket" aria-hidden="true"></i> ${
                  escapeHtml(tr('clsAiManage'))}${s.manage_reason ? ` <span class="cls-ai-why">${escapeHtml(s.manage_reason)}</span>` : ''}</p>` : ''}
              ${(s.category || s.vendor || s.model || s.name || s.ha_group)
                  ? `<button type="button" class="btn btn-secondary btn-small" data-action="cls-ai-apply">${escapeHtml(tr('clsAiApply'))}</button>` : ''}
            </div>`;
    }

    function clsApplyAi() {
        const s = clsAi.suggestions[clsSelected];
        const box = document.getElementById('clsInspector');
        if (!s || !box) return;
        const field = f => /** @type {HTMLInputElement|HTMLSelectElement|null} */ (box.querySelector(`[data-field="${f}"]`));
        const cat = field('category');
        if (s.category && cat) {
            cat.value = s.category;
            // Redraws the subcategory select for the new category.
            cat.dispatchEvent(new Event('change', { bubbles: true }));
        }
        for (const f of ['subcategory', 'name', 'vendor', 'model', 'ha_group']) {
            const el = field(f);
            if (el && s[f]) el.value = s[f];
        }
        clsSetDirty(true);
    }

    async function runClsAiSuggest() {
        if (!clsMayLeave()) return;
        const btn = /** @type {HTMLButtonElement|null} */ (document.getElementById('btnClsAiSuggest'));
        const label = btn ? btn.innerHTML : '';
        if (btn) { btn.disabled = true; btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> ${escapeHtml(tr('clsAiRunning'))}`; }
        try {
            const group = /** @type {HTMLSelectElement|null} */ (document.getElementById('categoriesGroupSelect'))?.value || 'all';
            const res = await apiFetch('/api/device-classification/ai-suggest', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ group, lang: currentLang })
            });
            const data = res ? await res.json().catch(() => ({})) : {};
            if (!(res && res.ok)) { showToast(data.detail || tr('clsAiFailed'), 'error'); return; }
            const manage = Object.values(data.suggestions || {}).filter(s => s.manage).length;
            showToast(tr('clsAiDone', { n: Object.keys(data.suggestions || {}).length,
                                        req: data.requested, rem: data.remaining, m: manage }), 'info');
            await loadClsAiSuggestions();
            clsView = clsScopedNodes().some(clsToClassify) || !clsScopedNodes().some(clsToManage) ? 'todo' : 'manage';
            clsViewChosen = true;
            renderCategoriesPanel();
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = label; }
        }
    }

    function renderClsMerges() {
        const body = document.getElementById('clsModelsBody');
        if (!body) return;
        if (!clsMerges.some(Boolean)) { body.innerHTML = `<p class="cls-ai-note">${escapeHtml(tr('clsAiModelsNone'))}</p>`; return; }
        body.innerHTML = clsMerges.map((m, i) => m ? `<div class="cls-merge">
              <div class="cls-merge-main"><span class="cls-merge-vendor">${escapeHtml(m.vendor)}</span>
                <b>${escapeHtml(m.canonical)}</b> ← ${m.duplicates.map(d => `<s>${escapeHtml(d)}</s>`).join(', ')}</div>
              ${m.reason ? `<p class="cls-ai-why">${escapeHtml(m.reason)}</p>` : ''}
              <div class="cls-merge-act">
                <button type="button" class="btn btn-primary btn-small" data-action="cls-merge-apply" data-i="${i}">${escapeHtml(tr('clsAiMerge'))}</button>
                <button type="button" class="btn btn-secondary btn-small" data-action="cls-merge-skip" data-i="${i}">${escapeHtml(tr('clsAiSkip'))}</button>
              </div>
            </div>` : '').join('');
    }

    async function openClsModels() {
        const body = document.getElementById('clsModelsBody');
        if (!body) return;
        openModal('clsModelsModal');
        body.innerHTML = `<p class="cls-ai-note"><i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> ${escapeHtml(tr('clsAiRunning'))}</p>`;
        const res = await apiFetch('/api/device-models/ai-normalize', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ lang: currentLang })
        });
        const data = res ? await res.json().catch(() => ({})) : {};
        if (!(res && res.ok)) {
            body.innerHTML = `<p class="cls-ai-note cls-bad">${escapeHtml(data.detail || tr('clsAiFailed'))}</p>`;
            return;
        }
        clsMerges = data.merges || [];
        renderClsMerges();
    }

    async function applyClsMerge(i) {
        const m = clsMerges[i];
        if (!m) return;
        const res = await apiFetch('/api/device-models/merge', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vendor: m.vendor, canonical: m.canonical, duplicates: m.duplicates })
        });
        const data = res ? await res.json().catch(() => ({})) : {};
        if (!(res && res.ok)) { showToast(data.detail || tr('clsAiMergeFailed'), 'error'); return; }
        showToast(tr('clsAiMerged', { n: data.devices_updated || 0 }), 'info');
        clsMerges[i] = null;
        renderClsMerges();
        loadCategoriesData();
    }

    document.getElementById('drawerTwinWarn')?.addEventListener('click', (e) => {
        const el = /** @type {HTMLElement} */ (e.target).closest('[data-action="open-name-twins"]');
        if (el instanceof HTMLElement && el.dataset.ip) openNameTwins(el.dataset.ip);
    });
    document.getElementById('btnClsAiSuggest')?.addEventListener('click', runClsAiSuggest);
    document.getElementById('btnClsAiModels')?.addEventListener('click', openClsModels);
    document.getElementById('btnCloseClsModels')?.addEventListener('click', () => closeModal('clsModelsModal'));
    document.getElementById('clsModelsBody')?.addEventListener('click', (e) => {
        const el = /** @type {HTMLElement} */ (e.target).closest('[data-action]');
        if (!(el instanceof HTMLElement)) return;
        const i = Number(el.dataset.i);
        if (el.dataset.action === 'cls-merge-apply') applyClsMerge(i);
        else if (el.dataset.action === 'cls-merge-skip') { clsMerges[i] = null; renderClsMerges(); }
    });

    function clsSetDirty(on) {
        clsDirty = on;
        document.querySelector('#clsInspector .cls-foot')?.classList.toggle('is-dirty', on);
    }

    // Leaving a device with unsaved edits asks first: the list is not a place
    // to lose a half-typed model name silently.
    function clsMayLeave() {
        if (!clsDirty) return true;
        const n = categoriesData.nodes.find(x => x.id === clsSelected);
        return confirm(tr('clsDiscardConfirm', { name: n ? n.label : '' }));
    }

    function clsSelect(id, focusRow) {
        if (id === clsSelected) return;
        if (!clsMayLeave()) return;
        clsSelected = id;
        document.querySelectorAll('#categoriesDeviceList .cls-row').forEach(r =>
            r.setAttribute('aria-current', String(r.getAttribute('data-node-id') === id)));
        const row = /** @type {HTMLElement|null} */ (document.querySelector(
            `#categoriesDeviceList .cls-row[data-node-id="${CSS.escape(id)}"]`));
        row?.scrollIntoView({ block: 'nearest' });
        if (focusRow) row?.focus();
        renderClsInspector();
    }

    function clsMove(step) {
        const ids = clsVisibleNodes().map(n => n.id);
        if (!ids.length) return;
        const i = ids.indexOf(clsSelected);
        clsSelect(ids[Math.max(0, Math.min(ids.length - 1, i + step))], true);
    }

    // Save only what changed, for this one device. Confirming a queued device
    // always sends the category: that is what turns "inferred" into "manual".
    async function saveCategoryEdits() {
        const n = categoriesData.nodes.find(x => x.id === clsSelected);
        if (!n) return;
        const box = document.getElementById('clsInspector');
        const val = f => /** @type {HTMLInputElement|null} */ (box?.querySelector(`[data-field="${f}"]`))?.value.trim();
        const was = { name: n.label, category: n.device_type, subcategory: n.subcategory || '',
                      vendor: n.vendor && n.vendor !== 'discovered' ? n.vendor : '',
                      model: n.model || '', ha_group: n.ha_group || '' };
        const body = { node_id: n.id };
        for (const f of Object.keys(was)) {
            const v = val(f);
            if (v !== undefined && v !== was[f]) body[f] = v;
        }
        // The category changed: the old subcategory belongs to another list.
        if (body.category && val('subcategory') === undefined) body.subcategory = '';
        if (clsToClassify(n)) body.category = val('category') || n.device_type;
        // A new model is filed under its vendor's catalogue.
        if (body.model && !body.vendor && was.vendor) body.vendor = was.vendor;
        if (Object.keys(body).length === 1) { clsSetDirty(false); return; }

        const nextInQueue = clsView === 'todo'
            ? clsVisibleNodes().map(x => x.id).filter(id => id !== n.id)[0] : null;
        const res = await apiFetch("/api/device-categories/assign", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        if (!(res && res.ok)) { alert(tr('clsSaveFailed')); return; }
        clsDirty = false;
        if (nextInQueue) clsSelected = nextInQueue;
        await loadCategoriesData();
        showToast(tr('clsSaved', { name: body.name || n.label }));
    }

    function discardCategoryEdits() {
        renderClsInspector();
    }

    async function clsPickName(btn) {
        const n = categoriesData.nodes.find(x => x.id === clsSelected);
        if (!n) return;
        const res = await apiFetch("/api/device-categories/assign", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ node_id: n.id, name: btn.dataset.name, version: btn.dataset.ver || '' })
        });
        if (res && res.ok) loadCategoriesData();
        else alert(tr('topoFailedToResolveConflict'));
    }

    document.getElementById('clsRail')?.addEventListener('click', (e) => {
        const el = /** @type {HTMLElement} */ (e.target).closest('[data-action]');
        if (!(el instanceof HTMLElement)) return;
        const act = el.dataset.action;
        if (act === 'cls-view') {
            if (!clsMayLeave()) return;
            clsDirty = false;
            clsView = el.dataset.view || 'all';
            clsViewChosen = true;
            clsPicked.clear();
            renderCategoriesPanel();
        } else if (act === 'delete-category' && el.dataset.k) {
            deleteCategory(el.dataset.k);
        } else if (act === 'delete-subcategory' && el.dataset.k && el.dataset.s) {
            deleteSubcategory(el.dataset.k, el.dataset.s);
        }
    });

    document.getElementById('categoriesDeviceList')?.addEventListener('click', (e) => {
        const row = /** @type {HTMLElement} */ (e.target).closest('[data-action="cls-select"]');
        if (!(row instanceof HTMLElement) || !row.dataset.nodeId) return;
        const me = /** @type {MouseEvent} */ (e);
        if (me.ctrlKey || me.metaKey) {
            // The row already open counts as the first pick.
            if (!clsPicked.size && clsSelected) clsPicked.add(clsSelected);
            const id = row.dataset.nodeId;
            if (clsPicked.has(id)) clsPicked.delete(id); else clsPicked.add(id);
            document.querySelectorAll('#categoriesDeviceList .cls-row').forEach(r => {
                const on = clsPicked.has(r.getAttribute('data-node-id') || '');
                r.classList.toggle('cls-picked', on);
                r.setAttribute('aria-pressed', String(on));
            });
            renderClsBulk();
            return;
        }
        if (clsPicked.size) {
            clsPicked.clear();
            document.querySelectorAll('#categoriesDeviceList .cls-picked').forEach(r => {
                r.classList.remove('cls-picked');
                r.setAttribute('aria-pressed', 'false');
            });
            renderClsBulk();
        }
        clsSelect(row.dataset.nodeId, false);
    });
    document.getElementById('btnClsBulkPromote')?.addEventListener('click', promotePicked);
    document.getElementById('btnClsBulkClear')?.addEventListener('click', () => {
        clsPicked.clear();
        renderCategoriesPanel();
    });

    document.getElementById('clsInspector')?.addEventListener('click', (e) => {
        const el = /** @type {HTMLElement} */ (e.target).closest('[data-action]');
        if (!(el instanceof HTMLElement) || !clsSelected) return;
        const act = el.dataset.action;
        if (act === 'cls-save') saveCategoryEdits();
        else if (act === 'cls-undo') discardCategoryEdits();
        else if (act === 'cls-pick-name') clsPickName(el);
        else if (act === 'cls-ai-apply') clsApplyAi();
        else if (act === 'cls-twin-scan') scanTwinPorts(el);
        else if (act === 'promote-device') promoteDevice(clsSelected);
        else if (act === 'mark-as-stack') markAsStack(clsSelected);
        else if (act === 'save-stack-members') saveStackMembers(clsSelected);
        else if (act === 'remove-stack') removeStack(clsSelected);
    });

    document.getElementById('clsInspector')?.addEventListener('input', (e) => {
        if (/** @type {HTMLElement} */ (e.target).closest('[data-field]')) clsSetDirty(true);
    });
    // Another category has other subcategories: redraw that select only, so
    // what was typed in the other fields stays.
    document.getElementById('clsInspector')?.addEventListener('change', (e) => {
        const t = e.target;
        if (!(t instanceof HTMLSelectElement) || t.dataset.field !== 'category') return;
        clsSetDirty(true);
        const subs = (categoriesData.categories[t.value] && categoriesData.categories[t.value].subcategories) || [];
        const html = subs.length ? clsSubSelect(subs, '') : '';
        const holder = document.getElementById('clsFSub')?.closest('.cls-field');
        if (holder) holder.outerHTML = html;
        else if (html) t.closest('.cls-two')?.insertAdjacentHTML('beforeend', html);
    });

    document.getElementById('clsSearch')?.addEventListener('input', () => {
        const visible = clsVisibleNodes();
        if (!visible.some(n => n.id === clsSelected) && !clsDirty) {
            clsSelected = visible.length ? visible[0].id : null;
            renderClsInspector();
        }
        renderClsList(visible);
    });

    // Up/down walk the list while the tab is open and focus is not in a field:
    // working through the queue should not need the mouse.
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
        const tab = document.getElementById('tab-categories');
        if (!tab || !tab.classList.contains('active')) return;
        const a = document.activeElement;
        if (a && (a.matches('input, select, textarea') || a.closest('.modal, details[open]'))) return;
        e.preventDefault();
        clsMove(e.key === 'ArrowDown' ? 1 : -1);
    });

    // ===== Gestione stack (tab Dispositivi) =====
    // I gruppi vivono in redundancy.db via /api/redundancy/groups (admin-only).
    // Salvare a mano marca il gruppo 'manual': il rilevamento CLI non lo tocca più.
    async function saveStackGroup(n, members, groupId) {
        const res = await apiFetch(groupId ? `/api/redundancy/groups/${groupId}` : '/api/redundancy/groups', {
            method: groupId ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                group_name: n.group, group_type: 'stack', name: n.label,
                logical_device_ip: n.id, members
            })
        });
        if (!(res && res.ok)) {
            alert(tr('topoStackSaveFailed'));
            return false;
        }
        await loadCategoriesData();
        return true;
    }

    async function saveStackMembers(nodeId) {
        const n = categoriesData.nodes.find(x => x.id === nodeId);
        const box = document.getElementById('clsInspector');
        if (!n || !n.stack || !box) return;
        const members = (n.stack.members || []).map((m, i) => {
            const get = (f) => /** @type {HTMLInputElement|null} */ (
                box.querySelector(`[data-stack-field="${f}"][data-stack-idx="${i}"]`))?.value.trim();
            return {
                role: get('role') || m.role || 'member',
                model: get('model') || null,
                serial: get('serial') || null,
                state: m.state || 'ready',
                device_ip: n.id, mgmt_ip: n.id,
            };
        });
        await saveStackGroup(n, members, n.stack.group_id);
    }

    async function removeStack(nodeId) {
        const n = categoriesData.nodes.find(x => x.id === nodeId);
        if (!n || !n.stack) return;
        if (!confirm(tr('topoRemoveTheStackGroup', {label: n.label}))) return;
        const res = await apiFetch(`/api/redundancy/groups/${n.stack.group_id}`, { method: 'DELETE' });
        if (!(res && res.ok)) { alert(tr('topoDeleteFailed')); return; }
        await loadCategoriesData();
    }

    async function markAsStack(nodeId) {
        const n = categoriesData.nodes.find(x => x.id === nodeId);
        if (!n) return;
        const count = parseInt(prompt(tr('topoNumberOfUnitsIn'), '2') || '', 10);
        if (!(count >= 2)) return;
        const model = (prompt(tr('topoUnitModel'), n.model || '') || '').trim();
        const members = Array.from({ length: count }, (_, i) => ({
            role: i === 0 ? 'master' : 'member',
            model: model || null, state: 'ready', device_ip: n.id, mgmt_ip: n.id,
        }));
        await saveStackGroup(n, members, null);
    }

    async function promoteDevice(nodeId) {
        const n = categoriesData.nodes.find(x => x.id === nodeId);
        if (!n || !n.display_ip) { alert(tr('topoNoAnnouncedIpAvailable')); return; }
        const msg = tr('topoPromoteToManagedIn', {label: n.label, display_ip: n.display_ip, group: n.group});
        if (!confirm(msg)) return;
        const failed = await promoteNodes([n]);
        if (failed && failed.length) alert(failed[0]);
    }

    async function promotePicked() {
        const nodes = clsPickedPromotable();
        if (!nodes.length || !confirm(tr('clsBulkPromoteConfirm', { n: nodes.length }))) return;
        const failed = await promoteNodes(nodes);
        if (!failed) return;
        clsPicked.clear();
        renderCategoriesPanel();
        showToast(tr('clsBulkPromoted', { n: nodes.length - failed.length }), failed.length ? 'error' : 'info');
        if (failed.length) alert(failed.join('\n'));
    }

    // One location per tenant, asked once even for twenty devices; then one
    // request each, so a device already in inventory fails alone. null when
    // the location was not picked (nothing sent), else the failure messages.
    async function promoteNodes(nodes) {
        const locs = new Map();
        for (const g of new Set(nodes.map(n => n.group))) {
            const loc = await pickLocation(g);
            if (!loc) return null;
            locs.set(g, loc);
        }
        const failed = [];
        for (const n of nodes) {
            const vendor = (n.vendor && n.vendor !== 'discovered') ? n.vendor : 'cisco';
            const res = await apiFetch("/api/promote-device", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    node_id: n.id, ip: n.display_ip, vendor, group: n.group, location: locs.get(n.group),
                    // Eredita ciò che è già stato scoperto via CDP/LLDP, incluso il
                    // nome eventualmente rinominato.
                    model: n.model || '',
                    version: n.version || '',
                    device_type: n.device_type || '',
                    hostname: n.label || ''
                })
            });
            if (!(res && res.ok)) {
                const e = res ? await res.json().catch(()=>({})) : {};
                failed.push(`${n.label}: ${e.detail || tr('topoPromotionFailed')}`);
            }
        }
        await loadCategoriesData();
        // Aggiorna la cache inventario così il nuovo gestito appare nel triage.
        try {
            const dres = await apiFetch('/api/local-devices');
            if (dres && dres.ok) {
                const d = await dres.json();
                globalDevices = d.devices; globalGroups = d.groups; globalVersions = d.detected_versions;
            }
        } catch (e) {}
        return failed;
    }

    async function createCategory() {
        const key = document.getElementById("newCatKey").value.trim();
        const label = document.getElementById("newCatLabel").value.trim();
        const sub = document.getElementById("newSubcat").value.trim();
        if (!key) { alert(tr('topoCategoryKeyRequired')); return; }
        const res = await apiFetch("/api/device-categories", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key, label, subcategory: sub })
        });
        if (res && res.ok) {
            document.getElementById("newCatKey").value = "";
            document.getElementById("newCatLabel").value = "";
            document.getElementById("newSubcat").value = "";
            loadCategoriesData();
        } else {
            alert(tr('topoFailedToCreateCategory'));
        }
    }

    async function deleteCategory(key) {
        if (!confirm(tr('topoDeleteCategoryConfirm', {key: key}))) return;
        const res = await apiFetch("/api/device-categories/delete", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key })
        });
        if (res && res.ok) loadCategoriesData();
        else alert(tr('topoCannotDeleteThisCategory'));
    }

    async function deleteSubcategory(key, sub) {
        if (!confirm(tr('topoRemoveSubcategoryConfirm', {sub: sub}))) return;
        const res = await apiFetch("/api/device-categories/delete-subcategory", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key, subcategory: sub })
        });
        if (res && res.ok) loadCategoriesData();
        else alert(tr('topoCannotRemoveSubcategory'));
    }

    function updateTopologyMapNodeStatus(ip, newStatus) {
        if (!globalVersions[ip]) globalVersions[ip] = {};
        globalVersions[ip].status = newStatus;

        if (networkInstance && networkInstance.body && networkInstance.body.data && networkInstance.body.data.nodes) {
            const nodesDataSet = networkInstance.body.data.nodes;
            const node = nodesDataSet.get(ip);
            if (node) {
                if (node.nodeDataVal) node.nodeDataVal.status = newStatus;
                else node.nodeDataVal = { id: ip, label: node.labelVal || ip, status: newStatus };

                const scan = globalVersions[ip] || { version: tr('topoNotDetected'), status: newStatus };
                const vtp = node.vtpVal || {};
                const stack = nodeStack(node.nodeDataVal);

                if (node.shape === 'image') {
                    Object.assign(node, nodeVisual(node.nodeDataVal, newStatus, node.vendorVal, vtp, stack));
                }
                node.title = createNodeTooltip(node.nodeDataVal, scan, node.vendorVal);
                if (node.opacity !== undefined) {
                    node._baseOpacity = (newStatus === 'offline') ? 0.45 : 1;
                    // Schema focus: a node outside it stays faded.
                    const keep = schemaFocusId && minimalOverlayData ? schemaNeighbors(minimalOverlayData.bundles || [], schemaFocusId) : null;
                    node.opacity = schemaNodeOpacity(node._baseOpacity, !keep || keep.has(node.id));
                }

                nodesDataSet.update(node);
            }
        }
    }
    window.updateTopologyMapNodeStatus = updateTopologyMapNodeStatus;
    window.loadInteractiveMap = loadInteractiveMap;

    // Cattura la mappa corrente su un canvas ad alta risoluzione (fit su tutta
    // la topologia, sfondo opaco) e lo passa a cb; poi ripristina la vista.
    // Usata sia dall'export PNG che da quello PDF.
    function captureMapCanvas(cb) {
        if (!networkInstance) {
            alert(tr('alertNoTopology'));
            return;
        }

        const container = document.getElementById("networkGraphContainer");
        // Salva dimensioni e vista correnti per ripristinarle dopo l'export
        const prevW     = container.style.width;
        const prevH     = container.style.height;
        const prevPos   = networkInstance.getViewPosition();
        const prevScale = networkInstance.getScale();

        // Esporta su un canvas molto più grande della finestra: più pixel = più
        // risoluzione. Con fit() l'inquadratura comprende TUTTI i dispositivi.
        const EXPORT_W = 3200, EXPORT_H = 2000;
        container.style.width  = EXPORT_W + "px";
        container.style.height = EXPORT_H + "px";
        networkInstance.setSize(EXPORT_W + "px", EXPORT_H + "px");
        networkInstance.fit({ animation: false });   // racchiude l'intera topologia
        networkInstance.redraw();

        const restore = () => {
            container.style.width  = prevW;
            container.style.height = prevH;
            networkInstance.setSize(prevW || "100%", prevH || "600px");
            networkInstance.redraw();
            networkInstance.moveTo({ position: prevPos, scale: prevScale, animation: false });
        };

        // Due frame per essere certi che il ridisegno alla nuova dimensione sia completo
        requestAnimationFrame(() => requestAnimationFrame(() => {
            try {
                const src = networkInstance.canvas.frame.canvas;
                // Componi su uno sfondo opaco così il PNG non risulta trasparente
                const out = document.createElement("canvas");
                out.width  = src.width;
                out.height = src.height;
                const ctx = out.getContext("2d");
                // La nuova mappa minimalista ha sfondo bianco, la classica scuro.
                ctx.fillStyle = getMapView() === 'minimal' ? "#ffffff" : cssVar('--surface-2', '#181e23');
                ctx.fillRect(0, 0, out.width, out.height);
                ctx.drawImage(src, 0, 0);
                cb(out);
            } catch (e) {
                console.error("Export mappa fallito:", e);
            } finally {
                restore();
            }
        }));
    }

    function downloadTopology() {
        captureMapCanvas(out => {
            const link = document.createElement("a");
            link.download = "sentinelnet-topology-" + new Date().toISOString().slice(0,10) + ".png";
            link.href = out.toDataURL("image/png");
            link.click();
        });
    }

    // Esporta la mappa come PDF a pagina singola, tutto lato client: il canvas
    // viene compresso in JPEG e incapsulato a mano in un PDF minimale (XObject
    // /DCTDecode). Nessuna libreria, nessuna chiamata al backend.
    function jpegToPdf(jpeg, w, h) {
        const pw = (w * 72 / 96).toFixed(2), ph = (h * 72 / 96).toFixed(2);
        const enc = new TextEncoder();
        const chunks = [], offsets = [];
        let len = 0;
        const push = b => { chunks.push(b); len += b.length; };
        const pushStr = s => push(enc.encode(s));
        const obj = (n, body) => { offsets[n] = len; pushStr(`${n} 0 obj\n${body}\nendobj\n`); };
        pushStr('%PDF-1.4\n');
        obj(1, '<< /Type /Catalog /Pages 2 0 R >>');
        obj(2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>');
        obj(3, `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${pw} ${ph}] /Resources << /XObject << /Im0 4 0 R >> >> /Contents 5 0 R >>`);
        offsets[4] = len;
        pushStr(`4 0 obj\n<< /Type /XObject /Subtype /Image /Width ${w} /Height ${h} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpeg.length} >>\nstream\n`);
        push(jpeg);
        pushStr('\nendstream\nendobj\n');
        const content = `q ${pw} 0 0 ${ph} 0 0 cm /Im0 Do Q`;
        obj(5, `<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
        const xrefPos = len;
        let xref = 'xref\n0 6\n0000000000 65535 f \n';
        for (let i = 1; i <= 5; i++) xref += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
        pushStr(xref + `trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF`);
        const bytes = new Uint8Array(len);
        let o = 0;
        chunks.forEach(c => { bytes.set(c, o); o += c.length; });
        return bytes;
    }

    function exportPdfMap() {
        captureMapCanvas(out => {
            const b64 = out.toDataURL("image/jpeg", 0.92).split(',')[1];
            const bin = atob(b64);
            const jpeg = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) jpeg[i] = bin.charCodeAt(i);
            const pdf = jpegToPdf(jpeg, out.width, out.height);
            const link = document.createElement("a");
            link.download = "sentinelnet-topology-" + new Date().toISOString().slice(0,10) + ".pdf";
            link.href = URL.createObjectURL(new Blob([pdf], { type: "application/pdf" }));
            link.click();
            URL.revokeObjectURL(link.href);
        });
    }

    // Esporta la mappa interattiva corrente come file Visio (.vsdx) nativo ed
    // editabile. Riusa posizioni/dati già presenti nell'istanza vis.js: nessuna
    // nuova chiamata all'API della topologia, solo un POST al backend che
    // costruisce il pacchetto OPC.
    // Dati dell'ultima mappa minimalista renderizzata (bundles + gruppi):
    // servono all'export Visio per riprodurre fedelmente l'overlay canvas.
    let minimalOverlayData = null;
    // Quando valorizzato (solo durante l'export Visio), drawMinimalOverlay vi
    // deposita i cavi come connettori strutturati invece di rasterizzarli.
    let visioConnectorSink = null;

    // Normalizza un colore canvas ('#rrggbb' o 'rgba(r,g,b,a)') in {hex, alpha}.
    function visioColor(c) {
        c = String(c || '#000000');
        let m = /^rgba?\((\d+)\s*,\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*([\d.]+))?\)$/.exec(c);
        if (m) {
            const hex = '#' + [m[1], m[2], m[3]].map(v => (+v).toString(16).padStart(2, '0')).join('');
            return { hex: hex.toUpperCase(), alpha: m[4] !== undefined ? +m[4] : 1 };
        }
        m = /^#([0-9a-f]{6})$/i.exec(c);
        return { hex: m ? ('#' + m[1]).toUpperCase() : '#000000', alpha: 1 };
    }

    // Contesto canvas "registratore": espone la stessa API 2D usata da
    // drawMinimalOverlay ma, invece di disegnare, accumula primitive
    // (polilinee, poligoni, rettangoli, testi) in coordinate rete. L'export
    // Visio riesegue l'overlay su questo contesto e spedisce le primitive al
    // backend: il .vsdx contiene ESATTAMENTE ciò che si vede sulla mappa.
    function makeRecordingCtx(prims) {
        const meas = document.createElement('canvas').getContext('2d');
        const stack = [];
        let subpaths = [], cur = null;
        const ctx = {
            strokeStyle: '#000', fillStyle: '#000', lineWidth: 1,
            font: '10px Arial', textAlign: 'left', textBaseline: 'alphabetic',
            lineJoin: 'round', lineCap: 'butt', _dash: [],
            // Translate/rotate are only used around vertical port labels:
            // tracked for fillText, never applied to paths.
            _t: { x: 0, y: 0, a: 0 },
            save() { stack.push({ s: this.strokeStyle, f: this.fillStyle, w: this.lineWidth, fo: this.font, a: this.textAlign, b: this.textBaseline, d: this._dash, t: Object.assign({}, this._t) }); },
            restore() { const p = stack.pop(); if (p) { this.strokeStyle = p.s; this.fillStyle = p.f; this.lineWidth = p.w; this.font = p.fo; this.textAlign = p.a; this.textBaseline = p.b; this._dash = p.d; this._t = p.t; } },
            translate(x, y) { const t = this._t; t.x += x * Math.cos(t.a) - y * Math.sin(t.a); t.y += x * Math.sin(t.a) + y * Math.cos(t.a); },
            rotate(r) { this._t.a += r; },
            setLineDash(d) { this._dash = d || []; },
            beginPath() { subpaths = []; cur = null; },
            moveTo(x, y) { cur = [[x, y]]; subpaths.push(cur); },
            lineTo(x, y) { if (!cur) this.moveTo(x, y); else cur.push([x, y]); },
            arc(x, y, r, a0, a1, ccw) {
                // Approssimazione poligonale (8 segmenti): sufficiente per i
                // ponticelli di scavalcamento e gli angoli arrotondati.
                const steps = 8;
                let d = a1 - a0;
                if (ccw && d > 0) d -= 2 * Math.PI;
                if (!ccw && d < 0) d += 2 * Math.PI;
                for (let i = 0; i <= steps; i++) {
                    const a = a0 + d * i / steps;
                    this.lineTo(x + r * Math.cos(a), y + r * Math.sin(a));
                }
            },
            arcTo(x1, y1) { this.lineTo(x1, y1); },  // angolo vivo: fedeltà sufficiente
            rect(x, y, w, h) { subpaths.push([[x, y], [x + w, y], [x + w, y + h], [x, y + h], [x, y]]); cur = null; },
            closePath() { if (cur && cur.length > 1) cur.push([...cur[0]]); },
            stroke() {
                const c = visioColor(this.strokeStyle);
                subpaths.forEach(sp => { if (sp.length > 1) prims.lines.push({ points: sp.map(p => [p[0], p[1]]), color: c.hex, alpha: c.alpha, width: this.lineWidth, dash: this._dash && this._dash.length ? true : false }); });
            },
            fill() {
                const c = visioColor(this.fillStyle);
                subpaths.forEach(sp => { if (sp.length > 2) prims.polys.push({ points: sp.map(p => [p[0], p[1]]), fill: c.hex, alpha: c.alpha }); });
            },
            fillRect(x, y, w, h) {
                const c = visioColor(this.fillStyle);
                prims.rects.push({ x, y, w, h, fill: c.hex, alpha: c.alpha });
            },
            measureText(t) { meas.font = this.font; return meas.measureText(t || ''); },
            fillText(text, x, y) {
                if (!text) return;
                meas.font = this.font;
                const w = meas.measureText(text).width;
                const size = parseFloat(/(\d+(?:\.\d+)?)px/.exec(this.font)?.[1] || '10');
                const bold = /bold/.test(this.font);
                // Converte allineamento/baseline in un punto CENTRALE del testo.
                let cx = x, cy = y;
                if (this.textAlign === 'left') cx = x + w / 2;
                else if (this.textAlign === 'right') cx = x - w / 2;
                if (this.textBaseline === 'bottom') cy = y - size / 2;
                else if (this.textBaseline === 'top') cy = y + size / 2;
                const t = this._t, cos = Math.cos(t.a), sin = Math.sin(t.a);
                const c = visioColor(this.fillStyle);
                prims.texts.push({ x: t.x + cx * cos - cy * sin, y: t.y + cx * sin + cy * cos, text, color: c.hex, size, bold, w, angle: t.a });
            }
        };
        return ctx;
    }

    async function exportVisioMap() {
        if (!networkInstance) {
            alert(tr('alertNoTopology'));
            return;
        }
        const positions = networkInstance.getPositions();
        const nodesDs = networkInstance.body.data.nodes;
        const edgesDs = networkInstance.body.data.edges;

        const stripTags = s => String(s || '').replace(/<\/?[bi]>/g, '');
        const nodes = nodesDs.get().map(n => {
            const p = positions[n.id] || { x: 0, y: 0 };
            const raw = n.nodeDataVal || {};
            let bb = null;
            try { bb = networkInstance.getBoundingBox(n.id); } catch (e) { bb = null; }
            const out = {
                id:    n.id,
                label: stripTags(n.labelVal || raw.label || String(n.id)),
                model: raw.model || raw.platform || '',
                ip:    n.id,
                x: p.x, y: p.y
            };
            if (bb) { out.w = bb.right - bb.left; out.h = bb.bottom - bb.top; }
            if (n.color && typeof n.color === 'object') {
                if (typeof n.color.background === 'string') out.fill = visioColor(n.color.background).hex;
                if (typeof n.color.border === 'string') out.border = visioColor(n.color.border).hex;
            }
            // Nella mappa minimalista la label multiriga (nome/modello/mgmt) è
            // già dentro n.label: si esporta così com'è, senza tag HTML.
            if (getMapView() === 'minimal' && typeof n.label === 'string') {
                out.label = stripTags(n.label);
                out.model = ''; out.ip = '';
            }
            return out;
        });

        let edges = [];
        let primitives = null;
        let connectors = null;
        if (getMapView() === 'minimal' && minimalOverlayData) {
            // Riesegue l'overlay sul contesto registratore: etichette di porta,
            // pillole Po/vPC e contenitori Sede finiscono nelle primitive; i
            // cavi vengono invece raccolti come connettori strutturati, che il
            // backend incolla ai connection point dei riquadri dispositivo.
            primitives = { lines: [], polys: [], rects: [], texts: [] };
            connectors = [];
            visioConnectorSink = connectors;
            try {
                drawMinimalOverlay(makeRecordingCtx(primitives), minimalOverlayData.bundles, minimalOverlayData.groupsInfo);
            } finally {
                visioConnectorSink = null;
            }
        } else {
            const pos = networkInstance.getPositions();
            edges = edgesDs.get().map(e => {
                const ex = e.exportVal || {};
                const pe = ex.pcEnds;
                return {
                    source: e.from, target: e.to,
                    // Same orientation as on screen: the left device's Po first.
                    label: ex.isPortChannel && pe
                        ? sideLabel({ prefix: '', a: pe.local, b: pe.remote, same: pe.same }, aIsLeft(pos, e.from, e.to))
                        : '',
                    color: ex.color || cssVar('--text-soft', '#8d9bb0')
                };
            });
        }

        const res = await apiFetch('/api/map/export/vsdx', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nodes, edges, primitives, connectors })
        });
        if (!res || !res.ok) {
            alert(tr('alertVisioExportError'));
            return;
        }
        const blob = await res.blob();
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'sentinelnet-map.vsdx';
        link.click();
        URL.revokeObjectURL(link.href);
    }

    // Current map (Schema or Hierarchy) as a native draw.io file: one card per
    // device inside its site container, real connectors glued to the cards
    // (draw.io re-routes them when a card moves), Port-channel name in the
    // middle and each end's ports at that end. Built in the browser: draw.io
    // reads plain uncompressed XML.
    function exportDrawioMap() {
        if (!networkInstance) { alert(tr('alertNoTopology')); return; }
        const pos = networkInstance.getPositions();
        const ds = networkInstance.body.data.nodes;
        const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        const ACCENT = { switch: '#0EA5E9', router: '#22C55E', firewall: '#EF4444', wlc: '#8B5CF6', ap: '#3B82F6',
                         server: '#EAB308', phone: '#14B8A6', camera: '#F97316', pc: '#64748B' };
        const cells = [];
        const cellId = {}, box = {}, zones = {};
        ds.forEach(nd => {
            if (!pos[nd.id]) return;
            const b = networkInstance.getBoundingBox(nd.id);
            box[nd.id] = b;
            const z = topoZone(nd.nodeDataVal || { id: nd.id });
            const s = zones[z.key] || (zones[z.key] = { label: z.label, ids: [], x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity });
            s.ids.push(nd.id);
            s.x0 = Math.min(s.x0, b.left); s.y0 = Math.min(s.y0, b.top);
            s.x1 = Math.max(s.x1, b.right); s.y1 = Math.max(s.y1, b.bottom);
        });
        let seq = 0;
        // Click actions (draw.io viewer / lightbox): a box hides every cable
        // and shows its own, the site container brings them all back. Each
        // cable carries the tag 'sn-cable' plus the cell ids of its two ends.
        const action = acts => esc('data:action/json,' + JSON.stringify({ actions: acts }));
        Object.values(zones).forEach(s => {
            const zid = 'z' + (seq++), PAD = 30, HEAD = 40;
            s.x0 -= PAD; s.y0 -= PAD + HEAD; s.x1 += PAD; s.y1 += PAD;
            cells.push(`<UserObject id="${zid}" label="${esc(String(s.label || '').toUpperCase())}" link="${action([{ show: { tags: ['sn-cable'] } }])}"><mxCell style="rounded=1;arcSize=2;whiteSpace=wrap;html=1;container=1;collapsible=0;fillColor=#F8FAFC;strokeColor=#CBD5E1;verticalAlign=top;align=left;spacingLeft=16;spacingTop=10;fontStyle=1;fontSize=14;fontColor=#64748B;" vertex="1" parent="1"><mxGeometry x="${s.x0}" y="${s.y0}" width="${s.x1 - s.x0}" height="${s.y1 - s.y0}" as="geometry"/></mxCell></UserObject>`);
            s.ids.forEach(id => {
                const nd = ds.get(id), n = nd.nodeDataVal || {}, b = box[id], cid = 'n' + (seq++);
                cellId[id] = cid;
                const off = n.status === 'offline';
                const accent = off ? '#94A3B8' : (ACCENT[n.device_type] || '#64748B');
                const dot = n.is_group ? '' : `<font color="${off ? '#EF4444' : '#10B981'}">●</font> `;
                const model = n.is_group ? '' : (n.model || n.platform || '');
                const ip = n.is_group ? '' : (n.mgmt_ip || n.display_ip || (n.status === 'discovered' ? n.reported_ip : n.id) || '');
                const html = `${dot}<b>${esc(n.label || id)}</b>`
                    + (model ? `<br><span style="font-size:10px;color:#64748B">${esc(model)}</span>` : '')
                    + (ip ? `<br><span style="font-size:9px;color:#94A3B8">${esc(ip)}</span>` : '');
                const style = `rounded=1;arcSize=10;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=${accent};strokeWidth=1.5;fontSize=12;fontColor=#0F172A;shadow=1;`
                    + (n.is_group ? 'dashed=1;' : '') + (off ? 'opacity=60;' : '');
                cells.push(`<UserObject id="${cid}" label="${esc(html)}" link="${action([{ hide: { tags: ['sn-cable'] } }, { show: { tags: [cid] } }])}"><mxCell style="${style}" vertex="1" parent="${zid}"><mxGeometry x="${b.left - s.x0}" y="${b.top - s.y0}" width="${b.right - b.left}" height="${b.bottom - b.top}" as="geometry"/></mxCell></UserObject>`);
            });
        });
        const tenantOf = id => ((ds.get(id) || {}).nodeDataVal || {}).group || '';
        const plain = p => (p && p !== 'Vicino' && p !== 'Neighbor') ? shortIface(p) : '';
        networkInstance.body.data.edges.get().forEach(e => {
            const l = e.lnk || e.srcLink;
            if (!l || !cellId[e.from] || !cellId[e.to]) return;
            const isPC = !!l.is_portchannel;
            const kind = l.kind === 'group' ? 'group' : l.kind === 'redundancy_heartbeat' ? 'ha' : isPC ? 'pc' : 'link';
            const lp = ((l.local_ports && l.local_ports.length) ? l.local_ports : [l.local_port]).map(plain).filter(Boolean);
            const rp = ((l.remote_ports && l.remote_ports.length) ? l.remote_ports : [l.remote_port]).map(plain).filter(Boolean);
            const a = pos[e.from], b = pos[e.to];
            // Same row: side to side; otherwise bottom of the upper card to the top of the lower.
            const glue = Math.abs(a.y - b.y) < 1
                ? (a.x <= b.x ? 'exitX=1;exitY=0.5;entryX=0;entryY=0.5;' : 'exitX=0;exitY=0.5;entryX=1;entryY=0.5;')
                : (a.y < b.y ? 'exitX=0.5;exitY=1;entryX=0.5;entryY=0;' : 'exitX=0.5;exitY=0;entryX=0.5;entryY=1;');
            const color = kind === 'pc' ? PC_COPPER : kind === 'ha' ? '#F9A825' : '#94A3B8';
            const dashed = kind === 'group' || kind === 'ha' || tenantOf(e.from) !== tenantOf(e.to);
            const style = `edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;endArrow=none;startArrow=none;${glue}`
                + `strokeColor=${color};strokeWidth=${kind === 'pc' ? 2.5 : 1.5};${dashed ? 'dashed=1;' : ''}`
                + `fontSize=10;fontStyle=1;fontColor=${color};labelBackgroundColor=#FFFFFF;`;
            let mid = kind === 'ha' ? 'HA' : '';
            if (kind === 'pc') {
                const ends = pcEnds(l), m = Math.max(1, lp.length, rp.length);
                mid = (ends.same ? ends.local : `${ends.local} ⇄ ${ends.remote}`) + (m > 1 ? ` ×${m}` : '');
            }
            const eid = 'e' + (seq++);
            cells.push(`<UserObject id="${eid}" label="${esc(mid)}" tags="sn-cable ${cellId[e.from]} ${cellId[e.to]}"><mxCell style="${style}" edge="1" parent="1" source="${cellId[e.from]}" target="${cellId[e.to]}"><mxGeometry relative="1" as="geometry"/></mxCell></UserObject>`);
            if (kind !== 'pc' && kind !== 'link') return;
            // End labels ride on the connector: they follow it when edited.
            [[lp, -0.75], [rp, 0.75]].forEach(([ps, x]) => {
                if (!ps.length) return;
                cells.push(`<mxCell id="${'e' + (seq++)}" value="${esc(ps.join(', '))}" style="edgeLabel;html=1;resizable=0;points=[];fontSize=9;fontColor=#475569;labelBackgroundColor=#FFFFFF;" vertex="1" connectable="0" parent="${eid}"><mxGeometry x="${x}" relative="1" as="geometry"><mxPoint as="offset"/></mxGeometry></mxCell>`);
            });
        });
        const xml = `<mxfile host="SentinelNet"><diagram id="sentinelnet" name="${esc(lastMapGroup || 'SentinelNet')}"><mxGraphModel grid="1" gridSize="10" guides="1" page="0" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>${cells.join('')}</root></mxGraphModel></diagram></mxfile>`;
        const link = document.createElement('a');
        link.href = URL.createObjectURL(new Blob([xml], { type: 'application/xml' }));
        link.download = 'sentinelnet-map-' + new Date().toISOString().slice(0, 10) + '.drawio';
        link.click();
        URL.revokeObjectURL(link.href);
    }

    async function resetTopology() {
        if (!confirm(tr('confirmReset'))) return;

        const res = await apiFetch('/api/topology/reset', { method: 'POST' });
        if (!res || !res.ok) {
            alert(tr('alertTopologyResetError'));
            return;
        }

        // 1. Distruggi istanza vis.js e pulisci il container
        if (networkInstance) {
            networkInstance.destroy();
            networkInstance = null;
        }
        const graphContainer = document.getElementById('networkGraphContainer');
        if (graphContainer) graphContainer.innerHTML = '';

        // 2. Ricarica inventario (aggiorna stati LED nella tabella)
        await refreshInventory();

        // 3. Forza reload di ENTRAMBE le viste indipendentemente dalla tab attiva
        await loadTopology();
        await loadInteractiveMap();

        const data = await res.json();
        console.info(`[Reset] Eliminati ${data.deleted} file cache.`);
    }

    // Static event listeners for Topology and Categories tabs
    document.getElementById('topologyGroupSelect')?.addEventListener('change', loadTopology);
    document.getElementById('btnResetPortchannels')?.addEventListener('click', resetTopology);
    document.getElementById('interactiveGroupSelect')?.addEventListener('change', loadInteractiveMap);
    document.getElementById('toggleDiscovered')?.addEventListener('change', loadInteractiveMap);
    document.getElementById('toggleVtpDomain')?.addEventListener('change', loadInteractiveMap);
    document.getElementById('mapViewMinimalBtn')?.addEventListener('click', () => setMapView('minimal'));
    document.getElementById('mapViewLayeredBtn')?.addEventListener('click', () => setMapView('layered'));
    // Schema: positions survive refreshes and drags, so after a few changes
    // the boxes drift; this lays them out again in rows, on demand.
    document.getElementById('schemaTidyBtn')?.addEventListener('click', () => {
        if (getMapView() === 'minimal') packSchemaRows();
    });
    document.getElementById('layeredResetBtn')?.addEventListener('click', () => {
        const g = document.getElementById('interactiveGroupSelect');
        resetLayeredLevels(g ? g.value : 'all');
    });
    document.getElementById('mapCoreList')?.addEventListener('change', ev => {
        const sel = /** @type {HTMLSelectElement} */ (ev.target);
        if (!sel.matches('select.map-core')) return;
        const g = document.getElementById('interactiveGroupSelect');
        const group = g ? g.value : 'all', zone = sel.dataset.zone || '';
        const cores = (rootsOf(group)[zone] || []).slice();
        if (sel.dataset.slot === '1') cores[1] = sel.value;
        else if (sel.value) cores[0] = sel.value;
        else cores.length = 0;   // first core back to automatic: the second goes too
        setLayeredRoots(group, zone, cores);
    });
    // Level names: one field per row of the map, labelled with a few of its
    // devices so it is clear which row is which. Empty fields stay empty.
    document.getElementById('layeredNamesBtn')?.addEventListener('click', () => {
        if (!networkInstance) return;
        const rows = {};
        networkInstance.body.data.nodes.forEach(nd => {
            const lv = layeredAssigned[nd.id] || 0;
            (rows[lv] || (rows[lv] = [])).push(nd.labelVal || nd.id);
        });
        const names = layeredLevelNames[layeredGroup] || [];
        document.getElementById('layeredNamesList').innerHTML = Object.keys(rows).map(Number).sort((a, b) => a - b).map(lv => {
            const who = rows[lv].slice(0, 3).join(', ') + (rows[lv].length > 3 ? ` +${rows[lv].length - 3}` : '');
            return `<div class="form-group">
                <label for="layeredName${lv}">${escapeHtml(tr('topoLevelN', { n: lv + 1 }))} · <span style="font-weight:400;">${escapeHtml(who)}</span></label>
                <input id="layeredName${lv}" data-level="${lv}" type="text" maxlength="40" value="${attrEsc(names[lv] || '')}" placeholder="${attrEsc(tr('phLayeredName'))}" style="padding-left:12px;">
            </div>`;
        }).join('');
        openModal('layeredNamesModal');
    });
    document.getElementById('btnSaveLayeredNames')?.addEventListener('click', () => {
        const names = [];
        document.querySelectorAll('#layeredNamesList input[data-level]').forEach(inp => {
            names[+inp.dataset.level] = inp.value.trim();
        });
        layeredLevelNames[layeredGroup] = names;
        localStorage.setItem('layeredLevelNames', JSON.stringify(layeredLevelNames));
        closeModal('layeredNamesModal');
        if (networkInstance) networkInstance.redraw();
    });
    [['layeredTagSize', 'size'], ['layeredTagForm', 'form'], ['layeredTagPlace', 'place']].forEach(([id, field]) => {
        const sel = document.getElementById(id);
        if (!sel) return;
        sel.value = layeredTagCfg[field];
        sel.addEventListener('change', () => {
            layeredTagCfg[field] = sel.value;
            // A new global size or form starts every link from it again.
            if (field !== 'place') layeredTagFlip = {};
            else layeredTagAdjust = {};
            saveLayeredTags();
            if (networkInstance) networkInstance.redraw();
        });
    });
    const pcLaneBox = document.getElementById('toggleLayeredPcLane');
    if (pcLaneBox) {
        pcLaneBox.checked = !!layeredTagCfg.lane;
        pcLaneBox.addEventListener('change', () => {
            layeredTagCfg.lane = pcLaneBox.checked;
            saveLayeredTags();
            if (networkInstance) networkInstance.redraw();
        });
    }
    document.getElementById('layeredTagResetBtn')?.addEventListener('click', () => {
        layeredTagFlip = {};
        layeredTagAdjust = {};
        saveLayeredTags();
        if (networkInstance) networkInstance.redraw();
    });
    document.getElementById('toggleLayeredFree')?.addEventListener('change', e => {
        layeredFree = e.target.checked;
        localStorage.setItem('layeredFree', layeredFree ? '1' : '0');
        updateMapViewButtons();
        redrawInteractiveMap();
    });
    document.getElementById('layeredTidyBtn')?.addEventListener('click', () => {
        delete layeredFreePos[layeredGroup];
        saveLayeredFreePos();
        redrawInteractiveMap();
    });
    document.getElementById('layeredCollapseBtn')?.addEventListener('click', () => {
        const g = document.getElementById('interactiveGroupSelect');
        collapseAllLayeredGroups(g ? g.value : 'all');
    });
    document.getElementById('toggleMinimalHover')?.addEventListener('change', (e) => {
        localStorage.setItem('minimalHoverInfo', e.target.checked ? '1' : '0');
        loadInteractiveMap();
    });
    // Schema readability controls: drawing changes only, no data reload.
    document.getElementById('schemaReadWrap')?.addEventListener('change', ev => {
        const el = /** @type {HTMLInputElement} */ (ev.target);
        if (el.id === 'toggleSchemaFocus') {
            setSchemaPref('schemaFocus', el.checked ? '1' : '0');
            if (!el.checked) applySchemaFocus(null);
        } else if (el.id === 'schemaPortLabels') {
            setSchemaPref('schemaPortLabels', el.value);
            networkInstance?.redraw();
        } else if (el.id === 'toggleSchemaWrap') {
            setSchemaPref('schemaWrap', el.checked ? '1' : '0');
            packSchemaRows();
        } else if (el.id === 'toggleSchemaGroupUplinks') {
            setSchemaPref('schemaGroupUplinks', el.checked ? '1' : '0');
            networkInstance?.redraw();
        } else if (el.id === 'schemaApMode') {
            // Boxes change (group) or move (column): rebuild and re-tidy.
            setSchemaPref('schemaApMode', el.value);
            // Groups left open (state shared with the hierarchy) would hide the change.
            if (el.value === 'group') { delete layeredExpanded[layeredGroup]; saveLayeredExpanded(); }
            schemaRetidy = true;
            redrawInteractiveMap();
        }
    });
    document.getElementById('schemaPresetRecommended')?.addEventListener('click', () => applySchemaPreset('recommended'));
    document.getElementById('schemaPresetOverview')?.addEventListener('click', () => applySchemaPreset('overview'));
    document.getElementById('btnResetInteractiveTopology')?.addEventListener('click', resetTopology);
    document.getElementById('btnRefreshInteractiveMap')?.addEventListener('click', loadInteractiveMap);
    document.getElementById('btnDownloadTopology')?.addEventListener('click', downloadTopology);
    document.getElementById('btnExportVisioMap')?.addEventListener('click', exportVisioMap);
    document.getElementById('btnExportDrawioMap')?.addEventListener('click', exportDrawioMap);
    // Floating zoom bar: steps of 20% around the view centre, and fit.
    const zoomBy = f => networkInstance && networkInstance.moveTo({ scale: networkInstance.getScale() * f, animation: { duration: 150 } });
    document.getElementById('mapZoomIn')?.addEventListener('click', () => zoomBy(1.2));
    document.getElementById('mapZoomOut')?.addEventListener('click', () => zoomBy(1 / 1.2));
    document.getElementById('mapZoomFit')?.addEventListener('click', () => networkInstance && networkInstance.fit({ animation: { duration: 200 } }));
    document.getElementById('btnExportPdfMap')?.addEventListener('click', exportPdfMap);
    document.getElementById('legendToggleBtn')?.addEventListener('click', toggleLegend);
    document.getElementById('categoriesGroupSelect')?.addEventListener('change', renderCategoriesPanel);
    document.getElementById('btnRefreshCategories')?.addEventListener('click', loadCategoriesData);
    document.getElementById('btnCreateCategory')?.addEventListener('click', createCategory);

    // The column registry lives in the backend, like the inventory export: a
    // second copy here is what lets the two drift apart.
    const CLS_EXPORT_PREFS_KEY = 'sentinelnet.classificationExportPrefs';
    let clsExportColumns = [];
    let clsExportPreviewTimer = null;

    function readClsPrefs() {
        try { return JSON.parse(localStorage.getItem(CLS_EXPORT_PREFS_KEY)) || {}; }
        catch (e) { return {}; }
    }

    function clsChecked(containerId) {
        return Array.from(document.querySelectorAll(`#${containerId} input:checked`))
            .map(el => el.value);
    }

    async function updateClsExportPreview() {
        if (clsExportPreviewTimer) clearTimeout(clsExportPreviewTimer);
        clsExportPreviewTimer = setTimeout(async () => {
            const cols = clsChecked('clsColumnList');
            const container = document.getElementById('clsExportPreviewContainer');
            const badge = document.getElementById('clsExportPreviewBadge');
            const status = document.getElementById('clsExportPreviewStatus');
            const L = (typeof i18n !== 'undefined' && i18n[currentLang]) || {};

            if (!cols.length) {
                if (badge) badge.textContent = `0 ${L.lblExportRowsCount || 'righe'}`;
                if (status) status.textContent = '';
                if (container) {
                    container.innerHTML = `<div style="color:var(--warning); padding:10px; font-size:12px;">${escapeHtml(L.alertExportNoColumns || 'Seleziona almeno una colonna')}</div>`;
                }
                return;
            }
            if (status) status.textContent = L.lblExportLoading || 'Caricamento...';
            const qs = new URLSearchParams({
                groups: clsChecked('clsFilterGroups').join(','),
                categories: clsChecked('clsFilterCategories').join(','),
                neighbour_source_categories: clsChecked('clsFilterNeighbourSourceCategories').join(','),
                neighbour_categories: clsChecked('clsFilterNeighbourCategories').join(','),
                columns: cols.join(','),
                limit: '15',
            });
            if (document.getElementById('clsOnlyMatchingNeighbours')?.checked) {
                qs.set('only_matching_neighbours', 'true');
            }

            const res = await apiFetch('/api/export/classification/preview?' + qs.toString());
            if (!res || !res.ok) {
                if (status) status.textContent = '';
                return;
            }
            const data = await res.json();
            if (badge) {
                badge.textContent = `${data.total_rows || 0} ${L.lblExportRowsCount || 'righe'}`;
            }
            if (status) {
                status.textContent = (data.total_rows > (data.rows || []).length)
                    ? `(${(L.lblExportShowingFirst || 'Prime {n} righe').replace('{n}', (data.rows || []).length)})`
                    : '';
            }
            if (!container) return;
            if (!data.rows || !data.rows.length) {
                container.innerHTML = `<div style="color:var(--text-muted); padding:10px; font-size:12px;">${escapeHtml(L.lblExportNoData || 'Nessun record corrisponde ai filtri')}</div>`;
                return;
            }
            container.innerHTML = `
                <table style="width:100%; border-collapse:collapse; white-space:nowrap; font-size:11px;">
                  <thead>
                    <tr style="position:sticky; top:0; background:var(--surface-3); border-bottom:1px solid var(--border); z-index:1;">
                      ${data.headers.map(h => `<th style="padding:4px 8px; text-align:left; font-weight:600; color:var(--text-bright); border-right:1px solid var(--border-subtle, rgba(255,255,255,0.05));">${escapeHtml(h)}</th>`).join('')}
                    </tr>
                  </thead>
                  <tbody>
                    ${data.rows.map((row, idx) => `
                      <tr style="border-bottom:1px solid var(--border-subtle, rgba(255,255,255,0.05)); background:${idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)'};">
                        ${row.map(cell => `<td style="padding:3px 8px; color:var(--text); border-right:1px solid var(--border-subtle, rgba(255,255,255,0.05));">${escapeHtml(cell === null || cell === undefined ? '' : String(cell))}</td>`).join('')}
                      </tr>
                    `).join('')}
                  </tbody>
                </table>`;
        }, 150);
    }

    function applyClsColumnPreset(presetKeys) {
        const want = new Set(presetKeys);
        const boxes = Array.from(document.querySelectorAll('#clsColumnList input'));
        boxes.forEach(b => { b.checked = want.has(b.value); });
        updateClsExportPreview();
    }

    async function openClassificationExportModal() {
        if (!clsExportColumns.length) {
            const res = await apiFetch('/api/export/classification/columns');
            if (!res || !res.ok) { alert(tr('alertExportError')); return; }
            const data = await res.json();
            clsExportColumns = data.columns;
            const seed = readClsPrefs();
            if (!seed.columns) {
                seed.columns = data.default;
                localStorage.setItem(CLS_EXPORT_PREFS_KEY, JSON.stringify(seed));
            }
        }
        const prefs = readClsPrefs();
        const nodes = (categoriesData && categoriesData.nodes) || [];
        const uniq = key => Array.from(new Set(nodes.map(n => n[key]).filter(Boolean)))
            .sort().map(v => ({ value: v, label: v }));
        renderCheckList('clsFilterGroups', uniq('group'), prefs.groups);
        renderCheckList('clsFilterCategories', uniq('device_type'), prefs.categories);
        renderCheckList('clsFilterNeighbourSourceCategories', uniq('device_type'),
                        prefs.neighbour_source_categories);
        renderCheckList('clsFilterNeighbourCategories', uniq('device_type'),
                        prefs.neighbour_categories);
        const matchChk = document.getElementById('clsOnlyMatchingNeighbours');
        if (matchChk) {
            matchChk.checked = !!prefs.only_matching_neighbours;
        }
        renderCheckList('clsColumnList',
            clsExportColumns.map(c => ({
                value: c.key, label: c.header + (c.explodes ? ' *' : '') })),
            prefs.columns);
        openModal('classificationExportModal');
        updateClsExportPreview();
    }

    async function runClassificationExport() {
        const prefs = {
            groups: clsChecked('clsFilterGroups'),
            categories: clsChecked('clsFilterCategories'),
            neighbour_source_categories: clsChecked('clsFilterNeighbourSourceCategories'),
            neighbour_categories: clsChecked('clsFilterNeighbourCategories'),
            columns: clsChecked('clsColumnList'),
            only_matching_neighbours:
                document.getElementById('clsOnlyMatchingNeighbours')?.checked,
        };
        if (!prefs.columns.length) { alert(tr('alertExportNoColumns')); return; }
        localStorage.setItem(CLS_EXPORT_PREFS_KEY, JSON.stringify(prefs));
        const qs = new URLSearchParams();
        for (const [k, v] of Object.entries(prefs)) {
            if (Array.isArray(v)) { if (v.length) qs.set(k, v.join(',')); }
            else if (v) qs.set(k, 'true');
        }
        const res = await apiFetch('/api/export/classification?' + qs.toString());
        if (!res || !res.ok) { alert(tr('alertExportError')); return; }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'sentinelnet-classification-' + new Date().toISOString().slice(0, 10) + '.csv';
        a.click();
        URL.revokeObjectURL(url);
        closeModal('classificationExportModal');
    }

    document.getElementById('btnExportClassification')
        ?.addEventListener('click', openClassificationExportModal);
    document.getElementById('btnRunClassificationExport')
        ?.addEventListener('click', runClassificationExport);
    document.getElementById('btnCloseClassificationExport')
        ?.addEventListener('click', () => {
            closeModal('classificationExportModal');
        });
    document.getElementById('clsColumnList')?.addEventListener('change', updateClsExportPreview);
    ['clsFilterGroups', 'clsFilterCategories', 'clsFilterNeighbourSourceCategories', 'clsFilterNeighbourCategories'].forEach(id => {
        document.getElementById(id)?.addEventListener('change', updateClsExportPreview);
    });
    document.getElementById('clsOnlyMatchingNeighbours')?.addEventListener('change', updateClsExportPreview);
    document.getElementById('btnClsColsToggle')?.addEventListener('click', () => {
        const boxes = Array.from(document.querySelectorAll('#clsColumnList input'));
        const turnOn = boxes.some(b => !b.checked);
        boxes.forEach(b => { b.checked = turnOn; });
        updateClsExportPreview();
    });
    document.getElementById('btnExportPresetClsDefault')?.addEventListener('click', () => {
        applyClsColumnPreset(['hostname', 'ip', 'tenant', 'category', 'status']);
    });
    document.getElementById('btnExportPresetClsAll')?.addEventListener('click', () => {
        applyClsColumnPreset(clsExportColumns.map(c => c.key));
    });
    document.getElementById('btnExportPresetClsAp')?.addEventListener('click', () => {
        applyClsColumnPreset(['hostname', 'ip', 'tenant', 'category', 'model', 'serial', 'neighbour_device', 'neighbour_port', 'neighbour_category', 'neighbour_serial']);
    });
    document.getElementById('btnExportPresetClsSerials')?.addEventListener('click', () => {
        applyClsColumnPreset(['hostname', 'ip', 'tenant', 'category', 'model', 'serial', 'member_index', 'member_role', 'member_serial', 'member_model']);
    });
