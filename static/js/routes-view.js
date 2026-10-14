// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// Routing tables of several devices, side by side.
//
// Config Analyzer already answers "what is configured on this box" from the
// backup. This view answers the runtime question across boxes: who has a
// route to this prefix, and what do the others do instead. Hence a matrix,
// one prefix per row and one device per column, and an address lookup that
// marks the route each device would pick.
//
// Nothing new is collected: /api/routes calls the same service on the chosen
// devices. Rows are fetched once per "Leggi tabelle"; search, type chips and
// the differences toggle work on what is already in the browser, so typing
// no longer reopens an SSH session per keystroke.
(function () {
    'use strict';

    let _rtRows = [];
    let _rtErrors = [];
    // Per device, from /api/routes: interface addresses, HA members, IPsec
    // tunnels. The route graph names next hops with it.
    let _rtContext = {};
    let _rtLoaded = [];          // [{value, label}] devices of the last read
    let _rtMatrix = [];
    let _rtUnknown = new Set();  // devices whose absence proves nothing (silent / backup only)
    const _rtLkOpen = new Set(); // lookup rows showing their candidate routes
    const _rtTypes = new Set();  // empty = every type
    let _rtDiffOnly = false;
    let _rtIface = '';           // exit interface picked in the rings; '' = any
    const _rtOpen = new Set();
    // ponytail: rendering cap, a full BGP table would freeze the tab.
    // Paginate if someone really needs to scroll past it.
    const RT_MAX_ROWS = 1500;

    // I colori dei tipi sono gli stessi in matrice, nei chip e nell'analisi
    // di percorso: un riquadro giallo deve voler dire la stessa cosa ovunque.
    // Solo le quattro famiglie che si incontrano davvero hanno un colore
    // proprio; il resto resta muto. --accent non esiste in questa palette (i
    // token sono --primary/--success/--warning/--danger/--info).
    const RT_TYPE_COLORS = {
        connected: '--success',
        local: '--text-muted',
        static: '--primary',
        ospf: '--warning',
        bgp: '--info',
        // Policy routes are not RIB entries: a colour of their own, a conductor
        // hue rather than a status lamp.
        policy: '--cond-d',
        eigrp: '--text-muted',
        rip: '--text-muted',
        isis: '--text-muted',
        other: '--text-muted',
        unknown: '--text-muted',
    };
    const RT_ATTACHED = ['connected', 'local'];
    const RT_TYPE_ORDER = ['connected', 'local', 'static', 'ospf', 'bgp', 'policy',
                           'eigrp', 'rip', 'isis', 'other', 'unknown'];

    function rtTypeColor(type) {
        const varName = RT_TYPE_COLORS[type] || '--text-muted';
        return `var(${varName})`;
    }

    // --- Model (pure, exercised by tests/js/test_routes_matrix.mjs) ----------

    /** Dotted quad to unsigned int, or null. */
    function ip4(s) {
        const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec((s || '').trim());
        if (!m) return null;
        const o = m.slice(1).map(Number);
        if (o.some(n => n > 255)) return null;
        return (((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0);
    }

    /** "10.0.0.0/16", "10.0.0.0 255.255.0.0" or a bare address (/32). */
    function parseNet(s) {
        const [addr, mask] = (s || '').trim().split(/[\/\s]+/);
        const base = ip4(addr);
        if (base === null) return null;
        let len = 32;
        if (mask !== undefined) {
            // "10.0.0.0/" mid-typing: Number('') is 0, which read as /0.
            if (mask === '') return null;
            const dotted = ip4(mask);
            len = dotted === null ? Number(mask) : 32 - Math.log2(((~dotted) >>> 0) + 1);
            if (!Number.isInteger(len) || len < 0 || len > 32) return null;
        }
        const bits = len === 0 ? 0 : (0xFFFFFFFF << (32 - len)) >>> 0;
        return { net: (base & bits) >>> 0, len, bits };
    }

    function netContains(n, ip) { return ((ip & n.bits) >>> 0) === n.net; }

    /** The rows of one device that win for `ip`: longest prefix, then lowest
     *  distance. Several rows on a tie (ECMP). */
    function rtLpm(rows, ip) {
        let best = [], bestLen = -1, bestAd = Infinity;
        for (const r of rows) {
            const n = parseNet(r.network);
            if (!n || !netContains(n, ip)) continue;
            const ad = r.distance == null ? 0 : r.distance;
            if (n.len > bestLen || (n.len === bestLen && ad < bestAd)) {
                best = [r]; bestLen = n.len; bestAd = ad;
            } else if (n.len === bestLen && ad === bestAd) {
                best.push(r);
            }
        }
        return best;
    }

    /** Address lookup, one answer per device: the route that takes `ip`, every
     *  other route that covers it with why it loses, and which criterion
     *  decided. `kind`: route | default | none (a live device with nothing
     *  covering it: dropped) | unknown (silent or backup-only, absence proves
     *  nothing). `decidedBy` uses the keys of rtRules(), plus 'only'/'ecmp'. */
    function rtLookup(rows, devices, unknownIps, ip) {
        return devices.map(d => {
            const own = rows.filter(r => r.device_ip === d.value);
            const winners = rtLpm(own, ip);
            if (!winners.length) {
                return { device: d, kind: unknownIps.has(d.value) ? 'unknown' : 'none',
                         winners, candidates: [], decidedBy: '', fromBackup: false };
            }
            const wLen = parseNet(winners[0].network).len;
            const ad = r => (r.distance == null ? 0 : r.distance);
            const candidates = own.map(r => ({ row: r, n: parseNet(r.network) }))
                .filter(c => c.n && netContains(c.n, ip))
                .sort((x, y) => y.n.len - x.n.len || ad(x.row) - ad(y.row) || (x.row.metric || 0) - (y.row.metric || 0))
                .map(c => ({ row: c.row,
                             verdict: winners.includes(c.row) ? 'win' : c.n.len < wLen ? 'lose-prefix' : 'lose-distance' }));
            const decidedBy = winners.length > 1 ? 'ecmp'
                : candidates.length === 1 ? 'only'
                : candidates.some(c => c.verdict === 'lose-distance') ? 'distanza' : 'prefisso';
            return { device: d, kind: wLen === 0 ? 'default' : 'route', winners, candidates, decidedBy,
                     fromBackup: winners.some(r => r.from_backup) };
        });
    }

    /** One entry per (vrf, prefix). For each device: its rows, or what it
     *  does instead — a covering shorter prefix, nothing at all ("hole"), or
     *  "unknown" when the device cannot be judged (it did not answer, or only
     *  its backup statics are known: absence there proves nothing). */
    function rtBuildMatrix(rows, devices, unknownIps) {
        const byKey = new Map();
        const perDev = new Map(devices.map(d => [d.value, []]));
        for (const r of rows) {
            const key = (r.vrf || '') + '|' + r.network;
            if (!byKey.has(key)) {
                byKey.set(key, { key, vrf: r.vrf || '', network: r.network,
                                 net: parseNet(r.network), cells: {} });
            }
            (byKey.get(key).cells[r.device_ip] ||= []).push(r);
            if (perDev.has(r.device_ip)) perDev.get(r.device_ip).push(r);
        }
        const out = [];
        for (const e of byKey.values()) {
            e.cover = {};
            e.missing = 0; e.holes = 0;
            for (const d of devices) {
                const own = e.cells[d.value];
                if (own) { own.sort((a, b) => (a.distance ?? 0) - (b.distance ?? 0)); continue; }
                e.missing += 1;
                if (unknownIps.has(d.value) || !e.net) { e.cover[d.value] = 'unknown'; continue; }
                // ponytail: linear scan per missing cell, fine for a few
                // thousand routes; index by prefix length if it gets slow.
                // Shorter prefixes only, BEFORE the match: a more specific
                // route (a /25 inside this /24) would otherwise win the LPM
                // and hide the /8 that really covers the prefix.
                const same = perDev.get(d.value).filter(r => {
                    const n = parseNet(r.network);
                    return (r.vrf || '') === e.vrf && !!n && n.len < e.net.len;
                });
                const via = rtLpm(same, e.net.net);
                if (via.length) e.cover[d.value] = via[0];
                else { e.cover[d.value] = 'hole'; e.holes += 1; }
            }
            out.push(e);
        }
        out.sort((a, b) => a.vrf.localeCompare(b.vrf)
            || (a.net && b.net ? (a.net.net - b.net.net) || (a.net.len - b.net.len)
                               : a.network.localeCompare(b.network)));
        return out;
    }

    /** What the search box means: an address (lookup), a prefix (overlap) or
     *  free text (substring on network, next-hop, interface). */
    function rtQuery(text) {
        const t = (text || '').trim();
        if (!t) return { kind: 'none' };
        if (t.indexOf('/') === -1) {
            const ip = ip4(t);
            if (ip !== null) return { kind: 'ip', ip, text: t };
        } else {
            const n = parseNet(t);
            if (n) return { kind: 'net', net: n };
        }
        return { kind: 'text', needle: t.toLowerCase() };
    }

    function rtMatches(entry, q) {
        if (q.kind === 'none') return true;
        if (q.kind === 'ip') return !!entry.net && netContains(entry.net, q.ip);
        if (q.kind === 'net') {
            if (!entry.net) return false;
            // Overlap: one of the two contains the other's network address.
            const wide = entry.net.len <= q.net.len ? entry.net : q.net;
            const narrow = wide === entry.net ? q.net : entry.net;
            return netContains(wide, narrow.net);
        }
        if (entry.network.toLowerCase().indexOf(q.needle) !== -1) return true;
        return Object.values(entry.cells).some(rs => rs.some(r =>
            (r.gateway || '').toLowerCase().indexOf(q.needle) !== -1
            || (r.interface || '').toLowerCase().indexOf(q.needle) !== -1));
    }

    /** Which selected device an address belongs to: its management IP, or a
     *  /32 "local" route it reports for one of its own interfaces. A shared
     *  connected subnet proves nothing (both ends have it), so it is not used. */
    // SD-WAN member state, worst wins when several members feed one ribbon.
    const RT_SK_STATE = { up: 1, degraded: 2, down: 3 };

    function rtDeviceOwners(allRows, devices, context = {}) {
        const owners = new Map(devices.map(d => [d.value, d.value]));
        for (const r of allRows) {
            const n = parseNet(r.network);
            if (r.type === 'local' && n && n.len === 32) owners.set(r.network.split('/')[0], r.device_ip);
        }
        // A FortiGate reports no local routes: its interface addresses come
        // from the REST interface list (context, from /api/routes).
        for (const d of devices) {
            for (const a of (context[d.value] || {}).addresses || []) owners.set(a.ip, d.value);
        }
        return owners;
    }

    /** Where a route goes: `{to, label, tunnel}`. `to` is the selected device
     *  that owns the next hop, if any. A FortiGate route into an IPsec tunnel
     *  has no gateway, only the tunnel's name as interface: the tunnel's
     *  remote gateway is the real next hop, often another selected FortiGate. */
    function rtHopResolver(owners, context, directLabel) {
        return r => {
            const ctx = context[r.device_ip] || {};
            // The route leaves through an SD-WAN member: its health checks say
            // whether that link is carrying traffic right now.
            const sdwan = (ctx.sdwan || []).find(m => m.interface === r.interface) || null;
            const gw = r.gateway && r.gateway !== '0.0.0.0' ? r.gateway : '';
            // The exit interface next to the gateway: which link, not only which ISP.
            if (gw) return { to: owners.get(gw), label: r.interface ? `${gw} · ${r.interface}` : gw, tunnel: null, sdwan };
            const tunnel = (ctx.tunnels || []).find(t => t.name === r.interface);
            if (tunnel) {
                return { to: owners.get(tunnel.remote_gw), tunnel, sdwan,
                         label: tunnel.remote_gw ? `${tunnel.name} ⇢ ${tunnel.remote_gw}` : tunnel.name };
            }
            // A connected network has no next hop: the interface is where it
            // lives, not a hop, and the label says so.
            const attached = r.type === 'connected' || r.type === 'local';
            const label = attached && r.interface ? `${directLabel} · ${r.interface}` : r.interface || directLabel;
            return { to: undefined, label, tunnel: null, sdwan };
        };
    }

    /** Depth of each device in the "routes via" graph: a device another
     *  selected device uses as next hop sits one stage after it. Back edges of
     *  a loop are ignored, so the result is always a finite left-to-right order. */
    function rtDeviceDepths(rows, devices, resolve) {
        const next = new Map(devices.map(d => [d.value, new Set()]));
        const fed = new Set();
        for (const r of rows) {
            const to = resolve(r).to;
            if (to && to !== r.device_ip && next.has(to) && next.has(r.device_ip)) {
                next.get(r.device_ip).add(to); fed.add(to);
            }
        }
        const depth = new Map();
        const walk = (d, k, path) => {
            if ((depth.get(d) ?? -1) >= k) return;
            depth.set(d, k);
            for (const s of next.get(d)) if (!path.has(s)) walk(s, k + 1, new Set(path).add(d));
        };
        const ids = devices.map(d => d.value);
        ids.filter(d => !fed.has(d)).forEach(d => walk(d, 0, new Set()));
        ids.filter(d => !depth.has(d)).forEach(d => walk(d, 0, new Set()));  // a pure loop
        return depth;
    }

    /** Route flows for the Sankey: device -> route type -> next hop, each link
     *  weighted by how many routes take it, and carrying those routes for the
     *  detail view. A next hop that is another selected device IS that
     *  device's node, so a chain reads left to right. Next hops past the
     *  `cap` busiest fold into one "other" node per stage. */
    function rtBuildSankey(rows, devices, { cap, resolve, otherLabel }) {
        const name = new Map(devices.map(d => [d.value, d.label]));
        const depth = rtDeviceDepths(rows, devices, resolve);
        const hopOf = r => resolve(r).label;
        const hopCount = new Map();
        for (const r of rows) hopCount.set(hopOf(r), (hopCount.get(hopOf(r)) || 0) + 1);
        const keep = new Set([...hopCount.entries()].sort((a, b) => b[1] - a[1])
            .slice(0, cap).map(([h]) => h));
        const nodes = new Map();
        const links = new Map();
        const node = (id, col, label, kind, extra) => {
            if (!nodes.has(id)) nodes.set(id, { id, col, label, kind, inn: 0, out: 0, ...extra });
            return nodes.get(id);
        };
        const worse = (a, b) => (RT_SK_STATE[b] || 0) > (RT_SK_STATE[a] || 0) ? b : a;
        const link = (s, t, type, r, hop) => {
            const k = s.id + '>' + t.id;
            if (!links.has(k)) links.set(k, { source: s.id, target: t.id, type, value: 0, rows: [] });
            const l = links.get(k);
            l.value += 1; l.rows.push(r);
            // A ribbon into a tunnel says which one, and whether it is down;
            // one over an SD-WAN member carries that member's worst state.
            if (hop && hop.tunnel) { l.tunnel = hop.tunnel.name; l.down = l.down || !hop.tunnel.up; }
            if (hop && hop.sdwan) {
                l.sdwan = hop.sdwan;
                l.state = worse(l.state, hop.sdwan.state);
                t.state = worse(t.state, hop.sdwan.state);
            }
            s.out += 1; t.inn += 1;
        };
        const devNode = ip => node('d|' + ip, 2 * (depth.get(ip) || 0), name.get(ip) || ip, 'device', { ip });
        for (const r of rows) {
            const type = r.type || 'unknown';
            const k = depth.get(r.device_ip) || 0;
            const d = devNode(r.device_ip);
            const t = node(`t|${r.device_ip}|${type}`, 2 * k + 1, type, 'type', { type, ip: r.device_ip });
            const hopInfo = resolve(r);
            const to = hopInfo.to;
            const other = to && to !== r.device_ip;
            // Only forward: the back edge of a loop stays a plain hop, named.
            let h;
            if (other && depth.has(to) && depth.get(to) > k) h = devNode(to);
            else {
                const hop = keep.has(hopOf(r)) || other ? hopOf(r) : otherLabel;
                h = node(`h|${2 * k + 2}|${hop}`, 2 * k + 2, other ? `${hop} · ${name.get(to) || to}` : hop,
                         hop === otherLabel ? 'other' : 'hop',
                         { down: !!(hopInfo.tunnel && !hopInfo.tunnel.up) });
            }
            link(d, t, type, r, null);
            link(t, h, type, r, hopInfo);
        }
        const all = [...nodes.values()];
        all.forEach(n => { n.value = Math.max(n.inn, n.out); });
        // Type nodes follow their device's position, then RT_TYPE_ORDER, so a
        // device's ribbons fan out without crossing its neighbour's.
        const devRank = new Map(all.filter(n => n.kind === 'device')
            .sort((a, b) => a.col - b.col || b.value - a.value).map((n, i) => [n.ip, i]));
        const typeRank = t => (RT_TYPE_ORDER.indexOf(t) + 100) % 100;
        const kindRank = { device: 0, type: 0, hop: 1, other: 2 };
        const ncols = Math.max(...all.map(n => n.col)) + 1;
        const cols = Array.from({ length: ncols }, (_, c) => all.filter(n => n.col === c).sort((a, b) =>
            kindRank[a.kind] - kindRank[b.kind]
            || (a.kind === 'type' && b.kind === 'type'
                ? devRank.get(a.ip) - devRank.get(b.ip) || typeRank(a.type) - typeRank(b.type)
                : b.value - a.value)));
        return { cols, links: [...links.values()], total: rows.length };
    }

    /** "wan1 (port1)", as the FortiGate Routing Monitor writes it; the bare
     *  name when the device reported no alias for it. */
    function rtIfaceName(context, ip, iface) {
        const a = ((context[ip] || {}).addresses || []).find(x => x.iface === iface && x.alias);
        return a ? `${a.alias} (${iface})` : iface;
    }

    /** The Routing Monitor's two rings, per device: its routes by type and by
     *  exit interface, connected included (the firewall counts them too). */
    function rtRingData(rows, devices) {
        const tally = (own, key) => {
            const m = new Map();
            for (const r of own) m.set(key(r), (m.get(key(r)) || 0) + 1);
            return [...m.entries()];
        };
        const typeRank = t => (RT_TYPE_ORDER.indexOf(t) + 100) % 100;
        return devices.map(d => {
            const own = rows.filter(r => r.device_ip === d.value);
            return {
                device: d, total: own.length,
                types: tally(own, r => r.type || 'unknown').sort((a, b) => typeRank(a[0]) - typeRank(b[0])),
                // Ties in natural order: Vlan2 before Vlan10.
                ifaces: tally(own, r => r.interface || '').sort((a, b) => b[1] - a[1]
                    || a[0].localeCompare(b[0], undefined, { numeric: true })),
            };
        }).filter(x => x.total);
    }

    /** One device's rows as the Routing Monitor lists them: sorted by network
     *  address then prefix length, narrowed by the ring filters. */
    function rtMonitorRows(rows, ip, types, iface) {
        const key = r => { const n = parseNet(r.network); return n ? [n.net, n.len] : [Infinity, 0]; };
        return rows.filter(r => r.device_ip === ip && (!types.size || types.has(r.type))
                                && (!iface || r.interface === iface))
            .sort((a, b) => { const x = key(a), y = key(b); return x[0] - y[0] || x[1] - y[1]; });
    }

    /** FortiGate policy routes as pseudo-rows for the graph only: one per
     *  enabled 'permit' policy route, type 'policy'. They are matched before
     *  the routing table, so leaving them out draws a path traffic may not
     *  take. Not in the matrix: they are not RIB entries. 'deny' ones send
     *  traffic back to the RIB and draw nothing of their own. */
    function rtPolicyRows(context, devices) {
        const out = [];
        for (const d of devices) {
            for (const p of (context[d.value] || {}).policy_routes || []) {
                if (!p.enabled || !p.permit) continue;
                const src = p.src.length ? p.src.join(', ') : 'any';
                out.push({ device: d.label, device_ip: d.value, vrf: '', from_backup: false,
                           network: p.dst.length ? p.dst.join(', ') : '0.0.0.0/0',
                           gateway: p.gateway, interface: p.output, type: 'policy',
                           raw_type: `policy #${p.seq} · src ${src}${p.input.length ? ' · in ' + p.input.join(', ') : ''}`,
                           distance: null, metric: null, policy: p });
            }
        }
        return out;
    }

    /** The search box applied to a policy row: its destinations may be
     *  subnets or object names, and no destination means any. */
    function rtPolicyMatches(row, q) {
        if (q.kind === 'none') return true;
        const dst = row.policy.dst;
        if (q.kind === 'ip' || q.kind === 'net') {
            if (!dst.length) return true;
            return dst.some(x => {
                const n = parseNet(x);
                if (!n) return false;
                if (q.kind === 'ip') return netContains(n, q.ip);
                const wide = n.len <= q.net.len ? n : q.net;
                return netContains(wide, (wide === n ? q.net : n).net);
            });
        }
        return [row.network, row.gateway, row.interface, row.raw_type]
            .some(v => (v || '').toLowerCase().indexOf(q.needle) !== -1);
    }

    // --- Data -----------------------------------------------------------------

    function rtSelectedDevices() {
        return pickerValues('rtDeviceFilter');
    }

    // L'elenco arriva dall'inventario, non dalle righe tornate: un apparato
    // mai interrogato deve poter essere scelto, ed e' il motivo per cui gli
    // switch non comparivano qui.
    async function loadRtDeviceList() {
        let devices = [];
        try {
            const res = await apiFetch('/api/routes/devices');
            if (res && res.ok) devices = (await res.json()).devices || [];
        } catch (e) { devices = []; }
        // Lo scope globale vale anche qui: senza filtro il picker elencava
        // tutti gli apparati di tutti i tenant.
        const tenant = window.globalSelectedTenant || 'all';
        if (tenant !== 'all') devices = devices.filter(d => d.group === tenant);
        renderPickerItems('rtDeviceFilter', devices
            .sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''))
            .map(d => ({ value: d.ip, label: d.hostname || d.ip, hint: d.ip })));
    }

    // Apertura del tab: si popola la lista e si aspetta. Interrogare da soli
    // tutta la flotta e' esattamente quello che questa vista non deve fare.
    async function routesTabShown() {
        await loadRtDeviceList();
        rtTraceSyncSources();
        renderRtTrace();
        renderRtMatrix();
    }

    async function loadRoutesTab() {
        const chosen = pickerSelected('rtDeviceFilter');
        _rtOpen.clear();
        _skSel = '';
        _rtIface = '';
        if (!chosen.length) {
            // Nessun apparato scelto: nessuna sessione aperta.
            _rtRows = []; _rtErrors = []; _rtLoaded = []; _rtMatrix = []; _rtContext = {};
            renderRtErrors();
            renderRtMatrix();
            return;
        }
        const body = document.getElementById('rtMxBody');
        if (body) {
            body.innerHTML = `<tr><td class="rt-mx-empty">${escapeHtml(tr('rtLoading'))}</td></tr>`;
        }
        try {
            const res = await apiFetch('/api/routes?device='
                + encodeURIComponent(chosen.map(d => d.value).join(',')));
            if (!res || !res.ok) throw new Error('HTTP ' + (res ? res.status : '?'));
            const data = await res.json();
            _rtRows = data.rows || [];
            _rtErrors = data.errors || [];
            _rtContext = data.context || {};
        } catch (e) {
            _rtRows = []; _rtContext = {};
            _rtErrors = [{ device_ip: '', error: String(e) }];
        }
        _rtLoaded = chosen;
        // Only a live answer lets absence mean "no route": a device that went
        // silent, or of which only the backup statics are known, is unknown.
        const live = new Set(_rtRows.filter(r => !r.from_backup).map(r => r.device_ip));
        const unknown = new Set(chosen.map(d => d.value).filter(ip => !live.has(ip)));
        _rtUnknown = unknown;
        _rtMatrix = rtBuildMatrix(_rtRows, chosen, unknown);
        renderRtErrors();
        renderRtMatrix();
    }

    function renderRtErrors() {
        const box = document.getElementById('rtErrors');
        if (!box) return;
        if (!_rtErrors.length) { box.style.display = 'none'; box.innerHTML = ''; return; }
        // Un apparato muto e' una riga accanto agli altri, non una tabella
        // vuota per tutti: senza dirlo, l'assenza delle sue rotte si legge
        // come "non ne ha".
        box.style.display = '';
        box.innerHTML = `<div class="rt-partial">
            <strong>${escapeHtml(tr('rtPartial', { n: _rtErrors.length }))}</strong>
            <ul>${_rtErrors.map(e => `<li><span class="rt-code">${
                    escapeHtml(e.device_ip || '?')}</span> &mdash; ${escapeHtml(e.error)}</li>`).join('')}</ul>
          </div>`;
    }

    // --- Render ---------------------------------------------------------------

    function rtKind(type) {
        return `<b class="rt-kind" style="background:${rtTypeColor(type)}" aria-hidden="true">${
            escapeHtml((type || '?').slice(0, 1).toUpperCase())}</b>`;
    }

    function rtVisible(q) {
        return _rtMatrix.filter(e =>
            (!_rtDiffOnly || e.missing > 0)
            && (!_rtTypes.size || Object.values(e.cells).some(rs => rs.some(r => _rtTypes.has(r.type))))
            && (!_rtIface || Object.values(e.cells).some(rs => rs.some(r => r.interface === _rtIface)))
            && rtMatches(e, q));
    }

    function rtSearchValue() {
        const el = /** @type {HTMLInputElement|null} */ (document.getElementById('rtSearch'));
        return el ? el.value : '';
    }

    function renderRtMatrix() {
        const head = document.getElementById('rtMxHead');
        const body = document.getElementById('rtMxBody');
        if (!head || !body) return;
        const q = rtQuery(rtSearchValue());
        const devs = _rtLoaded;
        renderRtLookup(q);
        renderRtTally();
        renderRtRings();
        renderRtChips();
        renderRtLegend();

        if (!devs.length) {
            renderRtSankey([]);
            head.innerHTML = '';
            body.innerHTML = `<tr><td class="rt-mx-empty">${escapeHtml(tr('rtPickDevices'))}</td></tr>`;
            return;
        }
        const backup = new Set(_rtRows.filter(r => r.from_backup).map(r => r.device_ip));
        const answered = new Set(_rtRows.map(r => r.device_ip));
        head.innerHTML = `<tr><th data-no-sort="1" class="rt-mx-net">${escapeHtml(tr('rtColNetwork'))}</th>${
            devs.map(d => {
                const tag = backup.has(d.value)
                    ? `<span class="rt-col-tag warn">${escapeHtml(tr('rtFromBackup'))}</span>`
                    : !answered.has(d.value)
                        ? `<span class="rt-col-tag">${escapeHtml(tr('rtMxSilent'))}</span>` : '';
                return `<th data-no-sort="1"><span class="rt-col-name">${escapeHtml(d.label)}</span>
                    <span class="rt-col-ip">${escapeHtml(d.value)}</span>${tag}</th>`;
            }).join('')}</tr>`;

        const rows = rtVisible(q);
        // Same filters as the matrix: search, type chips, differences only.
        renderRtSankey(rows);
        if (q.kind === 'ip') rows.sort((a, b) => b.net.len - a.net.len);
        const span = devs.length + 1;
        if (!rows.length) {
            const msg = q.kind === 'ip' ? tr('rtMxNoCover', { ip: q.text }) : tr('rtEmpty');
            body.innerHTML = `<tr><td class="rt-mx-empty" colspan="${span}">${escapeHtml(msg)}</td></tr>`;
            return;
        }
        // Lookup: each device's winning route is marked. That is the answer to
        // "where does this address go from here".
        const winners = new Set();
        if (q.kind === 'ip') {
            for (const d of devs) {
                for (const r of rtLpm(_rtRows.filter(x => x.device_ip === d.value), q.ip)) {
                    winners.add(d.value + '|' + (r.vrf || '') + '|' + r.network);
                }
            }
        }
        const html = [];
        for (const e of rows.slice(0, RT_MAX_ROWS)) {
            const open = _rtOpen.has(e.key);
            const state = e.holes ? 'hole' : e.missing ? 'gap' : 'full';
            html.push(`<tr class="rt-mx-row ${state}${open ? ' open' : ''}">
                <th scope="row" class="rt-mx-net">
                  <button type="button" class="rt-mx-toggle" data-action="rt-mx-toggle"
                          data-key="${escapeHtml(e.key)}" aria-expanded="${open}">
                    <i class="fa-solid fa-chevron-right" aria-hidden="true"></i><span>${
                        escapeHtml(e.network)}</span>
                  </button>${e.vrf ? `<span class="rt-mx-vrf">${escapeHtml(e.vrf)}</span>` : ''}
                </th>${devs.map(d => rtCell(e, d, winners)).join('')}</tr>`);
            if (open) html.push(rtDetailRow(e, devs));
        }
        if (rows.length > RT_MAX_ROWS) {
            html.push(`<tr><td class="rt-mx-empty" colspan="${span}">${
                escapeHtml(tr('rtMxCapped', { n: RT_MAX_ROWS, total: rows.length }))}</td></tr>`);
        }
        body.innerHTML = html.join('');
    }

    // Address typed in the search: one sentence per device saying which route
    // takes it and where it goes; a click opens that device's candidate routes
    // with the reason each one wins or loses. The matrix below stays as is.
    function renderRtLookup(q) {
        const box = document.getElementById('rtLookup');
        if (!box) return;
        if (q.kind !== 'ip' || !_rtLoaded.length) { box.hidden = true; box.innerHTML = ''; return; }
        const hopOf = (r, dev) => (r.gateway && r.gateway !== '0.0.0.0')
            ? r.gateway : rtIfaceName(_rtContext, dev, r.interface || '?');
        const rows = rtLookup(_rtRows, _rtLoaded, _rtUnknown, q.ip).map(a => {
            const dev = a.device.value;
            const name = `<b class="rt-lk-dev">${escapeHtml(a.device.label)}</b>`;
            if (a.kind === 'none') {
                return `<li class="rt-lk-row none"><p>${name}: <span class="rt-lk-bad">${escapeHtml(tr('rtLkNone'))}</span></p></li>`;
            }
            if (a.kind === 'unknown') {
                return `<li class="rt-lk-row unknown"><p>${name}: ${escapeHtml(tr('rtLkUnknown'))}</p></li>`;
            }
            const w = a.winners[0];
            const attached = RT_ATTACHED.includes(w.type) && !(w.gateway && w.gateway !== '0.0.0.0');
            const say = a.kind === 'default'
                ? tr('rtLkDefault', { net: w.network, hop: hopOf(w, dev) })
                : attached ? tr('rtLkConnected', { net: w.network, iface: hopOf(w, dev) })
                : tr('rtLkRoute', { net: w.network, type: w.raw_type || w.type, hop: hopOf(w, dev) });
            const ecmp = a.winners.length > 1
                ? ' ' + tr('rtLkEcmp', { hops: a.winners.slice(1).map(r => hopOf(r, dev)).join(', ') }) : '';
            const why = a.decidedBy === 'only' ? tr('rtWhyOnly')
                : a.decidedBy === 'prefisso' ? tr('rtWhyPrefix', { len: parseNet(w.network).len })
                : a.decidedBy === 'distanza' ? tr('rtWhyDistance') : tr('rtWhyEcmp');
            const backup = a.fromBackup ? ` <span class="rt-lk-warn">${escapeHtml(tr('rtWhyBackup'))}</span>` : '';
            const open = _rtLkOpen.has(dev);
            let detail = '';
            if (open) {
                const cand = a.candidates.map(c => {
                    const r = c.row, win = c.verdict === 'win';
                    return `<tr class="${win ? 'won' : 'lost'}">
                        <td class="rt-lead">${rtKind(r.type)}${escapeHtml(r.network)}</td>
                        <td>${r.gateway && r.gateway !== '0.0.0.0' ? escapeHtml(tr('rtTraceVia', { hop: r.gateway }))
                                        : escapeHtml(tr('rtTraceOnIface', { iface: hopOf(r, dev) }))}</td>
                        <td class="rt-num">/${escapeHtml(String(parseNet(r.network).len))}</td>
                        <td class="rt-num">${escapeHtml(String(r.distance == null ? 0 : r.distance))}</td>
                        <td class="rt-num">${escapeHtml(String(r.metric || 0))}</td>
                        <td class="rt-num"><span class="rt-outcome${win ? ' win' : ''}">${
                            escapeHtml(win ? tr('rtTraceWins') : tr('rtTraceDropped'))}</span></td>
                      </tr>`;
                }).join('');
                const hit = { prefisso: 0, distanza: 1, ecmp: 1, only: 0 }[a.decidedBy];
                const rules = rtRules().map((rule, i) =>
                    `<span class="rt-rule-step ${i === hit ? 'hit' : i > hit ? 'moot' : ''}">${escapeHtml(rule.label)}</span>`).join('');
                detail = `<div class="rt-lk-detail"><table class="rt-cand" data-no-colpicker>
                    <thead><tr>
                      <th data-no-sort="1">${escapeHtml(tr('rtColNetwork'))}</th>
                      <th data-no-sort="1">${escapeHtml(tr('rtColNextHop'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColPrefix'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColAd'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtColMetric'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColOutcome'))}</th>
                    </tr></thead><tbody>${cand}</tbody></table>
                    <div class="rt-rule">${rules}</div></div>`;
            }
            return `<li class="rt-lk-row ${a.kind}">
                <button type="button" class="rt-lk-toggle" data-action="rt-lk-toggle" data-dev="${escapeHtml(dev)}" aria-expanded="${open}">
                  <i class="fa-solid fa-chevron-right" aria-hidden="true"></i>
                  <span>${name}: ${escapeHtml(say + ecmp)}<span class="rt-lk-why">${escapeHtml(why)}${
                      a.candidates.length > 1 ? ' ' + escapeHtml(tr('rtLkCandidates', { n: a.candidates.length })) : ''}</span>${backup}</span>
                </button>${detail}</li>`;
        }).join('');
        box.hidden = false;
        box.innerHTML = `<h3>${escapeHtml(tr('rtLkHead', { ip: q.text }))}</h3><ul class="rt-lk-list">${rows}</ul>`;
    }

    function rtCell(e, d, winners) {
        const own = e.cells[d.value];
        if (own) {
            const r = own[0];
            const win = winners.has(d.value + '|' + e.vrf + '|' + e.network);
            const more = own.length > 1 ? `<span class="rt-more">+${own.length - 1}</span>` : '';
            // FortiOS writes 0.0.0.0 for "no gateway": the interface is the hop.
            const hop = (r.gateway && r.gateway !== '0.0.0.0' ? r.gateway : '')
                || (r.interface && rtIfaceName(_rtContext, d.value, r.interface));
            return `<td class="rt-cell${win ? ' win' : ''}"${win ? ` title="${escapeHtml(tr('rtMxWins'))}"` : ''}>${
                rtKind(r.type)}<span class="visually-hidden">${escapeHtml(r.type)} </span>${
                hop ? escapeHtml(hop) : '&mdash;'}${more}</td>`;
        }
        const c = e.cover[d.value];
        if (c === 'unknown') {
            return `<td class="rt-cell unknown"><span class="rt-mark unknown" aria-hidden="true"></span>${
                escapeHtml(tr('rtMxUnknown'))}</td>`;
        }
        if (c === 'hole') {
            return `<td class="rt-cell hole"><span class="rt-mark hole" aria-hidden="true"></span>${
                escapeHtml(tr('rtMxHole'))}</td>`;
        }
        return `<td class="rt-cell covered">${escapeHtml(tr('rtMxCoveredBy', { net: c.network }))}</td>`;
    }

    function rtDetailRow(e, devs) {
        const dash = '&mdash;';
        const lines = devs.flatMap(d => (e.cells[d.value] || []).map(r => `<tr>
            <td>${escapeHtml(d.label)}</td>
            <td>${rtKind(r.type)}${escapeHtml(r.raw_type || r.type || '')}</td>
            <td>${r.gateway ? escapeHtml(r.gateway) : dash}</td>
            <td>${r.interface ? escapeHtml(rtIfaceName(_rtContext, d.value, r.interface)) : dash}</td>
            <td class="rt-num">${r.distance == null ? dash : escapeHtml(String(r.distance))}</td>
            <td class="rt-num">${r.metric == null ? dash : escapeHtml(String(r.metric))}</td>
          </tr>`)).join('');
        return `<tr class="rt-mx-detail"><td colspan="${devs.length + 1}">
            <table class="rt-cand" data-no-colpicker><thead><tr>
              <th data-no-sort="1">${escapeHtml(tr('rtColDevice'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtColType'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtColGateway'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtColIface'))}</th>
              <th data-no-sort="1" class="rt-num">${escapeHtml(tr('rtColDistance'))}</th>
              <th data-no-sort="1" class="rt-num">${escapeHtml(tr('rtColMetric'))}</th>
            </tr></thead><tbody>${lines}</tbody></table></td></tr>`;
    }

    // Interface colours: the conductor hues, never a status lamp; past five
    // they repeat, the legend still names each one.
    const RT_IFACE_COLORS = ['--cond-a', '--cond-b', '--cond-c', '--cond-d', '--cond-trace'];

    function rtRingSvg(segs, total, label) {
        const R = 42, C = 2 * Math.PI * R;
        let off = 0;
        const arcs = segs.map(sg => {
            const len = C * sg.n / total;
            const arc = `<circle class="rt-ring-seg" cx="60" cy="60" r="${R}" stroke="${sg.color}"
                stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}"
                ${sg.action ? `data-action="${sg.action}" ${sg.attr}` : ''}><title>${escapeHtml(sg.label)}: ${sg.n}</title></circle>`;
            off += len;
            return arc;
        }).join('');
        return `<svg class="rt-ring" viewBox="0 0 120 120" role="img" aria-label="${escapeHtml(label)}">
            <g transform="rotate(-90 60 60)">${arcs}</g>
            <text x="60" y="58" class="rt-ring-total">${total}</text>
            <text x="60" y="78" class="rt-ring-sub">${escapeHtml(tr('rtRingTotal'))}</text></svg>`;
    }

    function rtRingBlock(title, segs, total) {
        const label = `${title}: ` + segs.map(sg => `${sg.label} ${sg.n}`).join(', ');
        return `<div class="rt-ring-block">${rtRingSvg(segs, total, label)}
            <div class="rt-ring-legend"><h4>${escapeHtml(title)}</h4>${segs.map(sg => {
                const inner = `<span class="rt-ring-dot" style="background:${sg.color}" aria-hidden="true"></span>${
                    escapeHtml(sg.label)}<span class="rt-ring-n">${sg.n}</span>`;
                // Not a filter (no interface, or the folded rest): plain text.
                return sg.action
                    ? `<button type="button" class="rt-ring-item" data-action="${sg.action}" ${sg.attr} aria-pressed="${sg.on}">${inner}</button>`
                    : `<span class="rt-ring-item rt-ring-rest">${inner}</span>`;
            }).join('')}</div></div>`;
    }

    // ponytail: past a handful of slices a ring stops being readable (a
    // switch with 40 VLANs); the smallest fold into one "N more", which the
    // table and the search box still reach one by one.
    const RT_RING_MAX = 8;
    function rtRingFold(segs) {
        if (segs.length <= RT_RING_MAX) return segs;
        const rest = segs.slice(RT_RING_MAX - 1);
        return segs.slice(0, RT_RING_MAX - 1).concat({
            n: rest.reduce((s, x) => s + x.n, 0), label: tr('rtRingOthers', { n: rest.length }),
            color: 'var(--text-soft)', on: false, action: '', attr: '' });
    }

    function renderRtRings() {
        const box = document.getElementById('rtRings');
        if (!box) return;
        const data = rtRingData(_rtRows, _rtLoaded);
        if (!data.length) {
            box.innerHTML = `<p class="rt-mx-empty">${escapeHtml(tr(_rtLoaded.length ? 'rtEmpty' : 'rtPickDevices'))}</p>`;
            return;
        }
        const ifaceColor = new Map();
        box.innerHTML = data.map(x => {
            const types = x.types.map(([t, n]) => ({
                n, label: t, color: rtTypeColor(t), on: _rtTypes.has(t),
                action: 'rt-ring-type', attr: `data-type="${escapeHtml(t)}"` }));
            const ifaces = x.ifaces.map(([i, n]) => {
                if (!ifaceColor.has(i)) ifaceColor.set(i, `var(${RT_IFACE_COLORS[ifaceColor.size % RT_IFACE_COLORS.length]})`);
                return { n, label: i ? rtIfaceName(_rtContext, x.device.value, i) : tr('rtRingNoIface'),
                         color: ifaceColor.get(i), on: !!i && _rtIface === i,
                         action: i ? 'rt-ring-iface' : '', attr: `data-iface="${escapeHtml(i)}"` };
            });
            return `<section class="rt-ring-card"><h4 class="rt-ring-dev">${escapeHtml(x.device.label)}
                <span class="rt-col-ip">${escapeHtml(x.device.value)}</span></h4>
                <div class="rt-ring-body"><div class="rt-ring-pair">${rtRingBlock(tr('rtRingType'), rtRingFold(types), x.total)}${
                    rtRingBlock(tr('rtRingIfaces'), rtRingFold(ifaces), x.total)}</div><div class="rt-monitor-wrap">${rtMonitorTable(x.device)}</div></div></section>`;
        }).join('');
    }

    // ponytail: a card lists this many; the table below holds the rest.
    const RT_MONITOR_MAX = 50;

    // The Routing Monitor's own table. The gateway is shown as the device
    // wrote it: FortiOS says 0.0.0.0 for a network on the interface itself.
    function rtMonitorTable(device) {
        const rows = rtMonitorRows(_rtRows, device.value, _rtTypes, _rtIface);
        const dash = '&mdash;';
        const body = rows.slice(0, RT_MONITOR_MAX).map(r => `<tr>
            <td>${escapeHtml(r.network)}</td>
            <td>${r.gateway ? escapeHtml(r.gateway) : dash}</td>
            <td>${r.interface ? escapeHtml(rtIfaceName(_rtContext, device.value, r.interface)) : dash}</td>
            <td class="rt-num">${r.distance == null ? dash : escapeHtml(String(r.distance))}</td>
            <td>${rtKind(r.type)}${escapeHtml(r.raw_type || r.type || '')}</td></tr>`).join('');
        const more = rows.length > RT_MONITOR_MAX
            ? `<p class="rt-mx-empty">${escapeHtml(tr('rtRingMore', { n: rows.length - RT_MONITOR_MAX }))}</p>` : '';
        return `<table class="rt-cand rt-monitor" data-no-colpicker><thead><tr>
              <th data-no-sort="1">${escapeHtml(tr('rtColNetwork'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtRingGateway'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtRingIfaces'))}</th>
              <th data-no-sort="1" class="rt-num">${escapeHtml(tr('rtColDistance'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtRingType'))}</th>
            </tr></thead><tbody>${body}</tbody></table>${more}`;
    }

    // ponytail: hand-rolled Sankey (fixed stage columns, no crossing
    // minimisation beyond ordering), enough for device -> type -> next hop
    // chains. A vendor lib only if it ever needs free-form graphs.
    const RT_SK_MAX_HOPS = 12;
    const RT_SK_DETAIL_MAX = 300;
    // Route types switched off in the graph. Directly attached networks start
    // off: they are not routes to anywhere, and drown the ones that are.
    const _skHidden = new Set(RT_ATTACHED);
    let _sk = null;                // last graph drawn, for the detail view
    let _skSel = '';               // 'n|<node id>' or 'l|<link index>'

    function renderRtSkTypes(rows) {
        const box = document.getElementById('rtSkTypes');
        if (!box) return;
        const counts = {};
        for (const r of rows) counts[r.type || 'unknown'] = (counts[r.type || 'unknown'] || 0) + 1;
        box.innerHTML = RT_TYPE_ORDER.filter(t => counts[t]).map(t =>
            `<button type="button" class="chip-choice rt-chip" data-action="rt-sk-type"
                data-type="${escapeHtml(t)}" aria-pressed="${!_skHidden.has(t)}">${
                rtKind(t)}${escapeHtml(t)}<span class="rt-chip-n">${counts[t]}</span></button>`).join('');
    }

    // State colours are the lamp tokens, reserved for state: never a type.
    const skStateColor = st => st === 'down' ? 'var(--lamp-fault)'
        : st === 'degraded' ? 'var(--lamp-warn)' : '';
    // ...and always carry a word, so the state is never colour alone.
    const skStateNote = n => {
        const key = n.down ? 'rtSkDown' : n.state === 'down' ? 'rtSkSdwanDown'
            : n.state === 'degraded' ? 'rtSkSdwanDegraded' : '';
        return key ? ` · ${escapeHtml(tr(key))}` : '';
    };
    const skSdwanText = m => tr('rtSkSdwanMember', { name: m.interface }) + ': ' + m.checks.map(c =>
        c.status === 'up'
            ? `${c.name} ${c.latency == null ? '' : c.latency + ' ms'}${c.loss == null ? '' : ' · ' + tr('rtSkLoss', { n: c.loss })}`.trim()
            : `${c.name} ${tr('rtSkCheckDown')}`).join('; ');

    function renderRtSankey(entries) {
        const box = document.getElementById('rtSankey');
        if (!box) return;
        const q = rtQuery(rtSearchValue());
        const shown = entries.flatMap(e => Object.values(e.cells).flat())
            .concat(rtPolicyRows(_rtContext, _rtLoaded).filter(r => rtPolicyMatches(r, q)))
            .filter(r => !_rtTypes.size || _rtTypes.has(r.type));
        renderRtSkTypes(shown);
        const rows = shown.filter(r => !_skHidden.has(r.type || 'unknown'));
        _sk = null;
        if (!rows.length) {
            const msg = !_rtLoaded.length ? 'rtPickDevices' : shown.length ? 'rtSkAllHidden' : 'rtEmpty';
            box.innerHTML = `<p class="rt-mx-empty">${escapeHtml(tr(msg))}</p>`;
            renderRtSkDetail();
            return;
        }
        // An HA cluster is one node: its name says so, the tooltip says with whom.
        const devices = _rtLoaded.map(d => {
            const peers = ((_rtContext[d.value] || {}).ha || []).map(p => p.hostname).filter(Boolean);
            return peers.length > 1 ? { ...d, label: `${d.label} · HA` } : d;
        });
        const g = rtBuildSankey(rows, devices, {
            cap: RT_SK_MAX_HOPS, otherLabel: tr('rtSkOther'),
            resolve: rtHopResolver(rtDeviceOwners(_rtRows, _rtLoaded, _rtContext), _rtContext, tr('rtSkDirect')) });
        _sk = g;
        const ncols = g.cols.length;
        const NODE_W = 12, GAP = 10, PAD_L = 170, PAD_R = 190, COL_MIN = 170;
        const W = Math.max(box.clientWidth || 900, PAD_L + PAD_R + (ncols - 1) * COL_MIN);
        const most = Math.max(...g.cols.map(c => c.length));
        const widest = Math.max(...g.cols.map(c => c.reduce((s, n) => s + n.value, 0)));
        // A thin node still owns a slot tall enough for its two label lines.
        const SLOT = 30;
        const k = (Math.max(220, Math.min(620, most * 38)) - GAP * (most - 1)) / widest;
        const xAt = c => PAD_L + c * (W - PAD_L - PAD_R - NODE_W) / Math.max(1, ncols - 1);
        const slot = n => Math.max(SLOT, n.value * k);
        const height = col => col.reduce((s, n) => s + slot(n), 0) + GAP * (col.length - 1);
        const H = Math.max(...g.cols.map(height));
        const byId = new Map();
        g.cols.forEach((col, c) => {
            let y = (H - height(col)) / 2;  // a shorter column sits centred
            for (const n of col) {
                const h = Math.max(2, n.value * k);
                Object.assign(n, { x: xAt(c), y: y + (slot(n) - h) / 2, h, usedOut: 0, usedIn: 0 });
                byId.set(n.id, n);
                y += slot(n) + GAP;
            }
        });
        // Stack each node's links in the order of the nodes they reach, so
        // ribbons leave and arrive without crossing inside a node.
        const ls = g.links.map((l, i) => ({ ...l, i, s: byId.get(l.source), t: byId.get(l.target), w: l.value * k }));
        for (const l of [...ls].sort((a, b) => a.t.y - b.t.y || a.s.y - b.s.y)) {
            l.sy = l.s.y + l.s.usedOut + l.w / 2; l.s.usedOut += l.w;
        }
        for (const l of [...ls].sort((a, b) => a.s.y - b.s.y || a.t.y - b.t.y)) {
            l.ty = l.t.y + l.t.usedIn + l.w / 2; l.t.usedIn += l.w;
        }
        const ink = 'var(--text)', muted = 'var(--text-muted)';
        const pct = v => `${v} (${(100 * v / g.total).toFixed(1)}%)`;
        const paths = ls.map(l => {
            const x0 = l.s.x + NODE_W, x1 = l.t.x, xm = (x0 + x1) / 2;
            const on = _skSel === 'l|' + l.i ? ' rt-sk-on' : '';
            return `<path class="rt-sk-link${on}" data-sk="l|${l.i}" data-s="${escapeHtml(l.source)}" data-t="${escapeHtml(l.target)}"
                d="M${x0},${l.sy}C${xm},${l.sy} ${xm},${l.ty} ${x1},${l.ty}"
                stroke="${skStateColor(l.down ? 'down' : l.state) || rtTypeColor(l.type)}" stroke-width="${Math.max(1, l.w)}"><title>${
                escapeHtml(`${l.s.label} → ${l.t.label}: ${pct(l.value)}`
                    + (l.tunnel ? ` · ${tr(l.down ? 'rtSkTunnelDown' : 'rtSkTunnelUp', { name: l.tunnel })}` : '')
                    + (l.sdwan ? ` · ${skSdwanText(l.sdwan)}` : ''))}</title></path>`;
        }).join('');
        const nodesSvg = [...byId.values()].map(n => {
            const fill = skStateColor(n.down ? 'down' : n.state) || (n.type ? rtTypeColor(n.type) : n.kind === 'device' ? 'var(--primary)' : muted);
            const left = n.col === 0;
            const tx = left ? n.x - 8 : n.x + NODE_W + 8;
            const cy = n.y + n.h / 2;
            const anchor = left ? 'end' : 'start';
            const on = _skSel === 'n|' + n.id ? ' rt-sk-on' : '';
            const peers = n.kind === 'device'
                ? ((_rtContext[n.ip] || {}).ha || []).map(p => p.hostname).filter(Boolean) : [];
            const say = `${n.label}: ${pct(n.value)}`
                + (peers.length > 1 ? ` · ${tr('rtSkHaMembers', { names: peers.join(', ') })}` : '');
            return `<g class="rt-sk-node${on}" data-sk="n|${escapeHtml(n.id)}" tabindex="0" role="button"
                    aria-label="${escapeHtml(say)}"><title>${escapeHtml(say)}</title>
                <rect x="${n.x - 4}" y="${n.y - 4}" width="${NODE_W + 8}" height="${n.h + 8}" fill="transparent"/>
                <rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="${n.h}" rx="2" fill="${fill}"/>
                <text x="${tx}" y="${cy - 2}" text-anchor="${anchor}" fill="${ink}" class="rt-sk-name">${escapeHtml(n.label)}</text>
                <text x="${tx}" y="${cy + 12}" text-anchor="${anchor}" fill="${muted}" class="rt-sk-val">${pct(n.value)}${skStateNote(n)}</text></g>`;
        }).join('');
        const heads = g.cols.map((_, c) => {
            const t = c === 0 ? tr('rtColDevice') : c % 2 ? tr('rtColType')
                : g.cols[c].some(n => n.kind === 'device') ? tr('rtSkStage') : tr('rtSkNextHop');
            return `<text x="${c === 0 ? xAt(0) + NODE_W : xAt(c)}" y="-10" text-anchor="${c === 0 ? 'end' : 'start'}"
                class="rt-sk-head" fill="${muted}">${escapeHtml(t)}</text>`;
        }).join('');
        box.innerHTML = `<svg class="rt-sk-svg" viewBox="0 -24 ${W} ${H + 32}" style="min-width:${W}px" role="group"
            aria-label="${escapeHtml(tr('rtSkAria', { n: g.total }))}">${heads}${paths}${nodesSvg}</svg>`;
        renderRtSkDetail();
    }

    /** The routes behind the selected node or ribbon: the "which prefixes
     *  end up here" question the picture alone cannot answer. */
    function renderRtSkDetail() {
        const box = document.getElementById('rtSkDetail');
        if (!box) return;
        const kind = _skSel.slice(0, 1), id = _skSel.slice(2);
        const nodeOf = nid => _sk && _sk.cols.flat().find(n => n.id === nid);
        let title = '', rows = [];
        if (_sk && kind === 'l' && _sk.links[Number(id)]) {
            const l = _sk.links[Number(id)];
            title = `${(nodeOf(l.source) || { label: '?' }).label} → ${(nodeOf(l.target) || { label: '?' }).label}`;
            rows = l.rows;
        } else if (kind === 'n' && nodeOf(id)) {
            title = nodeOf(id).label;
            const seen = new Set();
            for (const l of _sk.links) {
                if (l.source === id || l.target === id) l.rows.forEach(r => seen.add(r));
            }
            rows = [...seen];
        }
        if (!rows.length) { _skSel = ''; box.hidden = true; box.innerHTML = ''; return; }
        const name = new Map(_rtLoaded.map(d => [d.value, d.label]));
        const dash = '&mdash;';
        rows = [...rows].sort((a, b) => (a.device_ip || '').localeCompare(b.device_ip || '')
            || ((parseNet(a.network) || { net: 0 }).net - (parseNet(b.network) || { net: 0 }).net));
        const body = rows.slice(0, RT_SK_DETAIL_MAX).map(r => `<tr>
            <td>${escapeHtml(name.get(r.device_ip) || r.device_ip)}</td>
            <td class="rt-code">${escapeHtml(r.network)}${r.vrf ? ` <span class="rt-mx-vrf">${escapeHtml(r.vrf)}</span>` : ''}</td>
            <td>${rtKind(r.type)}${escapeHtml(r.raw_type || r.type || '')}</td>
            <td class="rt-code">${r.gateway ? escapeHtml(r.gateway) : dash}</td>
            <td>${r.interface ? escapeHtml(r.interface) : dash}</td>
            <td class="rt-num">${r.distance == null ? dash : escapeHtml(String(r.distance))}/${r.metric == null ? dash : escapeHtml(String(r.metric))}</td>
          </tr>`).join('');
        const more = rows.length > RT_SK_DETAIL_MAX
            ? `<p class="rt-mx-empty">${escapeHtml(tr('rtSkMore', { n: rows.length - RT_SK_DETAIL_MAX }))}</p>` : '';
        box.hidden = false;
        box.innerHTML = `<div class="rt-sk-detail-head">
              <strong>${escapeHtml(tr('rtSkDetailTitle', { name: title, n: rows.length }))}</strong>
              <button type="button" class="btn btn-secondary btn-small" data-action="rt-sk-close"
                      style="width:auto; margin:0;">${escapeHtml(tr('btnClose'))}</button>
            </div>
            <div class="table-container"><table class="rt-cand" data-no-colpicker><thead><tr>
              <th data-no-sort="1">${escapeHtml(tr('rtColDevice'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtColNetwork'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtColType'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtColGateway'))}</th>
              <th data-no-sort="1">${escapeHtml(tr('rtColIface'))}</th>
              <th data-no-sort="1" class="rt-num">${escapeHtml(tr('rtColDistance'))}/${escapeHtml(tr('rtColMetric'))}</th>
            </tr></thead><tbody>${body}</tbody></table></div>${more}`;
    }

    function rtSkSelect(key) {
        _skSel = key;
        document.querySelectorAll('#rtSankey .rt-sk-on').forEach(el => el.classList.remove('rt-sk-on'));
        document.querySelector(`#rtSankey [data-sk="${CSS.escape(key)}"]`)?.classList.add('rt-sk-on');
        renderRtSkDetail();
        document.getElementById('rtSkDetail')?.scrollIntoView({ block: 'nearest' });
    }

    function renderRtTally() {
        const box = document.getElementById('rtTally');
        if (!box) return;
        if (!_rtLoaded.length) { box.innerHTML = ''; box.style.display = 'none'; return; }
        box.style.display = '';
        const gaps = _rtMatrix.filter(e => e.missing).length;
        const holes = _rtMatrix.filter(e => e.holes).length;
        const answered = new Set(_rtRows.map(r => r.device_ip)).size;
        const item = (label, n) => `<span>${escapeHtml(label)} <b>${n}</b></span>`;
        box.innerHTML = item(tr('rtTallyDevices'), `${answered}/${_rtLoaded.length}`)
            + item(tr('rtTallyRoutes'), _rtRows.filter(r => !RT_ATTACHED.includes(r.type)).length)
            + item(tr('rtTallyConnected'), _rtRows.filter(r => RT_ATTACHED.includes(r.type)).length)
            + item(tr('rtTallyPrefixes'), _rtMatrix.length)
            + item(tr('rtTallyGaps'), gaps)
            + item(tr('rtTallyHoles'), holes);
    }

    function renderRtChips() {
        const box = document.getElementById('rtTypeChips');
        if (!box) return;
        const counts = {};
        for (const r of _rtRows) counts[r.type] = (counts[r.type] || 0) + 1;
        box.innerHTML = RT_TYPE_ORDER.filter(t => counts[t]).map(t =>
            `<button type="button" class="chip-choice rt-chip" data-action="rt-type"
                data-type="${escapeHtml(t)}" aria-pressed="${_rtTypes.has(t)}">${
                rtKind(t)}${escapeHtml(t)}<span class="rt-chip-n">${counts[t]}</span></button>`).join('');
    }

    function renderRtLegend() {
        const box = document.getElementById('rtMxLegend');
        if (!box) return;
        if (!_rtLoaded.length) { box.innerHTML = ''; return; }
        box.innerHTML = `<span><span class="rt-mark hole" aria-hidden="true"></span>${escapeHtml(tr('rtLegendHole'))}</span>
            <span><span class="rt-legend-cover">${escapeHtml(tr('rtMxCoveredBy', { net: '0.0.0.0/0' }))}</span>${
                escapeHtml(tr('rtLegendCover'))}</span>
            <span><span class="rt-mark unknown" aria-hidden="true"></span>${escapeHtml(tr('rtLegendUnknown'))}</span>
            <span><span class="rt-legend-win"></span>${escapeHtml(tr('rtLegendWin'))}</span>`;
    }


    // --- ANALISI DI PERCORSO -------------------------------------------------
    //
    // Le rotte raccolte rispondono anche alla domanda successiva: dove finisce
    // un indirizzo, e perche' su ogni apparato ha vinto quella riga. Il calcolo
    // sta nel backend (/api/routes/trace) e gira sugli apparati SELEZIONATI: la
    // vista non allarga la selezione da sola.

    let _trace = null;
    let _traceTimer = null;
    // Due analisi lanciate a distanza di un istante (clic e poi Invio): vale
    // quella chiesta per ultima, non quella che risponde per ultima.
    let _traceSeq = 0;

    // I tre criteri, nell'ordine in cui un apparato li guarda. Le etichette
    // sono chiamate letterali: tr() con una chiave costruita a runtime
    // sfugge al controllo di copertura del dizionario.
    const rtRules = () => [
        { key: 'prefisso', label: tr('rtRulePrefix') },
        { key: 'distanza', label: tr('rtRuleDistance') },
        { key: 'metrica', label: tr('rtRuleMetric') },
    ];

    const RT_VERDICTS = {
        'consegna': 'ok',
        'fuori inventario': 'muted',
        'nessuna rotta': 'bad',
        'anello': 'bad',
        'biforcazione': 'warn',
        'non interrogato': 'warn',
        'limite salti': 'warn',
    };

    const RT_END = {
        'consegna': { label: 'rtTraceEndDelivery', color: 'var(--lamp-up-ink)' },
        'fuori inventario': { label: 'rtTraceEndOutside', color: 'var(--text-muted)' },
        'nessuna rotta': { label: 'rtTraceEndDropped', color: 'var(--lamp-fault-ink)' },
        'anello': { label: 'rtTraceEndLoop', color: 'var(--lamp-fault-ink)' },
        'biforcazione': { label: 'rtTraceEndFork', color: 'var(--lamp-warn-ink)' },
        'non interrogato': { label: 'rtTraceEndUnknown', color: 'var(--lamp-warn-ink)' },
        'limite salti': { label: 'rtTraceEndHopLimit', color: 'var(--lamp-warn-ink)' },
    };

    function rtTraceSyncSources() {
        // Si parte da uno degli apparati scelti: partire da uno non
        // selezionato sarebbe una richiesta a sorpresa, ed e' un 404 lato API.
        const sel = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        if (!sel) return;
        const current = sel.value;
        const chosen = pickerSelected('rtDeviceFilter');
        sel.innerHTML = chosen.length
            ? chosen.map(d => `<option value="${escapeHtml(d.value)}">${
                  escapeHtml(d.label)}</option>`).join('')
            : `<option value="">${escapeHtml(tr('rtTraceNoDevices'))}</option>`;
        if (chosen.some(d => d.value === current)) sel.value = current;
    }

    function rtTraceVerdict(kind, text) {
        const box = document.getElementById('rtTraceVerdict');
        if (!box) return;
        box.className = 'badge rt-verdict on ' + kind;
        box.textContent = text;
    }

    function rtTraceOutcomeText(data) {
        const n = (data.hops || []).length;
        switch (data.outcome) {
            case 'consegna': return tr('rtTraceDelivered', { n: n });
            case 'fuori inventario': return tr('rtTraceOutside', { hop: data.exit_hop || '?' });
            case 'nessuna rotta': return tr('rtTraceNoRoute');
            case 'anello': return tr('rtTraceLoop');
            case 'biforcazione': return tr('rtTraceFork');
            case 'non interrogato': return tr('rtTraceNotQueried', { ip: data.device_ip || '?' });
            case 'limite salti': return tr('rtTraceHopLimit', { n: n });
            default: return data.outcome || '';
        }
    }

    async function loadRtTrace() {
        const src = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        const dst = /** @type {HTMLInputElement|null} */ (
            document.getElementById('rtTraceDst'));
        if (!src || !dst) return;
        clearInterval(_traceTimer);
        const mine = ++_traceSeq;
        const devices = rtSelectedDevices().join(',');
        if (!devices || !src.value) { rtTraceVerdict('muted', tr('rtPickDevices')); return; }
        if (!dst.value.trim()) { rtTraceVerdict('muted', tr('rtTraceNeedDst')); return; }

        rtTraceVerdict('muted', tr('rtTraceRunning'));
        const url = `/api/routes/trace?device=${encodeURIComponent(devices)}`
            + `&src=${encodeURIComponent(src.value)}&dst=${encodeURIComponent(dst.value.trim())}`;
        try {
            const res = await apiFetch(url);
            if (!res || mine !== _traceSeq) return;
            const data = await res.json();
            if (mine !== _traceSeq) return;
            if (!res.ok) {
                _trace = null;
                renderRtTrace();
                rtTraceVerdict('bad', data.detail || ('HTTP ' + res.status));
                return;
            }
            _trace = data;
        } catch (e) {
            _trace = null;
            renderRtTrace();
            rtTraceVerdict('bad', String(e));
            return;
        }
        renderRtTrace();
        rtTracePlay();
    }

    function renderRtTrace() {
        const rail = document.getElementById('rtTraceRail');
        const steps = document.getElementById('rtTraceSteps');
        const play = document.getElementById('btnRtTracePlay');
        const probe = document.getElementById('rtProbeBox');
        if (!rail || !steps) return;
        if (!_trace || !(_trace.hops || []).length) {
            rail.style.display = 'none';
            rail.innerHTML = '';
            // Non un vuoto: la vista dice cosa le serve per rispondere.
            steps.innerHTML = `<p class="rt-idle">${escapeHtml(tr('rtTraceIdle'))}</p>`;
            if (play) play.style.display = 'none';
            if (probe) probe.style.display = 'none';
            return;
        }
        rtTraceVerdict(RT_VERDICTS[_trace.outcome] || 'muted',
                       tr((RT_END[_trace.outcome] || RT_END['non interrogato']).label));
        rail.style.display = '';
        rail.innerHTML = rtRailHtml(_trace);
        steps.innerHTML = rtStepsHtml(_trace);
        if (play) play.style.display = '';
        // Il traceroute manda pacchetti: e' un'azione, non una lettura, e a un
        // viewer non viene nemmeno offerta.
        if (probe) probe.style.display = (currentRole === 'viewer') ? 'none' : '';
        const out = document.getElementById('rtProbeOut');
        if (out) { out.style.display = 'none'; out.innerHTML = ''; }
    }

    // La catena in HTML e non in SVG: i riquadri si dimensionano sul contenuto,
    // quindi un hostname lungo non finisce sopra il suo IP e la striscia non
    // viene rimpicciolita per stare in larghezza — su schermo stretto va a capo.
    function rtRailHtml(data) {
        const hops = data.hops || [];
        const end = RT_END[data.outcome] || RT_END['non interrogato'];
        const items = hops.map((hop, i) => {
            const win = hop.best;
            const role = i === 0 ? tr('rtTraceStart') : tr('rtTraceHopN', { n: i });
            const flag = hop.from_backup
                ? `<span class="rt-node-flag">${escapeHtml(tr('rtFromBackup'))}</span>` : '';
            const meta = win
                ? (win.gateway ? tr('rtTraceVia', { hop: win.gateway }) + '  ·  ad ' + win.ad
                               : tr('rtTraceOnIface', { iface: win.interface || '?' }))
                : '';
            const link = win ? `
                <div class="rt-link">
                  <span class="rt-link-net"><b class="rt-kind" style="background:${
                      rtTypeColor(win.type)}">${escapeHtml(
                          (win.type || '?').slice(0, 1).toUpperCase())}</b>${
                      escapeHtml(win.network || '')}</span>
                  <span class="rt-link-line"></span>
                  <span class="rt-link-meta">${escapeHtml(meta)}</span>
                </div>` : '';
            return `<li class="rt-hop" data-hop="${i}">
                <div class="rt-node">
                  <span class="rt-node-role">${escapeHtml(role)}</span>
                  <span class="rt-node-name">${escapeHtml(hop.device || '')}</span>
                  <span class="rt-node-ip">${escapeHtml(hop.device_ip || '')}</span>
                  ${flag}
                </div>${link}
              </li>`;
        }).join('');
        // Il riquadro d'esito chiude la catena: e' l'unico che porta il colore
        // dello stato, perche' in questo sistema il colore vuol dire stato.
        const tail = `<li class="rt-hop rt-hop-end" data-hop="${hops.length}">
            <div class="rt-node rt-node-end" style="--rt-end:${end.color}">
              <span class="rt-node-role">${escapeHtml(tr('rtTraceEnd'))}</span>
              <span class="rt-node-name">${escapeHtml(tr(end.label))}</span>
              <span class="rt-node-ip">${escapeHtml(rtTraceEndDetail(data))}</span>
            </div>
          </li>`;
        return `<ol class="rt-chain" aria-label="${
            escapeHtml(rtTraceOutcomeText(data))}">${items}${tail}</ol>`;
    }

    /** Il dettaglio sotto l'esito: l'indirizzo che chiude il percorso. */
    function rtTraceEndDetail(data) {
        if (data.outcome === 'consegna') return data.dst || '';
        if (data.outcome === 'fuori inventario') return data.exit_hop || '';
        if (data.outcome === 'non interrogato') return data.device_ip || '';
        return '';
    }

    function rtStepsHtml(data) {
        return (data.hops || []).map((hop, i) => {
            const cand = hop.candidates || [];
            const tiedCount = (hop.tied || []).length;
            const rows = cand.map((r, j) => {
                const color = rtTypeColor(r.type);
                const win = tiedCount ? j < tiedCount : j === 0;
                return `<tr class="${win ? 'won' : 'lost'}">
                    <td class="rt-lead"><b class="rt-kind" style="background:${color}">${
                        escapeHtml((r.type || '?').slice(0, 1).toUpperCase())}</b>${escapeHtml(r.network || '')}</td>
                    <td>${r.gateway ? escapeHtml(tr('rtTraceVia', { hop: r.gateway }))
                                    : escapeHtml(tr('rtTraceOnIface', { iface: r.interface || '?' }))}</td>
                    <td class="rt-num">/${escapeHtml(String(r.prefixlen))}</td>
                    <td class="rt-num">${escapeHtml(String(r.ad))}</td>
                    <td class="rt-num">${escapeHtml(String(r.metric || 0))}</td>
                    <td class="rt-num"><span class="rt-outcome${win ? ' win' : ''}">${
                        escapeHtml(win ? tr('rtTraceWins') : tr('rtTraceDropped'))}</span></td>
                  </tr>`;
            }).join('');
            let decided = false;
            const rules = rtRules().map(rule => {
                const hit = hop.decided_by === rule.key;
                const cls = hit ? 'hit' : (decided ? 'moot' : '');
                if (hit) decided = true;
                return `<span class="rt-rule-step ${cls}">${escapeHtml(rule.label)}</span>`;
            }).join('');
            let say = tr('rtWhyOnly');
            if (cand.length >= 2) {
                if (hop.decided_by === 'prefisso') say = tr('rtWhyPrefix', { len: cand[0].prefixlen });
                else if (hop.decided_by === 'distanza') say = tr('rtWhyDistance');
                else if (hop.decided_by === 'ecmp') say = tr('rtWhyEcmp');
                else say = tr('rtWhyMetric');
            }
            const backup = hop.from_backup
                ? ` <span style="color:var(--warning);">${escapeHtml(tr('rtWhyBackup'))}</span>` : '';
            const table = cand.length
                ? `<table class="rt-cand">
                    <thead><tr>
                      <th data-no-sort="1">${escapeHtml(tr('rtColNetwork'))}</th>
                      <th data-no-sort="1">${escapeHtml(tr('rtColNextHop'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColPrefix'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColAd'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtColMetric'))}</th>
                      <th class="rt-num" data-no-sort="1">${escapeHtml(tr('rtTraceColOutcome'))}</th>
                    </tr></thead><tbody>${rows}</tbody></table>
                    <div class="rt-rule">${rules}</div>`
                : `<span class="rt-step-empty">${
                      escapeHtml(tr('rtTraceNoRoute'))}</span>`;
            return `<div class="rt-step pending" data-step="${i}">
                <div class="rt-step-gutter"><span class="rt-step-n">${i + 1}</span></div>
                <div class="rt-step-body">
                  <div class="rt-step-head">
                    <span class="rt-step-dev">${escapeHtml(hop.device || '')}</span>
                    <span class="rt-step-ip">${escapeHtml(hop.device_ip || '')}</span>
                    ${hop.from_backup
                        ? `<span class="badge rt-badge-backup">${escapeHtml(tr('rtFromBackup'))}</span>`
                        : ''}
                  </div>
                  <p class="rt-step-say">${escapeHtml(say)}${backup}</p>
                  ${table}
                </div>
              </div>`;
        }).join('');
    }

    /** Rivelazione dei salti, uno alla volta: il tempo dell'animazione e' il
     *  tempo della spiegazione. Con prefers-reduced-motion si mostra tutto. */
    function rtTracePlay() {
        clearInterval(_traceTimer);
        const steps = [...document.querySelectorAll('#rtTraceSteps .rt-step')];
        const rail = document.getElementById('rtTraceRail');
        if (!steps.length || !rail) return;
        const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        const show = n => {
            steps.forEach((el, i) => {
                el.classList.toggle('pending', i >= n);
                el.classList.toggle('decided', i < n);
            });
            // Il salto i e il tratto che ne esce si accendono insieme: il
            // riquadro d'esito e' l'ultimo elemento della catena.
            rail.querySelectorAll('.rt-hop').forEach((hop, i) => {
                hop.classList.toggle('on', i < n);
            });
            // L'esito e' l'ultimo riquadro della catena e sta oltre l'ultimo
            // salto: si accende quando i salti sono finiti, non un giro dopo.
            rail.querySelector('.rt-hop-end')?.classList.toggle('on', n >= steps.length);
        };
        if (reduced) { show(steps.length); return; }
        show(0);
        let n = 0;
        _traceTimer = setInterval(() => {
            n += 1;
            show(n);
            if (n >= steps.length) clearInterval(_traceTimer);
        }, 700);
    }

    async function runRtProbe() {
        const src = /** @type {HTMLSelectElement|null} */ (
            document.getElementById('rtTraceSrc'));
        const dst = /** @type {HTMLInputElement|null} */ (
            document.getElementById('rtTraceDst'));
        const out = document.getElementById('rtProbeOut');
        if (!src || !dst || !out) return;
        out.style.display = '';
        out.textContent = tr('rtProbeRunning');
        let data = null;
        try {
            const res = await apiFetch('/api/routes/trace/probe', {
                method: 'POST',
                body: JSON.stringify({ device_ip: src.value, dst: dst.value.trim() }),
            });
            if (!res) return;
            data = await res.json();
            if (!res.ok) {
                out.innerHTML = `<span class="rt-ink-bad">${
                    escapeHtml(data.detail || ('HTTP ' + res.status))}</span>`;
                return;
            }
        } catch (e) {
            out.innerHTML = `<span class="rt-ink-bad">${escapeHtml(String(e))}</span>`;
            return;
        }
        if (data.error) {
            out.innerHTML = `<span class="rt-ink-bad">${escapeHtml(data.error)}</span>`;
            return;
        }
        // Confronto fra atteso e visto: un next-hop che non risponde non e' un
        // guasto (puo' non rispondere a ICMP), e' il punto da cui guardare.
        const expected = ((_trace && _trace.hops) || [])
            .map(h => h.best && h.best.gateway).filter(Boolean);
        const seen = (data.hops || []).map(h => h.ip).filter(Boolean);
        const missing = expected.filter(ip => seen.indexOf(ip) === -1);
        const line = missing.length
            ? `<span class="rt-ink-warn">${escapeHtml(
                  tr('rtProbeMissing', { hops: missing.join(', ') }))}</span>`
            : `<span class="rt-ink-ok">${escapeHtml(tr('rtProbeMatch'))}</span>`;
        const path = (data.hops || []).map(h => h.ip || '*').join(' -> ') || '-';
        out.innerHTML = `<div>${escapeHtml(tr('rtProbeSeen', { hops: path }))}</div>
          <div style="margin-top:6px;">${line}</div>
          <pre>${escapeHtml(data.output || '')}</pre>`;
    }

    document.getElementById('btnRtTrace')?.addEventListener('click', loadRtTrace);
    document.getElementById('btnRtTracePlay')?.addEventListener('click', rtTracePlay);
    document.getElementById('btnRtProbe')?.addEventListener('click', runRtProbe);
    document.getElementById('rtDeviceFilter')?.addEventListener('picker-change', rtTraceSyncSources);
    document.getElementById('rtTraceDst')?.addEventListener('keydown', e => {
        if (/** @type {KeyboardEvent} */ (e).key === 'Enter') loadRtTrace();
    });

    // Search re-renders what is already loaded. An address also becomes the
    // path analysis destination: the next question after "who routes it" is
    // "and where does it end up".
    let _rtSearchTimer = null;
    document.getElementById('rtSearch')?.addEventListener('input', () => {
        clearTimeout(_rtSearchTimer);
        _rtSearchTimer = setTimeout(() => {
            const q = rtQuery(rtSearchValue());
            const dst = /** @type {HTMLInputElement|null} */ (document.getElementById('rtTraceDst'));
            if (q.kind === 'ip' && dst) dst.value = q.text;
            renderRtMatrix();
        }, 150);
    });
    document.getElementById('btnRtDiffOnly')?.addEventListener('click', e => {
        _rtDiffOnly = !_rtDiffOnly;
        /** @type {HTMLElement} */ (e.currentTarget).setAttribute('aria-pressed', String(_rtDiffOnly));
        renderRtMatrix();
    });
    document.getElementById('rtTypeChips')?.addEventListener('click', e => {
        const chip = /** @type {HTMLElement} */ (e.target).closest('[data-action="rt-type"]');
        if (!chip) return;
        const t = chip.getAttribute('data-type') || '';
        if (_rtTypes.has(t)) _rtTypes.delete(t); else _rtTypes.add(t);
        renderRtMatrix();
        /** @type {HTMLElement|null} */ (document.querySelector(
            `#rtTypeChips [data-type="${CSS.escape(t)}"]`))?.focus();
    });
    // Rings: a type is the same filter as its chip; an interface is its own,
    // exact (a search for "port1" would also match port10).
    document.getElementById('rtRings')?.addEventListener('click', e => {
        const el = /** @type {Element} */ (e.target).closest('[data-action^="rt-ring-"]');
        if (!el) return;
        const t = el.getAttribute('data-type');
        if (t !== null) { if (_rtTypes.has(t)) _rtTypes.delete(t); else _rtTypes.add(t); }
        const i = el.getAttribute('data-iface');
        if (i) _rtIface = _rtIface === i ? '' : i;
        renderRtMatrix();
    });
    // Collapsed by default: drawn at its real width once opened.
    document.getElementById('rtSkPanel')?.addEventListener('toggle', e => {
        if (/** @type {HTMLDetailsElement} */ (e.currentTarget).open) renderRtSankey(rtVisible(rtQuery(rtSearchValue())));
    });
    // Sankey: its own type switches (the table keeps its chips), and the
    // routes behind a node or ribbon on double click / Enter.
    document.getElementById('rtSkTypes')?.addEventListener('click', e => {
        const chip = /** @type {HTMLElement} */ (e.target).closest('[data-action="rt-sk-type"]');
        if (!chip) return;
        const t = chip.getAttribute('data-type') || '';
        if (_skHidden.has(t)) _skHidden.delete(t); else _skHidden.add(t);
        renderRtSankey(rtVisible(rtQuery(rtSearchValue())));
        /** @type {HTMLElement|null} */ (document.querySelector(
            `#rtSkTypes [data-type="${CSS.escape(t)}"]`))?.focus();
    });
    const skTarget = e => /** @type {Element} */ (e.target).closest('[data-sk]');
    // Hovering (or focusing) a node keeps its own ribbons lit and dims the
    // rest: with a dozen hops the eye cannot follow one flow otherwise.
    const skFocus = e => {
        const svg = document.querySelector('#rtSankey svg');
        const el = skTarget(e);
        if (!svg) return;
        svg.querySelectorAll('.rt-sk-hl').forEach(p => p.classList.remove('rt-sk-hl'));
        const key = el ? el.getAttribute('data-sk') || '' : '';
        svg.classList.toggle('rt-sk-focus', key.startsWith('n|'));
        if (!key.startsWith('n|')) return;
        const id = key.slice(2);
        svg.querySelectorAll('.rt-sk-link').forEach(p => {
            if (p.getAttribute('data-s') === id || p.getAttribute('data-t') === id) p.classList.add('rt-sk-hl');
        });
    };
    document.getElementById('rtSankey')?.addEventListener('mouseover', skFocus);
    document.getElementById('rtSankey')?.addEventListener('focusin', skFocus);
    document.getElementById('rtSankey')?.addEventListener('mouseleave', skFocus);
    document.getElementById('rtSankey')?.addEventListener('dblclick', e => {
        const el = skTarget(e);
        if (el) rtSkSelect(el.getAttribute('data-sk') || '');
    });
    document.getElementById('rtSankey')?.addEventListener('keydown', e => {
        const el = skTarget(e);
        if (!el || (e.key !== 'Enter' && e.key !== ' ')) return;
        e.preventDefault();
        rtSkSelect(el.getAttribute('data-sk') || '');
    });
    document.getElementById('rtSkDetail')?.addEventListener('click', e => {
        if (!/** @type {Element} */ (e.target).closest('[data-action="rt-sk-close"]')) return;
        _skSel = '';
        document.querySelectorAll('#rtSankey .rt-sk-on').forEach(el => el.classList.remove('rt-sk-on'));
        renderRtSkDetail();
    });
    document.getElementById('rtMxBody')?.addEventListener('click', e => {
        const btn = /** @type {HTMLElement} */ (e.target).closest('[data-action="rt-mx-toggle"]');
        if (!btn) return;
        const key = btn.getAttribute('data-key') || '';
        if (_rtOpen.has(key)) _rtOpen.delete(key); else _rtOpen.add(key);
        renderRtMatrix();
        /** @type {HTMLElement|null} */ (document.querySelector(
            `#rtMxBody [data-key="${CSS.escape(key)}"]`))?.focus();
    });
    // La selezione non fa partire da sola la query: si sceglie e si preme
    // Leggi tabelle. Ogni apparato in piu' e' una sessione in piu' aperta.
    document.getElementById('btnRtRefresh')?.addEventListener('click', loadRoutesTab);

    // Cambiare tenant svuota la selezione: gli apparati scelti prima possono
    // non essere piu' in scope, e le righe gia' a schermo sarebbero di un
    // altro cliente.
    document.getElementById('rtLookup')?.addEventListener('click', e => {
        const btn = /** @type {HTMLElement|null} */ (/** @type {HTMLElement} */ (e.target).closest('[data-action="rt-lk-toggle"]'));
        if (!btn) return;
        const dev = btn.dataset.dev || '';
        if (_rtLkOpen.has(dev)) _rtLkOpen.delete(dev); else _rtLkOpen.add(dev);
        renderRtLookup(rtQuery(rtSearchValue()));
        /** @type {HTMLElement|null} */ (document.querySelector(
            `#rtLookup [data-dev="${CSS.escape(dev)}"]`))?.focus();
    });

    window.addEventListener('globalTenantChanged', () => {
        _rtLkOpen.clear(); _rtUnknown = new Set();
        _rtRows = []; _rtErrors = []; _rtLoaded = []; _rtMatrix = []; _rtContext = {};
        _rtOpen.clear();
        _rtIface = '';
        routesTabShown();
    });

    window.loadRoutesTab = routesTabShown;
    // The pure model, for tests/js/test_routes_matrix.mjs.
    window.rtModel = { ip4, parseNet, rtLpm, rtLookup, rtBuildMatrix, rtQuery, rtMatches,
                       rtBuildSankey, rtDeviceOwners, rtDeviceDepths, rtHopResolver,
                       rtPolicyRows, rtPolicyMatches, rtIfaceName, rtRingData, rtMonitorRows };
})();
