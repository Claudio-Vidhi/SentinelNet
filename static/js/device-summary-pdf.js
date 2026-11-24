// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// ===== Device PDF summary (Config Analyzer) =====
// One firewall or core switch on a few printable pages, built from the same
// /api/config-analyzer/{ip} object the tab shows. The document is fully
// self-contained (inline CSS and SVG, no script, no URL): the print endpoint
// blocks all DNS, and the preview iframe is the PDF.

// Zone-to-zone matrix of FortiOS policies. A policy listing several
// interfaces counts once under every src|dst pair; `any` stays its own
// row/column; a disabled policy passes no traffic and is not counted.
function zoneMatrix(policies) {
    const rows = new Set(), cols = new Set(), cells = {};
    for (const p of policies || []) {
        if (p.status === 'disable') continue;
        const kind = p.action === 'accept' ? 'accept' : 'deny';
        for (const s of p.srcintf || []) {
            for (const d of p.dstintf || []) {
                rows.add(s); cols.add(d);
                const c = cells[s + '|' + d] || (cells[s + '|' + d] = { accept: 0, deny: 0 });
                c[kind] += 1;
            }
        }
    }
    return { rows: [...rows].sort(), cols: [...cols].sort(), cells };
}

// headers: labels (already translated); rows: arrays of cell HTML (already escaped).
function dsTable(headers, rows) {
    if (!rows.length) return `<p class="none">${escapeHtml(tr('dsNone'))}</p>`;
    return `<table><thead><tr>${headers.map(h => `<th>${escapeHtml(h)}</th>`).join('')}</tr></thead>
        <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

// A long table starts on a fresh page rather than leaving its header orphaned.
function dsSection(titleKey, count, body) {
    const big = count > 20 ? ' class="big"' : '';
    return `<section${big}><h2>${escapeHtml(tr(titleKey))} <span class="n">${escapeHtml(count)}</span></h2>${body}</section>`;
}

// Same ring as routes-view.js rtRingSvg (that module is lazy for another tab),
// without the click targets: paper has nothing to click.
function dsRingSvg(segs, total) {
    const R = 42, C = 2 * Math.PI * R;
    let off = 0;
    const arcs = segs.map(sg => {
        const len = C * sg.n / total;
        const arc = `<circle cx="60" cy="60" r="${R}" fill="none" stroke-width="16" stroke="${sg.color}"
            stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}"></circle>`;
        off += len;
        return arc;
    }).join('');
    return `<svg class="ring" viewBox="0 0 120 120" role="img" aria-label="${escapeHtml(tr('dsRingTitle'))}">
        <g transform="rotate(-90 60 60)">${arcs}</g>
        <text x="60" y="58" class="ring-total">${escapeHtml(total)}</text>
        <text x="60" y="78" class="ring-sub">${escapeHtml(tr('rtRingTotal'))}</text></svg>`;
}

// Static routes by exit interface (FortiOS `device`; IOS has only a next hop).
// Colours are the four DESIGN.md conductors. ponytail: past 4 slices the
// smallest fold into one "N more"; the table below still lists every route.
function dsRouteRing(routes) {
    const COLORS = ['#1f6fb2', '#b8791a', '#2e8b57', '#6b4423'];
    const by = {};
    for (const r of routes) {
        const k = r.blackhole ? 'blackhole' : (r.device || r.next_hop || '—');
        by[k] = (by[k] || 0) + 1;
    }
    let segs = Object.entries(by).sort((a, b) => b[1] - a[1]).map(([label, n], i) => ({ label, n, color: COLORS[i % COLORS.length] }));
    if (segs.length > 4) {
        const rest = segs.slice(3);
        segs = segs.slice(0, 3).concat({ label: tr('rtRingOthers', { n: rest.length }), n: rest.reduce((s, x) => s + x.n, 0), color: '#525860' });
    }
    return `<div class="ring-block">${dsRingSvg(segs, routes.length)}<div class="legend"><h3>${escapeHtml(tr('dsRingTitle'))}</h3>${
        segs.map(sg => `<div><span class="dot" style="background:${sg.color}"></span>${escapeHtml(sg.label)} <b>${escapeHtml(sg.n)}</b></div>`).join('')}</div></div>`;
}

function dsMatrixTable(policies) {
    const m = zoneMatrix(policies);
    if (!m.rows.length) return `<p class="none">${escapeHtml(tr('dsNone'))}</p>`;
    const head = `<tr><th class="corner">${escapeHtml(tr('dsColSrc'))} \\ ${escapeHtml(tr('dsColDst'))}</th>${m.cols.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr>`;
    const body = m.rows.map(r => `<tr><th>${escapeHtml(r)}</th>${m.cols.map(c => {
        const x = m.cells[r + '|' + c];
        if (!x) return '<td class="empty"></td>';
        // Geometry as well as hue: a filled lens accepts, a hollow one denies.
        const cls = x.accept && x.deny ? 'mixed' : x.accept ? 'acc' : 'den';
        return `<td class="${cls}">${x.accept ? `<span class="a">● ${x.accept}</span>` : ''}${x.deny ? `<span class="d">○ ${x.deny}</span>` : ''}</td>`;
    }).join('')}</tr>`).join('');
    return `<p class="hint">${escapeHtml(tr('dsMatrixHint'))}</p><table class="matrix"><thead>${head}</thead><tbody>${body}</tbody></table>`;
}

function dsItemText(x) {
    if (x == null || typeof x !== 'object') return String(x ?? '—');
    const name = x.name || x.vlan || x.context || x.id || '';
    const extra = x.referenced_in || x.acl || (Array.isArray(x.allowaccess) ? x.allowaccess.join(', ') : '');
    return extra ? `${name} — ${extra}` : String(name);
}

function dsFindings(validation, lang) {
    // IOS validation keys carry their own titles; FortiOS ones live in config-analyzer.js.
    const IOS_KEYS = { unused_acls: 'titleCaUnusedAcls', missing_acls: 'titleCaMissingAcls', unused_vlans: 'titleCaUnusedVlans',
        undefined_vlans: 'titleCaUndefinedVlans', route_acl_refs: 'titleCaRouteAclRefs' };
    const v = validation || {};
    const rows = [];
    for (const f of v.policy_findings || []) {
        rows.push([`<span class="sev sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>`, escapeHtml(caDefectLine(f, i18n[currentLang] || i18n.it))]);
    }
    for (const [key, val] of Object.entries(v)) {
        if (key === 'policy_findings') continue;
        const label = IOS_KEYS[key] ? tr(IOS_KEYS[key]) : (caMvValLabels[key] ? caMvValLabels[key][lang] : key);
        if (val === true) rows.push(['<span class="sev sev-high">!</span>', escapeHtml(label)]);
        else if (Array.isArray(val) && val.length) rows.push([`<span class="sev sev-medium">${escapeHtml(val.length)}</span>`, `<b>${escapeHtml(label)}</b>: ${escapeHtml(val.map(dsItemText).join(', '))}`]);
    }
    return { count: rows.length, html: dsTable([tr('dsColSeverity'), tr('dsColFinding')], rows) };
}

function dsCss() {
    return `
@page { size: A4; margin: 14mm 12mm; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; padding: 18px; background: #ffffff; color: #16191c; font: 11px/1.45 "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
header { border-bottom: 2px solid #16191c; padding-bottom: 10px; margin-bottom: 14px; }
header .kicker, h2, th { font-family: "Arial Narrow", "Segoe UI", Arial, sans-serif; text-transform: uppercase; letter-spacing: .06em; }
header .kicker { font-size: 10px; color: #4a5058; }
h1 { margin: 2px 0 8px; font-size: 25px; font-weight: 600; }
.meta { display: flex; flex-wrap: wrap; gap: 4px 22px; color: #4a5058; }
.meta b { color: #16191c; font-family: Consolas, "Cascadia Mono", monospace; font-weight: 500; }
section { margin: 0 0 16px; }
section.big { break-before: page; }
h2 { font-size: 13px; margin: 0 0 6px; padding: 5px 8px; background: #e6e7e1; border-left: 3px solid #16191c; break-after: avoid; }
h2 .n { float: right; font-family: Consolas, monospace; color: #4a5058; }
h3 { font-size: 11px; margin: 0 0 4px; text-transform: uppercase; letter-spacing: .06em; color: #4a5058; }
table { width: 100%; border-collapse: collapse; font-size: 10px; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
th { text-align: left; font-size: 9px; font-weight: 600; color: #4a5058; background: #d4d7cf; padding: 4px 6px; border: 1px solid #a8ada4; }
td { padding: 3px 6px; border: 1px solid #a8ada4; vertical-align: top; font-family: Consolas, "Cascadia Mono", monospace; word-break: break-word; }
.none, .hint { color: #525860; margin: 2px 0 6px; }
.matrix { width: auto; }
.matrix th, .matrix td { text-align: center; min-width: 52px; }
.matrix tbody th { text-align: right; }
.matrix th:not(.corner) { text-transform: none; letter-spacing: 0; font-family: Consolas, "Cascadia Mono", monospace; }
.matrix td.empty { background: #ffffff; }
.matrix td.acc { background: rgba(47, 149, 78, 0.14); }
.matrix td.den { background: rgba(192, 57, 43, 0.13); }
.matrix td.mixed { background: rgba(184, 121, 26, 0.15); }
.matrix .a { color: #1e6b3c; font-weight: 700; display: block; }
.matrix .d { color: #9d2b20; font-weight: 700; display: block; }
.act-accept { color: #1e6b3c; font-weight: 700; }
.act-deny { color: #9d2b20; font-weight: 700; }
.ring-block { display: flex; gap: 16px; align-items: flex-start; margin-bottom: 8px; break-inside: avoid; }
.ring { width: 120px; height: 120px; flex: none; }
.ring-total { font: 700 21px Consolas, monospace; text-anchor: middle; dominant-baseline: middle; fill: #16191c; }
.ring-sub { font-size: 10px; text-anchor: middle; fill: #4a5058; }
.legend div { margin: 2px 0; font-family: Consolas, monospace; }
.dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
.sev { display: inline-block; min-width: 46px; padding: 1px 5px; text-align: center; font-family: "Arial Narrow", Arial, sans-serif; text-transform: uppercase; }
.sev-high { background: rgba(192, 57, 43, 0.13); color: #9d2b20; }
.sev-medium { background: rgba(184, 121, 26, 0.15); color: #8a5a0f; }
.sev-low, .sev-info { background: #e6e7e1; color: #4a5058; }
footer { margin-top: 18px; border-top: 1px solid #a8ada4; padding-top: 6px; color: #525860; font-size: 9px; }
`;
}

// Full printable document for one device. Every dynamic value is escaped:
// names, descriptions and comments come straight from a configuration file.
function deviceSummaryHtml(dev, lang) {
    const e = escapeHtml;
    const join = a => e((a || []).join(', ') || '—');
    const when = ts => ts ? new Date(ts * 1000).toLocaleString(lang) : '—';
    const fw = dev.config_type === 'fortios';
    const routes = (dev.routing && dev.routing.static) || [];
    const sections = [];

    if (fw) {
        const ifaces = dev.interfaces || [];
        sections.push(dsSection('dsSecInterfaces', ifaces.length, dsTable(
            [tr('dsColName'), tr('dsColIp'), tr('dsColRole'), tr('dsColVlan'), tr('dsColAccess'), tr('dsColStatus')],
            ifaces.map(i => [e(i.name), e(i.ip || '—'), e(i.role || '—'),
                e(i.vlanid ? `${i.vlanid} @ ${i.parent}` : '—'), join(i.allowaccess), e(i.status || '—')]))));
        const pols = dev.policies || [];
        sections.push(dsSection('dsSecMatrix', zoneMatrix(pols).rows.length, dsMatrixTable(pols)));
        sections.push(dsSection('dsSecPolicies', pols.length, dsTable(
            [tr('dsColId'), tr('dsColName'), tr('dsColIntf'), tr('dsColAddr'), tr('dsColService'), tr('dsColAction'), tr('dsColNat'), tr('dsColLog')],
            pols.map(p => [e(p.id), e(p.name || '—'), `${join(p.srcintf)} → ${join(p.dstintf)}`, `${join(p.srcaddr)} → ${join(p.dstaddr)}`,
                join(p.service), `<span class="act-${p.action === 'accept' ? 'accept' : 'deny'}">${e(p.action)}</span>${p.status === 'disable' ? ` (${e(tr('dsDisabled'))})` : ''}`,
                e(p.nat), e(p.logtraffic || '—')]))));
    } else {
        const vlans = dev.vlans || [];
        sections.push(dsSection('dsSecVlans', vlans.length, dsTable(
            [tr('dsColVlan'), tr('dsColName'), tr('dsColSvi'), tr('dsColAccessPorts'), tr('dsColTrunkPorts')],
            vlans.map(v => [e(v.id), e(v.name || '—'), e(v.svi ? (v.svi.ip || '—') + (v.svi.shutdown ? ' (shutdown)' : '') : '—'),
                e((v.access_ifaces || []).length), e((v.trunk_ifaces || []).length)]))));
    }

    sections.push(dsSection('dsSecRoutes', routes.length, (routes.length ? dsRouteRing(routes) : '') + dsTable(
        fw ? [tr('dsColPrefix'), tr('dsColNextHop'), tr('dsColIntf'), tr('dsColDistance'), tr('dsColStatus')]
           : [tr('dsColPrefix'), tr('dsColNextHop'), tr('dsColAd'), tr('dsColVrf'), tr('dsColName')],
        routes.map(r => fw
            ? [e(r.prefix), e(r.blackhole ? 'blackhole' : (r.next_hop || '—')), e(r.device || '—'), e(r.distance || '—'), e(r.status || '—')]
            : [e(r.prefix), e(r.next_hop || '—'), e(r.ad ?? '—'), e(r.vrf || '—'), e(r.name || '—')]))));

    if (fw) {
        const vips = dev.vips || [];
        sections.push(dsSection('dsSecVips', vips.length, dsTable(
            [tr('dsColName'), tr('dsColExtIp'), tr('dsColMappedIp'), tr('dsColIntf'), tr('dsColPorts')],
            vips.map(v => [e(v.name), e(v.extip || '—'), e(v.mappedip || '—'), e(v.extintf || '—'),
                e(v.extport ? `${v.extport} → ${v.mappedport || v.extport}` : '—')]))));
        const vpn = dev.vpn || {};
        const peers = vpn.peers || [];
        sections.push(dsSection('dsSecVpn', peers.length, dsTable(
            [tr('dsColName'), tr('dsColPeer')], peers.map(p => [e(p.name), e(p.remote_gw || '—')]))
            + ((vpn.phase2 || []).length ? `<p class="hint">${e(tr('dsColPhase2'))}: ${join(vpn.phase2)}</p>` : '')));
    } else {
        const acls = dev.acls || [];
        sections.push(dsSection('dsSecAcls', acls.length, dsTable(
            [tr('dsColName'), tr('dsColKind'), tr('dsColEntries'), tr('dsColApplied')],
            acls.map(a => [e(a.name), e(a.kind || '—'), e((a.entries || []).length),
                e((a.applied || []).map(x => `${x.where} ${x.target}${x.direction ? ' ' + x.direction : ''}`).join(', ') || '—')]))));
        const ifaces = dev.interfaces || [];
        sections.push(dsSection('dsSecInterfaces', ifaces.length, dsTable(
            [tr('dsColName'), tr('dsColMode'), tr('dsColVlan'), tr('dsColIp'), tr('dsColAcl'), tr('dsColDesc')],
            ifaces.map(i => [e(i.name) + (i.shutdown ? ' (shutdown)' : ''), e(i.mode || '—'),
                e(i.access_vlan || i.trunk_allowed || '—'), e(i.ip || '—'),
                e([i.acl_in && `${i.acl_in} in`, i.acl_out && `${i.acl_out} out`].filter(Boolean).join(', ') || '—'), e(i.description || '—')]))));
    }

    const f = dsFindings(dev.validation, lang);
    sections.push(dsSection('dsSecFindings', f.count, f.html));

    const meta = [[tr('dsMetaIp'), dev.ip], [tr('dsMetaType'), dev.config_type], [tr('dsMetaModel'), dev.model],
        [tr('dsMetaTenant'), dev.tenant], [tr('dsMetaBackup'), when(dev.backup_ts)]]
        .filter(([, v]) => v).map(([k, v]) => `<span>${e(k)}: <b>${e(v)}</b></span>`).join('');
    const title = `${tr('dsDocTitle')} — ${dev.hostname || dev.ip}`;
    return `<!doctype html>
<html lang="${e(lang)}"><head><meta charset="utf-8"><title>${e(title)}</title><style>${dsCss()}</style></head>
<body><header><div class="kicker">SentinelNet · ${e(tr(fw ? 'dsKindFirewall' : 'dsKindSwitch'))}</div>
<h1>${e(dev.hostname || dev.ip)}</h1><div class="meta">${meta}</div></header>
${sections.join('\n')}
<footer>${e(tr('dsGenerated'))}: ${e(new Date().toLocaleString(lang))} · ${e(tr('dsFooter'))}</footer></body></html>`;
}

// ---- Modal: preview, download ----
let dsCurrent = null; // { html, filename } of the open preview

async function openDeviceSummary(ip) {
    try {
        const res = await apiFetch('/api/config-analyzer/' + encodeURIComponent(ip));
        if (!res || !res.ok) throw new Error(String(res ? res.status : 'network'));
        const dev = await res.json();
        // The backup does not say which hardware it came from; the inventory does.
        dev.model = (globalDevices || []).find(d => d.IP === ip)?.Model || '';
        const html = deviceSummaryHtml(dev, currentLang);
        dsCurrent = { html, filename: 'summary-' + (dev.hostname || ip) };
        const frame = document.getElementById('devSummaryFrame');
        if (frame) frame.srcdoc = html;
        openModal('devSummaryModal');
    } catch (err) {
        showToast(tr('dsLoadFailed') + ' ' + (err.message || err), 'error');
    }
}
window.openDeviceSummary = openDeviceSummary;

async function downloadDeviceSummary() {
    if (!dsCurrent) return;
    const btn = document.getElementById('devSummaryBtnPdf');
    if (btn) btn.disabled = true;
    try {
        // Same printer as the compliance report (own route, scripts off): the PDF is the preview.
        const res = await apiFetch('/api/config-analyzer/summary/pdf', {
            method: 'POST', body: JSON.stringify(dsCurrent),
        });
        if (!res || !res.ok) {
            const detail = res ? ((await res.json().catch(() => ({}))).detail || res.status) : 'network';
            throw new Error(String(detail));
        }
        const url = URL.createObjectURL(await res.blob());
        const a = document.createElement('a');
        a.href = url;
        a.download = dsCurrent.filename + '.pdf';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(tr('nsaPdfDownloadedSuccessfully'), 'info');
    } catch (err) {
        showToast(tr('nsaFailedToGeneratePdf') + (err.message || err), 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

document.getElementById('devSummaryBtnPdf')?.addEventListener('click', downloadDeviceSummary);
document.getElementById('devSummaryBtnClose')?.addEventListener('click', () => closeModal('devSummaryModal'));
