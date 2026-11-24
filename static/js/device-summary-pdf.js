// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// ===== Device PDF summary (Config Analyzer) =====
// One firewall or core switch on a few printable pages, built from the same
// /api/config-analyzer/{ip} object the tab shows. The document is fully
// self-contained (inline CSS and SVG, fonts as data: URIs, no script, no URL):
// the print endpoint blocks all DNS, and the preview iframe is the PDF.
// It is read on screen far more often than on paper: sizes and spacing are
// set for a PDF viewer at 100%, the A4 page only gives the PDF its size.

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
        const arc = `<circle cx="60" cy="60" r="${R}" fill="none" stroke-width="16" style="stroke:${sg.color}"
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
// Colours are the four DESIGN.md conductors, as CSS variables. ponytail: past 4 slices the
// smallest fold into one "N more"; the table below still lists every route.
function dsRouteRing(routes) {
    const COLORS = ['var(--cond-a)', 'var(--cond-b)', 'var(--cond-c)', 'var(--cond-d)'];
    const by = {};
    for (const r of routes) {
        const k = r.blackhole ? 'blackhole' : (r.device || r.next_hop || '—');
        by[k] = (by[k] || 0) + 1;
    }
    let segs = Object.entries(by).sort((a, b) => b[1] - a[1]).map(([label, n], i) => ({ label, n, color: COLORS[i % COLORS.length] }));
    if (segs.length > 4) {
        const rest = segs.slice(3);
        segs = segs.slice(0, 3).concat({ label: tr('rtRingOthers', { n: rest.length }), n: rest.reduce((s, x) => s + x.n, 0), color: 'var(--lamp-idle)' });
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

// fonts: optional { saira, azeret } data: URIs (see dsFonts). Without them the
// document falls back to the stacks DESIGN.md names, and still prints.
function dsCss(fonts) {
    const f = fonts || {};
    const face = (family, weight, uri) => uri
        ? `@font-face { font-family: "${family}"; font-weight: ${weight}; font-style: normal; src: url("${uri}") format("woff2"); }\n` : '';
    return face('Saira Condensed', 600, f.saira) + face('Azeret Mono', '400 500', f.azeret) + `
/* DESIGN.md tokens on a light page. Every text colour clears 4.5:1 on white
   and on its wash: where a DESIGN.md lamp is too light for text, its -ink is
   a darker step of the same lamp's design.json tonal ramp. */
:root {
  --page: #ffffff;
  --surface-2: #f8fafc;
  --surface-3: #e2e8f0;
  --border: #cbd5e1;
  --border-strong: #94a3b8;
  --ink: #0f172a;
  --ink-muted: #475569;
  --ink-soft: #64748b;
  --cta: #2563eb;
  --lamp-up-ink: oklch(0.48 0.14 149);
  --lamp-warn-ink: oklch(0.50 0.13 68);
  --lamp-fault-ink: oklch(0.46 0.18 27);
  --lamp-idle-ink: oklch(0.48 0.015 240);
  --lamp-up-wash: rgba(16, 185, 129, 0.12);
  --lamp-warn-wash: rgba(245, 158, 11, 0.12);
  --lamp-fault-wash: rgba(239, 68, 68, 0.12);
  --lamp-idle-wash: rgba(100, 116, 139, 0.12);
  --lamp-idle: #64748b;
  --cond-a: #3b82f6;
  --cond-b: #f59e0b;
  --cond-c: #10b981;
  --cond-d: #a855f7;
  --font-legend: "Saira Condensed", "Arial Narrow", "Helvetica Neue", sans-serif;
  --font-prose: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --font-data: "Azeret Mono", ui-monospace, "Cascadia Mono", Consolas, monospace; }
@page { size: A4; margin: 12mm; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; padding: 22px 26px; background: var(--page); color: var(--ink); font: 10.5pt/1.5 var(--font-prose); }
@media print { body { padding: 0; } }
header { border-top: 4px solid var(--cta); padding: 14px 0 16px; margin-bottom: 22px; border-bottom: 1px solid var(--border); }
.kicker, h2, h3, th, .meta .k, .sev { font-family: var(--font-legend); font-weight: 600; text-transform: uppercase; letter-spacing: .06em; }
.kicker { font-size: 10pt; color: var(--cta); }
h1 { margin: 2px 0 12px; font: 600 26pt/1.1 var(--font-legend); letter-spacing: .01em; word-break: break-word; }
.meta { display: flex; flex-wrap: wrap; gap: 8px 32px; }
.meta > span { display: flex; flex-direction: column; }
.meta .k { font-size: 9pt; color: var(--ink-muted); }
.meta b { font: 500 10.5pt var(--font-data); }
section { margin: 0 0 26px; }
section.big { break-before: page; }
h2 { display: flex; align-items: baseline; gap: 10px; font-size: 15pt; margin: 0 0 10px; padding: 0 0 6px 12px;
     border-left: 4px solid var(--cta); border-bottom: 1px solid var(--border); break-after: avoid; }
h2 .n { margin-left: auto; font: 500 10pt var(--font-data); color: var(--ink-muted); background: var(--surface-3); padding: 1px 8px; border-radius: 2px; }
h3 { font-size: 11pt; margin: 0 0 8px; color: var(--ink-muted); }
table { width: 100%; border-collapse: collapse; font-size: 9.5pt; }
thead { display: table-header-group; }
tr { break-inside: avoid; }
th { text-align: left; font-size: 9pt; color: var(--ink-muted); background: var(--surface-3); padding: 7px 10px; border-bottom: 1px solid var(--border-strong); }
td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; font-family: var(--font-data); word-break: break-word; }
tbody tr:nth-child(even) td { background: var(--surface-2); }
.none, .hint { color: var(--ink-soft); margin: 2px 0 10px; }
.matrix { width: auto; margin: 4px 0; }
.matrix th, .matrix td { text-align: center; min-width: 76px; padding: 10px 12px; border: 1px solid var(--border); font-size: 10.5pt; }
.matrix tbody th { text-align: right; }
.matrix th:not(.corner) { text-transform: none; letter-spacing: 0; font: 500 10pt var(--font-data); color: var(--ink); }
.matrix .corner { font-size: 9pt; }
.matrix tbody tr td.empty { background: var(--page); }
.matrix tbody tr td.acc { background: var(--lamp-up-wash); }
.matrix tbody tr td.den { background: var(--lamp-fault-wash); }
.matrix tbody tr td.mixed { background: var(--lamp-warn-wash); }
.matrix .a { color: var(--lamp-up-ink); font-weight: 700; display: block; }
.matrix .d { color: var(--lamp-fault-ink); font-weight: 700; display: block; }
/* Geometry first: a filled lens accepts, a hollow one denies. */
.act-accept { color: var(--lamp-up-ink); font-weight: 700; }
.act-accept::before { content: "\\25CF  "; }
.act-deny { color: var(--lamp-fault-ink); font-weight: 700; }
.act-deny::before { content: "\\25CB  "; }
.ring-block { display: flex; gap: 28px; align-items: center; margin: 4px 0 16px; padding: 14px 18px; background: var(--surface-2); border: 1px solid var(--border); break-inside: avoid; }
.ring { width: 170px; height: 170px; flex: none; }
.ring-total { font: 500 22px var(--font-data); text-anchor: middle; dominant-baseline: middle; fill: var(--ink); }
.ring-sub { font: 600 9px var(--font-legend); text-transform: uppercase; letter-spacing: .06em; text-anchor: middle; fill: var(--ink-muted); }
.legend div { margin: 5px 0; font-family: var(--font-data); }
.dot { display: inline-block; width: 11px; height: 11px; border-radius: 50%; margin-right: 8px; vertical-align: -1px; }
.sev { display: inline-block; min-width: 58px; padding: 2px 8px; text-align: center; font-size: 9pt; border-radius: 2px; }
.sev-high { background: var(--lamp-fault-wash); color: var(--lamp-fault-ink); }
.sev-medium { background: var(--lamp-warn-wash); color: var(--lamp-warn-ink); }
.sev-low, .sev-info { background: var(--lamp-idle-wash); color: var(--lamp-idle-ink); }
footer { margin-top: 28px; border-top: 1px solid var(--border); padding-top: 8px; color: var(--ink-soft); font-size: 9pt; }
`;
}

// Full printable document for one device. Every dynamic value is escaped:
// names, descriptions and comments come straight from a configuration file.
function deviceSummaryHtml(dev, lang, fonts) {
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
        .filter(([, v]) => v).map(([k, v]) => `<span><span class="k">${e(k)}</span><b>${e(v)}</b></span>`).join('');
    const title = `${tr('dsDocTitle')} — ${dev.hostname || dev.ip}`;
    return `<!doctype html>
<html lang="${e(lang)}"><head><meta charset="utf-8"><title>${e(title)}</title><style>${dsCss(fonts)}</style></head>
<body><header><div class="kicker">SentinelNet · ${e(tr(fw ? 'dsKindFirewall' : 'dsKindSwitch'))}</div>
<h1>${e(dev.hostname || dev.ip)}</h1><div class="meta">${meta}</div></header>
${sections.join('\n')}
<footer>${e(tr('dsGenerated'))}: ${e(new Date().toLocaleString(lang))} · ${e(tr('dsFooter'))}</footer></body></html>`;
}

// ---- Modal: preview, download ----
let dsCurrent = null; // { html, filename } of the open preview
let dsFontsPromise = null; // fetched once per page load

// The app's own woff2 files as data: URIs, the only kind of font the print
// CSP admits. Only the faces the document uses: about 60 KB once encoded.
// A failed fetch leaves the fallback stacks rather than blocking the PDF.
function dsFonts() {
    const load = async name => {
        const res = await fetch('/static/fonts/' + name);
        if (!res.ok) throw new Error(String(res.status));
        const bytes = new Uint8Array(await res.arrayBuffer());
        let bin = '';
        for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        return 'data:font/woff2;base64,' + btoa(bin);
    };
    dsFontsPromise ??= Promise.all([load('saira-condensed-600.woff2'), load('azeret-mono-var.woff2')])
        .then(([saira, azeret]) => ({ saira, azeret }))
        .catch(() => { dsFontsPromise = null; return null; });
    return dsFontsPromise;
}

async function openDeviceSummary(ip) {
    try {
        const res = await apiFetch('/api/config-analyzer/' + encodeURIComponent(ip));
        if (!res || !res.ok) throw new Error(String(res ? res.status : 'network'));
        const dev = await res.json();
        // The backup does not say which hardware it came from; the inventory does.
        dev.model = (globalDevices || []).find(d => d.IP === ip)?.Model || '';
        const html = deviceSummaryHtml(dev, currentLang, await dsFonts());
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
