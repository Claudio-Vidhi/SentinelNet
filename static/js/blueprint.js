// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// static/js/blueprint.js
// ===== Network Blueprint (spec 2026-10-11 network-blueprint) =====
// The expected network of one organization, compared with the observed one.
// Every edit made here becomes a draft operation: nothing reaches the model
// until the draft is applied. The diagram mirrors the lists; it is not an
// editor.

(function () {
    let bpOrg = '';
    let bpState = null;       // GET /api/blueprint/{org}
    let bpFindings = [];      // GET /api/blueprint/{org}/checks
    let bpObservedAt = null;
    let bpNetwork = null;     // vis.Network of the diagram
    let bpLocSave = null;     // save callback of the open location modal
    let bpLinkSave = null;    // save callback of the open link modal
    let bpFindingsGroup = 'all';
    let bpFindingsSev = 'all'; // 'all' | 'error'
    let bpSelectedLocId = null;
    let bpLastObserve = null;

    const KIND_COLORS = { vpn: '--primary', wan: '--text-muted', mpls: '--warning', lan: '--success' };
    const SEV_RANK = { error: 0, warning: 1, unknown: 2, info: 3 };
    const SEV_COLORS = { error: '--danger', warning: '--warning', unknown: '--text-muted', info: '--primary' };
    const CODE_GROUP = {
        subnet_overlap: 'model', location_no_subnets: 'model', location_isolated: 'model',
        location_no_gateway: 'model', gateway_not_in_location: 'model',
        device_outside_subnets: 'subnets', arp_uncovered: 'subnets', subnet_unused: 'subnets',
        link_no_route: 'routing', route_without_link: 'routing',
        vpn_link_down: 'vpn', tunnel_without_link: 'vpn',
        purdue_dmz_bypass: 'purdue', purdue_layer_skip: 'purdue', purdue_subnet_overlap: 'purdue',
    };
    const EDITABLE = ['create_location', 'update_location', 'add_subnet', 'set_gateway', 'add_link'];

    const $ = (id) => document.getElementById(id);
    const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const api = (path) => `/api/blueprint/${encodeURIComponent(bpOrg)}${path}`;
    // Key = prefix + enum value from the API; every value has an entry in both
    // languages (the literal-key checker cannot see a computed key).
    const trEnum = (prefix, value) => tr(prefix + value);
    const roleLabel = (role) => trEnum('locRole_', role || 'other');

    async function errorText(res) {
        if (!res) return tr('uiError');
        const body = await res.json().catch(() => ({}));
        const d = body.detail;
        return (d && typeof d === 'object' ? d.message : d) || tr('uiError');
    }

    function send(path, method, body) {
        const opts = { method };
        if (body !== undefined) opts.body = JSON.stringify(body);
        return apiFetch(api(path), opts);
    }

    function draftOps() { return (bpState && bpState.draft && bpState.draft.ops) || []; }
    function model() { return bpState.preview || { locations: bpState.locations, links: bpState.links }; }
    function probeName(id) { const p = (bpState.probes || []).find((x) => x.id === id); return p ? p.name : id; }

    // Name of a location id, of a draft ref («+1»), or of a location only the draft has.
    function locName(id) {
        if (String(id).startsWith('+')) {
            const op = draftOps().find((o) => o.ref === id);
            return op ? op.name : id;
        }
        const l = bpState.locations[id] || model().locations[id];
        return l ? l.name : id;
    }

    // ---- loading -----------------------------------------------------------

    async function loadBlueprintTab() {
        const sel = $('bpOrgSelect');
        const orgs = Object.keys(globalGroups || {});
        sel.replaceChildren(...orgs.map((g) => new Option(orgLabel(g), g)));
        const wanted = window.bpPendingOrg;
        window.bpPendingOrg = null;
        // The sidebar tenant wins over the last one viewed here: picking it is
        // the user saying which organization they are working on.
        const g = window.globalSelectedTenant;
        const scoped = g && g !== 'all' && orgs.includes(g) ? g : '';
        bpOrg = wanted && orgs.includes(wanted) ? wanted
            : scoped || (orgs.includes(bpOrg) ? bpOrg : (orgs[0] || ''));
        sel.value = bpOrg;
        await reloadBlueprint();
    }
    window.loadBlueprintTab = loadBlueprintTab;
    // The draft lives on the server, so following the sidebar loses nothing.
    window.addEventListener('globalTenantChanged', () => {
        if (document.getElementById('tab-blueprint')?.classList.contains('active')) loadBlueprintTab();
    });

    async function reloadBlueprint() {
        if (!bpOrg) return;
        const res = await apiFetch(api(''));
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        bpState = await res.json();
        await runChecks();
    }

    async function runChecks() {
        const res = await apiFetch(api('/checks'));
        if (res && res.ok) {
            const body = await res.json();
            bpFindings = body.findings || [];
            bpObservedAt = body.observed_at;
        } else {
            bpFindings = [];
            showToast(await errorText(res), 'error');
        }
        render();
    }

    // ---- rendering ---------------------------------------------------------

    function render() {
        renderBar();
        renderCartouche();
        renderObserveReport();
        renderSteps();
        renderDraftBar();
        renderLocations();
        renderLinks();
        renderDiagram();
        renderNodeInspector();
        renderFindings();
    }

    function renderBar() {
        // The bar's buttons ship disabled: every handler needs bpState, which only
        // exists once an organization has loaded.
        document.querySelectorAll('.bp-bar button').forEach((b) => { b.disabled = false; });
        if ($('btnBpInstructions')) $('btnBpInstructions').disabled = false;
        const info = bpState.rev_info;
        $('bpRevInfo').textContent = info ? tr('bpRevInfo', { rev: info.rev, at: info.at, by: info.by || '—' }) : tr('bpRevNone');
        $('bpObsInfo').textContent = bpObservedAt ? tr('bpObsInfo', { at: bpObservedAt }) : tr('bpObsNone');
    }

    function renderCartouche() {
        const box = $('bpCartouche');
        if (!box || !bpState) return;
        const m = model();
        const locs = Object.keys(m.locations || {}).length;
        const links = Object.keys(m.links || {}).length;
        const errs = bpFindings.filter((f) => f.severity === 'error').length;
        const warns = bpFindings.filter((f) => f.severity === 'warning').length;
        const purdue = bpFindings.filter((f) => CODE_GROUP[f.code] === 'purdue').length;
        const rev = bpState.rev ? `v${bpState.rev}` : '—';
        const item = (lbl, val) => `<span>${escapeHtml(lbl)} <b>${escapeHtml(String(val))}</b></span>`;
        box.innerHTML = item(tr('bpCartoucheLocations'), locs)
            + item(tr('bpCartoucheLinks'), links)
            + item(tr('bpCartoucheErrors'), errs)
            + item(tr('bpCartoucheWarnings'), warns)
            + item(tr('bpCartouchePurdue'), purdue)
            + item(tr('bpCartoucheRev'), rev)
            + item(tr('bpCartoucheSnap'), bpObservedAt || '—');
    }

    function renderObserveReport() {
        const box = $('bpObserveReport');
        if (!box) return;
        if (!bpLastObserve || !Object.keys(bpLastObserve).length) {
            box.hidden = true;
            box.innerHTML = '';
            return;
        }
        const cards = Object.entries(bpLastObserve).map(([ip, st]) => {
            const rErr = st && st.routes_error ? String(st.routes_error) : '';
            const tErr = st && st.tunnels_error ? String(st.tunnels_error) : '';
            const hasErr = !!(rErr || tErr);
            return `<div class="bp-obs-card${hasErr ? ' is-err' : ''}">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:4px;">
                    <code class="bp-mono">${escapeHtml(ip)}</code>
                    <span class="badge ${hasErr ? 'badge-danger' : 'badge-success'}">${escapeHtml(tr(hasErr ? 'bpObsGwErr' : 'bpObsGwOk'))}</span>
                </div>
                ${rErr ? `<div style="font-size:11.5px;">${escapeHtml(tr('bpObsRoutesErr', { err: rErr }))}</div>` : ''}
                ${tErr ? `<div style="font-size:11.5px;">${escapeHtml(tr('bpObsTunnelsErr', { err: tErr }))}</div>` : ''}
            </div>`;
        }).join('');
        box.hidden = false;
        box.innerHTML = `<div class="bp-obs-head">
                <strong>${escapeHtml(tr('bpObsReportTitle'))}</strong>
                <button type="button" class="btn btn-secondary btn-small" data-action="bp-obs-dismiss" style="width:auto; margin:0;">${escapeHtml(tr('bpObsDismiss'))}</button>
            </div>
            <div class="bp-obs-grid">${cards}</div>`;
    }

    function renderSteps() {
        const locs = Object.values(model().locations);
        const any = locs.length > 0;
        const has = (code) => bpFindings.some((f) => f.code === code);
        const steps = [
            ['bpStep1', any, 'preset'],
            ['bpStep2', any && locs.every((l) => (l.subnets || []).length), 'findings'],
            ['bpStep3', any && !has('location_isolated'), 'findings'],
            ['bpStep4', any && locs.every((l) => l.gateway), 'findings'],
            ['bpStep5', !!bpObservedAt, 'observe'],
            ['bpStep6', any && !bpFindings.some((f) => f.severity === 'error'), 'findings'],
        ];
        const doneCount = steps.filter((s) => s[1]).length;
        if ($('bpStepsProgress')) {
            $('bpStepsProgress').textContent = tr('bpStepsProgress', { done: doneCount, total: steps.length });
        }
        const label = { preset: 'btnBpPreset', observe: 'btnBpObserve', findings: 'btnBpSeeFindings' };
        $('bpSteps').hidden = steps.every((s) => s[1]);
        $('bpStepsList').innerHTML = steps.map(([key, done, action]) => `<li class="${done ? 'is-done' : ''}">
            ${done ? '<i class="fa-solid fa-check" aria-hidden="true"></i> ' : ''}${escapeHtml(tr(key))}
            ${done ? '' : ` <button type="button" class="bp-link-btn" data-bp-step="${action}">${escapeHtml(tr(label[action]))}</button>`}</li>`).join('');
    }

    function renderDraftBar() {
        const draft = bpState.draft;
        $('bpDraftBar').hidden = !draft;
        if (!draft) return;
        const text = tr('bpDraftInfo', { n: draft.ops.length, rev: draft.base_rev });
        $('bpDraftInfo').textContent = bpState.draft_error
            ? `${text} — ${tr('bpDraftInvalid', { error: bpState.draft_error })}` : text;
    }

    function iconBtn(action, id, icon, key, danger) {
        return `<button type="button" class="inv-icon-btn${danger ? ' danger' : ''}" data-action="${action}" data-id="${escapeHtml(id)}" title="${escapeHtml(tr(key))}" aria-label="${escapeHtml(tr(key))}"><i class="fa-solid ${icon}"></i></button>`;
    }

    function findDraftLocOpIndex(id, loc) {
        return draftOps().findIndex((o) => o.op === 'create_location'
            && (o.ref === id || o.id === id || o.name === loc.name));
    }

    function findDraftLinkOpIndex(k) {
        return draftOps().findIndex((o) => o.op === 'add_link'
            && o.a === k.a && o.b === k.b && o.kind === k.kind);
    }

    function renderLocations() {
        const m = model();
        const ids = Object.keys(m.locations).sort((a, b) => m.locations[a].name.localeCompare(m.locations[b].name));
        $('bpLocationsBody').innerHTML = ids.map((id) => {
            const l = m.locations[id];
            let actions;
            if (id in bpState.locations) {
                actions = iconBtn('bp-edit-loc', id, 'fa-pen', 'btnBpEditOp') + iconBtn('bp-del-loc', id, 'fa-trash-can', 'btnBpRemoveOp', true);
            } else {
                const opIdx = findDraftLocOpIndex(id, l);
                const draftBtns = opIdx >= 0
                    ? iconBtn('bp-draft-op-edit', String(opIdx), 'fa-pen', 'btnBpEditOp')
                        + iconBtn('bp-draft-op-del', String(opIdx), 'fa-trash-can', 'btnBpRemoveOp', true)
                    : '';
                actions = `<span class="bp-draft-tag">${escapeHtml(tr('bpInDraft'))}</span> ${draftBtns}`;
            }
            return `<tr><td><strong>${escapeHtml(l.name)}</strong></td><td>${escapeHtml(roleLabel(l.role))}</td>
                <td class="bp-mono">${(l.subnets || []).map(escapeHtml).join('<br>') || '—'}</td>
                <td class="bp-mono">${escapeHtml(l.gateway || '—')}</td><td>${escapeHtml(probeName(l.probe))}</td>
                <td style="white-space:nowrap;">${actions}</td></tr>`;
        }).join('') || `<tr><td colspan="6" class="inv-muted">${escapeHtml(tr('bpNoLocations'))}</td></tr>`;
    }

    function renderLinks() {
        const m = model();
        $('bpLinksBody').innerHTML = Object.entries(m.links).map(([id, k]) => {
            let actions;
            if (id in bpState.links) {
                actions = iconBtn('bp-edit-link', id, 'fa-pen', 'btnBpEditOp') + iconBtn('bp-del-link', id, 'fa-trash-can', 'btnBpRemoveOp', true);
            } else {
                const opIdx = findDraftLinkOpIndex(k);
                const draftBtns = opIdx >= 0
                    ? iconBtn('bp-draft-op-edit', String(opIdx), 'fa-pen', 'btnBpEditOp')
                        + iconBtn('bp-draft-op-del', String(opIdx), 'fa-trash-can', 'btnBpRemoveOp', true)
                    : '';
                actions = `<span class="bp-draft-tag">${escapeHtml(tr('bpInDraft'))}</span> ${draftBtns}`;
            }
            return `<tr><td>${escapeHtml(locName(k.a))}</td><td>${escapeHtml(locName(k.b))}</td>
                <td>${escapeHtml(trEnum('bpKind_', k.kind))}</td><td style="white-space:nowrap;">${actions}</td></tr>`;
        }).join('') || `<tr><td colspan="4" class="inv-muted">${escapeHtml(tr('bpNoLinks'))}</td></tr>`;
    }

    function worstBy(kind) {
        const out = {};
        bpFindings.forEach((f) => {
            const id = (f.subject || {})[kind];
            if (id !== undefined && (out[id] === undefined || SEV_RANK[f.severity] < SEV_RANK[out[id]])) out[id] = f.severity;
        });
        return out;
    }

    // vis 'html' labels only parse <b>/<i>/<code>; & and < still need escaping.
    const visText = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;');

    function renderDiagram() {
        if (typeof vis === 'undefined') return;
        const m = model();
        const worstLoc = worstBy('location');
        const worstLink = worstBy('link');
        const text = cssVar('--text'), muted = cssVar('--text-muted'), surface = cssVar('--surface');
        const font = getComputedStyle(document.body).fontFamily;
        // Card nodes: name, then role and first subnet; the border carries the worst finding.
        const nodes = Object.entries(m.locations).map(([id, l]) => {
            const sub = [roleLabel(l.role), (l.subnets || [])[0]].filter(Boolean).join(' · ');
            const sev = worstLoc[id];
            return {
                id, shape: 'box', label: `<b>${visText(l.name)}</b>
<i>${visText(sub)}</i>`,
                margin: { top: 10, bottom: 10, left: 14, right: 14 },
                borderWidth: sev ? 2 : 1, borderWidthSelected: 2,
                color: { background: surface, border: cssVar(sev ? SEV_COLORS[sev] : '--border-strong'),
                    highlight: { background: surface, border: cssVar('--primary') },
                    hover: { background: surface, border: cssVar('--primary') } },
                shapeProperties: { borderRadius: 2, borderDashes: id in bpState.locations ? false : [4, 4] },
                font: { multi: 'html', face: font, color: text, size: 13,
                    bold: { color: text, size: 14, face: font }, ital: { color: muted, size: 11, face: font } },
                shadow: false,
            };
        });
        const edges = Object.entries(m.links).map(([id, k]) => ({
            id, from: k.a, to: k.b, label: trEnum('bpKind_', k.kind), width: 2, hoverWidth: 1,
            color: { color: cssVar(worstLink[id] ? SEV_COLORS[worstLink[id]] : KIND_COLORS[k.kind]), inherit: false },
            dashes: !(id in bpState.links),
            font: { color: muted, size: 10, face: font, background: surface, strokeWidth: 0, align: 'middle' },
        }));
        if (bpNetwork) bpNetwork.destroy();
        bpNetwork = new vis.Network($('bpDiagram'), { nodes, edges }, {
            physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { springLength: 160, avoidOverlap: 0.6 },
                stabilization: { iterations: 200 } },
            edges: { smooth: { enabled: true, type: 'continuous', roundness: 0.4 } },
            interaction: { hover: true, tooltipDelay: 150 },
        });
        // Freeze once laid out: cards stay where the admin drags them.
        bpNetwork.once('stabilizationIterationsDone', () => {
            bpNetwork.setOptions({ physics: false });
            bpNetwork.fit({ animation: { duration: 300 } });
        });
        bpNetwork.on('click', (p) => {
            if (p.nodes.length) {
                bpSelectedLocId = p.nodes[0];
                renderNodeInspector();
            } else if (!p.edges.length) {
                bpSelectedLocId = null;
                renderNodeInspector();
            }
        });
        bpNetwork.on('doubleClick', (p) => {
            if (p.nodes.length) {
                const nid = p.nodes[0];
                if (nid in bpState.locations) editLocation(nid);
                else {
                    const loc = model().locations[nid];
                    if (loc) editDraftOpAt(findDraftLocOpIndex(nid, loc));
                }
            } else if (p.edges.length) {
                const eid = p.edges[0];
                if (eid in bpState.links) editLink(eid);
                else {
                    const lk = model().links[eid];
                    if (lk) editDraftOpAt(findDraftLinkOpIndex(lk));
                }
            }
        });
    }

    function renderNodeInspector() {
        const box = $('bpNodeInspector');
        if (!box) return;
        const m = model();
        const loc = bpSelectedLocId ? (m.locations || {})[bpSelectedLocId] : null;
        if (!loc) {
            box.hidden = true;
            box.innerHTML = '';
            return;
        }
        const inDraft = !(bpSelectedLocId in (bpState.locations || {}));
        const locFindings = bpFindings.filter((f) => (f.subject || {}).location === bpSelectedLocId);
        const subnetsHtml = (loc.subnets || []).length
            ? (loc.subnets || []).map((s) => `<code class="bp-mono">${escapeHtml(s)}</code>`).join(', ')
            : '—';
        const findingsHtml = locFindings.length
            ? locFindings.map((f) => `<div><span class="bp-sev bp-sev-${escapeHtml(f.severity)}">${escapeHtml(trEnum('bpSev_', f.severity))}</span> ${findingText(f)}</div>`).join('')
            : `<span style="color:var(--text-muted);">${escapeHtml(tr('bpInspNoFindings'))}</span>`;
        box.hidden = false;
        box.innerHTML = `<div class="bp-insp-head">
                <div>
                    <span class="bp-group" style="margin:0 6px 0 0;">${escapeHtml(tr('bpInspTitle'))}</span>
                    <strong>${escapeHtml(loc.name)}</strong>
                    ${inDraft ? ` <span class="bp-draft-tag">${escapeHtml(tr('bpInDraft'))}</span>` : ''}
                </div>
                <button type="button" class="inv-icon-btn" data-action="bp-insp-close" aria-label="${escapeHtml(tr('bpInspClose'))}" title="${escapeHtml(tr('bpInspClose'))}"><i class="fa-solid fa-xmark"></i></button>
            </div>
            <div class="bp-insp-meta">
                <div><span class="bp-meta">${escapeHtml(tr('bpInspRole'))}:</span> ${escapeHtml(roleLabel(loc.role))}</div>
                <div><span class="bp-meta">${escapeHtml(tr('bpInspGateway'))}:</span> <span class="bp-mono">${escapeHtml(loc.gateway || '—')}</span></div>
                <div><span class="bp-meta">${escapeHtml(tr('bpInspProbe'))}:</span> ${escapeHtml(probeName(loc.probe))}</div>
                <div><span class="bp-meta">${escapeHtml(tr('bpInspSubnets'))}:</span> ${subnetsHtml}</div>
            </div>
            <div style="margin-bottom:8px; font-size:12px;">
                <span class="bp-meta">${escapeHtml(tr('bpInspFindings'))}:</span>
                <div style="margin-top:4px; display:flex; flex-direction:column; gap:4px;">${findingsHtml}</div>
            </div>
            <div class="bp-insp-actions">
                <button type="button" class="btn btn-secondary btn-small" data-action="bp-insp-edit" data-id="${escapeHtml(bpSelectedLocId)}">
                    <i class="fa-solid fa-pen" aria-hidden="true"></i> ${escapeHtml(tr('bpInspEdit'))}
                </button>
                ${loc.gateway ? `<button type="button" class="btn btn-primary btn-small" data-action="bp-insp-trace" data-id="${escapeHtml(bpSelectedLocId)}">
                    <i class="fa-solid fa-route" aria-hidden="true"></i> ${escapeHtml(tr('bpInspTrace'))}
                </button>` : ''}
            </div>`;
    }

    function findingKey(f) {
        const p = f.params || {};
        if (f.code === 'link_no_route') {
            if (f.severity === 'unknown') return 'bpf_link_no_route_unknown';
            if (p.via === 'default') return 'bpf_link_no_route_default';
            return p.backup_only ? 'bpf_link_no_route_backup' : 'bpf_link_no_route';
        }
        if (f.code === 'vpn_link_down') return 'bpf_vpn_link_down_' + p.state;
        if (f.code === 'device_outside_subnets' && p.owner) return 'bpf_device_outside_subnets_owner';
        return 'bpf_' + f.code;
    }

    function findingText(f) {
        const vars = {};
        Object.entries(f.params || {}).forEach(([k, v]) => {
            vars[k] = escapeHtml(Array.isArray(v) ? v.join(', ') : String(v));
        });
        return tr(findingKey(f), vars);
    }

    // HTML: every variable part is escaped here.
    function describeOp(op) {
        const n = (id) => escapeHtml(locName(id));
        switch (op.op) {
            // Every field the op sets, not just the name: the admin approves what
            // an assistant or an MCP client proposed, subnets and gateway included.
            case 'create_location': return tr('bpOpCreate', {
                name: escapeHtml(op.name), role: escapeHtml(roleLabel(op.role)),
                subnets: escapeHtml((op.subnets || []).join(', ') || '—'), gateway: escapeHtml(op.gateway || '—'),
                probe: escapeHtml(probeName(op.probe || 'central')) });
            case 'update_location': return tr('bpOpUpdate', { name: n(op.id), fields: escapeHtml(Object.entries(op.fields || {})
                .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join('; ')) });
            case 'add_subnet': return tr('bpOpAddSubnet', { name: n(op.id), subnet: escapeHtml(op.subnet) });
            case 'set_gateway': return tr('bpOpGateway', { name: n(op.id), ip: escapeHtml(op.ip) });
            case 'delete_location': return tr('bpOpDelete', { name: n(op.id) });
            case 'add_link': return tr('bpOpLink', { a: n(op.a), b: n(op.b), kind: escapeHtml(trEnum('bpKind_', op.kind)) });
            case 'remove_link': return tr('bpOpUnlink', { id: escapeHtml(op.id) });
        }
        return escapeHtml(op.op);
    }

    function firstUsableIp(cidr) {
        const s = String(cidr || '').trim();
        const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(s);
        if (!m) return '';
        const prefix = m[3] ? parseInt(m[3], 10) : 32;
        const last = parseInt(m[2], 10);
        return prefix < 31 ? `${m[1]}.${Math.min(254, last + 1)}` : `${m[1]}.${last}`;
    }

    function openRouteTraceFromBlueprint(srcLocId, dstCidr) {
        const m = model();
        const locs = m.locations || {};
        const srcGw = (locs[srcLocId] || {}).gateway || '';
        const allGws = [...new Set(Object.values(locs).map((l) => l.gateway).filter(Boolean))];
        if (!allGws.length) {
            showToast(tr('bpFindingsEmptyFilter'), 'warning');
            return;
        }
        let dstIp = firstUsableIp(dstCidr);
        if (!dstIp) {
            const otherSub = Object.entries(locs)
                .filter(([lid, l]) => lid !== srcLocId && (l.subnets || []).length)
                .map(([, l]) => l.subnets[0])[0];
            dstIp = firstUsableIp(otherSub || '');
        }
        const srcSubnet = ((locs[srcLocId] || {}).subnets || [])[0] || '';
        window.rtPendingTrace = {
            tenant: bpOrg || 'all',
            devices: allGws,
            src: srcGw || allGws[0],
            src_ip: firstUsableIp(srcSubnet),
            dst: dstIp,
            openView: 'trace',
        };
        if (typeof switchTab === 'function') switchTab('tab-routes');
    }

    function updateAcceptSelectedBtn() {
        const box = $('bpFindings');
        const btn = $('btnBpAcceptSelected');
        const allChk = $('bpSelectAllProposals');
        if (!box || !btn) return;
        const boxes = [...box.querySelectorAll('input[type=checkbox][data-f]')];
        const checked = boxes.filter((c) => c.checked).length;
        btn.disabled = checked === 0;
        btn.textContent = checked > 0 ? tr('bpAcceptSelectedCount', { n: checked }) : tr('btnBpAcceptSelected');
        if (allChk) {
            allChk.disabled = boxes.length === 0;
            allChk.checked = boxes.length > 0 && checked === boxes.length;
            allChk.indeterminate = checked > 0 && checked < boxes.length;
        }
    }

    function renderFindings() {
        const box = $('bpFindings');
        const bar = $('bpFindingsBar');
        if (bar) bar.hidden = !bpFindings.length;
        if (!bpFindings.length) {
            box.innerHTML = `<p class="inv-muted">${escapeHtml(tr('bpNoFindings'))}</p>`;
            updateAcceptSelectedBtn();
            return;
        }
        if (bar) {
            bar.querySelectorAll('[data-bp-group]').forEach((b) => {
                b.setAttribute('aria-pressed', String(b.dataset.bpGroup === bpFindingsGroup));
            });
            const sevBtn = $('btnBpSevFilter');
            if (sevBtn) sevBtn.setAttribute('aria-pressed', String(bpFindingsSev === 'error'));
        }
        const groups = ['model', 'subnets', 'routing', 'vpn', 'purdue'];
        const rendered = groups.map((g) => {
            if (bpFindingsGroup !== 'all' && bpFindingsGroup !== g) return '';
            const items = bpFindings.map((f, i) => [f, i]).filter(([f]) =>
                CODE_GROUP[f.code] === g
                && (bpFindingsSev === 'all' || f.severity === bpFindingsSev));
            if (!items.length) return '';
            return `<h4 class="bp-group">${escapeHtml(trEnum('bpGroup_', g))}</h4><ul class="bp-findings">${items.map(([f, i]) => {
                const sub = f.subject || {};
                const focusAttr = sub.location
                    ? `data-focus-kind="location" data-focus-id="${escapeHtml(sub.location)}"`
                    : (sub.link ? `data-focus-kind="link" data-focus-id="${escapeHtml(sub.link)}"` : '');
                const traceLink = (f.code === 'link_no_route' && sub.link && (f.params || {}).subnet)
                    ? `<button type="button" class="bp-link-btn" data-action="bp-trace-route" data-link="${escapeHtml(sub.link)}" data-subnet="${escapeHtml(f.params.subnet)}"><i class="fa-solid fa-route" aria-hidden="true"></i> ${escapeHtml(tr('bpTraceMissingRoute'))}</button>`
                    : '';
                const sevCls = f.severity === 'error' ? ' class="is-error"' : (f.severity === 'warning' ? ' class="is-warning"' : '');
                return `<li${sevCls}><div class="bp-finding-top">
                    <div><span class="bp-sev bp-sev-${escapeHtml(f.severity)}">${escapeHtml(trEnum('bpSev_', f.severity))}</span> ${findingText(f)}</div>
                    <div class="bp-finding-tools">
                        ${focusAttr ? `<button type="button" class="bp-link-btn" data-action="bp-focus-subject" ${focusAttr}>${escapeHtml(tr('bpFocusOnDiagram'))}</button>` : ''}
                        ${traceLink}
                    </div>
                </div>
                ${(f.proposal || []).map((op, j) => `<div class="bp-proposal">
                    <label><input type="checkbox" data-f="${i}" data-o="${j}" aria-label="${escapeHtml(tr('bpAcceptProposal'))}"> ${describeOp(op)}</label>
                    <button type="button" class="btn btn-secondary btn-small" data-action="bp-accept-one" data-f="${i}" data-o="${j}" style="width:auto; margin:0;">${escapeHtml(tr('bpAcceptOne'))}</button>
                    ${EDITABLE.includes(op.op) ? `<button type="button" class="bp-link-btn" data-action="bp-edit-proposal" data-f="${i}" data-o="${j}">${escapeHtml(tr('btnBpEditOp'))}</button>` : ''}
                </div>`).join('')}</li>`;
            }).join('')}</ul>`;
        }).join('');
        box.innerHTML = rendered || `<p class="inv-muted">${escapeHtml(tr('bpFindingsEmptyFilter'))}</p>`;
        updateAcceptSelectedBtn();
    }

    function renderDiff(d) {
        const fmt = (v) => (Array.isArray(v) ? v.join(', ') : v) || '—';
        const part = (title, p, label) => {
            const rows = [
                ...p.added.map((x) => `<li class="bp-diff-add">+ ${escapeHtml(label(x))}</li>`),
                ...p.removed.map((x) => `<li class="bp-diff-del">− ${escapeHtml(label(x))}</li>`),
                ...p.changed.map((x) => `<li>~ ${escapeHtml(x.label)}: ${escapeHtml(Object.entries(x.fields)
                    .map(([f, [a, b]]) => `${f}: ${fmt(a)} → ${fmt(b)}`).join('; '))}</li>`),
            ];
            return rows.length ? `<h4>${escapeHtml(title)}</h4><ul class="bp-diff">${rows.join('')}</ul>` : '';
        };
        const html = part(tr('bpLocations'), d.locations, (x) => x.name)
            + part(tr('bpLinks'), d.links, (x) => `${locName(x.a)} ↔ ${locName(x.b)} (${trEnum('bpKind_', x.kind)})`);
        return html || `<p class="inv-muted">${escapeHtml(tr('bpDiffNone'))}</p>`;
    }

    // ---- draft -------------------------------------------------------------

    async function addOps(ops, source = 'manual') {
        const res = await send('/draft', 'POST', { source, ops });
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return false; }
        await reloadBlueprint();
        return true;
    }

    async function replaceOps(ops) {
        const res = await send('/draft', 'PUT', { ops });
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return false; }
        await reloadBlueprint();
        return true;
    }

    // `id` set: the location exists and saving yields update_location with
    // the fields that changed. `op` prefills from a proposal or a draft op.
    function openLocationModal(id, op, onSave) {
        // Diff against the preview: what applies after the ops already in the draft.
        const base = id ? (model().locations[id] || bpState.locations[id]) : { name: '', role: 'branch', subnets: [], probe: 'central', gateway: '' };
        const v = Object.assign({}, base, { subnets: [...(base.subnets || [])] });
        if (op && op.op === 'create_location') Object.assign(v, op);
        if (op && op.op === 'update_location') Object.assign(v, op.fields);
        if (op && op.op === 'add_subnet') v.subnets = [...v.subnets, op.subnet];
        if (op && op.op === 'set_gateway') v.gateway = op.ip;
        $('bpLocName').value = v.name || '';
        $('bpLocRole').value = v.role || 'branch';
        $('bpLocSubnets').value = (v.subnets || []).join('\n');
        $('bpLocProbe').replaceChildren(...(bpState.probes || []).map((p) => new Option(p.name, p.id)));
        $('bpLocProbe').value = v.probe || 'central';
        const gwList = $('bpGatewayList');
        if (gwList) {
            const rank = (d) => {
                const vnd = String(d.Vendor || '').toLowerCase();
                return vnd === 'fortinet' ? 0 : (vnd === 'cisco' ? 1 : 2);
            };
            const candidates = (globalDevices || [])
                .filter((d) => (d.Group || '') === bpOrg && d.IP)
                .sort((a, b) => rank(a) - rank(b) || String(a.Hostname || '').localeCompare(String(b.Hostname || '')));
            gwList.replaceChildren(...candidates.map((d) => {
                const opt = document.createElement('option');
                opt.value = d.IP;
                opt.label = `${d.Hostname || d.IP} (${d.Vendor || ''}${d.Location ? ' · ' + d.Location : ''})`;
                return opt;
            }));
        }
        $('bpLocGateway').value = v.gateway || '';
        $('bpLocError').textContent = '';
        bpLocSave = async () => {
            const val = {
                name: $('bpLocName').value.trim(), role: $('bpLocRole').value,
                subnets: $('bpLocSubnets').value.split(/\s+/).filter(Boolean),
                probe: $('bpLocProbe').value, gateway: $('bpLocGateway').value.trim(),
            };
            let next;
            if (id) {
                const fields = {};
                Object.keys(val).forEach((k) => {
                    const was = k === 'subnets' ? (base.subnets || []) : (base[k] || '');
                    if (JSON.stringify(val[k]) !== JSON.stringify(was)) fields[k] = val[k];
                });
                // Editing a draft op: the preview already holds its changes, so
                // the diff above misses them. Keep every field the op touched.
                const kept = !op ? [] : op.op === 'update_location' ? Object.keys(op.fields || {})
                    : op.op === 'set_gateway' ? ['gateway'] : op.op === 'add_subnet' ? ['subnets'] : [];
                kept.forEach((k) => { fields[k] = val[k]; });
                if (!Object.keys(fields).length) { closeModal('bpLocationModal'); return; }
                next = { op: 'update_location', id, fields };
            } else {
                next = Object.assign({ op: 'create_location', ref: (op && op.ref) || '+1' },
                    op && op.id ? { id: op.id } : {}, val);
            }
            if (await onSave(next)) closeModal('bpLocationModal');
        };
        openModal('bpLocationModal');
    }

    function linkEndpoints() {
        const out = Object.entries(bpState.locations).map(([id, l]) => [id, l.name]);
        draftOps().filter((o) => o.op === 'create_location' && o.ref)
            .forEach((o) => out.push([o.ref, `${o.name} (${tr('bpInDraft')})`]));
        // Proposals may name a location only the preview has (its slug, not a ref).
        Object.entries(model().locations).filter(([id]) => !(id in bpState.locations))
            .forEach(([id, l]) => out.push([id, `${l.name} (${tr('bpInDraft')})`]));
        return out;
    }

    function openLinkModal(op, onSave) {
        const opts = linkEndpoints();
        ['bpLinkA', 'bpLinkB'].forEach((sid) => $(sid).replaceChildren(...opts.map(([id, name]) => new Option(name, id))));
        $('bpLinkA').value = (op && op.a) || (opts[0] || [''])[0];
        $('bpLinkB').value = (op && op.b) || (opts[1] || opts[0] || [''])[0];
        $('bpLinkKind').value = (op && op.kind) || 'vpn';
        $('bpLinkNote').value = (op && op.note) || '';
        $('bpLinkError').textContent = '';
        bpLinkSave = async () => {
            const next = { op: 'add_link', a: $('bpLinkA').value, b: $('bpLinkB').value,
                kind: $('bpLinkKind').value, note: $('bpLinkNote').value.trim() };
            if (next.a === next.b) { $('bpLinkError').textContent = tr('bpLinkSame'); return; }
            if (await onSave(next)) closeModal('bpLinkModal');
        };
        openModal('bpLinkModal');
    }

    function openOpEditor(op, onSave) {
        if (op.op === 'add_link') openLinkModal(op, onSave);
        else if (op.op === 'create_location') openLocationModal(null, op, onSave);
        else openLocationModal(op.id, op, onSave);
    }

    function editLocation(id) { openLocationModal(id, null, (next) => addOps([next])); }
    function editLink(id) { openLinkModal(bpState.links[id], (next) => addOps([{ op: 'remove_link', id }, next])); }

    function editDraftOpAt(i) {
        const ops = draftOps().slice();
        if (i < 0 || !ops[i]) return;
        openOpEditor(ops[i], async (next) => {
            ops[i] = Object.assign({}, next, { source: ops[i].source });
            return replaceOps(ops);
        });
    }

    async function removeDraftOpAt(i) {
        const ops = draftOps().slice();
        if (i < 0 || !ops[i]) return;
        ops.splice(i, 1);
        await replaceOps(ops);
    }

    async function acceptSelected() {
        const ops = [...$('bpFindings').querySelectorAll('input[type=checkbox][data-f]:checked')]
            .map((c) => bpFindings[+c.dataset.f].proposal[+c.dataset.o]);
        if (!ops.length) return;
        if (await addOps(ops, 'checks')) showToast(tr('bpAddedToDraft', { n: ops.length }), 'success');
    }

    function renderDraftOps() {
        $('bpDraftOps').innerHTML = draftOps().map((op, i) => `<li>${describeOp(op)}
            ${op.source === 'assistant' ? `<span class="bp-draft-tag">${escapeHtml(tr('bpOpFromAssistant'))}</span>` : ''}
            ${EDITABLE.includes(op.op) ? `<button type="button" class="bp-link-btn" data-action="bp-op-edit" data-i="${i}">${escapeHtml(tr('btnBpEditOp'))}</button>` : ''}
            <button type="button" class="bp-link-btn danger" data-action="bp-op-remove" data-i="${i}">${escapeHtml(tr('btnBpRemoveOp'))}</button></li>`).join('');
    }

    function openDraftModal(focusApply = false) {
        renderDraftOps();
        $('bpApplyNote').value = '';
        $('bpDraftError').textContent = '';
        $('bpConflict').hidden = true;
        openModal('bpDraftModal');
        if (focusApply) $('bpApplyNote')?.focus();
    }

    async function showConflict() {
        await reloadBlueprint();
        // Draft discarded elsewhere: nothing left to apply.
        if (!bpState.draft) { closeModal('bpDraftModal'); return; }
        const res = bpState.draft.base_rev
            ? await apiFetch(api(`/diff?a=${bpState.draft.base_rev}&b=${bpState.rev}`)) : null;
        $('bpConflictDiff').innerHTML = res && res.ok ? renderDiff(await res.json()) : '';
        $('bpConflict').hidden = false;
    }

    async function applyDraft() {
        const res = await send('/draft/apply', 'POST', { note: $('bpApplyNote').value.trim() });
        if (res && res.status === 409) { await showConflict(); return; }
        if (!res || !res.ok) { $('bpDraftError').textContent = await errorText(res); return; }
        const body = await res.json();
        closeModal('bpDraftModal');
        showToast(tr('bpApplied', { rev: body.rev }), 'success');
        const renamed = Object.entries(body.renamed || {});
        if (renamed.length) showToast(tr('bpRenamed', { list: renamed.map(([a, b]) => `${a} → ${b}`).join(', ') }), 'warning');
        // The locations table is the one Organizations shows: without this
        // the new location only appeared there after a page reload.
        await Promise.all([reloadBlueprint(), refreshInventory()]);
    }

    async function align() {
        const res = await send('/draft/align', 'POST', {});
        if (!res || !res.ok) { $('bpDraftError').textContent = await errorText(res); return; }
        $('bpConflict').hidden = true;
        await reloadBlueprint();
        renderDraftOps();
    }

    // ---- history, presets, observation --------------------------------------

    async function openHistory() {
        const res = await apiFetch(api('/revisions'));
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        const revs = (await res.json()).revisions;
        $('bpRevisionsBody').innerHTML = revs.map((r) => `<tr><td>${r.rev}</td><td>${escapeHtml(r.at)}</td>
            <td>${escapeHtml(r.by || '—')}</td><td>${escapeHtml(trEnum('bpSource_', r.source))}</td><td>${escapeHtml(r.note || '')}</td>
            <td>${r.rev === bpState.rev ? '' : `<button type="button" class="btn btn-secondary btn-small" data-action="bp-restore" data-rev="${r.rev}">${escapeHtml(tr('btnBpRestore'))}</button>`}</td></tr>`).join('');
        ['bpDiffA', 'bpDiffB'].forEach((sid) => $(sid).replaceChildren(...revs.map((r) => new Option(`rev ${r.rev}`, String(r.rev)))));
        if (revs.length) {
            $('bpDiffB').value = String(revs[0].rev);
            $('bpDiffA').value = String((revs[1] || revs[0]).rev);
        }
        $('bpDiffOut').innerHTML = '';
        openModal('bpHistoryModal');
    }

    async function compare() {
        const res = await apiFetch(api(`/diff?a=${$('bpDiffA').value}&b=${$('bpDiffB').value}`));
        $('bpDiffOut').innerHTML = res && res.ok ? renderDiff(await res.json()) : escapeHtml(await errorText(res));
    }

    async function restore(rev) {
        const res = await send('/draft', 'POST', { restore: rev });
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        closeModal('bpHistoryModal');
        showToast(tr('bpRestoreOpened', { rev }), 'success');
        await reloadBlueprint();
    }

    async function createPreset() {
        const res = await send('/draft', 'POST', { preset: $('bpPresetKind').value, n: parseInt($('bpPresetN').value, 10) || 1 });
        if (!res || !res.ok) { $('bpPresetError').textContent = await errorText(res); return; }
        closeModal('bpPresetModal');
        await reloadBlueprint();
    }

    async function observe() {
        const btn = $('btnBpObserve');
        btn.disabled = true;
        try {
            const res = await send('/observe', 'POST', {});
            if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
            const body = await res.json();
            bpLastObserve = body.gateways || {};
            showToast(tr('bpObserved', { n: Object.keys(bpLastObserve).length }), 'success');
            await runChecks();
        } finally {
            btn.disabled = false;
        }
    }

    function openPreset() {
        $('bpPresetError').textContent = '';
        openModal('bpPresetModal');
    }

    // ---- assistant (spec 2026-10-11 blueprint-assistant) ---------------------
    // Both entry points only append to the draft; the draft bar takes it from there.

    function openAssistant() {
        $('bpAssistError').textContent = '';
        $('bpAssistNotes').hidden = true;
        $('bpAssistUseAi').disabled = !bpState.ai_available;
        if (!bpState.ai_available) $('bpAssistUseAi').checked = false;
        openModal('bpAssistantModal');
    }

    async function runAssistant(path, body, btn) {
        btn.disabled = true;
        $('bpAssistError').textContent = '';
        $('bpAssistNotes').hidden = true;
        try {
            const res = await send(path, 'POST', body);
            if (!res || !res.ok) { $('bpAssistError').textContent = await errorText(res); return; }
            const out = await res.json();
            if (out.added) showToast(tr('bpAddedToDraft', { n: out.added }), 'success');
            $('bpAssistNotes').textContent = out.notes || '';
            $('bpAssistNotes').hidden = !out.notes;
            await reloadBlueprint();
        } finally {
            btn.disabled = false;
        }
    }

    function openInstructions() {
        $('bpInstrText').value = bpState.instructions || '';
        $('bpInstrError').textContent = '';
        openModal('bpInstructionsModal');
    }

    async function saveInstructions() {
        const res = await send('/instructions', 'PUT', { text: $('bpInstrText').value });
        if (!res || !res.ok) { $('bpInstrError').textContent = await errorText(res); return; }
        bpState.instructions = (await res.json()).instructions;
        closeModal('bpInstructionsModal');
        showToast(tr('bpInstrSaved'), 'success');
    }

    // ---- bindings (the module loads once, with its tab) ----------------------

    $('bpOrgSelect').addEventListener('change', () => {
        bpOrg = $('bpOrgSelect').value;
        bpSelectedLocId = null;
        bpLastObserve = null;
        reloadBlueprint();
    });
    $('btnBpCheck').addEventListener('click', () => reloadBlueprint());
    $('btnBpObserve').addEventListener('click', observe);
    $('btnBpPreset').addEventListener('click', openPreset);
    $('btnBpHistory').addEventListener('click', openHistory);
    $('btnBpAddLocation').addEventListener('click', () => openLocationModal(null, null, (next) => addOps([next])));
    $('btnBpAddLink').addEventListener('click', () => openLinkModal(null, (next) => addOps([next])));
    $('btnBpAcceptSelected').addEventListener('click', acceptSelected);
    $('btnBpDraftReview').addEventListener('click', () => openDraftModal(false));
    $('btnBpDraftApply').addEventListener('click', () => openDraftModal(true));
    $('btnBpDraftDiscard').addEventListener('click', async () => {
        if (!confirm(tr('bpConfirmDiscard'))) return;
        const res = await send('/draft/discard', 'POST', {});
        if (!res || !res.ok) { showToast(await errorText(res), 'error'); return; }
        await reloadBlueprint();
    });
    $('btnBpDraftApplyConfirm').addEventListener('click', applyDraft);
    $('btnBpAlign').addEventListener('click', align);
    $('btnBpLocSave').addEventListener('click', () => bpLocSave && bpLocSave());
    $('btnBpLinkSave').addEventListener('click', () => bpLinkSave && bpLinkSave());
    $('btnBpPresetCreate').addEventListener('click', createPreset);
    $('btnBpDiff').addEventListener('click', compare);
    $('btnBpAssistant').addEventListener('click', openAssistant);
    $('btnBpInstructions').addEventListener('click', openInstructions);
    $('btnBpAssistDescribe').addEventListener('click', () =>
        runAssistant('/assistant/describe', { text: $('bpAssistText').value }, $('btnBpAssistDescribe')));
    $('btnBpAssistDerive').addEventListener('click', () =>
        runAssistant('/assistant/derive', { use_ai: $('bpAssistUseAi').checked }, $('btnBpAssistDerive')));
    $('btnBpInstrSave').addEventListener('click', saveInstructions);

    $('bpObserveReport')?.addEventListener('click', (e) => {
        if (e.target.closest('[data-action="bp-obs-dismiss"]')) {
            bpLastObserve = null;
            renderObserveReport();
        }
    });
    $('btnBpDiagFit')?.addEventListener('click', () => {
        if (bpNetwork) bpNetwork.fit({ animation: { duration: 250 } });
    });
    $('btnBpDiagLegend')?.addEventListener('click', (e) => {
        const pop = $('bpDiagLegendPop');
        if (!pop) return;
        pop.hidden = !pop.hidden;
        e.currentTarget.setAttribute('aria-expanded', String(!pop.hidden));
    });
    $('btnBpDiagExport')?.addEventListener('click', () => {
        const canvas = $('bpDiagram')?.querySelector('canvas');
        if (!canvas || !(canvas instanceof HTMLCanvasElement)) return;
        const a = document.createElement('a');
        a.href = canvas.toDataURL('image/png');
        a.download = `blueprint-${bpOrg || 'network'}.png`;
        a.click();
    });
    $('bpNodeInspector')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const act = btn.dataset.action;
        const id = btn.dataset.id || bpSelectedLocId;
        if (act === 'bp-insp-close') {
            bpSelectedLocId = null;
            renderNodeInspector();
        } else if (act === 'bp-insp-edit' && id) {
            if (id in (bpState.locations || {})) editLocation(id);
            else {
                const loc = model().locations[id];
                if (loc) editDraftOpAt(findDraftLocOpIndex(id, loc));
            }
        } else if (act === 'bp-insp-trace' && id) {
            openRouteTraceFromBlueprint(id, '');
        }
    });
    $('bpSelectAllProposals')?.addEventListener('change', (e) => {
        const want = !!e.target.checked;
        $('bpFindings')?.querySelectorAll('input[type=checkbox][data-f]').forEach((c) => {
            c.checked = want;
        });
        updateAcceptSelectedBtn();
    });
    $('bpFindingsBar')?.addEventListener('click', (e) => {
        const grpBtn = e.target.closest('[data-bp-group]');
        if (grpBtn) {
            bpFindingsGroup = grpBtn.dataset.bpGroup || 'all';
            renderFindings();
            return;
        }
        if (e.target.closest('#btnBpSevFilter')) {
            bpFindingsSev = bpFindingsSev === 'error' ? 'all' : 'error';
            renderFindings();
        }
    });
    $('bpSteps').addEventListener('click', (e) => {
        const b = e.target.closest('[data-bp-step]');
        if (!b) return;
        if (b.dataset.bpStep === 'preset') openPreset();
        else if (b.dataset.bpStep === 'observe') observe();
        else $('bpFindings').scrollIntoView({ behavior: 'smooth' });
    });
    $('bpLocationsBody').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        const id = b.dataset.id;
        const act = b.dataset.action;
        if (act === 'bp-edit-loc') editLocation(id);
        else if (act === 'bp-del-loc' && confirm(tr('bpConfirmDeleteLoc', { name: locName(id) }))) {
            addOps([{ op: 'delete_location', id }]);
        } else if (act === 'bp-draft-op-edit') editDraftOpAt(+id);
        else if (act === 'bp-draft-op-del') removeDraftOpAt(+id);
    });
    $('bpLinksBody').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        const act = b.dataset.action;
        if (act === 'bp-edit-link') editLink(b.dataset.id);
        else if (act === 'bp-del-link') addOps([{ op: 'remove_link', id: b.dataset.id }]);
        else if (act === 'bp-draft-op-edit') editDraftOpAt(+b.dataset.id);
        else if (act === 'bp-draft-op-del') removeDraftOpAt(+b.dataset.id);
    });
    $('bpFindings').addEventListener('change', (e) => {
        if (e.target.matches('input[type=checkbox][data-f]')) updateAcceptSelectedBtn();
    });
    $('bpFindings').addEventListener('click', (e) => {
        const editBtn = e.target.closest('[data-action="bp-edit-proposal"]');
        if (editBtn) {
            const f = bpFindings[+editBtn.dataset.f];
            const j = +editBtn.dataset.o;
            openOpEditor(f.proposal[j], (next) => { f.proposal[j] = next; renderFindings(); return true; });
            return;
        }
        const oneBtn = e.target.closest('[data-action="bp-accept-one"]');
        if (oneBtn) {
            const f = bpFindings[+oneBtn.dataset.f];
            const op = f && f.proposal ? f.proposal[+oneBtn.dataset.o] : null;
            if (op) addOps([op], 'checks').then((ok) => { if (ok) showToast(tr('bpAddedToDraft', { n: 1 }), 'success'); });
            return;
        }
        const focusBtn = e.target.closest('[data-action="bp-focus-subject"]');
        if (focusBtn && bpNetwork) {
            const kind = focusBtn.dataset.focusKind;
            const id = focusBtn.dataset.focusId;
            if (kind === 'location' && id) {
                bpSelectedLocId = id;
                renderNodeInspector();
                bpNetwork.selectNodes([id]);
                bpNetwork.focus(id, { scale: 1.05, animation: { duration: 300 } });
            } else if (kind === 'link' && id) {
                const k = model().links[id];
                if (k) {
                    bpSelectedLocId = k.a;
                    renderNodeInspector();
                    bpNetwork.selectEdges([id]);
                    bpNetwork.fit({ nodes: [k.a, k.b], animation: { duration: 300 } });
                }
            }
            $('bpDiagram')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
            return;
        }
        const traceBtn = e.target.closest('[data-action="bp-trace-route"]');
        if (traceBtn) {
            const lk = model().links[traceBtn.dataset.link];
            const srcLocId = lk ? lk.a : '';
            openRouteTraceFromBlueprint(srcLocId, traceBtn.dataset.subnet || '');
        }
    });
    $('bpDraftOps').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        const i = +b.dataset.i;
        const ops = draftOps().slice();
        if (b.dataset.action === 'bp-op-remove') {
            ops.splice(i, 1);
            // PUT [] deletes the draft server-side: nothing left to review.
            replaceOps(ops).then(() => { if (draftOps().length) renderDraftOps(); else closeModal('bpDraftModal'); });
        } else if (b.dataset.action === 'bp-op-edit') {
            // One modal at a time: the draft list reopens after the edit.
            closeModal('bpDraftModal');
            openOpEditor(ops[i], async (next) => {
                ops[i] = Object.assign({}, next, { source: ops[i].source });
                const ok = await replaceOps(ops);
                if (ok) openDraftModal();
                return ok;
            });
        }
    });
    $('bpRevisionsBody').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action="bp-restore"]');
        if (b) restore(+b.dataset.rev);
    });
})();
