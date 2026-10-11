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

    const ROLE_SHAPES = { hq: 'star', datacenter: 'database', branch: 'dot', warehouse: 'square', other: 'triangle' };
    const KIND_COLORS = { vpn: '--primary', wan: '--text-muted', mpls: '--warning', lan: '--success' };
    const SEV_RANK = { error: 0, warning: 1, unknown: 2, info: 3 };
    const SEV_COLORS = { error: '--danger', warning: '--warning', unknown: '--text-muted', info: '--primary' };
    const CODE_GROUP = {
        subnet_overlap: 'model', location_no_subnets: 'model', location_isolated: 'model',
        location_no_gateway: 'model', gateway_not_in_location: 'model',
        device_outside_subnets: 'subnets', arp_uncovered: 'subnets', subnet_unused: 'subnets',
        link_no_route: 'routing', route_without_link: 'routing',
        vpn_link_down: 'vpn', tunnel_without_link: 'vpn',
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
        bpOrg = wanted && orgs.includes(wanted) ? wanted : (orgs.includes(bpOrg) ? bpOrg : (orgs[0] || ''));
        sel.value = bpOrg;
        await reloadBlueprint();
    }
    window.loadBlueprintTab = loadBlueprintTab;

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
        renderSteps();
        renderDraftBar();
        renderLocations();
        renderLinks();
        renderDiagram();
        renderFindings();
    }

    function renderBar() {
        const info = bpState.rev_info;
        $('bpRevInfo').textContent = info ? tr('bpRevInfo', { rev: info.rev, at: info.at, by: info.by || '—' }) : tr('bpRevNone');
        $('bpObsInfo').textContent = bpObservedAt ? tr('bpObsInfo', { at: bpObservedAt }) : tr('bpObsNone');
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

    function renderLocations() {
        const m = model();
        const ids = Object.keys(m.locations).sort((a, b) => m.locations[a].name.localeCompare(m.locations[b].name));
        $('bpLocationsBody').innerHTML = ids.map((id) => {
            const l = m.locations[id];
            const actions = id in bpState.locations
                ? iconBtn('bp-edit-loc', id, 'fa-pen', 'btnBpEditOp') + iconBtn('bp-del-loc', id, 'fa-trash-can', 'btnBpRemoveOp', true)
                : `<span class="bp-draft-tag">${escapeHtml(tr('bpInDraft'))}</span>`;
            return `<tr><td><strong>${escapeHtml(l.name)}</strong></td><td>${escapeHtml(roleLabel(l.role))}</td>
                <td class="bp-mono">${(l.subnets || []).map(escapeHtml).join('<br>') || '—'}</td>
                <td class="bp-mono">${escapeHtml(l.gateway || '—')}</td><td>${escapeHtml(probeName(l.probe))}</td>
                <td style="white-space:nowrap;">${actions}</td></tr>`;
        }).join('') || `<tr><td colspan="6" class="inv-muted">${escapeHtml(tr('bpNoLocations'))}</td></tr>`;
    }

    function renderLinks() {
        const m = model();
        $('bpLinksBody').innerHTML = Object.entries(m.links).map(([id, k]) => {
            const actions = id in bpState.links
                ? iconBtn('bp-edit-link', id, 'fa-pen', 'btnBpEditOp') + iconBtn('bp-del-link', id, 'fa-trash-can', 'btnBpRemoveOp', true)
                : `<span class="bp-draft-tag">${escapeHtml(tr('bpInDraft'))}</span>`;
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

    function renderDiagram() {
        if (typeof vis === 'undefined') return;
        const m = model();
        const worstLoc = worstBy('location');
        const worstLink = worstBy('link');
        const text = cssVar('--text');
        const nodes = Object.entries(m.locations).map(([id, l]) => ({
            id, label: l.name, shape: ROLE_SHAPES[l.role] || 'dot', size: 18, borderWidth: 2,
            color: { background: cssVar(worstLoc[id] ? SEV_COLORS[worstLoc[id]] : '--surface'), border: cssVar('--border') },
            shapeProperties: { borderDashes: id in bpState.locations ? false : [4, 4] },
            font: { color: text },
        }));
        const edges = Object.entries(m.links).map(([id, k]) => ({
            id, from: k.a, to: k.b, label: trEnum('bpKind_', k.kind), width: 2,
            color: cssVar(worstLink[id] ? SEV_COLORS[worstLink[id]] : KIND_COLORS[k.kind]),
            dashes: !(id in bpState.links), font: { color: text, strokeWidth: 0, size: 11 },
        }));
        if (bpNetwork) bpNetwork.destroy();
        bpNetwork = new vis.Network($('bpDiagram'), { nodes, edges },
            { physics: { stabilization: { iterations: 150 } }, interaction: { hover: true } });
        bpNetwork.on('click', (p) => {
            if (p.nodes.length && p.nodes[0] in bpState.locations) editLocation(p.nodes[0]);
            else if (p.edges.length && p.edges[0] in bpState.links) editLink(p.edges[0]);
        });
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
            case 'create_location': return tr('bpOpCreate', { name: escapeHtml(op.name), role: escapeHtml(roleLabel(op.role)) });
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

    function renderFindings() {
        const box = $('bpFindings');
        if (!bpFindings.length) { box.innerHTML = `<p class="inv-muted">${escapeHtml(tr('bpNoFindings'))}</p>`; return; }
        box.innerHTML = ['model', 'subnets', 'routing', 'vpn'].map((g) => {
            const items = bpFindings.map((f, i) => [f, i]).filter(([f]) => CODE_GROUP[f.code] === g);
            if (!items.length) return '';
            return `<h4 class="bp-group">${escapeHtml(trEnum('bpGroup_', g))}</h4><ul class="bp-findings">${items.map(([f, i]) => `
                <li><span class="bp-sev bp-sev-${escapeHtml(f.severity)}">${escapeHtml(trEnum('bpSev_', f.severity))}</span> ${findingText(f)}
                ${(f.proposal || []).map((op, j) => `<div class="bp-proposal">
                    <label><input type="checkbox" data-f="${i}" data-o="${j}" aria-label="${escapeHtml(tr('bpAcceptProposal'))}"> ${describeOp(op)}</label>
                    ${EDITABLE.includes(op.op) ? `<button type="button" class="bp-link-btn" data-action="bp-edit-proposal" data-f="${i}" data-o="${j}">${escapeHtml(tr('btnBpEditOp'))}</button>` : ''}
                </div>`).join('')}</li>`).join('')}</ul>`;
        }).join('');
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

    async function acceptSelected() {
        const ops = [...$('bpFindings').querySelectorAll('input[type=checkbox][data-f]:checked')]
            .map((c) => bpFindings[+c.dataset.f].proposal[+c.dataset.o]);
        if (!ops.length) return;
        if (await addOps(ops, 'checks')) showToast(tr('bpAddedToDraft', { n: ops.length }), 'success');
    }

    function renderDraftOps() {
        $('bpDraftOps').innerHTML = draftOps().map((op, i) => `<li>${describeOp(op)}
            ${EDITABLE.includes(op.op) ? `<button type="button" class="bp-link-btn" data-action="bp-op-edit" data-i="${i}">${escapeHtml(tr('btnBpEditOp'))}</button>` : ''}
            <button type="button" class="bp-link-btn danger" data-action="bp-op-remove" data-i="${i}">${escapeHtml(tr('btnBpRemoveOp'))}</button></li>`).join('');
    }

    function openDraftModal() {
        renderDraftOps();
        $('bpApplyNote').value = '';
        $('bpDraftError').textContent = '';
        $('bpConflict').hidden = true;
        openModal('bpDraftModal');
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
        await reloadBlueprint();
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
            showToast(tr('bpObserved', { n: Object.keys(body.gateways || {}).length }), 'success');
            await runChecks();
        } finally {
            btn.disabled = false;
        }
    }

    function openPreset() {
        $('bpPresetError').textContent = '';
        openModal('bpPresetModal');
    }

    // ---- bindings (the module loads once, with its tab) ----------------------

    $('bpOrgSelect').addEventListener('change', () => { bpOrg = $('bpOrgSelect').value; reloadBlueprint(); });
    $('btnBpCheck').addEventListener('click', () => reloadBlueprint());
    $('btnBpObserve').addEventListener('click', observe);
    $('btnBpPreset').addEventListener('click', openPreset);
    $('btnBpHistory').addEventListener('click', openHistory);
    $('btnBpAddLocation').addEventListener('click', () => openLocationModal(null, null, (next) => addOps([next])));
    $('btnBpAddLink').addEventListener('click', () => openLinkModal(null, (next) => addOps([next])));
    $('btnBpAcceptSelected').addEventListener('click', acceptSelected);
    $('btnBpDraftReview').addEventListener('click', openDraftModal);
    $('btnBpDraftApply').addEventListener('click', openDraftModal);
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
        if (b.dataset.action === 'bp-edit-loc') editLocation(id);
        else if (b.dataset.action === 'bp-del-loc' && confirm(tr('bpConfirmDeleteLoc', { name: locName(id) }))) {
            addOps([{ op: 'delete_location', id }]);
        }
    });
    $('bpLinksBody').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        if (b.dataset.action === 'bp-edit-link') editLink(b.dataset.id);
        else if (b.dataset.action === 'bp-del-link') addOps([{ op: 'remove_link', id: b.dataset.id }]);
    });
    $('bpFindings').addEventListener('click', (e) => {
        const b = e.target.closest('[data-action="bp-edit-proposal"]');
        if (!b) return;
        const f = bpFindings[+b.dataset.f];
        const j = +b.dataset.o;
        openOpEditor(f.proposal[j], (next) => { f.proposal[j] = next; renderFindings(); return true; });
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
