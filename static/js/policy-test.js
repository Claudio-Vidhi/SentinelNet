// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// -*- coding: utf-8 -*-
// ===== Policy & Route Validation =====
// Pure evaluation and offline reachability tracing against device backups.

(function () {
    let ptActiveSubtab = 'tracer';
    let ptSelectedIp = null;
    let ptExamplesCache = {};
    let ptFindingsCache = {};
    let ptMetaCache = {};
    let ptRenderedFindings = [];
    let ptLastWhatIf = null;
    let ptWiChangedOnly = true;
    let ptExCatchAllOnly = false;
    let ptExUnparsedOnly = false;

    async function loadPolicyTestTab() {
        const pending = window.ptPendingContext;
        if (pending) window.ptPendingContext = null;

        populatePolicyTenantSelect();
        if (pending && pending.tenant) {
            const tenantSel = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptTenantSelect'));
            if (tenantSel && Array.from(tenantSel.options).some(o => o.value === pending.tenant)) {
                tenantSel.value = pending.tenant;
            }
        }
        if (pending && pending.subtab) {
            ptActiveSubtab = pending.subtab;
        }
        populatePolicyDeviceSelect();

        if (pending && pending.device_ip) {
            const devSel = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptDeviceSelect'));
            if (devSel && Array.from(devSel.options).some(o => o.value === pending.device_ip)) {
                devSel.value = pending.device_ip;
                ptSelectedIp = pending.device_ip;
            }
        }
        switchPolicySubtab(ptActiveSubtab);
        if (ptSelectedIp) {
            await loadDeviceMetadata(ptSelectedIp);
        } else {
            updateDeviceMeta();
        }
        if (pending) {
            if (pending.subtab === 'whatif') {
                const flowsEl = /** @type {HTMLTextAreaElement|null} */ (document.getElementById('ptWiCustomFlows'));
                if (flowsEl && pending.src_ip && pending.dst_ip) {
                    flowsEl.value = `${pending.src_ip},${pending.dst_ip},${pending.proto || 'tcp'},${pending.dport || ''}`;
                }
            } else {
                const sEl = /** @type {HTMLInputElement|null} */ (document.getElementById('ptSrcIp'));
                const dEl = /** @type {HTMLInputElement|null} */ (document.getElementById('ptDstIp'));
                const pEl = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptProto'));
                const dpEl = /** @type {HTMLInputElement|null} */ (document.getElementById('ptDport'));
                if (sEl && pending.src_ip) sEl.value = pending.src_ip;
                if (dEl && pending.dst_ip) dEl.value = pending.dst_ip;
                if (pEl && pending.proto) pEl.value = String(pending.proto).toLowerCase();
                if (dpEl && pending.dport) dpEl.value = String(pending.dport);
                if (pending.autoRun && pending.src_ip && pending.dst_ip && ptSelectedIp) {
                    runPolicyTrace();
                }
            }
        }
        renderPolicySelectionState();
    }

    function populatePolicyTenantSelect() {
        const sel = document.getElementById('ptTenantSelect');
        if (!sel) return;
        const L = i18n[currentLang];
        const cur = sel.value;
        // globalGroups is declared `let` in core.js, so it is NOT a window
        // property: reading it as window.globalGroups yields undefined and the
        // usual `|| {}` fallback hides it. Read the bare identifier.
        const groups = Object.keys(globalGroups || {});
        sel.innerHTML = `<option value="">${escapeHtml(L.ptChooseTenant)}</option>` +
            groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(orgLabel(g))}</option>`).join('');
        sel.value = tenantSelectSeed(cur, groups, '');
    }

    function policyTenant() {
        const sel = document.getElementById('ptTenantSelect');
        return sel ? sel.value : '';
    }

    // Firewalls are excluded from this tab. Their live equivalents answer
    // authoritatively from the box (policy-lookup and the FIB route lookup in
    // FortiGate Management), while an offline trace over a backup cannot
    // resolve interface-derived address objects or dynamically learned routes
    // and lands on UNKNOWN. Two answers to the same question, one of them
    // structurally worse, is how an operator ends up trusting the wrong one.
    const PT_FIREWALL_VENDORS = ['fortinet', 'fortigate', 'paloalto', 'panos'];

    function ptIsFirewall(d) {
        return PT_FIREWALL_VENDORS.includes(
            String(d.Vendor || d.Type || '').toLowerCase());
    }

    function populatePolicyDeviceSelect() {
        const sel = document.getElementById('ptDeviceSelect');
        if (!sel) return;
        const L = i18n[currentLang];
        const tenant = policyTenant();
        const cur = sel.value;

        if (!tenant) {
            // No tenant, no device list. A flat list across every tenant puts
            // several customers' devices in one dropdown; on the estate this
            // product is built for that is a disclosure, not a convenience.
            sel.innerHTML = `<option value="">${escapeHtml(L.ptChooseTenantFirst)}</option>`;
            sel.disabled = true;
            ptSelectedIp = null;
            updateDeviceMeta();
            return;
        }

        const inTenant = (globalDevices || []).filter(
            d => (d.Group || '') === tenant);
        const includeFirewalls = (ptActiveSubtab === 'whatif');
        const devices = includeFirewalls
            ? inTenant
            : inTenant.filter(d => !ptIsFirewall(d));
        const hiddenFirewalls = inTenant.length - devices.length;
        sel.disabled = devices.length === 0;

        if (devices.length === 0) {
            const msg = hiddenFirewalls ? L.ptOnlyFirewallsInTenant : L.ptNoDevicesInTenant;
            sel.innerHTML = `<option value="">${escapeHtml(msg)}</option>`;
            ptSelectedIp = null;
            updateDeviceMeta();
            return;
        }

        // Deliberately NOT auto-selecting devices[0]. Landing on the tab and
        // finding a verdict already computed for a device nobody picked reads
        // as a statement about that device.
        sel.innerHTML = `<option value="">${escapeHtml(L.ptChooseDevice)}</option>` +
            devices.map(d => {
                const ip = d.IP || '';
                const host = d.Hostname || ip;
                const vendor = (d.Vendor || d.Type || 'cisco').toUpperCase();
                return `<option value="${escapeHtml(ip)}">${escapeHtml(host)} (${escapeHtml(ip)}) — ${escapeHtml(vendor)}</option>`;
            }).join('') +
            // Say that something was removed. A device silently missing from a
            // dropdown reads as a bug in the inventory, not as a decision.
            (hiddenFirewalls
                ? `<option value="" disabled>${escapeHtml(
                     L.ptFirewallsHidden.replace('{n}', String(hiddenFirewalls)))}</option>`
                : '');
        sel.value = devices.some(d => d.IP === cur) ? cur : '';
        ptSelectedIp = sel.value || null;
        const fwBanner = document.getElementById('ptFirewallNotice');
        const fwBannerText = document.getElementById('ptFirewallNoticeText');
        if (fwBanner && fwBannerText) {
            fwBanner.hidden = hiddenFirewalls <= 0;
            if (hiddenFirewalls > 0) {
                fwBannerText.textContent = tr('ptFirewallsBanner', { n: hiddenFirewalls });
            }
        }
        updateDeviceMeta(ptSelectedIp ? ptMetaCache[ptSelectedIp] : null);
    }

    /** Placeholder in every panel until a tenant AND a device are chosen.
     *  Returns true when it painted, i.e. when there is nothing to show yet. */
    function renderPolicySelectionState() {
        const badge = document.getElementById('ptFindingsBadge');
        if (badge) {
            const cachedFindings = ptSelectedIp ? ptFindingsCache[ptSelectedIp] : null;
            badge.hidden = !(cachedFindings && cachedFindings.length > 0);
            if (cachedFindings) badge.textContent = String(cachedFindings.length);
        }
        if (ptSelectedIp) return false;
        const L = i18n[currentLang];
        const msg = !policyTenant() ? L.ptChooseTenantFirst : L.ptChooseDeviceFirst;
        const empty = `<div style="text-align:center; padding:40px 20px; color:var(--text-muted);">
            <i class="fa-solid fa-hand-pointer fa-2x" style="margin-bottom:12px; opacity:0.4;"></i>
            <div style="font-size:13px;">${escapeHtml(msg)}</div>
        </div>`;
        ['ptTraceResultsContainer', 'ptExamplesContainer', 'ptFindingsContainer', 'ptWhatIfResultContainer']
            .forEach(id => {
                const el = document.getElementById(id);
                if (el) el.innerHTML = empty;
            });
        const cart = document.getElementById('ptFindingsCartouche');
        if (cart) cart.hidden = true;
        return true;
    }

    function populateDatalists(meta) {
        const fill = (id, items) => {
            const dl = document.getElementById(id);
            if (!dl) return;
            dl.replaceChildren(...items.map(({ value, label }) => {
                const opt = document.createElement('option');
                opt.value = value;
                if (label) opt.label = label;
                return opt;
            }));
        };
        if (!meta) {
            ['ptIntfList', 'ptAclList', 'ptRuleList', 'ptRouteList'].forEach(id => fill(id, []));
            return;
        }
        fill('ptIntfList', (meta.interfaces || []).map(itf => ({
            value: itf.name,
            label: [itf.ip, itf.zone ? `zone:${itf.zone}` : '', itf.acl_in ? `in:${itf.acl_in}` : '', itf.acl_out ? `out:${itf.acl_out}` : ''].filter(Boolean).join(' · '),
        })));
        fill('ptAclList', (meta.acls || []).map(a => ({
            value: a.name === 'firewall_policy' ? '' : a.name,
            label: `${a.name} (${a.rule_count})`,
        })).filter(x => x.value));
        fill('ptRuleList', (meta.rules || []).map(r => ({
            value: r.id,
            label: `${r.acl !== 'firewall_policy' ? r.acl + ' · ' : ''}#${r.id}${r.name ? ' ' + r.name : ''} (${r.action})`,
        })));
        fill('ptRouteList', (meta.static_routes || []).map(r => ({
            value: r.prefix,
            label: `${r.next_hop || r.interface || 'direct'} · AD ${r.distance}${r.vrf ? ' · VRF ' + r.vrf : ''}`,
        })));
    }

    async function loadDeviceMetadata(ip) {
        if (!ip) {
            populateDatalists(null);
            updateDeviceMeta(null);
            return;
        }
        if (ptMetaCache[ip]) {
            populateDatalists(ptMetaCache[ip]);
            updateDeviceMeta(ptMetaCache[ip]);
            return;
        }
        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ip)}/metadata`);
            if (res && res.ok) {
                const meta = await res.json();
                ptMetaCache[ip] = meta;
                if (ptSelectedIp === ip) {
                    populateDatalists(meta);
                    updateDeviceMeta(meta);
                }
            }
        } catch (e) { /* keep basic inventory badges */ }
    }

    function updateDeviceMeta(meta) {
        const metaEl = document.getElementById('ptDeviceMeta');
        if (!metaEl) return;
        const dev = ptSelectedIp
            ? (globalDevices || []).find(d => d.IP === ptSelectedIp) : null;
        if (!dev) { metaEl.innerHTML = ''; return; }
        const group = dev.Group || '';
        const vendor = (dev.Vendor || dev.Type || 'cisco').toUpperCase();
        const chips = [
            `<span class="badge">${escapeHtml(tr('ptTenantLabel'))}: ${escapeHtml(group)}</span>`,
            `<span class="badge">Vendor: ${escapeHtml(vendor)}</span>`,
        ];
        if (meta) {
            if (meta.config_type) {
                chips.push(`<span class="badge">${escapeHtml(tr('ptConfigTypeBadge'))}: ${escapeHtml(String(meta.config_type).toUpperCase())}</span>`);
            }
            const tsLabel = meta.backup_ts
                ? tr('ptBackupMeta', { at: new Date(meta.backup_ts * 1000).toLocaleString() })
                : tr('ptBackupUnknown');
            chips.push(`<span class="badge">${escapeHtml(tsLabel)}</span>`);
            if (meta.dynamic_routing_present) {
                const protos = (meta.protocols || []).join(', ');
                chips.push(`<span class="badge badge-warning">${escapeHtml(tr('ptDynRoutingChip'))}${protos ? ` (${escapeHtml(protos)})` : ''}</span>`);
            }
        }
        metaEl.innerHTML = chips.join(' ');
    }

    function switchPolicySubtab(subtab) {
        const wasWhatIf = (ptActiveSubtab === 'whatif');
        const isWhatIf = (subtab === 'whatif');
        ptActiveSubtab = subtab;
        document.querySelectorAll('#ptSubtabNav button').forEach(b => {
            b.classList.toggle('active', b.dataset.subtab === subtab);
        });

        const tracerEl = document.getElementById('ptSubtabTracer');
        const examplesEl = document.getElementById('ptSubtabExamples');
        const findingsEl = document.getElementById('ptSubtabFindings');
        const whatifEl = document.getElementById('ptSubtabWhatIf');

        if (tracerEl) tracerEl.style.display = (subtab === 'tracer') ? '' : 'none';
        if (examplesEl) examplesEl.style.display = (subtab === 'examples') ? '' : 'none';
        if (findingsEl) findingsEl.style.display = (subtab === 'findings') ? '' : 'none';
        if (whatifEl) whatifEl.style.display = isWhatIf ? '' : 'none';

        if (wasWhatIf !== isWhatIf) {
            populatePolicyDeviceSelect();
        }

        if (renderPolicySelectionState()) return;

        if (subtab === 'examples' && !ptExamplesCache[ptSelectedIp]) {
            loadPolicyExamples();
        } else if (subtab === 'findings' && !ptFindingsCache[ptSelectedIp]) {
            loadPolicyFindings();
        } else if (subtab === 'whatif') {
            syncWhatIfFields();
            const wiBox = document.getElementById('ptWhatIfResultContainer');
            if (wiBox && !wiBox.dataset.hasResult) {
                wiBox.innerHTML = `<div style="text-align:center; padding:40px 20px; color:var(--text-muted); font-size:13px;">
                    <i class="fa-solid fa-code-branch fa-2x" style="margin-bottom:12px; opacity:0.4;"></i>
                    <div>${escapeHtml(tr('ptWiNoResult'))}</div>
                </div>`;
            }
        }
    }

    async function runPolicyTrace() {
        if (!ptSelectedIp) {
            showToast(policyTenant() ? tr('ptChooseDeviceFirst')
                                     : tr('ptChooseTenantFirst'), 'warning');
            return;
        }

        const srcIp = (document.getElementById('ptSrcIp')?.value || '').trim();
        const dstIp = (document.getElementById('ptDstIp')?.value || '').trim();
        const proto = (document.getElementById('ptProto')?.value || 'tcp').trim();
        const dportRaw = (document.getElementById('ptDport')?.value || '').trim();
        const sportRaw = (document.getElementById('ptSport')?.value || '').trim();
        const ingress = (document.getElementById('ptIngressIntf')?.value || '').trim() || null;
        const egress = (document.getElementById('ptEgressIntf')?.value || '').trim() || null;
        const established = !!document.getElementById('ptEstablished')?.checked;
        const icmpTypeRaw = (document.getElementById('ptIcmpType')?.value || '').trim();

        if (!srcIp || !dstIp) {
            showToast(tr('ptNeedSrcDst'), 'warning');
            return;
        }

        const container = document.getElementById('ptTraceResultsContainer');
        if (container) {
            container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><div style="margin-top:10px;">${escapeHtml(tr('ptLoadingTrace'))}</div></div>`;
        }

        const payload = {
            src_ip: srcIp,
            dst_ip: dstIp,
            proto: proto,
            dport: dportRaw ? parseInt(dportRaw, 10) : null,
            sport: sportRaw ? parseInt(sportRaw, 10) : null,
            ingress_intf: ingress,
            egress_intf: egress,
            established: established,
            // Only meaningful for ICMP, and only when the operator picked a
            // message: left unset the engine cannot tell an echo from a reply.
            icmp_type: (proto === 'icmp' && icmpTypeRaw) ? parseInt(icmpTypeRaw, 10) : null,
        };

        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ptSelectedIp)}/trace`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            if (!res || !res.ok) {
                const errData = res ? await res.json().catch(() => ({})) : {};
                if (container) {
                    container.innerHTML = `<div class="panel" style="padding:16px; background:var(--lamp-fault-wash); border-color:var(--danger);"><i class="fa-solid fa-triangle-exclamation" style="color:var(--danger);"></i> <strong>${escapeHtml(tr('ptErrorPrefix'))}</strong> ${escapeHtml(errData.detail || tr('ptTraceErrGeneric'))}</div>`;
                }
                return;
            }

            const trace = await res.json();
            renderTraceResult(trace);
        } catch (e) {
            if (container) {
                container.innerHTML = `<div class="panel" style="padding:16px; background:var(--lamp-fault-wash); border-color:var(--danger);"><i class="fa-solid fa-triangle-exclamation" style="color:var(--danger);"></i> ${escapeHtml(tr('ptTraceNetErr'))}</div>`;
            }
        }
    }

    function stepKindTitle(kind) {
        if (kind === 'acl_in') return tr('ptPipelineAclIn');
        if (kind === 'route') return tr('ptPipelineRoute');
        if (kind === 'acl_out') return tr('ptPipelineAclOut');
        if (kind === 'policy') return tr('ptPipelinePolicy');
        if (kind === 'skipped_policy') return tr('ptPipelineSkipped');
        return kind || '';
    }

    function renderTraceResult(trace) {
        const container = document.getElementById('ptTraceResultsContainer');
        if (!container) return;

        const verdict = trace.verdict || 'UNKNOWN';
        let vColor = 'var(--text-muted)';
        let vBg = 'var(--surface-2)';
        let vBorder = 'var(--border)';
        let vIcon = 'fa-circle-question';

        if (verdict === 'PERMIT') {
            vColor = 'var(--lamp-up-ink)';
            vBg = 'var(--lamp-up-wash)';
            vBorder = 'var(--lamp-up-ink)';
            vIcon = 'fa-circle-check';
        } else if (verdict === 'DENY') {
            vColor = 'var(--lamp-fault-ink)';
            vBg = 'var(--lamp-fault-wash)';
            vBorder = 'var(--lamp-fault-ink)';
            vIcon = 'fa-circle-xmark';
        } else if (verdict === 'UNKNOWN') {
            vColor = 'var(--lamp-warn-ink)';
            vBg = 'var(--lamp-warn-wash)';
            vBorder = 'var(--lamp-warn-ink)';
            vIcon = 'fa-triangle-exclamation';
        }

        let html = `
        <div style="display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-radius:var(--radius); border:1px solid ${vBorder}; background:${vBg}; margin-bottom:18px;">
            <div style="display:flex; align-items:center; gap:14px;">
                <i class="fa-solid ${vIcon} fa-2x" style="color:${vColor};"></i>
                <div>
                    <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--text-muted);">${escapeHtml(tr('ptVerdictLabel'))}</div>
                    <div style="font-family:var(--font-legend); font-size:21px; font-weight:600; letter-spacing:0.06em; color:${vColor};">${escapeHtml(verdict)}</div>
                </div>
            </div>
            <div>
                ${trace.nat_applied ? `<span class="badge" style="background:var(--primary); color:var(--on-lamp);"><i class="fa-solid fa-arrows-split-up-and-left"></i> ${escapeHtml(tr('ptSourceNatActive'))}</span>` : ''}
            </div>
        </div>`;

        if (trace.dynamic_routing_present) {
            html += `
            <div style="padding:10px 14px; margin-bottom:16px; border:1px solid var(--warning); background:var(--lamp-warn-wash); color:var(--lamp-warn-ink); font-size:12px; display:flex; align-items:center; gap:10px; border-radius:var(--radius);">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>${escapeHtml(tr('ptDynamicRoutingWarning'))}</span>
            </div>`;
        }

        // The reasons behind an UNKNOWN verdict.
        const unresolved = trace.unresolved || [];
        if (unresolved.length) {
            html += `
            <div style="padding:10px 14px; margin-bottom:16px; border:1px solid var(--warning); background:var(--lamp-warn-wash); font-size:12px; border-radius:var(--radius);">
                <div style="font-weight:600; margin-bottom:6px; color:var(--lamp-warn-ink);">
                    <i class="fa-solid fa-circle-question"></i> ${escapeHtml(tr('ptUnresolvedTitle'))}
                </div>
                <ul style="margin:0; padding-left:18px; color:var(--text);">
                    ${unresolved.map(u => `<li>${escapeHtml(u)}</li>`).join('')}
                </ul>
            </div>`;
        }

        const steps = trace.steps || [];
        const routeStep = steps.find(s => s.kind === 'route');
        const ingressLabel = (document.getElementById('ptIngressIntf')?.value || (trace.flow && trace.flow.ingress_intf) || tr('ptAutoLabel')).trim();
        const egressLabel = (routeStep && routeStep.egress) || (trace.flow && trace.flow.egress_intf) || '';

        // Dynamic visual flowchart pipeline derived strictly from actual trace.steps
        const pipeNodes = [
            `<div class="pt-pipeline-node">
                <div class="pt-pipeline-node-title"><i class="fa-solid fa-arrow-right-to-bracket" style="color:var(--primary);"></i> ${escapeHtml(tr('ptPipelineIngress'))}</div>
                <div class="pt-pipeline-node-body"><code>${escapeHtml(ingressLabel)}</code></div>
            </div>`,
        ];
        steps.forEach(step => {
            const act = String(step.action || '').toLowerCase();
            const stateCls = act === 'permit' ? 'is-permit' : (act === 'deny' ? 'is-deny' : (act === 'unknown' ? 'is-unknown' : ''));
            let bodyText;
            if (step.kind === 'route') {
                const hop = step.next_hop || tr('ptConnectedLabel');
                bodyText = `${hop} ${tr('ptViaLabel')} ${step.egress || tr('ptAutoLabel')}${step.prefix ? ` (${step.prefix})` : ''}`;
            } else {
                bodyText = `${step.acl ? `[${step.acl}] ` : ''}${step.rule_id ? `Rule ${step.rule_id}: ` : ''}${step.raw_text || step.action || tr('ptDefaultDecision')}`;
            }
            pipeNodes.push(`<div class="pt-pipeline-node ${stateCls}">
                <div class="pt-pipeline-node-title">${escapeHtml(stepKindTitle(step.kind))}</div>
                <div class="pt-pipeline-node-body">${escapeHtml(bodyText)}</div>
            </div>`);
        });
        if (trace.nat_applied) {
            pipeNodes.push(`<div class="pt-pipeline-node is-nat">
                <div class="pt-pipeline-node-title" style="color:var(--cond-a);"><i class="fa-solid fa-shuffle"></i> ${escapeHtml(tr('ptPipelineNat'))}</div>
                <div class="pt-pipeline-node-body"><code>${escapeHtml(tr('ptSourceNatActive'))}</code></div>
            </div>`);
        }
        const vNodeCls = verdict === 'PERMIT' ? 'is-permit' : (verdict === 'DENY' ? 'is-deny' : 'is-unknown');
        pipeNodes.push(`<div class="pt-pipeline-node ${vNodeCls}">
            <div class="pt-pipeline-node-title" style="color:${vColor};"><i class="fa-solid ${vIcon}"></i> ${escapeHtml(tr('ptPipelineVerdict'))}</div>
            <div class="pt-pipeline-node-body" style="font-weight:700; font-size:15px; color:${vColor}; letter-spacing:0.05em;">${escapeHtml(verdict)}</div>
        </div>`);
        if (verdict !== 'DENY' && egressLabel) {
            pipeNodes.push(`<div class="pt-pipeline-node">
                <div class="pt-pipeline-node-title"><i class="fa-solid fa-arrow-right-from-bracket" style="color:var(--lamp-up-ink);"></i> ${escapeHtml(tr('ptPipelineEgress'))}</div>
                <div class="pt-pipeline-node-body"><code>${escapeHtml(egressLabel)}</code></div>
            </div>`);
        }

        html += `<div class="pt-pipeline">${pipeNodes.join('<div class="pt-pipeline-connector"><i class="fa-solid fa-arrow-down" aria-hidden="true"></i></div>')}</div>`;

        if (steps.length > 0) {
            html += `<h4 style="margin:20px 0 10px; font-size:14px; font-weight:700;"><i class="fa-solid fa-list-ol" style="color:var(--primary); margin-right:6px;"></i> ${escapeHtml(tr('ptStepsTitle'))}</h4>`;
            html += `<div style="display:flex; flex-direction:column; gap:10px;">`;
            steps.forEach((step, idx) => {
                let stepBadge = step.action || '';
                let badgeClass = 'badge';
                let stepWash = 'var(--lamp-idle-wash)';
                let stepRule = 'var(--border)';

                if (step.action === 'permit') {
                    badgeClass = 'badge badge-success';
                    stepWash = 'var(--lamp-up-wash)';
                    stepRule = 'var(--lamp-up-ink)';
                } else if (step.action === 'deny') {
                    badgeClass = 'badge badge-danger';
                    stepWash = 'var(--lamp-fault-wash)';
                    stepRule = 'var(--lamp-fault-ink)';
                } else if (step.action === 'unknown') {
                    badgeClass = 'badge badge-warning';
                    stepWash = 'var(--lamp-warn-wash)';
                    stepRule = 'var(--lamp-warn-ink)';
                }

                const kindLabel = stepKindTitle(step.kind);

                html += `
                <div style="border:1px solid ${stepRule}; background:${stepWash}; padding:12px 16px; border-radius:var(--radius);">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <div style="font-weight:600; font-size:13px;">
                            <span style="color:var(--text-muted); margin-right:6px;">#${idx + 1}</span>
                            <strong>${escapeHtml(kindLabel)}</strong>
                            ${step.acl ? `<span style="font-size:11px; color:var(--text-muted); margin-left:6px;">(${escapeHtml(step.acl)})</span>` : ''}
                            ${step.rule_id ? `<span style="font-size:11px; color:var(--text-muted); margin-left:4px;">[Rule: ${escapeHtml(step.rule_id)}]</span>` : ''}
                        </div>
                        <div>
                            ${stepBadge ? `<span class="${badgeClass}">${escapeHtml(stepBadge.toUpperCase())}</span>` : ''}
                        </div>
                    </div>
                    ${step.raw_text ? `<div style="font-family:var(--font-data); font-size:12.5px; background:var(--surface); padding:6px 10px; margin-top:6px; border:1px solid var(--border);">${escapeHtml(step.raw_text)}</div>` : ''}
                    ${step.prefix ? `<div style="font-size:12px; margin-top:4px;">${escapeHtml(tr('ptNextHopLabel'))}: <code>${escapeHtml(step.next_hop || tr('ptConnectedLabel'))}</code> ${escapeHtml(tr('ptViaLabel'))} <code>${escapeHtml(step.egress || tr('ptAutoLabel'))}</code> <span style="color:var(--text-muted);">${escapeHtml(tr('ptPrefixLabel'))}</span> <code>${escapeHtml(step.prefix)}</code></div>` : ''}
                    ${step.note ? `<div style="font-size:11px; color:var(--text-muted); margin-top:4px;"><i class="fa-solid fa-circle-info"></i> ${escapeHtml(step.note)}</div>` : ''}
                </div>`;
            });
            html += `</div>`;
        }

        container.innerHTML = html;
    }

    async function loadPolicyExamples() {
        if (!ptSelectedIp) return;
        const container = document.getElementById('ptExamplesContainer');
        if (container) {
            container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><div style="margin-top:10px;">${escapeHtml(tr('ptLoadingExamples'))}</div></div>`;
        }

        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ptSelectedIp)}/examples`);
            if (!res || !res.ok) {
                if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">${escapeHtml(tr('ptExamplesErr'))}</div>`;
                return;
            }
            const examples = await res.json();
            ptExamplesCache[ptSelectedIp] = examples;
            syncExamplesAclFilter(examples);
            renderExamples(examples);
        } catch (e) {
            if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">${escapeHtml(tr('ptExamplesNetErr'))}</div>`;
        }
    }

    function syncExamplesAclFilter(groups) {
        const sel = /** @type {HTMLSelectElement|null} */ (document.getElementById('ptExAclFilter'));
        if (!sel) return;
        const cur = sel.value;
        sel.innerHTML = `<option value="">${escapeHtml(tr('ptFilterAllAcls'))}</option>`
            + (groups || []).map(g => `<option value="${escapeHtml(g.name)}">${escapeHtml(g.name)}</option>`).join('');
        if ((groups || []).some(g => g.name === cur)) sel.value = cur;
    }

    function renderExamples(groups) {
        const container = document.getElementById('ptExamplesContainer');
        if (!container) return;
        const L = i18n[currentLang];

        if (!groups || groups.length === 0) {
            container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);">${escapeHtml(L.ptNoExamples)}</div>`;
            return;
        }

        // Said once, up front: these flows are synthesised from the rules, not
        // captured off the wire. Without it a reader can take a generated
        // 5-tuple for observed traffic.
        let html = `
        <div style="display:flex; align-items:flex-start; gap:10px; padding:10px 14px; margin-bottom:18px; border:var(--seam) solid var(--border-strong); background:var(--surface-2); font-size:13px; line-height:1.5;">
            <i class="fa-solid fa-flask" style="color:var(--text-soft); margin-top:2px;"></i>
            <span>${escapeHtml(L.ptExamplesCaption)}</span>
        </div>`;

        const searchVal = (document.getElementById('ptExSearch')?.value || '').trim().toLowerCase();
        const aclVal = (document.getElementById('ptExAclFilter')?.value || '').trim();
        const actVal = (document.getElementById('ptExActionFilter')?.value || '').trim().toLowerCase();

        // Grouped per rule set. A device carries several ACLs whose sequence
        // numbers each restart at 10, so a flat list of "Regola 10" cards left
        // the reader no way to tell which ACL a rule belonged to.
        let renderedSections = 0;
        groups.forEach(group => {
            if (aclVal && group.name !== aclVal) return;
            const bindings = group.bindings || [];
            const allExamples = group.examples || [];
            const examples = allExamples.filter(ex => {
                if (actVal && String(ex.action || '').toLowerCase() !== actVal) return false;
                if (ptExCatchAllOnly && !ex.matches_all) return false;
                if (ptExUnparsedOnly && ex.matching_flow) return false;
                if (searchVal) {
                    const mf = ex.matching_flow || {};
                    const hay = `${group.name} ${ex.rule_id || ''} ${ex.rule_name || ''} ${ex.raw_text || ''} ${mf.src_ip || ''} ${mf.dst_ip || ''} ${mf.dport || ''}`.toLowerCase();
                    if (!hay.includes(searchVal)) return false;
                }
                return true;
            });
            if (!examples.length) return;
            renderedSections += 1;
            const aclOptName = group.kind === 'firewall_policy' ? '' : (group.name || '');
            // Where an ACL is applied is the context that makes every rule
            // under it readable: "governs traffic entering Vlan10" is the
            // difference between a list of ACEs and an understandable policy.
            // It gets real size, not fine print.
            const bindingRow = bindings.length
                ? bindings.map(b => `
                    <span style="display:inline-flex; align-items:center; gap:7px; margin-right:14px;">
                        <span class="badge">${escapeHtml(b.direction === 'in' ? L.ptDirIn : L.ptDirOut)}</span>
                        <code style="font-size:13px;">${escapeHtml(b.interface)}</code>
                    </span>`).join('')
                : `<span style="color:var(--warning);"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(L.ptAclNotApplied)}</span>`;
            const boundIngress = (bindings.find(b => b.direction === 'in') || {}).interface || '';

            html += `
            <section style="margin-bottom:26px;">
                <div style="padding:10px 0 12px; border-bottom:var(--seam) solid var(--border-strong); margin-bottom:14px;">
                    <div style="display:flex; align-items:baseline; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                        <span style="font-family:var(--font-legend); font-size:17px; font-weight:600; letter-spacing:0.02em; text-transform:uppercase;">${escapeHtml(group.name)}</span>
                        <span style="font-family:var(--font-legend); font-size:10px; letter-spacing:0.16em; text-transform:uppercase; color:var(--text-soft);">
                            ${examples.length}/${allExamples.length} ${escapeHtml(L.ptRulesWord)} &middot; ${escapeHtml(L.ptDefaultWord)} ${escapeHtml(group.default_action || 'deny')}
                        </span>
                    </div>
                    ${group.declaration ? `<div style="margin-top:5px; font-family:var(--font-data); font-size:12.5px; color:var(--text-muted);">${escapeHtml(group.declaration)}</div>` : ''}
                    <div style="margin-top:7px; font-size:13px; color:var(--text);">${bindingRow}</div>
                </div>
                <div style="display:grid; grid-template-columns:repeat(auto-fill, minmax(420px, 1fr)); gap:16px;">`;

            examples.forEach(ex => {
                const mf = ex.matching_flow;
                const nm = ex.near_miss_flow;

                // An unparseable rule has no example: its coverage is unknown,
                // so no flow can be claimed to match it.
                if (!mf) {
                    html += `
                    <div style="border:var(--seam) solid var(--warning); background:var(--lamp-warn-wash); padding:14px;">
                        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
                            <span style="font-weight:600; font-size:13px;">${escapeHtml(L.ptRuleWord)} ${escapeHtml(ex.rule_id)}</span>
                            <span class="badge badge-warning">${escapeHtml(L.ptNotParsed)}</span>
                        </div>
                        ${ex.raw_text ? `<div style="font-family:var(--font-data); font-size:11px; background:var(--surface); padding:6px 8px; border:1px solid var(--border); margin-bottom:8px; word-break:break-all;">${escapeHtml(ex.raw_text)}</div>` : ''}
                        <div style="font-size:11px; color:var(--text-muted);"><i class="fa-solid fa-circle-info"></i> ${escapeHtml(ex.near_miss_reason || L.ptCoverageUnknown)}</div>
                    </div>`;
                    return;
                }

                const mfDport = mf.dport ? `:${mf.dport}` : '';
                const nmDport = nm && nm.dport ? `:${nm.dport}` : '';
                const mfIngress = mf.ingress_intf || boundIngress;
                const nmIngress = (nm && nm.ingress_intf) || boundIngress;

                // A rule with every field ANY matches everything. Printing one
                // arbitrary 5-tuple beside it reads as a claim about that
                // traffic specifically, so the card leads with what the rule
                // actually does and labels the flow as one illustration.
                const catchAll = !!ex.matches_all;

                html += `
                <div style="border:1px solid var(--border); background:var(--surface-2); padding:14px; display:flex; flex-direction:column; justify-content:space-between;">
                    <div>
                        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
                            <div>
                                <span style="font-weight:600; font-size:13px;">${escapeHtml(L.ptRuleWord)} ${escapeHtml(ex.rule_id)}</span>
                                ${ex.rule_name ? `<span style="font-size:12px; color:var(--text-muted); margin-left:6px;">${escapeHtml(ex.rule_name)}</span>` : ''}
                            </div>
                            <span class="badge ${ex.action === 'permit' ? 'badge-success' : 'badge-danger'}">${escapeHtml((ex.action || '').toUpperCase())}</span>
                        </div>
                        ${ex.raw_text ? `<div style="font-family:var(--font-data); font-size:11px; background:var(--surface); padding:6px 8px; border:1px solid var(--border); margin-bottom:10px; word-break:break-all;">${escapeHtml(ex.raw_text)}</div>` : ''}

                        ${catchAll ? `
                        <div style="display:flex; align-items:flex-start; gap:8px; padding:8px 10px; margin-bottom:8px; background:var(--lamp-warn-wash); border-left:1px solid var(--warning); font-size:12px;">
                            <i class="fa-solid fa-circle-exclamation" style="color:var(--warning); margin-top:2px;"></i>
                            <span><strong>${escapeHtml(L.ptMatchesAll)}</strong></span>
                        </div>` : ''}

                        <div style="font-size:12px; margin-bottom:6px;">
                            <span class="badge badge-success" style="margin-right:4px;">${escapeHtml(catchAll ? L.ptExampleWord : L.ptMatching)}</span>
                            <code>${escapeHtml(mf.src_ip)}</code> &rarr; <code>${escapeHtml(mf.dst_ip)}${escapeHtml(mfDport)}</code> <span style="color:var(--text-muted);">(${escapeHtml(ptFlowProto(mf))})</span>
                            ${catchAll ? `<div style="font-size:11px; color:var(--text-muted); margin-top:2px;">${escapeHtml(L.ptArbitraryExample)}</div>` : ''}
                        </div>

                        ${nm ? `
                        <div style="font-size:12px; margin-bottom:6px;">
                            <span class="badge badge-warning" style="margin-right:4px;">${escapeHtml(L.ptNearMiss)}</span>
                            <code>${escapeHtml(nm.src_ip)}</code> &rarr; <code>${escapeHtml(nm.dst_ip)}${escapeHtml(nmDport)}</code> <span style="color:var(--text-muted);">(${escapeHtml(ptFlowProto(nm))})</span>
                        </div>` : ''}

                        ${(!catchAll && ex.near_miss_reason) ? `<div style="font-size:11px; color:var(--text-muted); margin-top:2px;"><i class="fa-solid fa-circle-info"></i> ${escapeHtml(ex.near_miss_reason)}</div>` : ''}
                    </div>

                    <div style="margin-top:12px; display:flex; justify-content:flex-end; gap:8px; flex-wrap:wrap;">
                        <button type="button" class="btn btn-secondary btn-small" data-action="example-to-whatif"
                            data-acl="${escapeHtml(aclOptName)}"
                            data-rule="${escapeHtml(ex.rule_id || '')}"
                            data-flow="${escapeHtml(`${mf.src_ip},${mf.dst_ip},${mf.proto || 'tcp'},${mf.dport || ''}`)}"
                            style="width:auto; margin:0;">
                            <i class="fa-solid fa-code-branch"></i> ${escapeHtml(tr('ptSimulateInWhatIf'))}
                        </button>
                        <button class="btn btn-secondary btn-small" data-action="use-example"
                            data-src="${escapeHtml(mf.src_ip)}"
                            data-dst="${escapeHtml(mf.dst_ip)}"
                            data-proto="${escapeHtml(mf.proto || 'tcp')}"
                            data-dport="${escapeHtml(mf.dport || '')}"
                            data-sport="${escapeHtml(mf.sport || '')}"
                            data-ingress="${escapeHtml(mfIngress)}"
                            data-est="${mf.established ? '1' : '0'}"
                            data-icmp="${mf.icmp_type === null || mf.icmp_type === undefined ? '' : mf.icmp_type}"
                            style="width:auto; margin:0;">
                            <i class="fa-solid fa-arrow-right-to-bracket"></i> ${escapeHtml(L.ptUseInTracer)}
                        </button>
                        ${nm ? `
                        <button class="btn btn-secondary btn-small" data-action="use-example"
                            data-src="${escapeHtml(nm.src_ip)}"
                            data-dst="${escapeHtml(nm.dst_ip)}"
                            data-proto="${escapeHtml(nm.proto || 'tcp')}"
                            data-dport="${escapeHtml(nm.dport || '')}"
                            data-sport="${escapeHtml(nm.sport || '')}"
                            data-ingress="${escapeHtml(nmIngress)}"
                            data-est="${nm.established ? '1' : '0'}"
                            data-icmp="${nm.icmp_type === null || nm.icmp_type === undefined ? '' : nm.icmp_type}"
                            style="width:auto; margin:0;">
                            <i class="fa-solid fa-crosshairs"></i> ${escapeHtml(L.ptTryNearMiss)}
                        </button>` : ''}
                    </div>
                </div>`;
            });

            html += `</div></section>`;
        });

        if (renderedSections === 0) {
            html += `<div style="text-align:center; padding:30px; color:var(--text-muted);">${escapeHtml(tr('ptNoMatchingExamples'))}</div>`;
        }

        container.innerHTML = html;
    }

    function usePolicyExample(src, dst, proto, dport, sport, ingress, est, icmpType) {
        switchPolicySubtab('tracer');
        const srcEl = document.getElementById('ptSrcIp');
        const dstEl = document.getElementById('ptDstIp');
        const protoEl = document.getElementById('ptProto');
        const dportEl = document.getElementById('ptDport');
        const sportEl = document.getElementById('ptSport');
        const ingEl = document.getElementById('ptIngressIntf');
        const estEl = document.getElementById('ptEstablished');

        if (srcEl) srcEl.value = src || '';
        if (dstEl) dstEl.value = dst || '';
        if (protoEl) protoEl.value = proto || 'tcp';
        if (dportEl) dportEl.value = dport || '';
        if (sportEl) sportEl.value = sport || '';
        if (ingEl) ingEl.value = ingress || '';
        if (estEl) estEl.checked = (est === '1' || est === true);
        // The message type travels with the example: handing an echo-reply
        // packet to the tracer as a bare 'ICMP' would trace a different packet
        // from the one the card showed.
        const icmpEl = document.getElementById('ptIcmpType');
        if (icmpEl) icmpEl.value = (icmpType === undefined || icmpType === null) ? '' : String(icmpType);
        const icmpGrp = document.getElementById('ptIcmpTypeGroup');
        if (icmpGrp) icmpGrp.hidden = (proto || 'tcp') !== 'icmp';

        runPolicyTrace();
    }

    async function loadPolicyFindings() {
        if (!ptSelectedIp) return;
        const container = document.getElementById('ptFindingsContainer');
        if (container) {
            container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><div style="margin-top:10px;">${escapeHtml(tr('ptLoadingFindings'))}</div></div>`;
        }

        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ptSelectedIp)}/findings`);
            if (!res || !res.ok) {
                if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">${escapeHtml(tr('ptFindingsErr'))}</div>`;
                return;
            }
            const findings = await res.json();
            ptFindingsCache[ptSelectedIp] = findings;
            renderFindings(findings);
        } catch (e) {
            if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">${escapeHtml(tr('ptFindingsNetErr'))}</div>`;
        }
    }

    function findingTitleDesc(f) {
        const p = f.params || {};
        if (f.key === 'shadowed') {
            return [tr('ptFindShadowedTitle'), escapeHtml(tr('ptFindShadowedDesc', {
                rule: p.rule_id || '', acl: p.acl || f.acl_name || '', by: p.shadowed_by || '',
            }))];
        }
        if (f.key === 'unreachable') {
            return [tr('ptFindUnreachableTitle'), escapeHtml(tr('ptFindUnreachableDesc', {
                rule: p.rule_id || '', acl: p.acl || f.acl_name || '', by: p.blocked_by || '',
            }))];
        }
        if (f.key === 'any_any') {
            return [tr('ptFindAnyAnyTitle'), escapeHtml(tr('ptFindAnyAnyDesc', {
                rule: p.rule_id || '', acl: p.acl || f.acl_name || '',
            }))];
        }
        if (f.key === 'route_to_nowhere') {
            return [tr('ptFindRouteNowhereTitle'), escapeHtml(tr('ptFindRouteNowhereDesc', {
                prefix: p.prefix || '', nh: p.next_hop || '',
            }))];
        }
        if (f.key === 'unresolved_object') {
            return [tr('ptFindUnresolvedTitle'), escapeHtml(tr('ptFindUnresolvedDesc', {
                rule: p.rule_id || '', objects: (p.objects || []).join(', '),
            }))];
        }
        if (f.key === 'unused_object') {
            return [tr('ptFindUnusedObjTitle'), escapeHtml(tr('ptFindUnusedObjDesc', {
                obj: p.object || '', kind: p.kind || '', detail: p.detail || '',
            }))];
        }
        return [f.key, ''];
    }

    function renderFindings(findings) {
        const container = document.getElementById('ptFindingsContainer');
        if (!container) return;
        const L = i18n[currentLang];
        ptRenderedFindings = findings || [];

        const badge = document.getElementById('ptFindingsBadge');
        if (badge) {
            badge.hidden = ptRenderedFindings.length === 0;
            badge.textContent = String(ptRenderedFindings.length);
        }
        const cart = document.getElementById('ptFindingsCartouche');
        if (cart) {
            if (!ptRenderedFindings.length) {
                cart.hidden = true;
            } else {
                const high = ptRenderedFindings.filter(f => f.severity === 'high').length;
                const med = ptRenderedFindings.filter(f => f.severity === 'medium').length;
                const low = ptRenderedFindings.filter(f => f.severity === 'low' || f.severity === 'info').length;
                cart.hidden = false;
                cart.innerHTML = `<span>${escapeHtml(tr('ptFindCartHigh'))} <b>${high}</b></span>`
                    + `<span>${escapeHtml(tr('ptFindCartMed'))} <b>${med}</b></span>`
                    + `<span>${escapeHtml(tr('ptFindCartLow'))} <b>${low}</b></span>`
                    + `<span>${escapeHtml(tr('ptFindCartTotal'))} <b>${ptRenderedFindings.length}</b></span>`;
            }
        }

        const proveAllBtn = /** @type {HTMLButtonElement|null} */ (document.getElementById('btnPtProveAll'));

        if (!ptRenderedFindings.length) {
            if (proveAllBtn) proveAllBtn.disabled = true;
            container.innerHTML = `
            <div style="text-align:center; padding:40px; color:var(--success);">
                <i class="fa-solid fa-circle-check fa-3x" style="margin-bottom:14px; opacity:0.8;"></i>
                <div style="font-size:15px; font-weight:600;">${escapeHtml(tr('ptNoFindingsTitle'))}</div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">${escapeHtml(tr('ptNoFindingsDesc'))}</div>
            </div>`;
            return;
        }

        const q = (document.getElementById('ptFindSearch')?.value || '').trim().toLowerCase();
        const typeFilter = (document.getElementById('ptFindTypeFilter')?.value || '').trim();
        const indexed = ptRenderedFindings
            .map((f, idx) => ({ f, idx }))
            .filter(({ f }) => {
                if (typeFilter && f.key !== typeFilter) return false;
                if (q) {
                    const p = f.params || {};
                    const hay = `${f.key} ${f.acl_name || ''} ${p.rule_id || ''} ${p.acl || ''} ${p.prefix || ''} ${p.object || ''}`.toLowerCase();
                    if (!hay.includes(q)) return false;
                }
                return true;
            });

        if (proveAllBtn) {
            proveAllBtn.disabled = !indexed.some(({ f }) => f.witness && f.expected_rule_id);
        }

        if (!indexed.length) {
            container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);">${escapeHtml(tr('ptNoMatchingFindings'))}</div>`;
            return;
        }

        let html = `<div style="display:flex; flex-direction:column; gap:12px;">`;

        indexed.forEach(({ f, idx }) => {
            let sevBadge = 'badge badge-warning';
            let sevCardCls = 'is-medium';
            if (f.severity === 'high') {
                sevBadge = 'badge badge-danger';
                sevCardCls = 'is-high';
            } else if (f.severity === 'low') {
                sevBadge = 'badge';
                sevCardCls = '';
            }

            const [title, desc] = findingTitleDesc(f);
            const p = f.params || {};

            const w = f.witness;
            const proofBlock = (w && f.expected_rule_id) ? `
                <div style="margin-top:10px; padding-top:10px; border-top:var(--seam) solid var(--border);">
                    <div style="font-family:var(--font-legend); font-size:10px; letter-spacing:0.16em; text-transform:uppercase; color:var(--text-soft); margin-bottom:6px;">
                        ${escapeHtml(L.ptProofTitle)}
                    </div>
                    <div style="font-size:12px; margin-bottom:8px;">
                        <code>${escapeHtml(w.src_ip)}</code> &rarr; <code>${escapeHtml(w.dst_ip)}${w.dport ? escapeHtml(':' + w.dport) : ''}</code>
                        <span style="color:var(--text-muted);">(${escapeHtml(ptFlowProto(w))})</span>
                        <div style="font-size:11px; color:var(--text-muted); margin-top:3px;">${escapeHtml(L.ptProofExplain.replace('{rule}', p.rule_id || '').replace('{by}', f.expected_rule_id))}</div>
                    </div>
                    <button type="button" class="btn btn-secondary btn-small" data-action="prove-finding"
                        data-idx="${escapeHtml(String(idx))}" style="width:auto; margin:0;">
                        <i class="fa-solid fa-vial"></i> ${escapeHtml(L.ptProofRun)}
                    </button>
                    <div id="ptProofResult${escapeHtml(String(idx))}" style="margin-top:8px;"></div>
                </div>` : '';

            const cliBlocks = f.key === 'unused_object' ? `
                ${p.cli_dry_run ? `<div class="pt-cli-box">
                    <div class="pt-cli-head"><span>${escapeHtml(tr('ptDryRunCli'))}</span><button type="button" class="btn btn-secondary btn-small" data-action="copy-cli" data-cli="${escapeHtml(p.cli_dry_run)}" style="width:auto; margin:0;">${escapeHtml(tr('ptCopyCli'))}</button></div>
                    <pre>${escapeHtml(p.cli_dry_run)}</pre>
                </div>` : ''}
                ${p.cli_rollback ? `<div class="pt-cli-box">
                    <div class="pt-cli-head"><span>${escapeHtml(tr('ptRollbackCli'))}</span><button type="button" class="btn btn-secondary btn-small" data-action="copy-cli" data-cli="${escapeHtml(p.cli_rollback)}" style="width:auto; margin:0;">${escapeHtml(tr('ptCopyCli'))}</button></div>
                    <pre>${escapeHtml(p.cli_rollback)}</pre>
                </div>` : ''}` : '';

            const canWhatIf = ['shadowed', 'unreachable', 'any_any', 'route_to_nowhere'].includes(f.key);

            html += `
            <div class="pt-finding-card ${sevCardCls}">
                <div style="display:flex; justify-content:space-between; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:6px;">
                    <div style="font-weight:700; font-size:14px;">${escapeHtml(title)}</div>
                    <div style="display:flex; align-items:center; gap:8px;">
                        ${canWhatIf ? `<button type="button" class="btn btn-secondary btn-small" data-action="finding-to-whatif" data-idx="${escapeHtml(String(idx))}" style="width:auto; margin:0;"><i class="fa-solid fa-code-branch"></i> ${escapeHtml(tr('ptSimulateInWhatIf'))}</button>` : ''}
                        <span class="${sevBadge}">${escapeHtml((f.severity || 'medium').toUpperCase())}</span>
                    </div>
                </div>
                <div style="font-size:13px; color:var(--text); line-height:1.5;">${desc}</div>
                ${cliBlocks}
                ${proofBlock}
            </div>`;
        });

        html += `</div>`;
        container.innerHTML = html;
    }

    async function proveAllFindings() {
        const btn = /** @type {HTMLButtonElement|null} */ (document.getElementById('btnPtProveAll'));
        const buttons = [...document.querySelectorAll('#ptFindingsContainer button[data-action="prove-finding"]')];
        if (!buttons.length) return;
        if (btn) btn.disabled = true;
        try {
            for (let i = 0; i < buttons.length; i++) {
                const idx = parseInt(buttons[i].getAttribute('data-idx') || '-1', 10);
                if (idx >= 0) {
                    if (btn) btn.textContent = tr('ptProvingAll', { i: i + 1, n: buttons.length });
                    await proveFinding(idx);
                }
            }
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-vial" aria-hidden="true"></i> ${escapeHtml(tr('ptProveAllBtn'))}`;
            }
        }
    }

    /** Run a finding's witness packet and show whether the claim held.
     *
     *  The verdict comes from the same engine the tracer uses, so a green
     *  result is a real second opinion and a red one is a genuine
     *  disagreement between the detector and the evaluator - worth seeing,
     *  not worth hiding.
     */
    async function proveFinding(idx) {
        const f = ptRenderedFindings[idx];
        const out = document.getElementById('ptProofResult' + idx);
        if (!f || !out || !f.witness || !f.expected_rule_id) return;
        const L = i18n[currentLang];

        out.innerHTML = `<span style="font-size:12px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> ${escapeHtml(L.ptProofRunning)}</span>`;
        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ptSelectedIp)}/prove`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ witness: f.witness, expected_rule_id: f.expected_rule_id }),
            });
            if (!res || !res.ok) {
                out.innerHTML = `<span style="font-size:12px; color:var(--danger);">${escapeHtml(L.ptProofError)}</span>`;
                return;
            }
            const r = await res.json();
            const ok = !!r.proven;
            const col = ok ? 'var(--success)' : 'var(--warning)';
            const wash = ok ? 'var(--lamp-up-wash)' : 'var(--lamp-warn-wash)';
            const icon = ok ? 'fa-circle-check' : 'fa-circle-question';
            const msg = ok
                ? L.ptProofConfirmed.replace('{by}', r.actual_rule_id || '?')
                : L.ptProofNotConfirmed
                    .replace('{expected}', r.expected_rule_id || '?')
                    .replace('{actual}', r.actual_rule_id || '-');
            out.innerHTML = `
                <div style="display:flex; align-items:flex-start; gap:8px; padding:8px 10px; background:${wash}; border:1px solid ${col}; font-size:12px;">
                    <i class="fa-solid ${icon}" style="color:${col}; margin-top:2px;"></i>
                    <span>${escapeHtml(msg)} <span style="color:var(--text-muted);">(${escapeHtml(L.ptProofVerdict)}: ${escapeHtml((r.trace && r.trace.verdict) || '-')})</span></span>
                </div>`;
        } catch (e) {
            out.innerHTML = `<span style="font-size:12px; color:var(--danger);">${escapeHtml(L.ptProofError)}</span>`;
        }
    }

    function syncWhatIfFields() {
        const actEl = document.getElementById('ptWiAction');
        const ruleBox = document.getElementById('ptWiRuleFields');
        const ruleDetailBox = document.getElementById('ptWiRuleDetailFields');
        const routeBox = document.getElementById('ptWiRouteFields');
        if (!actEl) return;
        const act = actEl.value;
        const isRoute = (act === 'add_route' || act === 'remove_route');
        if (ruleBox) ruleBox.style.display = isRoute ? 'none' : '';
        if (routeBox) routeBox.style.display = isRoute ? '' : 'none';
        if (ruleDetailBox) {
            ruleDetailBox.style.display = (act === 'add_rule' || act === 'tighten_rule') ? '' : 'none';
        }
    }

    function parseCustomFlowsText(raw) {
        const out = [];
        String(raw || '').split(/\r?\n/).forEach(line => {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) return;
            const parts = trimmed.split(/[\s,;]+/).filter(Boolean);
            if (parts.length >= 2) {
                const dportVal = parts[3] ? parseInt(parts[3], 10) : null;
                out.push({
                    src_ip: parts[0],
                    dst_ip: parts[1],
                    proto: (parts[2] || 'tcp').toLowerCase(),
                    dport: (dportVal && !Number.isNaN(dportVal)) ? dportVal : null,
                });
            }
        });
        return out;
    }

    async function runPolicyWhatIf() {
        if (!ptSelectedIp) {
            showToast(policyTenant() ? tr('ptChooseDeviceFirst')
                                     : tr('ptChooseTenantFirst'), 'warning');
            return;
        }
        const box = document.getElementById('ptWhatIfResultContainer');
        if (box) {
            box.dataset.hasResult = '';
            box.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i></div>`;
        }

        const action = (document.getElementById('ptWiAction')?.value || 'disable_rule').trim();
        const dportRaw = (document.getElementById('ptWiDport')?.value || '').trim();
        const distRaw = parseInt(document.getElementById('ptWiDistance')?.value || '1', 10);
        const change = {
            action,
            rule_id: (document.getElementById('ptWiRuleId')?.value || '').trim() || null,
            acl: (document.getElementById('ptWiAcl')?.value || '').trim() || null,
            rule_action: (document.getElementById('ptWiRuleAction')?.value || 'permit').trim(),
            position: (document.getElementById('ptWiPosition')?.value || 'top').trim(),
            src_cidr: (document.getElementById('ptWiSrcCidr')?.value || '').trim() || null,
            dst_cidr: (document.getElementById('ptWiDstCidr')?.value || '').trim() || null,
            src_intf: (document.getElementById('ptWiSrcIntf')?.value || '').trim() || null,
            dst_intf: (document.getElementById('ptWiDstIntf')?.value || '').trim() || null,
            proto: (document.getElementById('ptWiProto')?.value || 'tcp').trim(),
            dport: dportRaw ? parseInt(dportRaw, 10) : null,
            prefix: (document.getElementById('ptWiPrefix')?.value || '').trim() || null,
            next_hop: (document.getElementById('ptWiNextHop')?.value || '').trim() || null,
            interface: (document.getElementById('ptWiIface')?.value || '').trim() || null,
            distance: (!Number.isNaN(distRaw) && distRaw >= 1 && distRaw <= 255) ? distRaw : 1,
        };
        const flows = parseCustomFlowsText(document.getElementById('ptWiCustomFlows')?.value || '');

        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ptSelectedIp)}/what-if`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ change, flows }),
            });
            if (!res || !res.ok) {
                const err = await (res ? res.json().catch(() => ({})) : Promise.resolve({}));
                if (box) {
                    box.innerHTML = `<div class="panel" style="padding:14px; background:var(--lamp-fault-wash); border-color:var(--danger);"><i class="fa-solid fa-triangle-exclamation" style="color:var(--danger);"></i> ${escapeHtml(err.detail || tr('ptWiSimFailed'))}</div>`;
                }
                return;
            }
            const data = await res.json();
            ptLastWhatIf = data;
            const changedCount = (data.flows || []).filter(r => String(r.transition || 'unchanged') !== 'unchanged').length;
            ptWiChangedOnly = changedCount > 0;
            if (box) box.dataset.hasResult = '1';
            renderWhatIfResult(data);
        } catch (e) {
            if (box) {
                box.innerHTML = `<div class="panel" style="padding:14px; background:var(--lamp-fault-wash); border-color:var(--danger);">${escapeHtml(String(e))}</div>`;
            }
        }
    }

    function transitionLabel(t) {
        if (t === 'broken') return tr('ptWiTransBroken');
        if (t === 'newly_allowed') return tr('ptWiTransNewlyAllowed');
        if (t === 'rerouted_or_changed') return tr('ptWiTransRerouted');
        return tr('ptWiTransUnchanged');
    }

    function renderWhatIfResult(data) {
        const box = document.getElementById('ptWhatIfResultContainer');
        if (!box) return;
        const s = data.summary || {};
        const risk = String(data.risk || 'LOW').toUpperCase();
        const riskCls = risk === 'HIGH' ? 'badge-danger' : (risk === 'MEDIUM' ? 'badge-warning' : 'badge-success');

        const kpiCard = (label, val, col) => `
            <div style="border:1px solid var(--border); background:var(--surface-2); padding:10px 12px; border-radius:var(--radius);">
                <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted);">${escapeHtml(label)}</div>
                <div style="font-size:20px; font-weight:700; color:${col}; font-family:var(--font-code);">${escapeHtml(String(val || 0))}</div>
            </div>`;

        const badgeForVerdict = (v) => {
            const up = String(v || 'UNKNOWN').toUpperCase();
            const cls = up === 'PERMIT' ? 'badge-success' : (up === 'DENY' ? 'badge-danger' : 'badge-warning');
            return `<span class="badge ${cls}">${escapeHtml(up)}</span>`;
        };

        const badgeForTransition = (t) => {
            const up = String(t || 'unchanged');
            const cls = up === 'broken' ? 'badge-danger'
                : (up === 'newly_allowed' || up === 'rerouted_or_changed' ? 'badge-warning' : 'badge');
            return `<span class="badge ${cls}">${escapeHtml(transitionLabel(up))}</span>`;
        };

        const allFlows = data.flows || [];
        const visibleFlows = ptWiChangedOnly
            ? allFlows.filter(row => String(row.transition || 'unchanged') !== 'unchanged')
            : allFlows;

        const rows = visibleFlows.map(row => {
            const f = row.flow || {};
            const b = row.before || {};
            const a = row.after || {};
            const dport = f.dport ? `:${f.dport}` : '';
            return `<tr style="border-top:1px solid var(--border); font-size:12px;">
                <td style="padding:6px 8px; font-family:var(--font-code);"><code>${escapeHtml(f.src_ip)}</code> &rarr; <code>${escapeHtml(f.dst_ip)}${escapeHtml(dport)}</code> <span style="color:var(--text-muted);">(${escapeHtml(ptFlowProto(f))})</span></td>
                <td style="padding:6px 8px; font-size:11px; color:var(--text-muted);">${escapeHtml(row.origin || '')}</td>
                <td style="padding:6px 8px;">${badgeForVerdict(b.verdict)} ${b.rule_id ? `<span style="font-size:11px; color:var(--text-muted);">#${escapeHtml(String(b.rule_id))}</span>` : ''}</td>
                <td style="padding:6px 8px;">${badgeForVerdict(a.verdict)} ${a.rule_id ? `<span style="font-size:11px; color:var(--text-muted);">#${escapeHtml(String(a.rule_id))}</span>` : ''}</td>
                <td style="padding:6px 8px;">${badgeForTransition(row.transition)}</td>
            </tr>`;
        }).join('');

        const fDiff = data.findings_diff || {};
        const resolved = fDiff.resolved || [];
        const introduced = fDiff.introduced || [];
        const rb = data.rollback || {};
        const applyText = `${rb.cli_apply || ''}${rb.api_dry_run ? '\n# API: ' + rb.api_dry_run : ''}`;
        const rollbackText = rb.cli_rollback || '';

        box.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:14px; padding:10px 14px; border:1px solid var(--border); background:var(--surface-2); border-radius:var(--radius);">
                <div style="font-family:var(--font-code); font-size:13px;"><strong>${escapeHtml(data.change_summary || '')}</strong> <span style="color:var(--text-muted);">(${escapeHtml(data.config_type || '')})</span></div>
                <div><span style="font-size:11px; color:var(--text-muted); margin-right:6px;">${escapeHtml(tr('ptWiRisk'))}:</span><span class="badge ${riskCls}">${escapeHtml(risk)}</span></div>
            </div>

            <div class="pt-wi-kpis">
                ${kpiCard(tr('ptWiBroken'), s.broken, 'var(--danger)')}
                ${kpiCard(tr('ptWiNewlyAllowed'), s.newly_allowed, 'var(--warning)')}
                ${kpiCard(tr('ptWiRerouted'), s.rerouted_or_changed, 'var(--primary)')}
                ${kpiCard(tr('ptWiUnchanged'), s.unchanged, 'var(--success)')}
            </div>

            <div class="pt-wi-grid-2" style="margin-bottom:14px;">
                <div style="border:1px solid var(--border); padding:10px 12px; background:var(--lamp-up-wash); border-radius:var(--radius);">
                    <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--lamp-up-ink); margin-bottom:4px;">${escapeHtml(tr('ptWiFindingsDiff'))} &mdash; ${escapeHtml(tr('ptWiResolved'))} (${escapeHtml(String(resolved.length))})</div>
                    <div style="font-size:12px;">${resolved.length ? resolved.map(x => `<div>&check; ${escapeHtml(x.key || '')} (${escapeHtml(String(x.rule_id || ''))})</div>`).join('') : '<span style="color:var(--text-muted);">—</span>'}</div>
                </div>
                <div style="border:1px solid var(--border); padding:10px 12px; background:var(--lamp-fault-wash); border-radius:var(--radius);">
                    <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--lamp-fault-ink); margin-bottom:4px;">${escapeHtml(tr('ptWiFindingsDiff'))} &mdash; ${escapeHtml(tr('ptWiIntroduced'))} (${escapeHtml(String(introduced.length))})</div>
                    <div style="font-size:12px;">${introduced.length ? introduced.map(x => `<div>! ${escapeHtml(x.key || '')} (${escapeHtml(String(x.rule_id || ''))})</div>`).join('') : '<span style="color:var(--text-muted);">—</span>'}</div>
                </div>
            </div>

            <div class="pt-wi-toolbar">
                <h4 style="margin:0; font-size:13px;">${escapeHtml(tr('ptWiDiffTable'))}</h4>
                <label class="pt-wi-toggle">
                    <input type="checkbox" id="ptWiChangedOnlyChk" ${ptWiChangedOnly ? 'checked' : ''}>
                    <span>${escapeHtml(tr('ptWiChangedOnly'))} (${escapeHtml(String(visibleFlows.length))}/${escapeHtml(String(allFlows.length))})</span>
                </label>
            </div>
            <div class="table-container" style="max-height:280px; overflow:auto; margin-bottom:14px;">
                <table style="width:100%; border-collapse:collapse;">
                    <thead>
                        <tr>
                            <th style="text-align:left; padding:6px 8px;">${escapeHtml(tr('ptWiFlow'))}</th>
                            <th style="text-align:left; padding:6px 8px;">${escapeHtml(tr('ptWiOrigin'))}</th>
                            <th style="text-align:left; padding:6px 8px;">${escapeHtml(tr('ptWiBefore'))}</th>
                            <th style="text-align:left; padding:6px 8px;">${escapeHtml(tr('ptWiAfter'))}</th>
                            <th style="text-align:left; padding:6px 8px;">${escapeHtml(tr('ptWiTransition'))}</th>
                        </tr>
                    </thead>
                    <tbody>${rows || `<tr><td colspan="5" style="padding:12px; text-align:center; color:var(--text-muted);">${escapeHtml(ptWiChangedOnly ? tr('ptWiNoChangedFlows') : '—')}</td></tr>`}</tbody>
                </table>
            </div>

            <div class="pt-wi-grid-2">
                <div class="pt-cli-box">
                    <div class="pt-cli-head">
                        <span>${escapeHtml(tr('ptWiApplyCli'))}</span>
                        <button type="button" class="btn btn-secondary btn-small" data-action="copy-cli" data-cli="${escapeHtml(applyText)}" style="width:auto; margin:0;">${escapeHtml(tr('ptCopyCli'))}</button>
                    </div>
                    <pre>${escapeHtml(applyText)}</pre>
                </div>
                <div class="pt-cli-box">
                    <div class="pt-cli-head">
                        <span>${escapeHtml(tr('ptWiRollbackCli'))}</span>
                        <button type="button" class="btn btn-secondary btn-small" data-action="copy-cli" data-cli="${escapeHtml(rollbackText)}" style="width:auto; margin:0;">${escapeHtml(tr('ptCopyCli'))}</button>
                    </div>
                    <pre>${escapeHtml(rollbackText)}</pre>
                </div>
            </div>`;
    }

    // Delegated event listener initialization.
    //
    // NOT inside a DOMContentLoaded handler: this module is lazy-loaded by
    // LAZY_TAB_SCRIPTS when the tab is first opened, which is always long
    // after DOMContentLoaded has fired. A listener registered for an event
    // already past never runs, so every control below stayed dead and the
    // failure was silent. The sibling lazy modules (redundancy.js and the
    // rest) bind directly in their IIFE for exactly this reason.
    // ICMP message names for flow labels. 'ICMP' alone hides the one field
    // that decides whether an echo rule or a reply rule catches the packet.
    const PT_ICMP_TYPE_NAMES = {
        0: 'echo-reply', 3: 'unreachable', 5: 'redirect', 8: 'echo',
        11: 'time-exceeded', 13: 'timestamp-request', 14: 'timestamp-reply',
        17: 'mask-request', 18: 'mask-reply', 30: 'traceroute',
    };

    function ptFlowProto(flow) {
        const proto = String(flow.proto || 'tcp').toUpperCase();
        const t = flow.icmp_type;
        if (t === null || t === undefined) return proto;
        const name = PT_ICMP_TYPE_NAMES[t];
        return name ? `${proto} ${name} (${t})` : `${proto} type ${t}`;
    }

    function bindPolicyTestControls() {
        const tenantSel = document.getElementById('ptTenantSelect');
        if (tenantSel) {
            tenantSel.addEventListener('change', () => {
                // Changing tenant invalidates the whole view: the selected
                // device belongs to the previous one, and its cached results
                // must not survive the switch.
                ptSelectedIp = null;
                ptExamplesCache = {};
                ptFindingsCache = {};
                ptMetaCache = {};
                ptLastWhatIf = null;
                populateDatalists(null);
                populatePolicyDeviceSelect();
                renderPolicySelectionState();
            });
        }

        const protoSel = document.getElementById('ptProto');
        if (protoSel) {
            const syncIcmpType = () => {
                const grp = document.getElementById('ptIcmpTypeGroup');
                if (grp) grp.hidden = protoSel.value !== 'icmp';
            };
            protoSel.addEventListener('change', syncIcmpType);
            syncIcmpType();
        }

        const sel = document.getElementById('ptDeviceSelect');
        if (sel) {
            sel.addEventListener('change', (e) => {
                ptSelectedIp = e.target.value || null;
                ptLastWhatIf = null;
                loadDeviceMetadata(ptSelectedIp);
                const wiBox = document.getElementById('ptWhatIfResultContainer');
                if (wiBox) wiBox.dataset.hasResult = '';
                if (renderPolicySelectionState()) return;
                if (ptActiveSubtab === 'examples') loadPolicyExamples();
                else if (ptActiveSubtab === 'findings') loadPolicyFindings();
                else if (ptActiveSubtab === 'whatif' && wiBox) {
                    wiBox.innerHTML = `<div style="text-align:center; padding:40px 20px; color:var(--text-muted); font-size:13px;">
                        <i class="fa-solid fa-code-branch fa-2x" style="margin-bottom:12px; opacity:0.4;"></i>
                        <div>${escapeHtml(tr('ptWiNoResult'))}</div>
                    </div>`;
                }
            });
        }

        document.getElementById('btnPtSwitchWhatIf')?.addEventListener('click', () => switchPolicySubtab('whatif'));
        document.getElementById('btnPtOpenFgt')?.addEventListener('click', () => {
            if (typeof switchTab === 'function') switchTab('tab-fortigate');
        });
        document.getElementById('btnPtProveAll')?.addEventListener('click', proveAllFindings);
        ['ptSrcIp', 'ptDstIp', 'ptDport', 'ptSport', 'ptIngressIntf', 'ptEgressIntf'].forEach(id => {
            document.getElementById(id)?.addEventListener('keydown', (e) => {
                if (/** @type {KeyboardEvent} */ (e).key === 'Enter') runPolicyTrace();
            });
        });

        const rerenderExamples = () => {
            if (ptSelectedIp && ptExamplesCache[ptSelectedIp]) renderExamples(ptExamplesCache[ptSelectedIp]);
        };
        document.getElementById('ptExSearch')?.addEventListener('input', rerenderExamples);
        document.getElementById('ptExAclFilter')?.addEventListener('change', rerenderExamples);
        document.getElementById('ptExActionFilter')?.addEventListener('change', rerenderExamples);
        document.getElementById('btnPtExCatchAll')?.addEventListener('click', (e) => {
            ptExCatchAllOnly = !ptExCatchAllOnly;
            e.currentTarget.setAttribute('aria-pressed', String(ptExCatchAllOnly));
            rerenderExamples();
        });
        document.getElementById('btnPtExUnparsed')?.addEventListener('click', (e) => {
            ptExUnparsedOnly = !ptExUnparsedOnly;
            e.currentTarget.setAttribute('aria-pressed', String(ptExUnparsedOnly));
            rerenderExamples();
        });
        document.getElementById('btnPtExReset')?.addEventListener('click', () => {
            ptExCatchAllOnly = false;
            ptExUnparsedOnly = false;
            const s = document.getElementById('ptExSearch');
            const acl = document.getElementById('ptExAclFilter');
            const act = document.getElementById('ptExActionFilter');
            if (s) s.value = '';
            if (acl) acl.value = '';
            if (act) act.value = '';
            document.getElementById('btnPtExCatchAll')?.setAttribute('aria-pressed', 'false');
            document.getElementById('btnPtExUnparsed')?.setAttribute('aria-pressed', 'false');
            rerenderExamples();
        });

        const rerenderFindings = () => {
            if (ptSelectedIp && ptFindingsCache[ptSelectedIp]) renderFindings(ptFindingsCache[ptSelectedIp]);
        };
        document.getElementById('ptFindSearch')?.addEventListener('input', rerenderFindings);
        document.getElementById('ptFindTypeFilter')?.addEventListener('change', rerenderFindings);

        const findingsBox = document.getElementById('ptFindingsContainer');
        if (findingsBox) {
            findingsBox.addEventListener('click', (e) => {
                const proveBtn = e.target.closest('button[data-action="prove-finding"]');
                if (proveBtn) {
                    proveFinding(parseInt(proveBtn.dataset.idx, 10));
                    return;
                }
                const copyBtn = e.target.closest('button[data-action="copy-cli"]');
                if (copyBtn && copyBtn.dataset.cli && navigator.clipboard) {
                    navigator.clipboard.writeText(copyBtn.dataset.cli);
                    showToast(tr('ptCopied'), 'success');
                    return;
                }
                const wiBtn = e.target.closest('button[data-action="finding-to-whatif"]');
                if (wiBtn) {
                    const f = ptRenderedFindings[parseInt(wiBtn.dataset.idx, 10)];
                    if (!f) return;
                    const p = f.params || {};
                    const actEl = document.getElementById('ptWiAction');
                    const ruleEl = document.getElementById('ptWiRuleId');
                    const aclEl = document.getElementById('ptWiAcl');
                    const prefixEl = document.getElementById('ptWiPrefix');
                    const flowsEl = document.getElementById('ptWiCustomFlows');
                    switchPolicySubtab('whatif');
                    if (f.key === 'route_to_nowhere') {
                        if (actEl) actEl.value = 'remove_route';
                        if (prefixEl) prefixEl.value = p.prefix || '';
                    } else if (f.key === 'any_any') {
                        if (actEl) actEl.value = 'tighten_rule';
                        if (ruleEl) ruleEl.value = p.rule_id || '';
                        if (aclEl) aclEl.value = (p.acl && p.acl !== 'firewall_policy') ? p.acl : '';
                    } else {
                        if (actEl) actEl.value = 'delete_rule';
                        if (ruleEl) ruleEl.value = p.rule_id || '';
                        if (aclEl) aclEl.value = (p.acl && p.acl !== 'firewall_policy') ? p.acl : '';
                    }
                    if (flowsEl && f.witness) {
                        const w = f.witness;
                        flowsEl.value = `${w.src_ip},${w.dst_ip},${w.proto || 'tcp'},${w.dport || ''}`;
                    }
                    syncWhatIfFields();
                    runPolicyWhatIf();
                }
            });
        }

        const wiBox = document.getElementById('ptWhatIfResultContainer');
        if (wiBox) {
            wiBox.addEventListener('click', (e) => {
                const copyBtn = e.target.closest('button[data-action="copy-cli"]');
                if (copyBtn && copyBtn.dataset.cli && navigator.clipboard) {
                    navigator.clipboard.writeText(copyBtn.dataset.cli);
                    showToast(tr('ptCopied'), 'success');
                }
            });
            wiBox.addEventListener('change', (e) => {
                if (e.target && e.target.id === 'ptWiChangedOnlyChk' && ptLastWhatIf) {
                    ptWiChangedOnly = !!e.target.checked;
                    renderWhatIfResult(ptLastWhatIf);
                }
            });
        }

        const subtabNav = document.getElementById('ptSubtabNav');
        if (subtabNav) {
            subtabNav.addEventListener('click', (e) => {
                const btn = e.target.closest('button[data-subtab]');
                if (btn && btn.dataset.subtab) {
                    switchPolicySubtab(btn.dataset.subtab);
                }
            });
        }

        const btnTrace = document.getElementById('btnPtRunTrace');
        if (btnTrace) {
            btnTrace.addEventListener('click', () => runPolicyTrace());
        }

        const wiActionSel = document.getElementById('ptWiAction');
        if (wiActionSel) {
            wiActionSel.addEventListener('change', syncWhatIfFields);
            syncWhatIfFields();
        }

        const btnWhatIf = document.getElementById('btnPtRunWhatIf');
        if (btnWhatIf) {
            btnWhatIf.addEventListener('click', () => runPolicyWhatIf());
        }

        const exContainer = document.getElementById('ptExamplesContainer');
        if (exContainer) {
            exContainer.addEventListener('click', (e) => {
                const wiBtn = e.target.closest('button[data-action="example-to-whatif"]');
                if (wiBtn) {
                    switchPolicySubtab('whatif');
                    const actEl = document.getElementById('ptWiAction');
                    const ruleEl = document.getElementById('ptWiRuleId');
                    const aclEl = document.getElementById('ptWiAcl');
                    const flowsEl = document.getElementById('ptWiCustomFlows');
                    if (actEl) actEl.value = 'disable_rule';
                    if (ruleEl) ruleEl.value = wiBtn.dataset.rule || '';
                    if (aclEl) aclEl.value = wiBtn.dataset.acl || '';
                    if (flowsEl && wiBtn.dataset.flow) flowsEl.value = wiBtn.dataset.flow;
                    syncWhatIfFields();
                    return;
                }
                const btn = e.target.closest('button[data-action="use-example"]');
                if (btn) {
                    usePolicyExample(
                        btn.dataset.src,
                        btn.dataset.dst,
                        btn.dataset.proto,
                        btn.dataset.dport,
                        btn.dataset.sport,
                        btn.dataset.ingress,
                        btn.dataset.est === '1',
                        btn.dataset.icmp
                    );
                }
            });
        }
    }

    bindPolicyTestControls();

    window.addEventListener('globalTenantChanged', () => {
        ptSelectedIp = null;
        ptExamplesCache = {};
        ptFindingsCache = {};
        ptMetaCache = {};
        ptLastWhatIf = null;
        if (document.getElementById('tab-policy-test')?.classList.contains('active')) {
            loadPolicyTestTab();
        }
    });

    // Expose to window for cross-module dispatch
    window.loadPolicyTestTab = loadPolicyTestTab;
    window.runPolicyTrace = runPolicyTrace;
    window.switchPolicySubtab = switchPolicySubtab;
    window.usePolicyExample = usePolicyExample;
})();
