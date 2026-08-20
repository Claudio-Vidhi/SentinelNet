// -*- coding: utf-8 -*-
// ===== Policy & Route Validation =====
// Pure evaluation and offline reachability tracing against device backups.

(function () {
    let ptActiveSubtab = 'tracer';
    let ptSelectedIp = null;
    let ptExamplesCache = {};
    let ptFindingsCache = {};
    let ptRenderedFindings = [];

    function loadPolicyTestTab() {
        populatePolicyTenantSelect();
        populatePolicyDeviceSelect();
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
            groups.map(g => `<option value="${escapeHtml(g)}">${escapeHtml(g)}</option>`).join('');
        sel.value = groups.includes(cur) ? cur : '';
    }

    function policyTenant() {
        const sel = document.getElementById('ptTenantSelect');
        return sel ? sel.value : '';
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

        const devices = (globalDevices || []).filter(
            d => (d.Group || 'Generale') === tenant);
        sel.disabled = devices.length === 0;

        if (devices.length === 0) {
            sel.innerHTML = `<option value="">${escapeHtml(L.ptNoDevicesInTenant)}</option>`;
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
            }).join('');
        sel.value = devices.some(d => d.IP === cur) ? cur : '';
        ptSelectedIp = sel.value || null;
        updateDeviceMeta();
    }

    /** Placeholder in every panel until a tenant AND a device are chosen.
     *  Returns true when it painted, i.e. when there is nothing to show yet. */
    function renderPolicySelectionState() {
        if (ptSelectedIp) return false;
        const L = i18n[currentLang];
        const msg = !policyTenant() ? L.ptChooseTenantFirst : L.ptChooseDeviceFirst;
        const empty = `<div style="text-align:center; padding:40px 20px; color:var(--text-muted);">
            <i class="fa-solid fa-hand-pointer fa-2x" style="margin-bottom:12px; opacity:0.4;"></i>
            <div style="font-size:13px;">${escapeHtml(msg)}</div>
        </div>`;
        ['ptTraceResultsContainer', 'ptExamplesContainer', 'ptFindingsContainer']
            .forEach(id => {
                const el = document.getElementById(id);
                if (el) el.innerHTML = empty;
            });
        return true;
    }

    function updateDeviceMeta() {
        const metaEl = document.getElementById('ptDeviceMeta');
        if (!metaEl) return;
        const dev = ptSelectedIp
            ? (globalDevices || []).find(d => d.IP === ptSelectedIp) : null;
        if (!dev) { metaEl.innerHTML = ''; return; }
        const group = dev.Group || 'Generale';
        const vendor = (dev.Vendor || dev.Type || 'cisco').toUpperCase();
        metaEl.innerHTML = `<span class="badge">${escapeHtml(i18n[currentLang].ptTenantLabel)}: ${escapeHtml(group)}</span> <span class="badge">Vendor: ${escapeHtml(vendor)}</span>`;
    }

    function switchPolicySubtab(subtab) {
        ptActiveSubtab = subtab;
        document.querySelectorAll('#ptSubtabNav button').forEach(b => {
            b.classList.toggle('active', b.dataset.subtab === subtab);
        });

        const tracerEl = document.getElementById('ptSubtabTracer');
        const examplesEl = document.getElementById('ptSubtabExamples');
        const findingsEl = document.getElementById('ptSubtabFindings');

        if (tracerEl) tracerEl.style.display = (subtab === 'tracer') ? '' : 'none';
        if (examplesEl) examplesEl.style.display = (subtab === 'examples') ? '' : 'none';
        if (findingsEl) findingsEl.style.display = (subtab === 'findings') ? '' : 'none';

        if (renderPolicySelectionState()) return;

        if (subtab === 'examples' && !ptExamplesCache[ptSelectedIp]) {
            loadPolicyExamples();
        } else if (subtab === 'findings' && !ptFindingsCache[ptSelectedIp]) {
            loadPolicyFindings();
        }
    }

    async function runPolicyTrace() {
        if (!ptSelectedIp) {
            alert(policyTenant() ? i18n[currentLang].ptChooseDeviceFirst
                                 : i18n[currentLang].ptChooseTenantFirst);
            return;
        }

        const srcIp = (document.getElementById('ptSrcIp')?.value || '').trim();
        const dstIp = (document.getElementById('ptDstIp')?.value || '').trim();
        const proto = (document.getElementById('ptProto')?.value || 'tcp').trim();
        const dportRaw = (document.getElementById('ptDport')?.value || '').trim();
        const sportRaw = (document.getElementById('ptSport')?.value || '').trim();
        const ingress = (document.getElementById('ptIngressIntf')?.value || '').trim() || null;
        const established = !!document.getElementById('ptEstablished')?.checked;
        const icmpTypeRaw = (document.getElementById('ptIcmpType')?.value || '').trim();

        if (!srcIp || !dstIp) {
            alert('Inserisci IP Sorgente e IP Destinazione.');
            return;
        }

        const container = document.getElementById('ptTraceResultsContainer');
        if (container) {
            container.innerHTML = `<div style="text-align:center; padding:40px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><div style="margin-top:10px;">Valutazione flow policy in corso...</div></div>`;
        }

        const payload = {
            src_ip: srcIp,
            dst_ip: dstIp,
            proto: proto,
            dport: dportRaw ? parseInt(dportRaw, 10) : null,
            sport: sportRaw ? parseInt(sportRaw, 10) : null,
            ingress_intf: ingress,
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

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                if (container) {
                    container.innerHTML = `<div class="panel" style="padding:16px; background:var(--lamp-fault-wash); border-left:1px solid var(--danger);"><i class="fa-solid fa-triangle-exclamation" style="color:var(--danger);"></i> <strong>Errore:</strong> ${escapeHtml(errData.detail || 'Impossibile completare il trace.')}</div>`;
                }
                return;
            }

            const trace = await res.json();
            renderTraceResult(trace);
        } catch (e) {
            if (container) {
                container.innerHTML = `<div class="panel" style="padding:16px; background:var(--lamp-fault-wash); border-left:1px solid var(--danger);"><i class="fa-solid fa-triangle-exclamation" style="color:var(--danger);"></i> Errore di rete durante il trace.</div>`;
            }
        }
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
            vColor = 'var(--success)';
            vBg = 'var(--lamp-up-wash)';
            vBorder = 'var(--success)';
            vIcon = 'fa-circle-check';
        } else if (verdict === 'DENY') {
            vColor = 'var(--danger)';
            vBg = 'var(--lamp-fault-wash)';
            vBorder = 'var(--danger)';
            vIcon = 'fa-circle-xmark';
        } else if (verdict === 'UNKNOWN') {
            vColor = 'var(--warning)';
            vBg = 'var(--lamp-warn-wash)';
            vBorder = 'var(--warning)';
            vIcon = 'fa-triangle-exclamation';
        }

        let html = `
        <div style="display:flex; align-items:center; justify-content:space-between; padding:16px 20px; border-radius:0; border:1px solid ${vBorder}; background:${vBg}; margin-bottom:18px;">
            <div style="display:flex; align-items:center; gap:14px;">
                <i class="fa-solid ${vIcon} fa-2x" style="color:${vColor};"></i>
                <div>
                    <div style="font-size:11px; text-transform:uppercase; font-weight:700; color:var(--text-muted);">Verdetto Finale</div>
                    <div style="font-family:var(--font-legend); font-size:21px; font-weight:600; letter-spacing:0.06em; color:${vColor};">${escapeHtml(verdict)}</div>
                </div>
            </div>
            <div>
                ${trace.nat_applied ? '<span class="badge" style="background:var(--primary); color:#fff;"><i class="fa-solid fa-arrows-split-up-and-left"></i> Source NAT Attivo</span>' : ''}
            </div>
        </div>`;

        if (trace.dynamic_routing_present) {
            html += `
            <div style="padding:10px 14px; margin-bottom:16px; border:1px solid var(--warning); background:var(--lamp-warn-wash); color:var(--warning); font-size:12px; display:flex; align-items:center; gap:10px;">
                <i class="fa-solid fa-triangle-exclamation"></i>
                <span>${escapeHtml(i18n[currentLang].ptDynamicRoutingWarning)}</span>
            </div>`;
        }

        // The reasons behind an UNKNOWN verdict. Without this the operator saw
        // a bare "UNKNOWN" with nothing naming the object that could not be
        // resolved, which is the whole content of the answer.
        const unresolved = trace.unresolved || [];
        if (unresolved.length) {
            html += `
            <div style="padding:10px 14px; margin-bottom:16px; border:1px solid var(--warning); background:var(--lamp-warn-wash); font-size:12px;">
                <div style="font-weight:600; margin-bottom:6px; color:var(--warning);">
                    <i class="fa-solid fa-circle-question"></i> ${escapeHtml(i18n[currentLang].ptUnresolvedTitle)}
                </div>
                <ul style="margin:0; padding-left:18px; color:var(--text);">
                    ${unresolved.map(u => `<li>${escapeHtml(u)}</li>`).join('')}
                </ul>
            </div>`;
        }

        const steps = trace.steps || [];
        if (steps.length === 0) {
            html += `<div style="color:var(--text-muted); font-size:13px;">Nessuno step attraversato nel pipeline decisionale.</div>`;
        } else {
            html += `<div style="display:flex; flex-direction:column; gap:10px;">`;
            steps.forEach((step, idx) => {
                let stepColor = 'var(--text)';
                let stepBadge = step.action || '';
                let badgeClass = 'badge';

                // The step's outcome is real information, so it keeps a colour —
                // but as a state wash with a 1px rule, the form DESIGN.md gives
                // for a row in a state, not a slab down the edge.
                let stepWash = 'var(--lamp-idle-wash)';
                let stepRule = 'var(--border)';

                if (step.action === 'permit') {
                    badgeClass = 'badge badge-success';
                    stepWash = 'var(--lamp-up-wash)';
                    stepRule = 'var(--success)';
                } else if (step.action === 'deny') {
                    badgeClass = 'badge badge-danger';
                    stepWash = 'var(--lamp-fault-wash)';
                    stepRule = 'var(--danger)';
                } else if (step.action === 'unknown') {
                    badgeClass = 'badge badge-warning';
                    stepWash = 'var(--lamp-warn-wash)';
                    stepRule = 'var(--warning)';
                }

                let kindLabel = step.kind;
                if (step.kind === 'acl_in') kindLabel = 'Ingress ACL';
                else if (step.kind === 'route') kindLabel = 'Route LPM';
                else if (step.kind === 'acl_out') kindLabel = 'Egress ACL';
                else if (step.kind === 'policy') kindLabel = 'Firewall Policy';
                else if (step.kind === 'skipped_policy') kindLabel = 'Policy Disabilitata (Skipped)';

                html += `
                <div style="border:1px solid var(--border); background:${stepWash}; padding:12px 16px; border-left:1px solid ${stepRule};">
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
                    ${step.prefix ? `<div style="font-size:12px; margin-top:4px;">Next-Hop: <code>${escapeHtml(step.next_hop || 'Connected')}</code> via <code>${escapeHtml(step.egress || 'Auto')}</code> <span style="color:var(--text-muted);">prefix</span> <code>${escapeHtml(step.prefix)}</code></div>` : ''}
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
            container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><div style="margin-top:10px;">Sintesi flussi d'esempio in corso...</div></div>`;
        }

        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ptSelectedIp)}/examples`);
            if (!res.ok) {
                if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">Impossibile caricare gli esempi per il dispositivo.</div>`;
                return;
            }
            const examples = await res.json();
            ptExamplesCache[ptSelectedIp] = examples;
            renderExamples(examples);
        } catch (e) {
            if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">Errore di rete durante il caricamento degli esempi.</div>`;
        }
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

        // Grouped per rule set. A device carries several ACLs whose sequence
        // numbers each restart at 10, so a flat list of "Regola 10" cards left
        // the reader no way to tell which ACL a rule belonged to.
        groups.forEach(group => {
            const bindings = group.bindings || [];
            const examples = group.examples || [];
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
                            ${examples.length} ${escapeHtml(L.ptRulesWord)} &middot; ${escapeHtml(L.ptDefaultWord)} ${escapeHtml(group.default_action || 'deny')}
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

                    <div style="margin-top:12px; display:flex; justify-content:flex-end; gap:8px;">
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
            container.innerHTML = `<div style="text-align:center; padding:30px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin fa-2x"></i><div style="margin-top:10px;">Analisi difetti statici in corso...</div></div>`;
        }

        try {
            const res = await apiFetch(`/api/policy-test/${encodeURIComponent(ptSelectedIp)}/findings`);
            if (!res.ok) {
                if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">Impossibile caricare i findings per il dispositivo.</div>`;
                return;
            }
            const findings = await res.json();
            ptFindingsCache[ptSelectedIp] = findings;
            renderFindings(findings);
        } catch (e) {
            if (container) container.innerHTML = `<div style="color:var(--danger); padding:20px;">Errore di rete durante il caricamento dei findings.</div>`;
        }
    }

    function renderFindings(findings) {
        const container = document.getElementById('ptFindingsContainer');
        if (!container) return;
        const L = i18n[currentLang];
        ptRenderedFindings = findings || [];

        if (!findings || findings.length === 0) {
            container.innerHTML = `
            <div style="text-align:center; padding:40px; color:var(--success);">
                <i class="fa-solid fa-circle-check fa-3x" style="margin-bottom:14px; opacity:0.8;"></i>
                <div style="font-size:15px; font-weight:600;">Nessun difetto di policy o routing rilevato</div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">Nessuna regola oscurata, non raggiungibile o rotta statica orfana identificata.</div>
            </div>`;
            return;
        }

        let html = `<div style="display:flex; flex-direction:column; gap:12px;">`;

        findings.forEach((f, idx) => {
            // Severity carries a wash plus a 1px rule, per DESIGN.md "Schedules":
            // the state is the fill, not a slab of colour down the edge.
            let sevBadge = 'badge badge-warning';
            let borderCol = 'var(--warning)';
            let washCol = 'var(--lamp-warn-wash)';
            if (f.severity === 'high') {
                sevBadge = 'badge badge-danger';
                borderCol = 'var(--danger)';
                washCol = 'var(--lamp-fault-wash)';
            } else if (f.severity === 'low') {
                sevBadge = 'badge';
                borderCol = 'var(--border)';
                washCol = 'var(--surface-2)';
            }

            let title = f.key;
            let desc = '';
            const p = f.params || {};

            if (f.key === 'shadowed') {
                title = 'Regola Oscurata / Ridondante (Shadowed)';
                desc = `La regola <strong>${escapeHtml(p.rule_id || '')}</strong> nella lista <code>${escapeHtml(p.acl || '')}</code> è interamente coperta dalla regola precedente <strong>${escapeHtml(p.shadowed_by || '')}</strong> e non verrà mai valutata per il traffico di match.`;
            } else if (f.key === 'unreachable') {
                title = 'Regola Non Raggiungibile (Unreachable)';
                desc = `La regola <strong>${escapeHtml(p.rule_id || '')}</strong> nella lista <code>${escapeHtml(p.acl || '')}</code> si trova dopo la regola ANY-ANY <strong>${escapeHtml(p.blocked_by || '')}</strong> e non può essere mai raggiunta.`;
            } else if (f.key === 'any_any') {
                title = 'Permesso Troppo Ampio (ANY-ANY Permit)';
                desc = `La regola <strong>${escapeHtml(p.rule_id || '')}</strong> nella lista <code>${escapeHtml(p.acl || '')}</code> autorizza traffico con sorgente, destinazione, protocollo e porte totalmente senza restrizioni (ANY-ANY).`;
            } else if (f.key === 'route_to_nowhere') {
                title = 'Rotta Statica Verso il Vuoto (Route to Nowhere)';
                desc = `La rotta statica verso il prefisso <code>${escapeHtml(p.prefix || '')}</code> punta al next-hop <code>${escapeHtml(p.next_hop || '')}</code> che non appartiene ad alcuna subnet direttamente connessa sulle interfacce attive.`;
            } else if (f.key === 'unresolved_object') {
                title = 'Riferimento a Oggetto Non Definito';
                desc = `La regola <strong>${escapeHtml(p.rule_id || '')}</strong> fa riferimento a oggetti indirizzo o servizio non definiti nel backup: <code>${escapeHtml((p.objects || []).join(', '))}</code>.`;
            }

            // A finding asserts a rule cannot fire. The witness turns that into
            // something the reader can check: a packet the rule was written to
            // catch, traced live by the same engine the tracer uses. Without it
            // the panel only says "trust me".
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
                    <button class="btn btn-secondary btn-small" data-action="prove-finding"
                        data-idx="${escapeHtml(String(idx))}" style="width:auto; margin:0;">
                        <i class="fa-solid fa-vial"></i> ${escapeHtml(L.ptProofRun)}
                    </button>
                    <div id="ptProofResult${escapeHtml(String(idx))}" style="margin-top:8px;"></div>
                </div>` : '';

            html += `
            <div style="border:1px solid var(--border); background:${washCol}; padding:14px 18px; border-left:1px solid ${borderCol};">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                    <div style="font-weight:700; font-size:14px;">${escapeHtml(title)}</div>
                    <span class="${sevBadge}">${escapeHtml((f.severity || 'medium').toUpperCase())}</span>
                </div>
                <div style="font-size:13px; color:var(--text); line-height:1.5;">${desc}</div>
                ${proofBlock}
            </div>`;
        });

        html += `</div>`;
        container.innerHTML = html;
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
                updateDeviceMeta();
                if (renderPolicySelectionState()) return;
                if (ptActiveSubtab === 'examples') loadPolicyExamples();
                else if (ptActiveSubtab === 'findings') loadPolicyFindings();
            });
        }

        const findingsBox = document.getElementById('ptFindingsContainer');
        if (findingsBox) {
            findingsBox.addEventListener('click', (e) => {
                const btn = e.target.closest('button[data-action="prove-finding"]');
                if (btn) proveFinding(parseInt(btn.dataset.idx, 10));
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

        const exContainer = document.getElementById('ptExamplesContainer');
        if (exContainer) {
            exContainer.addEventListener('click', (e) => {
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

    // Expose to window for cross-module dispatch
    window.loadPolicyTestTab = loadPolicyTestTab;
    window.runPolicyTrace = runPolicyTrace;
    window.switchPolicySubtab = switchPolicySubtab;
    window.usePolicyExample = usePolicyExample;
})();
