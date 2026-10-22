// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
//
// "Aggiungi apparati" (#addDevicesWizard): source -> addresses and destination
// -> per-row check -> result. The address flow runs here on /api/verify-device
// and /api/add-device; the other sources open the flow that already exists.
(() => {
    const $ = (id) => document.getElementById(id);

    // Sources handled elsewhere. `gate` is the tab whose visibility decides
    // whether the card is offered (scan and manual config are write actions
    // reached from tabs a viewer can open).
    const ADD_SOURCES = {
        one:    { tab: 'tab-provisioning', focus: 'devIp' },
        csv:    { tab: 'tab-import' },
        scan:   { tab: 'tab-devices', click: 'btnSubnetScan', gate: 'tab-import' },
        nbr:    { tab: 'tab-categories' },
        manual: { tab: 'tab-import', click: 'btnOpenManualConfig' },
        ztp:    { tab: 'tab-provisioner' },
    };
    const VERIFY_PARALLEL = 6;

    // rows: one per address {ip, hostname, vendor, state, msg, include, exists}
    // state: run | ok | bad | remote. results: null until the add starts.
    const adw = { rows: [], results: null, adding: false, gen: 0, ctx: null };

    const parsed = () => expandAddressList($('adwAddresses').value);
    const pickedLocation = () => locationById($('adwLocation').value);
    const probeOf = (loc) => (loc && loc.probe) || 'central';
    const included = () => adw.rows.filter((r) => r.include);

    // --- step: addresses and destination ---------------------------------
    function renderChips() {
        const r = parsed();
        $('adwChips').innerHTML =
            (r.ips.length ? `<span class="chip">${escapeHtml(tr('adwCount', { n: r.ips.length }))}</span>` : '')
            + r.bad.map((b) => `<span class="chip chip-bad">${escapeHtml(b)}</span>`).join('')
            + (r.truncated ? `<span class="chip chip-bad">${escapeHtml(tr('importPasteTruncated', { n: r.ips.length }))}</span>` : '');
    }

    function renderProbeNote() {
        const loc = pickedLocation();
        const probe = probeOf(loc);
        const note = $('adwProbeNote');
        note.hidden = !loc || probe === 'central';
        note.textContent = tr('adwRemoteProbe', { probe });
    }

    function fillLocations() {
        const sel = $('adwLocation');
        const keep = sel.value;
        const tenant = $('adwTenant').value;
        sel.innerHTML = `<option value="">${escapeHtml(tr('adwPickLocation'))}</option>` + locationOptionsHtml(keep, tenant);
        const own = globalLocations.filter((l) => l.org === tenant);
        if (!sel.value && own.length === 1) sel.value = own[0].id;
        renderProbeNote();
    }

    async function fillProfiles() {
        const sel = $('adwProfile');
        const keep = sel.value;
        const res = await apiFetch('/api/identities?tenant=' + encodeURIComponent($('adwTenant').value));
        const idents = res && res.ok ? (await res.json()).identities : [];
        sel.innerHTML = `<option value="default">${escapeHtml(tr('optProfileDefault').replace(/<[^>]*>/g, ''))}</option>`
            + idents.map((i) => `<option value="identity:${escapeHtml(i.id)}">${escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('');
        if (Array.from(sel.options).some((o) => o.value === keep)) sel.value = keep;
        else if (idents.length === 1) sel.value = `identity:${idents[0].id}`;
    }

    async function prepareDestination() {
        if (!Object.keys(globalGroups).length) {
            const res = await apiFetch('/api/groups');
            if (res && res.ok) { const d = await res.json(); globalGroups = (d && d.groups) || d || {}; }
        }
        if (!globalLocations.length) await loadLocations();
        const sel = $('adwTenant');
        const keep = sel.value || window.globalSelectedTenant;
        sel.innerHTML = Object.keys(globalGroups).map((g) =>
            `<option value="${escapeHtml(g)}">${escapeHtml(orgLabel(g))}</option>`).join('');
        if (keep in globalGroups) sel.value = keep;
        const vendor = $('adwVendor');
        const keepVendor = vendor.value || 'auto';
        vendor.innerHTML = autoVendorOption(keepVendor) + buildVendorOptions(keepVendor);
        fillLocations();
        await fillProfiles();
        renderChips();
    }

    // --- step: per-row check ---------------------------------------------
    const stateText = (r) => ({
        run: tr('adwStRun'),
        ok: r.exists ? tr('adwStUpdate') : tr('adwStReady'),
        bad: tr('adwStFix'),
        remote: tr('adwStRemote'),
    })[r.state];
    const stateClass = { run: 'is-run', ok: 'is-ok', bad: 'is-bad', remote: 'is-warn' };

    function renderRows() {
        // A failure's reason goes on its own full-width line under the row.
        $('adwRows').innerHTML = adw.rows.map((r, i) => `<tr class="${r.state === 'bad' ? 'has-msg' : ''}">
            <td><input type="checkbox" data-adw-include="${i}" ${r.include ? 'checked' : ''} ${r.state === 'run' ? 'disabled' : ''}
                 aria-label="${escapeHtml(tr('adwAriaInclude', { ip: r.ip }))}"></td>
            <td><code>${escapeHtml(r.ip)}</code></td>
            <td>${escapeHtml(r.hostname || '—')}</td>
            <td><select data-adw-vendor="${i}" aria-label="${escapeHtml(tr('adwAriaVendor', { ip: r.ip }))}">
                <option value="">${escapeHtml(tr('optScanNoVendor'))}</option>${buildVendorOptions(r.vendor)}</select></td>
            <td><span class="adw-state ${stateClass[r.state]}">${escapeHtml(stateText(r) || '')}</span></td>
            <td>${r.state === 'bad' ? `<button type="button" class="btn btn-secondary btn-small" data-adw-retry="${i}">${escapeHtml(tr('adwRetry'))}</button>` : ''}</td>
          </tr>${r.state === 'bad' ? `<tr class="adw-msg"><td></td><td colspan="5">${escapeHtml(r.msg)}</td></tr>` : ''}`).join('');
        const all = $('adwAll');
        if (all instanceof HTMLInputElement) all.checked = adw.rows.length > 0 && adw.rows.every((r) => r.include);
        setVerifyFooter();
    }

    function setVerifyFooter() {
        if (wizard.current() !== 'verify') return;
        const running = adw.rows.some((r) => r.state === 'run');
        const ok = adw.rows.filter((r) => r.state === 'ok').length;
        const bad = adw.rows.filter((r) => r.state === 'bad').length;
        $('adwVerifyStatus').textContent = running
            ? tr('adwVerifyRunning', { done: adw.rows.filter((r) => r.state !== 'run').length, total: adw.rows.length })
            : adw.ctx.probe !== 'central' ? tr('adwRemoteProbe', { probe: adw.ctx.probe })
            : tr('adwVerifySummary', { ok, bad });
        const next = document.querySelector('#addDevicesWizard [data-wizard-next]');
        if (!(next instanceof HTMLButtonElement)) return;
        next.textContent = tr('adwAddN', { n: included().length });
        next.disabled = running || included().length === 0;
    }

    async function verifyRow(row, gen) {
        row.state = 'run';
        renderRows();
        const { vendor, profile, group, probe } = adw.ctx;
        const res = await apiFetch('/api/verify-device', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: row.ip, vendor: row.vendor || vendor, profile, group, probe }),
        });
        const data = res ? await res.json().catch(() => ({})) : {};
        if (gen !== adw.gen) return;
        if (res && res.ok && data.ok) {
            Object.assign(row, { state: 'ok', hostname: data.hostname || '', include: true, msg: '' });
            if (data.vendor && data.vendor !== 'auto') row.vendor = data.vendor;
        } else {
            Object.assign(row, { state: 'bad', include: false,
                                 msg: (data && (data.error || data.detail)) || tr('uiNetworkError') });
        }
        renderRows();
    }

    async function enterVerify() {
        const gen = ++adw.gen;
        const loc = pickedLocation();
        adw.ctx = { vendor: $('adwVendor').value, profile: $('adwProfile').value,
                    group: $('adwTenant').value, location: $('adwLocation').value, probe: probeOf(loc) };
        const known = new Set((globalDevices || []).map((d) => d.IP));
        const remote = adw.ctx.probe !== 'central';
        adw.rows = parsed().ips.map((ip) => ({
            ip, hostname: '', vendor: adw.ctx.vendor === 'auto' ? '' : adw.ctx.vendor,
            state: remote ? 'remote' : 'run', msg: '', include: remote, exists: known.has(ip),
        }));
        // After the wizard's own render, which sets the Next label.
        queueMicrotask(renderRows);
        if (remote) return;
        let next = 0;
        const worker = async () => {
            while (next < adw.rows.length && gen === adw.gen) await verifyRow(adw.rows[next++], gen);
        };
        await Promise.all(Array.from({ length: Math.min(VERIFY_PARALLEL, adw.rows.length) }, worker));
    }

    // --- step: result ------------------------------------------------------
    function renderDone() {
        const res = adw.results || [];
        const added = res.filter((x) => x.ok && !x.row.exists).length;
        const updated = res.filter((x) => x.ok && x.row.exists).length;
        const failed = res.filter((x) => !x.ok);
        const left = adw.rows.filter((r) => !r.include);
        const pending = adw.adding ? included().length - res.length : 0;
        $('adwDone').innerHTML = `
          <div class="adw-kpis">
            <div><strong>${added}</strong><span>${escapeHtml(tr('adwKpiAdded'))}</span></div>
            <div><strong>${updated}</strong><span>${escapeHtml(tr('adwKpiUpdated'))}</span></div>
            <div><strong>${failed.length + left.length}</strong><span>${escapeHtml(tr('adwKpiLeft'))}</span></div>
          </div>
          ${pending ? `<p class="set-desc">${escapeHtml(tr('adwAdding', { n: pending }))}</p>` : ''}
          <ul class="adw-result">${res.map((x) => `<li class="${x.ok ? 'is-ok' : 'is-bad'}">
              <code>${escapeHtml(x.row.ip)}</code> ${escapeHtml(x.row.hostname || '')}
              <span>${escapeHtml(x.ok ? (x.row.exists ? tr('adwRowUpdated') : tr('adwRowAdded')) : x.msg)}</span></li>`).join('')}
            ${left.map((r) => `<li class="is-warn"><code>${escapeHtml(r.ip)}</code>
              <span>${escapeHtml(r.state === 'bad' ? r.msg : tr('adwExcluded'))}</span></li>`).join('')}
          </ul>
          ${adw.adding ? '' : `<div class="adw-done-actions">
            <button type="button" class="btn btn-secondary" data-adw-action="inventory">${escapeHtml(tr('homeOpenInventory').replace(/<[^>]*>/g, '').trim())}</button>
            <button type="button" class="btn btn-secondary" data-adw-action="again">${escapeHtml(tr('adwAgain'))}</button>
            ${failed.length + left.length ? `<button type="button" class="btn btn-secondary" data-adw-action="download">${escapeHtml(tr('adwDownloadLeft'))}</button>` : ''}
          </div>`}`;
    }

    async function enterDone() {
        if (adw.results) { renderDone(); return; }
        adw.results = [];
        adw.adding = true;
        const { group, location: loc, probe, profile } = adw.ctx;
        renderDone();
        for (const row of included()) {
            const res = await apiFetch('/api/add-device', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: row.ip, vendor: row.vendor, profile, group, location: loc, probe,
                                       username: '', password: '', enable_secret: '' }),
            });
            const err = res && !res.ok ? await res.json().catch(() => ({})) : null;
            adw.results.push({ row, ok: !!(res && res.ok), msg: err ? (err.detail || tr('alertSaveDeviceError')) : '' });
            renderDone();
        }
        adw.adding = false;
        renderDone();
        wizard.refresh();
        refreshInventory();
    }

    function downloadLeft() {
        const failed = new Map((adw.results || []).filter((x) => !x.ok).map((x) => [x.row.ip, x.msg]));
        const rows = adw.rows.filter((r) => !r.include || failed.has(r.ip))
            .map((r) => [r.ip, failed.get(r.ip) || (r.state === 'bad' ? r.msg : tr('adwExcluded'))]);
        const csv = 'IP,Note\n' + rows.map(([ip, note]) => `${ip},"${String(note).replace(/"/g, '""')}"`).join('\n');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
        a.download = 'apparati-scartati.csv';
        a.click();
        URL.revokeObjectURL(a.href);
    }

    const wizard = createWizard('addDevicesWizard', {
        steps: [
            { id: 'source', label: 'adwStepSource', skip: () => !!adw.results },
            { id: 'addresses', label: 'adwStepAddresses', skip: () => !!adw.results,
              validate: () => parsed().ips.length > 0 && !!$('adwLocation').value && !!$('adwTenant').value },
            { id: 'verify', label: 'adwStepVerify', skip: () => !!adw.results, onEnter: enterVerify,
              validate: () => included().length > 0 && !adw.rows.some((r) => r.state === 'run') },
            { id: 'done', label: 'adwStepDone', onEnter: enterDone, validate: () => !adw.adding,
              finishLabel: 'btnClose' },
        ],
        onFinish: () => wizard.close(),
    });

    async function openAddDevices(at) {
        adw.gen++;
        Object.assign(adw, { rows: [], results: null, adding: false });
        const panel = $('addDevicesWizard');
        panel.querySelectorAll('[data-add-source]').forEach((b) => {
            const s = ADD_SOURCES[b.getAttribute('data-add-source')];
            if (b instanceof HTMLElement) b.hidden = !canOpenTab(s.gate || s.tab);
        });
        const addr = panel.querySelector('[data-adw-source="addr"]');
        if (addr instanceof HTMLElement) addr.hidden = !canOpenTab('tab-provisioning');
        await prepareDestination();
        wizard.open({ at, onClose: () => { adw.gen++; } });
    }
    window.openAddDevices = openAddDevices;

    // --- events ------------------------------------------------------------
    const panel = $('addDevicesWizard');
    $('adwAddresses').addEventListener('input', renderChips);
    $('adwTenant').addEventListener('change', () => { fillLocations(); fillProfiles(); });
    $('adwLocation').addEventListener('change', renderProbeNote);
    // The wizard redraws on every change and resets the Next label: put it back.
    panel.addEventListener('change', (e) => {
        const t = e.target;
        if (t instanceof HTMLInputElement && t.id === 'adwAll') {
            adw.rows.forEach((r) => { if (r.state !== 'run') r.include = t.checked; });
            renderRows();
        } else if (t instanceof HTMLInputElement && t.dataset.adwInclude !== undefined) {
            adw.rows[+t.dataset.adwInclude].include = t.checked;
            renderRows();
        } else if (t instanceof HTMLSelectElement && t.dataset.adwVendor !== undefined) {
            adw.rows[+t.dataset.adwVendor].vendor = t.value;
            setVerifyFooter();
        } else {
            setVerifyFooter();
        }
    });
    panel.addEventListener('click', async (e) => {
        const t = e.target instanceof Element ? e.target : null;
        if (!t) return;
        if (t.closest('[data-adw-source="addr"]')) { wizard.goTo('addresses'); $('adwAddresses').focus(); return; }
        const retry = t.closest('[data-adw-retry]');
        if (retry) { verifyRow(adw.rows[+(retry.getAttribute('data-adw-retry') || 0)], adw.gen); return; }
        const act = t.closest('[data-adw-action]');
        if (act) {
            const a = act.getAttribute('data-adw-action');
            if (a === 'inventory') { wizard.close(); switchTab('tab-devices'); }
            else if (a === 'again') {
                Object.assign(adw, { results: null, rows: [] });
                const box = $('adwAddresses');
                if (box instanceof HTMLTextAreaElement) box.value = '';
                renderChips();
                wizard.goTo('addresses');
            }
            else if (a === 'download') downloadLeft();
            return;
        }
        const card = t.closest('[data-add-source]');
        if (!card) return;
        const s = ADD_SOURCES[card.getAttribute('data-add-source') || ''];
        wizard.close();
        await switchTab(s.tab);
        if (s.click) $(s.click)?.click();
        if (s.focus) $(s.focus)?.focus();
    });
    document.addEventListener('click', (e) => {
        if (e.target instanceof Element && e.target.closest('[data-action="open-add-devices"]')) openAddDevices();
    });
})();
