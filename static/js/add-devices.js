// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
//
// "Aggiungi apparati" (#addDevicesWizard): source -> input and destination ->
// check -> result, all inside the panel for addresses, CSV file, network scan
// and discovered neighbors. "Senza accesso" and "Nuova configurazione" are their own
// procedures and open them.
(() => {
    const $ = (id) => document.getElementById(id);
    const VERIFY_PARALLEL = 6;

    // Which tabs must be visible for a source to be offered. Scan, CSV and
    // manual config are write actions: tab-import is the write-only gate.
    const SOURCE_GATES = {
        addr: ['tab-provisioning'], csv: ['tab-import'], scan: ['tab-devices', 'tab-import'],
        nbr: ['tab-categories', 'tab-provisioning'], manual: ['tab-import'], ztp: ['tab-provisioner'],
    };
    const ELSEWHERE = new Set(['manual', 'ztp']);

    // src: chosen source. rows: one per device in the check step
    //   {ip, hostname, vendor, state, msg, include, exists, nodeId?, csvRow?, location?}
    //   state: run | ok | bad | remote | new | update | error | skipped (last four: CSV preview)
    // results: null until the add starts. gen: stales async loops on close.
    // csvDecisions: per-row answers to the CSV preview ({ location } = move it there).
    const adw = { src: 'addr', rows: [], results: null, adding: false, gen: 0, ctx: null,
                  csvText: '', csvDecisions: {}, neighbors: [] };

    const isCsv = () => adw.src === 'csv';
    const parsed = () => expandAddressList(val('adwAddresses'));
    const pickedLocation = () => locationById(val('adwLocation'));
    const probeOf = (loc) => (loc && loc.probe) || 'central';
    const included = () => adw.rows.filter((r) => r.include);
    function val(id) {
        const el = $(id);
        return el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement ? el.value : '';
    }
    const post = (url, body) => apiFetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

    // --- step 1: source ------------------------------------------------------
    function renderSources() {
        $('addDevicesWizard').querySelectorAll('[data-adw-source]').forEach((b) => {
            const on = b.getAttribute('data-adw-source') === adw.src;
            b.classList.toggle('is-on', on);
            b.setAttribute('aria-checked', String(on));
        });
    }

    // --- step 2: input and destination ---------------------------------------
    function renderInputs() {
        const panel = $('addDevicesWizard');
        panel.querySelectorAll('[data-adw-for]').forEach((el) => {
            if (el instanceof HTMLElement) el.hidden = el.getAttribute('data-adw-for') !== adw.src;
        });
        panel.querySelectorAll('[data-adw-hide]').forEach((el) => {
            if (el instanceof HTMLElement) el.hidden = el.getAttribute('data-adw-hide') === adw.src;
        });
        fillLocations();
        if (adw.src === 'nbr') renderNeighbors();
        if (isCsv()) loadProbeIds();
    }

    // The Probe column carries the probe id, a slug nobody types: list the real ones.
    async function loadProbeIds() {
        const res = await apiFetch('/api/probes');
        const probes = res && res.ok ? (await res.json()).probes || [] : [];
        $('importProbeIdsList').innerHTML = probes.map((x) => `<code>${escapeHtml(x.id)}</code>`).join(' ');
        $('importProbeIds').hidden = !probes.length;
    }

    // 'Probe' is in the template although optional: next to Group, with a
    // different value, it shows they are two things. Omitted, it is 'central'.
    const CSV_TEMPLATE = [
        'IP,Username,Password,Enable Secret,Hostname,Group,Location,Probe,Vendor',
        '192.0.2.1,admin,Mypass123!,enablepass,switch-01,acme,roma,central,cisco',
        '198.51.100.1,manager,Pwd456!,secret,switch-02,acme,roma,probe-roma,hpe',
        '',
    ].join('\n');

    function downloadTemplate() {
        // BOM first: without it Excel reads the file as ANSI and mangles accented site names.
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob(['\ufeff' + CSV_TEMPLATE], { type: 'text/csv;charset=utf-8' }));
        a.download = 'sentinelnet-inventario-modello.csv';
        a.click();
        URL.revokeObjectURL(a.href);
    }

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
        note.hidden = isCsv() || !loc || probe === 'central';
        note.textContent = tr('adwRemoteProbe', { probe });
    }

    function fillLocations() {
        const sel = $('adwLocation');
        const keep = val('adwLocation');
        const tenant = val('adwTenant');
        // For a CSV the empty choice is meaningful: each row's own Location.
        sel.innerHTML = `<option value="">${escapeHtml(tr(isCsv() ? 'importPickDestination' : 'adwPickLocation'))}</option>`
            + locationOptionsHtml(keep, tenant);
        const own = globalLocations.filter((l) => l.org === tenant);
        if (!val('adwLocation') && own.length === 1 && sel instanceof HTMLSelectElement) sel.value = own[0].id;
        renderProbeNote();
    }

    async function fillProfiles() {
        const sel = $('adwProfile');
        const keep = val('adwProfile');
        const res = await apiFetch('/api/identities?tenant=' + encodeURIComponent(val('adwTenant')));
        const idents = res && res.ok ? (await res.json()).identities : [];
        sel.innerHTML = `<option value="default">${escapeHtml(tr('optProfileDefault').replace(/<[^>]*>/g, ''))}</option>`
            + idents.map((i) => `<option value="identity:${escapeHtml(i.id)}">${escapeHtml(i.name)} (${escapeHtml(i.username)})</option>`).join('');
        if (!(sel instanceof HTMLSelectElement)) return;
        if (Array.from(sel.options).some((o) => o.value === keep)) sel.value = keep;
        else if (idents.length === 1) sel.value = `identity:${idents[0].id}`;
    }

    async function loadNeighbors() {
        $('adwNbrList').innerHTML = `<p class="form-hint">${escapeHtml(tr('adwNbrLoading'))}</p>`;
        const res = await apiFetch('/api/device-classification');
        const data = res && res.ok ? await res.json() : { nodes: [] };
        adw.neighbors = (data.nodes || []).filter((n) => n.discovered && n.display_ip)
            .map((n) => ({ node: n, picked: false }));
        renderNeighbors();
        wizard.refresh();
    }

    function renderNeighbors() {
        const tenant = val('adwTenant');
        const list = adw.neighbors.filter((x) => x.node.group === tenant);
        $('adwNbrList').innerHTML = list.length
            ? list.map((x) => {
                const i = adw.neighbors.indexOf(x);
                const n = x.node;
                return `<label class="adw-nbr"><input type="checkbox" data-adw-nbr="${i}" ${x.picked ? 'checked' : ''}>
                    <code>${escapeHtml(n.display_ip)}</code> <b>${escapeHtml(n.label || '')}</b>
                    <span>${escapeHtml([n.vendor && n.vendor !== 'discovered' ? n.vendor.toUpperCase() : '', n.model || ''].filter(Boolean).join(' · '))}</span></label>`;
            }).join('')
            : `<p class="form-hint">${escapeHtml(tr('adwNbrNone'))}</p>`;
    }

    async function prepareDestination() {
        if (!Object.keys(globalGroups).length) {
            const res = await apiFetch('/api/groups');
            if (res && res.ok) { const d = await res.json(); globalGroups = (d && d.groups) || d || {}; }
        }
        if (!globalLocations.length) await loadLocations();
        const sel = $('adwTenant');
        const keep = val('adwTenant') || window.globalSelectedTenant;
        sel.innerHTML = Object.keys(globalGroups).map((g) =>
            `<option value="${escapeHtml(g)}">${escapeHtml(orgLabel(g))}</option>`).join('');
        if (keep in globalGroups && sel instanceof HTMLSelectElement) sel.value = keep;
        const vendor = $('adwVendor');
        const keepVendor = val('adwVendor') || 'auto';
        vendor.innerHTML = autoVendorOption(keepVendor) + buildVendorOptions(keepVendor);
        await fillProfiles();
        renderChips();
    }

    function inputReady() {
        if (!val('adwTenant')) return false;
        if (adw.src === 'csv') return !!adw.csvText;
        if (!val('adwLocation')) return false;
        if (adw.src === 'addr') return parsed().ips.length > 0;
        if (adw.src === 'scan') return !!val('adwScanNet').trim();
        if (adw.src === 'nbr') return adw.neighbors.some((x) => x.picked && x.node.group === val('adwTenant'));
        return false;
    }

    // --- step 3: check -------------------------------------------------------
    const STATE_TEXT = {
        run: () => tr('adwStRun'), ok: (r) => tr(r.exists ? 'adwStUpdate' : 'adwStReady'), bad: () => tr('adwStFix'),
        remote: () => tr('adwStRemote'), new: () => tr('importStNew'), update: () => tr('importStUpdate'),
        error: () => tr('importStError'), skipped: () => tr('importStSkipped'),
    };
    const STATE_CLASS = { run: 'is-run', ok: 'is-ok', new: 'is-ok', update: 'is-ok', bad: 'is-bad',
                          error: 'is-bad', skipped: 'is-warn', remote: 'is-warn' };
    const hasMsg = (r) => !!r.msg;
    const locked = (r) => r.state === 'run' || r.state === 'error' || r.state === 'skipped';

    function renderRows() {
        // Fourth column: vendor for a live check, site for a CSV preview (its
        // vendor comes from the file).
        const heads = document.querySelectorAll('#addDevicesWizard .adw-table thead th');
        heads[3].textContent = tr(isCsv() ? 'adwLblLocation' : 'adwThVendor');
        $('adwRows').innerHTML = adw.rows.map((r, i) => `<tr class="${hasMsg(r) ? 'has-msg' : ''}">
            <td><input type="checkbox" data-adw-include="${i}" ${r.include ? 'checked' : ''} ${locked(r) ? 'disabled' : ''}
                 aria-label="${escapeHtml(tr('adwAriaInclude', { ip: r.ip }))}"></td>
            <td><code>${escapeHtml(r.ip || '—')}</code></td>
            <td>${escapeHtml(r.hostname || '—')}</td>
            <td>${isCsv() ? escapeHtml(r.location ? locationLabel(r.location) : '—')
                : `<select data-adw-vendor="${i}" aria-label="${escapeHtml(tr('adwAriaVendor', { ip: r.ip }))}">
                   <option value="">${escapeHtml(tr('optScanNoVendor'))}</option>${buildVendorOptions(r.vendor)}</select>`}</td>
            <td><span class="adw-state ${STATE_CLASS[r.state]}">${escapeHtml(STATE_TEXT[r.state](r))}</span></td>
            <td>${r.state === 'bad' ? `<button type="button" class="btn btn-secondary btn-small" data-adw-retry="${i}">${escapeHtml(tr('adwRetry'))}</button>`
                : r.moveTo ? `<button type="button" class="btn btn-secondary btn-small" data-adw-move="${i}">${escapeHtml(tr('importActionMove', { name: locationLabel(r.moveTo) }))}</button>` : ''}</td>
          </tr>${hasMsg(r) ? `<tr class="adw-msg${['new', 'update'].includes(r.state) ? ' is-info' : ''}"><td></td><td colspan="5">${escapeHtml(r.msg)}</td></tr>` : ''}`).join('');
        const all = $('adwAll');
        const free = adw.rows.filter((r) => !locked(r));
        if (all instanceof HTMLInputElement) all.checked = free.length > 0 && free.every((r) => r.include);
        setVerifyFooter();
    }

    function setVerifyFooter(status) {
        if (wizard.current() !== 'verify' || !adw.ctx) return;
        const running = adw.rows.some((r) => r.state === 'run') || adw.ctx.scanning;
        if (status) $('adwVerifyStatus').textContent = status;
        else if (isCsv()) {
            $('adwVerifyStatus').textContent = tr('adwCsvSummary', {
                ready: adw.rows.filter((r) => r.state === 'new' || r.state === 'update').length,
                bad: adw.rows.filter((r) => r.state === 'error' || r.state === 'skipped').length });
        } else if (!adw.ctx.scanning) {
            const ok = adw.rows.filter((r) => r.state === 'ok').length;
            const bad = adw.rows.filter((r) => r.state === 'bad').length;
            $('adwVerifyStatus').textContent = adw.rows.some((r) => r.state === 'run')
                ? tr('adwVerifyRunning', { done: adw.rows.filter((r) => r.state !== 'run').length, total: adw.rows.length })
                : adw.ctx.probe !== 'central' ? tr('adwRemoteProbe', { probe: adw.ctx.probe })
                : !adw.rows.length ? tr('adwScanNothing')
                : tr('adwVerifySummary', { ok, bad });
        }
        const next = document.querySelector('#addDevicesWizard [data-wizard-next]');
        if (!(next instanceof HTMLButtonElement)) return;
        next.textContent = tr(isCsv() ? 'adwImportN' : 'adwAddN', { n: included().length });
        next.disabled = running || included().length === 0;
    }

    async function verifyRow(row, gen) {
        row.state = 'run';
        renderRows();
        const { vendor, profile, group, probe } = adw.ctx;
        const res = await post('/api/verify-device', { ip: row.ip, vendor: row.vendor || vendor, profile, group, probe });
        const data = res ? await res.json().catch(() => ({})) : {};
        if (gen !== adw.gen) return;
        if (res && res.ok && data.ok) {
            Object.assign(row, { state: 'ok', hostname: data.hostname || row.hostname, include: true, msg: '' });
            if (data.vendor && data.vendor !== 'auto') row.vendor = data.vendor;
        } else {
            Object.assign(row, { state: 'bad', include: false,
                                 msg: (data && (data.error || data.detail)) || tr('uiNetworkError') });
        }
        renderRows();
    }

    async function verifyAll(gen) {
        if (adw.ctx.probe !== 'central') {
            adw.rows.forEach((r) => { r.state = 'remote'; r.include = true; });
            renderRows();
            return;
        }
        let next = 0;
        const worker = async () => {
            while (next < adw.rows.length && gen === adw.gen) await verifyRow(adw.rows[next++], gen);
        };
        await Promise.all(Array.from({ length: Math.min(VERIFY_PARALLEL, adw.rows.length) }, worker));
    }

    function newRow(ip, extra = {}) {
        const known = new Set((globalDevices || []).map((d) => d.IP));
        return { ip, hostname: '', vendor: adw.ctx.vendor === 'auto' ? '' : adw.ctx.vendor,
                 state: 'run', msg: '', include: false, exists: known.has(ip), ...extra };
    }

    async function runScan(gen) {
        adw.ctx.scanning = true;
        setVerifyFooter(tr('adwScanRunning', { done: 0, total: '…' }));
        const ports = val('adwScanPorts').split(/[\s,;]+/).filter(Boolean).map(Number);
        const res = await post('/api/scan-subnet', { network: val('adwScanNet').trim(), ports });
        const start = res ? await res.json().catch(() => ({})) : {};
        if (!res || !res.ok) {
            adw.ctx.scanning = false;
            setVerifyFooter(tr('devVerifyFail', { err: start.detail || tr('uiNetworkError') }));
            return null;
        }
        for (;;) {
            await new Promise((r) => setTimeout(r, 1500));
            if (gen !== adw.gen) return null;
            const poll = await apiFetch(`/api/scan-subnet/${start.job_id}`);
            const job = poll && poll.ok ? await poll.json() : { status: 'error' };
            if (job.status === 'running') { setVerifyFooter(tr('adwScanRunning', { done: job.progress, total: job.total })); continue; }
            adw.ctx.scanning = false;
            if (job.status !== 'done') { setVerifyFooter(tr('devVerifyFinishedWithError')); return null; }
            return (job.results || []).map((r) => r.ip);
        }
    }

    async function runCsvPreview(gen) {
        const res = await post('/api/import-csv/preview', { csv_data: adw.csvText, org: adw.ctx.group || null,
                                                            location: adw.ctx.location || null, decisions: adw.csvDecisions });
        const data = res ? await res.json().catch(() => ({})) : {};
        if (gen !== adw.gen) return;
        if (!res || !res.ok) { setVerifyFooter(tr('devVerifyFail', { err: data.detail || tr('alertImportCsvError') })); return; }
        adw.rows = (data.rows || []).map((r) => ({
            ip: r.ip || '', hostname: r.hostname || '', location: r.location || '', csvRow: r.row, state: r.status,
            include: r.status === 'new' || r.status === 'update', exists: r.status === 'update',
            moveTo: r.action && r.action.kind === 'move' ? r.action.location : '',
            msg: [r.reason,
                  ...Object.keys(r.changes || {}).map((f) => (r.changes[f][1] === 'changed'
                      ? `${f}: ${tr('importPwdChanged')}` : `${f}: ${r.changes[f][0]} → ${r.changes[f][1]}`)),
                  ...(r.warnings || []), r.credentials_note]
                .filter(Boolean).join(' · '),
        }));
        renderRows();
    }

    async function enterVerify() {
        const gen = ++adw.gen;
        adw.ctx = { vendor: val('adwVendor'), profile: val('adwProfile'), group: val('adwTenant'),
                    location: val('adwLocation'), probe: probeOf(pickedLocation()), scanning: false };
        adw.rows = [];
        // After the wizard's own render, which sets the Next label.
        queueMicrotask(renderRows);
        if (isCsv()) { await runCsvPreview(gen); return; }
        if (adw.src === 'nbr') {
            const auto = adw.ctx.vendor === 'auto';
            adw.rows = adw.neighbors.filter((x) => x.picked && x.node.group === adw.ctx.group).map(({ node: n }) =>
                newRow(n.display_ip, { hostname: n.label || '', nodeId: n.id, node: n,
                                       vendor: auto ? (n.vendor && n.vendor !== 'discovered' ? n.vendor : '') : adw.ctx.vendor }));
        } else {
            const ips = adw.src === 'scan' ? ((await runScan(gen)) || []) : parsed().ips;
            if (gen !== adw.gen) return;
            adw.rows = ips.map((ip) => newRow(ip));
        }
        renderRows();
        await verifyAll(gen);
    }

    // --- step 4: result --------------------------------------------------------
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
          ${adw.adding ? `<p class="set-desc">${escapeHtml(tr('adwAdding', { n: pending }))}</p>` : ''}
          <ul class="adw-result">${res.map((x) => `<li class="${x.ok ? 'is-ok' : 'is-bad'}">
              <code>${escapeHtml(x.row.ip)}</code> ${escapeHtml(x.row.hostname || '')}
              <span>${escapeHtml(x.ok ? tr(x.row.exists ? 'adwRowUpdated' : 'adwRowAdded') : x.msg)}</span></li>`).join('')}
            ${left.map((r) => `<li class="is-warn"><code>${escapeHtml(r.ip || '—')}</code>
              <span>${escapeHtml(r.msg || tr('adwExcluded'))}</span></li>`).join('')}
          </ul>
          ${adw.adding ? '' : `<div class="adw-done-actions">
            <button type="button" class="btn btn-secondary" data-adw-action="inventory">${escapeHtml(tr('homeOpenInventory').replace(/<[^>]*>/g, '').trim())}</button>
            <button type="button" class="btn btn-secondary" data-adw-action="again">${escapeHtml(tr('adwAgain'))}</button>
            ${failed.length + left.length ? `<button type="button" class="btn btn-secondary" data-adw-action="download">${escapeHtml(tr('adwDownloadLeft'))}</button>` : ''}
          </div>`}`;
    }

    async function addOne(row) {
        const { group, location, probe, profile } = adw.ctx;
        if (row.nodeId) {
            // Promote first, so the device keeps what CDP/LLDP already knew
            // (model, version, category, name); the add below sets credentials.
            const n = row.node;
            await post('/api/promote-device', { node_id: n.id, ip: row.ip, vendor: row.vendor || 'cisco', group, location,
                                                model: n.model || '', version: n.version || '',
                                                device_type: n.device_type || '', hostname: n.label || '' });
        }
        const res = await post('/api/add-device', { ip: row.ip, vendor: row.vendor, profile, group, location, probe,
                                                    username: '', password: '', enable_secret: '' });
        const err = res && !res.ok ? await res.json().catch(() => ({})) : null;
        return { row, ok: !!(res && res.ok), msg: err ? (err.detail || tr('alertSaveDeviceError')) : '' };
    }

    async function importCsv() {
        const decisions = { ...adw.csvDecisions };
        adw.rows.filter((r) => !r.include && !locked(r)).forEach((r) => { decisions[r.csvRow] = { skip: true }; });
        const res = await post('/api/import-csv', { csv_data: adw.csvText, org: adw.ctx.group || null,
                                                    location: adw.ctx.location || null, decisions });
        const data = res ? await res.json().catch(() => ({})) : {};
        if (!res || !res.ok) {
            adw.results = included().map((row) => ({ row, ok: false, msg: data.detail || tr('alertImportCsvError') }));
            return;
        }
        const failed = new Map((data.failed || []).map((f) => [String(f.ip), String(f.error)]));
        adw.results = included().map((row) => ({ row, ok: !failed.has(row.ip), msg: failed.get(row.ip) || '' }));
    }

    async function enterDone() {
        if (adw.results) { renderDone(); return; }
        adw.results = [];
        adw.adding = true;
        renderDone();
        if (isCsv()) await importCsv();
        else for (const row of included()) { adw.results.push(await addOne(row)); renderDone(); }
        adw.adding = false;
        renderDone();
        wizard.refresh();
        refreshInventory();
    }

    function downloadLeft() {
        const failed = new Map((adw.results || []).filter((x) => !x.ok).map((x) => [x.row.ip, x.msg]));
        const rows = adw.rows.filter((r) => !r.include || failed.has(r.ip))
            .map((r) => [r.ip, failed.get(r.ip) || r.msg || tr('adwExcluded')]);
        const csv = 'IP,Note\n' + rows.map(([ip, note]) => `${ip},"${String(note).replace(/"/g, '""')}"`).join('\n');
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
        a.download = 'apparati-scartati.csv';
        a.click();
        URL.revokeObjectURL(a.href);
    }

    const inPanel = () => !ELSEWHERE.has(adw.src);
    const wizard = createWizard('addDevicesWizard', {
        steps: [
            { id: 'source', label: 'adwStepSource', skip: () => !!adw.results, finishLabel: 'adwOpen' },
            { id: 'addresses', label: 'adwStepAddresses', skip: () => !!adw.results || !inPanel(),
              onEnter: renderInputs, validate: inputReady },
            { id: 'verify', label: 'adwStepVerify', skip: () => !!adw.results || !inPanel(), onEnter: enterVerify,
              validate: () => included().length > 0 && !adw.rows.some((r) => r.state === 'run') },
            { id: 'done', label: 'adwStepDone', skip: () => !inPanel(), onEnter: enterDone,
              validate: () => !adw.adding, finishLabel: 'btnClose', noJump: true },
        ],
        onFinish: async (stepId) => {
            wizard.close();
            if (stepId !== 'source') return;
            if (adw.src === 'manual') window.openManualConfigWizard();
            else await switchTab('tab-provisioner');
        },
    });

    // preset: { src, group, location } -- e.g. the CSV import of one location,
    // from the Organizations tab. It opens on the input step.
    async function openAddDevices(preset = {}) {
        adw.gen++;
        Object.assign(adw, { rows: [], results: null, adding: false, csvText: '', csvDecisions: {}, neighbors: [], ctx: null });
        const panel = $('addDevicesWizard');
        let first = null;
        panel.querySelectorAll('[data-adw-source]').forEach((b) => {
            const src = b.getAttribute('data-adw-source') || '';
            const ok = SOURCE_GATES[src].every(canOpenTab);
            if (b instanceof HTMLElement) b.hidden = !ok;
            if (ok && !first) first = src;
        });
        if (!first) return;
        if (preset.src && SOURCE_GATES[preset.src].every(canOpenTab)) adw.src = preset.src;
        if (!SOURCE_GATES[adw.src].every(canOpenTab)) adw.src = first;
        const file = $('adwCsvFile');
        if (file instanceof HTMLInputElement) file.value = '';
        $('adwCsvNote').hidden = true;
        renderSources();
        const tenant = $('adwTenant');
        if (preset.group && tenant instanceof HTMLSelectElement) tenant.value = preset.group;
        await prepareDestination();
        if (adw.src === 'nbr') loadNeighbors();
        wizard.open({ at: preset.src ? 'addresses' : undefined, editable: true, onClose: () => { adw.gen++; } });
        // After the step's own fill, which builds the location options.
        const loc = $('adwLocation');
        if (preset.location && loc instanceof HTMLSelectElement) { loc.value = preset.location; renderProbeNote(); }
    }
    window.openAddDevices = openAddDevices;

    // --- events ------------------------------------------------------------
    const panel = $('addDevicesWizard');
    $('adwAddresses').addEventListener('input', renderChips);
    $('adwTenant').addEventListener('change', () => { fillLocations(); fillProfiles(); if (adw.src === 'nbr') renderNeighbors(); });
    // New location for the chosen tenant (admins: /api/locations is admin-only).
    function newLocation() {
        window.openNewLocation(val('adwTenant'), async (id) => {
            await loadLocations();
            fillLocations();
            const loc = $('adwLocation');
            if (loc instanceof HTMLSelectElement) loc.value = id;
            renderProbeNote();
            wizard.refresh();
        });
    }
    $('adwNewLocation').addEventListener('click', newLocation);
    // A new tenant has no location yet: an admin goes straight on to create one.
    $('adwNewTenant').addEventListener('click', () => window.openNewTenant(async (name) => {
        await prepareDestination();
        const sel = $('adwTenant');
        if (sel instanceof HTMLSelectElement) sel.value = name;
        fillLocations();
        await fillProfiles();
        wizard.refresh();
        if (isAdminRole(currentRole)) newLocation();
    }));
    $('adwLocation').addEventListener('change', renderProbeNote);
    $('adwCsvFile').addEventListener('change', () => {
        const input = $('adwCsvFile');
        const f = input instanceof HTMLInputElement && input.files ? input.files[0] : null;
        adw.csvText = '';
        adw.csvDecisions = {};
        if (!f) return;
        const reader = new FileReader();
        reader.onload = () => {
            adw.csvText = String(reader.result || '');
            const note = $('adwCsvNote');
            note.textContent = tr('adwCsvLoaded', { name: f.name, n: Math.max(0, adw.csvText.trim().split(/\r?\n/).length - 1) });
            note.hidden = false;
            wizard.refresh();
        };
        reader.readAsText(f);
    });
    // The wizard redraws on every change and resets the Next label: put it back.
    panel.addEventListener('change', (e) => {
        const t = e.target;
        if (t instanceof HTMLInputElement && t.id === 'adwAll') {
            adw.rows.forEach((r) => { if (!locked(r)) r.include = t.checked; });
            renderRows();
        } else if (t instanceof HTMLInputElement && t.dataset.adwInclude !== undefined) {
            adw.rows[+t.dataset.adwInclude].include = t.checked;
            renderRows();
        } else if (t instanceof HTMLInputElement && t.dataset.adwNbr !== undefined) {
            adw.neighbors[+t.dataset.adwNbr].picked = t.checked;
            wizard.refresh();
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
        const src = t.closest('[data-adw-source]');
        if (src) {
            adw.src = src.getAttribute('data-adw-source') || 'addr';
            renderSources();
            if (adw.src === 'nbr' && !adw.neighbors.length) loadNeighbors();
            wizard.goTo('source');   // redraws the rail and the Next label for this source
            return;
        }
        const retry = t.closest('[data-adw-retry]');
        if (retry) { verifyRow(adw.rows[+(retry.getAttribute('data-adw-retry') || 0)], adw.gen); return; }
        const move = t.closest('[data-adw-move]');
        if (move) {
            const row = adw.rows[+(move.getAttribute('data-adw-move') || 0)];
            adw.csvDecisions[row.csvRow] = { location: row.moveTo };
            runCsvPreview(adw.gen);
            return;
        }
        if (t.closest('#btnDownloadCsvTemplate')) { downloadTemplate(); return; }
        const act = t.closest('[data-adw-action]');
        if (act) {
            const a = act.getAttribute('data-adw-action');
            if (a === 'inventory') { wizard.close(); switchTab('tab-devices'); }
            else if (a === 'again') {
                Object.assign(adw, { results: null, rows: [] });
                const box = $('adwAddresses');
                if (box instanceof HTMLTextAreaElement) box.value = '';
                adw.neighbors.forEach((x) => { x.picked = false; });
                renderChips();
                wizard.goTo('addresses');
            }
            else if (a === 'download') downloadLeft();
            return;
        }
        // "Opzioni avanzate": the full device form, starting from what is filled here.
        if (t.closest('[data-add-source="one"]')) {
            const prefill = { group: val('adwTenant'), location: val('adwLocation'), ip: parsed().ips[0] || '' };
            wizard.close();
            window.openDeviceForm(prefill);
        }
    });
    // Double click on a source: choose it and go on.
    panel.addEventListener('dblclick', (e) => {
        if (e.target instanceof Element && e.target.closest('[data-adw-source]')) {
            const next = panel.querySelector('[data-wizard-next]');
            if (next instanceof HTMLButtonElement) next.click();
        }
    });
    document.addEventListener('click', (e) => {
        if (e.target instanceof Element && e.target.closest('[data-action="open-add-devices"]')) openAddDevices();
    });
})();
