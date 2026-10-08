// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
//
// Manual config upload for devices SentinelNet cannot reach: the commands to
// run, the session logs dropped in, one review card per file, then one POST
// per device. Opened from the Import tab and from a manual device's row.
// Spec: docs/superpowers/specs/2026-10-08-manual-config-repository-design.md
(function () {
    const $ = (id) => document.getElementById(id);
    // fixed: a manual device being re-uploaded from its row (fields locked).
    // gen: bumped on every (re)open and review entry so a slower async run can tell it is stale.
    const mc = { guide: null, files: [], rows: [], results: null, fixed: null, gen: 0 };

    // Analysis id -> [label key, tab that shows it].
    const ANALYSIS_TABS = {
        analyzer: ['mcAnAnalyzer', 'tab-config'],
        audit: ['mcAnAudit', 'tab-netsec-audit'],
        policy: ['mcAnPolicy', 'tab-policy-test'],
        drift: ['mcAnDrift', 'tab-config-drift'],
        routes: ['mcAnRoutes', 'tab-routes'],
        cve: ['mcAnCve', 'tab-security'],
    };

    const optionsHtml = (items, current, blankLabel) =>
        (blankLabel !== undefined ? `<option value="">${escapeHtml(blankLabel)}</option>` : '')
        + items.map(([value, label]) => `<option value="${escapeHtml(value)}"${value === current ? ' selected' : ''}>${escapeHtml(label)}</option>`).join('');

    async function loadGuide() {
        if (mc.guide) return mc.guide;
        const res = await apiFetch('/api/manual-config/guide');
        if (!res || !res.ok) return null;
        mc.guide = await res.json();
        $('mcVendor').innerHTML = optionsHtml(mc.guide.vendors.map((v) => [v.vendor, v.vendor.toUpperCase()]), '');
        return mc.guide;
    }

    function vendorValue() {
        const sel = $('mcVendor');
        return sel instanceof HTMLSelectElement ? sel.value : '';
    }

    function renderGuide() {
        const v = (mc.guide?.vendors || []).find((x) => x.vendor === vendorValue());
        if (!v) return;
        $('mcPaging').textContent = v.paging || tr('mcNoPaging');
        $('mcCommands').textContent = v.commands.join('\n');
        $('mcNotes').innerHTML = v.notes.map((k) => `<li>${escapeHtml(tr(k))}</li>`).join('');
    }

    function addFiles(list) {
        for (const f of Array.from(list || [])) {
            if (mc.fixed && mc.files.length) break; // a row re-upload takes one file
            if (!mc.files.some((x) => x.name === f.name && x.size === f.size)) mc.files.push(f);
        }
        renderFileList();
        wizard.refresh();
    }

    function renderFileList() {
        $('mcFileList').innerHTML = mc.files.map((f, i) => `<li>
            <span>${escapeHtml(f.webkitRelativePath || f.name)} · ${Math.max(1, Math.round(f.size / 1024))} KB</span>
            <button type="button" class="inv-icon-btn" data-action="mc-remove-file" data-index="${i}"
              aria-label="${escapeHtml(tr('mcRemoveFile', { name: f.name }))}"><i class="fa-solid fa-xmark"></i></button>
          </li>`).join('');
    }

    async function enterReview() {
        const vendor = vendorValue();
        const gen = ++mc.gen;
        const rows = [];
        $('mcReviewBody').innerHTML = `<p class="form-hint">${escapeHtml(tr('mcReading'))}</p>`;
        mc.rows = [];
        for (const file of mc.files) {
            const text = await file.text();
            const res = await apiFetch('/api/manual-config/preview', {
                method: 'POST', body: JSON.stringify({ text, vendor }) });
            const p = res && res.ok ? await res.json() : null;
            if (gen !== mc.gen) return; // superseded by a newer run or a reopen
            rows.push({
                file, text, vendor,
                ip: mc.fixed?.ip || p?.ip_candidates?.[0] || '',
                candidates: p?.ip_candidates || [],
                hostname: mc.fixed?.hostname || p?.hostname || '',
                group: mc.fixed?.group || '',
                site: mc.fixed?.site || 'central',
                category: '',
                version: p?.version || '',
                model: p?.model || '',
                structured: !!p?.structured,
                analyses: p?.analyses || [],
                error: p ? '' : tr('mcPreviewFailed'),
            });
        }
        if (gen !== mc.gen) return;
        mc.rows = rows;
        fillApplyAll();
        renderReview();
        wizard.refresh();
    }

    function groupItems() { return Object.keys(globalGroups || {}).map((g) => [g, g]); }
    function siteItems() { return (mc.guide?.sites || []).map((s) => [s.id, s.name]); }
    function categoryItems() { return Object.entries(mc.guide?.categories || {}).map(([k, c]) => [k, c.label]); }

    function fillApplyAll() {
        $('mcApplyAll').hidden = !!mc.fixed;
        $('mcAllGroup').innerHTML = optionsHtml(groupItems(), '', tr('mcAllNone'));
        $('mcAllSite').innerHTML = optionsHtml(siteItems(), '', tr('mcAllNone'));
        $('mcAllCategory').innerHTML = optionsHtml(categoryItems(), '', tr('mcAllNone'));
    }

    function renderReview() {
        const lock = mc.fixed ? ' disabled' : '';
        $('mcReviewBody').innerHTML = mc.rows.map((r, i) => `
          <fieldset class="mc-card" data-row="${i}">
            <legend>${escapeHtml(r.file.webkitRelativePath || r.file.name)}</legend>
            ${r.error ? `<p class="form-hint" role="alert">${escapeHtml(r.error)}</p>` : ''}
            <div class="mc-grid">
              <label>${escapeHtml(tr('mcLblHostname'))}<input data-field="hostname" value="${escapeHtml(r.hostname)}"${lock}></label>
              <label>IP<input data-field="ip" list="mcIps${i}" value="${escapeHtml(r.ip)}" inputmode="decimal"${lock}></label>
              <datalist id="mcIps${i}">${r.candidates.map((c) => `<option value="${escapeHtml(c)}"></option>`).join('')}</datalist>
              <label>${escapeHtml(tr('mcLblTenant'))}<select data-field="group"${lock}>${optionsHtml(groupItems(), r.group, '')}</select></label>
              <label>${escapeHtml(tr('mcLblSite'))}<select data-field="site"${lock}>${optionsHtml(siteItems(), r.site)}</select></label>
              <label>${escapeHtml(tr('mcLblCategory'))}<select data-field="category">${optionsHtml(categoryItems(), r.category, tr('mcCategoryAuto'))}</select></label>
              <label>${escapeHtml(tr('mcLblVersion'))}<input data-field="version" value="${escapeHtml(r.version)}"></label>
            </div>
            <p class="mc-analyses">${escapeHtml(tr('mcUnlocks'))}
              ${r.analyses.map((a) => `<span class="chip">${escapeHtml(tr(ANALYSIS_TABS[a][0]))}</span>`).join(' ')}</p>
            ${r.structured ? '' : `<p class="form-hint">${escapeHtml(tr('mcPlainFileHint'))}</p>`}
          </fieldset>`).join('');
    }

    function applyAll() {
        const read = (id) => { const el = $(id); return el instanceof HTMLSelectElement ? el.value : ''; };
        const values = { group: read('mcAllGroup'), site: read('mcAllSite'), category: read('mcAllCategory') };
        mc.rows.forEach((r) => { for (const [k, v] of Object.entries(values)) if (v) r[k] = v; });
        renderReview();
        wizard.refresh();
    }

    async function importAll() {
        const gen = mc.gen;
        const next = $('manualConfigWizard').querySelector('[data-wizard-next]');
        if (next instanceof HTMLButtonElement) next.disabled = true; // no double import
        const results = [];
        try {
            for (const r of mc.rows) {
                const res = await apiFetch('/api/manual-config/import', {
                    method: 'POST',
                    body: JSON.stringify({
                        text: r.text, vendor: r.vendor, ip: r.ip.trim(), group: r.group,
                        site: r.site, hostname: r.hostname.trim(), category: r.category,
                        version: r.version.trim(), model: r.model,
                    }),
                });
                let body = null;
                try { body = res ? await res.json() : null; } catch (e) { body = null; }
                const detail = body && body.detail;
                results.push({
                    row: r, ok: !!(res && res.ok),
                    detail: typeof detail === 'string' ? detail : (detail ? JSON.stringify(detail) : ''),
                    analyses: (body && body.analyses) || [],
                });
            }
            try { await refreshInventory(); } catch (e) { /* the results are still worth showing */ }
            if (gen !== mc.gen) return; // sheet closed and reopened meanwhile
            mc.results = results;
            wizard.goTo('result');
        } catch (e) {
            showToast(tr('alertError'), 'error');
        } finally {
            if (next instanceof HTMLButtonElement) next.disabled = false;
        }
    }

    function renderResult() {
        $('mcResultList').innerHTML = mc.results.map((x) => `<li>
            <span class="led ${x.ok ? 'led-success' : 'led-danger'}"></span>
            <strong>${escapeHtml(x.row.hostname || x.row.ip)}</strong> <code>${escapeHtml(x.row.ip)}</code>
            ${x.ok
                ? x.analyses.map((a) => `<button type="button" class="chip" data-switch-tab="${ANALYSIS_TABS[a][1]}">${escapeHtml(tr(ANALYSIS_TABS[a][0]))}</button>`).join(' ')
                : `<span class="form-hint">${escapeHtml(x.detail || tr('alertError'))}</span>`}
          </li>`).join('');
    }

    const wizard = createWizard('manualConfigWizard', {
        steps: [
            { id: 'guide', label: 'mcStepGuide', skip: () => !!mc.results,
              onEnter: renderGuide, validate: () => !!vendorValue() },
            { id: 'files', label: 'mcStepFiles', skip: () => !!mc.results,
              validate: () => mc.files.length > 0 },
            { id: 'review', label: 'mcStepReview', skip: () => !!mc.results, onEnter: enterReview,
              validate: () => mc.rows.length > 0 && mc.rows.every((r) => r.ip.trim() && r.group && !r.error),
              finishLabel: 'mcBtnImport' },
            { id: 'result', label: 'mcStepResult', skip: () => !mc.results,
              onEnter: renderResult, finishLabel: 'btnClose' },
        ],
        onFinish: async (stepId) => {
            if (stepId === 'result') { wizard.close(); return; }
            await importAll();
        },
    });

    async function openManualConfigWizard(ip) {
        mc.gen++;
        Object.assign(mc, { files: [], rows: [], results: null, fixed: null });
        const form = $('mcForm');
        if (form instanceof HTMLFormElement) form.reset();
        renderFileList();
        if (!(await loadGuide())) { showToast(tr('alertError'), 'error'); return; }
        if (ip) {
            const d = (globalDevices || []).find((x) => x.IP === ip && x.manual);
            if (d) {
                mc.fixed = { ip: d.IP, group: d.Group, site: d.Site || 'central', hostname: d.Hostname || '' };
                const sel = $('mcVendor');
                // An unknown vendor leaves the first option selected: the guide step must stay usable.
                if (sel instanceof HTMLSelectElement && d.Vendor) {
                    const v = d.Vendor.toLowerCase();
                    if (Array.from(sel.options).some((o) => o.value === v)) sel.value = v;
                }
            }
        }
        const input = $('mcFileInput');
        if (input instanceof HTMLInputElement) input.multiple = !mc.fixed;
        wizard.open();
    }
    window.openManualConfigWizard = openManualConfigWizard;

    $('btnOpenManualConfig')?.addEventListener('click', () => openManualConfigWizard());
    $('mcVendor')?.addEventListener('change', renderGuide);

    const zone = $('mcDropZone');
    zone?.addEventListener('click', (e) => {
        if (e.target instanceof HTMLInputElement) return;
        $('mcFileInput').click();
    });
    zone?.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('is-over'); });
    zone?.addEventListener('dragleave', () => zone.classList.remove('is-over'));
    zone?.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('is-over');
        addFiles(e.dataTransfer?.files);
    });
    for (const id of ['mcFileInput', 'mcFolderInput']) {
        $(id)?.addEventListener('change', (e) => {
            const t = e.target;
            if (!(t instanceof HTMLInputElement)) return;
            addFiles(t.files);
            t.value = '';
        });
    }

    $('manualConfigWizard')?.addEventListener('click', (e) => {
        const t = e.target instanceof Element ? e.target.closest('[data-action], [data-switch-tab]') : null;
        if (!(t instanceof HTMLElement)) return;
        // core.js switches the tab on the same click; the sheet must not stay over it.
        if (t.dataset.switchTab) { wizard.close(); return; }
        const action = t.dataset.action;
        if (action === 'mc-copy') {
            const text = [$('mcPaging').textContent, $('mcCommands').textContent].filter(Boolean).join('\n');
            navigator.clipboard?.writeText(text)
                .then(() => showToast(tr('mcCopied'), 'success'))
                .catch(() => showToast(tr('alertError'), 'error'));
        } else if (action === 'mc-pick-folder') {
            $('mcFolderInput').click();
        } else if (action === 'mc-remove-file') {
            mc.files.splice(Number(t.dataset.index), 1);
            renderFileList();
            wizard.refresh();
        } else if (action === 'mc-apply-all') {
            applyAll();
        }
    });

    const onFieldEdit = (e) => {
        const t = e.target;
        if (!(t instanceof HTMLInputElement || t instanceof HTMLSelectElement)) return;
        const card = t.closest('[data-row]');
        if (!(card instanceof HTMLElement) || !t.dataset.field) return;
        mc.rows[Number(card.dataset.row)][t.dataset.field] = t.value;
    };
    $('mcReviewBody')?.addEventListener('input', onFieldEdit);
    $('mcReviewBody')?.addEventListener('change', onFieldEdit);
})();
