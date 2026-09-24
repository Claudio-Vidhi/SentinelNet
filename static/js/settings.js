// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
    // ===== Settings tab (Users, Sites, MCP Server, App/Network/CLI Settings) =====

    // A tenant-scoped admin passes isAdminRole() locally but 403s server-side
    // on a route gated by require_unscoped_admin (global settings, sites,
    // fleet, ...): these loaders used to swallow that response and leave the
    // panel blank with no explanation.
    // A Settings open fires ~8 of these loaders in quick succession; without
    // this window a scoped admin got a toast per loader instead of one.
    let lastForbiddenToastAt = 0;
    async function toastOnForbidden(res) {
        if (!res || res.status !== 403) return;
        const now = Date.now();
        if (now - lastForbiddenToastAt < 2000) return;
        lastForbiddenToastAt = now;
        const e = await res.json().catch(() => ({}));
        showToast(e.detail || tr('setSettingsNotLoadedYet'), 'error');
    }

    // --- SEDI MULTI-SITO (admin) ---
    async function loadSites() {
        if (!isAdminRole(currentRole)) return;
        const res = await apiFetch('/api/sites');
        if (!res || !res.ok) { await toastOnForbidden(res); return; }
        const data = await res.json();
        await renderSitesTable(data.sites || []);
    }

    async function renderSitesTable(sites) {
        const body = document.getElementById('sitesTableBody');
        if (!body) return;
        const L = i18n[currentLang];
        // A jump row carries its device-default identity inline: the bastion
        // login and the login used on the devices behind it are two different
        // credentials, and there is no other screen to change the second one.
        const identities = sites.some(s => s.mode === 'jump') ? await getIdentities() : [];
        body.innerHTML = sites.map(s => {
            const isCentral = s.id === 'central';
            const modeBadge = s.mode === 'agent'
                ? '<span class="chip">SITE AGENT</span>'
                : s.mode === 'jump'
                ? '<span class="chip">JUMP (BASTION)</span>'
                : '<span class="status ok"><span class="led led-success"></span>CENTRAL POLL</span>';
            const last = s.last_seen ? new Date(s.last_seen * 1000).toLocaleString() : '—';
            const subnets = (s.subnets || []).map(escapeHtml).join(', ') || '—';
            // Solo una sede con agente puo' essere offline: il central poll non
            // ha un processo remoto che riporta heartbeat. Soglia legata
            // all'intervallo configurato dell'agente, non fissa: con un
            // intervallo lungo un agente sano risulterebbe sempre offline.
            let statusCell = '<span style="color:var(--text-muted);">—</span>';
            if (s.mode === 'agent') {
                const staleAfter = Math.max(120, (s.interval || 60) * 2);
                const online = s.last_seen && (Date.now() / 1000 - s.last_seen) < staleAfter;
                statusCell = online
                    ? `<span class="status ok"><span class="led led-success"></span>${L.lblAgentOnline}</span>`
                    : `<span class="status bad"><span class="led led-danger"></span>${L.lblAgentOffline}</span>`;
            }
            if (s.mode === 'jump' && !s.bastion_verified_ts) {
                statusCell = `<span class="chip is-warn">${escapeHtml(tr('chipNotVerified'))}</span>`;
            }
            let actions = '';
            if (s.mode === 'agent') {
                actions += `<button data-action="open-agent-control" data-site-id="${escapeHtml(s.id)}" style="color:var(--warning); background:none; border:none; cursor:pointer; margin-right:10px;" title="Pannello di controllo ed aggiornamento agente remoti"><i class="fa-solid fa-gears"></i> Gestione Agente</button>`;
                // Chi possiede l'inventario di questa sede. Spento: l'agente,
                // e le credenziali non lasciano la sede. Acceso: il centrale,
                // che le spinge all'agente -- comodo, ma e' una scelta di
                // sicurezza, quindi va vista nella riga della sede.
                actions += `<label style="margin-right:10px; font-size:11px; color:var(--text-muted); cursor:pointer;">`
                    + `<input type="checkbox" data-action="set-site-central-managed" data-site-id="${escapeHtml(s.id)}"${s.central_manages_devices ? ' checked' : ''} style="vertical-align:middle; margin-right:4px;">`
                    + `${escapeHtml(L.lblCentralManagesDevices)}</label>`;
                actions += `<button data-action="regen-site-token" data-site-id="${escapeHtml(s.id)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-key"></i> ${L.btnRegenSiteToken}</button>`;
            }
            if (s.mode === 'jump') {
                // Two identities, two selects. One unlabelled dropdown next to
                // "Test bastion" read as the bastion credential while it set
                // the DEVICE one, so an operator could fix the login the test
                // does not use and see the same refusal again — with no way to
                // reach the bastion identity at all after site creation.
                actions += `<span style="font-size:10px; color:var(--text-muted); margin-right:3px;">${escapeHtml(L.lblIdentityBastionShort)}</span>`;
                // A select whose stored value matches no option silently
                // displays the FIRST one, which reads as "configured" while
                // the site still points at an identity that no longer exists.
                const jumpKnown = identities.some(i => i.id === s.jump_identity);
                const jumpMissing = jumpKnown ? '' : `<option value="" selected>${escapeHtml(L.optMissingIdentity)}</option>`;
                actions += `<select data-action="set-site-jump-identity" data-site-id="${escapeHtml(s.id)}" title="${escapeHtml(L.lblJumpIdentity)}" style="margin-right:10px; padding:2px 6px; font-size:12px;">${jumpMissing}${identityOptions(identities, s.jump_identity || '')}</select>`;
                actions += `<span style="font-size:10px; color:var(--text-muted); margin-right:3px;">${escapeHtml(L.lblIdentityDeviceShort)}</span>`;
                actions += `<select data-action="set-site-device-identity" data-site-id="${escapeHtml(s.id)}" title="${escapeHtml(L.lblDeviceIdentity)}" style="margin-right:10px; padding:2px 6px; font-size:12px;"><option value="">${escapeHtml(L.optNoDeviceIdentity)}</option>${identityOptions(identities, s.device_identity || '')}</select>`;
                actions += `<button data-action="test-bastion" data-site-id="${escapeHtml(s.id)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-plug-circle-check"></i> ${L.btnTestBastion}</button>`;
            }
            const editBtn = `<button data-action="edit-site" data-site-id="${escapeHtml(s.id)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-pen"></i> ${L.btnEditSite}</button>`;
            if (!isCentral) {
                actions += `<button data-action="delete-site" data-site-id="${escapeHtml(s.id)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${L.btnDeleteSite}</button>`;
                actions = editBtn + actions;
            } else {
                // La sede predefinita non si elimina e non cambia modalita',
                // ma nome e subnet sono suoi come di ogni altra.
                actions = editBtn + `<span class="chip">${L.lblSiteDefault}</span>`;
            }
            return `<tr>
                <td><strong>${escapeHtml(s.id)}</strong></td>
                <td>${escapeHtml(s.name)}</td>
                <td>${modeBadge}</td>
                <td>${statusCell}</td>
                <td style="font-size:12px;">${subnets}</td>
                <td style="font-size:12px; color:var(--text-muted);">${last}</td>
                <td style="white-space:nowrap;">${actions}</td>
            </tr>`;
        }).join('');
    }

    let identitiesCache = null;

    async function getIdentities() {
        if (identitiesCache) return identitiesCache;
        const res = await apiFetch('/api/identities');
        identitiesCache = (res && res.ok) ? (await res.json()).identities || [] : [];
        return identitiesCache;
    }

    function identityOptions(identities, selected) {
        return identities.map(i => `<option value="${escapeHtml(i.id)}"${
            i.id === selected ? ' selected' : ''}>${escapeHtml(i.name)} (${
            escapeHtml(i.username)})</option>`).join('');
    }

    // --- Site wizard (docs/superpowers/specs/2026-09-23-site-wizard-design.md) ---
    // One side panel for create, edit and agent enrollment:
    // Mode → Details → Connection (jump only) → Summary → Enrollment (new token).
    const CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/;
    function isCidr(s) {
        const m = CIDR_RE.exec(s);
        return !!m && m.slice(1, 5).every((o) => +o <= 255) && +m[5] <= 32;
    }
    const sw = {
        editing: null,     // site being edited; null when creating
        test: null,        // last draft-test answer for the current bastion fields
        token: null,       // agent token to enroll, shown once
        siteId: null,      // site the enrollment step is about
        heartbeat: null,   // interval polling last_seen during enrollment
        keepDraft: false,  // closed only to go create an identity: keep the fields
    };
    const swEl = (id) => document.getElementById(id);
    const swMode = () => document.querySelector('input[name="swMode"]:checked')?.value || '';
    const swSubnets = () => swEl('swSubnets').value.split(',').map((x) => x.trim()).filter(Boolean);
    function swJumpFields() {
        return {
            jump_host: swEl('swJumpHost').value.trim(),
            jump_port: parseInt(swEl('swJumpPort').value, 10) || 22,
            jump_identity: swEl('swJumpIdentity').value,
        };
    }
    // Editing a jump site whose bastion is untouched needs no new test.
    function swJumpChanged() {
        const e = sw.editing;
        if (!e || e.mode !== 'jump') return true;
        const j = swJumpFields();
        return j.jump_host !== (e.jump_host || '') || j.jump_port !== (e.jump_port || 22)
            || j.jump_identity !== (e.jump_identity || '');
    }
    function swTestPassed() {
        return !!sw.test && sw.test.status === 'success' && swEl('swFpConfirm').checked;
    }

    const siteWizard = createWizard('siteWizard', {
        steps: [
            // Once a token is issued the site exists: every step but
            // Enrollment skips, so Back cannot reach Save a second time.
            { id: 'mode', label: 'swStepMode', skip: () => !!sw.token, validate: () => !!swMode() },
            { id: 'details', label: 'swStepDetails', onEnter: onSwDetailsEnter, skip: () => !!sw.token,
              validate: () => {
                  if (!swEl('swName').value.trim() || !swSubnets().every(isCidr)) return false;
                  if (swMode() !== 'jump') return true;
                  const j = swJumpFields();
                  return !!j.jump_host && !!j.jump_identity && j.jump_port >= 1 && j.jump_port <= 65535;
              } },
            { id: 'connect', label: 'swStepConnect',
              skip: () => !!sw.token || swMode() !== 'jump' || !swJumpChanged(),
              validate: () => swTestPassed() || swEl('swSkipVerify').checked },
            { id: 'summary', label: 'swStepSummary', onEnter: renderSwSummary, skip: () => !!sw.token,
              finishLabel: 'btnSaveSite' },
            { id: 'enroll', label: 'swStepEnroll', skip: () => !sw.token,
              onEnter: startSwHeartbeat, finishLabel: 'btnClose' },
        ],
        onFinish: async (stepId) => {
            if (stepId === 'enroll') { siteWizard.close(); return; }
            await saveSiteWizard();
        },
    });

    function resetSiteWizard() {
        stopSwHeartbeat();
        Object.assign(sw, { editing: null, test: null, token: null, siteId: null, keepDraft: false });
        swEl('siteWizardForm').reset();
        swInvalidateTest();
        swEl('swSubnetChips').replaceChildren();
        swEl('swSaveError').textContent = '';
        document.querySelectorAll('input[name="swMode"]').forEach((r) => { r.disabled = false; });
        swEl('siteWizardTitle').textContent = tr('titleNewSite');
    }

    function onSiteWizardClose() {
        stopSwHeartbeat();
        if (!sw.keepDraft) resetSiteWizard();
    }

    function openNewSiteWizard() {
        const resume = sw.keepDraft;
        if (!resume) resetSiteWizard();
        sw.keepDraft = false;
        // A resumed edit draft stays an edit: same rail, same update on save.
        siteWizard.open({ at: resume ? 'details' : 'mode', editable: !!sw.editing, onClose: onSiteWizardClose });
    }

    async function openEditSiteWizard(siteId) {
        const res = await apiFetch('/api/sites');
        if (!res || !res.ok) return;
        const site = ((await res.json()).sites || []).find((s) => s.id === siteId);
        if (!site) return;
        resetSiteWizard();
        sw.editing = site;
        swEl('siteWizardTitle').textContent = tr('swTitleEdit');
        document.querySelectorAll('input[name="swMode"]').forEach((r) => {
            r.checked = r.value === (site.mode || 'central');
            // The default site is the central's own: changing its mode would
            // take away the central's direct path to its own devices.
            r.disabled = site.id === 'central';
        });
        swEl('swName').value = site.name || '';
        swEl('swSubnets').value = (site.subnets || []).join(', ');
        swEl('swJumpHost').value = site.jump_host || '';
        swEl('swJumpPort').value = site.jump_port || 22;
        await populateSwIdentitySelects(site.jump_identity || '', site.device_identity || '');
        siteWizard.open({ at: 'details', editable: true, onClose: onSiteWizardClose });
    }

    async function populateSwIdentitySelects(jumpValue, deviceValue) {
        const identities = await getIdentities();
        swEl('swJumpIdentity').innerHTML = identityOptions(identities, jumpValue);
        // The device default is optional: without it the devices behind the
        // bastion fall back to the global credentials (core/device_credentials.py).
        swEl('swDeviceIdentity').innerHTML = `<option value="">${escapeHtml(tr('optNoDeviceIdentity'))}</option>`
            + identityOptions(identities, deviceValue);
    }

    // Called after an identity is created, edited or deleted (provisioning.js).
    window.refreshSiteIdentitySelects = async function () {
        identitiesCache = null;
        if (!isModalOpen('siteWizard') && !sw.keepDraft) return;
        await populateSwIdentitySelects(swEl('swJumpIdentity').value, swEl('swDeviceIdentity').value);
    };

    // "+ New identity": the draft survives the trip to the identities panel,
    // and "Nuova sede" resumes it at the Details step.
    function goCreateIdentity() {
        sw.keepDraft = true;
        siteWizard.close();
        switchTab('tab-provisioning');
        document.getElementById('identitiesPanel')?.scrollIntoView();
    }

    async function onSwDetailsEnter() {
        const jump = swMode() === 'jump';
        swEl('swJumpFields').hidden = !jump;
        if (jump) await populateSwIdentitySelects(swEl('swJumpIdentity').value, swEl('swDeviceIdentity').value);
        renderSwSubnetChips();
        siteWizard.refresh();
    }

    function renderSwSubnetChips() {
        swEl('swSubnetChips').replaceChildren(...swSubnets().map((s) => {
            const chip = document.createElement('span');
            const ok = isCidr(s);
            chip.className = 'chip' + (ok ? '' : ' is-bad');
            chip.textContent = s;
            if (!ok) chip.title = tr('swSubnetInvalid');
            return chip;
        }));
    }

    // A test vouches for the exact host/port/identity it ran against.
    function swInvalidateTest() {
        sw.test = null;
        const out = swEl('swTestResult');
        out.replaceChildren();
        out.className = 'test-result';
        swEl('swFpConfirmWrap').hidden = true;
        swEl('swFpConfirm').checked = false;
    }

    async function swRunTest() {
        swInvalidateTest();
        const out = swEl('swTestResult');
        out.textContent = tr('swTesting');
        siteWizard.refresh();
        const res = await apiFetch('/api/sites/test-bastion/draft', {
            method: 'POST', body: JSON.stringify(swJumpFields()),
        });
        if (!res) { out.textContent = ''; return; }
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            out.className = 'test-result is-bad';
            out.textContent = data.detail || tr('uiError');
            return;
        }
        sw.test = data;
        renderSwTestResult(data);
        siteWizard.refresh();
    }

    function renderSwTestResult(data) {
        const out = swEl('swTestResult');
        const ok = data.status === 'success';
        out.className = 'test-result ' + (ok ? 'is-ok' : 'is-bad');
        const head = document.createElement('strong');
        head.textContent = ok ? tr('swTestOk')
            : data.status === 'auth_failed' ? tr('msgBastionAuthFailed')
            : data.status === 'host_key_mismatch' ? tr('swTestHostKey')
            : tr('msgBastionUnreachable');
        const pre = document.createElement('pre');
        pre.textContent = ok ? `${tr('swFpLabel')} (${data.key_type})\n${data.fingerprint}` : (data.message || '');
        out.replaceChildren(head, pre);
        if (!ok) return;
        swEl('swFpConfirmWrap').hidden = false;
        // Already pinned and matching: nothing new to trust.
        swEl('swFpConfirm').checked = !!data.known;
        if (data.known) {
            const note = document.createElement('p');
            note.textContent = tr('swFpKnown');
            out.appendChild(note);
        }
    }

    function renderSwSummary() {
        const mode = swMode();
        const modeLabel = { central: 'swModeCentral', agent: 'swModeAgent', jump: 'optSiteJump' }[mode];
        const rows = [
            ['lblSiteName', swEl('swName').value.trim()],
            ['lblSiteMode', tr(modeLabel)],
            ['lblSiteSubnets', swSubnets().join(', ') || '—'],
        ];
        if (mode === 'jump') {
            const j = swJumpFields();
            const verified = swJumpChanged() ? swTestPassed() : !!sw.editing.bastion_verified_ts;
            rows.push(['lblJumpHost', `${j.jump_host}:${j.jump_port}`]);
            rows.push(['swSumBastion', tr(verified ? 'swVerified' : 'swNotVerified')]);
        }
        swEl('swSummary').replaceChildren(...rows.flatMap(([key, value]) => {
            const dt = document.createElement('dt');
            dt.textContent = tr(key);
            const dd = document.createElement('dd');
            dd.textContent = value;
            return [dt, dd];
        }));
        // The consequences of a mode change are said BEFORE saving: two of
        // the three touch the token, i.e. the agent's ability to log in.
        const was = sw.editing ? sw.editing.mode : null;
        const warn = swEl('swModeWarning');
        warn.hidden = !was || was === mode;
        warn.textContent = warn.hidden ? '' : modeChangeWarning(swMode());
        swEl('swSaveError').textContent = '';
    }

    async function saveSiteWizard() {
        const mode = swMode();
        const editing = sw.editing;
        const body = { name: swEl('swName').value.trim(), subnets: swSubnets() };
        if (mode === 'jump') {
            Object.assign(body, swJumpFields(), { device_identity: swEl('swDeviceIdentity').value });
            if (swJumpChanged() && swTestPassed()) body.confirmed_fingerprint = sw.test.fingerprint;
        }
        if (editing) {
            body.id = editing.id;
            if (mode !== editing.mode) body.mode = mode;
        } else {
            body.mode = mode;
        }
        const res = await apiFetch(editing ? '/api/sites/update' : '/api/sites', {
            method: 'POST', body: JSON.stringify(body),
        });
        if (!res) return;
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            swEl('swSaveError').textContent = data.detail || tr('uiError');
            // 409: the confirmed key is not the one the server saw any more.
            if (res.status === 409) {
                swInvalidateTest();
                siteWizard.goTo('connect');
                swEl('swTestResult').textContent = data.detail || '';
            }
            return;
        }
        loadSites();
        const id = editing ? editing.id : data.site.id;
        // Switching to 'agent' issues the token in the save itself (see
        // routers/sites.py): shown once, like on creation.
        if (data.token) { showSiteEnrollment(id, data.token); return; }
        siteWizard.close();
        showToast(tr('swSaved'), 'info');
    }

    function showSiteEnrollment(siteId, token) {
        sw.token = token;
        sw.siteId = siteId;
        const { cfg, cmds } = enrollmentText(siteId, token);
        // textContent, not innerHTML: the token is a value, not markup.
        document.getElementById('siteEnrollConfig').textContent = cfg;
        document.getElementById('siteEnrollCommands').textContent = cmds;
        if (isModalOpen('siteWizard')) siteWizard.goTo('enroll');
        else siteWizard.open({ at: 'enroll', onClose: onSiteWizardClose });
    }

    function paintSwHeartbeat(online) {
        swEl('swHeartbeatLed').className = 'led ' + (online ? 'led-success' : 'led-warning');
        swEl('swHeartbeatText').textContent = tr(online ? 'swEnrollOnline' : 'swEnrollWaiting');
    }

    // Green on the first heartbeat AFTER the token was issued: an agent still
    // running with the old token cannot produce one.
    function startSwHeartbeat() {
        stopSwHeartbeat();
        paintSwHeartbeat(false);
        const since = Date.now() / 1000;
        sw.heartbeat = setInterval(async () => {
            const res = await apiFetch('/api/sites');
            if (!res || !res.ok) return;
            const site = ((await res.json()).sites || []).find((s) => s.id === sw.siteId);
            if (site && site.last_seen && site.last_seen >= since) {
                paintSwHeartbeat(true);
                stopSwHeartbeat();
                loadSites();
            }
        }, 5000);
    }

    function stopSwHeartbeat() {
        if (sw.heartbeat) clearInterval(sw.heartbeat);
        sw.heartbeat = null;
    }

    async function testBastion(id) {
        const res = await apiFetch('/api/sites/test-bastion', {
            method: 'POST', body: JSON.stringify({ id }),
        });
        if (!res) return;
        const data = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(data.detail || tr('uiError'), 'error'); return; }
        if (data.status === 'success') showToast(`${tr('msgBastionOk')} ${data.fingerprint || ''}`, 'info');
        else if (data.status === 'auth_failed') showToast(`${tr('msgBastionAuthFailed')} ${data.message || ''}`, 'error');
        else if (data.status === 'host_key_mismatch') showToast(`${tr('swTestHostKey')} ${data.message || ''}`, 'error');
        else showToast(`${tr('msgBastionUnreachable')} ${data.message || ''}`, 'error');
        loadSites();
    }

    async function regenSiteToken(id) {
        if (!confirm(tr('setRegenerateTheTokenFor', {id: id}))) return;
        const res = await apiFetch('/api/sites/regenerate-token', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (res && res.ok) {
            const data = await res.json();
            showSiteEnrollment(id, data.token);
            loadSites();
        } else if (res) { const e = await res.json(); alert((tr('uiError')) + (e.detail || '')); }
    }

    async function setSiteJumpIdentity(id, identityId) {
        // A jump site cannot exist without a bastion identity, so there is no
        // empty option to send.
        if (!identityId) { loadSites(); return; }
        const res = await apiFetch('/api/sites/update', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, jump_identity: identityId })
        });
        if (res && !res.ok) {
            const e = await res.json();
            alert((tr('uiError')) + (e.detail || ''));
        }
        loadSites();
    }

    async function setSiteDeviceIdentity(id, identityId) {
        const res = await apiFetch('/api/sites/update', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, device_identity: identityId })
        });
        if (res && !res.ok) {
            const e = await res.json();
            alert((tr('uiError')) + (e.detail || ''));
            loadSites();
        }
    }

    async function setSiteCentralManaged(id, enabled) {
        const res = await apiFetch('/api/sites/update', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, central_manages_devices: enabled })
        });
        if (res && !res.ok) {
            const e = await res.json();
            alert((tr('uiError')) + (e.detail || ''));
        }
        loadSites();
    }

    // --- Arruolamento di una sede agent (G5) ---
    // Il token si mostra una volta sola, e da solo non dice cosa farne: chi
    // installa l'agente doveva ricavare agent.json e i comandi dalla
    // documentazione e incollarci il token a mano. Escono insieme.
    function enrollmentText(siteId, token) {
        const cfg = JSON.stringify({
            central_url: window.location.origin,
            site_id: siteId,
            token: token,
            interval: 60,
            verify_tls: window.location.protocol === 'https:',
            data_dir: '/opt/SentinelNet/agent-data',
        }, null, 2);
        const cmds = [
            'sudo install -d -m 700 /opt/SentinelNet',
            "sudo tee /opt/SentinelNet/agent.json > /dev/null << 'EOF'",
            cfg,
            'EOF',
            'sudo chmod 600 /opt/SentinelNet/agent.json',
            'sudo systemctl restart sentinelnet-agent',
        ].join('\n');
        return { cfg, cmds };
    }

    function copySiteEnrollment() {
        const cfg = document.getElementById('siteEnrollConfig').textContent;
        const cmds = document.getElementById('siteEnrollCommands').textContent;
        navigator.clipboard.writeText(cfg + '\n\n' + cmds);
    }

    function modeChangeWarning(mode) {
        return tr(mode === 'central' ? 'warnSiteModeToCentral'
            : mode === 'agent' ? 'warnSiteModeToAgent' : 'warnSiteModeToJump');
    }

    async function deleteSite(id) {
        if (!confirm(tr('setDeleteSite', {id: id}))) return;
        const res = await apiFetch('/api/sites/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id })
        });
        if (res && res.ok) loadSites();
        else if (res) { const e = await res.json(); alert((tr('uiError')) + (e.detail || '')); }
    }

    // --- TAB MCP SERVER (guida + selezione tool esposti ai client LLM) ---

    function mcpConfigSnippetText() {
        return JSON.stringify({
            mcpServers: {
                sentinelnet: {
                    command: "python",
                    // Il modulo sta in ai/, non nella radice: lo snippet è
                    // fatto per essere incollato, quindi il percorso deve
                    // essere quello vero.
                    args: ["/percorso/SentinelNet/ai/mcp_server.py"],
                    env: {
                        SENTINELNET_URL: window.location.origin,
                        SENTINELNET_USERNAME: "<utente-dedicato>",
                        SENTINELNET_PASSWORD: "<password>"
                    }
                }
            }
        }, null, 2);
    }

    async function loadMcpTab() {
        const pre = document.getElementById('mcpConfigSnippet');
        if (pre) pre.textContent = mcpConfigSnippetText();
        const list = document.getElementById('mcpToolList');
        if (!list) return;
        const res = await apiFetch('/api/mcp/settings');
        if (!res || !res.ok) { list.innerHTML = '<span style="color:var(--text-muted); font-size:12px;">Impossibile caricare le impostazioni MCP.</span>'; return; }
        const data = await res.json();
        const disabled = new Set(data.disabled_tools || []);
        const L = i18n[currentLang];
        list.innerHTML = (data.tools || []).map(t => {
            const isEnabled = !disabled.has(t.name);
            const stKey = isEnabled ? 'mcpStEnabled' : 'mcpStDisabled';
            return `
            <label style="display:flex; align-items:flex-start; gap:8px; font-size:13px; padding:8px 10px; border:1px solid var(--border); border-radius:0; background:var(--surface); cursor:pointer;">
              <input type="checkbox" class="mcp-tool-toggle" value="${escapeHtml(t.name)}" ${isEnabled ? 'checked' : ''} style="margin-top:2px;">
              <span style="flex:1;">
                <span style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
                  <code style="font-size:12px;">${escapeHtml(t.name)}</code>
                  <span class="status ${isEnabled ? 'ok' : 'bad'}"><span class="led ${isEnabled ? 'led-success' : 'led-danger'}"></span><span data-i18n="${stKey}">${escapeHtml(L[stKey])}</span></span>
                </span>
                <span style="color:var(--text-muted); font-size:11px;">${escapeHtml(t.description || '')}</span>
              </span>
            </label>`;
        }).join('');
    }

    async function saveMcpSettings() {
        const statusEl = document.getElementById('mcpSettingsStatus');
        const disabled = [...document.querySelectorAll('.mcp-tool-toggle')]
            .filter(cb => !cb.checked).map(cb => cb.value);
        const res = await apiFetch('/api/mcp/settings', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ disabled_tools: disabled })
        });
        if (res && res.ok) {
            if (statusEl) statusEl.textContent = 'Impostazioni salvate.';
        } else {
            const e = res ? await res.json().catch(() => ({})) : {};
            if (statusEl) statusEl.textContent = 'Errore: ' + (e.detail || 'salvataggio fallito.');
        }
    }

    function copyMcpConfig() {
        navigator.clipboard.writeText(mcpConfigSnippetText());
    }

    // --- GESTIONE UTENTI (solo admin) ---

    // Tab assegnabili ai ruoli non-admin. DERIVATE dalla barra di
    // navigazione, non elencate a mano: la lista scritta a mano aveva perso
    // sei tab (wlc, interfacce, HA, policy-test, rotte, config-drift), che
    // nessun admin poteva quindi concedere a nessuno, e ne portava una NON
    // assegnabile (tab-groups e' requires-admin, quindi la spunta non
    // rivelava niente). Ogni tab nuova la faceva sbagliare di nuovo.
    //
    // Un pulsante con 'data-tabs' governa piu' pannelli (Mappa + Mappa
    // interattiva, Provisioning + Provisioner): ognuno e' una spunta
    // distinta, com'era prima. Le etichette dei pannelli secondari non sono
    // nel markup del pulsante, e sono le sole due cose ancora nominate qui.
    const SECONDARY_TAB_LABELS = {
        'tab-map-interactive': 'tabInteractive',
        'tab-provisioner': 'tabProvisioner',
    };

    // The five requires-admin tabs that ARE a concession on an admin-level
    // row (they gate the admin panels themselves). tab-incidents and
    // tab-fortigate are also requires-admin but are ordinary operational
    // tabs, not part of the admin-management group, so they stay excluded.
    const ADMIN_GROUP_TABS = ['tab-users', 'tab-groups', 'tab-sites', 'tab-mcp', 'tab-settings'];

    // Of ADMIN_GROUP_TABS, only these route to endpoints gated by
    // require_unscoped_admin (spec D5): tab-users' own routes (create,
    // role, disable, ...) only need require_admin + the scope/grant asserts,
    // not an unscoped admin — only /api/users/invite does, and that's
    // handled by hiding the invite button (applyRoleUI), not by this hint.
    const UNSCOPED_ADMIN_HINT_TABS = ['tab-settings', 'tab-sites', 'tab-groups', 'tab-mcp'];

    // rowRole: role of the account being edited. Admin-level rows also offer
    // the ADMIN_GROUP_TABS; other rows never do (granting one would have no
    // effect, the button stays hidden by the requires-admin CSS gate).
    function assignableTabs(rowRole) {
        const rowIsAdmin = rowRole === 'admin' || rowRole === 'super_admin';
        const out = [];
        const seen = new Set();
        document.querySelectorAll('.nav-item[data-tab]').forEach(btn => {
            const primary = btn.getAttribute('data-tab');
            const isAdminGroupBtn = btn.classList.contains('requires-admin');
            if (isAdminGroupBtn && !(rowIsAdmin && ADMIN_GROUP_TABS.includes(primary))) return;
            const ids = (btn.getAttribute('data-tabs') || primary || '').split(/\s+/);
            const navLabel = btn.querySelector('[data-i18n]');
            const navKey = navLabel ? navLabel.getAttribute('data-i18n') : null;
            ids.forEach(id => {
                // tab-home e' sempre visibile: non e' una concessione.
                if (!id || id === 'tab-home' || seen.has(id)) return;
                seen.add(id);
                out.push({ id, key: SECONDARY_TAB_LABELS[id] || navKey,
                          needsUnscopedAdmin: UNSCOPED_ADMIN_HINT_TABS.includes(id) });
            });
        });
        // A tab-restricted actor can grant only what it holds itself
        // (mirrors assert_tabs_within_grant server-side).
        if (currentAllowedTabs.length > 0) {
            return out.filter(t => currentAllowedTabs.includes(t.id));
        }
        return out;
    }

    async function loadUsers() {
        if (!isAdminRole(currentRole)) return;
        const res = await apiFetch('/api/users');
        if (!res || !res.ok) return;
        renderUsersTable(await res.json());
    }

    function renderUsersTable(users) {
        const body = document.getElementById('usersTableBody');
        if (!body) return;
        const delText = tr('uiDelete');
        // A scoped actor may grant only its own tenants (assert_groups_within_scope
        // server-side); an unscoped actor still offers every tenant.
        const allGroups = currentUserGroups.length > 0 ? currentUserGroups : Object.keys(globalGroups);
        body.innerHTML = users.map(u => {
            const isSelf = u.username === currentUsername;
            const manageable = !isSelf && canManageRole(currentRole, u.role);
            const roleOptions = ['viewer', 'operator', 'admin', 'super_admin']
                .filter(r => r === u.role || canAssignRole(currentRole, r))
                .map(r => `<option value="${r}" ${r === u.role ? 'selected' : ''}>${roleLabel(r)}</option>`).join('');
            const scope = Array.isArray(u.groups) ? u.groups : [];

            // Editor sedi: manageable (incluse le righe admin, in pratica solo
            // per il super_admin) mostra i checkbox; altrimenti un riepilogo.
            let scopeCell;
            if (!manageable) {
                scopeCell = isAdminRole(u.role)
                    ? `<span style="color:var(--text-muted); font-size:12px;">${tr('setAllTenantsAdmin')}</span>`
                    : `<span style="color:var(--text-muted); font-size:12px;">${scope.length ? scope.map(escapeHtml).join(', ') : tr('uiAllTenants')}</span>`;
            } else {
                const summary = scope.length === 0
                    ? `<span style="color:var(--success);">${tr('uiAllTenants')}</span>`
                    : `<span style="color:var(--primary);">${scope.map(escapeHtml).join(', ')}</span>`;
                const checks = allGroups.map(g =>
                    `<label style="display:flex; align-items:center; gap:6px; padding:3px 4px; font-size:12px; cursor:pointer;">
                       <input type="checkbox" class="scope-box" value="${escapeHtml(g)}" ${scope.includes(g) ? 'checked' : ''}
                              data-action="save-user-groups" data-username="${escapeHtml(u.username)}"
                              style="accent-color:var(--primary); cursor:pointer;">
                       ${escapeHtml(g)}
                     </label>`).join('');
                scopeCell = `<details data-u="${escapeHtml(u.username)}" style="position:relative;">
                    <summary style="cursor:pointer; list-style:none; font-size:12px; padding:2px 0;">
                      <i class="fa-solid fa-location-dot" style="color:var(--text-muted); margin-right:4px;"></i>${summary}
                    </summary>
                    <div style="margin-top:6px; padding:6px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); max-height:160px; overflow:auto;">
                      <div style="font-size:10px; color:var(--text-muted); margin-bottom:4px;">${tr('setNoneCheckedAllTenants')}</div>
                      ${checks || `<span style="color:var(--text-muted); font-size:12px;">${tr('setNoTenants')}</span>`}
                    </div>
                  </details>`;
            }

            // Editor tab: manageable (incluse le righe admin) mostra i checkbox,
            // con salvataggio esplicito (staged, no auto-save); altrimenti un riepilogo.
            let tabsCell;
            if (!manageable) {
                tabsCell = `<span style="color:var(--text-muted); font-size:12px;">${isAdminRole(u.role) ? tr('setAllTabsAdmin') : tr('setAllTabs')}</span>`;
            } else {
                const allowed = normalizeAllowedTabs(u.allowed_tabs);
                const tabsSummary = allowed.length === 0
                    ? `<span style="color:var(--success);">${tr('setAllTabs')}</span>`
                    : `<span style="color:var(--primary);">${allowed.length} ${tr('setTabS')}</span>`;
                const tabChecks = assignableTabs(u.role).map(t =>
                    `<label style="display:flex; align-items:center; gap:6px; padding:3px 4px; font-size:12px; cursor:pointer;">
                       <input type="checkbox" class="tabs-box" value="${t.id}" ${allowed.includes(t.id) ? 'checked' : ''}
                              data-action="mark-tabs-dirty"
                              style="accent-color:var(--primary); cursor:pointer;">
                       ${(t.key && i18n[currentLang][t.key]) || t.id}
                       ${t.needsUnscopedAdmin ? `<span style="color:var(--text-muted); font-size:10px;">(${tr('setTabNeedsUnscopedAdmin')})</span>` : ''}
                     </label>`).join('');
                tabsCell = `<details data-u="${escapeHtml(u.username)}" data-orig='${JSON.stringify(allowed)}' style="position:relative;">
                    <summary style="cursor:pointer; list-style:none; font-size:12px; padding:2px 0;">
                      <i class="fa-solid fa-table-columns" style="color:var(--text-muted); margin-right:4px;"></i>${tabsSummary}
                    </summary>
                    <div style="margin-top:6px; padding:6px; border:1px solid var(--border); border-radius:0; background:var(--surface-3); max-height:200px; overflow:auto;">
                      <div style="font-size:10px; color:var(--text-muted); margin-bottom:4px;">${tr('setNoneCheckedAllTabs')}</div>
                      ${tabChecks}
                      <div style="margin-top:8px; display:flex; align-items:center; gap:8px;">
                        <button type="button" class="btn btn-primary btn-small tabs-save-btn" data-action="save-user-tabs" style="display:none; width:auto; margin:0; padding:4px 10px; font-size:12px;">
                          <i class="fa-solid fa-floppy-disk"></i> ${tr('uiSave')}
                        </button>
                        <span class="tabs-dirty-label" style="display:none; color:var(--warning); font-size:11px;">${tr('setUnsavedChanges')}</span>
                      </div>
                    </div>
                  </details>`;
            }

            const disabled = !!u.disabled;
            const disabledBadge = disabled
                ? ` <span class="role-pill" style="background:color-mix(in srgb, var(--danger) 15%, transparent); color:var(--danger); border:1px solid color-mix(in srgb, var(--danger) 35%, transparent);">${tr('setDisabled')}</span>`
                : '';
            const toggleText = disabled
                ? (tr('setEnable'))
                : (tr('setDisable'));
            const toggleIcon = disabled ? 'fa-circle-check' : 'fa-ban';
            const toggleColor = disabled ? 'var(--success)' : 'var(--warning)';
            const toggleBtn = !manageable ? '' :
                `<button data-action="toggle-user-disabled" data-username="${escapeHtml(u.username)}" data-disabled="${disabled ? '1' : '0'}"
                    style="color:${toggleColor}; background:none; border:none; cursor:pointer; margin-right:10px;">
                    <i class="fa-solid ${toggleIcon}"></i> ${toggleText}</button>`;

            // Invited accounts cannot sign in until approved; rejecting one is deleting it.
            const pending = !!u.pending_approval;
            const pendingBadge = pending
                ? ` <span class="role-pill" style="background:color-mix(in srgb, var(--warning) 15%, transparent); color:var(--warning); border:1px solid color-mix(in srgb, var(--warning) 35%, transparent);">${tr('setPendingApproval')}</span>`
                : '';
            const approveBtn = (pending && manageable)
                ? `<button data-action="approve-user" data-username="${escapeHtml(u.username)}" style="color:var(--success); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-user-check"></i> ${tr('setApprove')}</button>`
                : '';
            const resetBtn = (u.email && !pending && !disabled && manageable)
                ? `<button data-action="send-user-reset" data-username="${escapeHtml(u.username)}" style="color:var(--primary); background:none; border:none; cursor:pointer; margin-right:10px;"><i class="fa-solid fa-key"></i> ${tr('setSendReset')}</button>`
                : '';

            return `<tr style="${disabled ? 'opacity:0.55;' : ''}">
                <td><strong>${escapeHtml(u.username)}</strong>${isSelf ? ` <span style="color:var(--text-muted); font-size:11px;">(${tr('setYou')})</span>` : ''}${disabledBadge}${pendingBadge}</td>
                <td><input type="text" value="${escapeHtml(u.email || '')}" placeholder="${tr('setNone')}"
                       data-action="save-user-email" data-username="${escapeHtml(u.username)}" ${(manageable || isSelf) ? '' : 'disabled'}
                       style="font-size:12px; padding:4px 8px; width:190px; border-radius:0; border:1px solid var(--border); background:var(--surface-3); color:var(--text); outline:none;"></td>
                <td>${manageable
                    ? `<select data-action="change-user-role" data-username="${escapeHtml(u.username)}" aria-label="${tr('lblNewUserRole')}"
                       style="font-size:12px; padding:4px 8px; border-radius:0; border:1px solid var(--border); background:var(--surface-3); color:var(--text); cursor:pointer; outline:none;">
                    ${roleOptions}
                  </select>`
                    : `<span class="role-pill role-pill-${escapeHtml(u.role)}">${roleLabel(u.role)}</span>`}</td>
                <td>${scopeCell}</td>
                <td>${tabsCell}</td>
                <td style="white-space:nowrap; font-size:12px; color:var(--text-muted);">${escapeHtml(formatLastLogin(u.last_login))}</td>
                <td style="white-space:nowrap;">${approveBtn}${resetBtn}${toggleBtn}${(manageable || isSelf) ? `<button data-action="delete-user" data-username="${escapeHtml(u.username)}" style="color:var(--danger); background:none; border:none; cursor:pointer;"><i class="fa-solid fa-trash-can"></i> ${delText}</button>` : ''}</td>
            </tr>`;
        }).join('');
    }

    // L'indirizzo serve solo al recupero password: senza, quell'account puo'
    // essere riaperto unicamente con il break-glass da CLI.
    async function saveUserEmail(username, email) {
        const res = await apiFetch('/api/users/email', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email })
        });
        if (res && res.ok) {
            showToast(tr('setEmailUpdated'), 'success');
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            showToast(e.detail || (tr('setUpdateFailed')), 'error');
            loadUsers();
        }
    }

    async function inviteUser() {
        const email = document.getElementById('inviteEmail').value.trim();
        const role = document.getElementById('inviteRole').value;
        if (!email) {
            showToast(tr('setEnterAnEmailAddress'), 'error');
            return;
        }
        const res = await apiFetch('/api/users/invite', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, role })
        });
        if (res && res.ok) {
            document.getElementById('inviteEmail').value = '';
            closeModal('inviteUserModal');
            showToast(tr('setInvitationSentTo', {email: email}), 'success');
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            showToast(e.detail || (tr('setInvitationFailed')), 'error');
        }
    }

    async function saveUserGroups(username) {
        const details = document.querySelector(`#usersTableBody details[data-u="${CSS.escape(username)}"]`);
        if (!details) return;
        const groups = [...details.querySelectorAll('.scope-box:checked')].map(cb => cb.value);
        const res = await apiFetch('/api/users/groups', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, groups })
        });
        if (res && res.ok) {
            loadUsers();   // aggiorna il riepilogo
        } else if (res) {
            const e = await res.json();
            alert((tr('uiError')) + (e.detail || ''));
        }
    }

    // Staged: il toggle di una checkbox non chiama l'API, mostra solo il pulsante Salva
    // se lo stato differisce da quello originale caricato dal server.
    function markTabsDirty(checkboxEl) {
        const details = checkboxEl.closest('details');
        if (!details) return;
        const original = JSON.parse(details.dataset.orig || '[]').slice().sort();
        const current = [...details.querySelectorAll('.tabs-box:checked')].map(cb => cb.value).sort();
        const dirty = JSON.stringify(original) !== JSON.stringify(current);
        const btn = details.querySelector('.tabs-save-btn');
        const label = details.querySelector('.tabs-dirty-label');
        if (btn) btn.style.display = dirty ? 'inline-flex' : 'none';
        if (label) label.style.display = dirty ? 'inline' : 'none';
    }

    async function saveUserTabs(btnEl) {
        const details = btnEl.closest('details');
        if (!details) return;
        const username = details.dataset.u;
        const allowed_tabs = [...details.querySelectorAll('.tabs-box:checked')].map(cb => cb.value);
        const res = await apiFetch('/api/users/tabs', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, allowed_tabs })
        });
        if (res && res.ok) {
            loadUsers();
        } else if (res) {
            const e = await res.json();
            alert((tr('uiError')) + (e.detail || ''));
        }
    }

    async function createUser() {
        const username = document.getElementById('newUserName').value.trim();
        const password = document.getElementById('newUserPass').value;
        const role     = document.getElementById('newUserRole').value;
        const email    = document.getElementById('newUserEmail').value.trim();
        // No password is fine with an email: the user sets one from a mailed link.
        if (!username || (!password && !email)) {
            alert(tr('setUsernameAndPasswordAre'));
            return;
        }
        const res = await apiFetch('/api/users', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role, email })
        });
        if (res && res.ok) {
            const d = await res.json().catch(() => ({}));
            if (d.setup_link_sent) showToast(tr('setSetupLinkSent', {email: email}), 'success');
            else if (d.welcome_mail_sent) showToast(tr('setWelcomeMailSent'), 'success');
            if (d.welcome_mail_error) showToast(tr('setWelcomeMailFailed', {error: d.welcome_mail_error}), 'warning');
            document.getElementById('newUserName').value = '';
            document.getElementById('newUserPass').value = '';
            document.getElementById('newUserEmail').value = '';
            closeModal('createUserModal');
            loadUsers();
        } else if (res) {
            const e = await res.json();
            alert((tr('uiError')) + (e.detail || ''));
        }
    }

    async function deleteUser(username) {
        const isSelf = username === currentUsername;
        const msg = isSelf
            ? (tr('setDeleteYourOwnAccount', {username: username}))
            : (tr('setDeleteUser', {username: username}));
        if (!confirm(msg)) return;
        const res = await apiFetch('/api/users/delete', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        // Cancellato il proprio account la sessione non vale più: si esce subito,
        // invece di lasciare che sia la prima chiamata a fallire con un 401.
        if (res && res.ok) { if (isSelf) logout(); else loadUsers(); }
        else if (res) { const e = await res.json(); alert((tr('uiError')) + (e.detail || '')); }
    }

    async function approveUser(username) {
        const res = await apiFetch('/api/users/approve', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        if (res && res.ok) {
            showToast(tr('setUserApproved', {username: username}), 'success');
            loadUsers();
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            showToast(e.detail || tr('setUpdateFailed'), 'error');
        }
    }

    // The link goes to the address on file: the admin never learns a password.
    async function sendUserReset(username) {
        const res = await apiFetch('/api/users/send-reset', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        if (res && res.ok) {
            showToast(tr('setResetSentTo', {username: username}), 'success');
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            showToast(e.detail || tr('setUpdateFailed'), 'error');
        }
    }

    async function toggleUserDisabled(username, currentlyDisabled) {
        const res = await apiFetch('/api/users/disable', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, disabled: !currentlyDisabled })
        });
        if (res && res.ok) loadUsers();
        else if (res) { const e = await res.json(); alert((tr('uiError')) + (e.detail || '')); }
    }

    async function changeUserRole(username, role) {
        const res = await apiFetch('/api/users/role', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, role })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            alert((tr('uiError')) + ((e && e.detail) || ''));
            loadUsers(); // ripristina la selezione corretta
        }
    }

    // --- IMPOSTAZIONI: esposizione in rete (solo admin) ---

    async function loadAppSettings() {
        if (!isAdminRole(currentRole)) return;
        const box = document.getElementById('netSettingsBody');
        if (!box) return;
        const res = await apiFetch('/api/settings/network');
        if (!res || !res.ok) { box.innerHTML = ''; return; }
        const d = await res.json();
        renderAppSettings(d);
        loadCliBlacklistSetting();
        loadPingMonitorSettings();
        loadTenantTelemetrySettings();
        loadSessionSettings();
        loadFleetVersions();
        if (typeof loadObsSettings === 'function') {
            loadObsSettings();
        }
        loadAppAdvSettings();
        if (typeof loadCloudBackup === 'function') {
            loadCloudBackup();
        }
        loadSmtpSettings();
        loadSsoSettings();
    }

    // --- IMPOSTAZIONI: Single Sign-On OIDC (solo admin) ---

    let ssoLoaded = false;

    function renderSsoStatus(cfg) {
        const box = document.getElementById('ssoStatusBox');
        if (!box) return;
        if (!cfg.enabled) {
            box.textContent = tr('setDisabledOnlyLocalAccounts');
            return;
        }
        const provisioning = cfg.auto_provision
            ? (tr('setAccountsCreatedOnFirst'))
            : (tr('setExistingAccountsOnly'));
        box.textContent = `${cfg.issuer_url} · ${cfg.client_id} · ${provisioning}`;
    }

    async function loadSsoSettings() {
        if (!isAdminRole(currentRole)) return;
        const res = await apiFetch('/api/settings/sso');
        if (!res || !res.ok) { await toastOnForbidden(res); return; }
        const cfg = await res.json();
        document.getElementById('ssoEnabled').checked = !!cfg.enabled;
        document.getElementById('ssoIssuerUrl').value = cfg.issuer_url || '';
        document.getElementById('ssoProviderName').value = cfg.provider_name || '';
        document.getElementById('ssoClientId').value = cfg.client_id || '';
        document.getElementById('ssoAdminGroup').value = cfg.admin_group || '';
        document.getElementById('ssoOperatorGroup').value = cfg.operator_group || '';
        document.getElementById('ssoDefaultRole').value = cfg.default_role || 'viewer';
        document.getElementById('ssoAutoProvision').checked = !!cfg.auto_provision;
        document.getElementById('ssoSyncRoles').checked = !!cfg.sync_roles;
        const secret = document.getElementById('ssoClientSecret');
        secret.value = '';
        secret.placeholder = cfg.has_client_secret
            ? (tr('setStoredLeaveEmptyTo'))
            : '';
        renderSsoStatus(cfg);
        ssoLoaded = true;
    }

    async function saveSsoSettings() {
        if (!ssoLoaded) {
            showToast(tr('setSettingsNotLoadedYet'), 'error');
            return;
        }
        const res = await apiFetch('/api/settings/sso', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: document.getElementById('ssoEnabled').checked,
                issuer_url: document.getElementById('ssoIssuerUrl').value.trim(),
                provider_name: document.getElementById('ssoProviderName').value.trim(),
                client_id: document.getElementById('ssoClientId').value.trim(),
                client_secret: document.getElementById('ssoClientSecret').value,
                admin_group: document.getElementById('ssoAdminGroup').value.trim(),
                operator_group: document.getElementById('ssoOperatorGroup').value.trim(),
                default_role: document.getElementById('ssoDefaultRole').value,
                auto_provision: document.getElementById('ssoAutoProvision').checked,
                sync_roles: document.getElementById('ssoSyncRoles').checked,
            })
        });
        if (res && res.ok) {
            showToast(tr('setSsoSettingsSaved'), 'success');
            loadSsoSettings();
        } else if (res) {
            const e = await res.json().catch(() => ({}));
            showToast(e.detail || (tr('setSaveFailed')), 'error');
        }
    }

    // --- IMPOSTAZIONI: server di posta SMTP (solo admin) ---

    // Come per la copia offsite: il salvataggio resta bloccato finche' la
    // configurazione non e' entrata nel form, altrimenti un GET fallito
    // salverebbe i default vuoti sopra a quella buona.
    let smtpLoaded = false;

    function renderSmtpStatus(cfg) {
        const box = document.getElementById('smtpStatusBox');
        if (!box) return;
        if (!cfg.enabled) {
            box.textContent = tr('setDisabledPasswordRecoveryBy');
            return;
        }
        const auth = cfg.username
            ? `${cfg.username}${cfg.has_password ? '' : (tr('setNoPassword'))}`
            : (tr('setAnonymous'));
        box.textContent = `${cfg.host}:${cfg.port} · ${cfg.tls_mode} · ${auth} · from ${cfg.from_email || '—'}`;
    }

    async function loadSmtpSettings() {
        if (!isAdminRole(currentRole)) return;
        const res = await apiFetch('/api/settings/smtp');
        if (!res || !res.ok) { await toastOnForbidden(res); return; }
        const cfg = await res.json();
        document.getElementById('smtpEnabled').checked = !!cfg.enabled;
        document.getElementById('smtpHost').value = cfg.host || '';
        document.getElementById('smtpPort').value = cfg.port || 587;
        document.getElementById('smtpTlsMode').value = cfg.tls_mode || 'starttls';
        document.getElementById('smtpUsername').value = cfg.username || '';
        document.getElementById('smtpFromEmail').value = cfg.from_email || '';
        // La password non torna mai dall'API: campo vuoto = mantieni quella salvata.
        const pw = document.getElementById('smtpPassword');
        pw.value = '';
        pw.placeholder = cfg.has_password
            ? (tr('uiStoredLeaveEmptyTo'))
            : '';
        renderSmtpStatus(cfg);
        smtpLoaded = true;
    }

    async function saveSmtpSettings() {
        if (!smtpLoaded) {
            showToast(tr('setSettingsNotLoadedYet'), 'error');
            return;
        }
        const res = await apiFetch('/api/settings/smtp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                enabled: document.getElementById('smtpEnabled').checked,
                host: document.getElementById('smtpHost').value.trim(),
                port: parseInt(document.getElementById('smtpPort').value, 10) || 587,
                username: document.getElementById('smtpUsername').value.trim(),
                password: document.getElementById('smtpPassword').value,
                from_email: document.getElementById('smtpFromEmail').value.trim(),
                tls_mode: document.getElementById('smtpTlsMode').value,
            }),
        });
        if (res && res.ok) {
            showToast(tr('setSmtpSettingsSaved'), 'success');
            loadSmtpSettings();
        } else {
            const d = res ? await res.json().catch(() => ({})) : {};
            showToast(d.detail || (tr('setSaveFailed')), 'error');
        }
    }

    async function sendSmtpTest() {
        const to = document.getElementById('smtpTestTo').value.trim();
        if (!to) {
            showToast(tr('setEnterARecipientAddress'), 'error');
            return;
        }
        const res = await apiFetch('/api/settings/smtp/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to }),
        });
        if (res && res.ok) {
            showToast(tr('setTestMessageSentTo', {to: to}), 'success');
        } else {
            const d = res ? await res.json().catch(() => ({})) : {};
            showToast(d.detail || (tr('setSendFailed')), 'error');
        }
    }

    // --- IMPOSTAZIONI AVANZATE (sezione 'app', solo admin) ---

    // 'grp' raggruppa i campi per ambito dentro la card generale (solo
    // presentazione: il salvataggio resta un unico POST /api/settings/app).
    const APP_ADV_FIELDS = [
        { key: 'port',                  type: 'number', lbl: 'lblAppPort',      grp: 'appAdvGrpServer' },
        { key: 'ssl_certfile',          type: 'text',   lbl: 'lblAppSslCert',   grp: 'appAdvGrpServer' },
        { key: 'ssl_keyfile',           type: 'text',   lbl: 'lblAppSslKey',    grp: 'appAdvGrpServer' },
        { key: 'cors_origins',          type: 'text',   lbl: 'lblAppCors',      grp: 'appAdvGrpServer' },
        { key: 'app_base_url',          type: 'text',   lbl: 'lblAppBaseUrl',   grp: 'appAdvGrpServer' },
        { key: 'retention_flows_days',  type: 'number', lbl: 'lblAppRetFlows',  grp: 'appAdvGrpRetention' },
        { key: 'retention_syslog_days', type: 'number', lbl: 'lblAppRetSyslog', grp: 'appAdvGrpRetention' },
        { key: 'retention_events_days', type: 'number', lbl: 'lblAppRetEvents', grp: 'appAdvGrpRetention' },
        { key: 'audit_history_days',   type: 'number', lbl: 'lblAppRetAuditHist', grp: 'appAdvGrpRetention', min: 0 },
        { key: 'config_drift_keep_versions', type: 'number', lbl: 'lblAppRetDriftVersions', grp: 'appAdvGrpRetention', min: 0 },
    ];

    async function loadAppAdvSettings() {
        if (!isAdminRole(currentRole)) return;
        const box = document.getElementById('appAdvBody');
        if (!box) return;
        const res = await apiFetch('/api/settings/app');
        if (!res || !res.ok) { box.innerHTML = ''; await toastOnForbidden(res); return; }
        renderAppAdvSettings(await res.json());
    }

    function renderAppAdvSettings(d) {
        const box = document.getElementById('appAdvBody');
        if (!box) return;
        const L = i18n[currentLang];
        const s = d.settings || {}, env = d.env_overrides || {}, def = d.defaults || {};
        const subhead = (key, fallback) =>
            `<div style="margin-top:10px; margin-bottom:6px; font-size:12px; color:var(--text-muted); text-transform:uppercase; font-weight:700;" data-i18n="${key}">${escapeHtml(L[key] || fallback)}</div>`;
        let lastGrp = null;
        const rows = APP_ADV_FIELDS.map(f => {
            const over = env[f.key];
            const envNote = over ? `<span style="font-size:11px; color:var(--warning);"> ${escapeHtml(L.msgEnvOverride || 'Sovrascritto da variabile d\'ambiente')}</span>` : '';
            let hdr = '';
            if (f.grp !== lastGrp) { hdr = subhead(f.grp, f.grp); lastGrp = f.grp; }
            const minAttr = f.min != null ? `min="${f.min}"` : (f.type === 'number' ? 'min="1"' : '');
            return `${hdr}
            <div class="form-group" style="max-width:420px;">
                <label data-i18n="${f.lbl}">${escapeHtml(L[f.lbl] || f.key)}</label>${envNote}
                <input id="appadv_${f.key}" type="${f.type}" ${minAttr} ${over ? 'disabled' : ''}
                       value="${s[f.key] != null ? escapeHtml(String(s[f.key])) : ''}"
                       placeholder="${def[f.key] != null ? def[f.key] : ''}" style="padding-left:12px;">
            </div>`;
        }).join('');
        box.innerHTML = `
            ${rows}
            ${subhead('appAdvGrpStartup', 'Avvio')}
            <label style="display:flex; align-items:center; gap:10px; cursor:pointer; margin-bottom:14px;">
                <input type="checkbox" id="appadv_no_browser" ${s.no_browser ? 'checked' : ''} ${env.no_browser ? 'disabled' : ''}>
                <span style="font-size:13px;" data-i18n="lblAppNoBrowser">${escapeHtml(L.lblAppNoBrowser || 'Non aprire il browser all\'avvio')}</span>
            </label>
            <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">
                ${escapeHtml(L.lblAppDataDir || 'Cartella dati (solo env SENTINELNET_DATA_DIR)')}: <code>${escapeHtml(d.data_dir || '')}</code>
            </div>
            <button id="btnSaveAppAdv" class="btn btn-primary btn-small">
                <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(L.btnSave || 'Salva')}
            </button>
            <div id="appAdvError" style="margin-top:10px; font-size:12px; color:var(--danger);"></div>`;
    }

    async function saveAppAdvSettings() {
        const errEl = document.getElementById('appAdvError');
        if (errEl) errEl.textContent = '';
        const payload = {};
        APP_ADV_FIELDS.forEach(f => {
            const el = document.getElementById(`appadv_${f.key}`);
            if (!el || el.disabled) return;
            payload[f.key] = el.value.trim() === '' ? null : el.value.trim();
        });
        const nb = document.getElementById('appadv_no_browser');
        if (nb && !nb.disabled) payload.no_browser = nb.checked;
        const res = await apiFetch('/api/settings/app', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            const msg = (e && e.detail) || (tr('uiSaveError'));
            if (errEl) errEl.textContent = msg; else alert(msg);
            return;
        }
        const banner = document.getElementById('appAdvRestartBanner');
        if (banner) banner.style.display = 'block';
        showToast(tr('msgObsRestartRequired') || 'Riavvio richiesto per applicare le modifiche.', 'warning');
    }

    async function loadCliBlacklistSetting() {
        const cb = document.getElementById('cliBlacklistToggle');
        if (!cb) return;
        const res = await apiFetch('/api/settings/cli-blacklist');
        if (!res || !res.ok) { await toastOnForbidden(res); return; }
        const d = await res.json();
        cb.checked = !!d.cli_blacklist_operators;
    }

    async function saveCliBlacklistSetting() {
        const cb = document.getElementById('cliBlacklistToggle');
        const statusEl = document.getElementById('cliBlacklistStatus');
        const res = await apiFetch('/api/settings/cli-blacklist', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cli_blacklist_operators: cb.checked })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            alert((tr('uiError')) + ((e && e.detail) || ''));
            cb.checked = !cb.checked; // ripristina lo stato precedente
            return;
        }
        if (statusEl) statusEl.textContent = tr('msgCliBlacklistSaved');
    }

    function renderAppSettings(d) {
        const box = document.getElementById('netSettingsBody');
        if (!box) return;
        const L = i18n[currentLang];
        const localIps = d.local_ips || [];
        const options = ['0.0.0.0', '127.0.0.1', ...localIps.filter(ip => ip !== '0.0.0.0' && ip !== '127.0.0.1')];
        const current = d.configured_host || d.effective_host || '0.0.0.0';
        const optHtml = options.map(ip => {
            const hint = ip === '0.0.0.0' ? ` ${escapeHtml(L.optAllIfaces)}` : ip === '127.0.0.1' ? ` ${escapeHtml(L.optLocalOnly)}` : '';
            return `<option value="${escapeHtml(ip)}" ${ip === current ? 'selected' : ''}>${escapeHtml(ip)}${hint}</option>`;
        }).join('');
        const envNote = d.env_override
            ? `<div style="margin-top:10px; padding:8px 10px; border:1px solid var(--warning); border-radius:0; color:var(--warning); font-size:12px;"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(L.msgEnvOverride)}</div>`
            : '';
        box.innerHTML = `
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
                <span style="font-size:12px; color:var(--text-muted);">${escapeHtml(L.lblNetHost)}:</span>
                <span class="badge" style="font-size:11px; color:var(--primary); border:1px solid var(--primary); font-family:var(--font-code);">${escapeHtml(d.effective_host || '—')}</span>
                <span style="font-size:12px; color:var(--text-muted); margin-left:16px;">${escapeHtml(L.lblNetPort)}:</span>
                <span style="font-family:var(--font-code); font-size:12px;">${escapeHtml(d.port != null ? String(d.port) : '—')}</span>
            </div>
            <div class="form-group" style="max-width:360px;">
                <select id="netHostSelect" ${d.env_override ? 'disabled' : ''} style="padding-left:12px;">${optHtml}</select>
            </div>
            ${envNote}
            <div style="margin-top:12px;">
                <button id="btnSaveAppSettings" class="btn btn-primary btn-small" ${d.env_override ? 'disabled' : ''} data-i18n="btnSave">
                    <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(L.btnSave || (tr('uiSave')))}
                </button>
            </div>
            <div id="netSettingsNotice" style="margin-top:10px; font-size:12px; color:var(--warning);"></div>`;
    }

    async function saveAppSettings() {
        const sel = document.getElementById('netHostSelect');
        if (!sel) return;
        const L = i18n[currentLang];
        const res = await apiFetch('/api/settings/network', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: sel.value })
        });
        const notice = document.getElementById('netSettingsNotice');
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            if (notice) notice.textContent = (tr('uiError')) + ((e && e.detail) || '');
            return;
        }
        if (notice) notice.textContent = L.msgRestartRequired;
    }

    // --- CERTIFICATO TLS SELF-SIGNED (solo admin) ---

    async function generateSelfSignedCert() {
        const hostEl = document.getElementById('selfSignedHost');
        const statusEl = document.getElementById('selfSignedStatus');
        if (!hostEl) return;
        const res = await apiFetch('/api/settings/tls/self-signed', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ host: hostEl.value.trim() })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            if (statusEl) statusEl.textContent = (tr('uiError')) + ((e && e.detail) || '');
            return;
        }
        const d = await res.json();
        if (statusEl) statusEl.textContent = tr('msgSelfSignedDone', {certfile: d.certfile});
    }

    // --- RIAVVIO DELL'APPLICAZIONE (solo admin) ---

    async function updateApplication() {
        if (!confirm(tr('msgConfirmUpdateApp'))) return;
        const statusEl = document.getElementById('restartAppStatus');
        if (statusEl) statusEl.textContent = tr('msgUpdateRunning');
        const res = await apiFetch('/api/settings/update', { method: 'POST' });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            if (statusEl) statusEl.textContent = (tr('uiError')) + ((e && e.detail) || '');
            return;
        }
        const d = await res.json();
        if (d.status === 'up-to-date') {
            if (statusEl) statusEl.textContent = tr('msgUpdateUpToDate');
            return;
        }
        watchRestart(d.latest || null);
    }

    // The answer to restart/update comes from the process that is about to go
    // away, so it cannot tell how things ended. Poll /api/version (public)
    // and report each phase: still up, down, back (with its version), or not
    // back at all. `target`: the version an update must come back with.
    async function watchRestart(target) {
        const statusEl = document.getElementById('restartAppStatus');
        const say = (key, vars) => { if (statusEl) statusEl.textContent = tr(key, vars); };
        const start = Date.now();
        let wentDown = false;
        while (Date.now() - start < 5 * 60 * 1000) {
            await new Promise(r => setTimeout(r, 2000));
            const s = Math.round((Date.now() - start) / 1000);
            let version = null;
            try {
                const r = await fetch('/api/version', { cache: 'no-store' });
                if (r.ok) version = (await r.json()).version;
            } catch (e) { /* down: that is the phase we are waiting through */ }
            if (!version) { wentDown = true; say('msgRestartWaitingUp', { s }); continue; }
            if (target && version === target) { say('msgRestartBack', { version }); return; }
            if (!wentDown) { say('msgRestartWaitingDown', { s }); continue; }
            say(target ? 'msgUpdateNotApplied' : 'msgRestartBack', { version });
            return;
        }
        say('msgRestartNotBack');
    }

    async function restartApplication() {
        if (!confirm(tr('msgConfirmRestartApp'))) return;
        const statusEl = document.getElementById('restartAppStatus');
        const res = await apiFetch('/api/settings/restart', { method: 'POST' });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            if (statusEl) statusEl.textContent = (tr('uiError')) + ((e && e.detail) || '');
            return;
        }
        watchRestart(null);
    }

    // Disabilita in anticipo cio' che qui non puo' funzionare, invece di
    // lasciar premere e rispondere 409. I due rifiuti erano gia' documentati
    // lato server, ma l'utente li scopriva solo dopo il clic.
    function applyUpdateCapabilities(d) {
        const hint = document.getElementById('restartAppHint');
        const btnUpd = document.getElementById('btnUpdateApp');
        const btnRst = document.getElementById('btnRestartApp');
        const notes = [];

        if (btnRst) {
            btnRst.disabled = !d.can_restart;
            if (!d.can_restart) notes.push(tr('msgRestartNeedsSupervisor'));
        }
        if (btnUpd) {
            btnUpd.disabled = !d.can_update;
            if (!d.can_update) {
                notes.push(d.install_kind === 'exe'
                    ? tr('msgUpdateNeedsService')
                    : tr('msgUpdateNeedsGit'));
            }
        }
        if (hint) hint.textContent = notes.join(' ');

        // Con l'installer si puo' dire QUALE versione c'e', non solo che si
        // puo' aggiornare. Il controllo non scarica nulla.
        if (d.install_kind === 'exe') checkForUpdate();
    }

    async function checkForUpdate() {
        const el = document.getElementById('updateAvailable');
        if (!el) return;
        const res = await apiFetch('/api/settings/update/check');
        if (!res || !res.ok) { el.textContent = ''; return; }
        const d = await res.json();
        el.textContent = d.status === 'available'
            ? tr('msgUpdateAvailable', { version: d.latest })
            : tr('msgUpdateUpToDate');
    }

    // --- VERSIONI DELLA FLOTTA (solo admin) ---

    async function loadFleetVersions() {
        if (!isAdminRole(currentRole)) return;
        const body = document.getElementById('fleetVersionsBody');
        if (!body) return;
        const res = await apiFetch('/api/fleet/versions');
        if (!res || !res.ok) { body.innerHTML = ''; await toastOnForbidden(res); return; }
        const d = await res.json();
        applyUpdateCapabilities(d);
        const dash = '—';
        const rows = [`<tr>
            <td><strong>${escapeHtml(tr('lblFleetCentral'))}</strong></td>
            <td>${escapeHtml(d.central.version || dash)}</td>
            <td>${dash}</td>
            <td>${dash}</td>
            <td>${dash}</td>
            <td><span class="chip">${escapeHtml(tr('lblFleetInstallKind'))}: ${escapeHtml(d.install_kind || dash)}</span></td>
        </tr>`];
        for (const a of (d.agents || [])) {
            // Marcatore visibile: una versione diversa o un checkout sporco
            // sono esattamente cio' per cui si guarda questo pannello.
            const marks = [];
            if (a.behind) marks.push(`<span class="status bad"><span class="led led-danger"></span>${escapeHtml(tr('lblFleetBehind'))}</span>`);
            if (a.dirty) marks.push(`<span class="status bad"><span class="led led-warning"></span>${escapeHtml(tr('lblFleetDirty'))}</span>`);
            if (!marks.length) marks.push(`<span class="status ok"><span class="led led-success"></span>${escapeHtml(tr('lblFleetAligned'))}</span>`);
            rows.push(`<tr>
                <td>${escapeHtml(a.name || a.site_id)}</td>
                <td>${escapeHtml(a.version || dash)}</td>
                <td>${escapeHtml(a.commit || dash)}</td>
                <td>${escapeHtml(a.branch || dash)}</td>
                <td>${a.last_seen ? escapeHtml(new Date(a.last_seen * 1000).toLocaleString()) : dash}</td>
                <td>${marks.join(' ')}</td>
            </tr>`);
        }
        if (!(d.agents || []).length) {
            rows.push(`<tr><td colspan="6" style="color:var(--text-muted);">${escapeHtml(tr('msgFleetNoAgents'))}</td></tr>`);
        }
        body.innerHTML = rows.join('');
    }

    // --- MONITOR PING CONTINUO (solo admin) ---

    async function loadSessionSettings() {
        if (!isAdminRole(currentRole)) return;
        const res = await apiFetch('/api/settings/session');
        if (!res || !res.ok) { await toastOnForbidden(res); return; }
        const cfg = await res.json();
        document.getElementById('sessionIdleMinutes').value = cfg.idle_minutes;
        document.getElementById('sessionMaxHours').value = cfg.max_hours;
    }

    async function saveSessionSettings() {
        const statusEl = document.getElementById('sessionSettingsStatus');
        const idle = parseInt(document.getElementById('sessionIdleMinutes').value, 10);
        const maxHours = parseInt(document.getElementById('sessionMaxHours').value, 10);
        const res = await apiFetch('/api/settings/session', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ idle_minutes: idle, max_hours: maxHours })
        });
        if (res && res.ok) {
            statusEl.textContent = tr('msgSessionSettingsSaved');
            return;
        }
        const e = res ? await res.json().catch(() => ({})) : {};
        // A 422 from the range check carries a list; the cap check a sentence.
        statusEl.textContent = typeof e.detail === 'string' ? tr('uiError') + e.detail : tr('msgSessionSettingsInvalid');
    }

    async function loadPingMonitorSettings() {
        if (!isAdminRole(currentRole)) return;
        const toggle = document.getElementById('pingMonitorToggle');
        const intervalEl = document.getElementById('pingMonitorInterval');
        if (!toggle || !intervalEl) return;
        const res = await apiFetch('/api/settings/ping-monitor');
        if (!res || !res.ok) { await toastOnForbidden(res); return; }
        const cfg = await res.json();
        toggle.checked = !!cfg.enabled;
        intervalEl.value = cfg.interval_seconds || 60;
        loadPingMonitorStatus();
    }

    async function savePingMonitorSettings() {
        const toggle = document.getElementById('pingMonitorToggle');
        const intervalEl = document.getElementById('pingMonitorInterval');
        const statusEl = document.getElementById('pingMonitorStatus');
        if (!toggle || !intervalEl) return;
        const L = i18n[currentLang];
        const interval = parseInt(intervalEl.value, 10);
        if (!Number.isFinite(interval) || interval < 5 || interval > 86400) {
            if (statusEl) statusEl.textContent = L.msgPingMonitorIntervalInvalid || 'Intervallo non valido (5–86400 secondi).';
            return;
        }
        const res = await apiFetch('/api/settings/ping-monitor', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: toggle.checked, interval_seconds: interval })
        });
        if (!res || !res.ok) {
            const e = res ? await res.json() : null;
            if (statusEl) statusEl.textContent = (tr('uiError')) + ((e && e.detail) || '');
            return;
        }
        if (statusEl) statusEl.textContent = L.msgPingMonitorSaved || 'Impostazioni monitor ping salvate.';
        loadPingMonitorStatus();
    }

    async function loadPingMonitorStatus() {
        const summaryEl = document.getElementById('pingMonitorSummary');
        const statusEl = document.getElementById('pingMonitorStatus');
        if (!summaryEl) return;
        const L = i18n[currentLang];
        const res = await apiFetch('/api/ping-monitor/status');
        if (!res || !res.ok) { summaryEl.innerHTML = ''; return; }
        const st = await res.json();
        const lastRun = st.last_run ? new Date(st.last_run * 1000).toLocaleString() : '—';
        if (statusEl) {
            statusEl.textContent = st.enabled
                ? `${L.lblPingMonitorLastRun || 'Ultimo ciclo'}: ${lastRun}`
                : (L.msgPingMonitorDisabled || 'Monitor ping disattivato.');
        }
        // Three buckets, not two: a jump-site device is never pinged (the
        // bastion tunnel carries no ICMP), so the backend reports it under
        // summary.unknown. Rendering only up/down made those devices vanish
        // from the panel with no explanation. Same vocabulary and lamp as the
        // inventory KPI row for the state (invKpiUnknownLabel / led-discovered).
        const s = st.summary || { total: 0, up: 0, down: 0, unknown: 0 };
        summaryEl.innerHTML = `
            <span class="chip">${escapeHtml(L.lblPingMonitorTotal || 'Dispositivi')}: ${s.total}</span>
            <span class="status ok"><span class="led led-success"></span>${escapeHtml(L.lblPingMonitorUp || 'Up')}: ${s.up}</span>
            <span class="status bad"><span class="led led-danger"></span>${escapeHtml(L.lblPingMonitorDown || 'Down')}: ${s.down}</span>
            <span class="status idle"><span class="led led-discovered"></span>${escapeHtml(L.invKpiUnknownLabel || 'Non misurabile')}: ${s.unknown || 0}</span>`;
    }

    // --- TELEMETRIA PER TENANT ---
    async function loadTenantTelemetrySettings() {
        if (!isAdminRole(currentRole)) return;
        const container = document.getElementById('tenantTelemetryContainer');
        if (!container) return;
        const res = await apiFetch('/api/settings/tenant-telemetry');
        if (!res || !res.ok) { await toastOnForbidden(res); return; }
        const data = await res.json();
        renderTenantTelemetryTable(data);
    }

    function renderTenantTelemetryTable(telemetryMap) {
        const container = document.getElementById('tenantTelemetryContainer');
        if (!container) return;
        const tenants = Object.keys(telemetryMap);
        if (!tenants.length) {
            container.innerHTML = `<p style="color:var(--text-muted); font-size:13px;">${escapeHtml(tr('ttNoTenants'))}</p>`;
            return;
        }

        let html = `<table class="ui-table" style="width:100%; font-size:13px;">
            <thead>
                <tr>
                    <th>${escapeHtml(tr('ttColTenant'))}</th>
                    <th>${escapeHtml(tr('ttColPing'))}</th>
                    <th>${escapeHtml(tr('ttColSnmp'))}</th>
                    <th>${escapeHtml(tr('ttColApi'))}</th>
                    <th>${escapeHtml(tr('ttColTriage'))}</th>
                    <th>${escapeHtml(tr('ttColAction'))}</th>
                </tr>
            </thead>
            <tbody>`;

        for (const t of tenants) {
            const item = telemetryMap[t];
            html += `<tr>
                <td><strong>${escapeHtml(t)}</strong></td>
                <td>
                    <label style="display:inline-flex; align-items:center; gap:6px; cursor:pointer;">
                        <input type="checkbox" id="tt_ping_${escapeHtml(t)}" ${item.ping_enabled ? 'checked' : ''}> Ping
                    </label>
                </td>
                <td>
                    <label style="display:inline-flex; align-items:center; gap:6px; cursor:pointer;">
                        <input type="checkbox" id="tt_snmp_${escapeHtml(t)}" ${item.snmp_enabled ? 'checked' : ''}> SNMP
                    </label>
                </td>
                <td>
                    <label style="display:inline-flex; align-items:center; gap:6px; cursor:pointer;">
                        <input type="checkbox" id="tt_api_${escapeHtml(t)}" ${item.api_enabled ? 'checked' : ''}> API
                    </label>
                </td>
                <td>
                    <label style="display:inline-flex; align-items:center; gap:6px; cursor:pointer;">
                        <input type="checkbox" id="tt_triage_${escapeHtml(t)}" ${item.triage_enabled ? 'checked' : ''}> Triage
                    </label>
                </td>
                <td>
                    <button type="button" class="btn btn-secondary btn-small" data-action="save-tenant-telemetry" data-tenant="${escapeHtml(t)}" style="width:auto; margin:0;">
                        <i class="fa-solid fa-floppy-disk"></i> ${escapeHtml(tr('ttSave'))}
                    </button>
                </td>
            </tr>`;
        }

        html += `</tbody></table>`;
        container.innerHTML = html;
    }

    async function saveTenantTelemetry(tenant) {
        const pingEl = document.getElementById(`tt_ping_${tenant}`);
        const snmpEl = document.getElementById(`tt_snmp_${tenant}`);
        const apiEl = document.getElementById(`tt_api_${tenant}`);
        const triageEl = document.getElementById(`tt_triage_${tenant}`);
        if (!pingEl || !snmpEl || !apiEl || !triageEl) return;

        const payload = {
            ping_enabled: pingEl.checked,
            snmp_enabled: snmpEl.checked,
            api_enabled: apiEl.checked,
            triage_enabled: triageEl.checked
        };

        const res = await apiFetch(`/api/settings/tenant-telemetry/${encodeURIComponent(tenant)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res && res.ok) {
            showToast(`${tr('ttSaved')} ${tenant}`, 'success');
        } else {
            showToast(`${tr('ttSaveError')} ${tenant}`, 'error');
        }
    }

    document.getElementById('tenantTelemetryContainer')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action="save-tenant-telemetry"]');
        if (btn && btn.dataset.tenant) {
            saveTenantTelemetry(btn.dataset.tenant);
        }
    });

    // Delegated and static event listeners
    document.getElementById('uiVariantSelect')?.addEventListener('change', (e) => {
        if (typeof applyUiVariant === 'function') applyUiVariant(e.target.value, true);
    });

    document.getElementById('uiVariantCardsGrid')?.addEventListener('click', (e) => {
        const card = e.target.closest('[data-action="apply-ui-variant"]');
        if (card && card.dataset.variant && typeof applyUiVariant === 'function') {
            applyUiVariant(card.dataset.variant, true);
        }
    });

    // Settings index: a click scrolls to the section and marks it. While
    // scrolling, the marked entry is the last section whose top has passed the
    // top of the viewport. The last few sections are too short to ever reach
    // the top (the page ends first), so at the bottom of the page the entry the
    // user clicked stays marked, or else the last section on screen.
    const settingsNav = document.getElementById('settingsNav');
    if (settingsNav) {
        let pinned = null;
        const markActive = (id) => settingsNav.querySelectorAll('[data-settings-jump]').forEach(btn => {
            const on = btn.dataset.settingsJump === id;
            btn.classList.toggle('active', on);
            if (on) btn.setAttribute('aria-current', 'true'); else btn.removeAttribute('aria-current');
        });
        const syncActive = () => {
            const tab = document.getElementById('tab-settings');
            if (!tab || !tab.classList.contains('active')) return;
            if (pinned) { markActive(pinned); return; }
            const sections = [...tab.querySelectorAll('.set-section')].filter(sec => sec.offsetParent !== null);
            if (!sections.length) return;
            const scroller = document.scrollingElement;
            const lastSec = sections[sections.length - 1].getBoundingClientRect();
            const atBottom = lastSec.bottom <= window.innerHeight + 2
                || scroller.scrollTop + window.innerHeight >= scroller.scrollHeight - 2;
            let current = sections[0];
            for (const sec of sections) {
                const top = sec.getBoundingClientRect().top;
                if (top <= 140 || (atBottom && top < window.innerHeight)) current = sec;
            }
            markActive(current.id);
        };
        settingsNav.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-settings-jump]');
            if (!btn) return;
            pinned = btn.dataset.settingsJump;
            markActive(pinned);
            document.getElementById(pinned)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        // Only the user's own scrolling releases the clicked entry; the smooth
        // scroll started by the click must not.
        ['wheel', 'touchmove', 'keydown'].forEach(ev =>
            window.addEventListener(ev, () => { pinned = null; }, { passive: true }));
        // Capture: the page may scroll on <main> rather than on the document.
        document.addEventListener('scroll', syncActive, { capture: true, passive: true });
        syncActive();
    }

    document.getElementById('cliBlacklistToggle')?.addEventListener('change', saveCliBlacklistSetting);
    document.getElementById('btnSavePingMonitor')?.addEventListener('click', savePingMonitorSettings);
    document.getElementById('btnSaveSessionSettings')?.addEventListener('click', saveSessionSettings);
    document.getElementById('btnRestartApp')?.addEventListener('click', restartApplication);
    document.getElementById('btnUpdateApp')?.addEventListener('click', updateApplication);
    document.getElementById('btnGenerateSelfSigned')?.addEventListener('click', generateSelfSignedCert);

    document.getElementById('appAdvBody')?.addEventListener('click', (e) => {
        if (e.target.closest('#btnSaveAppAdv')) saveAppAdvSettings();
    });

    document.getElementById('netSettingsBody')?.addEventListener('click', (e) => {
        if (e.target.closest('#btnSaveAppSettings')) saveAppSettings();
    });

    document.getElementById('sitesTableBody')?.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn || !btn.dataset.siteId) return;
        const act = btn.dataset.action;
        const siteId = btn.dataset.siteId;
        if (act === 'open-agent-control' && typeof openAgentControlModal === 'function') openAgentControlModal(siteId);
        else if (act === 'edit-site') openEditSiteWizard(siteId);
        else if (act === 'regen-site-token') regenSiteToken(siteId);
        else if (act === 'delete-site') deleteSite(siteId);
        else if (act === 'test-bastion') testBastion(siteId);
    });

    // The panel lives outside sitesTableBody: it needs its own listeners.
    document.getElementById('siteWizard')?.addEventListener('click', (e) => {
        if (e.target.closest('#swTestBtn')) swRunTest();
        else if (e.target.closest('[data-action="copy-site-enroll"]')) copySiteEnrollment();
        else if (e.target.closest('[data-action="sw-new-identity"]')) goCreateIdentity();
    });
    document.getElementById('siteWizard')?.addEventListener('input', (e) => {
        if (e.target.id === 'swSubnets') renderSwSubnetChips();
        if (['swJumpHost', 'swJumpPort'].includes(e.target.id)) swInvalidateTest();
    });
    document.getElementById('siteWizard')?.addEventListener('change', (e) => {
        if (e.target.name === 'swMode' || e.target.id === 'swJumpIdentity') swInvalidateTest();
    });
    // Enter in a field must not submit (and reload) the page.
    document.getElementById('siteWizardForm')?.addEventListener('submit', (e) => e.preventDefault());

    document.getElementById('sitesTableBody')?.addEventListener('change', (e) => {
        const sel = e.target.closest('[data-action="set-site-device-identity"]');
        if (sel && sel.dataset.siteId) setSiteDeviceIdentity(sel.dataset.siteId, sel.value);
        const jump = e.target.closest('[data-action="set-site-jump-identity"]');
        if (jump && jump.dataset.siteId) setSiteJumpIdentity(jump.dataset.siteId, jump.value);
        const cm = e.target.closest('[data-action="set-site-central-managed"]');
        if (cm && cm.dataset.siteId) setSiteCentralManaged(cm.dataset.siteId, cm.checked);
    });

    document.getElementById('usersTableBody')?.addEventListener('change', (e) => {
        const grp = e.target.closest('[data-action="save-user-groups"]');
        if (grp && grp.dataset.username) {
            saveUserGroups(grp.dataset.username);
            return;
        }
        const dirty = e.target.closest('[data-action="mark-tabs-dirty"]');
        if (dirty) {
            markTabsDirty(dirty);
            return;
        }
        const role = e.target.closest('[data-action="change-user-role"]');
        if (role && role.dataset.username) {
            changeUserRole(role.dataset.username, role.value);
            return;
        }
        const mail = e.target.closest('[data-action="save-user-email"]');
        if (mail && mail.dataset.username) {
            saveUserEmail(mail.dataset.username, mail.value.trim());
            return;
        }
    });

    document.getElementById('usersTableBody')?.addEventListener('click', (e) => {
        const saveTabs = e.target.closest('[data-action="save-user-tabs"]');
        if (saveTabs) {
            saveUserTabs(saveTabs);
            return;
        }
        const toggleDis = e.target.closest('[data-action="toggle-user-disabled"]');
        if (toggleDis && toggleDis.dataset.username) {
            toggleUserDisabled(toggleDis.dataset.username, toggleDis.dataset.disabled === '1');
            return;
        }
        const delUser = e.target.closest('[data-action="delete-user"]');
        if (delUser && delUser.dataset.username) {
            deleteUser(delUser.dataset.username);
            return;
        }
        const approveBtn = e.target.closest('[data-action="approve-user"]');
        if (approveBtn && approveBtn.dataset.username) {
            approveUser(approveBtn.dataset.username);
            return;
        }
        const resetBtn = e.target.closest('[data-action="send-user-reset"]');
        if (resetBtn && resetBtn.dataset.username) {
            sendUserReset(resetBtn.dataset.username);
            return;
        }
    });

    document.getElementById('btnCreateUser')?.addEventListener('click', createUser);
    document.getElementById('btnInviteUser')?.addEventListener('click', inviteUser);
    document.getElementById('btnNewSite')?.addEventListener('click', openNewSiteWizard);
    document.getElementById('smtpBtnSave')?.addEventListener('click', saveSmtpSettings);
    document.getElementById('smtpBtnTest')?.addEventListener('click', sendSmtpTest);
    document.getElementById('ssoBtnSave')?.addEventListener('click', saveSsoSettings);
    document.getElementById('btnCopyMcpConfig')?.addEventListener('click', copyMcpConfig);
    document.getElementById('btnSaveMcpSettings')?.addEventListener('click', saveMcpSettings);

