// -*- coding: utf-8 -*-
// Gestione frontend Notifiche Email (preferenze personali, regole admin, storico invii).

let _notifySubtab = 'prefs';
let _currentNotifyRules = [];

async function loadNotificationsTab() {
    const L = i18n[currentLang];

    // Visibilità sotto-tab Regole: solo admin
    const rulesBtn = document.getElementById('btnNotifyTabRules');
    if (rulesBtn) {
        rulesBtn.style.display = isAdminRole(currentRole) ? '' : 'none';
    }

    // Controlla stato SMTP per il banner in cima
    _checkSmtpStatus();

    // Inizializza listener se non già registrati
    _initNotificationsListeners();

    // Carica la sotto-tab attiva
    _switchNotifySubtab(_notifySubtab);
}

async function _checkSmtpStatus() {
    try {
        const res = await apiFetch('/api/settings/smtp');
        if (res && res.ok) {
            const data = await res.json();
            const banner = document.getElementById('notifySmtpDisabledBanner');
            if (banner) {
                banner.style.display = data.enabled ? 'none' : 'flex';
            }
        }
    } catch (_) {}
}

function _switchNotifySubtab(subtab) {
    _notifySubtab = subtab;
    const btnPrefs = document.getElementById('btnNotifyTabPrefs');
    const btnRules = document.getElementById('btnNotifyTabRules');
    const btnLog = document.getElementById('btnNotifyTabLog');

    const panelPrefs = document.getElementById('notifySubtabPrefs');
    const panelRules = document.getElementById('notifySubtabRules');
    const panelLog = document.getElementById('notifySubtabLog');

    if (btnPrefs) btnPrefs.className = subtab === 'prefs' ? 'btn btn-small btn-primary' : 'btn btn-small btn-secondary';
    if (btnRules) btnRules.className = subtab === 'rules' ? 'btn btn-small btn-primary' : 'btn btn-small btn-secondary';
    if (btnLog) btnLog.className = subtab === 'log' ? 'btn btn-small btn-primary' : 'btn btn-small btn-secondary';

    if (panelPrefs) panelPrefs.style.display = subtab === 'prefs' ? 'block' : 'none';
    if (panelRules) panelRules.style.display = subtab === 'rules' ? 'block' : 'none';
    if (panelLog) panelLog.style.display = subtab === 'log' ? 'block' : 'none';

    if (subtab === 'prefs') {
        _loadNotifyPrefs();
    } else if (subtab === 'rules') {
        _loadNotifyRules();
    } else if (subtab === 'log') {
        _loadNotifyLog();
    }
}

let _notifyListenersInit = false;
function _initNotificationsListeners() {
    if (_notifyListenersInit) return;
    _notifyListenersInit = true;

    document.getElementById('btnNotifyTabPrefs')?.addEventListener('click', () => _switchNotifySubtab('prefs'));
    document.getElementById('btnNotifyTabRules')?.addEventListener('click', () => _switchNotifySubtab('rules'));
    document.getElementById('btnNotifyTabLog')?.addEventListener('click', () => _switchNotifySubtab('log'));

    // Modalità digest toggle intervallo
    document.querySelectorAll('input[name="notifyPrefMode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const digestOpt = document.getElementById('notifyPrefDigestOptions');
            if (digestOpt) {
                digestOpt.style.display = e.target.value === 'digest' ? 'inline-block' : 'none';
            }
        });
    });

    document.getElementById('btnSaveNotifyPrefs')?.addEventListener('click', _saveNotifyPrefs);
    document.getElementById('btnTestNotifyPrefs')?.addEventListener('click', _testNotifyPrefs);

    document.getElementById('btnNewNotifyRule')?.addEventListener('click', _openNewRuleModal);
    document.getElementById('btnRefreshNotifyLog')?.addEventListener('click', _loadNotifyLog);
    document.getElementById('notifyLogStatusFilter')?.addEventListener('change', _loadNotifyLog);

    // Delegazione tabella regole
    document.getElementById('notifyRulesTableBody')?.addEventListener('click', (e) => {
        const editBtn = e.target.closest('[data-action="edit-notify-rule"]');
        if (editBtn) {
            _openEditRuleModal(parseInt(editBtn.dataset.id, 10));
            return;
        }
        const testBtn = e.target.closest('[data-action="test-notify-rule"]');
        if (testBtn) {
            _testNotifyRule(parseInt(testBtn.dataset.id, 10));
            return;
        }
        const delBtn = e.target.closest('[data-action="delete-notify-rule"]');
        if (delBtn) {
            _deleteNotifyRule(parseInt(delBtn.dataset.id, 10));
            return;
        }
        const toggle = e.target.closest('[data-action="toggle-notify-rule"]');
        if (toggle) {
            _toggleRuleEnabled(parseInt(toggle.dataset.id, 10), toggle.checked);
        }
    });

    // Modale regola
    document.querySelectorAll('[data-action="close-modal-notify-rule"]').forEach(btn => {
        btn.addEventListener('click', () => closeModal('modalNotifyRule'));
    });
    document.getElementById('btnSubmitNotifyRule')?.addEventListener('click', _submitNotifyRule);

    // Link a SMTP settings da banner
    document.querySelector('[data-action="notify-goto-smtp"]')?.addEventListener('click', () => {
        switchTab('tab-settings');
        const jump = document.querySelector('[data-settings-jump="smtpPanel"]');
        if (jump) jump.click();
    });
}

// --- PREFERENZE PERSONALI ---

async function _loadNotifyPrefs() {
    const res = await apiFetch('/api/notifications/prefs');
    if (!res || !res.ok) return;
    const data = await res.json();
    const prefs = data.prefs || {};
    const email = data.email || '';
    const hasEmail = data.has_email;

    // Badge email
    const badge = document.getElementById('notifyUserEmailBadge');
    if (badge) {
        if (hasEmail) {
            badge.innerHTML = `<span style="display:inline-flex; align-items:center; gap:6px; padding:4px 10px; background:var(--surface-2); border:1px solid var(--border); border-radius:16px; font-size:12px;"><i class="fa-solid fa-circle" style="font-size:7px; color:var(--success);"></i> <span style="color:var(--text-muted);">Destinazione:</span> <b style="font-family:var(--font-code); color:var(--text);">${escapeHtml(email)}</b></span>`;
        } else {
            badge.innerHTML = `<span style="display:inline-flex; align-items:center; gap:6px; padding:4px 10px; background:color-mix(in srgb, var(--warning) 12%, transparent); border:1px solid color-mix(in srgb, var(--warning) 30%, transparent); border-radius:16px; font-size:12px; color:var(--warning);"><i class="fa-solid fa-triangle-exclamation"></i> <span>${escapeHtml(tr('notifyNoEmailWarn'))}</span> <a href="#" id="btnNotifyOpenProfile" style="margin-left:4px; font-weight:600; text-decoration:underline;">${escapeHtml(tr('notifySetEmail'))}</a></span>`;
            document.getElementById('btnNotifyOpenProfile')?.addEventListener('click', (e) => {
                e.preventDefault();
                document.getElementById('btnOpenProfile')?.click();
            });
        }
    }

    const enInput = document.getElementById('notifyPrefEnabled');
    if (enInput) enInput.checked = prefs.enabled !== false;

    // Checkbox tipi di evento
    const activeKinds = new Set(prefs.kinds || []);
    document.querySelectorAll('.notify-pref-kind').forEach(chk => {
        chk.checked = activeKinds.has(chk.value);
    });

    const sevSelect = document.getElementById('notifyPrefMinSeverity');
    if (sevSelect) sevSelect.value = prefs.min_severity || 'low';

    // Gruppi/Tenant consentiti
    const grpContainer = document.getElementById('notifyPrefGroupsContainer');
    if (grpContainer) {
        const userGroups = Array.isArray(globalGroups) && globalGroups.length
            ? globalGroups.map(g => g.name || g.Name || g)
            : [];
        const prefGroups = new Set(prefs.groups || []);
        if (!userGroups.length) {
            grpContainer.innerHTML = `<span style="color:var(--text-muted); font-size:12px;">${escapeHtml(tr('notifyGroupsAll'))}</span>`;
        } else {
            grpContainer.innerHTML = userGroups.map(g => `
                <label style="display:flex; align-items:center; gap:6px; font-size:12px; cursor:pointer;">
                    <input type="checkbox" class="notify-pref-group" value="${escapeHtml(g)}" ${prefGroups.has(g) ? 'checked' : ''} aria-label="${escapeHtml(g)}">
                    <span>${escapeHtml(g)}</span>
                </label>
            `).join('');
        }
    }

    // Modalità
    const mode = prefs.mode || 'immediate';
    const modeRadio = document.querySelector(`input[name="notifyPrefMode"][value="${mode}"]`);
    if (modeRadio) modeRadio.checked = true;
    const digestOpt = document.getElementById('notifyPrefDigestOptions');
    if (digestOpt) digestOpt.style.display = mode === 'digest' ? 'inline-block' : 'none';
    const digestInterval = document.getElementById('notifyPrefDigestInterval');
    if (digestInterval) digestInterval.value = String(prefs.digest_every_min || 60);

    // Orari silenziosi
    const qStart = document.getElementById('notifyPrefQuietStart');
    if (qStart) qStart.value = prefs.quiet_start || '';
    const qEnd = document.getElementById('notifyPrefQuietEnd');
    if (qEnd) qEnd.value = prefs.quiet_end || '';
    const qBypass = document.getElementById('notifyPrefQuietBypass');
    if (qBypass) qBypass.checked = prefs.quiet_bypass_critical !== false;
}

async function _saveNotifyPrefs() {
    const kinds = [];
    document.querySelectorAll('.notify-pref-kind:checked').forEach(chk => kinds.push(chk.value));

    const groups = [];
    document.querySelectorAll('.notify-pref-group:checked').forEach(chk => groups.push(chk.value));

    const modeInput = document.querySelector('input[name="notifyPrefMode"]:checked');
    const mode = modeInput ? modeInput.value : 'immediate';
    const digestInterval = document.getElementById('notifyPrefDigestInterval');
    const digest_every_min = digestInterval ? parseInt(digestInterval.value, 10) : 60;

    const payload = {
        enabled: document.getElementById('notifyPrefEnabled')?.checked ?? true,
        kinds: kinds,
        min_severity: document.getElementById('notifyPrefMinSeverity')?.value || 'low',
        groups: groups,
        mode: mode,
        digest_every_min: digest_every_min,
        quiet_start: document.getElementById('notifyPrefQuietStart')?.value || null,
        quiet_end: document.getElementById('notifyPrefQuietEnd')?.value || null,
        quiet_bypass_critical: document.getElementById('notifyPrefQuietBypass')?.checked ?? true,
    };

    const res = await apiFetch('/api/notifications/prefs', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
    if (res && res.ok) {
        showToast(tr('notifyPrefsSaved'));
    } else {
        const err = await res.json().catch(() => ({}));
        showToast(err.detail || 'Errore salvataggio preferenze', 'error');
    }
}

async function _testNotifyPrefs() {
    const res = await apiFetch('/api/notifications/prefs/test', { method: 'POST' });
    if (res && res.ok) {
        showToast(tr('notifyTestSent'));
    } else {
        const err = await res.json().catch(() => ({}));
        showToast(err.detail || 'Errore invio prova', 'error');
    }
}

// --- REGOLE ADMIN ---

async function _loadNotifyRules() {
    const tbody = document.getElementById('notifyRulesTableBody');
    if (!tbody) return;
    const res = await apiFetch('/api/notifications/rules');
    if (!res || !res.ok) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--danger); padding:16px;">Errore caricamento regole</td></tr>`;
        return;
    }
    _currentNotifyRules = await res.json();
    if (!_currentNotifyRules.length) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-muted); padding:24px;">Nessuna regola configurata.</td></tr>`;
        return;
    }

    const sevBadgeStyle = {
        critical: 'background:var(--sev-critical-wash, rgba(239,68,68,0.12)); color:var(--sev-critical, #ef4444); border:1px solid var(--sev-critical, #ef4444);',
        high: 'background:var(--sev-high-wash, rgba(249,115,22,0.12)); color:var(--sev-high, #f97316); border:1px solid var(--sev-high, #f97316);',
        medium: 'background:var(--sev-medium-wash, rgba(234,179,8,0.12)); color:var(--sev-medium, #eab308); border:1px solid var(--sev-medium, #eab308);',
        low: 'background:var(--sev-low-wash, rgba(16,185,129,0.12)); color:var(--sev-low, #10b981); border:1px solid var(--sev-low, #10b981);',
    };

    tbody.innerHTML = _currentNotifyRules.map(r => {
        const kindsChips = (r.kinds || []).map(k => `
            <span style="font-size:10px; font-family:var(--font-code); background:var(--surface-2); border:1px solid var(--border); padding:2px 6px; margin-right:4px; border-radius:3px;">${escapeHtml(k)}</span>
        `).join('');
        const sevStyle = sevBadgeStyle[r.min_severity] || 'background:var(--surface-2); border:1px solid var(--border);';
        const recipientsList = (r.recipients || []).join(', ');
        const groupsList = (r.groups || []).length ? r.groups.join(', ') : 'Tutti';
        const modeBadge = r.mode === 'digest'
            ? `<span style="font-size:11px; display:inline-flex; align-items:center; gap:4px; color:var(--primary);"><i class="fa-solid fa-inbox"></i> Digest (${r.digest_every_min || 60}m)</span>`
            : `<span style="font-size:11px; display:inline-flex; align-items:center; gap:4px; color:var(--warning);"><i class="fa-solid fa-bolt"></i> Immediato</span>`;

        return `
            <tr>
                <td><b>${escapeHtml(r.name)}</b></td>
                <td>${kindsChips}</td>
                <td><span style="font-size:10px; font-weight:700; border-radius:12px; padding:2px 8px; ${sevStyle}">${escapeHtml(r.min_severity.toUpperCase())}</span></td>
                <td style="font-size:12px;">${escapeHtml(groupsList)}</td>
                <td style="font-family:var(--font-code); font-size:11px; max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(recipientsList)}">${escapeHtml(recipientsList)}</td>
                <td>${modeBadge}</td>
                <td>
                    <label style="cursor:pointer; margin:0;">
                        <input type="checkbox" data-action="toggle-notify-rule" data-id="${r.id}" ${r.enabled ? 'checked' : ''} aria-label="Attiva o disattiva regola ${escapeHtml(r.name)}">
                    </label>
                </td>
                <td style="white-space:nowrap;">
                    <button type="button" class="btn btn-small btn-secondary" data-action="edit-notify-rule" data-id="${r.id}" style="width:auto; margin:0; padding:3px 8px; font-size:11px;" title="Modifica"><i class="fa-solid fa-pen"></i></button>
                    <button type="button" class="btn btn-small btn-secondary" data-action="test-notify-rule" data-id="${r.id}" style="width:auto; margin:0; padding:3px 8px; font-size:11px;" title="Test invio"><i class="fa-solid fa-paper-plane"></i></button>
                    <button type="button" class="btn btn-small btn-secondary" data-action="delete-notify-rule" data-id="${r.id}" style="width:auto; margin:0; padding:3px 8px; font-size:11px; color:var(--danger);" title="Elimina"><i class="fa-solid fa-trash"></i></button>
                </td>
            </tr>
        `;
    }).join('');
}

function _openNewRuleModal() {
    document.getElementById('notifyRuleEditId').value = '';
    document.getElementById('modalNotifyRuleTitle').innerHTML = `<i class="fa-solid fa-bell" style="color:var(--primary);"></i> ${escapeHtml(tr('notifyBtnNewRule'))}`;
    document.getElementById('notifyRuleName').value = '';
    document.getElementById('notifyRuleEnabled').checked = true;
    document.getElementById('notifyRuleRecipients').value = '';
    document.querySelectorAll('.notify-rule-kind').forEach(chk => chk.checked = true);
    document.getElementById('notifyRuleMinSeverity').value = 'low';
    document.getElementById('notifyRuleMode').value = 'immediate';
    document.getElementById('notifyRuleQuietStart').value = '';
    document.getElementById('notifyRuleQuietEnd').value = '';
    document.getElementById('notifyRuleQuietBypass').checked = true;
    openModal('modalNotifyRule');
}

function _openEditRuleModal(ruleId) {
    const r = _currentNotifyRules.find(x => x.id === ruleId);
    if (!r) return;
    document.getElementById('notifyRuleEditId').value = String(r.id);
    document.getElementById('modalNotifyRuleTitle').innerHTML = `<i class="fa-solid fa-bell" style="color:var(--primary);"></i> Modifica: ${escapeHtml(r.name)}`;
    document.getElementById('notifyRuleName').value = r.name || '';
    document.getElementById('notifyRuleEnabled').checked = r.enabled !== false;
    document.getElementById('notifyRuleRecipients').value = (r.recipients || []).join(', ');
    const activeKinds = new Set(r.kinds || []);
    document.querySelectorAll('.notify-rule-kind').forEach(chk => {
        chk.checked = activeKinds.has(chk.value);
    });
    document.getElementById('notifyRuleMinSeverity').value = r.min_severity || 'low';
    document.getElementById('notifyRuleMode').value = r.mode || 'immediate';
    document.getElementById('notifyRuleQuietStart').value = r.quiet_start || '';
    document.getElementById('notifyRuleQuietEnd').value = r.quiet_end || '';
    document.getElementById('notifyRuleQuietBypass').checked = r.quiet_bypass_critical !== false;
    openModal('modalNotifyRule');
}

async function _submitNotifyRule() {
    const editId = document.getElementById('notifyRuleEditId').value;
    const name = document.getElementById('notifyRuleName')?.value?.trim();
    if (!name) {
        showToast('Inserisci un nome per la regola', 'warning');
        return;
    }
    const recipientsRaw = document.getElementById('notifyRuleRecipients')?.value?.trim() || '';
    const recipients = recipientsRaw.split(/[\s,;]+/).map(x => x.trim()).filter(x => x.includes('@'));
    if (!recipients.length) {
        showToast('Inserisci almeno un destinatario valido', 'warning');
        return;
    }

    const kinds = [];
    document.querySelectorAll('.notify-rule-kind:checked').forEach(chk => kinds.push(chk.value));

    const payload = {
        name: name,
        enabled: document.getElementById('notifyRuleEnabled')?.checked ?? true,
        recipients: recipients,
        kinds: kinds,
        min_severity: document.getElementById('notifyRuleMinSeverity')?.value || 'low',
        groups: [],
        mode: document.getElementById('notifyRuleMode')?.value || 'immediate',
        digest_every_min: 60,
        quiet_start: document.getElementById('notifyRuleQuietStart')?.value || null,
        quiet_end: document.getElementById('notifyRuleQuietEnd')?.value || null,
        quiet_bypass_critical: document.getElementById('notifyRuleQuietBypass')?.checked ?? true,
    };

    const isEdit = !!editId;
    const url = isEdit ? `/api/notifications/rules/${editId}` : '/api/notifications/rules';
    const method = isEdit ? 'PUT' : 'POST';

    const res = await apiFetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });

    if (res && res.ok) {
        closeModal('modalNotifyRule');
        showToast(tr('notifyRuleSaved'));
        _loadNotifyRules();
    } else {
        const err = await res.json().catch(() => ({}));
        showToast(err.detail || 'Errore salvataggio regola', 'error');
    }
}

async function _toggleRuleEnabled(ruleId, enabled) {
    const r = _currentNotifyRules.find(x => x.id === ruleId);
    if (!r) return;
    const payload = { ...r, enabled: enabled };
    await apiFetch(`/api/notifications/rules/${ruleId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
    });
}

async function _testNotifyRule(ruleId) {
    const res = await apiFetch(`/api/notifications/rules/${ruleId}/test`, { method: 'POST' });
    if (res && res.ok) {
        showToast(tr('notifyRuleTestSent'));
    } else {
        const err = await res.json().catch(() => ({}));
        showToast(err.detail || 'Errore test regola', 'error');
    }
}

async function _deleteNotifyRule(ruleId) {
    if (!confirm(tr('notifyConfirmDeleteRule'))) return;
    const res = await apiFetch(`/api/notifications/rules/${ruleId}`, { method: 'DELETE' });
    if (res && res.ok) {
        showToast(tr('notifyRuleDeleted'));
        _loadNotifyRules();
    } else {
        const err = await res.json().catch(() => ({}));
        showToast(err.detail || 'Errore eliminazione regola', 'error');
    }
}

// --- STORICO INVIO ---

async function _loadNotifyLog() {
    const tbody = document.getElementById('notifyLogTableBody');
    if (!tbody) return;
    const statusFilter = document.getElementById('notifyLogStatusFilter')?.value;
    let url = '/api/notifications/log?limit=100';
    if (statusFilter) url += `&status=${encodeURIComponent(statusFilter)}`;

    const res = await apiFetch(url);
    if (!res || !res.ok) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--danger); padding:16px;">Errore caricamento storico</td></tr>`;
        return;
    }
    const logs = await res.json();
    if (!logs.length) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted); padding:24px;">Nessun evento registrato.</td></tr>`;
        return;
    }

    tbody.innerHTML = logs.map(l => {
        const tsDate = new Date(l.ts * 1000);
        const tsStr = tsDate.toLocaleString();
        let statusBadge = '';
        if (l.status === 'sent') {
            statusBadge = `<span style="display:inline-flex; align-items:center; gap:5px; font-size:11px; padding:2px 8px; border-radius:12px; background:var(--lamp-up-wash, rgba(16,185,129,0.12)); color:var(--lamp-up-ink, #059669); font-weight:600;"><i class="fa-solid fa-circle-check" style="font-size:10px;"></i> ${escapeHtml(tr('notifyLogSent'))}</span>`;
        } else if (l.status === 'failed') {
            statusBadge = `<span style="display:inline-flex; align-items:center; gap:5px; font-size:11px; padding:2px 8px; border-radius:12px; background:var(--lamp-fault-wash, rgba(239,68,68,0.12)); color:var(--lamp-fault-ink, #dc2626); font-weight:600;" title="${escapeHtml(l.error || '')}"><i class="fa-solid fa-circle-xmark" style="font-size:10px;"></i> ${escapeHtml(tr('notifyLogFailed'))}</span>`;
        } else {
            statusBadge = `<span style="display:inline-flex; align-items:center; gap:5px; font-size:11px; padding:2px 8px; border-radius:12px; background:var(--lamp-warn-wash, rgba(245,158,11,0.12)); color:var(--lamp-warn-ink, #d97706); font-weight:600;" title="Soppresso anti-flood (finestra 30 min)"><i class="fa-solid fa-shield-halved" style="font-size:10px;"></i> ${escapeHtml(tr('notifyLogSuppressed'))}</span>`;
        }
        const kindBadge = `<span style="font-size:10px; font-family:var(--font-code); background:var(--surface-2); border:1px solid var(--border); padding:2px 6px; border-radius:3px; color:var(--text);">${escapeHtml(l.kind)}</span>`;

        return `
            <tr>
                <td style="font-size:11px; color:var(--text-muted); white-space:nowrap;" title="${escapeHtml(tsDate.toISOString())}">${escapeHtml(tsStr)}</td>
                <td style="font-size:11px; font-family:var(--font-code); color:var(--text-soft);">${escapeHtml(l.target)}</td>
                <td style="font-size:12px;">${escapeHtml(l.recipient || '—')}</td>
                <td>${kindBadge}</td>
                <td style="font-size:12px; max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(l.title)}">${escapeHtml(l.title)}</td>
                <td>${statusBadge}</td>
                <td style="font-size:11px; color:var(--text-muted); max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(l.error || '')}">${escapeHtml(l.error || '—')}</td>
            </tr>
        `;
    }).join('');
}

window.loadNotificationsTab = loadNotificationsTab;
