// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// "My profile": the signed-in user's own account. Summary of what they can
// see, password change, verified recovery address and "sign out everywhere".
// Only /api/profile and /api/auth/* are called: nothing here needs admin.

// Shared with settings.js (users table): an ISO timestamp, or "never".
function formatLastLogin(iso) {
    if (!iso) return tr('setNever');
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString(tr('homeEnGb'));
}

function profileMsg(text, ok) {
    const el = document.getElementById('profileMsg');
    if (!el) return;
    el.textContent = text;
    el.style.color = ok ? 'var(--success)' : 'var(--danger)';
    el.style.display = 'block';
}

function profileField(id) {
    const el = /** @type {HTMLInputElement|null} */ (document.getElementById(id));
    return el ? el.value.trim() : '';
}

function clearProfileFields(ids) {
    ids.forEach(id => {
        const el = /** @type {HTMLInputElement|null} */ (document.getElementById(id));
        if (el) el.value = '';
    });
}

async function openProfile() {
    const res = await apiFetch('/api/profile');
    if (!res || !res.ok) return;
    const p = await res.json();
    const all = tr('profAll');
    const tabs = normalizeAllowedTabs(p.allowed_tabs);
    const unrestricted = isAdminRole(p.role);
    const set = (id, text) => { const el = document.getElementById(id); if (el) el.textContent = text; };
    set('profUsername', p.username);
    set('profRole', roleLabel(p.role));
    set('profTenants', unrestricted || !p.groups.length ? all : p.groups.join(', '));
    set('profTabs', unrestricted || !tabs.length ? all : `${tabs.length} ${tr('setTabS')}`);
    set('profLastLogin', formatLastLogin(p.last_login));
    set('profEmailValue', p.email || tr('setNone'));
    clearProfileFields(['profCurPass', 'profNewPass', 'profConfirmPass', 'profNewEmail', 'profEmailPass']);
    const msg = document.getElementById('profileMsg');
    if (msg) msg.style.display = 'none';
    loadProfileMcpGrants();
    openModal('profileModal');
}

async function loadProfileMcpGrants() {
    const box = document.getElementById('profMcpList');
    if (!box) return;
    const res = await apiFetch('/api/mcp/my-grants');
    if (!res || !res.ok) return;
    const grants = (await res.json()).grants || [];
    const when = (ts) => ts ? new Date(ts * 1000).toLocaleString() : tr('mcpGrantNever');
    box.innerHTML = grants.length ? grants.map(g => `
        <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; font-size:12.5px; padding:8px 10px; border:1px solid var(--border); background:var(--surface);">
          <span>${escapeHtml(g.label || '')} · ${escapeHtml(tr(g.read_only ? 'mcpGrantReadOnly' : 'mcpGrantFullRole'))}
            <span style="display:block; color:var(--text-muted); font-size:11px;">${escapeHtml(tr('mcpGrantLastUsed'))} ${escapeHtml(when(g.last_used))}</span>
          </span>
          <button type="button" class="btn btn-secondary btn-small" style="width:auto; margin:0;" data-action="revoke-my-mcp-grant" data-id="${escapeHtml(g.id)}">${escapeHtml(tr('mcpGrantRevoke'))}</button>
        </div>`).join('')
        : `<span style="color:var(--text-muted); font-size:12px;">${escapeHtml(tr('profMcpNone'))}</span>`;
}

async function revokeProfileMcpGrant(id) {
    if (!confirm(tr('mcpGrantRevokeConfirm'))) return;
    const res = await apiFetch('/api/mcp/my-grants/revoke', { method: 'POST', body: JSON.stringify({ id }) });
    if (!res || !res.ok) profileMsg(tr('mcpGrantRevokeFailed'), false);
    loadProfileMcpGrants();
}

async function profileChangePassword() {
    const np = profileField('profNewPass');
    if (np.length < 8) { profileMsg(tr('alertPassTooShort'), false); return; }
    if (np !== profileField('profConfirmPass')) { profileMsg(tr('alertPassMismatch'), false); return; }
    const res = await apiFetch('/api/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ old_password: profileField('profCurPass'), new_password: np }),
    });
    if (!res) return;
    if (res.ok) {
        clearProfileFields(['profCurPass', 'profNewPass', 'profConfirmPass']);
        profileMsg(tr('profPwChanged'), true);
    } else {
        const e = await res.json().catch(() => ({}));
        profileMsg(e.detail || tr('alertPassChangeErr'), false);
    }
}

async function profileChangeEmail() {
    const email = profileField('profNewEmail');
    const res = await apiFetch('/api/profile/email', {
        method: 'POST',
        body: JSON.stringify({ email, current_password: profileField('profEmailPass') }),
    });
    if (!res) return;
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { profileMsg(d.detail || tr('setUpdateFailed'), false); return; }
    clearProfileFields(['profEmailPass', 'profNewEmail']);
    if (d.verification_sent) {
        profileMsg(tr('profEmailSent', { email }), true);
    } else {
        const cur = document.getElementById('profEmailValue');
        if (cur) cur.textContent = tr('setNone');
        profileMsg(tr('profEmailCleared'), true);
    }
}

async function profileLogoutAll() {
    if (!confirm(tr('profLogoutAllConfirm'))) return;
    const res = await apiFetch('/api/auth/logout-all', { method: 'POST' });
    closeModal('profileModal');
    if (res && res.ok) logout();
}

document.getElementById('btnOpenProfile')?.addEventListener('click', (e) => {
    e.preventDefault();
    openProfile();
});
document.getElementById('btnCloseProfile')?.addEventListener('click', () => closeModal('profileModal'));
document.getElementById('btnProfChangePw')?.addEventListener('click', profileChangePassword);
document.getElementById('btnProfEmail')?.addEventListener('click', profileChangeEmail);
document.getElementById('btnProfLogoutAll')?.addEventListener('click', profileLogoutAll);
document.getElementById('profMcpList')?.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="revoke-my-mcp-grant"]');
    if (btn) revokeProfileMcpGrant(btn.dataset.id);
});
