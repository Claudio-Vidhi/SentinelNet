// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// MCP bridge consent page (templates/mcp_authorize.html). Loaded alone with
// i18n.js, not with core.js: every top-level name carries the mcpc prefix
// because tsc checks all of static/js as one shared global scope.
//
// The URL carries what the bridge sent: port/state/challenge for the PKCE
// loopback redirect, client/host to show, exp for when it stops listening.
// Approving posts them to /api/mcp/authorize and follows the redirect to
// 127.0.0.1; cancelling sends error=access_denied there, so the bridge stops
// waiting at once. The bridge then sends the browser back with ?result=.

const mcpcQuery = new URLSearchParams(window.location.search);
const mcpcReq = {
    port: Number(mcpcQuery.get('port')),
    state: mcpcQuery.get('state') || '',
    challenge: mcpcQuery.get('challenge') || '',
    client: mcpcQuery.get('client') || '',
    host: mcpcQuery.get('host') || '',
    exp: Number(mcpcQuery.get('exp')) || 0,
};
const MCPC_CSRF = { 'X-Requested-With': 'SentinelNet' };
let mcpcInfo = null;
let mcpcTimer = 0;

function mcpcEl(id) { return document.getElementById(id); }

function mcpcClientName() { return mcpcReq.client || tr('mcpcClientFallback'); }

function mcpcTranslate() {
    document.documentElement.lang = currentLang;
    document.title = tr('mcpcPageTitle');
    document.querySelectorAll('[data-i18n]').forEach(el => {
        el.textContent = tr(el.getAttribute('data-i18n'));
    });
}

// One card at a time; the lamp on the bus follows the state.
function mcpcShow(id, lamp) {
    ['mcpcLoading', 'mcpcLogin', 'mcpcAsk', 'mcpcResult'].forEach(s => { mcpcEl(s).hidden = s !== id; });
    mcpcEl('mcpcLamp').dataset.state = lamp || 'idle';
}

function mcpcResult(kind, titleKey, textKey) {
    clearInterval(mcpcTimer);
    // The question in the title is answered: the card carries the outcome.
    mcpcEl('mcpcTitle').hidden = true;
    const icon = { done: 'fa-check', denied: 'fa-xmark', expired: 'fa-clock', invalid: 'fa-question', failed: 'fa-triangle-exclamation' }[kind];
    mcpcEl('mcpcResultIcon').innerHTML = `<i class="fa-solid ${icon}"></i>`;
    mcpcEl('mcpcResultIcon').dataset.kind = kind;
    mcpcEl('mcpcResultTitle').textContent = tr(titleKey);
    mcpcEl('mcpcResultText').textContent = textKey ? tr(textKey, { client: mcpcClientName() }) : '';
    mcpcShow('mcpcResult', kind === 'done' ? 'up' : kind === 'denied' || kind === 'expired' ? 'idle' : 'fault');
}

function mcpcValid() {
    return mcpcReq.port >= 1024 && mcpcReq.port <= 65535 && mcpcReq.state.length >= 8
        && /^[A-Za-z0-9_-]{43}$/.test(mcpcReq.challenge);
}

function mcpcSecondsLeft() { return mcpcReq.exp - Math.floor(Date.now() / 1000); }

function mcpcTick() {
    const left = mcpcSecondsLeft();
    if (left <= 0) { mcpcResult('expired', 'mcpcExpiredTitle', 'mcpcExpiredText'); return; }
    mcpcEl('mcpcExpires').textContent = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
}

function mcpcRenderPerms() {
    const ro = !mcpcInfo.can_choose || mcpcEl('mcpcReadOnly').checked;
    const ul = mcpcEl('mcpcPerms');
    ul.textContent = '';
    let actions = false;
    for (const p of mcpcInfo.permissions) {
        const on = ro ? p.read_only : p.full;
        if (on && p.key === 'actions') actions = true;
        const li = document.createElement('li');
        li.dataset.on = on ? '1' : '0';
        li.innerHTML = `<i class="fa-solid ${on ? 'fa-check' : 'fa-minus'}" aria-hidden="true"></i><span></span>`;
        const label = { read: tr('mcpcPerm_read'), config: tr('mcpcPerm_config'), actions: tr('mcpcPerm_actions') }[p.key] || p.key;
        li.querySelector('span').textContent = label + (on ? '' : ' — ' + tr('mcpcPermOff'));
        ul.appendChild(li);
    }
    mcpcEl('mcpcWarn').hidden = !actions;
    mcpcEl('mcpcLamp').dataset.state = actions ? 'warn' : 'idle';
}

async function mcpcLoadConsent() {
    const res = await fetch('/api/mcp/authorize/info');
    if (res.status === 401) { mcpcShowLogin(); return; }
    if (!res.ok) { mcpcResult('failed', 'mcpcFailedTitle', null); return; }
    mcpcInfo = await res.json();
    mcpcEl('mcpcUsername').textContent = mcpcInfo.username;
    const roleKey = { viewer: 'roleViewer', operator: 'roleOperator', admin: 'roleAdmin', super_admin: 'roleSuperAdmin' }[mcpcInfo.role];
    mcpcEl('mcpcRole').textContent = roleKey ? tr(roleKey) : mcpcInfo.role;
    mcpcEl('mcpcRoBox').hidden = !mcpcInfo.can_choose;
    mcpcEl('mcpcClient').textContent = mcpcClientName();
    mcpcEl('mcpcHost').textContent = mcpcReq.host || '—';
    mcpcEl('mcpcRedirectTo').textContent = `http://127.0.0.1:${mcpcReq.port}`;
    mcpcShow('mcpcAsk');
    mcpcRenderPerms();
    mcpcTick();
    mcpcTimer = setInterval(mcpcTick, 1000);
    mcpcEl('btnMcpcApprove').focus();
}

async function mcpcShowLogin() {
    mcpcShow('mcpcLogin');
    mcpcEl('mcpcUser').focus();
    try {
        const res = await fetch('/api/auth/sso/config');
        const cfg = res.ok ? await res.json() : {};
        if (cfg.enabled) {
            // The IdP sends the browser back here, not to the dashboard.
            const back = window.location.pathname + window.location.search;
            mcpcEl('mcpcSsoLink').setAttribute('href', '/api/auth/sso/login?next=' + encodeURIComponent(back));
            if (cfg.provider_name) mcpcEl('mcpcSsoText').textContent = cfg.provider_name;
            mcpcEl('mcpcSsoBox').hidden = false;
        }
    } catch (e) { /* no SSO button: local sign-in still works */ }
}

mcpcEl('mcpcLoginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = mcpcEl('mcpcLoginError');
    err.hidden = true;
    const res = await fetch('/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: mcpcEl('mcpcUser').value.trim(), password: mcpcEl('mcpcPass').value }),
    }).catch(() => null);
    const data = res ? await res.json().catch(() => ({})) : {};
    mcpcEl('mcpcPass').value = '';
    if (!res || !res.ok) {
        err.textContent = data.detail || tr('mcpcLoginFailed');
        err.hidden = false;
        return;
    }
    if (data.must_change_password) {
        err.textContent = tr('mcpcMustChangePw');
        err.hidden = false;
        return;
    }
    mcpcShow('mcpcLoading');
    mcpcLoadConsent();
});

mcpcEl('btnMcpcSwitch').addEventListener('click', async () => {
    clearInterval(mcpcTimer);
    await fetch('/api/auth/logout', { method: 'POST', headers: MCPC_CSRF }).catch(() => null);
    mcpcShowLogin();
});

mcpcEl('mcpcReadOnly').addEventListener('change', mcpcRenderPerms);

mcpcEl('btnMcpcApprove').addEventListener('click', async () => {
    if (mcpcSecondsLeft() <= 0) { mcpcTick(); return; }
    const btn = mcpcEl('btnMcpcApprove');
    btn.disabled = true;
    const res = await fetch('/api/mcp/authorize', {
        method: 'POST', headers: { ...MCPC_CSRF, 'Content-Type': 'application/json' },
        body: JSON.stringify({
            port: mcpcReq.port, state: mcpcReq.state, challenge: mcpcReq.challenge,
            client: mcpcReq.client, host: mcpcReq.host,
            read_only: !mcpcInfo.can_choose || mcpcEl('mcpcReadOnly').checked,
        }),
    }).catch(() => null);
    const data = res ? await res.json().catch(() => ({})) : {};
    if (res && res.ok && data.redirect) {
        window.location.assign(data.redirect);
        return;
    }
    btn.disabled = false;
    const err = mcpcEl('mcpcAskError');
    err.textContent = (typeof data.detail === 'string' && data.detail) || tr('mcpcFailedTitle');
    err.hidden = false;
});

mcpcEl('btnMcpcDeny').addEventListener('click', () => {
    clearInterval(mcpcTimer);
    if (mcpcSecondsLeft() <= 0) { mcpcResult('denied', 'mcpcDeniedTitle', 'mcpcDeniedText'); return; }
    // Tell the bridge, which answers by sending the browser back with
    // ?result=denied.
    const q = new URLSearchParams({ error: 'access_denied', state: mcpcReq.state });
    window.location.assign(`http://127.0.0.1:${mcpcReq.port}/callback?${q}`);
});

function mcpcStart() {
    mcpcTranslate();
    mcpcEl('mcpcTitle').textContent = tr('mcpcTitle', { client: mcpcClientName() });
    const result = mcpcQuery.get('result');
    // Outcome pages come from the bridge's redirect: drop the query so a
    // reload or the history never replays the request.
    if (result) window.history.replaceState({}, document.title, window.location.pathname);
    if (result === 'done') { mcpcResult('done', 'mcpcDoneTitle', 'mcpcDoneText'); return; }
    if (result === 'denied') { mcpcResult('denied', 'mcpcDeniedTitle', 'mcpcDeniedText'); return; }
    if (!mcpcValid()) { mcpcResult('invalid', 'mcpcInvalidTitle', 'mcpcInvalidText'); return; }
    if (mcpcSecondsLeft() <= 0) { mcpcResult('expired', 'mcpcExpiredTitle', 'mcpcExpiredText'); return; }
    mcpcLoadConsent();
}

mcpcStart();
