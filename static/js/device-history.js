// Copyright 2026 Claudio Vidhi
// SPDX-License-Identifier: AGPL-3.0-only
// static/js/device-history.js
// tab-device-history: the inventory's chronology. One fetch of every event in
// the caller's scope (/api/device-history), then tenant, period, kind and
// search are filtered here, so switching a filter never waits on the server.

let dhEvents = [];
let dhKind = 'all';
let dhLoaded = false;

// Inventory fields in the order an engineer reads a device, with their labels.
const DH_FIELDS = [
    ['Hostname', 'dhFHostname'], ['IP', 'dhFIp'], ['Vendor', 'dhFVendor'],
    ['Profile', 'dhFProfile'], ['Group', 'dhFTenant'], ['Probe', 'dhFProbe'],
    ['Username', 'dhFUsername'], ['Transports', 'dhFTransports'],
    ['SSH Port', 'dhFSshPort'], ['SNMP Disabled', 'dhFSnmpDisabled'],
    ['Password', 'dhFPassword'], ['Enable Secret', 'dhFEnable'],
    ['SNMP Community', 'dhFCommunity'],
];
const DH_SECRETS = new Set(['Password', 'Enable Secret', 'SNMP Community']);
// One import or agent sync writes many rows with one timestamp: from this
// many events of the same kind it reads as one batch, opened on demand.
const DH_BATCH_MIN = 3;

function dhFieldLabel(key) {
    const f = DH_FIELDS.find(([k]) => k === key);
    return f ? tr(f[1]) : key;
}

function dhValue(key, v) {
    if (DH_SECRETS.has(key)) return v ? tr('dhSecretSet') : '—';
    if (key === 'SNMP Disabled') return v ? tr('dhYes') : tr('dhNo');
    if (key === 'Transports' && v) {
        try {
            return Object.entries(JSON.parse(v)).map(([p, port]) => `${p}:${port}`).join(' · ');
        } catch (e) { return v; }
    }
    return v || '—';
}

function dhDayKey(ts) {
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function dhDayLabel(ts) {
    const now = new Date();
    const yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    if (dhDayKey(ts) === dhDayKey(now.getTime() / 1000)) return tr('dhToday');
    if (dhDayKey(ts) === dhDayKey(yesterday.getTime() / 1000)) return tr('dhYesterday');
    return new Date(ts * 1000).toLocaleDateString(currentLang,
        { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
}

function dhTime(ts) {
    return new Date(ts * 1000).toLocaleTimeString(currentLang, { hour: '2-digit', minute: '2-digit' });
}

// How long a decommissioned device stayed: back to the entry that added it.
// dhEvents is newest first, so that entry is the first 'added' after this one.
function dhServiceDays(ev) {
    const i = dhEvents.indexOf(ev);
    const ip = ev.device?.IP;
    const added = dhEvents.slice(i + 1).find(e => e.event === 'added'
        && e.tenant === ev.tenant && e.device?.IP === ip);
    return added ? Math.max(0, Math.round((ev.ts - added.ts) / 86400)) : null;
}

function dhFiltered() {
    const tenant = document.getElementById('dhTenant')?.value || 'all';
    const days = parseInt(document.getElementById('dhPeriod')?.value || '0', 10);
    const term = (document.getElementById('dhSearch')?.value || '').trim().toLowerCase();
    const since = days ? Date.now() / 1000 - days * 86400 : 0;
    return dhEvents.filter(e => {
        if (tenant !== 'all' && e.tenant !== tenant) return false;
        if (e.ts < since) return false;
        if (!term) return true;
        const d = e.device || {};
        return [d.IP, d.Hostname, d.Vendor, e.actor].some(x => (x || '').toLowerCase().includes(term));
    });
}

function dhVerb(kind, batch) {
    const keys = batch
        ? { added: 'dhBatchAdded', removed: 'dhBatchRemoved', changed: 'dhBatchChanged' }
        : { added: 'dhVerbAdded', removed: 'dhVerbRemoved', changed: 'dhVerbChanged' };
    return keys[kind];
}

function dhMeta(e, extra) {
    const parts = [];
    if (e.device?.Hostname) parts.push(`<span class="dh-ip">${escapeHtml(e.device.IP)}</span>`);
    if (e.source === 'baseline') {
        parts.push(`<span>${escapeHtml(tr('dhBaselineNote'))}</span>`);
    } else {
        const who = e.actor === 'system' ? tr('dhSystem') : e.actor;
        parts.push(`<span>${escapeHtml(tr('dhBy'))} <span class="dh-actor">${escapeHtml(who)}</span></span>`);
    }
    if (extra) parts.push(`<span>${extra}</span>`);
    // Rebuilt from audit.log: says so, because it knows less than a live entry.
    if (e.source === 'audit') parts.push(`<span class="dh-source">${escapeHtml(tr('dhFromAudit'))}</span>`);
    return `<span class="dh-meta">${parts.join('<span class="dh-sep" aria-hidden="true"></span>')}</span>`;
}

function dhChangeList(e) {
    return Object.entries(e.changes || {}).map(([k, [a, b]]) => (DH_SECRETS.has(k) && a && b) ? `
        <li><span class="dh-key">${escapeHtml(dhFieldLabel(k))}</span>
            <span class="dh-to">${escapeHtml(tr('dhSecretChanged'))}</span></li>` : `
        <li><span class="dh-key">${escapeHtml(dhFieldLabel(k))}</span>
            <span class="dh-from">${escapeHtml(dhValue(k, a))}</span>
            <i class="fa-solid fa-arrow-right-long" aria-hidden="true"></i>
            <span class="dh-to">${escapeHtml(dhValue(k, b))}</span></li>`).join('');
}

// A rebuilt entry only has what the audit line recorded: show those fields,
// not a row of dashes that would read as "empty" rather than "not recorded".
function dhSnapshot(d, rebuilt) {
    return DH_FIELDS.filter(([k]) => !rebuilt || d[k]).map(([k, label]) =>
        `<div><dt>${escapeHtml(tr(label))}</dt><dd>${escapeHtml(dhValue(k, d[k]))}</dd></div>`).join('');
}

function dhSummary(e, title, meta) {
    return `<summary>
        <time class="dh-time" datetime="${new Date(e.ts * 1000).toISOString()}">${escapeHtml(dhTime(e.ts))}</time>
        <i class="dh-node" data-ev="${e.event}" aria-hidden="true"></i>
        <span class="dh-line"><span class="dh-title">${title}</span>${meta}</span>
        <i class="fa-solid fa-chevron-down dh-caret" aria-hidden="true"></i>
      </summary>`;
}

function dhSingle(e) {
    const d = e.device || {};
    let extra = '';
    if (e.event === 'changed') {
        extra = escapeHtml(Object.keys(e.changes || {}).map(dhFieldLabel).join(', '));
    } else if (e.event === 'removed') {
        const days = dhServiceDays(e);
        if (days !== null) extra = escapeHtml(tr('dhInService', { n: days }));
    }
    const rebuilt = !!e.source;
    const verb = e.source === 'baseline' ? 'dhVerbBaseline' : dhVerb(e.event);
    const title = `<b>${escapeHtml(d.Hostname || d.IP)}</b> <span class="dh-verb">${escapeHtml(tr(verb))}</span> <span class="dh-tenant">${escapeHtml(e.tenant)}</span>`;
    const changeItems = dhChangeList(e);
    const changes = e.event === 'changed'
        ? `<h4 class="dh-h">${escapeHtml(tr('dhChanges'))}</h4>${changeItems
            ? `<ul class="dh-changes">${changeItems}</ul>`
            : `<p class="dh-note">${escapeHtml(tr('dhChangeUnknown'))}</p>`}` : '';
    return `<details class="dh-ev" data-ev="${e.event}">
      ${dhSummary(e, title, dhMeta(e, extra))}
      <div class="dh-body">
        ${changes}
        <h4 class="dh-h">${escapeHtml(tr(e.event === 'removed' ? 'dhSnapLast' : 'dhSnapAt'))}</h4>
        <dl class="dh-snap">${dhSnapshot(d, rebuilt)}</dl>
        <div class="dh-config">
          <button type="button" class="btn btn-secondary btn-small" data-dh-config="${escapeHtml(e.id)}"><i class="fa-solid fa-file-lines" aria-hidden="true"></i> ${escapeHtml(tr('dhViewConfig'))}</button>
          <pre class="dh-config-text" hidden></pre>
        </div>
      </div>
    </details>`;
}

function dhBatch(group) {
    const e = group[0];
    const tenants = [...new Set(group.map(x => x.tenant))];
    const where = tenants.length === 1
        ? `<span class="dh-tenant">${escapeHtml(tenants[0])}</span>`
        : `<span class="dh-tenant">${escapeHtml(tr('dhTenantsN', { n: tenants.length }))}</span>`;
    const verb = e.source === 'baseline' ? 'dhBatchBaseline' : dhVerb(e.event, true);
    const title = `<b>${escapeHtml(tr(verb, { n: group.length }))}</b> ${where}`;
    const rows = group.map(x => {
        const d = x.device || {};
        return `<li><span class="dh-name">${escapeHtml(d.Hostname || d.IP)}</span><span class="dh-ip">${escapeHtml(d.IP)}</span><span class="dh-vendor">${escapeHtml(d.Vendor || '')}</span><span class="dh-tenant">${escapeHtml(x.tenant)}</span></li>`;
    }).join('');
    return `<details class="dh-ev dh-batch" data-ev="${e.event}">
      ${dhSummary(e, title, dhMeta({ ...e, device: {} }, e.source === 'baseline' ? '' : escapeHtml(tr('dhOneWrite'))))}
      <div class="dh-body"><ul class="dh-batch-list">${rows}</ul></div>
    </details>`;
}

function dhEmpty(msg) {
    return `<p class="dh-empty">${escapeHtml(msg)}</p>`;
}

function renderDeviceHistory() {
    const box = document.getElementById('dhTimeline');
    if (!box || !dhLoaded) return;
    const inScope = dhFiltered();
    const count = k => inScope.filter(e => e.event === k).length;
    const added = count('added');
    const removed = count('removed');
    const setText = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = String(v); };
    setText('dhCountAll', inScope.length);
    setText('dhCountAdded', added);
    setText('dhCountRemoved', removed);
    setText('dhCountChanged', count('changed'));
    const net = added - removed;
    setText('dhNet', net > 0 ? `+${net}` : net < 0 ? `−${-net}` : '0');

    const shown = dhKind === 'all' ? inScope : inScope.filter(e => e.event === dhKind);
    if (!dhEvents.length) { box.innerHTML = dhEmpty(tr('dhEmptyAll')); return; }
    if (!shown.length) { box.innerHTML = dhEmpty(tr('dhEmptyFilter')); return; }

    let html = '';
    let day = null;
    for (let i = 0; i < shown.length;) {
        const e = shown[i];
        if (dhDayKey(e.ts) !== day) {
            if (day !== null) html += '</ol></section>';
            day = dhDayKey(e.ts);
            const n = shown.filter(x => dhDayKey(x.ts) === day).length;
            html += `<section class="dh-day"><h3 class="dh-day-head"><span>${escapeHtml(dhDayLabel(e.ts))}</span><span class="dh-day-count">${escapeHtml(tr(n === 1 ? 'dhEvents1' : 'dhEventsN', { n }))}</span></h3><ol class="dh-list">`;
        }
        // One write (same stamp, kind and author) collapses into one row.
        let j = i + 1;
        while (j < shown.length && shown[j].ts === e.ts && shown[j].event === e.event
               && shown[j].actor === e.actor) j++;
        const group = shown.slice(i, j);
        html += group.length >= DH_BATCH_MIN
            ? `<li>${dhBatch(group)}</li>`
            : group.map(x => `<li>${dhSingle(x)}</li>`).join('');
        i = j;
    }
    box.innerHTML = html + '</ol></section>';
}

function dhFillTenants() {
    const sel = /** @type {HTMLSelectElement|null} */ (document.getElementById('dhTenant'));
    if (!sel) return;
    // A decommissioned device's tenant may no longer exist; it still has a
    // history, so the list is the union of both.
    const names = [...new Set([...Object.keys(globalGroups || {}), ...dhEvents.map(e => e.tenant)])].sort();
    const inv = /** @type {HTMLSelectElement|null} */ (document.getElementById('filterGroupSelect'));
    const keep = sel.value || inv?.value || 'all';
    sel.innerHTML = `<option value="all">${escapeHtml(tr('dhAllTenants'))}</option>`
        + names.map(n => `<option value="${escapeHtml(n)}">${escapeHtml(orgLabel(n))}</option>`).join('');
    sel.value = names.includes(keep) ? keep : 'all';
}

async function loadDeviceHistoryTab() {
    const box = document.getElementById('dhTimeline');
    if (!box) return;
    if (!dhLoaded) {
        box.innerHTML = Array.from({ length: 5 }, () =>
            '<div class="dh-sk" aria-hidden="true"><span class="sk" style="width:40px"></span><span class="sk dh-sk-node"></span><span class="sk" style="width:46%"></span><span class="sk" style="width:18%"></span></div>').join('');
    }
    const res = await apiFetch('/api/device-history');
    if (!res || !res.ok) {
        dhLoaded = false;
        box.innerHTML = dhEmpty(tr(res && res.status === 403 ? 'dhForbidden' : 'dhLoadError'));
        return;
    }
    dhEvents = (await res.json()).events || [];
    dhLoaded = true;
    dhFillTenants();
    renderDeviceHistory();
}

async function dhShowConfig(btn) {
    const pre = btn.parentElement.querySelector('.dh-config-text');
    if (!pre) return;
    if (!pre.hidden) { pre.hidden = true; return; }
    btn.disabled = true;
    const res = await apiFetch(`/api/device-history/${encodeURIComponent(btn.dataset.dhConfig)}/config`);
    btn.disabled = false;
    pre.hidden = false;
    if (!res || !res.ok) {
        pre.textContent = tr(res && res.status === 404 ? 'dhNoConfig' : 'dhLoadError');
        return;
    }
    const data = await res.json();
    const at = String(data.seen_at).replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2}).*$/, '$1-$2-$3 $4:$5 UTC');
    pre.textContent = `# ${tr('dhConfigOf', { at, n: data.versions })}\n\n${data.text}`;
}

document.getElementById('dhTenant')?.addEventListener('change', renderDeviceHistory);
document.getElementById('dhPeriod')?.addEventListener('change', renderDeviceHistory);
document.getElementById('dhSearch')?.addEventListener('input', renderDeviceHistory);
document.querySelector('#tab-device-history .dh-kinds')?.addEventListener('click', (e) => {
    const btn = /** @type {HTMLElement|null} */ (/** @type {HTMLElement} */ (e.target).closest('[data-dh-kind]'));
    if (!btn) return;
    dhKind = btn.dataset.dhKind || 'all';
    document.querySelectorAll('#tab-device-history [data-dh-kind]').forEach(b => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-pressed', String(b === btn));
    });
    renderDeviceHistory();
});
document.getElementById('dhTimeline')?.addEventListener('click', (e) => {
    const btn = /** @type {HTMLButtonElement|null} */ (/** @type {HTMLElement} */ (e.target).closest('[data-dh-config]'));
    if (btn) dhShowConfig(btn);
});
