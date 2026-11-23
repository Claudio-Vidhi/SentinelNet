// FortiGate advisor master-detail view: list grouped by policy, detail built
// from the rec's checks / changes / policy snapshot.
//
// Example data only (RFC 5737, invented names).
//
//   node tests/js/test_fgt_advisor_view.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/fortigate-management.js'), 'utf8');

const start = src.indexOf('const FGT_ADV_SEVS');
const end = src.indexOf('// Copy the CLI snippet next to');
assert.ok(start > 0 && end > start, 'advisor view not found');

const tr = (k, p) => (p ? `${k}(${Object.values(p).join(',')})` : k);
const escapeHtml = s => String(s).replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
const FGT_FMT = { bytes: v => `${v}B`, time: v => `t${v}` };
const window = {};
const api = (0, eval)(`((tr, escapeHtml, FGT_FMT, window) => { ${src.slice(start, end)};
    return { _fgtAdvListHtml, _fgtAdvDetailHtml }; })`)(tr, escapeHtml, FGT_FMT, window);
assert.equal(typeof window.fgtAdvisorMount, 'function', 'window export missing');

const policy = {
    id: '7', name: 'Pub-Web', position: 2, action: 'accept',
    srcintf: ['wan1'], dstintf: ['dmz'], srcaddr: ['all'], dstaddr: ['VIP_web'], service: ['HTTPS'],
    nat: 'disable', 'inspection-mode': 'flow', 'auto-asic-offload': 'enable', 'utm-status': '',
    'ssl-ssh-profile': 'no-inspection', 'av-profile': '', 'webfilter-profile': '',
    'application-list': '', 'dnsfilter-profile': '', 'ips-sensor': '',
    bytes: 1000, hit_count: 5, last_used: null, src_is_wan: true, dst_is_wan: false,
    is_vip: true, vip: 'VIP_web: 203.0.113.10 → 10.0.20.10',
};
const vip = {
    id: 'ADV-VIP-L7-7', severity: 'HIGH', category: 'Layer 7 / VIP', policy_id: '7', policy_name: 'Pub-Web',
    title: 'VIP <without> IPS', risk: 'Exposed.', reuse_note: "Reusing 'IPS_Srv' (2).", cli: 'config firewall policy',
    policy, highlight: ['dstaddr', 'ips-sensor'],
    checks: [{ ok: false, text: 'Destination is a VIP', field: 'dstaddr', value: 'VIP_web' },
             { ok: false, text: 'No IPS sensor', field: 'ips-sensor', value: '' },
             { ok: true, text: 'Source all expected', field: 'srcaddr', value: 'all' }],
    changes: [{ field: 'ips-sensor', old: '', new: 'IPS_Srv' }],
};
const ssl = { ...vip, id: 'ADV-SSL-7', severity: 'WARN', title: 'SSL', checks: [], changes: [] };
const prof = {
    id: 'ADV-AV-PROFILE-AV_Mon', severity: 'WARN', category: 'Antivirus', policy_id: null, title: 'AV',
    profile: { name: 'AV_Mon', kind: 'antivirus', fields: [{ key: 'http.av-scan', value: 'monitor' }],
               used_by: [{ id: '3', name: 'lan-out' }] },
    highlight: ['http.av-scan'], checks: [], changes: [],
};

// 1. By policy: one group per policy with its mini flow, profile recs under
//    their own "Profile <name>" group.
const list = api._fgtAdvListHtml([vip, ssl, prof], { mode: 'policy', sel: vip.id });
assert.equal((list.match(/fgt-adv-grp"/g) || []).length, 2);
assert.match(list, /wan1 <i>→<\/i> dmz <i>·<\/i> all <i>→<\/i> VIP_web <i>·<\/i> HTTPS/);
assert.match(list, /fgtAdvProfileGroup\(AV_Mon\)/);
assert.match(list, /data-id="ADV-VIP-L7-7"\s+aria-pressed="true"/);
assert.ok(!list.includes('<without>'), 'title not escaped');

// 2. Detail: problems, "not a problem" apart, cause marks, diff, siblings.
const d = api._fgtAdvDetailHtml(vip, [vip, ssl, prof]);
const problems = d.slice(d.indexOf('fgt-adv-why'), d.indexOf('fgt-adv-ok'));
assert.match(problems, /Destination is a VIP/);
assert.match(problems, /ips-sensor = fgtAdvEmpty/);
assert.ok(!problems.includes('Source all expected'));
assert.match(d.slice(d.indexOf('fgt-adv-ok')), /Source all expected/);
assert.match(d, /fgt-adv-node hit[\s\S]*VIP_web: 203\.0\.113\.10/);
assert.match(d, /fgt-adv-prof none hit"><b>IPS<\/b>/);
assert.match(d, /<td class="old">—<\/td>\s*<td class="new">IPS_Srv<\/td>/);
assert.match(d, /fgtAdvRisk:<\/b> Exposed\./);
assert.match(d, /data-action="fgt-copy-cli"/);
assert.match(d, /fgtAdvMore[\s\S]*data-id="ADV-SSL-7"/);

// 3. A profile rec shows the profile card with its users, no siblings.
const p = api._fgtAdvDetailHtml(prof, [vip, ssl, prof]);
assert.match(p, /fgtAdvProfileInUse/);
assert.match(p, /http\.av-scan<\/div>\s*<div class="v hit">monitor/);
assert.match(p, /#3 lan-out/);
assert.ok(!p.includes('fgtAdvMore'));

console.log('ok');
