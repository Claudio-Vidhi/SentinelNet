// Device PDF summary (device-summary-pdf.js): zone matrix and report HTML, run in isolation.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/device-summary-pdf.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const fn = name => {
    const start = src.indexOf(`function ${name}(`);
    assert.ok(start >= 0, `missing ${name}`);
    const end = src.indexOf('\n}\n', start) + 2;
    return (0, eval)(`(${src.slice(start, end)})`);
};

// The globals the module borrows from core.js, i18n.js and config-analyzer.js.
globalThis.escapeHtml = s => String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
globalThis.tr = (key, vars) => key + (vars ? JSON.stringify(vars) : '');
globalThis.i18n = { it: {}, en: {} };
globalThis.currentLang = 'it';
globalThis.caMvValLabels = {};
globalThis.caDefectLine = f => `defect:${f.key}:${f.rule_id}`;
for (const name of ['dsTable', 'dsSection', 'dsRingSvg', 'dsRouteRing', 'dsMatrixTable', 'dsFindings', 'dsItemText', 'dsCss', 'zoneMatrix'])
    globalThis[name] = fn(name);
const zoneMatrix = globalThis.zoneMatrix;
const deviceSummaryHtml = fn('deviceSummaryHtml');

// Zone matrix: a policy over several interfaces counts once per listed pair,
// `any` is a row of its own, and a disabled policy passes no traffic.
const m = zoneMatrix([
    { srcintf: ['lan', 'dmz'], dstintf: ['wan1'], action: 'accept' },
    { srcintf: ['any'], dstintf: ['wan1'], action: 'deny' },
    { srcintf: ['lan'], dstintf: ['wan1'], action: 'accept', status: 'disable' },
]);
assert.deepEqual(m.cells, {
    'lan|wan1': { accept: 1, deny: 0 },
    'dmz|wan1': { accept: 1, deny: 0 },
    'any|wan1': { accept: 0, deny: 1 },
});
assert.deepEqual([...m.rows].sort(), ['any', 'dmz', 'lan']);
assert.deepEqual(m.cols, ['wan1']);

const forti = {
    ip: '192.0.2.1', hostname: 'fw-01', config_type: 'fortios', tenant: 'acme', backup_ts: 1700000000,
    interfaces: [{ name: 'port1', ip: '192.0.2.1/24', role: 'lan', allowaccess: ['ping', 'https'], status: 'up', vlanid: '', parent: '' }],
    policies: [{ id: '7', name: '<b>bold</b>', srcintf: ['port1'], dstintf: ['wan1'], srcaddr: ['all'], dstaddr: ['all'],
                 service: ['ALL'], action: 'accept', nat: 'enable', status: 'enable', logtraffic: 'all' }],
    vips: [{ name: 'web-vip', extip: '203.0.113.10', mappedip: '10.0.0.10', extintf: 'wan1', extport: '443', mappedport: '443' }],
    routing: { static: [{ seq: '1', prefix: '0.0.0.0/0', next_hop: '198.51.100.1', device: 'wan1', distance: '10',
                          dst_kind: 'prefix', blackhole: false, status: 'enable' }] },
    vpn: { phase1: ['to-branch'], phase2: ['to-branch-p2'], peers: [{ name: 'to-branch', remote_gw: '198.51.100.2' }] },
    validation: { policy_findings: [{ key: 'any_any', severity: 'high', rule_id: '7' }], any_any_policies: ['7'], logging_disabled: true },
};
const h = deviceSummaryHtml(forti, 'it');
assert.ok(h.startsWith('<!doctype html>'), 'a whole document');
assert.ok(h.includes('fw-01'), 'hostname');
for (const sec of ['dsSecInterfaces', 'dsSecMatrix', 'dsSecPolicies', 'dsSecRoutes', 'dsSecVips', 'dsSecVpn', 'dsSecFindings'])
    assert.ok(h.includes(sec), `section ${sec}`);
assert.ok(h.includes('&lt;b&gt;bold&lt;/b&gt;') && !h.includes('<b>bold'), 'policy name escaped');
assert.ok(!/<script/i.test(h), 'no script');
assert.ok(!/http-equiv/i.test(h), 'no http-equiv: the print route refuses it');
assert.ok(!/https?:\/\//.test(h), 'no external URL');
assert.ok(h.includes('<svg'), 'route ring drawn');
assert.ok(h.includes('defect:any_any:7') && h.includes('to-branch') && h.includes('203.0.113.10'));
assert.ok(!h.includes('@font-face'), 'no fonts passed: fallback stacks only');

// Fonts embedded: data: URIs only, the print CSP admits nothing else.
const uri = 'data:font/woff2;base64,d09GMgABAAAAA';
const hf = deviceSummaryHtml(forti, 'en', { saira: uri, azeret: uri });
assert.equal((hf.match(/@font-face/g) || []).length, 2, 'Saira and Azeret faces');
assert.ok(hf.includes('url("data:font/woff2;base64,'), 'font as data: URI');
assert.ok(!/url\(\s*["']?(https?:|\/)/i.test(hf), 'no font fetched from a URL');
assert.ok(!/<script/i.test(hf) && !/http-equiv/i.test(hf) && !/https?:\/\//.test(hf));

const ios = {
    ip: '192.0.2.2', hostname: 'switch-01', config_type: 'ios', backup_ts: 1700000000,
    vlans: [{ id: '10', name: 'users', svi: { ip: '10.0.10.1/24', shutdown: false }, access_ifaces: ['Gi1/0/1'], trunk_ifaces: ['Gi1/0/48'] }],
    interfaces: [{ name: 'GigabitEthernet1/0/1', mode: 'access', access_vlan: '10', trunk_allowed: '', ip: '', description: 'pc', shutdown: false, acl_in: '', acl_out: '' }],
    routing: { static: [{ prefix: '0.0.0.0/0', next_hop: '10.0.10.254', ad: null, name: '', vrf: '' }], protocols: [], vrfs: [] },
    acls: [{ name: 'MGMT', kind: 'standard', entries: [{ seq: '10', action: 'permit', text: '10.0.0.0 0.0.0.255' }],
             applied: [{ where: 'line', target: 'vty 0 4', direction: 'in' }] }],
    vpn: [],
    validation: { unused_acls: [], missing_acls: [{ name: 'GONE', referenced_in: 'interface Vlan10 (in)' }], policy_findings: [] },
};
const hi = deviceSummaryHtml(ios, 'en');
assert.ok(hi.includes('switch-01'));
assert.ok(hi.includes('dsSecVlans') && hi.includes('dsSecAcls'), 'VLAN and ACL sections');
assert.ok(!hi.includes('dsSecMatrix'), 'no policy matrix on a switch');
assert.ok(hi.includes('vty 0 4') && hi.includes('GONE'));
assert.ok(!/<script/i.test(hi) && !/https?:\/\//.test(hi) && !/http-equiv/i.test(hi));

// The PDF button (config-analyzer.js): only firewalls with a layout of their
// own (FortiOS) and switches; a PAN-OS firewall would print as a switch.
const ca = readFileSync(new URL('../../static/js/config-analyzer.js', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const caFn = name => {
    const start = ca.indexOf(`    function ${name}(`);
    assert.ok(start >= 0, `missing ${name}`);
    return (0, eval)(`(${ca.slice(start, ca.indexOf('\n    }\n', start) + 6)})`);
};
for (const name of ['isFirewallDevice', 'isServerDevice']) globalThis[name] = caFn(name);
const caPdfButton = caFn('caPdfButton');
const L = { dsBtnPdf: 'PDF' };
assert.ok(caPdfButton({ ip: '192.0.2.1', config_type: 'fortios' }, L).includes('ca-pdf-summary'));
assert.ok(caPdfButton({ ip: '192.0.2.2', config_type: 'ios' }, L).includes('ca-pdf-summary'));
assert.equal(caPdfButton({ ip: '192.0.2.3', config_type: 'panos' }, L), '');
assert.equal(caPdfButton({ ip: '192.0.2.4', config_type: 'ios', vendor: 'paloalto' }, L), '');

console.log('device_summary: ok');
