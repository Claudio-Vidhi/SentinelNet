// Client diagnosis rows say what each source knows about THIS client.
//
// The old view printed "OK" whenever the API answered and the size of the
// whole ARP/DHCP table, which read as "the client is fine" whatever the truth.
// The mapping is the substance of the view, so it runs for real here.
//
//   node tests/js/test_client_diagnosis_rows.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/fortigate-management.js'), 'utf8');

const start = src.indexOf('const _FGT_DIAG_IP');
const end = src.indexOf('function renderFgtClientDiagnosis');
assert.ok(start > 0 && end > start, '_fgtDiagRows not found');

const tr = (k, p) => (p ? `${k}${JSON.stringify(p)}` : k);
const _fgtCell = v => (typeof v === 'object' ? JSON.stringify(v) : String(v));
const _fgtDiagRows = (0, eval)(
    `((tr, _fgtCell) => { ${src.slice(start, end)}; return _fgtDiagRows; })`)(tr, _fgtCell);

const byLabel = rows => Object.fromEntries(rows.map(r => [r.label, r]));
const sent = { client: '192.0.2.2', dest: '198.51.100.8', protocol: 'ICMP' };
const body = { client: '192.0.2.2', client_type: 'ip', sections: {
    arp: { data: [{ ip: '192.0.2.20', mac: 'AA:BB:CC:DD:EE:20' }, { ip: '192.0.2.2', mac: 'AA:BB:CC:DD:EE:02', interface: 'internal' }] },
    dhcp_leases: { data: [{ ip: '192.0.2.20' }] },
    sessions: { data: 'total session: 0' },
    traffic_logs: { data: [{ action: 'deny', dstip: '198.51.100.8' }, { action: 'accept', dstip: '203.0.113.5' }] },
    policy_lookup: { data: { policy_id: 0, success: true } },
    wifi_clients: { error: 'HTTP 404' },
} };
const r = byLabel(_fgtDiagRows(body, sent));

// 1. Found means THIS client, with what identifies it - not the table size.
assert.equal(r.fgtDiagSecArp.kind, 'ok');
assert.match(r.fgtDiagSecArp.detail, /AA:BB:CC:DD:EE:02/);
// 2. 192.0.2.20 is not 192.0.2.2: absent, and the size is only context.
assert.equal(r.fgtDiagSecDhcp.kind, 'warn');
assert.equal(r.fgtDiagSecDhcp.outcome, 'fgtDiagNotFound');
// 3. Zero sessions from the CLI text is "none", not "OK".
assert.equal(r.fgtDiagSecSessions.outcome, 'fgtDiagNoSessions');
// 4. Logs count the blocked ones and the ones to the destination.
assert.equal(r.fgtDiagSecLogs.kind, 'warn');
assert.match(r.fgtDiagSecLogs.detail, /"deny":1/);
assert.match(r.fgtDiagSecLogs.detail, /"n":1,"dest":"198.51.100.8"/);
// 5. A failed source says so.
assert.equal(r.fgtDiagSecWifi.kind, 'bad');
// 6. The policy lookup is the verdict above the table, not a row.
assert.equal(Object.keys(r).length, 5);

// 7. A MAC client is matched across separators, and the row shows its IP.
const macBody = { client: 'aa-bb-cc-dd-ee-02', client_type: 'mac', resolved_ip: '192.0.2.2',
                  sections: { arp: body.sections.arp } };
const m = byLabel(_fgtDiagRows(macBody, {}));
assert.equal(m.fgtDiagSecArp.kind, 'ok');
assert.match(m.fgtDiagSecArp.detail, /192\.0\.2\.2/);

// 8. CLI text: a whole-address match, 192.0.2.2 is not found inside 192.0.2.20.
const cli = byLabel(_fgtDiagRows({ client: '192.0.2.2', client_type: 'ip',
    sections: { arp: { data: '192.0.2.20  0  aa:bb:cc:dd:ee:20 internal' } } }, {}));
assert.equal(cli.fgtDiagSecArp.outcome, 'fgtDiagNotFound');

console.log('ok - client diagnosis rows: per-client presence, sessions, logs, errors, MAC, CLI text');
