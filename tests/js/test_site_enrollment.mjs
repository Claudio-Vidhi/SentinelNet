// Il testo di arruolamento deve contenere il token e un agent.json valido:
// e' l'unico momento in cui il token esiste in chiaro, e un file sbagliato
// costringe a rigenerarlo.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/settings.js', import.meta.url), 'utf8');
const start = src.indexOf('function enrollmentText');
assert.ok(start !== -1, 'enrollmentText assente da settings.js');
const end = src.indexOf('\n    }', start);
const body = src.slice(start, end + 6);

global.window = { location: { origin: 'https://192.0.2.10:8000', protocol: 'https:' } };
const enrollmentText = new Function('window', body + '; return enrollmentText;')(global.window);

const { cfg, cmds } = enrollmentText('milano', 'TOK-EN-123');
const parsed = JSON.parse(cfg);
assert.strictEqual(parsed.site_id, 'milano');
assert.strictEqual(parsed.token, 'TOK-EN-123');
assert.strictEqual(parsed.central_url, 'https://192.0.2.10:8000');
assert.strictEqual(parsed.verify_tls, true, 'su https la verifica TLS resta accesa');
assert.ok(parsed.data_dir, 'senza data_dir l agente scrive nella cwd del servizio');
assert.ok(cmds.includes('agent.json'), 'i comandi non nominano il file che scrivono');
assert.ok(cmds.includes('chmod 600'), 'il file porta un token: non va lasciato leggibile a tutti');
assert.ok(cmds.includes('TOK-EN-123'), 'il token non arriva nei comandi');

// Su http la verifica TLS non puo' essere accesa, o l agente rifiuta il
// proprio centrale.
global.window.location = { origin: 'http://192.0.2.10:8000', protocol: 'http:' };
const plain = enrollmentText('milano', 'T2');
assert.strictEqual(JSON.parse(plain.cfg).verify_tls, false);

console.log('ok - agent.json e comandi di arruolamento coerenti');
