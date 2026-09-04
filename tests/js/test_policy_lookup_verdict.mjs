// Il verdetto di una policy-lookup si ricava da cio' che il firewall ha detto.
//
// La vista mostrava la risposta come tabella chiave/valore: consentito/negato
// e il numero di policy erano due righe fra le altre. La tabella di mappatura
// e' la sostanza della nuova vista, quindi si esegue davvero — un controllo
// per sottostringhe passerebbe anche con i colori invertiti.
//
//   node tests/js/test_policy_lookup_verdict.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const src = readFileSync(join(root, 'static/js/fortigate-management.js'), 'utf8');

const start = src.indexOf('function _fgtLookupVerdict');
const end = src.indexOf('function renderFgtPolicyLookup');
assert.ok(start > 0 && end > start, '_fgtLookupVerdict non trovata');

const tr = k => k;
const _fgtLookupVerdict = (0, eval)(
    `(tr => { ${src.slice(start, end)}; return _fgtLookupVerdict; })`)(tr);

const ACCEPT = [{ policyid: 7, name: 'LAN-to-WAN', action: 'accept' }];
const DENY = [{ policyid: 9, name: 'Block-Guest', action: 'deny' }];

// 1. Policy esplicita che accetta -> consentito, verde, con nome.
let v = _fgtLookupVerdict({ policy_id: 7, success: true }, ACCEPT);
assert.equal(v.kind, 'accept');
assert.equal(v.policyId, 7);
assert.equal(v.policyName, 'LAN-to-WAN');
assert.match(v.color, /success/);

// 2. Policy esplicita che nega -> negato, rosso.
v = _fgtLookupVerdict({ policy_id: 9, success: true }, DENY);
assert.equal(v.kind, 'deny');
assert.match(v.color, /danger/);

// 3. policyid 0 e' la deny implicita: una corrispondenza, non un'assenza.
v = _fgtLookupVerdict({ policy_id: 0, success: true }, ACCEPT);
assert.equal(v.kind, 'deny');
assert.equal(v.policyId, 0);
assert.equal(v.note, 'fgtLookupImplicitDeny');

// 4. success:false -> nessuna corrispondenza, e NON un "negato" inventato.
v = _fgtLookupVerdict({ success: false }, ACCEPT);
assert.equal(v.kind, 'nomatch');
assert.equal(v.policyId, undefined);

// 5. Nessun policy_id -> nessuna corrispondenza.
assert.equal(_fgtLookupVerdict({}, ACCEPT).kind, 'nomatch');
assert.equal(_fgtLookupVerdict({ policy_id: null }, ACCEPT).kind, 'nomatch');

// 6. Policy trovata ma azione ignota (pill Policy mai aperta): si dichiara la
//    corrispondenza e si dice dove leggere l'azione. Mai un verde a caso.
v = _fgtLookupVerdict({ policy_id: 7, success: true }, null);
assert.equal(v.kind, 'matched');
assert.equal(v.policyId, 7);
assert.equal(v.note, 'fgtLookupOpenPolicies');
assert.notEqual(v.kind, 'accept');

// 7. L'id arriva come stringa da alcune versioni di FortiOS: stesso verdetto.
v = _fgtLookupVerdict({ policy_id: '7', success: true }, ACCEPT);
assert.equal(v.kind, 'accept');

console.log('ok — verdetto policy-lookup: accetta, nega, deny implicita, nessuna corrispondenza');
