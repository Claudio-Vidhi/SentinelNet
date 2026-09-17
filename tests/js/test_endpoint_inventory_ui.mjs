// Test UI per Endpoint Inventory:
// 1. Il click sulla riga apre/chiude i dettagli senza avviare la diagnosi.
// 2. La diagnosi viene invocata solo cliccando il pulsante esplicito.
// 3. La colonna configurazione porta tronca a 3 righe e permette l'espansione.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../../static/js/endpoint-inventory.js', import.meta.url), 'utf8');

// Verifica che il click sulla riga usi ep-row-toggle e non più ep-row-diagnose
assert.ok(src.includes('data-action="ep-row-toggle"'), 'Manca data-action="ep-row-toggle" sulle righe');
assert.ok(!src.includes('data-action="ep-row-diagnose"'), 'Trovata ancora data-action="ep-row-diagnose" sulle righe');

// Verifica che la funzione di rendering del dettaglio esista e copra i campi
assert.ok(src.includes('function _renderEndpointDetailRow'), 'Manca _renderEndpointDetailRow');
assert.ok(src.includes('function _toggleEndpointDetail'), 'Manca _toggleEndpointDetail');
assert.ok(src.includes('colspan="10"'), 'La riga di dettaglio deve avere colspan="10" per tutta la larghezza');

// Verifica anteprima configurazione porte e pulsante espandi
assert.ok(src.includes('data-action="ep-toggle-cfg"'), 'Manca azione ep-toggle-cfg');
assert.ok(src.includes('epThConfig'), 'Manca colonna Configurazione nell header occupazione porte');
assert.ok(src.includes('/api/config-analyzer/'), 'endpointsPorts deve richiedere la configurazione dal config-analyzer');

// Riassunto su una riga della config porta: senza "interface ..." e "!".
const fnStart = src.indexOf('function portCfgSummary');
const fnEnd = src.indexOf('\n}\n', fnStart) + 2;
assert.ok(fnStart > 0, 'Manca portCfgSummary');
const portCfgSummary = (0, eval)(`(${src.slice(fnStart, fnEnd)})`);
assert.deepEqual(
    portCfgSummary('interface GigabitEthernet1/0/4\n switchport access vlan 7\n spanning-tree portfast\n shutdown\n!'),
    { text: 'switchport access vlan 7 · spanning-tree portfast', more: 1, count: 3 });
assert.deepEqual(portCfgSummary('interface FortyGigabitEthernet3/1/1\n'), { text: '', more: 0, count: 0 });
// Il blocco completo si apre in una riga a tutta larghezza, non nella cella.
assert.ok(src.includes("cfgRow.className = 'ep-cfg-row'"), 'La config completa deve aprirsi in una riga ep-cfg-row');

console.log('endpoint_inventory_ui: ok');
