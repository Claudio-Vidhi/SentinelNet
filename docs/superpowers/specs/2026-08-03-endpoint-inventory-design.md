# Endpoint Inventory — tab di inventario client, ed export

Data: 2026-08-03. Ramo `Dev`.

> Indirizzi di esempio RFC 5737 (`192.0.2.x`, `198.51.100.x`) e nomi segnaposto,
> come impone `CLAUDE.md` §"Protect real data".

## Perché

Il dato sui client esiste già ed è raccolto da mesi — `mac_sightings` (dove è
attaccato) e `arp_entries` (che IP ha) — ma nessuna schermata risponde alla
domanda più semplice che un cliente fa: **"quanti e quali dispositivi ci sono
nella mia rete?"**. Le tre tab esistenti rispondono ad altro:

| Tab | Domanda | Unità di riga |
|---|---|---|
| MAC Tracker | "dov'è questo MAC?" | avvistamento |
| Client Map | "chi è `192.0.2.10` e su che porta sta?" | binding MAC↔IP |
| Diagnosi Client | "perché questo client non funziona?" | referto singolo |

Nessuna dà **un elenco**, nessuna si esporta. Un inventario è la vista per riga
= dispositivo, filtrabile e portabile fuori (CSV per il cliente, JSON per uno
script).

Nello stesso lavoro entra una correzione di comportamento della diagnosi: quando
lo stesso indirizzo esiste in più tenant, **la scelta della sede non la fa il
programma**. È la stessa realtà multi-tenant che l'inventario deve modellare, ed
è il punto in cui le due parti si toccano.

## Decisioni prese con l'utente

- **Sola lettura, nessuna tabella nuova.** L'inventario è derivato al momento
  della lettura da `mac_sightings` + `arp_entries` + `switch_if_macs`. Niente
  annotazioni persistenti (nome, proprietario, "approvato"): sarebbe uno stato
  da mantenere allineato alla rete, e la rete cambia da sola. Se un giorno
  servirà un registro d'asset con campi editabili, sarà un lavoro suo.
- **Export lato client.** `Blob` nel browser, CSV e JSON, esattamente le righe
  che la tabella mostra (filtri + selezione applicati). Stesso schema di
  `topology.js:exportCategoriesCsv()`. Nessuna rotta di export, nessun secondo
  formattatore che col tempo diverge dall'ordine di colonne del primo.
- **Quattro funzioni oltre alla tabella**: strip di KPI, colonna di flag
  derivati, click di riga → Diagnosi Client, vista occupazione porte.
- **Diagnosi multi-tenant: non si sceglie in automatico.** Con 2+ tenant non si
  produce alcun referto finché l'utente non indica la sede.

## Approccio scelto

La query di rollup vive in `collectors/mac_history.py` — due funzioni nuove,
`endpoint_inventory()` e `port_occupancy()` — e il router è sottile.

`mac_history` possiede già il DB, il lock, `_connect()`, `_access_positions_for()`,
`reclassify_sightings()` e `topology_uplinks()`: la nuova query li riusa in SQL.
Le due alternative sono state scartate:

- **un `services/endpoint_inventory.py` che compone le funzioni pubbliche** —
  confine di file più pulito, ma `search()` torna avvistamenti grezzi limitati,
  quindi si riaggregherebbe in Python ciò che una `GROUP BY` fa in una query, e
  la logica a forma di database finirebbe divisa fra due moduli;
- **estendere `client_map()` con un flag di raggruppamento** — diff più corto
  sulla carta, forma sbagliata: `client_map()` parte da `arp_entries`, quindi
  ogni endpoint senza binding ARP sparirebbe. È esattamente il buco chiuso per
  la diagnosi con `l2_only`. L'inventario deve partire da `mac_sightings` e
  agganciare l'ARP a sinistra.

---

# Parte A — Endpoint Inventory

## A.1 Cosa conta come endpoint

Una riga per **(MAC, tenant)** — stessa chiave di `_access_positions_for()`.
Un MAC presente in due tenant è legittimamente due righe: è la realtà
multi-tenant, non un duplicato da fondere.

Costruzione:

1. si parte da `mac_sightings` (la verità L2: ogni MAC mai visto);
2. gli avvistamenti passano da `reclassify_sightings()` **prima** di ogni
   giudizio, così i Port-channel non passano per porte di accesso — la riga
   grezza `is_uplink` non li riconosce;
3. si aggancia `arp_entries` a sinistra per gli IP (zero, uno o molti);
4. si escludono i MAC presenti in `switch_if_macs`: sono le interfacce proprie
   degli switch, infrastruttura e non endpoint.

Inclusi ma **marcati, mai nascosti**: i MAC visti solo su uplink e quelli senza
binding ARP. Un endpoint che non so collocare resta un endpoint; toglierlo
dall'elenco farebbe tornare un conteggio più pulito e più falso.

## A.2 Colonne

`mac`, `oui_vendor`, `tenant`, `site`, `ips[]`, e la posizione di accesso più
recente (`switch_ip`, `switch_name`, `interface`, `vlan`), più `first_seen`,
`last_seen`, `seen_count`, `access_port_count`, `client_type`, `flags[]`.

`client_type` viene da `inventory_manager.get_category_assignments()` per IP —
certo solo se assegnato a mano nella scheda "Dispositivi e categorie",
altrimenti `client` generico. Non si eredita mai `source_type`, che descrive il
gateway e non il client (stessa regola già scritta in `client_map()`).

## A.3 Flag — tutti derivati in lettura, nulla di persistito

| Flag | Regola |
|---|---|
| `AMBIGUOUS` | 2+ posizioni di accesso distinte (switch, interfaccia) |
| `RANDOM` | `not endpoints.is_stable_identity(mac)` — il MAC può cambiare alla prossima sessione, il binding vale adesso e basta |
| `VM` | `endpoints.classify_mac().vendor_kind` valorizzato |
| `MULTI-IP` | 2+ IP distinti in `arp_entries` |
| `NO-IP` | nessun binding ARP: nessuna visibilità L3 su quella VLAN |
| `TRANSIT-ONLY` | visto solo su uplink: endpoint reale dietro uno switch non gestito |
| `STALE` | `last_seen` più vecchio della soglia |
| `NEW` | `first_seen` entro la soglia |

Derivati e non salvati per la stessa ragione già scritta in
`observability/endpoints.py`: il giorno in cui la classificazione impara
qualcosa di nuovo, migliora anche ciò che è stato raccolto ieri.

Soglia `STALE`/`NEW`: un unico parametro `stale_days`, default 7, regolabile
dalla UI e passato alla rotta. Non si aggiunge una preferenza salvata.

## A.4 Occupazione porte

Seconda modalità di rendering della stessa tab, per switch.

L'elenco delle interfacce di uno switch **esiste già**: `switch_if_macs` viene
popolata a ogni scansione MAC da `collect_interface_macs()` (`show interfaces`,
o `ietf-interfaces` via NETCONF/RESTCONF). Incrociata con `mac_sightings` dà lo
stato di ogni porta:

- `occupied` — almeno un MAC di accesso (uplink esclusi);
- `uplink` — porta che `topology_uplinks()` conosce come uplink, **anche se
  nessun MAC vi compare**: una porta di trunk momentaneamente muta non è una
  porta libera, e proporla come tale manda un tecnico a infilare un cavo in un
  uplink;
- `free` — nell'elenco interfacce, nessun MAC e nessun uplink noto.

Quattro avvertenze **scritte nella UI**, non sepolte nel codice:

1. l'elenco è fresco quanto l'ultima scansione MAC di quello switch: si mostra
   `switch_if_macs.last_seen`;
2. **`free` significa "nessun MAC imparato", non "nessun cavo"** — un
   dispositivo silenzioso legge come porta libera;
3. uno switch la cui raccolta `if_macs` è fallita (non fatale, lista vuota)
   mostra **"elenco porte non disponibile"**, mai "0 porte libere". Zero righe
   travestite da "nessun dato" sono peggio di un buco dichiarato;
4. `Vlan*`, `Loopback*`, `Null*`, `Port-channel*` restano visibili ma fuori dal
   conteggio delle porte libere: non sono porte in cui infilare un cavo.

## A.5 API — `routers/endpoint_inventory.py`

Due rotte, entrambe `get_current_user`: sola lettura, non serve
`require_operator`.

```
GET /api/endpoints/list
    ?tenant=&site=&switch=&vlan=&q=&stale_days=7&limit=2000
    → {results: [...], total, truncated, counts: {...}}

GET /api/endpoints/ports?switch=<ip>
    → {switch, if_list_age_s, port_list_known, ports: [...]}
```

Scoping per tenant con `user_group_scope()`, stessa regola di `mac_search`: un
tenant fuori dal profilo dell'utente è 403, non ignorato in silenzio.

`limit` default 2000 con flag `truncated`: la UI dichiara "2000 di 4711" e
l'export avverte che sta esportando ciò che è caricato. Un inventario può avere
migliaia di righe e una tabella HTML non ne regge decine di migliaia.

Il nome del file è `endpoint_inventory.py` e non `endpoints.py`: quel nome è già
di `observability/endpoints.py` (classificatore di indirizzi) e due moduli
omonimi con scopi diversi si confondono alla prima lettura.

## A.6 Frontend

`static/js/endpoint-inventory.js`, tab `tab-endpoints`, quarta sorella nel
gruppo di nav di MAC Tracker / Client Map / Diagnosi (`dashboard.html:171`).

Ordine a schermo: strip KPI → barra filtri → tabella ordinabile con selezione a
checkbox → due pulsanti di export → interruttore per la modalità occupazione
porte.

- Click di riga: passa MAC **e tenant** alla tab Diagnosi già esistente. Nessun
  secondo renderer del referto — la regola di un solo renderer resta, con il
  test che fallisce se ne ricompare un altro.
  **È il punto in cui le due parti si toccano**: la riga di inventario conosce
  già il proprio tenant (la chiave è (MAC, tenant)), quindi lo passa e la
  diagnosi non entra mai nello stato `ambiguous` della Parte B. La domanda si
  pone a chi digita un indirizzo a mano, non a chi arriva da una riga che la
  sede ce l'ha già scritta sopra.
- i18n IT+EN in `i18n.js`, con le icone Font Awesome **dentro** le stringhe
  tradotte: `changeLanguage()` sostituisce `innerHTML` in blocco e le icone
  fuori dalla stringa sparirebbero al cambio lingua.
- Ogni valore che arriva dagli apparati passa da `escapeHtml(jsStr(x))`.

## A.7 Test

`tests/test_endpoint_inventory.py`:

- deduplica per (mac, tenant): stesso MAC in due tenant = due righe;
- i MAC di `switch_if_macs` non compaiono;
- MAC visto solo su uplink → `TRANSIT-ONLY`, presente in elenco;
- MAC senza ARP → `NO-IP`, con la posizione L2 valorizzata;
- due posizioni di accesso → `AMBIGUOUS`; due IP → `MULTI-IP`;
- confini di `STALE`/`NEW` rispetto a `stale_days`;
- Port-channel non riconosciuto dalla topologia resta accesso (un server con
  bond LACP è legittimamente lì);
- occupazione porte: `occupied` / `free` / `uplink`, esclusione delle
  interfacce non fisiche dal conteggio, e switch senza elenco →
  `port_list_known: false` invece di zero porte libere;
- **scoping**: un utente del tenant A non vede mai una riga del tenant B.

Più: controlli grep in `tests/test_helpers_frontend.py` (tab registrata nella
nav, funzione di export presente, un solo renderer del referto), e `/api/endpoints`
aggiunto a `ALLOWED_NEW_PREFIXES` in `tests/test_router_parity.py:58`.

---

# Parte B — Diagnosi multi-tenant: la scelta non la fa il programma

## B.1 Comportamento attuale e perché cambia

Oggi `_position()` sceglie la posizione **più recente**, produce il referto
completo per quel tenant, e poi mostra i chip delle altre sedi con un avviso.
Il referto arriva quindi già formato su una sede scelta dal programma.

Il problema non è la regola "più recente" — per un portatile che gira fra sedi è
persino ragionevole — ma il fatto che il risultato **si presenta come definitivo**
mentre riposa su una scelta che nessuno ha confermato. Chi legge un referto
completo non lo rilegge come provvisorio, e la sezione successiva è un pulsante
che tocca la rete.

## B.2 Comportamento nuovo

Quando l'indirizzo cercato risolve a **2+ tenant** e la richiesta non ne indica
uno, `diagnose()` **non produce alcun referto**: torna
`status: "ambiguous"` con la lista dei candidati e si ferma lì. Nessuna
interrogazione ad apparati, nessuna sezione compilata, nessun `complete`.

```json
{
  "status": "ambiguous",
  "client": "aa:bb:cc:dd:ee:01",
  "tenants_available": [
    {"tenant": "Tenant-A", "site": "sede-1", "ip": "192.0.2.10",
     "switch_name": "switch-01", "switch_port": "GigabitEthernet1/0/4",
     "last_seen": "2026-08-03T09:12:00+00:00", "l2_only": false},
    {"tenant": "Tenant-B", "site": "sede-2", "ip": "198.51.100.7",
     "switch_name": "switch-07", "switch_port": "GigabitEthernet1/0/2",
     "last_seen": "2026-08-01T14:40:00+00:00", "l2_only": false}
  ]
}
```

Con `tenant` valorizzato nella richiesta il flusso è quello di oggi, invariato:
lo scoping si restringe a quel tenant e il referto si produce per intero. Un
tenant fuori dal profilo dell'utente resta 403.

Con **un solo** tenant candidato nulla cambia: nessuna domanda, referto diretto.
L'ambiguità che non c'è non va inventata.

## B.3 Frontend

`_diagTenantChoice()` diventa la schermata dello stato `ambiguous` invece di una
striscia sotto un referto già disegnato: stessi chip, stesso ordine (più recente
in cima, con data — è il dato su cui si decide), ma da soli e senza referto
sotto. `diagnosiPickTenant()` resta com'è: fissa `_diagTenant` e rilancia.

Il pulsante di port bounce non è raggiungibile in questo stato, perché non
esiste alcun referto da cui parte.

## B.4 Test

In `tests/test_client_diagnosis.py`:

- MAC in due tenant senza `tenant` nella richiesta → `status: "ambiguous"`,
  `tenants_available` con due voci, **nessuna sezione** del referto presente;
- lo stesso MAC con `tenant` indicato → referto completo per quel tenant;
- MAC in un tenant solo → referto diretto, nessuno stato `ambiguous`;
- l'ambiguità si valuta **dentro lo scope dell'utente**: un MAC presente in A e
  B, per un utente che vede solo A, non è ambiguo;
- tenant fuori scope → 403 (già coperto, si verifica che regga).

## B.5 Lacuna dichiarata — port bounce senza tenant

`PortBounceSchema` non ha campo `tenant`, e `verify_port()` chiama
`_position(mac, True, tenants)` con lo scope **completo** dell'utente
(`client_diagnosis.py:953`): il cancello ri-sceglie da sé il tenant più recente,
indipendentemente da quello che il referto mostrava.

Conseguenza dopo questa modifica: l'utente conferma Tenant-B, legge un referto
di Tenant-B, preme bounce — e il controllo valida contro la posizione in
Tenant-A. Nel caso benigno è un 409 incomprensibile ("il client non risulta su
X ma su Y"); nel caso cattivo, con IP di management che si ripetono fra sedi,
combacia e si agisce sulla sede sbagliata.

La correzione è nota e piccola — `tenant` in `PortBounceSchema`, passato a
`verify_port()` — ma è **fuori dall'ambito deciso per questo lavoro**. Resta
scritta qui perché è un cancello di sicurezza che oggi guarda la porta sbagliata.

---

## Fuori ambito

- **Registro d'asset con campi editabili** (nome, proprietario, tag "approvato"):
  è la scelta scartata in apertura, non un rinvio implicito.
- **Hostname da DHCP e client wireless.** `fortigate_service.get_dhcp_leases()` e
  `get_wifi_clients()` esistono ma non sono mai storicizzati; unirli
  all'inventario è raccolta nuova più storage nuovo, ed è la terza opzione
  scartata.
- **Rotta di export lato server con audit.** Scartata con l'export lato client:
  se un giorno l'esportazione di un inventario dovrà lasciare traccia, la traccia
  va messa sulla query che estrae le righe, non su un secondo percorso.
- **Correzione del tenant nel port bounce** — vedi §B.5.
- **Responsività** — progetto separato già concordato, 26 tab.
