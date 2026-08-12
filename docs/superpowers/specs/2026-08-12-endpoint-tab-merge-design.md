# Endpoint — un solo tab, quattro viste

Data: 2026-08-12. Base: `HEAD = c7d40a1`, ramo `Dev`.
Origine: `docs/ui_tab_overlap_analysis.md` §A1, con le tre parti fuori perimetro
prototipate e discusse con l'utente prima di scrivere questa spec.

> Indirizzi di esempio RFC 5737 (`192.0.2.x`), MAC di esempio RFC 7042
> (`aa:bb:cc:...`), come impone `CLAUDE.md` §"Protect real data".

## Perché

Il gruppo `Localizzazione Endpoint` è già **una sola voce di navigazione**
(`data-tabs="tab-mac tab-clientmap tab-diagnosi tab-endpoints"`,
`templates/dashboard.html:235`), ma dentro sono quattro `.tab-content` separati,
commutati da una barra di sottotab **ricopiata identica in tutti e quattro**.

È esattamente la forma da cui partiva Traffico prima di §A3.

### Quattro selettori di tenant per lo stesso gruppo

| Controllo | Pane | Tipo |
| :--- | :--- | :--- |
| `#macScanGroup` | Tracker MAC | select singola |
| `#arpScanGroup` | Client Map | select singola |
| `#arpTenantMenu` (+ `#arpTenantSummary`, `#arpTenantList`) | Client Map | **multi-select** |
| `#epFilterTenant` | Inventario | select singola |

Quattro controlli per la stessa domanda, e non tutti dello stesso tipo.

### Due contatori con lo stesso nome

`#kpiMacUniqueMacs` e `#kpiArpUniqueMacs` sono etichettati entrambi
`macKpiUniqueLabel` / `arpKpiUniqueLabel` = **"MAC Univoci"** ("Unique MACs").
Contano insiemi diversi — i MAC visti nelle tabelle MAC degli switch contro i MAC
che hanno un binding ARP noto — e oggi stanno a pochi centimetri l'uno dall'altro.

### La barra di sottotab, quattro volte

Lo stesso blocco `<div class="subtab-bar">` con quattro bottoni è duplicato in
ognuno dei quattro `.tab-content`. Tre delle tredici duplicazioni di §B4.

## Decisioni prese con l'utente

1. **Merge di contenitore, non ricucitura.** Quattro pill che mappano 1:1 i
   quattro tab di oggi. Il markup si sposta, non si riscrive.
2. **Un solo selettore di tenant in testata.** I quattro controlli tenant
   spariscono; `#locTenant` li sostituisce. **`#arpTenantMenu` collassa a una
   selezione singola**: si perde il confronto dei binding fra più tenant
   contemporaneamente. Perdita di funzione dichiarata e accettata.
3. **Le etichette dei due KPI si separano** (deciso dopo il prototipo): il merge
   da solo sposterebbe i due contatori in pane diversi, cioè nasconderebbe
   l'ambiguità invece di risolverla.

### Fuori perimetro, con il motivo

| Cosa | Perché no |
| :--- | :--- |
| **Ricerca unificata** (§A1, una query per MAC e IP, una riga sola) | La riga unita è facile quando esistono entrambe le metà. Il lavoro vero sono gli stati parziali: MAC senza binding, IP mai avvistato su una porta, MAC con tre IP. In una rete reale sono la maggioranza, non l'eccezione. Spec propria. |
| **Raccolta unificata** (§A1, un pannello per le due scansioni) | Le due scansioni **non hanno lo stesso bersaglio**: la MAC gira sugli switch d'accesso, l'ARP sui gateway L3. Un solo multi-select dovrebbe etichettare gli apparati per ruolo o filtrarsi da sé. Si scambierebbero due pannelli che funzionano per un selettore che può offrire uno switch a una scansione che non sa cosa farsene. |
| **§A2, le tre diagnosi** | Tocca due tab fuori da questo gruppo. Il referto cross-vendor è già il superset (chiama lui la rotta WLC). Trasformare gli altri due in scorciatoie è piccolo; unire i tre **formati di risposta** non lo è. |

## Struttura target

```
#tab-endpoint
├── hero (titolo + descrizione, cambiano per pill)   ← uno solo
├── #locTenant (select tenant)                       ← uno solo
├── barra pill: #locPill-mac | -clientmap | -diagnosi | -inventory
└── #locPane-mac | -clientmap | -diagnosi | -inventory
```

Prefisso `loc*` (Localizzazione) e **non** `ep*`: `static/js/endpoint-inventory.js`
possiede già `_ep*` e `#ep*`, e una collisione lì è del tipo che non dà errore,
semplicemente prende l'elemento sbagliato.

Chi ridisegna cosa, per non lasciarlo all'interpretazione:

- cambiare **tenant** ridisegna **solo il pane aperto**; gli altri si ridisegnano
  quando li si apre;
- cambiare **pill** ridisegna quel pane con il tenant corrente;
- il pane non ancora visitato nella sessione fa il suo `load*()` alla prima
  apertura, non prima.

## Mappatura elemento per elemento

| Oggi | Domani |
| :--- | :--- |
| `#tab-mac` (contenuto, senza barra e senza hero) | `#locPane-mac` |
| `#tab-clientmap` (idem) | `#locPane-clientmap` |
| `#tab-diagnosi` (idem) | `#locPane-diagnosi` |
| `#tab-endpoints` (idem) | `#locPane-inventory` |
| 4 × `<div class="subtab-bar">` | 1 barra pill |
| 4 × hero | 1 hero, testo per pill |
| `#macScanGroup`, `#arpScanGroup`, `#arpTenantMenu`, `#epFilterTenant` | `#locTenant` |
| `onchange` dei quattro | `locTenantChanged()` |
| `macKpiUniqueLabel` "MAC Univoci" | "MAC visti sugli switch" / "MACs seen on switches" |
| `arpKpiUniqueLabel` "MAC Univoci" | "MAC con un IP noto" / "MACs with a known IP" |

### Punti d'ingresso da aggiornare

Quattro, tutti a `switchTab('tab-endpoint')` più la scelta della pill. Nessuno
shim di compatibilità: quattro chiamanti sono meno di un alias da mantenere.

| File | Riga | Oggi |
| :--- | :--- | :--- |
| `static/js/core.js` | 731 | `else if (tabId === 'tab-mac') loadMacTracker();` |
| `static/js/diagnosi.js` | 82 | `switchTab('tab-diagnosi');` |
| `static/js/endpoint-inventory.js` | 212 | `switchTab('tab-diagnosi');` |
| `static/js/settings.js` | 181 | `{ id: 'tab-mac', key: 'tabMacTracker' }` in `ASSIGNABLE_TABS` |

### Il permesso salvato: l'unico punto che può rompere qualcosa

`settings.js:181` **non** è il tab d'avvio: è `ASSIGNABLE_TABS`, l'elenco dei tab
assegnabili ai ruoli non-admin. Il valore scelto finisce in `allowed_tabs`
**dentro `users.json`** (`security/user_manager.py:171`), e
`applyRoleUI()` (`static/js/core.js:538-544`) confronta quella lista con l'id
estratto dall'`onclick` della voce di navigazione:

```js
const m = btn.getAttribute('onclick').match(/switchTab\('([^']+)'/);
if (tabId && !allowedTabs.includes(tabId)) btn.style.display = 'none';
```

Quando l'`onclick` diventa `switchTab('tab-endpoint', this)`, ogni utente
non-admin che ha `tab-mac` fra i permessi **perde l'intero gruppo Endpoint**, in
silenzio: nessun errore, la voce sparisce e basta.

Il rimedio NON è riscrivere `users.json` — quel file non lo tocca questo lavoro
(vale la regola generale sui file di credenziali). Serve un alias in **lettura**,
in un punto solo: `applyRoleUI()` normalizza `tab-mac` → `tab-endpoint` prima del
confronto. `ASSIGNABLE_TABS` passa a `{ id: 'tab-endpoint', key: 'tabEndpointLoc' }`,
così i permessi salvati da qui in avanti usano l'id nuovo e l'alias serve solo ai
vecchi.

È l'unica compatibilità all'indietro di tutto il lavoro, e c'è perché il dato è
di proprietà dell'utente, non del codice.

## Cosa non cambia

- Le rotte: nessuna. Questo è un lavoro di sola interfaccia.
- Il contenuto dei quattro pane: tabelle, form, KPI (a parte due etichette),
  override MAC, azioni sulla porta — tutto identico.
- **Il caricamento pigro**: `loadMacTracker()`, `loadClientMapTab()`,
  `loadEndpointsTab()` partono alla **prima attivazione della pill**, non
  all'apertura del tab. Aprire Endpoint non deve lanciare tre raccolte.
- I nomi delle funzioni in `client-map.js`, `diagnosi.js`,
  `endpoint-inventory.js`: restano dove sono.

## Punti aperti

- **Pill iniziale**: `Tracker MAC`. Nessuna persistenza della pill scelta fra una
  sessione e l'altra — Traffico non ce l'ha, e aggiungerla qui creerebbe due
  comportamenti diversi in due tab gemelli.
- **Deep-link**: `diagnoseClientInTab()` e il bottone dell'inventario devono
  atterrare sulla pill Diagnosi con il campo già riempito, come fanno oggi.

## Test

1. `tests/test_endpoint_tab.py`, sul modello di `tests/test_traffico_tab.py`:
   - le quattro pill e i quattro pane esistono con gli id previsti;
   - `#tab-mac`, `#tab-clientmap`, `#tab-diagnosi`, `#tab-endpoints` **non**
     esistono più come `.tab-content`;
   - nel gruppo c'è **un solo** select di tenant;
   - i quattro punti d'ingresso puntano a `tab-endpoint`;
   - le due etichette KPI sono diverse fra loro, nelle due lingue.
   - **un `allowed_tabs` che contiene `tab-mac` continua a mostrare la voce
     Endpoint**: è la sola regressione silenziosa possibile in questo lavoro, e
     un test per sottostringhe non la vedrebbe — va esercitato `applyRoleUI()`.
2. `tests/test_ui_revamp.py`: aggiornare le asserzioni che nominano i vecchi id.
3. Verifica a browser: le quattro pill si aprono, il tenant in testata ridisegna
   il pane aperto, la diagnosi da Client Map e da Inventario atterra riempita, e
   aprire il tab non lancia raccolte.

## Fasi

1. Barra pill + quattro pane vuoti, hero unico, `#locTenant` in testata. Il
   vecchio contenuto resta dov'è, irraggiungibile ma intatto.
2. Il contenuto entra nei quattro pane. Via le quattro barre di sottotab e i
   quattro hero.
3. I quattro selettori tenant spariscono dietro `locTenantChanged()`;
   `#arpTenantMenu` collassa.
4. I quattro punti d'ingresso, più `ASSIGNABLE_TABS` e l'alias di lettura in
   `applyRoleUI()` per i permessi già salvati.
5. Le due etichette KPI, in `it` e `en`.
6. Test, verifica a browser, aggiornamento di
   `docs/netsec_troubleshooting_qa_v3.md` §4 e di `ui_tab_overlap_analysis.md`
   §A1 (che va marcato DONE come si è fatto con §A3).
