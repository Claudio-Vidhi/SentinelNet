# Diagnosi Client — tab dedicata e tre lacune chiuse

Data: 2026-08-03. Ramo `Dev`.

> Indirizzi di esempio RFC 5737 (`192.0.2.x`, `198.51.100.x`) e nomi segnaposto,
> come impone `CLAUDE.md` §"Protect real data".

## Perché

Il referto di diagnosi client esiste già (`services/client_diagnosis.py`) ma vive
in una modale della Client Map, e tre limiti erano dichiarati e non risolti:

1. il controllo trunk guarda un salto solo, non la catena fino al gateway;
2. nessuno riscansiona prima di diagnosticare: il referto mostra l'età dei dati
   e lascia il giudizio all'operatore;
3. nessuna azione sulla porta trovata — il bounce si fa a mano dal terminale.

Tutte e tre sono cose che il referto *mostra*, quindi stanno in questo lavoro.
La responsività di tutte le tab è un progetto a parte: tocca 25 schermate e non
condivide nulla con la diagnosi.

## Decisioni prese con l'utente

- **Un solo renderer.** Il referto si sposta nella tab nuova; la modale della
  Client Map sparisce e il suo pulsante porta alla tab già compilata. Due copie
  dello stesso referto sarebbero due copie da tenere allineate.
- **Storico: si mostra quello che c'è.** `mac_sightings` e `arp_entries` sono
  già storici (chiave unica per posizione e per binding, con `first_seen`,
  `last_seen`, `seen_count`, potati da `retention_days`). Nessuna migrazione.
  Resta fuori il log cronologico dei cambi (il flapping A→B→A→B è
  indistinguibile da A→B): sarebbe una tabella nuova, non serve per ora.
- **Freschezza: automatica quando serve, mirata.** Sotto soglia si usa il dato,
  sopra soglia si riscansionano DUE apparati — il gateway che ha risposto
  l'ARP e lo switch di accesso — non la flotta.
- **Port bounce: rotta dedicata, solo admin.** Il comando lo costruisce il
  driver del vendor; l'utente non digita nulla, quindi la blacklist `conf t`
  non viene mai scavalcata.

## Fase 1 — Catena trunk multi-salto

`_trunk_chain(access_switch_ip, gateway_ip, vlan, tenant)` sostituisce
`_trunk_check` in `services/client_diagnosis.py:184`.

- I vicini arrivano da `core_engine.generate_network_map()` (nodi e link
  ricavati dal CDP/LLDP dei backup, già in cache).
- BFS dallo switch di accesso al gateway; `visited` come guardia sui cicli,
  tetto di salti per non camminare una topologia malata all'infinito.
- Per ogni salto si riusa l'analisi di oggi (`config_analyzer.analyze_device`),
  ma **ristretta all'interfaccia che guarda il salto successivo** invece che a
  tutti i trunk: è la domanda giusta, e taglia i falsi positivi dei trunk che
  vanno altrove.
- Esito per salto: `carrying` | `missing` | `unknown`.
  `unknown` = nessun backup di configurazione per quell'apparato. Un salto
  ignoto NON dà una catena promossa: `ok` resta falso e `reason` dice quale
  salto manca — stessa convenzione di `_path`, dove `complete` significa "non
  ci sono buchi nel racconto", non "va tutto bene".
- `switchport mode trunk` senza `allowed-vlan` continua a valere "tutte le
  VLAN passano" (default IOS): è il falso positivo più facile da produrre.

Test: catena che porta la VLAN; VLAN che si perde a metà catena; salto senza
backup; ciclo nella topologia; nessun percorso fra accesso e gateway.

## Fase 2 — Cronologia del client

`client_history(mac, tenant)` in `collectors/mac_history.py` (sta lì: legge le
sue tabelle, non è logica di diagnosi).

- Da `mac_sightings`: ogni coppia porta/VLAN occupata, con switch, `first_seen`,
  `last_seen`, `seen_count`, uplink esclusi come già fa `client_map`.
- Da `arp_entries`: ogni IP tenuto, con il gateway che l'ha visto e le stesse
  date.
- Ordinamento per `last_seen` decrescente, tetto di righe.

Test: più posizioni per lo stesso MAC ordinate; più IP; filtro tenant; MAC
sconosciuto torna liste vuote e non solleva.

## Fase 3 — Freschezza

`_ensure_fresh(position, max_age_s)` prima delle sezioni che dipendono dalla
posizione.

- Età da `binding_last_seen` e `port_last_seen`, già presenti nella sezione
  `position`.
- Sotto soglia: nessuna scansione.
- Sopra soglia: riscansione mirata di `gateway_ip` (ARP) e `switch_ip` (MAC)
  con i collector esistenti, poi si rirosolve la posizione.
- Se la riscansione fallisce non si interrompe la diagnosi: si prosegue con il
  dato vecchio e lo si dichiara. Un referto che non esce è peggio di un referto
  che dice quanto è vecchio.
- Soglia in `mac_settings` accanto a `retention_days`, default 900 secondi.
- Il referto riporta `freshness: {refreshed: bool, reason, ages}`.

Test: dato fresco non scansiona; dato vecchio scansiona i due apparati giusti;
fallimento della scansione degrada e lo dice; soglia letta dalle impostazioni.

## Fase 4 — Port bounce

`POST /api/diagnose/port-bounce`, `require_admin`, corpo
`{switch_ip, interface, client_mac}`.

- L'interfaccia deve corrispondere a quella che una diagnosi ha appena
  restituito per quel MAC, e il binding deve stare dentro la soglia di
  freschezza: altrimenti **409**. Una porta vecchia significa staccare il PC di
  qualcun altro.
- Il comando lo compone il driver del vendor (`shutdown` / `no shutdown` sulla
  sola interfaccia risolta). Nessun testo dell'utente raggiunge l'apparato: la
  blacklist `conf t` non va scavalcata perché non passa da lì.
- `log_audit` prima e dopo, con utente, apparato, interfaccia ed esito.
- Scoping per sede come ogni altra rotta (`assert_device_allowed`).
- Lato UI serve digitare il nome dell'interfaccia per confermare.

Test: non-admin 403; interfaccia che non combacia 409; binding vecchio 409;
sede non consentita 403; caso felice scrive due righe di audit.

## Fase 5 — Tab

`static/js/diagnosi.js` nuovo, `#tab-diagnosi` in `templates/dashboard.html`.

- Ricerca per IP o MAC, più destinazione/porta/protocollo opzionali.
- Le sei schede di oggi, spostate dalla modale, più **Cronologia** e
  **Catena trunk**.
- Il pulsante della Client Map porta qui invece di aprire la modale; la modale
  e i suoi helper spariscono da `client-map.js`.
- Ingressi: riga della Client Map, riga di Dispositivi, ricerca della tab.
- Escaping `escapeHtml(jsStr(x))` su ogni valore che arriva dagli apparati.
- i18n: chiavi it + en, icone dentro le stringhe tradotte (`changeLanguage()`
  sostituisce `innerHTML` in blocco).

Test: grep-style con `frontend_source()`, come impone la casa — nessun runner JS.

## Cancello per ogni fase

```sh
uv run pyrefly check
uv run python -m unittest discover -s tests
graphify update .
```

E `uv run pyinstaller SentinelNet.spec` alla fine: l'exe è ciò che viene
provato.

## Fuori perimetro

- Responsività delle 25 tab: progetto separato, deciso con l'utente.
- Log cronologico dei cambi di porta/IP (flapping contato): tabella nuova,
  non serve finché la cronologia aggregata basta.
- Azioni di scrittura diverse dal bounce (cambio VLAN, port-security): nessuno
  le ha chieste.
