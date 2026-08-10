# Subnet Scan — sola scoperta, login solo su richiesta

Data: 2026-08-10. Ramo `ui-intergration`.

> Indirizzi di esempio RFC 5737 (`192.0.2.x`, `198.51.100.x`) e nomi segnaposto,
> come impone `CLAUDE.md` §"Protect real data".

## Perché

La scansione subnet di oggi non è una scoperta: è un tentativo di login di massa.
`scan_subnet()` fa il ping di tutta la rete, e su **ogni** host vivo con la 22
aperta apre una sessione SSH vera con le credenziali globali di
`core_engine.DEFAULT_USERNAME/PASSWORD/SECRET`, passate dal router senza che
l'utente scelga nulla (`routers/scan.py:33`).

Le conseguenze non sono teoriche:

- ogni host che non usa quelle credenziali registra un fallimento di
  autenticazione — una /24 produce una raffica di auth-failure su tutta la rete;
- dove esiste una politica di lockout, gli account si bloccano;
- per un IDS/SIEM il profilo è indistinguibile da un credential spraying;
- le credenziali usate sono quelle globali, non quelle che l'utente avrebbe
  scelto per quella sede.

Il campo `use_default_creds` dello schema di richiesta è dichiarato e **mai
letto** (`routers/scan.py:26`): non esiste modo, oggi, di chiedere una scansione
che non tenti il login.

La scoperta e l'autenticazione sono due operazioni con rischi diversi e vanno
separate: **la scansione trova, l'utente decide se e con quale identità
provare a entrare.**

## Decisioni prese con l'utente

- **La verifica è opzionale.** L'utente può aggiungere all'inventario un host
  scoperto senza mai scegliere un'identità e senza che il programma tenti alcun
  login.
- **La verifica agisce sulle righe selezionate**, non su tutto ciò che ha la 22
  aperta. Il numero di tentativi di autenticazione è una scelta esplicita, resa
  visibile dal contatore sul pulsante.
- **Porte configurabili**, campo libero a lista più chip preimpostati che vi si
  appendono. Default `22`.
- **Nessun pre-filtro ping rigido.** Un host che non risponde al ping ma ha una
  porta aperta deve comparire: i firewall che scartano ICMP sono la norma, non
  l'eccezione.
- **Un host vivo al ping ma senza porte aperte compare lo stesso**, con le
  colonne porta vuote. La finestra mostra cosa c'è sulla rete, non solo cosa è
  gestibile.
- **Aggiunta senza verifica = solo IP.** Nessun vendor indovinato. Il vendor
  esiste solo accanto al selettore di identità, al momento della verifica.
- **La verifica usa `probe_device()` con un vendor scelto dall'utente**, non un
  controllo di sola autenticazione: così si ottiene anche l'hostname, e
  l'identità verificata può essere scritta sul dispositivo.

## Architettura

### Fase 1 — `collectors/network_scanner.py`

`scan_subnet()` diventa sola scoperta. Firma nuova:

```python
def scan_subnet(address, ports, max_workers=50, progress_cb=None) -> list[dict]
```

Spariscono `vendor_hint` e `credentials`, e con loro l'import di
`crypto_vault`, quello di `probe_device`, la cifratura preventiva delle
credenziali e tutta la funzione interna `_triage`.

Una unità di lavoro per host: ping, poi ogni porta con
`is_reachable(ip, port, timeout=1)`. Il timeout va passato esplicitamente: il
default è 2 secondi (`core/core_engine.py:210`) e su una subnet silenziosa
`len(hosts) × len(ports)` connect da 2s ciascuno mettono la scansione in
ginocchio.

Le porte arrivano già validate dal router (vedi Fase 2); lo scanner non le
rivalida.

Riga di risultato:

```python
{"ip": "192.0.2.10", "alive": True, "open_ports": [22, 443]}
```

Un host entra nella lista se `alive` **oppure** `open_ports` non è vuota. Gli
host che non rispondono a nulla non compaiono.

Spariscono dal risultato `ssh_ok`, `hostname`, `vendor`, `added`.

Il progresso torna a una fase sola: `progress_cb(done, len(hosts))`. Cade quindi
il totale che cresce a metà corsa — sia il commento e la logica in
`routers/scan.py:38-44`, sia il suo specchio nel poller JS
(`static/js/devices.js:774-776`), sia il campo `total` variabile.

Costo su una /24 con 3 porte: 254 unità da 1 ping (fino a 3s) + 3 connect (1s),
con 50 thread.

### Fase 2 — `routers/scan.py`

`SubnetScanRequest` si riduce a:

```python
network: str
ports: list[int] = [22]
```

`vendor`, `group`, `auto_add`, `use_default_creds` vengono rimossi. Le porte
sono input utente: `Field(ge=1, le=65535)` sugli elementi e un tetto alla
lunghezza della lista (16) — senza, `254 × 65535` connect sono a un POST di
distanza. Lista vuota = solo ping, è un caso legittimo.

`assert_group_allowed` non serve più all'avvio: la scansione non scrive più in
inventario. Il controllo resta dov'è già, su `/api/add-device`
(`routers/inventory.py:164`), che è ora l'unica via d'ingresso.

Sparisce il blocco `auto_add` di `routers/scan.py:54-71`.

Restano invariati: thread dedicato (non `BackgroundTasks`), `_scan_jobs` con il
suo lock, la GC dei soli job conclusi dopo 600s, e `GET /api/scan-subnet/{job_id}`.

### Fase 3 — verifica, `POST /api/scan-verify`

Endpoint nuovo, stesso file, `require_operator`.

```python
class ScanVerifyRequest(BaseModel):
    ips: list[str]
    vendor: str
    identity_id: str
```

Riusa il meccanismo dei job già presente — stesso dizionario `_scan_jobs`,
stesso lock, stessa GC, stesso endpoint di polling, stesso poller JS. Una
chiamata sincrona è stata scartata: la selezione può contenere centinaia di
righe e `probe_device` ha 15s di timeout di connessione per host.

La verifica è un **job a sé**, con un proprio `job_id`: non modifica il job di
scoperta, che può essere già stato raccolto dalla GC quando l'utente si decide.
È il frontend a fondere i risultati nelle righe già a schermo, per IP. Un
`job_id` di verifica interrogato su `GET /api/scan-subnet/{job_id}` restituisce
quindi righe `{ip, ok, hostname, error}`, non righe di scoperta.

Per ogni IP: `identity_manager.get_identity_credentials(identity_id)` →
dizionario device (`Profile: 'custom'`, `Group: 'Discovered'`, password e secret
già cifrate una volta sola fuori dal ciclo) → `probe_device()`.

Riga di risultato:

```python
{"ip": "192.0.2.10", "ok": True, "hostname": "switch-01", "error": None}
```

**Controllo tenant, obbligatorio.** Prima di decifrare qualunque credenziale,
l'identità richiesta dev'essere fra quelle visibili al tenant del chiamante
(`get_identities(tenant)` filtra già così, `security/identity_manager.py:86`).
Senza questo controllo un operatore ottiene la password di un altro tenant
indovinandone l'id, che è un `uuid4().hex` ma resta un id opaco passato
dall'utente. Identità non visibile → 404, non 403: non si conferma l'esistenza
di risorse di altri tenant.

Ogni verifica va a `log_audit`, con utente, identità e numero di IP: è
l'operazione che genera i tentativi di autenticazione, dev'essere tracciata.

### Fase 4 — finestra di scansione

`templates/dashboard.html`, modale `subnetScanModal` (riga ~3359). Layout:

```
Network:  [192.0.2.0/24                    ]
Ports:    [22,443                          ]
          (+SSH 22)(+Telnet 23)(+HTTPS 443)(+8443)   <- i chip appendono
Group:    [Generale v]          [ Avvia Scansione ]
─────────────────────────────────────────────
TROVATI 12                            [x] tutti
[x] 192.0.2.10   ping ✓   22,443       —
[ ] 192.0.2.11   ping ✗   443          —
[x] 192.0.2.12   ping ✓   22           —
─────────────────────────────────────────────
Identità: [core-switches v] Vendor: [cisco v]  [ Verifica selezionati (2) ]
                                               [ Aggiungi selezionati (2) ]
```

I due pulsanti in basso sono indipendenti: nessuno dei due richiede l'altro.

- **Verifica selezionati** — attivo solo con un'identità scelta. Riempie
  l'ultima colonna con `✓ hostname` oppure `✗ motivo`.
- **Aggiungi selezionati** — sempre attivo con almeno una riga selezionata.
  Scrive `{ip, vendor: "", profile: "default", group}`; se la riga è stata
  verificata con successo, scrive invece
  `{ip, vendor: <quello scelto>, profile: "identity:<id>", group}`, così il
  dispositivo entra già gestito.

Il selettore identità si popola da `GET /api/identities`, che restituisce già le
sole identità del tenant e non espone segreti.

Escaping: `escapeHtml(jsStr(x))` come da convenzione del progetto su ogni valore
che finisce nel markup delle righe.

Tolti dal modale: `scanVendorSelect` (il vendor si sposta accanto all'identità) e
la checkbox `scanAutoAdd`. `scanGroupSelect` resta — `add-device` richiede un
gruppo e `assert_group_allowed` lo verifica.

Le stringhe nuove seguono l'i18n esistente (`data-i18n`, IT/EN).

## Conseguenze note

- **Vendor vuoto.** `DeviceSchema.vendor` è `str` obbligatorio ma accetta la
  stringa vuota, e `add_or_update_device` non lo valida. Un dispositivo aggiunto
  senza verifica resta quindi senza vendor finché qualcuno non lo modifica; il
  primo backup o triage fallisce con il `ValueError` di `resolve_driver`. È lo
  stato "non gestito" voluto, ma è un percorso di errore reale: la tabella
  dispositivi deve mostrare quelle righe come prive di vendor, non lasciarle
  sembrare normali finché non si rompono.
- **La scoperta non tocca più l'autenticazione.** Una sweep non genera più
  fallimenti di login. La verifica sì, ma solo sulle righe che un umano ha
  spuntato.
- **Superficie in meno:** `use_default_creds` (dichiarato e mai letto) e
  `auto_add` vengono eliminati, non lasciati appesi.

## Test

In `tests/test_scan_and_hostkeys.py`, che già copre la scansione:

1. lista porte: valida, vuota (solo ping), fuori intervallo → 422, oltre 16
   elementi → 422;
2. host trovato solo dalla porta, con ping fallito;
3. host trovato solo dal ping, senza porte aperte, con `open_ports` vuota;
4. host che non risponde a nulla: assente dal risultato;
5. `scan_subnet` non apre alcuna connessione SSH — `probe_device` sostituito da
   un doppio che fallisce il test se chiamato;
6. `/api/scan-verify` con un'identità di un altro tenant → 404, e nessuna
   chiamata a `get_identity_credentials`;
7. `/api/scan-verify` felice: `probe_device` sostituito, risultato `ok` e
   hostname sulla riga giusta.

## Fuori ambito

- Rilevamento del vendor dalle porte aperte o da un banner: indovinare il vendor
  è esattamente ciò che questa modifica smette di fare.
- Scansione UDP, rilevamento di servizi, fingerprinting.
- Modifica di `probe_device`, che va già bene così com'è.
