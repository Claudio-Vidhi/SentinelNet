# Chi instrada questa VLAN — gateway L3 dedotto dalla configurazione

Data: 2026-08-04. Ramo `Dev`.

> Indirizzi di esempio RFC 5737 (`192.0.2.x`, `198.51.100.x`) e nomi segnaposto,
> come impone `CLAUDE.md` §"Protect real data".

## Perché

La catena dei trunk della Diagnosi Client si percorre solo se si sa dove
finisce. Il capolinea oggi è **il gateway che ha risposto all'ARP**: senza
quello `_trunk_chain` degrada al controllo del solo switch di accesso e lo
dichiara —

> «solo i trunk dello switch di accesso: nessun gateway noto per questo client,
> quindi non c'è una catena da percorrere»

È una risposta onesta ma mezza. E la VLAN del client un instradatore ce l'ha
quasi sempre: nella maggior parte dei casi il firewall, ma non di rado uno
switch L3 con la sua SVI. Quel fatto sta già scritto nei backup di
configurazione che il programma raccoglie e analizza da mesi — semplicemente
non lo legge nessuno.

Questo lavoro lo legge, e lo usa per chiudere la catena.

**Non** è il tracciamento di percorso fra VLAN, e non è una vista "chi instrada
cosa": vedi §"Fuori ambito".

## Cosa esiste già

| Pezzo | Dove | Cosa dà |
|---|---|---|
| SVI per VLAN | `config_analyzer` (mappa `svis`) | `{"ip": <CIDR>, "shutdown": bool}` per VLAN id |
| Scansione per tenant | `config_analyzer.analyze_all(group_filter, allowed_groups)` | itera l'inventario, filtra per `Group`, chiama `analyze_device` |
| Interfacce FortiOS | `fw_analyzers/fortios.py` (`config system interface`) | nome, `ip` già in CIDR, zona, vdom, stato |
| Stato HA per apparato | `redundancy.device_redundancy_badge(ip)` | badge del gruppo con il **ruolo di QUELL'apparato** |
| Età del backup | envelope dell'analisi (`backup_ts`) | quanto è vecchia la risposta |

Due cose mancano e sono il lavoro vero: `fortios.py` **non legge `vlanid`**,
quindi le VLAN instradate dal firewall sono invisibili; e `analyze_device`
**non ha cache**, quindi ogni interrogazione rilegge e ri-parsa i file da disco.

## Decisioni prese

1. **La configurazione è la fonte, l'assegnazione manuale è il ripiego.** Stessa
   forma a due livelli di `resolve_endpoint` (OSSERVATO, poi DICHIARATO): un
   fatto misurato batte una dichiarazione, e la risposta dice sempre quale dei
   due è.
2. **Niente ruolo per apparato.** Un apparato instrada certe VLAN e non altre:
   un campo `Role` sull'inventario non saprebbe dirlo, e costerebbe una colonna
   CSV da dichiarare in quattro punti. Si assegna per VLAN, dove serve.
3. **Approccio A**: derivazione su richiesta più memo, nessuno schema nuovo.

## Architettura

Modulo nuovo `services/vlan_routing.py`, un solo punto d'ingresso:

```python
route_owner(vlan, tenant, client_ip=None) -> {
    "known": bool,
    "device_ip": str,          # chi instrada
    "svi_ip": str,             # l'indirizzo L3 su quella VLAN, in CIDR
    "source": "config" | "manual",
    "backup_age_s": int,       # quanto è vecchio il fatto
    "candidates": [str],       # solo in caso di parità
    "reason": str,             # solo quando known è False
}
```

Modulo a parte perché `client_diagnosis.py` sfiora le 1100 righe e questa è una
domanda autonoma — «chi instrada la VLAN N nel tenant T» — che si prova da sola.

### Flusso nella diagnosi

`_trunk_chain` degrada oggi quando `gateway_ip` è assente. È l'unico gancio:

```
gateway_ip dall'ARP?
   sì -> invariato, percorso di oggi
   no -> route_owner(vlan, tenant, client_ip)
           trovato     -> capolinea della catena, _hop_path come sempre
           non trovato -> degrado di oggi, con una ragione migliore
```

Nient'altro cambia. La scelta del firewall, `_across_sites` e il rinfresco ARP
continuano a usare solo dati osservati.

## La regola di derivazione

```
tenant is None -> RIFIUTO. Non si cerca.
tenant == ""   -> "Generale", il tenant predefinito. Si cerca.
   |
analyze_all(group_filter=tenant, allowed_groups=[tenant])
   |
candidati = SVI (IOS) o interfaccia VLAN (FortiOS) per quella VLAN,
            esclusi shutdown / status down
   |
1. client_ip dentro la subnet di UN solo candidato   -> vincitore
2. altrimenti badge per candidato, ruolo active/master, UNO solo -> vincitore
3. altrimenti parità -> si restituiscono i candidati e si degrada
   |
nessun candidato -> override manuale -> altrimenti ignoto/assente (sotto)
```

### Il tenant è un confine, non un filtro

`analyze_all` **non filtra** quando `group_filter` è falsy: un `tenant` vuoto
farebbe scansionare tutti i gruppi e potrebbe restituire lo switch L3 di un
altro cliente come gateway di questo. È esattamente la falla chiusa in
`_resolve_fortigate` (commit `92a04c5`), e va chiusa qui prima di aprirla.

Perciò si passano entrambi i gate, `group_filter=tenant` e
`allowed_groups=[tenant]`: il secondo regge anche se un domani il controllo di
falsy del primo cambia.

**`None` e `""` non sono la stessa cosa**, ed è la distinzione da cui dipende
tutto il resto:

| `tenant` | Significato | Comportamento |
|---|---|---|
| `None` | il tenant non si conosce (posizione ignota) | **rifiuto**, nessuna scansione |
| `""` | il tenant predefinito, senza `Group` impostato | si normalizza a `"Generale"` e si cerca lì |
| `"sede-a"` | un tenant vero | si cerca lì |

Confonderli romperebbe il caso più comune — l'installazione senza gruppi, dove
`arp_collector` scrive `""` e `analyze_all` legge `"Generale"` — che è lo stesso
inciampo evitato in `_tenant_key` per la scelta del firewall. `route_owner`
normalizza da sé; la diagnosi lo chiama solo quando la posizione è nota, quindi
`None` arriva solo da un chiamante che davvero non sa.

Il tenant è quello **risolto dall'inventario** (`Group`), che sovrascrive la
cartella del backup: la cartella non è affidabile come confine.

### Ignoto e assente sono risposte diverse

`analyze_all` scarta in silenzio gli apparati senza backup. Si calcola quindi
l'insieme degli apparati del tenant meno quelli analizzati:

- insieme **non vuoto** e nessun candidato ⇒ `known: False`, ragione **ignota**,
  con l'elenco degli apparati illeggibili;
- tutti leggibili e nessun candidato ⇒ `known: False`, ragione «nessuna
  interfaccia L3 trovata per la VLAN N», che **non** è «questa VLAN non è
  instradata».

È la convenzione di `_trunk_check` — un salto senza backup è `unknown`, non un
salto promosso — e qui conta il doppio: chi legge sta per andare a toccare la
rete.

Ogni risposta porta l'età del backup da cui viene. Un instradatore dedotto vale
quanto la configurazione che lo dice.

## VLAN instradate dal firewall

`fortios.py` percorre già `config system interface` ed estrae già l'indirizzo in
CIDR; non legge `vlanid`, e produce una sezione da mostrare invece che un dato
da interrogare.

Si aggiunge la lettura di `vlanid` **nel ciclo esistente** e si emette un elenco
interrogabile accanto alla sezione visuale, che resta con le stesse colonne (le
colonne sono UI: cambiarle è churn che questo lavoro non richiede).

`route_owner` tratta poi un'interfaccia VLAN FortiOS esattamente come una SVI.

**Limite dichiarato:** non tutte le interfacce VLAN portano un indirizzo
analizzabile. Quelle senza corrispondono per solo VLAN id, senza discriminazione
per subnet, e finiscono al passo 2 o alla parità.

## Assegnazione manuale

`data/vlan_routing.json`:

```json
{"tenants": {"<tenant>": {"<vlan>": "192.0.2.1"}}}
```

JSON in chiaro: non contiene un segreto, quindi niente Fernet (a differenza di
`tenant_snmp.json`). `data/` è già in `.gitignore`.

In v1 è **sola lettura**: nessuna rotta, nessuna UI. Si consulta solo dopo che
la configurazione non ha dato niente, e la risposta porta sempre
`source: "manual"`, così una riga scritta a mano non si traveste da fatto
misurato.

## Cache delle analisi

`config_analyzer.analyze_device_cached(ip)`, memo su `(ip, mtime del backup)`,
con tetto LRU (128) perché la rotazione dei backup fa crescere le chiavi.

È l'abilitatore: oggi ogni salto di `_trunk_check` rilegge e ri-parsa un file.
Il memo paga la scansione nuova **e** accelera la catena che già percorrete. La
chiave su `mtime` fa sì che un backup nuovo invalidi da solo.

## Contratto verso il referto

La sezione trunk guadagna `gateway_source` (`arp` | `config` | `manual`),
`gateway_device` (da `device_ip`), `gateway_vlan_ip` (da `svi_ip`),
`gateway_backup_age_s` (da `backup_age_s`) e `candidates` in caso di parità.
Con `gateway_source: "arp"` gli altri campi restano assenti: il percorso di
oggi non cambia forma.

`diagnosi.js` aggiunge una riga:

> Gateway VLAN 226: `switch-01` (SVI `192.0.2.1/24`) — dedotto dalla
> configurazione, backup di 3 giorni fa

Il percorso "non noto" è già reso dalla card esistente con la sua ragione.

## Prove

**Unità su `route_owner`** (con `analyze_all` in patch):

| Caso | Atteso |
|---|---|
| `client_ip` dentro una sola subnet | quel candidato |
| due candidati, uno con ruolo `active`/`master` | quello attivo |
| coppia HSRP, nessun ruolo attivo distinguibile | parità, `candidates`, degrado |
| SVI in `shutdown` | ignorata |
| un apparato del tenant senza backup | `known: False`, ragione **ignota**, elenco |
| `tenant=None` | **rifiuto**, nessuna scansione |
| `tenant=""` | si cerca in `"Generale"`, non si rifiuta |
| configurazione muta e override presente | `source: "manual"` |
| interfaccia VLAN FortiOS con `vlanid` | candidato risolto |

**Parser:** `set vlanid` estratto da una configurazione sintetica (RFC 5737).

**Cache:** seconda chiamata non rilegge; `mtime` diverso invalida.

**Diagnosi:** la catena si chiude quando l'ARP non ha gateway.

## Limiti dichiarati

- Indirizzi **secondari** delle SVI scartati a monte (`config_analyzer`, ramo
  `ip address ... secondary`: resta solo un flag). Client su una subnet
  secondaria ⇒ candidato mancato ⇒ degrado.
- Nessun IPv6.
- PAN-OS non toccato: `panos.py` resta senza VLAN interrogabili.
- La parità non si scioglie con un'euristica. Si dichiara.

## Fuori ambito

- **Vista "chi instrada cosa"** per tenant. `route_owner` la regge già: è una
  rotta di lettura e una tabella, quando servirà.
- **Tracciamento di percorso fra VLAN** (client → L3 → NGFW → destinazione):
  vuole gli archi L3 nella topologia, ed è un lavoro suo.
- **Ruolo per apparato** (core/distribuzione/accesso) come campo d'inventario.
