# Roadmap operativa — rumore e flusso di lavoro

Spunti presi da Nagios/Naemon, riordinati dopo verifica sul codice. Il criterio
non è la ricchezza della funzionalità ma **quanto dato nuovo richiede**: le voci
che si reggono su ciò che già raccogliamo vengono prima.

Nessuna di queste voci fa vedere di più della rete. Servono a far sì che
l'ingegnere si fidi di ciò che legge, non a scoprire qualcosa di nuovo. È un
obiettivo diverso, e va tenuto distinto.

## Ordine

| # | Voce | Stato | Nota |
|---|------|-------|------|
| 1 | Flapping detection | **fatto** | `IFACE_FLAPPING_001` |
| 2 | Soppressione con finestra (Scheduled Downtime) | **fatto** | `observability/suppression.py`, applicata nel correlatore |
| 3 | Conferma prima di concludere | da fare | il debito che esplode con le notifiche |
| 4 | `device.unreachable` | da fare | il silenzio deve diventare un fatto |
| 5 | Acknowledgement completo | da fare | 3 colonne, non una funzionalità |
| 6 | Notification Engine → Escalation | da decidere | fuori scope dal piano iniziale |

## Perché quest'ordine e non quello proposto

**1. Flapping prima di tutto.** Unica voce che non richiede nessun dato nuovo, e
il rumore esiste già: un `IFACE_DOWN_001` a ogni caduta, un `IFACE_RECOVERED_001`
che ritratta a ogni risalita, una conclusione riscritta a ogni giro. Il codice lo
sapeva già — sta scritto nel rimedio di `IFACE_RECOVERED_001` — e non faceva
nulla.

**2. Downtime e `interface_expectations` sono lo stesso modello.** Uno dice
"questa porta è giù per progetto, per sempre", l'altro "questo apparato è giù per
progetto, da martedì alle 22". Stessa domanda (*l'operatore se lo aspettava?*),
stessa risposta architetturale: non sopprimere il fatto, cambiare
l'interpretazione. Implementarli separati significa avere due posti dove cercare
perché un allarme non è scattato. Va fatta **una** soppressione con finestra
opzionale, dove "per sempre" è il caso senza scadenza.

**3. Conferma prima di concludere — il punto su cui dissentiamo da Nagios.**
Scartare HARD/SOFT dicendo che «Evidence → Incident con confidence e retraction è
più ricco» confonde due problemi. HARD/SOFT serve a *non concludere alla prima
osservazione*; la ritrattazione agisce **dopo** aver concluso.

Finché la conclusione la legge solo la UI, va bene. Con un Notification Engine,
«avevo concluso, poi ho ritrattato» significa aver già svegliato qualcuno alle
tre di notte, e ritrattare un'email non si può.

Che il buco esista si vede dal codice: `BASELINE_NORMAL_RETRACT_001` è nato per
smontare picchi transitori a posteriori — è una conferma fatta al contrario, che
paga il prezzo di aver concluso nel frattempo.

Non serve la macchina a stati di Nagios. Serve che una regola dichiari **quante
osservazioni le occorrono prima di produrre evidenza**: un parametro in più nel
catalogo.

**4. `device.unreachable` invece dell'albero delle dipendenze.** Nagios ha
bisogno di UNREACHABLE perché fa check attivi: pinga tutto e deve distinguere
"host guasto" da "router in mezzo guasto". SentinelNet è passivo.

Il poller SNMP ha introdotto il primo check attivo, e oggi un apparato che smette
di rispondere non produce niente: `_poll_device` torna lista vuota e si passa
oltre. **Silenzio, non un fatto.** Quello è il buco reale, ed è molto più piccolo
di un albero di dipendenze. La propagazione topologica viene dopo, e richiede il
Flow Path via CDP.

**5. Acknowledgement è già all'80%.** `incidents.status` ha `new → ack →
resolved` con transizioni vincolate e concorrenza ottimistica. Mancano
`acknowledged_by`, timestamp e nota: oggi il "chi" finisce solo in audit log, non
sull'incidente.

## Scartate, e perché

| Voce | Motivo |
|------|--------|
| Active checks continui | SentinelNet osserva; l'unica eccezione è il poller, che raccoglie stato, non verifica raggiungibilità |
| Stati OK/WARNING/CRITICAL | evidenze con ruolo causale e confidenza dicono di più |
| **Plugin architecture** | l'equivalente esiste già **due volte**: una sorgente nuova è un adapter in `normalize.py`, una logica nuova è una voce in `RULES`. Un terzo meccanismo darebbe solo tre posti dove cercare |

Passive checks non è una voce: flussi, syslog, API e SNMP *sono* già osservazioni
passive.
